// Gallery root migration I2(b) (BioBind security model, section 6;
// design note dev-workspace/notes/gallery-root-migration.md).
//
// BioZKFHE binds the ordered list of block commitments u_m = H(C_m) into each
// session ctx, but nothing on chain checks how that list changes after an
// enrollment: SCMV.Update either appends C_enroll as a new block or adds it
// homomorphically into the last block, and the result is computed off chain.
// This script models the proposed rule:
//   append : u_{M+1} = H(C_enroll), checked on chain from the session-bound digest;
//   merge  : u_M' = H(C_M + C_enroll), accepted only with >= t distinct roster
//            signatures over (sid, m, u_old, H(C_enroll), slot, N_old, N_new, u_new);
//            honest members recompute the deterministic addition themselves.
// "Ciphertexts" are transparent SCMV plaintext matrices (addition is exact, as in
// scmv-model.mjs); digests stand in for hashes of canonical uncompressed BGV bytes.
// No EVM; synthetic vectors only.
// Usage: .toolchain/node-v24.19.0-win-x64/node.exe scripts/gallery-root-migration.mjs
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { ethers } from "ethers";
import { ScmvGallery, prepare, scmvBase, syntheticPeople } from "./lib/scmv-model.mjs";

const { keccak256, defaultAbiCoder: abi, SigningKey, recoverAddress, computeAddress, id, joinSignature } = ethers.utils;
const root = resolve(import.meta.dirname, "..");
const out = resolve(root, "build", "gallery-root-migration");
const GAMMA = 128, L = 128;
const PARAMS = { L, d: 4, n: 3, gamma: GAMMA, T: scmvBase(GAMMA, L) };
const TAU = BigInt(GAMMA * GAMMA / 2);
const CAP = PARAMS.n * PARAMS.d; // templates per SCMV block

const ser = (rows) => JSON.stringify(rows, (_, x) => (typeof x === "bigint" ? x.toString() : x));
const H = (rows) => keccak256(abi.encode(["string", "string"], ["BioBind/ct/v1", ser(rows)]));
const add = (A, B) => A.map((row, i) => row.map((x, j) => x + B[i][j]));
const zeroLike = (A) => A.map((row) => row.map(() => 0n));
const migrationDigest = (m) => keccak256(abi.encode(
  ["string", "bytes32", "uint64", "bytes32", "bytes32", "uint64", "uint64", "uint64", "bytes32"],
  ["BioBind/gallery-migration/v1", m.sid, m.block, m.uOld, m.hEnroll, m.slot, m.nOld, m.nNew, m.uNew]));

// Committee: n = 5, t = 3; members 3 and 4 are corrupt (t - 1 = 2).
const keys = Array.from({ length: 5 }, (_, i) => new SigningKey(id(`committee-${i}`)));
const roster = new Set(keys.map((k) => computeAddress(k.publicKey).toLowerCase()));
const T_SIG = 3;
const CORRUPT = new Set([3, 4]);
const outsider = new SigningKey(id("not-a-member"));
const sign = (k, m) => joinSignature(k.signDigest(migrationDigest(m)));

/// On-chain source state: ordered block commitments u and authenticated count N.
class Source {
  constructor(rule) { this.rule = rule; this.u = []; this.N = 0; }

  /// rule "caller": paper semantics, the next state is whatever the caller supplies.
  /// rule "migration": append checked on chain; merge needs t distinct roster signatures.
  apply(session, claim, sigs = []) {
    if (this.rule === "caller") { this.u = claim.u; this.N = claim.N; return "Applied"; }
    const { hEnroll, slot } = session; // bound at request time (I1)
    if (slot !== this.N || claim.nNew !== this.N + 1) throw new Error("SlotOrCount");
    const appendCase = this.N % CAP === 0;
    if (appendCase) {
      if (claim.block !== this.u.length || claim.uNew !== hEnroll) throw new Error("AppendMismatch");
      this.u.push(claim.uNew);
    } else {
      const m = { sid: session.sid, block: this.u.length - 1, uOld: this.u.at(-1), hEnroll, slot,
        nOld: this.N, nNew: this.N + 1, uNew: claim.uNew };
      if (claim.block !== m.block || claim.uOld !== m.uOld) throw new Error("StaleOrWrongBlock");
      const signers = new Set();
      for (const s of sigs) {
        const a = recoverAddress(migrationDigest(m), s).toLowerCase();
        if (roster.has(a)) signers.add(a); // non-members ignored, duplicates counted once
      }
      if (signers.size < T_SIG) throw new Error("InsufficientConfirmations");
      this.u[this.u.length - 1] = claim.uNew;
    }
    this.N += 1;
    return "Applied";
  }
}

/// Untrusted compute node holding the ciphertext gallery off chain.
class ComputeNode {
  constructor() { this.blocks = []; this.N = 0; }
  propose(Venroll, mode) {
    const appendCase = this.N % CAP === 0;
    if (appendCase) return { appendCase, next: Venroll.map((r) => [...r]) };
    const last = this.blocks.at(-1);
    if (mode === "drop") return { appendCase, next: last };
    if (mode === "zero") return { appendCase, next: add(last, zeroLike(Venroll)) };
    return { appendCase, next: add(last, Venroll) };
  }
  commit({ appendCase, next }) {
    if (appendCase) this.blocks.push(next); else this.blocks[this.blocks.length - 1] = next;
    this.N += 1;
  }
  gallery() {
    const g = new ScmvGallery(PARAMS);
    g.blocks = this.blocks;
    g.N = this.N;
    return g;
  }
}

/// Committee member: honest members recompute C_M + C_enroll from the available bytes.
function confirm(i, m, cOld, Venroll) {
  if (!CORRUPT.has(i) && H(add(cOld, Venroll)) !== m.uNew) return null;
  return sign(keys[i], m);
}

const unique = (g, v) => g.identify(prepare(v, 0, PARAMS).Videntify).every((s) => s < TAU);

function scenario(rule, attack) {
  const people = syntheticPeople(11, L);
  const src = new Source(rule), node = new ComputeNode();

  const enroll = (v, mode = "honest", extraSigs = () => []) => {
    const { Venroll } = prepare(v, src.N, PARAMS);
    const session = { sid: id(`sid-${src.N}-${mode}`), hEnroll: H(Venroll), slot: src.N };
    const p = node.propose(Venroll, mode);
    const uNew = H(p.next);
    if (rule === "caller") {
      const u = p.appendCase ? [...src.u, uNew] : [...src.u.slice(0, -1), uNew];
      src.apply(session, { u, N: src.N + 1 });
      node.commit(p);
      return "Applied";
    }
    const claim = { block: p.appendCase ? src.u.length : src.u.length - 1, uOld: src.u.at(-1), uNew, nNew: src.N + 1 };
    let sigs = [];
    if (!p.appendCase) {
      const m = { sid: session.sid, block: claim.block, uOld: claim.uOld, hEnroll: session.hEnroll,
        slot: session.slot, nOld: src.N, nNew: src.N + 1, uNew };
      sigs = [...keys.map((_, i) => confirm(i, m, node.blocks.at(-1), Venroll)).filter(Boolean), ...extraSigs(m)];
    }
    try {
      src.apply(session, claim, sigs);
      node.commit(p);
      return "Applied";
    } catch (e) {
      return `Rejected:${e.message}`;
    }
  };

  for (let i = 0; i < 10; i++) assert.equal(enroll(people.capture(`p${i}`, GAMMA)), "Applied");
  // Slot 10 lands inside the second block, so A's enrollment is a merge.
  const vA = people.capture("A", GAMMA);
  const r = { rule, attack };
  if (attack === "drop" || attack === "zero") r.attackOutcome = enroll(vA, attack);
  else if (attack === "outsider-and-duplicates") {
    // The two corrupt members already sign; add a repeat from member 3 and two outsider signatures.
    r.attackOutcome = enroll(vA, "drop", (m) => [sign(keys[3], m), sign(outsider, m), sign(outsider, m)]);
  } else r.attackOutcome = enroll(vA, "honest");
  // Consequence: does a fresh capture of A still pass deduplication afterwards?
  r.secondEnrollmentOfAPassesDedup = unique(node.gallery(), people.capture("A", GAMMA));
  r.onChainCountMatchesNode = src.N === node.N;
  r.onChainCommitmentsMatchNode = src.u.length === node.blocks.length && src.u.every((u, i) => u === H(node.blocks[i]));
  return r;
}

function onChainChecks() {
  const src = new Source("migration");
  const v = syntheticPeople(5, L).capture("x", GAMMA);
  const res = {};
  const attempt = (key, fn) => {
    try { res[key] = fn(); } catch (e) { res[key] = `Rejected:${e.message}`; }
  };
  const { Venroll: V0 } = prepare(v, 0, PARAMS);
  const s0 = { sid: id("s0"), hEnroll: H(V0), slot: 0 };
  attempt("wrongSlot", () => src.apply({ ...s0, slot: 1 }, { block: 0, uNew: s0.hEnroll, nNew: 1 }));
  attempt("appendWrongDigest", () => src.apply(s0, { block: 0, uNew: id("other"), nNew: 1 }));
  attempt("appendHonestWithoutCommittee", () => src.apply(s0, { block: 0, uNew: s0.hEnroll, nNew: 1 }));
  const { Venroll: V1 } = prepare(v, 1, PARAMS);
  const s1 = { sid: id("s1"), hEnroll: H(V1), slot: 1 };
  attempt("staleUOld", () => src.apply(s1, { block: 0, uOld: id("stale"), uNew: id("x"), nNew: 2 }));
  return res;
}

const results = {
  honest: scenario("migration", "honest"),
  dropEnrollment_callerRoot: scenario("caller", "drop"),
  dropEnrollment_migration: scenario("migration", "drop"),
  zeroEnrollment_migration: scenario("migration", "zero"),
  outsiderAndDuplicateSignatures: scenario("migration", "outsider-and-duplicates"),
  onChainChecks: onChainChecks(),
};
assert.equal(results.honest.attackOutcome, "Applied");
assert.equal(results.honest.secondEnrollmentOfAPassesDedup, false);
assert.equal(results.honest.onChainCommitmentsMatchNode, true);
assert.equal(results.dropEnrollment_callerRoot.secondEnrollmentOfAPassesDedup, true);
for (const k of ["dropEnrollment_migration", "zeroEnrollment_migration", "outsiderAndDuplicateSignatures"]) {
  assert.equal(results[k].attackOutcome, "Rejected:InsufficientConfirmations");
}
assert.equal(results.onChainChecks.wrongSlot, "Rejected:SlotOrCount");
assert.equal(results.onChainChecks.appendWrongDigest, "Rejected:AppendMismatch");
assert.equal(results.onChainChecks.appendHonestWithoutCommittee, "Applied");
assert.equal(results.onChainChecks.staleUOld, "Rejected:StaleOrWrongBlock");

const record = {
  generatedAt: new Date().toISOString(),
  scope: "Gallery root migration rule I2(b) on the SCMV plaintext model; committee n=5, t=3, members 3 and 4 corrupt; synthetic vectors; no EVM",
  params: { ...PARAMS, T: PARAMS.T.toString(), tau: TAU.toString(), committee: { n: 5, t: T_SIG, corrupt: [...CORRUPT] } },
  results,
};
await mkdir(out, { recursive: true });
await writeFile(resolve(out, "result.json"), `${JSON.stringify(record, null, 2)}\n`, "utf8");
process.stdout.write(`${JSON.stringify(results, null, 2)}\n`);
