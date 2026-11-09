// BioZKFHEEnrollmentSource evaluation: bound request (I1), snapshot verdict
// with stale abort (I3), gallery root migration (I2(b)), adapter view, and
// atomic credential issuance through UBCAAuthGateway, with gas.
//
// Part S drives the source contract directly with a software bridge key and a
// simulated committee to run the negative controls (A1, A2, slot, A3/A3',
// root-migration attacks) and the gas sweep over t. Part E runs the R1
// EnrollmentBridge reference (MCU packet -> bridge -> bound source -> committee
// -> adapter -> gateway issuance) on the same contract.
//
// The committee is simulated in JS: it identifies on the session snapshot
// (SCMV plaintext model) and recomputes merged blocks over transparent
// stand-in ciphertexts. PVSC block proofs, coverage, and threshold decryption
// are not executed, and their on-chain cost is not included.
// Local Ganache, synthetic vectors, software keys only.
// Usage: .toolchain/node-v24.19.0-win-x64/node.exe scripts/enrollment-source-evaluation.mjs
import assert from "node:assert/strict";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { createHash, generateKeyPairSync } from "node:crypto";
import ganache from "ganache";
import solc from "solc";
import { ethers } from "ethers";
import { MESSAGE_ENROLL, computeSessionBinding, createP256ECDHKeyPair, createTrustedCapturePacket,
  deriveChannelKey, deriveP256SharedSecret } from "./trusted-capture-wire.mjs";
import { ScmvGallery, prepare, scmvBase, syntheticPeople } from "./lib/scmv-model.mjs";
import { ciphertextDigest, enrollRequestDigest, sourceContextHash, standInCiphertext }
  from "./lib/biozkfhe-source-model.mjs";
import { EnrollmentBridge, toU16 } from "./lib/enrollment-bridge.mjs";
import { registerSyntheticPolicy } from "./lib/canonical-policy.mjs";
import { encodeFinalizedSession, finalizedRecordFor } from "./lib/finalized-record.mjs";

const root = resolve(import.meta.dirname, "..");
const out = resolve(root, process.env.BIOBIND_OUT ?? "build/enrollment-source");
const { keccak256, defaultAbiCoder: abi, joinSignature, id } = ethers.utils;
const hash = id;
const confirmed = async (tx) => (await tx).wait();
const event = (r, name, arg) => r.events.find((e) => e.event === name).args[arg];
const json = (v) => JSON.stringify(v, (_, x) => (typeof x === "bigint" ? x.toString() : x), 2);

const GAMMA = 128, L = 128;
const PARAMS = { L, d: 4, n: 3, gamma: GAMMA, T: scmvBase(GAMMA, L) };
const CAP = PARAMS.n * PARAMS.d;
const TAU = BigInt(GAMMA * GAMMA / 2);
const EPSILON = 2000;
const STATUS = ["None", "Created", "Bound", "Finalized", "AbortedStaleSlot", "Duplicate"];
const VARIANTS = {
  v1: { path: "BioZKFHEEnrollmentSource.sol", name: "BioZKFHEEnrollmentSource" },
  compact: { path: "BioZKFHEEnrollmentSourceCompact.sol", name: "BioZKFHEEnrollmentSourceCompact" },
};
const RECORD_FIELDS = ["sid", "status", "galleryCount", "blockCount", "gallerySnapshotHash",
  "snapshotLastCommitment", "contextHash", "queryDigest", "enrollDigest"];
const plainRecord = (r) => Object.fromEntries(RECORD_FIELDS.map((f) => [f, r[f]]));
/// Variant-specific call shapes: v1 addresses a session by sid; compact passes
/// the open-session record back as calldata and tracks it from events.
function variantApi(variant, source) {
  const v1 = variant === "v1";
  return {
    key: (s) => (v1 ? s.sid : s.rec),
    opened(r) {
      const a = r.events.find((e) => e.event === "SessionCreated").args;
      if (v1) return { sid: a.sid, ctxHash: a.contextHash, N: a.galleryCount.toNumber(),
        ev: { gallerySnapshotHash: a.gallerySnapshotHash, ledgerMetaHash: a.ledgerMetaHash } };
      const rec = plainRecord(a.record);
      return { sid: a.sid, ctxHash: rec.contextHash, N: Number(rec.galleryCount), rec,
        ev: { gallerySnapshotHash: rec.gallerySnapshotHash, ledgerMetaHash: a.ledgerMetaHash } };
    },
    rebound(s, r) {
      if (!v1) s.rec = plainRecord(r.events.find((e) => e.event === "RequestBound").args.record);
    },
    async statusOf(s, r) {
      if (v1) return STATUS[await source.sessionStatus(s.sid)];
      return STATUS[r.events.find((e) => e.event === "SessionClosed").args.status];
    },
    /// Calldata record of a Finalized session: v1 reads it back from storage;
    /// compact takes it from the SessionFinalized event.
    async recordOf(s, r) {
      if (v1) return encodeFinalizedSession(await source.getFinalizedSession(s.sid));
      return encodeFinalizedSession(r.events.find((e) => e.event === "SessionFinalized").args.record);
    },
  };
}
const rand32 = () => `0x${createHash("sha256").update(String(Math.random())).digest("hex")}`;
const sortByAddress = (ws) => [...ws].sort((a, b) => (BigInt(a.address) < BigInt(b.address) ? -1 : 1));

async function compile() {
  const paths = ["UBCALifecycle.sol", "UBCAAuthGateway.sol",
    "interfaces/IBioZKFHEUniquenessAdapter.sol", "interfaces/IBioZKFHEFinalizationSource.sol",
    "BioZKFHEFinalizationAdapter.sol", "BioZKFHEEnrollmentSource.sol", "BioZKFHEEnrollmentSourceCompact.sol",
    "generated/Groth16Verifier128.sol"];
  const sources = Object.fromEntries(await Promise.all(paths.map(async (p) =>
    [p, { content: await readFile(resolve(root, "contracts", p), "utf8") }])));
  const result = JSON.parse(solc.compile(JSON.stringify({ language: "Solidity", sources,
    settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: "shanghai",
      outputSelection: { "*": { "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"] } } } })));
  const errors = (result.errors ?? []).filter((e) => e.severity === "error");
  assert.equal(errors.length, 0, errors.map((e) => e.formattedMessage).join("\n"));
  return result.contracts;
}

/// Off-chain committee simulation. Honest members identify on the session
/// snapshot and recompute u_new; corrupt members sign whatever is proposed.
class Committee {
  constructor(wallets) {
    this.wallets = sortByAddress(wallets);
    this.gallery = new ScmvGallery(PARAMS);
    this.blockCts = [];
    this.snapshots = new Map();
  }
  snapshot(sid) {
    const g = new ScmvGallery(PARAMS);
    g.blocks = this.gallery.blocks.map((W) => W.map((r) => [...r]));
    g.N = this.gallery.N;
    this.snapshots.set(sid, { g, cts: [...this.blockCts] });
  }
  /// Honest proposal for (sid): verdict on the snapshot and the implied migration.
  propose(sid, cIdentify, cEnroll) {
    const { g, cts } = this.snapshots.get(sid);
    const unique = g.identify(cIdentify.rows).every((s) => s < TAU);
    const append = g.N % CAP === 0;
    const blockIndex = append ? cts.length : cts.length - 1;
    const uOld = append ? ethers.constants.HashZero : cts.at(-1).digest;
    let next;
    if (append) next = cEnroll;
    else {
      const last = cts.at(-1);
      const rows = last.rows.map((row, i) => row.map((x, j) => x + cEnroll.rows[i][j]));
      const randomness = keccak256(abi.encode(["bytes32", "bytes32"], [last.randomness, cEnroll.randomness]));
      next = { role: "block", rows, randomness };
      next.digest = ciphertextDigest(next);
    }
    const outputDigest = keccak256(abi.encode(["string", "bytes32", "bool"], ["outputs", sid, unique]));
    return { unique, append, blockIndex, uOld, uNew: unique ? next.digest : ethers.constants.HashZero,
      outputDigest, next, Venroll: cEnroll.rows };
  }
  async sign(source, key, p, signers = this.wallets) {
    const digest = await source.confirmationDigest(key, p.unique, p.outputDigest, p.blockIndex, p.uOld, p.uNew);
    return sortByAddress(signers).map((w) => joinSignature(w._signingKey().signDigest(digest)));
  }
  /// Apply a finalized migration to the committee's view of the gallery.
  commit(p) {
    if (p.append) this.blockCts.push(p.next); else this.blockCts[this.blockCts.length - 1] = p.next;
    this.gallery.update(p.Venroll);
  }
}

async function setupChain(accounts = 6) {
  const chain = ganache.provider({ chain: { chainId: 31337, hardfork: "shanghai" },
    logging: { quiet: true }, miner: { blockGasLimit: 30000000 },
    wallet: { deterministic: true, totalAccounts: accounts } });
  const provider = new ethers.providers.Web3Provider(chain);
  const wallets = Object.values(chain.getInitialAccounts()).map(({ secretKey }) => new ethers.Wallet(secretKey, provider));
  return { chain, provider, wallets };
}

const deployer = (contracts, signer) => async (path, name, ...args) => {
  const c = contracts[path][name];
  const x = await new ethers.ContractFactory(c.abi, `0x${c.evm.bytecode.object}`, signer).deploy(...args);
  const r = await x.deployTransaction.wait();
  x.deployGas = r.gasUsed.toNumber();
  return x;
};

/// Static-call a state-changing method and report whether it reverts with the
/// expected custom error (selector search as in enrollment-bridge-evaluation.mjs).
async function reverts(promise, errorName, contract) {
  try {
    await promise;
  } catch (error) {
    const selector = contract.interface.getSighash(errorName);
    const found = [];
    const walk = (x, depth) => {
      if (depth > 5 || x == null) return;
      if (typeof x === "string") { if (x.startsWith("0x")) found.push(x); return; }
      if (typeof x === "object") for (const k of ["data", "error", "body"]) walk(x[k], depth + 1);
    };
    walk(error, 0);
    if (typeof error.body === "string") {
      try { walk(JSON.parse(error.body), 0); } catch { /* not JSON */ }
    }
    if (found.some((v) => v.startsWith(selector))) return errorName;
    const other = found.map((v) => { try { return contract.interface.parseError(v).name; } catch { return null; } }).find(Boolean);
    return `other:${other ?? String(error.message).slice(0, 60)}`;
  }
  return "NOT_REVERTED";
}

// ---------------------------------------------------------------- Part S
async function partS(contracts, variant, t, n, { full }) {
  const { chain, wallets } = await setupChain(2);
  const [owner] = wallets;
  try {
    const deploy = deployer(contracts, owner);
    const committeeKeys = Array.from({ length: n }, (_, i) => new ethers.Wallet(id(`committee-${t}-${n}-${i}`)));
    const committee = new Committee(committeeKeys);
    const model = hash("source/model/synthetic"), quant = hash("source/quant/synthetic");
    const source = await deploy(VARIANTS[variant].path, VARIANTS[variant].name,
      committeeKeys.map((w) => w.address), t, PARAMS.n, PARAMS.d, model, quant);
    const api = variantApi(variant, source);
    const key = api.key;
    const bridgeKey = new ethers.Wallet(id("software-bridge"));
    await confirmed(source.registerBridge(bridgeKey.address));
    const people = syntheticPeople(31, L);
    const gas = { createSession: [], bindRequest: [], finalizeAppend: [], finalizeMerge: [], finalizeStale: [], finalizeDuplicate: [] };

    const open = async () => {
      const r = await confirmed(source.createSession());
      gas.createSession.push(r.gasUsed.toNumber());
      const s = api.opened(r);
      committee.snapshot(s.sid);
      return s;
    };
    const client = (s, v, { enrollVector = v } = {}) => {
      const { Videntify, h, k } = prepare(v, s.N, PARAMS);
      const { Venroll } = prepare(enrollVector, s.N, PARAMS);
      return { cIdentify: standInCiphertext("identify", Videntify, rand32()),
        cEnroll: standInCiphertext("enroll", Venroll, rand32()), h, k };
    };
    const declare = (s, c, count = s.N) => joinSignature(bridgeKey._signingKey().signDigest(enrollRequestDigest({
      chainId: 31337, sourceContract: source.address, sid: s.sid, sourceContextHash: s.ctxHash, galleryCount: count,
      queryCiphertextDigest: c.cIdentify.digest, enrollmentCiphertextDigest: c.cEnroll.digest, h: c.h, k: c.k })));
    const bind = async (s, c, sig = declare(s, c)) => {
      const r = await confirmed(source.bindRequest(key(s), c.cIdentify.digest, c.cEnroll.digest, s.N, c.h, c.k, sig));
      gas.bindRequest.push(r.gasUsed.toNumber());
      api.rebound(s, r);
    };
    const finalize = async (s, c) => {
      const p = committee.propose(s.sid, c.cIdentify, c.cEnroll);
      const r = await confirmed(source.finalize(key(s), p.unique, p.outputDigest, p.uNew, await committee.sign(source, key(s), p)));
      const status = await api.statusOf(s, r);
      const g = r.gasUsed.toNumber();
      if (status === "Finalized") {
        committee.commit(p);
        (p.append ? gas.finalizeAppend : gas.finalizeMerge).push(g);
        s.record = await api.recordOf(s, r);
      }
      else if (status === "AbortedStaleSlot") gas.finalizeStale.push(g);
      else if (status === "Duplicate") gas.finalizeDuplicate.push(g);
      return status;
    };
    const enroll = async (v) => { const s = await open(); const c = client(s, v); await bind(s, c); return finalize(s, c); };

    // Context-hash encoding agreement with the JS model.
    const s0 = await open();
    const ctxPre = { chainId: 31337, sourceContract: source.address, sid: s0.sid, op: 1, galleryCount: s0.N,
      gallerySnapshotHash: s0.ev.gallerySnapshotHash, ledgerMetaHash: s0.ev.ledgerMetaHash };
    const res = { variant, t, n, contextHashMatchesModel: sourceContextHash(ctxPre) === s0.ctxHash };
    assert.equal(res.contextHashMatchesModel, true);
    const c0 = client(s0, people.capture("p0", GAMMA));
    await bind(s0, c0);
    assert.equal(await finalize(s0, c0), "Finalized");
    for (let i = 1; i < 14; i++) assert.equal(await enroll(people.capture(`p${i}`, GAMMA)), "Finalized"); // crosses a block boundary
    res.honestEnrolled = (await source.galleryCount()).toNumber();
    res.blockCount = await source.blockCount();
    res.onChainLastCommitmentMatchesCommittee = (await source.lastBlockCommitment()) === committee.blockCts.at(-1).digest;
    res.recaptureIsDuplicate = await enroll(people.capture("p3", GAMMA));
    if (!full) return { ...res, gas };

    const N = {};
    // A1: host swaps C_enroll for a zero-vector ciphertext after the bridge declared the real one.
    {
      const s = await open();
      const real = client(s, people.capture("A1", GAMMA));
      const swapped = { ...real, cEnroll: client(s, people.capture("A1", GAMMA), { enrollVector: Array(L).fill(0) }).cEnroll };
      N.A1_swappedEnrollCiphertext = await reverts(source.callStatic.bindRequest(key(s), swapped.cIdentify.digest, swapped.cEnroll.digest,
        s.N, swapped.h, swapped.k, declare(s, real)), "UnregisteredBridge", source);
      // A1 without any bridge declaration (paper semantics client).
      N.A1_noBridgeDeclaration = await reverts(source.callStatic.bindRequest(key(s), real.cIdentify.digest, real.cEnroll.digest,
        s.N, real.h, real.k, "0x"), "UnregisteredBridge", source);
      // A2: declared N differs from the snapshot (even if the bridge signed it).
      const wrongN = 1;
      N.A2_wrongDeclaredCount = await reverts(source.callStatic.bindRequest(key(s), real.cIdentify.digest, real.cEnroll.digest,
        wrongN, real.h, real.k, declare(s, real, wrongN)), "DeclaredCountMismatch", source);
      // Slot (h,k) inconsistent with N.
      N.slotInconsistentWithCount = await reverts(source.callStatic.bindRequest(key(s), real.cIdentify.digest, real.cEnroll.digest,
        s.N, (real.h + 1) % PARAMS.d, real.k, declare(s, { ...real, h: (real.h + 1) % PARAMS.d })), "SlotMismatch", source);
    }
    // A3 / A3': same person, two sessions on one snapshot; then distinct people concurrently.
    {
      const s1 = await open(), s2 = await open();
      const c1 = client(s1, people.capture("A", GAMMA)), c2 = client(s2, people.capture("A", GAMMA));
      await bind(s1, c1); await bind(s2, c2);
      const verdict2OnSnapshot = committee.propose(s2.sid, c2.cIdentify, c2.cEnroll).unique;
      N.A3prime = { firstStatus: await finalize(s1, c1), secondVerdictOnSnapshotWasUnique: verdict2OnSnapshot,
        secondStatus: await finalize(s2, c2) };
      N.A3prime.retryStatus = await enroll(people.capture("A", GAMMA));
      const d1 = await open(), d2 = await open();
      const e1 = client(d1, people.capture("B", GAMMA)), e2 = client(d2, people.capture("C", GAMMA));
      await bind(d1, e1); await bind(d2, e2);
      N.A3_distinctConcurrent = { B: await finalize(d1, e1), C: await finalize(d2, e2) };
      N.A3_distinctConcurrent.Cretry = await enroll(people.capture("C", GAMMA));
    }
    // Root migration attacks on a merge (current N is not a block boundary).
    {
      assert.notEqual((await source.galleryCount()).toNumber() % CAP, 0);
      const s = await open();
      const c = client(s, people.capture("D", GAMMA));
      await bind(s, c);
      const p = committee.propose(s.sid, c.cIdentify, c.cEnroll);
      const dropped = { ...p, uNew: p.uOld }; // compute node keeps the old block
      const corrupt = committee.wallets.slice(0, t - 1);
      N.mergeDropWithTMinus1Signers = await reverts(source.callStatic.finalize(key(s), true, p.outputDigest, dropped.uNew,
        await committee.sign(source, key(s), dropped, corrupt)), "InsufficientConfirmations", source);
      const outsiders = Array.from({ length: t }, (_, i) => new ethers.Wallet(id(`outsider-${i}`)));
      N.mergeDropWithOutsiderSigners = await reverts(source.callStatic.finalize(key(s), true, p.outputDigest, dropped.uNew,
        await committee.sign(source, key(s), dropped, [...corrupt, ...outsiders])), "InsufficientConfirmations", source);
      const dupSigs = await committee.sign(source, key(s), dropped, corrupt);
      N.mergeDropWithRepeatedSigner = await reverts(source.callStatic.finalize(key(s), true, p.outputDigest, dropped.uNew,
        [...dupSigs, dupSigs[0]]), "InsufficientConfirmations", source);
      // Honest signatures over the true u_new cannot be replayed onto a different u_new.
      N.honestSignaturesReplayedOnOtherUNew = await reverts(source.callStatic.finalize(key(s), true, p.outputDigest, dropped.uNew,
        await committee.sign(source, key(s), p)), "InsufficientConfirmations", source);
      N.honestMergeAfterAttacks = await finalize(s, c);
    }
    // Append check is on chain: even t valid member signatures cannot install u_new != H(C_enroll).
    {
      while ((await source.galleryCount()).toNumber() % CAP !== 0) await enroll(people.capture(`fill${Math.random()}`, GAMMA));
      const s = await open();
      const c = client(s, people.capture("E", GAMMA));
      await bind(s, c);
      const p = committee.propose(s.sid, c.cIdentify, c.cEnroll);
      const bogus = { ...p, uNew: rand32() };
      N.appendWrongCommitmentWithTSigners = await reverts(source.callStatic.finalize(key(s), true, p.outputDigest, bogus.uNew,
        await committee.sign(source, key(s), bogus)), "AppendMismatch", source);
      N.honestAppendAfterAttack = await finalize(s, c);
    }
    // Adapter view: finalized session readable, aborted/duplicate sessions rejected.
    {
      const adapter = await deployer(contracts, owner)("BioZKFHEFinalizationAdapter.sol", "BioZKFHEFinalizationAdapter", source.address);
      const s = await open();
      const c = client(s, people.capture("F", GAMMA));
      await bind(s, c);
      await finalize(s, c);
      const r = await adapter.previewFinalizedUniqueEnrollment(s.sid, s.record);
      N.adapterReadsFinalized = r.enrollmentCiphertextDigest === c.cEnroll.digest;
      const dup = await open();
      const cd = client(dup, people.capture("F", GAMMA));
      await bind(dup, cd);
      assert.equal(await finalize(dup, cd), "Duplicate");
      try { await adapter.previewFinalizedUniqueEnrollment(dup.sid, finalizedRecordFor(dup.sid)); N.adapterRejectsDuplicate = false; }
      catch { N.adapterRejectsDuplicate = true; }
    }
    res.negative = N;
    res.runtimeBytes = contracts[VARIANTS[variant].path][VARIANTS[variant].name].evm.deployedBytecode.object.length / 2;
    res.deploymentGas = source.deployGas;
    return { ...res, gas };
  } finally {
    await chain.disconnect();
  }
}

// ---------------------------------------------------------------- Part E
async function partE(contracts, variant) {
  const { chain, provider, wallets } = await setupChain(4);
  const [owner, holder1, holder2] = wallets;
  try {
    const deploy = deployer(contracts, owner);
    const t = 3, n = 5;
    const committeeKeys = Array.from({ length: n }, (_, i) => new ethers.Wallet(id(`e2e-committee-${i}`)));
    const committee = new Committee(committeeKeys);
    const modelHash = hash("bridge/model/synthetic-FaceNet-shaped-128");
    const quantizationHash = hash("bridge/quant/L2-gamma128-round/u16-offset32768/v1");
    const verifier = await deploy("generated/Groth16Verifier128.sol", "Groth16Verifier");
    const gateway = await deploy("UBCAAuthGateway.sol", "UBCAAuthGateway", verifier.address);
    const source = await deploy(VARIANTS[variant].path, VARIANTS[variant].name,
      committeeKeys.map((w) => w.address), t, PARAMS.n, PARAMS.d, modelHash, quantizationHash);
    const api = variantApi(variant, source);
    const adapter = await deploy("BioZKFHEFinalizationAdapter.sol", "BioZKFHEFinalizationAdapter", source.address);
    await confirmed(gateway.configureUniquenessAdapter(adapter.address));
    await confirmed(adapter.configureAuthorizedConsumer(gateway.address));
    await confirmed(gateway.disableLegacyReceiptPath());
    const { policyHash } = await registerSyntheticPolicy(gateway, {
      label: "bridge/policy/sqdist-2000/u16-offset/128/v1", modelHash, quantizationHash, epsilon: EPSILON });
    const policyDigest = (await gateway.policyFieldDigest(policyHash)).toString();

    const derivationKey = ethers.Wallet.createRandom();
    await confirmed(source.registerBridge(derivationKey.address));
    const mcuKeys = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const deviceVersionId = event(await confirmed(gateway.registerDevice(derivationKey.address,
      hash("bridge/AFE-stack/software-reference-NOT-hardware"), modelHash, quantizationHash, policyHash)),
    "DeviceRegistered", "deviceVersionId");
    const mcu = { deviceVersionId: hash("bridge/mcu-version"), firmwareMeasurement: hash("bridge/mcu-fw"),
      channelId: hash("bridge/attested-channel") };
    const mcuECDH = createP256ECDHKeyPair(), teeECDH = createP256ECDHKeyPair();
    const shared = deriveP256SharedSecret(mcuECDH.privateKey, teeECDH.publicKey);
    const keyFor = (binding) => deriveChannelKey(shared, mcu.channelId, computeSessionBinding(binding));
    const bridge = new EnrollmentBridge({ derivationKey, deviceVersionId, modelHash, quantizationHash, policyHash,
      policyDigest, scmv: PARAMS, mcu: { ...mcu, publicKey: mcuKeys.publicKey } });
    let sealed = bridge.initialize();
    let mcuCounter = 0n;
    const people = syntheticPeople(23, L);
    const now = async () => (await provider.getBlock("latest")).timestamp;
    const destination = { chainId: 31337, gateway: gateway.address };

    const gas = [];
    async function enrollAndIssue(person, holder, lineageLabel) {
      const r0 = await confirmed(source.createSession());
      const ss = api.opened(r0);
      const ev = { sid: ss.sid, contextHash: ss.ctxHash };
      committee.snapshot(ss.sid);
      const ctx = { chainId: 31337, sourceContract: source.address, sid: ss.sid, op: 1,
        galleryCount: ss.N, gallerySnapshotHash: ss.ev.gallerySnapshotHash, ledgerMetaHash: ss.ev.ledgerMetaHash };
      const binding = { sourceChainId: 31337, sourceContract: source.address, sourceSessionId: ev.sid,
        sourceContextHash: ev.contextHash, destinationChainId: 31337, destinationGateway: gateway.address,
        holder: holder.address, lineageId: hash(lineageLabel), enrollmentContext: hash(`${lineageLabel}/ctx`),
        policyHash, modelHash, quantizationHash };
      const packet = createTrustedCapturePacket({ messageType: MESSAGE_ENROLL, vector: toU16(people.capture(person, GAMMA)),
        metadata: { ...mcu, modelHash, quantizationHash, policyHash, sessionBinding: computeSessionBinding(binding),
          counter: ++mcuCounter, notAfter: 4_000_000_000n, coordinateBits: 16 },
        channelKey: keyFor(binding), signingPrivateKey: mcuKeys.privateKey });
      bridge.config.mcu.channelKey = keyFor(binding);
      const prep = await bridge.prepareEnrollment(sealed, { packet, binding, sourceContext: ctx, now: await now() });
      sealed = prep.sealed;
      const a = prep.attestation;
      const r1 = await confirmed(source.bindRequest(api.key(ss), prep.cIdentify.digest, prep.cEnroll.digest, a.galleryCount, a.h, a.k, a.signature));
      api.rebound(ss, r1);
      const p = committee.propose(ss.sid, prep.cIdentify, prep.cEnroll);
      const r2 = await confirmed(source.finalize(api.key(ss), p.unique, p.outputDigest, p.uNew, await committee.sign(source, api.key(ss), p)));
      const status = await api.statusOf(ss, r2);
      if (status !== "Finalized") return { status };
      committee.commit(p);
      const sourceRecord = await api.recordOf(ss, r2);
      const receipt = await adapter.previewFinalizedUniqueEnrollment(ev.sid, sourceRecord);
      const plain = Object.fromEntries(["receiptId", "sourceChainId", "sourceContract", "sourceSessionId",
        "sourceContextHash", "gallerySnapshotHash", "queryCiphertextDigest", "enrollmentCiphertextDigest",
        "verifiedOutputCollectionDigest", "finalizationDigest", "uniqueInputDigest", "modelHash",
        "quantizationHash", "finalizedAtBlock"].map((f) => [f, receipt[f].toString()]));
      const request = { receiptId: plain.receiptId, lineageId: binding.lineageId, cEnroll: prep.cEnrollPoseidon, policyHash,
        modelHash, quantizationHash, templateVersion: 1, holder: binding.holder, deviceVersionId,
        uniqueInputDigest: plain.uniqueInputDigest, enrollmentContext: binding.enrollmentContext };
      const link = bridge.signEnrollmentLink(sealed, { receipt: plain, request, destination });
      sealed = link.sealed;
      const r3 = await confirmed(gateway.issueFromFinalizedBioZKFHESession(ev.sid, sourceRecord, request, link.signature));
      const row = { person, append: p.append, createSession: r0.gasUsed.toNumber(), bindRequest: r1.gasUsed.toNumber(),
        finalize: r2.gasUsed.toNumber(), issuance: r3.gasUsed.toNumber() };
      row.total = row.createSession + row.bindRequest + row.finalize + row.issuance;
      gas.push(row);
      return { status, credentialId: event(r3, "FinalizedUniquenessReceiptIssued", "credentialId") };
    }
    const e1 = await enrollAndIssue("P1", holder1, "lineage/P1"); // append (new block)
    const e2 = await enrollAndIssue("P2", holder2, "lineage/P2"); // merge
    const e3 = await enrollAndIssue("P1", holder2, "lineage/P1-again"); // duplicate, no credential
    return { issued: [e1.status, e2.status], sameSecondEnrollment: e3.status, gas };
  } finally {
    await chain.disconnect();
  }
}

const contracts = await compile();
const med = (xs) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];
const byVariant = {};
for (const variant of ["v1", "compact"]) {
  const main = await partS(contracts, variant, 3, 5, { full: true });
  const sweep = [];
  for (const [t, n] of [[3, 5], [5, 9], [7, 13]]) {
    const r = await partS(contracts, variant, t, n, { full: false });
    sweep.push({ t, n, finalizeAppendMedian: med(r.gas.finalizeAppend), finalizeMergeMedian: med(r.gas.finalizeMerge),
      samples: { append: r.gas.finalizeAppend.length, merge: r.gas.finalizeMerge.length } });
  }
  const e2e = await partE(contracts, variant);
  byVariant[variant] = { main, tSweep: sweep, endToEnd: e2e };
}

for (const [variant, { main, endToEnd: e2e }] of Object.entries(byVariant)) {
  const N = main.negative;
  assert.equal(N.A1_swappedEnrollCiphertext, "UnregisteredBridge");
  assert.equal(N.A1_noBridgeDeclaration, "UnregisteredBridge");
  assert.equal(N.A2_wrongDeclaredCount, "DeclaredCountMismatch");
  assert.equal(N.slotInconsistentWithCount, "SlotMismatch");
  assert.deepEqual([N.A3prime.firstStatus, N.A3prime.secondVerdictOnSnapshotWasUnique, N.A3prime.secondStatus, N.A3prime.retryStatus],
    ["Finalized", true, "AbortedStaleSlot", "Duplicate"]);
  assert.deepEqual([N.A3_distinctConcurrent.B, N.A3_distinctConcurrent.C, N.A3_distinctConcurrent.Cretry],
    ["Finalized", "AbortedStaleSlot", "Finalized"]);
  for (const k of ["mergeDropWithTMinus1Signers", "mergeDropWithOutsiderSigners", "mergeDropWithRepeatedSigner", "honestSignaturesReplayedOnOtherUNew"]) {
    assert.equal(N[k], "InsufficientConfirmations", `${variant} ${k}`);
  }
  assert.equal(N.honestMergeAfterAttacks, "Finalized");
  assert.equal(N.appendWrongCommitmentWithTSigners, "AppendMismatch");
  assert.equal(N.honestAppendAfterAttack, "Finalized");
  assert.equal(N.adapterReadsFinalized, true);
  assert.equal(N.adapterRejectsDuplicate, true);
  assert.equal(main.onChainLastCommitmentMatchesCommittee, true);
  assert.equal(main.recaptureIsDuplicate, "Duplicate");
  assert.deepEqual(e2e.issued, ["Finalized", "Finalized"]);
  assert.equal(e2e.sameSecondEnrollment, "Duplicate");
}

const summary = Object.fromEntries(Object.entries(byVariant).map(([v, { main, tSweep, endToEnd }]) => [v, {
  runtimeBytes: main.runtimeBytes, deploymentGas: main.deploymentGas,
  medians: Object.fromEntries(Object.entries(main.gas).filter(([, xs]) => xs.length).map(([op, xs]) => [op, med(xs)])),
  tSweep, endToEnd: endToEnd.gas }]));
const record = {
  generatedAt: new Date().toISOString(),
  scope: "BioZKFHE enrollment source, v1 (all session fields in storage) vs compact (record digest while open, adapter fields on Finalized only): bound request, snapshot verdict with stale abort, gallery root migration, adapter view, atomic gateway issuance; local Ganache 7.9.2, solc " + solc.version(),
  securityWarning: "Simulated committee and software bridge keys; PVSC, coverage, and threshold decryption not executed and not in gas; synthetic vectors; never deploy.",
  params: { ...PARAMS, T: PARAMS.T.toString(), tau: TAU.toString() },
  summary, byVariant,
};
await mkdir(out, { recursive: true });
await writeFile(resolve(out, "result.json"), `${json(record)}\n`, "utf8");
process.stdout.write(`${json(summary)}\n`);
