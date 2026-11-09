// A3' (BioBind security model v0.1, section 7): one person, two concurrent
// enrollment sessions identified against the same gallery snapshot.
//
// BioZKFHE binds the gallery snapshot into ctx and PVSC certifies identify
// over the committed snapshot blocks, so the uniqueness verdict is relative to
// the snapshot taken when the session opened. The existing source model
// (biozkfhe-source-model.mjs) identifies against the *current* gallery at
// finalize time, which hides this race. This script compares three semantics
// on the SCMV plaintext model, with honest ciphertext content (I1 and I2 hold):
//   current  : identify on the gallery at finalization (existing model)
//   snapshot : identify on the snapshot fixed at session creation (paper)
//   snapshot+stale : snapshot identify, abort if N moved before finalization
// Synthetic vectors only; PVSC, committee decryption and gas are not modelled.
// Usage: .toolchain/node-v24.19.0-win-x64/node.exe scripts/a3prime-snapshot-race.mjs
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { ScmvGallery, prepare, scmvBase, syntheticPeople } from "./lib/scmv-model.mjs";

const root = resolve(import.meta.dirname, "..");
const out = resolve(root, "build", "a3prime");
const GAMMA = 128, L = 128;
const PARAMS = { L, d: 4, n: 3, gamma: GAMMA, T: scmvBase(GAMMA, L) };
const TAU = BigInt(GAMMA * GAMMA / 2); // same threshold as enrollment-bridge-evaluation.mjs

const copyGallery = (g) => {
  const c = new ScmvGallery(g.params);
  c.blocks = g.blocks.map((W) => W.map((row) => [...row]));
  c.N = g.N;
  return c;
};
const unique = (gallery, v) => gallery.identify(prepare(v, 0, PARAMS).Videntify).every((s) => s < TAU);

class Source {
  constructor(semantics) {
    this.semantics = semantics;
    this.gallery = new ScmvGallery(PARAMS);
    this.sessions = [];
  }
  open(v) {
    const s = { v, N0: this.gallery.N, snapshot: copyGallery(this.gallery), status: "Open" };
    this.sessions.push(s);
    return s;
  }
  finalize(s) {
    const g = this.semantics === "current" ? this.gallery : s.snapshot;
    if (!unique(g, s.v)) return (s.status = "Duplicate");
    if (this.semantics === "snapshot+stale" && this.gallery.N !== s.N0) return (s.status = "AbortedStaleSlot");
    // Slot is taken from the authenticated count at write time (I2 holds).
    this.gallery.update(prepare(s.v, this.gallery.N, PARAMS).Venroll);
    return (s.status = "Finalized");
  }
}

function run(semantics) {
  const people = syntheticPeople(11, L);
  const src = new Source(semantics);
  for (let i = 0; i < 10; i++) assert.equal(src.finalize(src.open(people.capture(`p${i}`, GAMMA))), "Finalized");
  // Same person A, two fresh captures, both sessions opened before either finalizes.
  const s1 = src.open(people.capture("A", GAMMA));
  const s2 = src.open(people.capture("A", GAMMA));
  const r1 = src.finalize(s1), r2 = src.finalize(s2);
  const result = { first: r1, second: r2,
    uniquenessResultsForA: [r1, r2].filter((r) => r === "Finalized").length };
  if (r2 === "AbortedStaleSlot") result.retry = src.finalize(src.open(people.capture("A", GAMMA)));
  // Control: two different people concurrently must both succeed (no false abort after retry).
  const c1 = src.open(people.capture("B", GAMMA)), c2 = src.open(people.capture("C", GAMMA));
  const k1 = src.finalize(c1);
  let k2 = src.finalize(c2);
  if (k2 === "AbortedStaleSlot") k2 = `AbortedStaleSlot -> retry ${src.finalize(src.open(people.capture("C", GAMMA)))}`;
  result.controlDistinctPeople = { B: k1, C: k2 };
  result.galleryCount = src.gallery.N;
  return result;
}

const results = { current: run("current"), snapshot: run("snapshot"), "snapshot+stale": run("snapshot+stale") };
assert.equal(results.snapshot.uniquenessResultsForA, 2, "A3' expected to succeed under snapshot semantics");
assert.equal(results["snapshot+stale"].uniquenessResultsForA, 1);
assert.equal(results["snapshot+stale"].retry, "Duplicate");
const record = { generatedAt: new Date().toISOString(),
  scope: "A3' snapshot race on the SCMV plaintext model; synthetic vectors; honest ciphertext content; slot from count at write time",
  params: { ...PARAMS, T: PARAMS.T.toString(), tau: TAU.toString() }, results };
await mkdir(out, { recursive: true });
await writeFile(resolve(out, "result.json"), `${JSON.stringify(record, null, 2)}\n`, "utf8");
process.stdout.write(`${JSON.stringify(results, null, 2)}\n`);
