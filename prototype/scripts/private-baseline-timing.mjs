// Matched private baselines: 512-D/12-bit v2 ZK matching versus trusted
// attested matching with ZK-hidden membership. Same nine public inputs and
// depth-20 trees. Five alternating-order rounds after one warmup.
// Software fixtures, local benchmark keys. Times exclude capture/TCB signing.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { buildEddsa, buildPoseidon } from "circomlibjs";
import { groth16, wtns } from "snarkjs";
import { DST_ENROLL, DST_PROBE, poseidonCommitment, poseidonCommitmentWide, squaredDistance } from "./commitment.mjs";

const root = resolve(import.meta.dirname, "..");
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const ROUNDS = 5;
const DST = { ID: 3n, LEAF: 4n, DEV: 5n, CAPTURE: 6n, NULLIFIER: 7n };
const CIRCUITS = [
  { circuit: "auth_private_v2_512_b12_dev20", wide: true, devDepth: 20, attested: false },
  { circuit: "auth_private_attested_dev20", wide: true, devDepth: 20, attested: true },
];
const outDir = resolve(root, process.env.BIOBIND_OUT ?? "build/private-baseline-timing-20261030");
await mkdir(outDir, {recursive:true});

const poseidon = await buildPoseidon();
const eddsa = await buildEddsa();
const F = poseidon.F;
const H = (xs) => F.toObject(poseidon(xs.map(BigInt)));
const field = (l) => BigInt(`0x${createHash("sha256").update(l).digest("hex")}`) % R;
const str = (o) => JSON.parse(JSON.stringify(o, (_, v) => (typeof v === "bigint" ? v.toString() : v)));

function merkle(leaves, depth, index) {
  const zeros = [0n];
  for (let i = 0; i < depth; i++) zeros.push(H([zeros[i], zeros[i]]));
  let level = new Map(leaves.map((v, i) => [i, v]));
  const pathElements = [], pathIndices = [];
  let idx = index;
  for (let d = 0; d < depth; d++) {
    pathElements.push(level.has(idx ^ 1) ? level.get(idx ^ 1) : zeros[d]);
    pathIndices.push(idx & 1);
    const next = new Map();
    for (const k of new Set([...level.keys()].map((x) => x >> 1))) {
      next.set(k, H([level.has(2 * k) ? level.get(2 * k) : zeros[d], level.has(2 * k + 1) ? level.get(2 * k + 1) : zeros[d]]));
    }
    level = next;
    idx >>= 1;
  }
  return { root: level.get(0), pathElements, pathIndices };
}

const demo = JSON.parse(await readFile(process.argv[2], "utf8"));
const enroll = demo.profiles.b12.unsigned.A_enroll, probe = demo.profiles.b12.unsigned.A_probe;
const epsilon = BigInt(JSON.parse(await readFile(resolve(root, "..", "experiments", "biometric",
  "results", "lfw_view2_int12.json"), "utf8")).folds[0].threshold);

async function input(c) {
  const policyDigest = field("policy/lfw-512/b12"), ctxHash = field("ctx/b12");
  const commitFn = c.wide ? poseidonCommitmentWide : poseidonCommitment;
  const commit = (roleTag, ctx, salt, values) => commitFn({ roleTag, policyDigest, contextDigest: ctx, dimension: 512, salt, values, bits: 12, packSize: 20 });
  const rEnroll = field("rEnroll"), rProbe = field("rProbe");
  const cEnroll = await commit(DST_ENROLL, 0n, rEnroll, enroll), cProbe = await commit(DST_PROBE, ctxHash, rProbe, probe);
  const s = field("identity-secret/A");
  const cred = merkle([field("o1"), field("o2"), H([DST.LEAF, cEnroll, H([DST.ID, s]), policyDigest, 1n])], 20, 2);
  const prv = createHash("sha256").update("device-key/AFE-512").digest();
  const [ax, ay] = eddsa.prv2pub(prv).map((q) => F.toObject(q));
  const fw = field("fw"), model = field("model/inception-vggface2-512"), quant = field("quant/b12");
  const dev = merkle([H([DST.DEV, ax, ay, fw, model, quant, policyDigest])], c.devDepth, 0);
  const notAfter = 4_000_000_000n, scope = field("scope/app");
  assert.ok(squaredDistance(enroll.map(BigInt),probe.map(BigInt)) <= epsilon);
  const msg=c.attested ? [8n,cEnroll,cProbe,ctxHash,policyDigest,model,quant,fw,notAfter,epsilon]
    : [DST.CAPTURE,cProbe,ctxHash,policyDigest,model,quant,fw,notAfter];
  const sig = eddsa.signPoseidon(prv, F.e(H(msg)));
  const values = { credRoot: cred.root, devRoot: dev.root, cProbe, policyDigest, ctxHash, epsilon, notAfter, scope,
    nullifier: H([DST.NULLIFIER, s, scope]), identitySecret: s, templateVersion: 1n, cEnroll, rEnroll, rProbe,
    enrollment: enroll, probe, credPathElements: cred.pathElements, credPathIndices: cred.pathIndices,
    devAx: ax, devAy: ay, devFirmware: fw, devModel: model, devQuantization: quant,
    devPathElements: dev.pathElements, devPathIndices: dev.pathIndices,
    sigR8x: F.toObject(sig.R8[0]), sigR8y: F.toObject(sig.R8[1]), sigS: sig.S };
  if (c.attested) for (const n of ['enrollment','probe','rEnroll','rProbe']) delete values[n];
  return str(values);
}

const inputs = await Promise.all(CIRCUITS.map(input));
const times = CIRCUITS.map(() => ({ witnessMs: [], proveMs: [] }));
for (let round = 0; round < ROUNDS + 1; round++) { // round 0 is a warm-up and is discarded
  const order=round%2 ? [1,0] : [0,1];
  for (const i of order) {
    const c=CIRCUITS[i];
    const dir = resolve(root, "build", c.circuit);
    const wtnsPath = resolve(outDir, `${c.circuit}-timing.wtns`);
    const t0 = performance.now();
    await wtns.calculate(inputs[i], resolve(dir, `${c.circuit}_js`, `${c.circuit}.wasm`), wtnsPath);
    const t1 = performance.now();
    const generated = await groth16.prove(resolve(dir, `${c.circuit}_final.zkey`), wtnsPath);
    const t2 = performance.now();
    const vk=JSON.parse(await readFile(resolve(dir,"verification_key.json"),"utf8"));
    assert.equal(await groth16.verify(vk,generated.publicSignals,generated.proof),true);
    const expected=['credRoot','devRoot','cProbe','policyDigest','ctxHash','epsilon','notAfter','scope','nullifier'].map(n=>inputs[i][n]);
    assert.deepEqual(generated.publicSignals,expected);
    if (round > 0) {
      times[i].witnessMs.push(Math.round(t1 - t0));
      times[i].proveMs.push(Math.round(t2 - t1));
    }
  }
}
const med = (xs) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];
const results = CIRCUITS.map((c, i) => ({ ...c, ...times[i], witnessMedianMs: med(times[i].witnessMs), proveMedianMs: med(times[i].proveMs),
  totalMedianMs: med(times[i].witnessMs.map((w, k) => w + times[i].proveMs[k])) }));
const record = { generatedAt: new Date().toISOString(),node:process.version, rounds: ROUNDS, warmupDiscarded: 1,
  scope:"Private baseline, same public inputs, alternating execution order; CPU times exclude capture, matching/opening checks in the TCB, signing and network.",
  allProofsVerified:true,publicSignalsIdentical:true,results };
await mkdir(outDir, { recursive: true });
await writeFile(resolve(outDir, "prove-timing-interleaved.json"), `${JSON.stringify(record, null, 2)}\n`, "utf8");
process.stdout.write(`${JSON.stringify(results.map(({ circuit, witnessMedianMs, proveMedianMs, totalMedianMs }) => ({ circuit, witnessMedianMs, proveMedianMs, totalMedianMs })), null, 2)}\n`);
if (globalThis.curve_bn128) await globalThis.curve_bn128.terminate();
process.exit(0);
