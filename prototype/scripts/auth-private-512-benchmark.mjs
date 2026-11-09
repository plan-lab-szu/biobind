// 512-D unlinkable authentication circuits with real LFW features at 16, 12, and
// 8-bit coordinates: constraints, benchmark-only Groth16 setup (local pot16),
// proving time, genuine acceptance and impostor rejection.
// Inputs: demo vectors from experiments/biometric/scripts/export_demo_vectors.py
// (quantized with the same rule as the LFW scoring). Epsilon per profile is the
// fold-0 threshold of the LFW View 2 protocol (selected on folds 1-9).
// Usage (from prototype/):
//   .toolchain/node-v24.19.0-win-x64/node.exe scripts/auth-private-512-benchmark.mjs <data-dir>/embeddings/demo_vectors.json
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { buildEddsa, buildPoseidon } from "circomlibjs";
import { groth16, wtns } from "snarkjs";
import { DST_ENROLL, DST_PROBE, poseidonCommitment, squaredDistance } from "./commitment.mjs";

const root = resolve(import.meta.dirname, "..");
const bio = resolve(root, "..", "experiments", "biometric", "results");
const ptau = resolve(root, "build", "proving", "local-benchmark-setup", "pot16_final.ptau");
const snarkjsCli = resolve(root, "node_modules", "snarkjs", "build", "cli.cjs");
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const L = 512, CRED_DEPTH = 20, DEV_DEPTH = 10, REPS = 3;
const DST = { ID: 3n, LEAF: 4n, DEV: 5n, CAPTURE: 6n, NULLIFIER: 7n };
const PROFILES = [
  { key: "b16", circuit: "auth_private_512", bits: 16, packSize: 15, lfw: "lfw_view2_biozkfhe_gamma512.json", verifier: "Groth16VerifierPrivate512.sol" },
  { key: "b12", circuit: "auth_private_512_b12", bits: 12, packSize: 20, lfw: "lfw_view2_int12.json" },
  { key: "b8", circuit: "auth_private_512_b8", bits: 8, packSize: 30, lfw: "lfw_view2_int8.json" },
];

const poseidon = await buildPoseidon();
const eddsa = await buildEddsa();
const F = poseidon.F;
const H = (xs) => F.toObject(poseidon(xs.map(BigInt)));
const field = (label) => BigInt(`0x${createHash("sha256").update(label).digest("hex")}`) % R;
const str = (o) => JSON.parse(JSON.stringify(o, (_, v) => (typeof v === "bigint" ? v.toString() : v)));
const cli = (...args) => execFileSync(process.execPath, [snarkjsCli, ...args], { cwd: root, stdio: "pipe" }).toString();

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

async function buildInput(p, enroll, probe, epsilon) {
  const policyDigest = field(`policy/lfw-512/${p.key}`), ctxHash = field(`ctx/${p.key}`);
  const rEnroll = field("rEnroll"), rProbe = field("rProbe");
  const commit = (roleTag, contextDigest, salt, values) => poseidonCommitment({ roleTag, policyDigest, contextDigest,
    dimension: L, salt, values, bits: p.bits, packSize: p.packSize });
  const cEnroll = await commit(DST_ENROLL, 0n, rEnroll, enroll);
  const cProbe = await commit(DST_PROBE, ctxHash, rProbe, probe);
  const s = field("identity-secret/A");
  const leaf = H([DST.LEAF, cEnroll, H([DST.ID, s]), policyDigest, 1n]);
  const cred = merkle([field("o1"), field("o2"), leaf], CRED_DEPTH, 2);
  const prv = createHash("sha256").update("device-key/AFE-512").digest();
  const [ax, ay] = eddsa.prv2pub(prv).map((q) => F.toObject(q));
  const fw = field("fw"), model = field("model/inception-vggface2-512"), quant = field(`quant/${p.key}`);
  const dev = merkle([H([DST.DEV, ax, ay, fw, model, quant, policyDigest])], DEV_DEPTH, 0);
  const notAfter = 4_000_000_000n;
  const sig = eddsa.signPoseidon(prv, F.e(H([DST.CAPTURE, cProbe, ctxHash, policyDigest, model, quant, fw, notAfter])));
  const scope = field("scope/app");
  return { credRoot: cred.root, devRoot: dev.root, cProbe, policyDigest, ctxHash, epsilon, notAfter, scope,
    nullifier: H([DST.NULLIFIER, s, scope]), identitySecret: s, templateVersion: 1n, cEnroll, rEnroll, rProbe,
    enrollment: enroll, probe, credPathElements: cred.pathElements, credPathIndices: cred.pathIndices,
    devAx: ax, devAy: ay, devFirmware: fw, devModel: model, devQuantization: quant,
    devPathElements: dev.pathElements, devPathIndices: dev.pathIndices,
    sigR8x: F.toObject(sig.R8[0]), sigR8y: F.toObject(sig.R8[1]), sigS: sig.S };
}

const demo = JSON.parse(await readFile(process.argv[2], "utf8"));
const results = [];
for (const p of PROFILES) {
  const out = resolve(root, "build", p.circuit);
  const wasm = resolve(out, `${p.circuit}_js`, `${p.circuit}.wasm`);
  const r1cs = resolve(out, `${p.circuit}.r1cs`);
  const prof = demo.profiles[p.key];
  const epsilon = BigInt(JSON.parse(await readFile(resolve(bio, p.lfw), "utf8")).folds[0].threshold);
  const enroll = prof.unsigned.A_enroll, probe = prof.unsigned.A_probe, impostor = prof.unsigned.B_probe;
  const genuineDistance = squaredDistance(enroll.map(BigInt), probe.map(BigInt));
  const impostorDistance = squaredDistance(enroll.map(BigInt), impostor.map(BigInt));

  const valid = await buildInput(p, enroll, probe, epsilon);
  await wtns.calculate(str(valid), wasm, resolve(out, "valid.wtns"));
  let impostorRejected;
  try {
    await wtns.calculate(str(await buildInput(p, enroll, impostor, epsilon)), wasm, resolve(out, "impostor.wtns"));
    impostorRejected = false;
  } catch {
    impostorRejected = true;
  }

  const info = cli("r1cs", "info", r1cs);
  const zkey0 = resolve(out, `${p.circuit}_0000.zkey`), zkey = resolve(out, `${p.circuit}_final.zkey`);
  const t0 = performance.now();
  cli("groth16", "setup", r1cs, ptau, zkey0);
  cli("zkey", "contribute", zkey0, zkey, "--name=benchmark-only", `-e=${randomBytes(32).toString("hex")}`);
  const setupSeconds = (performance.now() - t0) / 1000;
  cli("zkey", "export", "verificationkey", zkey, resolve(out, "verification_key.json"));
  if (p.verifier) cli("zkey", "export", "solidityverifier", zkey, resolve(root, "contracts", "generated", p.verifier));
  const vkey = JSON.parse(await readFile(resolve(out, "verification_key.json"), "utf8"));
  const proveMs = [];
  let verified = true;
  for (let i = 0; i < REPS; i++) {
    const t1 = performance.now();
    const { proof, publicSignals } = await groth16.fullProve(str(valid), wasm, zkey);
    proveMs.push(Math.round(performance.now() - t1));
    verified &&= await groth16.verify(vkey, publicSignals, proof);
  }
  const row = { profile: p.key, circuit: p.circuit, bits: p.bits, packSize: p.packSize, gamma: prof.gamma, offset: prof.offset,
    constraints: Number(/# of Constraints:\s*(\d+)/.exec(info)?.[1]), epsilon: epsilon.toString(),
    genuineDistance: genuineDistance.toString(), impostorDistance: impostorDistance.toString(),
    verified, impostorRejected, proveMs, setupSeconds: Math.round(setupSeconds) };
  results.push(row);
  process.stdout.write(`${JSON.stringify(row)}\n`);
}

const record = { generatedAt: new Date().toISOString(),
  scope: "512-D auth_private circuits at 16/12/8-bit coordinates with real LFW features (InceptionResnetV1 VGGFace2); benchmark-only Groth16 setup on local pot16",
  securityWarning: "Benchmark-only single-contributor setup; software keys; never deploy.",
  demoSelection: demo.selection, results };
const outDir = resolve(root, "build", "auth-private-512");
await mkdir(outDir, { recursive: true });
await writeFile(resolve(outDir, "results.json"), `${JSON.stringify(record, null, 2)}\n`, "utf8");
for (const r of results) {
  assert.equal(r.verified, true, r.profile);
  assert.equal(r.impostorRejected, true, r.profile);
}
if (globalThis.curve_bn128) await globalThis.curve_bn128.terminate();
process.exit(0);
