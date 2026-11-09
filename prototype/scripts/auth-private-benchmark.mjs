// Unlinkable authentication circuit (circuits/auth_private_128.circom):
// builds a valid witness input and negative variants, runs a benchmark-only
// Groth16 setup on the local powers of tau, measures proving time, checks that
// every negative variant fails witness generation, and measures on-chain
// verifier gas against the existing five-input 128-D verifier.
// Synthetic vectors and software EdDSA keys only. Never deploy these keys.
// Usage (from prototype/): .toolchain/node-v24.19.0-win-x64/node.exe scripts/auth-private-benchmark.mjs
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { buildEddsa, buildPoseidon } from "circomlibjs";
import ganache from "ganache";
import solc from "solc";
import { ethers } from "ethers";
import { groth16, wtns } from "snarkjs";

const root = resolve(import.meta.dirname, "..");
const name = "auth_private_128";
const out = resolve(root, "build", name);
const wasm = resolve(out, `${name}_js`, `${name}.wasm`);
const r1cs = resolve(out, `${name}.r1cs`);
const ptau = resolve(root, "build", "proving", "local-benchmark-setup", "pot15_final.ptau");
const node = process.execPath;
const snarkjsCli = resolve(root, "node_modules", "snarkjs", "build", "cli.cjs");
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const CRED_DEPTH = 20, DEV_DEPTH = 10, REPS = 5;
const DST = { ID: 3n, LEAF: 4n, DEV: 5n, CAPTURE: 6n, NULLIFIER: 7n };

const poseidon = await buildPoseidon();
const eddsa = await buildEddsa();
const F = poseidon.F;
const H = (xs) => F.toObject(poseidon(xs.map(BigInt)));
const field = (label) => BigInt(`0x${createHash("sha256").update(label).digest("hex")}`) % R;
const randField = () => BigInt(`0x${randomBytes(32).toString("hex")}`) % R;
const cli = (...args) => execFileSync(node, [snarkjsCli, ...args], { cwd: root, stdio: "pipe" }).toString();

/// Sparse Poseidon(2) Merkle tree with zero subtrees; returns root and path for one index.
function merkle(leaves, depth, index) {
  const zeros = [0n];
  for (let i = 0; i < depth; i++) zeros.push(H([zeros[i], zeros[i]]));
  let level = new Map(leaves.map((v, i) => [i, v]));
  const pathElements = [], pathIndices = [];
  let idx = index;
  for (let d = 0; d < depth; d++) {
    const sibling = idx ^ 1;
    pathElements.push(level.has(sibling) ? level.get(sibling) : zeros[d]);
    pathIndices.push(idx & 1);
    const next = new Map();
    for (const k of new Set([...level.keys()].map((x) => x >> 1))) {
      const l = level.has(2 * k) ? level.get(2 * k) : zeros[d];
      const r = level.has(2 * k + 1) ? level.get(2 * k + 1) : zeros[d];
      next.set(k, H([l, r]));
    }
    level = next;
    idx >>= 1;
  }
  return { root: level.get(0), pathElements, pathIndices };
}

const base = JSON.parse(await readFile(resolve(root, "inputs", "generated", "auth_distance_128.json"), "utf8"));
const thresholdFail = JSON.parse(await readFile(resolve(root, "inputs", "generated", "threshold_fail.json"), "utf8"));

function buildInput(b, overrides = {}) {
  const policyDigest = BigInt(b.policyDigest);
  const s = overrides.identitySecret ?? field("identity-secret/holder-A");
  const templateVersion = 1n;
  const idc = H([DST.ID, s]);
  const leaf = H([DST.LEAF, BigInt(b.cEnroll), idc, policyDigest, templateVersion]);
  const others = Array.from({ length: 7 }, (_, i) => field(`other-leaf-${i}`));
  const credLeaves = [...others.slice(0, 5), leaf, ...others.slice(5)];
  const cred = merkle(credLeaves, CRED_DEPTH, 5);

  const prv = createHash("sha256").update("device-key/AFE-1").digest();
  const [ax, ay] = eddsa.prv2pub(prv).map((p) => F.toObject(p));
  const firmware = field("fw/1.0"), model = field("model/synthetic-128"), quant = field("quant/u16-offset");
  const devLeaf = H([DST.DEV, ax, ay, firmware, model, quant, policyDigest]);
  const otherDevs = Array.from({ length: 3 }, (_, i) => field(`other-device-${i}`));
  const dev = merkle([otherDevs[0], devLeaf, ...otherDevs.slice(1)], DEV_DEPTH, 1);

  const notAfter = 4_000_000_000n;
  const signedProbe = overrides.signedProbe ?? BigInt(b.cProbe);
  const msg = H([DST.CAPTURE, signedProbe, BigInt(b.ctxHash), policyDigest, model, quant, firmware, notAfter]);
  const sig = eddsa.signPoseidon(prv, F.e(msg));
  const scope = field("scope/app-1");
  const input = {
    credRoot: cred.root, devRoot: dev.root, cProbe: b.cProbe, policyDigest: b.policyDigest, ctxHash: b.ctxHash,
    epsilon: b.epsilon, notAfter, scope, nullifier: H([DST.NULLIFIER, s, scope]),
    identitySecret: s, templateVersion, cEnroll: b.cEnroll, rEnroll: b.rEnroll, rProbe: b.rProbe,
    enrollment: b.enrollment, probe: b.probe,
    credPathElements: cred.pathElements, credPathIndices: cred.pathIndices,
    devAx: ax, devAy: ay, devFirmware: firmware, devModel: model, devQuantization: quant,
    devPathElements: dev.pathElements, devPathIndices: dev.pathIndices,
    sigR8x: F.toObject(sig.R8[0]), sigR8y: F.toObject(sig.R8[1]), sigS: sig.S,
  };
  return { ...input, ...(overrides.patch ?? {}) };
}
const str = (o) => JSON.parse(JSON.stringify(o, (_, v) => (typeof v === "bigint" ? v.toString() : v)));

const valid = buildInput(base);
const negatives = {
  credentialNotInTree: { ...valid, credRoot: field("some-other-credential-root") },
  identitySecretMismatch: buildInput(base, { patch: { identitySecret: field("identity-secret/holder-B") } }),
  nullifierForOtherScope: { ...valid, scope: field("scope/app-2") },
  deviceNotInTree: { ...valid, devRoot: field("some-other-device-root") },
  signatureOverOtherProbe: buildInput(base, { signedProbe: BigInt(base.cProbe) + 1n }),
  thresholdFail: buildInput(thresholdFail),
  // Probe commitment that does not open to the witness (signature re-made over it).
  probeCommitmentMismatch: buildInput({ ...base, cProbe: (BigInt(base.cProbe) + 1n).toString() }),
};

await mkdir(out, { recursive: true });
const inputsDir = resolve(root, "inputs", "generated");
await writeFile(resolve(inputsDir, `${name}.json`), `${JSON.stringify(str(valid), null, 2)}\n`);

// Valid witness, then every negative must fail.
await wtns.calculate(str(valid), wasm, resolve(out, `${name}.wtns`));
cli("wtns", "check", r1cs, resolve(out, `${name}.wtns`));
const negativeResults = {};
for (const [label, input] of Object.entries(negatives)) {
  try {
    await wtns.calculate(str(input), wasm, resolve(out, "negative.wtns"));
    negativeResults[label] = "WITNESS_ACCEPTED";
  } catch {
    negativeResults[label] = "rejected";
  }
}

// Benchmark-only setup on the local ptau (single contributor; never deploy).
const zkey0 = resolve(out, `${name}_0000.zkey`), zkey = resolve(out, `${name}_final.zkey`);
const info = cli("r1cs", "info", r1cs);
cli("groth16", "setup", r1cs, ptau, zkey0);
cli("zkey", "contribute", zkey0, zkey, "--name=benchmark-only", `-e=${randomBytes(32).toString("hex")}`);
cli("zkey", "export", "verificationkey", zkey, resolve(out, "verification_key.json"));
cli("zkey", "export", "solidityverifier", zkey, resolve(root, "contracts", "generated", "Groth16VerifierPrivate128.sol"));
const vkey = JSON.parse(await readFile(resolve(out, "verification_key.json"), "utf8"));

const proveMs = [];
let proof, publicSignals;
for (let i = 0; i < REPS; i++) {
  const t0 = performance.now();
  ({ proof, publicSignals } = await groth16.fullProve(str(valid), wasm, zkey));
  proveMs.push(performance.now() - t0);
}
const verified = await groth16.verify(vkey, publicSignals, proof);
assert.equal(verified, true);
// A valid proof must not verify with a different nullifier or root.
const tampered = [...publicSignals];
tampered[8] = (BigInt(tampered[8]) + 1n).toString();
const tamperedRejected = !(await groth16.verify(vkey, tampered, proof));

// On-chain verifier gas, new (9 inputs) vs existing 128-D (5 inputs).
async function verifierGas() {
  const compile = async (file) => {
    const content = await readFile(resolve(root, "contracts", "generated", file), "utf8");
    const o = JSON.parse(solc.compile(JSON.stringify({ language: "Solidity", sources: { [file]: { content } },
      settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: "shanghai",
        outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } } } })));
    return o.contracts[file].Groth16Verifier;
  };
  const chain = ganache.provider({ chain: { chainId: 31337, hardfork: "shanghai" }, logging: { quiet: true },
    wallet: { deterministic: true, totalAccounts: 1 } });
  try {
    const signer = new ethers.providers.Web3Provider(chain).getSigner(0);
    const deploy = async (c) => (await new ethers.ContractFactory(c.abi, `0x${c.evm.bytecode.object}`, signer).deploy()).deployed();
    const vNew = await deploy(await compile("Groth16VerifierPrivate128.sol"));
    const calldata = JSON.parse(`[${await groth16.exportSolidityCallData(proof, publicSignals)}]`);
    const okNew = await vNew.verifyProof(...calldata);
    const txNew = await (await signer.sendTransaction({ to: vNew.address,
      data: vNew.interface.encodeFunctionData("verifyProof", calldata) })).wait();
    const old = JSON.parse(await readFile(resolve(root, "build", "gas", "results.json"), "utf8"));
    return { privateVerifierAccepts: okNew, privateVerifierTxGas: txNew.gasUsed.toNumber(),
      existing128VerifierTxGasRecorded: old.results[0].verification.medianGasUsed };
  } finally {
    await chain.disconnect();
  }
}
const gas = await verifierGas();

const median = (xs) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];
const constraints = Number(/# of Constraints:\s*(\d+)/.exec(info)?.[1]);
const record = {
  generatedAt: new Date().toISOString(),
  scope: "auth_private_128: AuthDistance(128) + credential tree (depth 20) + device tree (depth 10) + in-circuit EdDSA-Poseidon capture signature + scope nullifier",
  securityWarning: "Benchmark-only single-contributor Groth16 setup on local pot15; software EdDSA keys; synthetic vectors; never deploy.",
  constraints, publicInputs: 9, r1csInfo: info.trim().split("\n"),
  negatives: negativeResults, verified, tamperedNullifierRejected: tamperedRejected,
  proveMs: proveMs.map((x) => Math.round(x)), proveMedianMs: Math.round(median(proveMs)),
  gas,
};
await writeFile(resolve(out, "results.json"), `${JSON.stringify(record, null, 2)}\n`, "utf8");
process.stdout.write(`${JSON.stringify({ constraints, negatives: negativeResults, verified, tamperedRejected,
  proveMs: record.proveMs, gas }, null, 2)}\n`);
for (const [label, r] of Object.entries(negativeResults)) assert.equal(r, "rejected", label);
assert.equal(tamperedRejected, true);
if (globalThis.curve_bn128) await globalThis.curve_bn128.terminate();
process.exit(0);
