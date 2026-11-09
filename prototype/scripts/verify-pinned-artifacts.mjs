import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { promisify } from "node:util";
import solc from "solc";
import { ethers } from "ethers";

const execFileAsync = promisify(execFile);
const root = resolve(import.meta.dirname, "..");
const outputRoot = resolve(root, "build", "pinned-profile");
const verifierCli = resolve(root, "node_modules", "snarkjs", "build", "cli.cjs");
const pinnedSource = await readFile(resolve(root, "contracts", "BioZEROPinnedGateway.sol"), "utf8");

function pinnedConstant(name) {
  const match = pinnedSource.match(new RegExp(`${name}\\s*=\\s*(0x[0-9a-fA-F]{64})`));
  assert.ok(match, `missing pinned constant ${name}`);
  return match[1].toLowerCase();
}

async function sha256File(path) {
  const bytes = await readFile(resolve(root, path));
  return { path: path.replaceAll("\\", "/"), bytes: bytes.length,
    sha256: `0x${createHash("sha256").update(bytes).digest("hex")}` };
}

async function cli(...args) {
  const { stdout, stderr } = await execFileAsync(process.execPath,
    [verifierCli, ...args], { cwd: root, maxBuffer: 8 * 1024 * 1024 });
  return `${stdout}\n${stderr}`.replace(/\x1b\[[0-9;]*m/g, "");
}

await mkdir(outputRoot, { recursive: true });
const profiles = [];
for (const dimension of [128, 512]) {
  const stem = `auth_distance_${dimension}`;
  const circuit = `build/${stem}/${stem}.r1cs`;
  const wasm = `build/${stem}/${stem}_js/${stem}.wasm`;
  const provingKey = `build/proving/${stem}/${stem}_benchmark_final.zkey`;
  const verificationKey = `build/proving/${stem}/verification_key.json`;
  const verifierSource = `contracts/generated/Groth16Verifier${dimension}.sol`;
  const files = await Promise.all([
    `circuits/${stem}.circom`, "circuits/auth_distance.circom",
    "circuits/lib/poseidon_chain.circom", "circuits/lib/vector_packing.circom",
    circuit, wasm, provingKey, verificationKey, verifierSource,
  ].map(sha256File));
  const fileByPath = Object.fromEntries(files.map((file) => [file.path, file]));
  const expectedR1cs = pinnedConstant(`CIRCUIT${dimension}_R1CS_SHA256`);
  assert.equal(fileByPath[circuit].sha256, expectedR1cs,
    `${dimension}-D circuit changed without updating the pinned profile`);

  const verification = await cli("zkey", "verify", circuit,
    "build/proving/local-benchmark-setup/pot15_final.ptau", provingKey);
  assert.match(verification, /ZKey Ok!/);

  const exportedVk = resolve(outputRoot, `verification_key_${dimension}.export.json`);
  await cli("zkey", "export", "verificationkey", provingKey, exportedVk);
  assert.deepEqual(JSON.parse(await readFile(exportedVk, "utf8")),
    JSON.parse(await readFile(resolve(root, verificationKey), "utf8")),
    `${dimension}-D verification key differs from zkey`);

  const exportedVerifier = resolve(outputRoot, `Groth16Verifier${dimension}.export.sol`);
  await cli("zkey", "export", "solidityverifier", provingKey, exportedVerifier);
  const normalized = (text) => text.replaceAll("\r\n", "\n").trimEnd();
  assert.equal(normalized(await readFile(exportedVerifier, "utf8")),
    normalized(await readFile(resolve(root, verifierSource), "utf8")),
    `${dimension}-D generated verifier differs from zkey export`);

  const compiled = JSON.parse(solc.compile(JSON.stringify({
    language: "Solidity", sources: { [verifierSource]: {
      content: await readFile(resolve(root, verifierSource), "utf8") } },
    settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: "shanghai",
      metadata: { bytecodeHash: "none" },
      outputSelection: { "*": { "*": ["evm.deployedBytecode.object"] } } },
  })));
  const errors = (compiled.errors ?? []).filter(({ severity }) => severity === "error");
  assert.deepEqual(errors.map(({ formattedMessage }) => formattedMessage), []);
  const bytecode = compiled.contracts[verifierSource].Groth16Verifier.evm.deployedBytecode.object;
  const runtimeCodeHash = ethers.utils.keccak256(`0x${bytecode}`);
  assert.equal(runtimeCodeHash, pinnedConstant(`VERIFIER${dimension}_CODEHASH`),
    `${dimension}-D verifier runtime changed without updating the pinned profile`);

  profiles.push({ dimension, r1csSha256: expectedR1cs, verifierRuntimeCodeHash: runtimeCodeHash,
    verifierRuntimeBytes: bytecode.length / 2, zkeyVerifiedAgainstR1csAndPtau: true,
    exportedVerificationKeyMatches: true, exportedSolidityVerifierMatches: true,
    files });
  process.stdout.write(`Verified pinned ${dimension}-D profile\n`);
}

const manifest = {
  scope: "local benchmark artifacts only; single-machine setup is not a production ceremony",
  compiler: { version: solc.version(), optimizerRuns: 200, evmVersion: "shanghai",
    bytecodeHash: "none" },
  node: process.version,
  powersOfTau: await sha256File("build/proving/local-benchmark-setup/pot15_final.ptau"),
  pinnedGatewaySource: await sha256File("contracts/BioZEROPinnedGateway.sol"),
  gatewaySource: await sha256File("contracts/UBCAAuthGateway.sol"),
  lifecycleSource: await sha256File("contracts/UBCALifecycle.sol"),
  profiles,
};
const manifestPath = resolve(outputRoot, "artifact-manifest.json");
await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
process.stdout.write(`Wrote ${manifestPath}\n`);
