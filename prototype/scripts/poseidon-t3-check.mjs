// Checks contracts/PoseidonT3.sol against circomlibjs Poseidon(2) on random and
// edge inputs, and measures the in-EVM gas of one hash (gasleft difference) for
// the internal library versus an external call to the circomlibjs-generated
// Poseidon contract. Local Ganache only.
// Usage (from prototype/): .toolchain/node-v24.19.0-win-x64/node.exe scripts/poseidon-t3-check.mjs
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { buildPoseidon, poseidonContract } from "circomlibjs";
import ganache from "ganache";
import solc from "solc";
import { ethers } from "ethers";

const root = resolve(import.meta.dirname, "..");
const out = resolve(root, "build", "poseidon-t3");
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const poseidon = await buildPoseidon();
const H = (a, b) => poseidon.F.toObject(poseidon([a, b]));

const harness = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "PoseidonT3.sol";
interface IPoseidon2 { function poseidon(uint256[2] calldata inputs) external pure returns (uint256); }
contract PoseidonT3Harness {
    function hash(uint256 a, uint256 b) external pure returns (uint256) { return PoseidonT3.hash(a, b); }
    function hashGas(uint256 a, uint256 b) external view returns (uint256 h, uint256 used) {
        uint256 g = gasleft();
        h = PoseidonT3.hash(a, b);
        used = g - gasleft();
    }
    function externalGas(IPoseidon2 p, uint256 a, uint256 b) external view returns (uint256 h, uint256 used) {
        uint256 g = gasleft();
        h = p.poseidon([a, b]);
        used = g - gasleft();
    }
}`;
const compiled = JSON.parse(solc.compile(JSON.stringify({
  language: "Solidity",
  sources: { "PoseidonT3.sol": { content: await readFile(resolve(root, "contracts", "PoseidonT3.sol"), "utf8") },
    "Harness.sol": { content: harness } },
  settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: "shanghai",
    outputSelection: { "*": { "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"] } } },
})));
const errors = (compiled.errors ?? []).filter((e) => e.severity === "error");
assert.equal(errors.length, 0, errors.map((e) => e.formattedMessage).join("\n"));
const h = compiled.contracts["Harness.sol"].PoseidonT3Harness;

const chain = ganache.provider({ chain: { chainId: 31337, hardfork: "shanghai" }, logging: { quiet: true },
  wallet: { deterministic: true, totalAccounts: 1 } });
const record = { generatedAt: new Date().toISOString() };
try {
  const signer = new ethers.providers.Web3Provider(chain).getSigner(0);
  const c = await (await new ethers.ContractFactory(h.abi, `0x${h.evm.bytecode.object}`, signer).deploy()).deployed();
  const ext = await (await new ethers.ContractFactory(poseidonContract.generateABI(2), poseidonContract.createCode(2), signer).deploy()).deployed();
  const rnd = () => BigInt(`0x${randomBytes(32).toString("hex")}`) % R;
  const cases = [[0n, 0n], [1n, 2n], [R - 1n, R - 1n], [0n, R - 1n], [R - 1n, 0n]];
  for (let i = 0; i < 64; i++) cases.push([rnd(), rnd()]);
  let mismatches = 0;
  const lib = [], external = [];
  for (const [a, b] of cases) {
    const [hv, used] = await c.hashGas(a, b);
    const [he, usedExt] = await c.externalGas(ext.address, a, b);
    if (hv.toString() !== H(a, b).toString() || he.toString() !== hv.toString()) mismatches += 1;
    lib.push(used.toNumber());
    external.push(usedExt.toNumber());
  }
  const med = (xs) => [...xs].sort((x, y) => x - y)[Math.floor(xs.length / 2)];
  Object.assign(record, {
    scope: "PoseidonT3 (generated inline assembly, internal library) vs circomlibjs Poseidon(2) and the circomlibjs-generated contract; solc " + solc.version() + ", optimizer 200, Shanghai, Ganache 7.9.2",
    cases: cases.length, mismatches,
    libraryHashGasMedian: med(lib), libraryHashGasRange: [Math.min(...lib), Math.max(...lib)],
    circomlibjsExternalCallGasMedian: med(external),
    harnessRuntimeBytes: h.evm.deployedBytecode.object.length / 2,
  });
} finally {
  await chain.disconnect();
}
await mkdir(out, { recursive: true });
await writeFile(resolve(out, "result.json"), `${JSON.stringify(record, null, 2)}\n`, "utf8");
process.stdout.write(`${JSON.stringify(record, null, 2)}\n`);
assert.equal(record.mismatches, 0);
