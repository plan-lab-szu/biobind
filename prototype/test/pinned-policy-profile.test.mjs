import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import ganache from "ganache";
import solc from "solc";
import { ethers } from "ethers";
import { syntheticPolicySpec } from "../scripts/lib/canonical-policy.mjs";

const root = resolve(import.meta.dirname, "..");
const sourcePaths = [
  "UBCALifecycle.sol", "UBCAAuthGateway.sol", "BioZEROPinnedGateway.sol",
  "interfaces/IBioZKFHEUniquenessAdapter.sol",
  "generated/Groth16Verifier128.sol", "generated/Groth16Verifier512.sol",
];

async function compiledContracts() {
  const sources = Object.fromEntries(await Promise.all(sourcePaths.map(async (path) =>
    [path, { content: await readFile(resolve(root, "contracts", path), "utf8") }])));
  const output = JSON.parse(solc.compile(JSON.stringify({
    language: "Solidity", sources,
    settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: "shanghai",
      metadata: { bytecodeHash: "none" },
      outputSelection: { "*": { "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"] } } },
  })));
  const errors = (output.errors ?? []).filter(({ severity }) => severity === "error");
  assert.deepEqual(errors.map(({ formattedMessage }) => formattedMessage), []);
  return output.contracts;
}

async function rejects(call, label) {
  await assert.rejects(call, undefined, label);
}

test("pinned profile admits only matching 128/512-D verifier and circuit artifacts", async (t) => {
  const contracts = await compiledContracts();
  const chain = ganache.provider({ chain: { chainId: 31337, hardfork: "shanghai" },
    logging: { quiet: true }, miner: { blockGasLimit: 30_000_000 },
    wallet: { deterministic: true, totalAccounts: 3 } });
  t.after(() => chain.disconnect());
  const provider = new ethers.providers.Web3Provider(chain);
  const wallets = Object.values(chain.getInitialAccounts())
    .map(({ secretKey }) => new ethers.Wallet(secretKey, provider));
  const owner = wallets[0];
  const gatewayArtifact = contracts["BioZEROPinnedGateway.sol"].BioZEROPinnedGateway;
  assert.ok(gatewayArtifact.evm.deployedBytecode.object.length / 2 <= 24_576);
  const gatewayFactory = new ethers.ContractFactory(
    gatewayArtifact.abi, `0x${gatewayArtifact.evm.bytecode.object}`, owner);

  await rejects(() => gatewayFactory.deploy(wallets[1].address), "EOA verifier");
  for (const dimension of [128, 512]) {
    const verifierArtifact = contracts[`generated/Groth16Verifier${dimension}.sol`].Groth16Verifier;
    const verifier = await new ethers.ContractFactory(
      verifierArtifact.abi, `0x${verifierArtifact.evm.bytecode.object}`, owner).deploy();
    await verifier.deployTransaction.wait();
    const gateway = await gatewayFactory.deploy(verifier.address);
    await gateway.deployTransaction.wait();

    const actualVerifierHash = ethers.utils.keccak256(await provider.getCode(verifier.address));
    const pinnedVerifierHash = await gateway[`VERIFIER${dimension}_CODEHASH`]();
    assert.equal(actualVerifierHash, pinnedVerifierHash);
    assert.equal(Number(await gateway.pinnedDimension()), dimension);
    const r1cs = await readFile(resolve(root, "build", `auth_distance_${dimension}`,
      `auth_distance_${dimension}.r1cs`));
    const actualCircuitHash = `0x${createHash("sha256").update(r1cs).digest("hex")}`;
    assert.equal(actualCircuitHash, await gateway.pinnedCircuitHash());

    const modelHash = ethers.utils.id(`profile/model/${dimension}`);
    const quantizationHash = ethers.utils.id("profile/u16");
    const spec = { ...syntheticPolicySpec({ label: `profile/${dimension}`,
      modelHash, quantizationHash, epsilon: 271, dimension }),
      circuitHash: actualCircuitHash };
    await rejects(() => gateway.registerCanonicalPolicy({ ...spec,
      dimension: dimension === 128 ? 512 : 128 }), "wrong dimension");
    await rejects(() => gateway.registerCanonicalPolicy({ ...spec,
      circuitHash: ethers.utils.id("wrong circuit") }), "wrong circuit");
    const policyHash = await gateway.canonicalPolicyHash(spec);
    await (await gateway.registerCanonicalPolicy(spec)).wait();
    assert.equal(await gateway.canonicalPolicyRegistered(policyHash), true);
    assert.equal((await gateway.policyMatchThresholds(policyHash)).toNumber(), 271);
    await rejects(() => gateway.connect(wallets[1]).registerCanonicalPolicy(spec),
      "unauthorized registration");
  }
});
