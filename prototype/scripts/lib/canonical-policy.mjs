import { ethers } from "ethers";

const hash = (value) => ethers.utils.id(value);

// Synthetic-only policy builder for local protocol tests and benchmarks.
// A journal run must replace the descriptive hashes with artifact hashes.
export function syntheticPolicySpec({ label, modelHash, quantizationHash, epsilon, dimension = 128 }) {
  if (!label || !modelHash || !quantizationHash) throw new Error("policy inputs missing");
  return {
    applicationId: hash(`${label}/application`),
    modelHash,
    preprocessingHash: hash(`${label}/preprocessing-fixture`),
    quantizationHash,
    circuitHash: hash(`${label}/circuit-fixture/${dimension}`),
    budgetPolicyHash: hash(`${label}/budget-fixture`),
    dimension,
    coordinateBits: 16,
    quantizedMax: 65535,
    metricId: 1,
    commitmentFormatVersion: 1,
    distanceBits: 48,
    epsilon,
  };
}

export async function registerSyntheticPolicy(gateway, params) {
  const spec = syntheticPolicySpec(params);
  const policyHash = await gateway.canonicalPolicyHash(spec);
  await (await gateway.registerCanonicalPolicy(spec)).wait();
  return { policyHash, spec };
}
