import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  detectionProbability,
  minimumSamplesForDetection,
  sampleCount,
} from "./lib/sampling.mjs";

const prototypeRoot = resolve(import.meta.dirname, "..");
const outputRoot = resolve(prototypeRoot, "build", "baselines");

const oldPaper128 = {
  source: "ISC_2026_paper_7168.pdf, Section 6.3, Table 1 and Figure 3",
  fixedGroth16Gas: 271_200,
  rows: [
    { lambda: 1, reportedSpotGas: 701_400, reportedFivePercent: 0.2914 },
    { lambda: 2, reportedSpotGas: 981_900, reportedFivePercent: 0.4979 },
    { lambda: 4, reportedSpotGas: 1_568_200, reportedFivePercent: 0.7479 },
    { lambda: 8, reportedSpotGas: 2_874_200, reportedFivePercent: 0.9712 },
  ],
};

function percentage(probability) {
  return `${(probability * 100).toFixed(2)}%`;
}

function ratio(numerator, denominator) {
  return Number((numerator / denominator).toFixed(3));
}

const verifierResults = JSON.parse(
  await readFile(resolve(prototypeRoot, "build", "gas", "results.json"), "utf8"),
);
const gatewayResults = JSON.parse(
  await readFile(
    resolve(prototypeRoot, "build", "gateway", "results.json"),
    "utf8",
  ),
);
const pedersenGasResults = JSON.parse(
  await readFile(
    resolve(prototypeRoot, "build", "pedersen-gas", "results.json"),
    "utf8",
  ),
);
const routeA128 = verifierResults.results.find(({ dimension }) => dimension === 128);
const gateway128 = gatewayResults.results.find(({ dimension }) => dimension === 128);
if (!routeA128 || !gateway128) {
  throw new Error("128D Route A verifier/gateway results are missing");
}

const dimensions = [128, 512];
const lambdas = [1, 2, 4, 8];
const sampling = dimensions.map((dimension) => {
  const nearFivePercentBadCoordinates = Math.round(dimension * 0.05);
  return {
    dimension,
    nearFivePercentBadCoordinates,
    nearFivePercentActualFraction:
      nearFivePercentBadCoordinates / dimension,
    rows: lambdas.map((lambda) => {
      const samples = sampleCount(dimension, lambda);
      return {
        lambda,
        samples,
        coverage: samples / dimension,
        oneBadCoordinateDetection: detectionProbability(dimension, 1, samples),
        nearFivePercentDetection: detectionProbability(
          dimension,
          nearFivePercentBadCoordinates,
          samples,
        ),
      };
    }),
    samplesRequiredForOneBadCoordinate: [0.95, 0.99, 1].map(
      (targetDetection) => ({
        targetDetection,
        samples: minimumSamplesForDetection(dimension, 1, targetDetection),
      }),
    ),
  };
});

const paperAudit = oldPaper128.rows.map((paperRow) => {
  const recomputed = sampling[0].rows.find(
    ({ lambda }) => lambda === paperRow.lambda,
  );
  const totalReportedCryptographicGas =
    oldPaper128.fixedGroth16Gas + paperRow.reportedSpotGas;
  return {
    ...paperRow,
    samples: recomputed.samples,
    recomputedOneBadCoordinateDetection: recomputed.oneBadCoordinateDetection,
    recomputedFivePercentDetection: recomputed.nearFivePercentDetection,
    fivePercentPercentagePointDifference:
      100 *
      (paperRow.reportedFivePercent - recomputed.nearFivePercentDetection),
    totalReportedCryptographicGas,
    ratioToRouteAPureVerifier: ratio(
      totalReportedCryptographicGas,
      routeA128.verification.medianGasUsed,
    ),
    ratioToRouteAAnchoredFirstAuthentication: ratio(
      totalReportedCryptographicGas,
      gateway128.anchoredAuthentication.first.transactionGas,
    ),
  };
});

const record = {
  generatedAt: new Date().toISOString(),
  scope:
    "Recomputed sampling soundness plus an audit of gas values reported by the old BioZero manuscript; this is not a fresh Pedersen EVM remeasurement.",
  roundingRule:
    "The near-5% case uses round(0.05*N): w=6 at N=128 and w=26 at N=512.",
  oldPaper128,
  routeA128: {
    pureVerifierGas: routeA128.verification.medianGasUsed,
    statefulAuthenticationGas: gateway128.authentication.transactionGas,
    statefulChallengeGas: gateway128.setupTransactions.issueChallengeGas,
    anchoredFirstAuthenticationGas:
      gateway128.anchoredAuthentication.first.transactionGas,
    anchoredSteadyAuthenticationGas:
      gateway128.anchoredAuthentication.steady.transactionGas,
  },
  sameHarnessPedersenKernel: pedersenGasResults,
  sampling,
  paperAudit,
  comparisonWarning:
    "Old reported gas and current Route A gas were measured in different implementations. Ratios are orientation only until both relations run in one harness.",
};

const table128 = paperAudit
  .map(
    (row) =>
      `| ${row.lambda} | ${row.samples} | ${percentage(row.recomputedOneBadCoordinateDetection)} | ` +
      `${percentage(row.recomputedFivePercentDetection)} | ${percentage(row.reportedFivePercent)} | ` +
      `${row.reportedSpotGas.toLocaleString("en-US")} | ${row.totalReportedCryptographicGas.toLocaleString("en-US")} |`,
  )
  .join("\n");

const table512 = sampling[1].rows
  .map(
    (row) =>
      `| ${row.lambda} | ${row.samples} | ${percentage(row.coverage)} | ` +
      `${percentage(row.oneBadCoordinateDetection)} | ${percentage(row.nearFivePercentDetection)} |`,
  )
  .join("\n");

const measuredPedersenTable = pedersenGasResults.results
  .map(
    (row) =>
      `| ${row.label} | ${row.samples} | ${percentage(row.oneBadCoordinateDetection)} | ` +
      `${row.medianGasUsed.toLocaleString("en-US")} | ${row.medianExecutionGasAfterIntrinsic.toLocaleString("en-US")} | ` +
      `${row.calldata.bytes.toLocaleString("en-US")} | ${
        row.unsampledTargetTamperAccepted ? "accepted" : "rejected"
      } |`,
  )
  .join("\n");

const report = `# Legacy Pedersen sampling baseline audit

Generated: ${record.generatedAt}

## Scope

This is a reproducible audit of the exact without-replacement sampling formula and a transcription of the old manuscript's reported gas. It is **not** a new Pedersen contract measurement. Gas ratios are orientation only until both designs run in the same harness.

## 128-dimensional audit

The near-5% case is six bad coordinates (4.6875%), matching the old table's lambda=1 and lambda=8 values.

| lambda | samples | one bad: exact detection | six bad: exact detection | old table "5%" | reported spot gas | reported spot + Groth16 gas |
|---:|---:|---:|---:|---:|---:|---:|
${table128}

The old table's lambda=2 and lambda=4 "5%" entries do not equal the stated exact hypergeometric formula: recomputation gives 50.83% and 78.02%, rather than 49.79% and 74.79%. The lambda=1 and lambda=8 entries do match six bad coordinates.

For one corrupted coordinate, detection is exactly t/N. At N=128, 95%, 99%, and deterministic detection require 122, 127, and 128 sampled coordinates respectively.

## 512-dimensional soundness projection

This table projects sampling probability only; it does not extrapolate gas.

| lambda | samples | coordinate coverage | one bad: detection | 26 bad: detection |
|---:|---:|---:|---:|---:|
${table512}

At N=512, 95%, 99%, and deterministic detection of one corrupted coordinate require 487, 507, and 512 samples respectively.

## Same-harness BN254 Pedersen kernel

The following values were freshly measured with the same Node.js, solc, Ganache, optimizer, and Shanghai configuration as Route A. The kernel executes six consistency equations per sampled coordinate and reconstructs the distance commitment across all 128 coordinates. It deliberately excludes Fiat-Shamir sample derivation, enrollment storage, nonce state, and the legacy threshold Groth16 verifier, so it is not the full old protocol.

| case | samples | one bad: detection | transaction gas | execution after intrinsic | calldata bytes | tamper at coordinate 127 |
|---|---:|---:|---:|---:|---:|---|
${measuredPedersenTable}

The reconstruction-only row is not an authentication mode; it isolates the unavoidable O(N) product-commitment transport and reconstruction in the old relation. For every partial-check row, changing the unsampled coordinate 127 is accepted and changes the reconstructed commitment. FullCheck rejects the same modification.

## Current Route A reference

- Pure Groth16 verifier: ${record.routeA128.pureVerifierGas.toLocaleString("en-US")} gas.
- Stateful authentication transaction: ${record.routeA128.statefulAuthenticationGas.toLocaleString("en-US")} gas, plus ${record.routeA128.statefulChallengeGas.toLocaleString("en-US")} gas for the first challenge transaction.
- Anchored first/steady authentication: ${record.routeA128.anchoredFirstAuthenticationGas.toLocaleString("en-US")} / ${record.routeA128.anchoredSteadyAuthenticationGas.toLocaleString("en-US")} gas.
- The new relation checks every coordinate inside the circuit and has no sampling-miss term. Its prover time, proving-key size, and memory still scale with dimension.
`;

await mkdir(outputRoot, { recursive: true });
await writeFile(
  resolve(outputRoot, "pedersen-sampling-results.json"),
  `${JSON.stringify(record, null, 2)}\n`,
  "utf8",
);
await writeFile(
  resolve(outputRoot, "PEDERSEN_SAMPLING_AUDIT.md"),
  report,
  "utf8",
);

process.stdout.write(
  `Wrote Pedersen sampling audit. Old N=128 lambda=1 total=${paperAudit[0].totalReportedCryptographicGas} gas; ` +
    `Route A pure verifier=${record.routeA128.pureVerifierGas} gas.\n`,
);
