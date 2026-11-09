import { readFile, writeFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import os from "node:os";

const [mode, zkeyPath, witnessPath, repetitionsText, metricsPath, proofPath, publicPath] =
  process.argv.slice(2);
const repetitions = Number.parseInt(repetitionsText, 10);

const workerMode = /^cold-workers-(\d+)$/.exec(mode ?? "");
if (
  !(mode === "cold-single" || mode === "warm-multi" || workerMode) ||
  !zkeyPath ||
  !witnessPath ||
  !Number.isInteger(repetitions) ||
  repetitions <= 0 ||
  !metricsPath ||
  !proofPath ||
  !publicPath
) {
  throw new Error(
    "usage: prover-ablation-operation.mjs " +
      "<cold-single|cold-workers-N|warm-multi> <zkey> <witness> <repetitions> " +
      "<metrics.json> <proof.json> <public.json>",
  );
}

const hostCpuList = os.cpus();
const requestedWorkers = mode === "cold-single"
  ? 1
  : workerMode
    ? Number.parseInt(workerMode[1], 10)
    : hostCpuList.length;
if (
  !Number.isInteger(requestedWorkers) ||
  requestedWorkers < 1 ||
  requestedWorkers > hostCpuList.length
) {
  throw new RangeError(`worker count must be in [1, ${hostCpuList.length}]`);
}
if (workerMode) {
  os.cpus = () => hostCpuList.slice(0, requestedWorkers);
}
const { groth16 } = await import("snarkjs");

function bigintJson(value) {
  return JSON.stringify(
    value,
    (_, nested) => (typeof nested === "bigint" ? nested.toString() : nested),
    2,
  );
}

function memorySnapshot() {
  const usage = process.memoryUsage();
  return {
    rssMiB: usage.rss / 2 ** 20,
    heapUsedMiB: usage.heapUsed / 2 ** 20,
    externalMiB: usage.external / 2 ** 20,
    arrayBuffersMiB: usage.arrayBuffers / 2 ** 20,
  };
}

function roundedSnapshot(snapshot) {
  return Object.fromEntries(
    Object.entries(snapshot).map(([key, value]) => [key, Math.round(value * 100) / 100]),
  );
}

function delay(milliseconds) {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));
}

const singleThread = mode === "cold-single";
const proverOptions = singleThread ? { singleThread: true } : undefined;
const runs = [];
let lastResult;

for (let run = 0; run < repetitions; run += 1) {
  global.gc?.();
  await delay(25);
  const before = memorySnapshot();
  let sampledPeakRssMiB = before.rssMiB;
  const sampler = setInterval(() => {
    sampledPeakRssMiB = Math.max(
      sampledPeakRssMiB,
      process.memoryUsage().rss / 2 ** 20,
    );
  }, 5);

  const start = performance.now();
  lastResult = await groth16.prove(
    zkeyPath,
    witnessPath,
    undefined,
    proverOptions,
  );
  const elapsedMs = performance.now() - start;
  clearInterval(sampler);

  const after = memorySnapshot();
  sampledPeakRssMiB = Math.max(sampledPeakRssMiB, after.rssMiB);
  global.gc?.();
  await delay(25);
  const afterGc = memorySnapshot();

  runs.push({
    run: run + 1,
    elapsedMs: Math.round(elapsedMs * 100) / 100,
    before: roundedSnapshot(before),
    sampledPeakRssMiB: Math.round(sampledPeakRssMiB * 100) / 100,
    after: roundedSnapshot(after),
    afterGc: roundedSnapshot(afterGc),
  });
}

if (!lastResult || lastResult.publicSignals.length !== 5) {
  throw new Error("unexpected Groth16 output");
}

await Promise.all([
  writeFile(proofPath, `${bigintJson(lastResult.proof)}\n`, "utf8"),
  writeFile(publicPath, `${bigintJson(lastResult.publicSignals)}\n`, "utf8"),
]);

const workerConcurrency = singleThread
  ? 1
  : (globalThis.curve_bn128?.tm?.concurrency ?? null);
const record = {
  generatedAt: new Date().toISOString(),
  mode,
  singleThread,
  workerConcurrency,
  requestedWorkers,
  workerLimitMethod: workerMode
    ? "os.cpus() limited before importing snarkjs/ffjavascript in an isolated process"
    : null,
  repetitions,
  nodeHardwareConcurrency: globalThis.navigator?.hardwareConcurrency ?? null,
  scope:
    "groth16.prove only, using an existing .wtns and zkey; proof verification is performed by the parent benchmark outside the measured process",
  runs,
};
await writeFile(metricsPath, `${JSON.stringify(record, null, 2)}\n`, "utf8");

if (globalThis.curve_bn128?.terminate) {
  await globalThis.curve_bn128.terminate();
}
process.exit(0);
