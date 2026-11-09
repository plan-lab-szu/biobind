import { readFile, writeFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import { groth16, wtns } from "snarkjs";

const [mode, ...args] = process.argv.slice(2);

function usage() {
  throw new Error(
    "usage: benchmark-operation.mjs " +
      "witness <input.json> <circuit.wasm> <witness.wtns> <metrics.json> | " +
      "prove <zkey> <witness.wtns> <proof.json> <public.json> <metrics.json> | " +
      "verify <vkey.json> <public.json> <proof.json> <metrics.json>",
  );
}

function bigintJson(value) {
  return JSON.stringify(
    value,
    (_, nested) => (typeof nested === "bigint" ? nested.toString() : nested),
    2,
  );
}

global.gc?.();
const baselineRss = process.memoryUsage().rss;
let sampledPeakRss = baselineRss;
const sampler = setInterval(() => {
  sampledPeakRss = Math.max(sampledPeakRss, process.memoryUsage().rss);
}, 5);

let valid;
let metricsPath;
let start;

try {
  if (mode === "witness" && args.length === 4) {
    const [inputPath, wasmPath, witnessPath, outputMetricsPath] = args;
    metricsPath = outputMetricsPath;
    const input = JSON.parse(await readFile(inputPath, "utf8"));
    global.gc?.();
    start = performance.now();
    await wtns.calculate(input, wasmPath, witnessPath, {});
  } else if (mode === "prove" && args.length === 5) {
    const [zkeyPath, witnessPath, proofPath, publicPath, outputMetricsPath] = args;
    metricsPath = outputMetricsPath;
    global.gc?.();
    start = performance.now();
    const { proof, publicSignals } = await groth16.prove(zkeyPath, witnessPath);
    const elapsedMs = performance.now() - start;
    sampledPeakRss = Math.max(sampledPeakRss, process.memoryUsage().rss);
    await writeFile(proofPath, `${bigintJson(proof)}\n`, "utf8");
    await writeFile(publicPath, `${bigintJson(publicSignals)}\n`, "utf8");
    start = performance.now() - elapsedMs;
  } else if (mode === "verify" && args.length === 4) {
    const [vkeyPath, publicPath, proofPath, outputMetricsPath] = args;
    metricsPath = outputMetricsPath;
    const [vkey, publicSignals, proof] = await Promise.all(
      [vkeyPath, publicPath, proofPath].map(async (path) =>
        JSON.parse(await readFile(path, "utf8")),
      ),
    );
    global.gc?.();
    start = performance.now();
    valid = await groth16.verify(vkey, publicSignals, proof);
    if (!valid) {
      throw new Error("proof verification returned false");
    }
  } else {
    usage();
  }

  const elapsedMs = performance.now() - start;
  sampledPeakRss = Math.max(sampledPeakRss, process.memoryUsage().rss);
  clearInterval(sampler);
  await writeFile(
    metricsPath,
    `${JSON.stringify(
      {
        mode,
        elapsedMs: Math.round(elapsedMs * 100) / 100,
        baselineRssMiB: Math.round((baselineRss / 2 ** 20) * 100) / 100,
        sampledPeakRssMiB: Math.round((sampledPeakRss / 2 ** 20) * 100) / 100,
        valid,
      },
      null,
      2,
    )}\n`,
    "utf8",
  );
} finally {
  clearInterval(sampler);
}

// snarkjs/ffjavascript can retain worker-thread handles after an operation.
// All outputs are flushed above, so terminate the one-operation benchmark
// process explicitly instead of letting those handles contaminate wall time.
process.exit(0);
