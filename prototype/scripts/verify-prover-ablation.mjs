import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import { groth16 } from "snarkjs";

const prototypeRoot = resolve(import.meta.dirname, "..");
const circuits = ["auth_distance_128", "auth_distance_512"];
let checked = 0;

for (const circuit of circuits) {
  const outputRoot = resolve(prototypeRoot, "build", "prover-ablation", circuit);
  const verificationKey = JSON.parse(
    await readFile(
      resolve(
        prototypeRoot,
        "build",
        "proving",
        circuit,
        "verification_key.json",
      ),
      "utf8",
    ),
  );
  const proofFiles = (await readdir(outputRoot))
    .filter((name) => name.endsWith(".proof.json"))
    .sort();

  for (const proofFile of proofFiles) {
    const stem = proofFile.slice(0, -".proof.json".length);
    const [proof, publicSignals] = await Promise.all([
      readFile(resolve(outputRoot, proofFile), "utf8").then(JSON.parse),
      readFile(resolve(outputRoot, `${stem}.public.json`), "utf8").then(JSON.parse),
    ]);
    if (!(await groth16.verify(verificationKey, publicSignals, proof))) {
      throw new Error(`invalid ablation proof: ${circuit}/${proofFile}`);
    }
    checked += 1;
  }
}

process.stdout.write(`Verified ${checked} prover-ablation proofs.\n`);
if (globalThis.curve_bn128?.terminate) {
  await globalThis.curve_bn128.terminate();
}
process.exit(0);
