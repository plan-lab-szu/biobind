import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DST_ENROLL,
  DST_PROBE,
  poseidonCommitment,
  squaredDistance,
} from "./commitment.mjs";

const scriptRoot = dirname(fileURLToPath(import.meta.url));
const prototypeRoot = resolve(scriptRoot, "..");
const outputRoot = resolve(prototypeRoot, "inputs", "generated");

function deterministicVectors(dimension) {
  const enrollment = Array.from({ length: dimension }, (_, index) =>
    BigInt(10000 + ((index * 257) % 30000)),
  );
  const probe = enrollment.map((value, index) => value + BigInt((index % 5) - 2));
  return { enrollment, probe };
}

function stringifyBigInts(value) {
  return JSON.stringify(
    value,
    (_, nestedValue) => (typeof nestedValue === "bigint" ? nestedValue.toString() : nestedValue),
    2,
  );
}

async function buildAuthInput(dimension, packSize) {
  const policyDigest = 9876543210123456789n + BigInt(dimension);
  const ctxHash = 12345678900987654321n + BigInt(dimension);
  const rEnroll = 11111111111111111111n + BigInt(dimension);
  const rProbe = 22222222222222222222n + BigInt(dimension);
  const { enrollment, probe } = deterministicVectors(dimension);
  const distance = squaredDistance(enrollment, probe);
  const epsilon = distance + 16n;

  const cEnroll = await poseidonCommitment({
    roleTag: DST_ENROLL,
    policyDigest,
    contextDigest: 0n,
    dimension,
    salt: rEnroll,
    values: enrollment,
    packSize,
  });
  const cProbe = await poseidonCommitment({
    roleTag: DST_PROBE,
    policyDigest,
    contextDigest: ctxHash,
    dimension,
    salt: rProbe,
    values: probe,
    packSize,
  });

  return {
    cEnroll,
    cProbe,
    policyDigest,
    ctxHash,
    epsilon,
    rEnroll,
    rProbe,
    enrollment,
    probe,
  };
}

async function writeJson(name, value) {
  const outputPath = resolve(outputRoot, name);
  await writeFile(outputPath, `${stringifyBigInts(value)}\n`, "utf8");
  return outputPath;
}

async function generate(dimension) {
  const packedInput = await buildAuthInput(dimension, 15);
  const unpackedInput = await buildAuthInput(dimension, 1);
  const distance = squaredDistance(packedInput.enrollment, packedInput.probe);

  const packedPath = await writeJson(`auth_distance_${dimension}.json`, packedInput);
  const unpackedPath = await writeJson(
    `auth_distance_${dimension}_unpacked.json`,
    unpackedInput,
  );
  const distanceOnlyPath = await writeJson(`distance_only_${dimension}.json`, {
    epsilon: packedInput.epsilon,
    enrollment: packedInput.enrollment,
    probe: packedInput.probe,
  });

  process.stdout.write(
    `generated ${packedPath}, ${unpackedPath}, ${distanceOnlyPath}; distance=${distance}\n`,
  );
}

async function generateInvalid128() {
  const valid = await buildAuthInput(128, 15);
  const distance = squaredDistance(valid.enrollment, valid.probe);

  await writeJson("context_mismatch.json", {
    ...valid,
    ctxHash: valid.ctxHash + 1n,
  });
  await writeJson("threshold_fail.json", {
    ...valid,
    epsilon: distance - 1n,
  });
  await writeJson("coordinate_out_of_range.json", {
    ...valid,
    enrollment: [65536n, ...valid.enrollment.slice(1)],
  });
}

await mkdir(outputRoot, { recursive: true });
await generate(128);
await generate(512);
await generateInvalid128();
