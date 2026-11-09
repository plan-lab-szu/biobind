import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { buildBn128 } from "ffjavascript";
import ganache from "ganache";
import solc from "solc";
import { ethers } from "ethers";
import { detectionProbability, sampleCount } from "./lib/sampling.mjs";

const prototypeRoot = resolve(import.meta.dirname, "..");
const outputRoot = resolve(prototypeRoot, "build", "pedersen-gas");
const dimension = 128;
const repetitions = 3;
const challenge = 17n;
const hDiscreteLog = 5n;

function mod(value, modulus) {
  const reduced = value % modulus;
  return reduced >= 0n ? reduced : reduced + modulus;
}

function median(values) {
  const ordered = [...values].sort((a, b) => a - b);
  return ordered[Math.floor(ordered.length / 2)];
}

function calldataCost(hexData) {
  const bytes = ethers.utils.arrayify(hexData);
  let zeroBytes = 0;
  for (const value of bytes) {
    if (value === 0) zeroBytes += 1;
  }
  const nonzeroBytes = bytes.length - zeroBytes;
  return {
    bytes: bytes.length,
    zeroBytes,
    nonzeroBytes,
    gas: zeroBytes * 4 + nonzeroBytes * 16,
  };
}

async function compileContract() {
  const source = await readFile(
    resolve(prototypeRoot, "contracts", "PedersenSamplingVerifier.sol"),
    "utf8",
  );
  const input = {
    language: "Solidity",
    sources: { "PedersenSamplingVerifier.sol": { content: source } },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: "shanghai",
      outputSelection: {
        "*": { "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"] },
      },
    },
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors ?? []).filter(({ severity }) => severity === "error");
  if (errors.length > 0) {
    throw new Error(errors.map(({ formattedMessage }) => formattedMessage).join("\n"));
  }
  return output.contracts["PedersenSamplingVerifier.sol"].PedersenSamplingVerifier;
}

function buildTranscript(curve) {
  const scalarField = curve.r;
  const pointCache = new Map();

  function pointFromScalar(rawScalar) {
    const scalar = mod(rawScalar, scalarField);
    const key = scalar.toString();
    if (!pointCache.has(key)) {
      if (scalar === 0n) {
        pointCache.set(key, { x: "0", y: "0" });
      } else {
        const affine = curve.G1.toAffine(
          curve.G1.timesScalar(curve.G1.one, scalar),
        );
        const [x, y] = curve.G1.toObject(affine);
        pointCache.set(key, { x: x.toString(), y: y.toString() });
      }
    }
    return pointCache.get(key);
  }

  function commitmentScalar(message, randomness) {
    return mod(message + hDiscreteLog * randomness, scalarField);
  }

  function relation({
    coordinate,
    relationTag,
    sourceMessage,
    sourceRandomness,
    multiplicationBaseCommitment,
    multiplierRandomness,
    targetRandomness,
  }) {
    const tagOffset = BigInt(relationTag * 10_000 + coordinate * 100);
    const b1 = 101n + tagOffset;
    const b2 = 203n + tagOffset;
    const b3 = 307n + tagOffset;
    const alphaScalar = commitmentScalar(b1, b2);
    const betaScalar = mod(
      b1 * multiplicationBaseCommitment + hDiscreteLog * b3,
      scalarField,
    );
    return {
      alpha: pointFromScalar(alphaScalar),
      beta: pointFromScalar(betaScalar),
      zM: mod(b1 + challenge * sourceMessage, scalarField).toString(),
      zR: mod(b2 + challenge * sourceRandomness, scalarField).toString(),
      zU: mod(
        b3 +
          challenge *
            (targetRandomness - multiplierRandomness * sourceMessage),
        scalarField,
      ).toString(),
    };
  }

  const c00 = [];
  const c11 = [];
  const c01 = [];
  const samples = [];
  let distanceScalar = 0n;

  for (let index = 0; index < dimension; index += 1) {
    const i = BigInt(index);
    const m0 = 100n + i;
    const m1 = m0 + BigInt(index % 3);
    const r0 = 1_000n + 3n * i;
    const r1 = 2_000n + 5n * i;
    const r00 = 3_000n + 7n * i;
    const r11 = 4_000n + 11n * i;
    const r01 = 5_000n + 13n * i;

    const c0Scalar = commitmentScalar(m0, r0);
    const c1Scalar = commitmentScalar(m1, r1);
    const c00Scalar = commitmentScalar(m0 * m0, r00);
    const c11Scalar = commitmentScalar(m1 * m1, r11);
    const c01Scalar = commitmentScalar(m0 * m1, r01);

    c00.push(pointFromScalar(c00Scalar));
    c11.push(pointFromScalar(c11Scalar));
    c01.push(pointFromScalar(c01Scalar));
    distanceScalar = mod(
      distanceScalar + c00Scalar + c11Scalar - 2n * c01Scalar,
      scalarField,
    );

    samples.push({
      index,
      c0: pointFromScalar(c0Scalar),
      c1: pointFromScalar(c1Scalar),
      square0: relation({
        coordinate: index,
        relationTag: 0,
        sourceMessage: m0,
        sourceRandomness: r0,
        multiplicationBaseCommitment: c0Scalar,
        multiplierRandomness: r0,
        targetRandomness: r00,
      }),
      square1: relation({
        coordinate: index,
        relationTag: 1,
        sourceMessage: m1,
        sourceRandomness: r1,
        multiplicationBaseCommitment: c1Scalar,
        multiplierRandomness: r1,
        targetRandomness: r11,
      }),
      cross01: relation({
        coordinate: index,
        relationTag: 2,
        sourceMessage: m1,
        sourceRandomness: r1,
        multiplicationBaseCommitment: c0Scalar,
        multiplierRandomness: r0,
        targetRandomness: r01,
      }),
    });
  }

  return {
    c00,
    c11,
    c01,
    samples,
    expectedDistance: pointFromScalar(distanceScalar),
  };
}

const compiled = await compileContract();
const curve = await buildBn128();
let eip1193;

try {
  const transcript = buildTranscript(curve);
  const expectedDistanceDigest = ethers.utils.keccak256(
    ethers.utils.defaultAbiCoder.encode(
      ["uint256", "uint256"],
      [transcript.expectedDistance.x, transcript.expectedDistance.y],
    ),
  );
  eip1193 = ganache.provider({
    chain: { chainId: 31337, hardfork: "shanghai" },
    miner: { blockGasLimit: 30_000_000 },
    logging: { quiet: true },
    wallet: { deterministic: true, totalAccounts: 2 },
  });
  const provider = new ethers.providers.Web3Provider(eip1193);
  const signer = provider.getSigner(0);
  const factory = new ethers.ContractFactory(
    compiled.abi,
    `0x${compiled.evm.bytecode.object}`,
    signer,
  );
  const contract = await factory.deploy(dimension);
  const deploymentReceipt = await contract.deployTransaction.wait();

  const cases = [1, 2, 4, 8].map((lambda) => ({
    label: `lambda-${lambda}`,
    lambda,
    samples: sampleCount(dimension, lambda),
  }));
  cases.unshift({ label: "reconstruction-only", lambda: null, samples: 0 });
  cases.push({ label: "full-check", lambda: null, samples: dimension });

  const results = [];
  for (const benchmarkCase of cases) {
    const sampleProofs = transcript.samples.slice(0, benchmarkCase.samples);
    const args = {
      challenge: challenge.toString(),
      c00: transcript.c00,
      c11: transcript.c11,
      c01: transcript.c01,
      samples: sampleProofs,
    };
    const staticResult = await contract.callStatic.verifySpot(args);
    if (staticResult !== expectedDistanceDigest) {
      throw new Error(`${benchmarkCase.label} reconstructed the wrong distance`);
    }

    let modifiedResponseRejected = null;
    if (sampleProofs.length > 0) {
      const tamperedProofs = structuredClone(sampleProofs);
      tamperedProofs[0].square0.zM = (
        BigInt(tamperedProofs[0].square0.zM) + 1n
      ).toString();
      modifiedResponseRejected = false;
      try {
        await contract.callStatic.verifySpot({ ...args, samples: tamperedProofs });
      } catch {
        modifiedResponseRejected = true;
      }
      if (!modifiedResponseRejected) {
        throw new Error(`${benchmarkCase.label} accepted a modified response`);
      }
    }

    const tamperedC00 = structuredClone(transcript.c00);
    tamperedC00[dimension - 1] = structuredClone(transcript.c00[dimension - 2]);
    let unsampledTargetTamperAccepted = true;
    let tamperedDistanceDigest;
    try {
      tamperedDistanceDigest = await contract.callStatic.verifySpot({
        ...args,
        c00: tamperedC00,
      });
    } catch {
      unsampledTargetTamperAccepted = false;
    }
    if (benchmarkCase.samples < dimension) {
      if (
        !unsampledTargetTamperAccepted ||
        tamperedDistanceDigest === expectedDistanceDigest
      ) {
        throw new Error(
          `${benchmarkCase.label} did not expose the conditional sampling miss`,
        );
      }
    } else if (unsampledTargetTamperAccepted) {
      throw new Error("full-check accepted a modified product commitment");
    }

    const request = await contract.populateTransaction.verifySpot(args);
    const callData = calldataCost(request.data);
    const gasUsed = [];
    const gasEstimated = [];
    for (let run = 0; run < repetitions; run += 1) {
      gasEstimated.push((await signer.estimateGas(request)).toNumber());
      const transaction = await signer.sendTransaction({
        ...request,
        gasLimit: 30_000_000,
      });
      const receipt = await transaction.wait();
      if (receipt.status !== 1) {
        throw new Error(`${benchmarkCase.label} transaction ${run} failed`);
      }
      gasUsed.push(receipt.gasUsed.toNumber());
    }

    const intrinsicGas = 21_000 + callData.gas;
    const result = {
      ...benchmarkCase,
      oneBadCoordinateDetection:
        benchmarkCase.samples === dimension
          ? 1
          : detectionProbability(dimension, 1, benchmarkCase.samples),
      repetitions,
      accepted: true,
      modifiedResponseRejected,
      unsampledTargetTamperAccepted,
      distanceReconstructionMatches: true,
      gasUsed,
      medianGasUsed: median(gasUsed),
      gasEstimated,
      medianGasEstimated: median(gasEstimated),
      calldata: callData,
      intrinsicGas,
      medianExecutionGasAfterIntrinsic: median(gasUsed) - intrinsicGas,
    };
    results.push(result);
    process.stdout.write(
      `${result.label}: t=${result.samples}, gas=${result.medianGasUsed}, ` +
        `execution=${result.medianExecutionGasAfterIntrinsic}, calldata=${result.calldata.bytes} bytes\n`,
    );
  }

  const record = {
    generatedAt: new Date().toISOString(),
    scope:
      "Same-harness BN254 verification kernel for six legacy Pedersen consistency equations per sampled coordinate plus full-vector distance commitment reconstruction. It excludes Fiat-Shamir sample derivation, enrollment storage, nonce state, and the legacy threshold Groth16 verifier.",
    securityWarning:
      "The benchmark uses H=5G so valid points can be generated deterministically. This is insecure for a real Pedersen commitment but has the same EVM group-operation cost.",
    dimension,
    compiler: solc.version(),
    optimizerRuns: 200,
    evmVersion: "shanghai",
    chain: "Ganache 7.9.2, chain id 31337",
    repetitions,
    deployment: {
      gasUsed: deploymentReceipt.gasUsed.toNumber(),
      initCodeBytes: compiled.evm.bytecode.object.length / 2,
      runtimeCodeBytes: compiled.evm.deployedBytecode.object.length / 2,
    },
    operationCountPerSample: {
      consistencyEquations: 6,
      bn254ScalarMultiplications: 18,
      bn254Additions: 12,
    },
    fixedDistanceReconstruction: {
      coordinates: dimension,
      bn254AdditionsPerCoordinate: 4,
    },
    results,
  };

  await mkdir(outputRoot, { recursive: true });
  await writeFile(
    resolve(outputRoot, "results.json"),
    `${JSON.stringify(record, null, 2)}\n`,
    "utf8",
  );
} finally {
  if (eip1193) await eip1193.disconnect();
  await curve.terminate();
}
