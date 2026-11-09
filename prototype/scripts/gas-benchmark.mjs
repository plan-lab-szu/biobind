import { readFile, mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import ganache from "ganache";
import solc from "solc";
import { ethers } from "ethers";
import { groth16 } from "snarkjs";

const prototypeRoot = resolve(import.meta.dirname, "..");
const outputRoot = resolve(prototypeRoot, "build", "gas");
const repetitions = 5;

function median(values) {
  const ordered = [...values].sort((a, b) => a - b);
  const middle = Math.floor(ordered.length / 2);
  return ordered.length % 2
    ? ordered[middle]
    : (ordered[middle - 1] + ordered[middle]) / 2;
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

async function compileVerifier(sourcePath) {
  const source = await readFile(sourcePath, "utf8");
  const input = {
    language: "Solidity",
    sources: { "Groth16Verifier.sol": { content: source } },
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
  return output.contracts["Groth16Verifier.sol"].Groth16Verifier;
}

async function benchmarkCase({ dimension, source, provingRoot }) {
  const compiled = await compileVerifier(resolve(prototypeRoot, source));
  const proof = JSON.parse(
    await readFile(resolve(prototypeRoot, provingRoot, "run-01-proof.json"), "utf8"),
  );
  const publicSignals = JSON.parse(
    await readFile(resolve(prototypeRoot, provingRoot, "run-01-public.json"), "utf8"),
  );
  const solidityArguments = JSON.parse(
    `[${await groth16.exportSolidityCallData(proof, publicSignals)}]`,
  );

  const eip1193 = ganache.provider({
    chain: { chainId: 31337, hardfork: "shanghai" },
    miner: { blockGasLimit: 30_000_000 },
    logging: { quiet: true },
    wallet: { deterministic: true, totalAccounts: 2 },
  });
  const provider = new ethers.providers.Web3Provider(eip1193);
  const signer = provider.getSigner(0);

  try {
    const factory = new ethers.ContractFactory(
      compiled.abi,
      `0x${compiled.evm.bytecode.object}`,
      signer,
    );
    const contract = await factory.deploy();
    const deploymentReceipt = await contract.deployTransaction.wait();

    const accepted = await contract.callStatic.verifyProof(...solidityArguments);
    if (!accepted) throw new Error(`valid ${dimension}-dimensional proof rejected`);

    const invalidArguments = structuredClone(solidityArguments);
    const scalarField =
      21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    invalidArguments[3][3] = (
      (BigInt(invalidArguments[3][3]) + 1n) % scalarField
    ).toString();
    const invalidAccepted = await contract.callStatic.verifyProof(...invalidArguments);
    if (invalidAccepted) {
      throw new Error(`proof with modified public ctxHash accepted for dimension ${dimension}`);
    }

    const gasUsed = [];
    const gasEstimated = [];
    let callData;
    for (let run = 0; run < repetitions; run += 1) {
      const request = await contract.populateTransaction.verifyProof(...solidityArguments);
      callData ??= calldataCost(request.data);
      gasEstimated.push((await signer.estimateGas(request)).toNumber());
      const transaction = await signer.sendTransaction(request);
      const receipt = await transaction.wait();
      if (receipt.status !== 1) throw new Error(`verification transaction ${run} failed`);
      gasUsed.push(receipt.gasUsed.toNumber());
    }

    const intrinsicGas = 21_000 + callData.gas;
    return {
      dimension,
      publicInputs: publicSignals.length,
      compiler: solc.version(),
      optimizerRuns: 200,
      evmVersion: "shanghai",
      repetitions,
      deployment: {
        gasUsed: deploymentReceipt.gasUsed.toNumber(),
        initCodeBytes: compiled.evm.bytecode.object.length / 2,
        runtimeCodeBytes: compiled.evm.deployedBytecode.object.length / 2,
      },
      verification: {
        accepted,
        modifiedContextRejected: !invalidAccepted,
        gasUsed,
        medianGasUsed: median(gasUsed),
        gasEstimated,
        medianGasEstimated: median(gasEstimated),
        intrinsicGas,
        medianExecutionGasAfterIntrinsic: median(gasUsed) - intrinsicGas,
      },
      calldata: callData,
    };
  } finally {
    await eip1193.disconnect();
  }
}

await mkdir(outputRoot, { recursive: true });
const cases = [
  {
    dimension: 128,
    source: "contracts/generated/Groth16Verifier128.sol",
    provingRoot: "build/proving/auth_distance_128",
  },
  {
    dimension: 512,
    source: "contracts/generated/Groth16Verifier512.sol",
    provingRoot: "build/proving/auth_distance_512",
  },
];

const results = [];
for (const benchmark of cases) {
  const result = await benchmarkCase(benchmark);
  results.push(result);
  process.stdout.write(
    `${result.dimension}D: deploy=${result.deployment.gasUsed}, ` +
      `verify=${result.verification.medianGasUsed}, calldata=${result.calldata.bytes} bytes\n`,
  );
}

const record = {
  generatedAt: new Date().toISOString(),
  warning: "Verifier keys come from the local benchmark-only ceremony and must not be deployed.",
  chain: "Ganache 7.9.2, chain id 31337, Shanghai hardfork",
  results,
};
await writeFile(
  resolve(outputRoot, "results.json"),
  `${JSON.stringify(record, null, 2)}\n`,
  "utf8",
);
