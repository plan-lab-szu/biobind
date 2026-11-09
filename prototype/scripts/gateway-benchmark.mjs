import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { randomBytes } from "node:crypto";
import ganache from "ganache";
import solc from "solc";
import { ethers } from "ethers";
import { groth16, wtns } from "snarkjs";
import {
  DST_PROBE,
  poseidonCommitment,
} from "./commitment.mjs";

const prototypeRoot = resolve(import.meta.dirname, "..");
const outputRoot = resolve(prototypeRoot, "build", "gateway");
const scalarField =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function randomFieldElement() {
  return BigInt(`0x${randomBytes(32).toString("hex")}`) % scalarField;
}

function jsonWithBigInts(value) {
  return JSON.stringify(
    value,
    (_, nested) => (typeof nested === "bigint" ? nested.toString() : nested),
    2,
  );
}

function calldataCost(hexData) {
  const bytes = ethers.utils.arrayify(hexData);
  const zeroBytes = bytes.filter((value) => value === 0).length;
  const nonzeroBytes = bytes.length - zeroBytes;
  return {
    bytes: bytes.length,
    zeroBytes,
    nonzeroBytes,
    gas: zeroBytes * 4 + nonzeroBytes * 16,
  };
}

async function compileContracts(verifierSourcePath) {
  const [gatewaySource, verifierSource] = await Promise.all([
    readFile(resolve(prototypeRoot, "contracts", "BioAuthGateway.sol"), "utf8"),
    readFile(resolve(prototypeRoot, verifierSourcePath), "utf8"),
  ]);
  const input = {
    language: "Solidity",
    sources: {
      "BioAuthGateway.sol": { content: gatewaySource },
      "Groth16Verifier.sol": { content: verifierSource },
    },
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
  return {
    gateway: output.contracts["BioAuthGateway.sol"].BioAuthGateway,
    verifier: output.contracts["Groth16Verifier.sol"].Groth16Verifier,
  };
}

function factory(compiled, signer) {
  return new ethers.ContractFactory(
    compiled.abi,
    `0x${compiled.evm.bytecode.object}`,
    signer,
  );
}

async function transactionGas(transactionPromise) {
  const transaction = await transactionPromise;
  const receipt = await transaction.wait();
  if (receipt.status !== 1) throw new Error("transaction failed");
  return { transaction, receipt, gasUsed: receipt.gasUsed.toNumber() };
}

async function expectRevert(operation, label) {
  try {
    await operation();
  } catch {
    return true;
  }
  throw new Error(`negative test unexpectedly succeeded: ${label}`);
}

async function benchmarkCase({ dimension, verifierSource, provingRoot }) {
  const compiled = await compileContracts(verifierSource);
  const eip1193 = ganache.provider({
    chain: { chainId: 31337, hardfork: "shanghai" },
    miner: { blockGasLimit: 30_000_000 },
    logging: { quiet: true },
    wallet: { deterministic: true, totalAccounts: 3 },
  });
  const provider = new ethers.providers.Web3Provider(eip1193);
  const initialAccounts = Object.values(eip1193.getInitialAccounts());
  const beneficiary = new ethers.Wallet(initialAccounts[0].secretKey, provider);
  const device = new ethers.Wallet(initialAccounts[1].secretKey, provider);
  const outsider = new ethers.Wallet(initialAccounts[2].secretKey, provider);

  try {
    const verifier = await factory(compiled.verifier, beneficiary).deploy();
    const verifierDeployment = await verifier.deployTransaction.wait();
    const gateway = await factory(compiled.gateway, beneficiary).deploy(verifier.address);
    const gatewayDeployment = await gateway.deployTransaction.wait();

    const baseInputPath = resolve(
      prototypeRoot,
      "inputs",
      "generated",
      `auth_distance_${dimension}.json`,
    );
    const baseInput = JSON.parse(await readFile(baseInputPath, "utf8"));
    const policyDigest = baseInput.policyDigest;
    const credentialId = ethers.utils.id(`BioZERO credential ${dimension}`);
    const action = ethers.utils.id("authorize-login");
    const firmwareMeasurement = ethers.utils.id("mock-afe-firmware-v1");
    const modelHash = ethers.utils.id(`mock-embedding-model-${dimension}-v1`);
    const credentialVersion = 1;
    const templateVersion = 1;
    const policyVersion = 1;

    const credentialConfiguration = await transactionGas(
      gateway.configureCredential(
        credentialId,
        baseInput.cEnroll,
        policyDigest,
        credentialVersion,
        templateVersion,
        policyVersion,
        true,
      ),
    );

    const latestBlock = await provider.getBlock("latest");
    const deviceConfiguration = await transactionGas(
      gateway.configureDevice(
        device.address,
        firmwareMeasurement,
        modelHash,
        policyDigest,
        latestBlock.timestamp - 1,
        latestBlock.timestamp + 86_400,
        true,
      ),
    );

    const deadline = latestBlock.timestamp + 600;
    const challenge = await transactionGas(
      gateway.issueChallenge(
        action,
        credentialId,
        credentialVersion,
        templateVersion,
        policyVersion,
        policyDigest,
        deadline,
      ),
    );
    const challengeLog = challenge.receipt.logs
      .map((log) => {
        try {
          return gateway.interface.parseLog(log);
        } catch {
          return undefined;
        }
      })
      .find((parsed) => parsed?.name === "ChallengeIssued");
    if (!challengeLog) throw new Error("ChallengeIssued event missing");
    const nonce = challengeLog.args.nonce;
    const ctxHash = challengeLog.args.ctxHash.toString();

    const context = {
      beneficiary: beneficiary.address,
      action,
      credentialId,
      credentialVersion,
      templateVersion,
      policyVersion,
      policyDigest,
      nonce,
      deadline,
    };
    const recomputedContext = await gateway.computeContextHash(context);
    if (recomputedContext.ctxHash.toString() !== ctxHash) {
      throw new Error("contract context hash did not reproduce ChallengeIssued value");
    }

    const probeSalt = randomFieldElement();
    const cProbe = await poseidonCommitment({
      roleTag: DST_PROBE,
      policyDigest: BigInt(policyDigest),
      contextDigest: BigInt(ctxHash),
      dimension,
      salt: probeSalt,
      values: baseInput.probe.map(BigInt),
      packSize: 15,
    });
    const dynamicInput = {
      ...baseInput,
      cProbe,
      ctxHash,
      rProbe: probeSalt,
    };

    const caseOutputRoot = resolve(outputRoot, `${dimension}`);
    await mkdir(caseOutputRoot, { recursive: true });
    const dynamicInputPath = resolve(caseOutputRoot, "input.json");
    const witnessPath = resolve(caseOutputRoot, "witness.wtns");
    const proofPath = resolve(caseOutputRoot, "proof.json");
    const publicPath = resolve(caseOutputRoot, "public.json");
    await writeFile(dynamicInputPath, `${jsonWithBigInts(dynamicInput)}\n`, "utf8");

    const wasmPath = resolve(
      prototypeRoot,
      "build",
      `auth_distance_${dimension}`,
      `auth_distance_${dimension}_js`,
      `auth_distance_${dimension}.wasm`,
    );
    const zkeyPath = resolve(prototypeRoot, provingRoot, `auth_distance_${dimension}_benchmark_final.zkey`);
    await wtns.calculate(dynamicInput, wasmPath, witnessPath, {});
    const { proof, publicSignals } = await groth16.prove(zkeyPath, witnessPath);
    if (publicSignals[3].toString() !== ctxHash) {
      throw new Error("proof public context does not match issued challenge");
    }
    await writeFile(proofPath, `${jsonWithBigInts(proof)}\n`, "utf8");
    await writeFile(publicPath, `${jsonWithBigInts(publicSignals)}\n`, "utf8");
    const proofArguments = JSON.parse(
      `[${await groth16.exportSolidityCallData(proof, publicSignals)}]`,
    );

    const captureCounter = 1;
    const notAfter = deadline;
    const captureValue = {
      cProbe: cProbe.toString(),
      ctxHash,
      policyDigest,
      modelHash,
      firmwareMeasurement,
      device: device.address,
      counter: captureCounter,
      notAfter,
    };
    const domain = {
      name: "BioZERO Capture",
      version: "1",
      chainId: 31337,
      verifyingContract: gateway.address,
    };
    const types = {
      Capture: [
        { name: "cProbe", type: "uint256" },
        { name: "ctxHash", type: "uint256" },
        { name: "policyDigest", type: "uint256" },
        { name: "modelHash", type: "bytes32" },
        { name: "firmwareMeasurement", type: "bytes32" },
        { name: "device", type: "address" },
        { name: "counter", type: "uint64" },
        { name: "notAfter", type: "uint64" },
      ],
    };
    const signature = await device._signTypedData(domain, types, captureValue);
    const capture = { ...captureValue, signature };
    const authArguments = [...proofArguments, context, capture];

    const invalidCapture = {
      ...capture,
      signature: `${signature.slice(0, -2)}${signature.endsWith("00") ? "01" : "00"}`,
    };
    const invalidSignatureRejected = await expectRevert(
      () => gateway.callStatic.verifyAndConsume(...proofArguments, context, invalidCapture),
      "modified capture signature",
    );
    const outsiderRejected = await expectRevert(
      () => gateway.connect(outsider).callStatic.verifyAndConsume(...authArguments),
      "non-beneficiary submitter",
    );

    const credentialRevocation = await transactionGas(
      gateway.configureCredential(
        credentialId,
        baseInput.cEnroll,
        policyDigest,
        credentialVersion,
        templateVersion,
        policyVersion,
        false,
      ),
    );
    const revokedCredentialRejected = await expectRevert(
      () => gateway.callStatic.verifyAndConsume(...authArguments),
      "revoked credential",
    );
    const credentialReactivation = await transactionGas(
      gateway.configureCredential(
        credentialId,
        baseInput.cEnroll,
        policyDigest,
        credentialVersion,
        templateVersion,
        policyVersion,
        true,
      ),
    );

    const deviceRevocation = await transactionGas(
      gateway.configureDevice(
        device.address,
        firmwareMeasurement,
        modelHash,
        policyDigest,
        latestBlock.timestamp - 1,
        latestBlock.timestamp + 86_400,
        false,
      ),
    );
    const revokedDeviceRejected = await expectRevert(
      () => gateway.callStatic.verifyAndConsume(...authArguments),
      "revoked capture device",
    );
    const deviceReactivation = await transactionGas(
      gateway.configureDevice(
        device.address,
        firmwareMeasurement,
        modelHash,
        policyDigest,
        latestBlock.timestamp - 1,
        latestBlock.timestamp + 86_400,
        true,
      ),
    );

    const expirySnapshot = await provider.send("evm_snapshot", []);
    await provider.send("evm_increaseTime", [601]);
    await provider.send("evm_mine", []);
    const expiredChallengeRejected = await expectRevert(
      () => gateway.callStatic.verifyAndConsume(...authArguments),
      "expired challenge",
    );
    if (!(await provider.send("evm_revert", [expirySnapshot]))) {
      throw new Error("failed to restore EVM snapshot after expiry test");
    }

    const accepted = await gateway.callStatic.verifyAndConsume(...authArguments);
    if (!accepted) throw new Error("full acceptance predicate returned false");
    const authRequest = await gateway.populateTransaction.verifyAndConsume(...authArguments);
    const authCalldata = calldataCost(authRequest.data);
    const authEstimate = (await beneficiary.estimateGas(authRequest)).toNumber();
    const authentication = await transactionGas(beneficiary.sendTransaction(authRequest));
    const replayRejected = await expectRevert(
      () => gateway.callStatic.verifyAndConsume(...authArguments),
      "consumed nonce replay",
    );

    const cleanupBaseBlock = await provider.getBlock("latest");
    const cleanupDeadline = cleanupBaseBlock.timestamp + 60;
    const cleanupChallenge = await transactionGas(
      gateway.issueChallenge(
        action,
        credentialId,
        credentialVersion,
        templateVersion,
        policyVersion,
        policyDigest,
        cleanupDeadline,
      ),
    );
    const cleanupLog = cleanupChallenge.receipt.logs
      .map((log) => {
        try {
          return gateway.interface.parseLog(log);
        } catch {
          return undefined;
        }
      })
      .find((parsed) => parsed?.name === "ChallengeIssued");
    if (!cleanupLog) throw new Error("cleanup ChallengeIssued event missing");
    const cleanupContext = {
      ...context,
      nonce: cleanupLog.args.nonce,
      deadline: cleanupDeadline,
    };
    const prematureForeignCleanupRejected = await expectRevert(
      () => gateway.connect(outsider).callStatic.cancelChallenge(cleanupContext),
      "foreign cleanup before expiry",
    );
    await provider.send("evm_increaseTime", [61]);
    await provider.send("evm_mine", []);
    const expiredChallengeCleanup = await transactionGas(
      gateway.connect(outsider).cancelChallenge(cleanupContext),
    );
    if ((await gateway.pendingContexts(cleanupContext.nonce)) !== ethers.constants.HashZero) {
      throw new Error("expired pending context was not deleted");
    }

    const subjectKey = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["address", "bytes32"],
        [beneficiary.address, credentialId],
      ),
    );

    async function buildAnchoredAuthentication(authCounter, captureSequence, prefix) {
      const anchor = await provider.getBlock("latest");
      await provider.send("evm_mine", []);
      const anchoredContextTemplate = {
        beneficiary: beneficiary.address,
        action,
        credentialId,
        credentialVersion,
        templateVersion,
        policyVersion,
        policyDigest,
        authCounter,
        anchorBlock: anchor.number,
        anchorHash: anchor.hash,
      };
      const [, anchoredCtxHashValue] = await gateway.computeAnchoredContextHash(
        anchoredContextTemplate,
      );
      const anchoredCtxHash = anchoredCtxHashValue.toString();
      const anchoredProbeSalt = randomFieldElement();
      const anchoredCProbe = await poseidonCommitment({
        roleTag: DST_PROBE,
        policyDigest: BigInt(policyDigest),
        contextDigest: BigInt(anchoredCtxHash),
        dimension,
        salt: anchoredProbeSalt,
        values: baseInput.probe.map(BigInt),
        packSize: 15,
      });
      const anchoredInput = {
        ...baseInput,
        cProbe: anchoredCProbe,
        ctxHash: anchoredCtxHash,
        rProbe: anchoredProbeSalt,
      };
      const anchoredWitnessPath = resolve(caseOutputRoot, `${prefix}-witness.wtns`);
      const anchoredProofPath = resolve(caseOutputRoot, `${prefix}-proof.json`);
      const anchoredPublicPath = resolve(caseOutputRoot, `${prefix}-public.json`);
      await wtns.calculate(anchoredInput, wasmPath, anchoredWitnessPath, {});
      const anchoredProof = await groth16.prove(zkeyPath, anchoredWitnessPath);
      await writeFile(
        anchoredProofPath,
        `${jsonWithBigInts(anchoredProof.proof)}\n`,
        "utf8",
      );
      await writeFile(
        anchoredPublicPath,
        `${jsonWithBigInts(anchoredProof.publicSignals)}\n`,
        "utf8",
      );
      const anchoredProofArguments = JSON.parse(
        `[${await groth16.exportSolidityCallData(
          anchoredProof.proof,
          anchoredProof.publicSignals,
        )}]`,
      );
      const anchoredBlock = await provider.getBlock("latest");
      const anchoredNotAfter = anchoredBlock.timestamp + 600;
      const anchoredCaptureValue = {
        cProbe: anchoredCProbe.toString(),
        ctxHash: anchoredCtxHash,
        policyDigest,
        modelHash,
        firmwareMeasurement,
        device: device.address,
        counter: captureSequence,
        notAfter: anchoredNotAfter,
      };
      const anchoredSignature = await device._signTypedData(
        domain,
        types,
        anchoredCaptureValue,
      );
      return {
        context: anchoredContextTemplate,
        arguments: [
          ...anchoredProofArguments,
          anchoredContextTemplate,
          { ...anchoredCaptureValue, signature: anchoredSignature },
        ],
      };
    }

    const anchoredFirst = await buildAnchoredAuthentication(0, 2, "anchored-00");
    const staleAnchorSnapshot = await provider.send("evm_snapshot", []);
    for (let block = 0; block < 65; block += 1) {
      await provider.send("evm_mine", []);
    }
    const staleAnchorRejected = await expectRevert(
      () => gateway.callStatic.verifyAnchored(...anchoredFirst.arguments),
      "stale block anchor",
    );
    if (!(await provider.send("evm_revert", [staleAnchorSnapshot]))) {
      throw new Error("failed to restore EVM snapshot after stale-anchor test");
    }
    const anchoredFirstAccepted = await gateway.callStatic.verifyAnchored(
      ...anchoredFirst.arguments,
    );
    if (!anchoredFirstAccepted) throw new Error("first anchored authentication rejected");
    const anchoredFirstRequest = await gateway.populateTransaction.verifyAnchored(
      ...anchoredFirst.arguments,
    );
    const anchoredFirstCalldata = calldataCost(anchoredFirstRequest.data);
    const anchoredFirstTransaction = await transactionGas(
      beneficiary.sendTransaction(anchoredFirstRequest),
    );
    const anchoredReplayRejected = await expectRevert(
      () => gateway.callStatic.verifyAnchored(...anchoredFirst.arguments),
      "anchored counter replay",
    );
    if ((await gateway.authCounters(subjectKey)).toNumber() !== 1) {
      throw new Error("anchored authentication counter did not increment");
    }

    const anchoredSteady = await buildAnchoredAuthentication(1, 3, "anchored-01");
    const anchoredSteadyAccepted = await gateway.callStatic.verifyAnchored(
      ...anchoredSteady.arguments,
    );
    if (!anchoredSteadyAccepted) throw new Error("steady anchored authentication rejected");
    const anchoredSteadyRequest = await gateway.populateTransaction.verifyAnchored(
      ...anchoredSteady.arguments,
    );
    const anchoredSteadyCalldata = calldataCost(anchoredSteadyRequest.data);
    const anchoredSteadyTransaction = await transactionGas(
      beneficiary.sendTransaction(anchoredSteadyRequest),
    );

    return {
      dimension,
      compiler: solc.version(),
      evmVersion: "shanghai",
      verifierDeploymentGas: verifierDeployment.gasUsed.toNumber(),
      gatewayDeployment: {
        gasUsed: gatewayDeployment.gasUsed.toNumber(),
        runtimeCodeBytes: compiled.gateway.evm.deployedBytecode.object.length / 2,
      },
      setupTransactions: {
        configureCredentialGas: credentialConfiguration.gasUsed,
        configureDeviceGas: deviceConfiguration.gasUsed,
        issueChallengeGas: challenge.gasUsed,
        revokeCredentialGas: credentialRevocation.gasUsed,
        reactivateCredentialGas: credentialReactivation.gasUsed,
        revokeDeviceGas: deviceRevocation.gasUsed,
        reactivateDeviceGas: deviceReactivation.gasUsed,
        cleanupIssueChallengeGas: cleanupChallenge.gasUsed,
        expiredChallengeCleanupGas: expiredChallengeCleanup.gasUsed,
      },
      authentication: {
        accepted,
        transactionGas: authentication.gasUsed,
        estimatedGas: authEstimate,
        calldata: authCalldata,
        intrinsicGas: 21_000 + authCalldata.gas,
        executionGasAfterIntrinsic:
          authentication.gasUsed - 21_000 - authCalldata.gas,
      },
      anchoredAuthentication: {
        first: {
          accepted: anchoredFirstAccepted,
          transactionGas: anchoredFirstTransaction.gasUsed,
          calldata: anchoredFirstCalldata,
          intrinsicGas: 21_000 + anchoredFirstCalldata.gas,
          executionGasAfterIntrinsic:
            anchoredFirstTransaction.gasUsed - 21_000 - anchoredFirstCalldata.gas,
        },
        steady: {
          accepted: anchoredSteadyAccepted,
          transactionGas: anchoredSteadyTransaction.gasUsed,
          calldata: anchoredSteadyCalldata,
          intrinsicGas: 21_000 + anchoredSteadyCalldata.gas,
          executionGasAfterIntrinsic:
            anchoredSteadyTransaction.gasUsed - 21_000 - anchoredSteadyCalldata.gas,
        },
        counterAfter: (await gateway.authCounters(subjectKey)).toNumber(),
      },
      negativeTests: {
        invalidSignatureRejected,
        outsiderRejected,
        revokedCredentialRejected,
        revokedDeviceRejected,
        expiredChallengeRejected,
        replayRejected,
        prematureForeignCleanupRejected,
        expiredChallengeCleaned: true,
        staleAnchorRejected,
        anchoredReplayRejected,
      },
    };
  } finally {
    await eip1193.disconnect();
  }
}

await mkdir(outputRoot, { recursive: true });
const cases = [
  {
    dimension: 128,
    verifierSource: "contracts/generated/Groth16Verifier128.sol",
    provingRoot: "build/proving/auth_distance_128",
  },
  {
    dimension: 512,
    verifierSource: "contracts/generated/Groth16Verifier512.sol",
    provingRoot: "build/proving/auth_distance_512",
  },
];

const results = [];
for (const benchmark of cases) {
  const result = await benchmarkCase(benchmark);
  results.push(result);
  process.stdout.write(
    `${result.dimension}D full auth: ${result.authentication.transactionGas} gas, ` +
      `${result.authentication.calldata.bytes} calldata bytes\n`,
  );
}

await writeFile(
  resolve(outputRoot, "results.json"),
  `${JSON.stringify(
    {
      generatedAt: new Date().toISOString(),
      warning: "MockAFE and local benchmark ceremony only; not a production deployment.",
      results,
    },
    null,
    2,
  )}\n`,
  "utf8",
);

// groth16 proving can leave ffjavascript worker handles alive after all files
// are flushed. End this batch explicitly so automation observes completion.
process.exit(0);
