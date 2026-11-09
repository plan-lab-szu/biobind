import { finalizedRecordFor, rememberFinalized } from "./lib/finalized-record.mjs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { randomBytes } from "node:crypto";
import ganache from "ganache";
import solc from "solc";
import { ethers } from "ethers";
import { groth16, wtns } from "snarkjs";
import { DST_PROBE, poseidonCommitment } from "./commitment.mjs";

const prototypeRoot = resolve(import.meta.dirname, "..");
const outputRoot = resolve(prototypeRoot, "build", "provenance-evaluation");
const scalarField =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const researchScope = {
  authorization: "authorized defensive academic evaluation",
  executionEnvironment: "in-process Ganache test chain only",
  systemsInScope: [
    "researcher-owned BioZERO prototype",
    "deliberately incomplete local comparison baseline",
    "natural local composition baselines for enrollment and lifecycle seams",
  ],
  systemsOutOfScope: [
    "third-party services",
    "public networks",
    "real users and real biometric data",
  ],
  purpose:
    "measure whether individually sound uniqueness, ZK, capture-signature, freshness, and lifecycle components establish end-to-end provenance under natural incomplete composition",
};

function jsonWithBigInts(value) {
  return JSON.stringify(
    value,
    (_, nested) => (typeof nested === "bigint" ? nested.toString() : nested),
    2,
  );
}

function randomFieldElement() {
  return BigInt(`0x${randomBytes(32).toString("hex")}`) % scalarField;
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
  if (receipt.status !== 1) throw new Error("local transaction failed");
  return receipt.gasUsed.toNumber();
}

async function expectLocalRejection(operation, label) {
  try {
    await operation();
  } catch {
    return true;
  }
  throw new Error(`negative control unexpectedly succeeded: ${label}`);
}

async function compileContracts() {
  const [
    gatewaySource,
    baselineSource,
    naiveCompositionSource,
    uniquenessAdapterInterface,
    finalizationSourceInterface,
    finalizationAdapterSource,
    localFinalizationSource,
    verifierSource,
  ] = await Promise.all([
    readFile(resolve(prototypeRoot, "contracts", "BioAuthGateway.sol"), "utf8"),
    readFile(
      resolve(prototypeRoot, "contracts", "ProvenanceOmissionBaseline.sol"),
      "utf8",
    ),
    readFile(
      resolve(prototypeRoot, "contracts", "NaiveCompositionBaselines.sol"),
      "utf8",
    ),
    readFile(
      resolve(
        prototypeRoot,
        "contracts",
        "interfaces",
        "IBioZKFHEUniquenessAdapter.sol",
      ),
      "utf8",
    ),
    readFile(
      resolve(
        prototypeRoot,
        "contracts",
        "interfaces",
        "IBioZKFHEFinalizationSource.sol",
      ),
      "utf8",
    ),
    readFile(
      resolve(prototypeRoot, "contracts", "BioZKFHEFinalizationAdapter.sol"),
      "utf8",
    ),
    readFile(
      resolve(
        prototypeRoot,
        "contracts",
        "test",
        "LocalBioZKFHEFinalizationSource.sol",
      ),
      "utf8",
    ),
    readFile(
      resolve(prototypeRoot, "contracts", "generated", "Groth16Verifier128.sol"),
      "utf8",
    ),
  ]);
  const compilerInput = {
    language: "Solidity",
    sources: {
      "BioAuthGateway.sol": { content: gatewaySource },
      "ProvenanceOmissionBaseline.sol": { content: baselineSource },
      "NaiveCompositionBaselines.sol": { content: naiveCompositionSource },
      "interfaces/IBioZKFHEUniquenessAdapter.sol": {
        content: uniquenessAdapterInterface,
      },
      "interfaces/IBioZKFHEFinalizationSource.sol": {
        content: finalizationSourceInterface,
      },
      "BioZKFHEFinalizationAdapter.sol": {
        content: finalizationAdapterSource,
      },
      "test/LocalBioZKFHEFinalizationSource.sol": {
        content: localFinalizationSource,
      },
      "Groth16Verifier.sol": { content: verifierSource },
    },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: "shanghai",
      outputSelection: {
        "*": { "*": ["abi", "evm.bytecode.object"] },
      },
    },
  };
  const compilerOutput = JSON.parse(solc.compile(JSON.stringify(compilerInput)));
  const errors = (compilerOutput.errors ?? []).filter(
    ({ severity }) => severity === "error",
  );
  if (errors.length > 0) {
    throw new Error(errors.map(({ formattedMessage }) => formattedMessage).join("\n"));
  }
  return {
    verifier: compilerOutput.contracts["Groth16Verifier.sol"].Groth16Verifier,
    baseline:
      compilerOutput.contracts["ProvenanceOmissionBaseline.sol"]
        .ProvenanceOmissionBaseline,
    booleanReceiptBaseline:
      compilerOutput.contracts["NaiveCompositionBaselines.sol"]
        .BooleanReceiptEnrollmentBaseline,
    historicalAuthorizationBaseline:
      compilerOutput.contracts["NaiveCompositionBaselines.sol"]
        .HistoricalAuthorizationBaseline,
    finalizationSource:
      compilerOutput.contracts["test/LocalBioZKFHEFinalizationSource.sol"]
        .LocalBioZKFHEFinalizationSource,
    finalizationAdapter:
      compilerOutput.contracts["BioZKFHEFinalizationAdapter.sol"]
        .BioZKFHEFinalizationAdapter,
    gateway: compilerOutput.contracts["BioAuthGateway.sol"].BioAuthGateway,
  };
}

function renderReport(result) {
  return `# Authorized local provenance security evaluation

## Scope

This is a defensive academic experiment against researcher-owned code. It ran
only on an in-process Ganache test chain. No third-party endpoint, public
network, real account, or real biometric record was accessed.

The comparison contract is deliberately incomplete and does not represent a
claim about any named paper or deployed service. The proving key is explicitly
a benchmark-only key.

## Question

Do individually sound uniqueness, ZK matching, capture signing, freshness, and
authorization components automatically establish an end-to-end biometric
provenance chain when composed through natural but incomplete interfaces?

## Local negative and positive controls

| Observation | Result |
|---|---:|
| Offline Groth16 verification of host-constructed witness | ${result.cryptographicValidity.offlineGroth16Verified ? "PASS" : "FAIL"} |
| Deliberately incomplete baseline accepts that valid proof | ${result.provenanceOmissionBaseline.hostConstructedWitnessAccepted ? "YES" : "NO"} |
| Baseline rejects reuse of the same nullifier | ${result.provenanceOmissionBaseline.sameNullifierRejected ? "YES" : "NO"} |
| Valid same-chain terminal receipt is consumed and its lineage stored | ${result.naturalNaiveCompositions.sameChainTerminalReceiptLineageStored ? "YES" : "NO"} |
| That one-time receipt still issues an unrelated enrollment commitment | ${result.naturalNaiveCompositions.enrollmentSubstitutionAccepted ? "YES" : "NO"} |
| Authorized host-input signing API blesses a host-constructed probe | ${result.naturalNaiveCompositions.authorizedBlindSigningApiAcceptedHostConstructedProbe ? "YES" : "NO"} |
| Cached authorization remains usable after credential revocation | ${result.naturalNaiveCompositions.cachedAuthorizationAcceptedAfterCredentialRevocation ? "YES" : "NO"} |
| Provenance-aware gateway rejects evidence signed outside the authorized device identity | ${result.provenanceAwareGateway.unauthorizedCaptureEvidenceRejected ? "YES" : "NO"} |
| Rejected attempt leaves its challenge unconsumed | ${result.provenanceAwareGateway.challengePreservedAfterRejection ? "YES" : "NO"} |
| Provenance-aware gateway checks live credential state at submission | ${result.provenanceAwareGateway.currentStateRejectionAfterRevocation ? "YES" : "NO"} |
| Same proof is accepted with the authorized mock capture signature | ${result.provenanceAwareGateway.authorizedCaptureEvidenceAccepted ? "YES" : "NO"} |
| Accepted attempt consumes its challenge and rejects replay | ${result.provenanceAwareGateway.replayAfterConsumptionRejected ? "YES" : "NO"} |

## Interpretation

The constructed probe equals the synthetic enrollment vector and therefore has
distance zero. The full-vector circuit, proof, uniqueness decision, one-time
receipt state, capture signature, and cached authorization are each functioning
as configured; this test does not break their underlying cryptography. Instead,
three composition seams remain: a canonical receipt derived from a valid
same-chain terminal state does not authenticate the independently chosen
enrollment commitment, a signing key does not prove its API derived the signed
commitment from a sensor, and a historical authorization does not imply current
eligibility at the acceptance linearization point.

The gateway rejects signatures outside its configured device and rejects the
prepared transaction after live credential revocation. However, the local
authorized-device positive control signs a host-supplied commitment, so its
acceptance also demonstrates why a contract signature check alone is
insufficient: the real MCU/TEE API must internally derive the commitment from
authenticated sensor data. This is a local composition-gap evaluation, not a
claim of compromising any external system.

## Limits

The authorized-device key is a software wallet used as a deterministic mock.
This run validates protocol composition and state transitions, not physical
sensor wiring, TEE key isolation, secure boot, PAD/liveness, or production
governance. Those require the separate hardware evaluation.

Machine-readable evidence: \`result.json\`.
`;
}

async function evaluate() {
  await mkdir(outputRoot, { recursive: true });
  console.log("AUTHORIZED LOCAL DEFENSIVE EVALUATION");
  console.log(jsonWithBigInts(researchScope));

  const compiled = await compileContracts();
  const eip1193 = ganache.provider({
    chain: { chainId: 31337, hardfork: "shanghai" },
    miner: { blockGasLimit: 30_000_000 },
    logging: { quiet: true },
    wallet: { deterministic: true, totalAccounts: 4 },
  });
  const provider = new ethers.providers.Web3Provider(eip1193);
  const initialAccounts = Object.values(eip1193.getInitialAccounts());
  const systemOwner = new ethers.Wallet(initialAccounts[0].secretKey, provider);
  const authorizedDevice = new ethers.Wallet(initialAccounts[1].secretKey, provider);
  const holderHost = new ethers.Wallet(initialAccounts[2].secretKey, provider);
  const localUntrustedSigner = new ethers.Wallet(
    initialAccounts[3].secretKey,
    provider,
  );

  try {
    const verifier = await factory(compiled.verifier, systemOwner).deploy();
    await verifier.deployTransaction.wait();
    const baseline = await factory(compiled.baseline, systemOwner).deploy(
      verifier.address,
    );
    await baseline.deployTransaction.wait();
    const finalizationSource = await factory(
      compiled.finalizationSource,
      systemOwner,
    ).deploy();
    await finalizationSource.deployTransaction.wait();
    const finalizationAdapter = await factory(
      compiled.finalizationAdapter,
      systemOwner,
    ).deploy(finalizationSource.address);
    await finalizationAdapter.deployTransaction.wait();
    const booleanReceiptBaseline = await factory(
      compiled.booleanReceiptBaseline,
      systemOwner,
    ).deploy(verifier.address, finalizationAdapter.address);
    await booleanReceiptBaseline.deployTransaction.wait();
    await transactionGas(
      finalizationAdapter.configureAuthorizedConsumer(
        booleanReceiptBaseline.address,
      ),
    );
    const historicalAuthorizationBaseline = await factory(
      compiled.historicalAuthorizationBaseline,
      systemOwner,
    ).deploy(verifier.address);
    await historicalAuthorizationBaseline.deployTransaction.wait();
    const gateway = await factory(compiled.gateway, systemOwner).deploy(
      verifier.address,
    );
    await gateway.deployTransaction.wait();

    const baseInput = JSON.parse(
      await readFile(
        resolve(prototypeRoot, "inputs", "generated", "auth_distance_128.json"),
        "utf8",
      ),
    );
    const credentialId = ethers.utils.id("local-provenance-evaluation-credential");
    const substitutedCredentialId = ethers.utils.id(
      "local-enrollment-substitution-credential",
    );
    const historicalCredentialId = ethers.utils.id(
      "local-historical-authorization-credential",
    );
    const sourceSessionIdForVectorA = ethers.utils.id(
      "local-finalized-unique-enrollment-session-for-vector-a",
    );
    const action = ethers.utils.id("local-authorize-session");
    const firmwareMeasurement = ethers.utils.id("mock-capture-firmware-v1");
    const modelHash = ethers.utils.id("mock-embedding-model-128-v1");
    const quantizationHash = ethers.utils.id("mock-quantization-policy-v1");
    const credentialVersion = 1;
    const templateVersion = 1;
    const policyVersion = 1;

    await transactionGas(
      baseline.configureCredential(
        credentialId,
        baseInput.cEnroll,
        baseInput.policyDigest,
        holderHost.address,
      ),
    );
    const sourceFinalizationBlock = await provider.getBlockNumber();
    await transactionGas(
      finalizationSource.recordImmutableSession(sourceSessionIdForVectorA, rememberFinalized(sourceSessionIdForVectorA, {
        operation: 1,
        finalized: true,
        uniquenessAccepted: true,
        expectedBlockCount: 4,
        verifiedBlockCount: 4,
        confirmationThreshold: 3,
        confirmationCount: 3,
        sourceContextHash: ethers.utils.id("vector-a-source-context"),
        gallerySnapshotHash: ethers.utils.id("vector-a-gallery-snapshot"),
        queryCiphertextDigest: ethers.utils.id("vector-a-query-ciphertext"),
        enrollmentCiphertextDigest: ethers.utils.id(
          "vector-a-enrollment-ciphertext",
        ),
        verifiedOutputCollectionDigest: ethers.utils.id(
          "vector-a-verified-output-collection",
        ),
        modelHash,
        quantizationHash,
        finalizedAtBlock: sourceFinalizationBlock,
      })),
    );
    const uniqueReceiptPreview =
      await finalizationAdapter.previewFinalizedUniqueEnrollment(
        sourceSessionIdForVectorA,
      finalizedRecordFor(sourceSessionIdForVectorA),
      );
    await transactionGas(
      booleanReceiptBaseline.issueFromUniqueReceipt(
        sourceSessionIdForVectorA,
        finalizedRecordFor(sourceSessionIdForVectorA),
        substitutedCredentialId,
        baseInput.cEnroll,
        baseInput.policyDigest,
        holderHost.address,
      ),
    );
    await transactionGas(
      historicalAuthorizationBaseline.configureCredential(
        historicalCredentialId,
        baseInput.cEnroll,
        baseInput.policyDigest,
        holderHost.address,
      ),
    );
    await transactionGas(
      gateway.configureCredential(
        credentialId,
        baseInput.cEnroll,
        baseInput.policyDigest,
        credentialVersion,
        templateVersion,
        policyVersion,
        true,
      ),
    );
    const configurationBlock = await provider.getBlock("latest");
    await transactionGas(
      gateway.configureDevice(
        authorizedDevice.address,
        firmwareMeasurement,
        modelHash,
        baseInput.policyDigest,
        configurationBlock.timestamp - 1,
        configurationBlock.timestamp + 86_400,
        true,
      ),
    );

    const challengeBlock = await provider.getBlock("latest");
    const deadline = challengeBlock.timestamp + 600;
    const challengeTransaction = await gateway.connect(holderHost).issueChallenge(
      action,
      credentialId,
      credentialVersion,
      templateVersion,
      policyVersion,
      baseInput.policyDigest,
      deadline,
    );
    const challengeReceipt = await challengeTransaction.wait();
    const challengeEvent = challengeReceipt.logs
      .map((log) => {
        try {
          return gateway.interface.parseLog(log);
        } catch {
          return undefined;
        }
      })
      .find((parsed) => parsed?.name === "ChallengeIssued");
    if (!challengeEvent) throw new Error("local ChallengeIssued event missing");

    const nonce = challengeEvent.args.nonce;
    const ctxHash = challengeEvent.args.ctxHash.toString();
    const context = {
      beneficiary: holderHost.address,
      action,
      credentialId,
      credentialVersion,
      templateVersion,
      policyVersion,
      policyDigest: baseInput.policyDigest,
      nonce,
      deadline,
    };
    const historicalAuthorizationId = ethers.utils.id(
      "local-cached-authorization-before-revocation",
    );
    await transactionGas(
      historicalAuthorizationBaseline
        .connect(holderHost)
        .cacheAuthorization(
          historicalAuthorizationId,
          historicalCredentialId,
          ctxHash,
        ),
    );
    const [encodedContextHash, recomputedCtxHash] =
      await gateway.computeContextHash(context);
    if (recomputedCtxHash.toString() !== ctxHash) {
      throw new Error("challenge context did not reproduce locally");
    }

    // Negative-control witness: the holder-side host substitutes the synthetic
    // enrollment vector for a fresh sensor-derived probe. This is possible in
    // the declared P0 comparison model because the host knows the enrollment
    // opening, but it does not possess the authorized capture signing key.
    const probeSalt = randomFieldElement();
    const cProbe = await poseidonCommitment({
      roleTag: DST_PROBE,
      policyDigest: BigInt(baseInput.policyDigest),
      contextDigest: BigInt(ctxHash),
      dimension: 128,
      salt: probeSalt,
      values: baseInput.enrollment.map(BigInt),
      packSize: 15,
    });
    const constructedInput = {
      ...baseInput,
      probe: [...baseInput.enrollment],
      cProbe: cProbe.toString(),
      ctxHash,
      rProbe: probeSalt.toString(),
    };
    const inputPath = resolve(outputRoot, "synthetic-constructed-input.json");
    const witnessPath = resolve(outputRoot, "witness.wtns");
    const proofPath = resolve(outputRoot, "proof.json");
    const publicPath = resolve(outputRoot, "public.json");
    await writeFile(inputPath, `${jsonWithBigInts(constructedInput)}\n`, "utf8");

    const wasmPath = resolve(
      prototypeRoot,
      "build",
      "auth_distance_128",
      "auth_distance_128_js",
      "auth_distance_128.wasm",
    );
    const zkeyPath = resolve(
      prototypeRoot,
      "build",
      "proving",
      "auth_distance_128",
      "auth_distance_128_benchmark_final.zkey",
    );
    const verificationKeyPath = resolve(
      prototypeRoot,
      "build",
      "proving",
      "auth_distance_128",
      "verification_key.json",
    );
    const provingStarted = process.hrtime.bigint();
    await wtns.calculate(constructedInput, wasmPath, witnessPath, {});
    const { proof, publicSignals } = await groth16.prove(zkeyPath, witnessPath);
    const provingElapsedMs = Number(process.hrtime.bigint() - provingStarted) / 1e6;
    const verificationKey = JSON.parse(
      await readFile(verificationKeyPath, "utf8"),
    );
    const offlineGroth16Verified = await groth16.verify(
      verificationKey,
      publicSignals,
      proof,
    );
    if (!offlineGroth16Verified) throw new Error("offline Groth16 control failed");
    if (
      publicSignals[0].toString() !== baseInput.cEnroll ||
      publicSignals[1].toString() !== cProbe.toString() ||
      publicSignals[3].toString() !== ctxHash
    ) {
      throw new Error("proof public signals do not match local evaluation context");
    }
    await writeFile(proofPath, `${jsonWithBigInts(proof)}\n`, "utf8");
    await writeFile(publicPath, `${jsonWithBigInts(publicSignals)}\n`, "utf8");
    const proofArguments = JSON.parse(
      `[${await groth16.exportSolidityCallData(proof, publicSignals)}]`,
    );

    const nullifier = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ["string", "bytes32", "bytes32", "uint256"],
        ["LOCAL-PROVENANCE-EVAL-v1", credentialId, nonce, cProbe.toString()],
      ),
    );
    const baselineAccepted = await baseline
      .connect(holderHost)
      .callStatic.authenticate(...proofArguments, credentialId, nullifier);
    if (!baselineAccepted) throw new Error("baseline positive control failed");
    const baselineGas = await transactionGas(
      baseline
        .connect(holderHost)
        .authenticate(...proofArguments, credentialId, nullifier),
    );
    const baselineReplayRejected = await expectLocalRejection(
      () =>
        baseline
          .connect(holderHost)
          .callStatic.authenticate(...proofArguments, credentialId, nullifier),
      "baseline nullifier reuse",
    );

    const substitutionNullifier = ethers.utils.id(
      "local-enrollment-substitution-nullifier",
    );
    const enrollmentSubstitutionAccepted = await booleanReceiptBaseline
      .connect(holderHost)
      .callStatic.authenticate(
        ...proofArguments,
        substitutedCredentialId,
        substitutionNullifier,
      );
    if (!enrollmentSubstitutionAccepted) {
      throw new Error("enrollment-substitution composition control failed");
    }
    const enrollmentSubstitutionGas = await transactionGas(
      booleanReceiptBaseline
        .connect(holderHost)
        .authenticate(
          ...proofArguments,
          substitutedCredentialId,
          substitutionNullifier,
        ),
    );
    const soundReceiptConsumed =
      (await finalizationAdapter.consumedBy(sourceSessionIdForVectorA)) !==
      ethers.constants.HashZero;
    const substitutedCredential =
      await booleanReceiptBaseline.credentials(substitutedCredentialId);
    const receiptLineageStored =
      substitutedCredential.receiptId === uniqueReceiptPreview.receiptId &&
      substitutedCredential.uniqueInputDigest ===
        uniqueReceiptPreview.uniqueInputDigest;
    const unrelatedEnrollmentCommitmentStored =
      substitutedCredential.cEnroll.toString() === baseInput.cEnroll;
    if (!receiptLineageStored || !unrelatedEnrollmentCommitmentStored) {
      throw new Error("same-chain receipt lineage control failed");
    }

    await transactionGas(
      historicalAuthorizationBaseline.revokeCredential(
        historicalCredentialId,
      ),
    );
    const cachedAuthorizationAcceptedAfterRevocation =
      await historicalAuthorizationBaseline
        .connect(holderHost)
        .callStatic.authenticateFromCachedAuthorization(
          ...proofArguments,
          historicalAuthorizationId,
        );
    if (!cachedAuthorizationAcceptedAfterRevocation) {
      throw new Error("historical-state composition control failed");
    }
    const historicalAuthorizationGas = await transactionGas(
      historicalAuthorizationBaseline
        .connect(holderHost)
        .authenticateFromCachedAuthorization(
          ...proofArguments,
          historicalAuthorizationId,
        ),
    );

    const captureValue = {
      cProbe: cProbe.toString(),
      ctxHash,
      policyDigest: baseInput.policyDigest,
      modelHash,
      firmwareMeasurement,
      device: authorizedDevice.address,
      counter: 1,
      notAfter: deadline,
    };
    const captureDomain = {
      name: "BioZERO Capture",
      version: "1",
      chainId: 31337,
      verifyingContract: gateway.address,
    };
    const captureTypes = {
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

    const outsideSignature = await localUntrustedSigner._signTypedData(
      captureDomain,
      captureTypes,
      captureValue,
    );
    const unauthorizedCaptureEvidenceRejected = await expectLocalRejection(
      () =>
        gateway
          .connect(holderHost)
          .callStatic.verifyAndConsume(
            ...proofArguments,
            context,
            { ...captureValue, signature: outsideSignature },
          ),
      "signature outside configured capture-device identity",
    );
    const challengePreservedAfterRejection =
      (await gateway.pendingContexts(nonce)).toLowerCase() ===
      encodedContextHash.toLowerCase();
    if (!challengePreservedAfterRejection) {
      throw new Error("rejected local control changed challenge state");
    }

    const authorizedSignature = await authorizedDevice._signTypedData(
      captureDomain,
      captureTypes,
      captureValue,
    );
    const authorizedCapture = { ...captureValue, signature: authorizedSignature };
    const revokedStateSnapshot = await provider.send("evm_snapshot", []);
    await transactionGas(
      gateway.configureCredential(
        credentialId,
        baseInput.cEnroll,
        baseInput.policyDigest,
        credentialVersion,
        templateVersion,
        policyVersion,
        false,
      ),
    );
    const currentStateRejectionAfterRevocation = await expectLocalRejection(
      () =>
        gateway
          .connect(holderHost)
          .callStatic.verifyAndConsume(
            ...proofArguments,
            context,
            authorizedCapture,
          ),
      "live credential revoked before submission",
    );
    const challengePreservedAfterRevocation =
      (await gateway.pendingContexts(nonce)).toLowerCase() ===
      encodedContextHash.toLowerCase();
    if (!(await provider.send("evm_revert", [revokedStateSnapshot]))) {
      throw new Error("failed to restore live-state comparison snapshot");
    }
    const authorizedAccepted = await gateway
      .connect(holderHost)
      .callStatic.verifyAndConsume(
        ...proofArguments,
        context,
        authorizedCapture,
      );
    if (!authorizedAccepted) throw new Error("authorized capture control failed");
    const protectedGatewayGas = await transactionGas(
      gateway
        .connect(holderHost)
        .verifyAndConsume(...proofArguments, context, authorizedCapture),
    );
    const replayAfterConsumptionRejected = await expectLocalRejection(
      () =>
        gateway
          .connect(holderHost)
          .callStatic.verifyAndConsume(
            ...proofArguments,
            context,
            authorizedCapture,
          ),
      "consumed protected challenge reuse",
    );
    const challengeConsumed =
      (await gateway.pendingContexts(nonce)) === ethers.constants.HashZero;

    const result = {
      generatedAt: new Date().toISOString(),
      compiler: solc.version(),
      node: process.version,
      researchScope,
      threatModel: {
        holderSideHostControlled: true,
        syntheticEnrollmentOpeningKnownToHost: true,
        authorizedCaptureSigningKeyKnownToHost: false,
        padInScope: false,
      },
      construction: {
        dimension: 128,
        vectorSource: "synthetic generated fixture only",
        probeConstruction: "host substitutes synthetic enrollment vector",
        squaredDistance: "0",
        provingKeyStatus: "benchmark-only; not production ceremony",
        provingElapsedMs,
      },
      cryptographicValidity: {
        offlineGroth16Verified,
        enrollmentCommitmentMatched: publicSignals[0].toString() === baseInput.cEnroll,
        probeCommitmentMatched: publicSignals[1].toString() === cProbe.toString(),
        freshnessContextMatched: publicSignals[3].toString() === ctxHash,
      },
      provenanceOmissionBaseline: {
        hostConstructedWitnessAccepted: baselineAccepted,
        sameNullifierRejected: baselineReplayRejected,
        authenticationGas: baselineGas,
      },
      naturalNaiveCompositions: {
        soundUniqueReceiptConsumed: soundReceiptConsumed,
        sameChainTerminalReceiptLineageStored: receiptLineageStored,
        uniqueInputDigestDeliberatelyDiffersFromCredentialTemplate: true,
        unrelatedEnrollmentCommitmentStored,
        enrollmentSubstitutionAccepted,
        enrollmentSubstitutionGas,
        authorizedBlindSigningApiAcceptedHostConstructedProbe:
          authorizedAccepted,
        cachedAuthorizationAcceptedAfterCredentialRevocation:
          cachedAuthorizationAcceptedAfterRevocation,
        historicalAuthorizationGas,
      },
      provenanceAwareGateway: {
        unauthorizedCaptureEvidenceRejected,
        challengePreservedAfterRejection,
        currentStateRejectionAfterRevocation,
        challengePreservedAfterRevocation,
        authorizedCaptureEvidenceAccepted: authorizedAccepted,
        challengeConsumedAfterAcceptance: challengeConsumed,
        replayAfterConsumptionRejected,
        authenticationGas: protectedGatewayGas,
      },
      interpretation:
        "Sound component results do not compose automatically: a canonical one-time receipt derived from valid same-chain terminal state can authorize an unrelated enrollment commitment, an authorized key exposed as a host-input signing API can bless a host-constructed probe, and historical eligibility can survive revocation unless live state is checked at acceptance.",
      limitations: [
        "software-wallet device mock, not a TEE key",
        "no physical sensor-path validation",
        "no PAD/liveness claim",
        "no real biometric data",
        "no external system evaluated",
      ],
    };
    await writeFile(
      resolve(outputRoot, "result.json"),
      `${jsonWithBigInts(result)}\n`,
      "utf8",
    );
    await writeFile(
      resolve(outputRoot, "REPORT.md"),
      renderReport(result),
      "utf8",
    );
    return result;
  } finally {
    await eip1193.disconnect();
  }
}

evaluate()
  .then(async (result) => {
    console.log("\nLOCAL EVALUATION COMPLETE");
    console.log(jsonWithBigInts({
      offlineGroth16Verified:
        result.cryptographicValidity.offlineGroth16Verified,
      omissionBaselineAccepted:
        result.provenanceOmissionBaseline.hostConstructedWitnessAccepted,
      unauthorizedCaptureEvidenceRejected:
        result.provenanceAwareGateway.unauthorizedCaptureEvidenceRejected,
      authorizedCaptureEvidenceAccepted:
        result.provenanceAwareGateway.authorizedCaptureEvidenceAccepted,
      report: resolve(outputRoot, "REPORT.md"),
    }));
    if (globalThis.curve_bn128?.terminate) {
      await globalThis.curve_bn128.terminate();
    }
  })
  .catch(async (error) => {
    console.error(error);
    if (globalThis.curve_bn128?.terminate) {
      await globalThis.curve_bn128.terminate();
    }
    process.exitCode = 1;
  });
