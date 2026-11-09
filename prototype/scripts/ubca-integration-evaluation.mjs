import { finalizedRecordFor, rememberFinalized } from "./lib/finalized-record.mjs";
import { mkdir, mkdtemp, readFile, rmdir, unlink, writeFile } from "node:fs/promises";
import { resolve, join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import ganache from "ganache";
import solc from "solc";
import { ethers } from "ethers";
import { groth16, wtns } from "snarkjs";
import { WitnessCalculatorBuilder } from "circom_runtime";
import {
  DST_ENROLL,
  DST_PROBE,
  poseidonCommitment,
  squaredDistance,
} from "./commitment.mjs";
import { syntheticPolicySpec } from "./lib/canonical-policy.mjs";
import { Eip712BudgetedSigner } from "./lib/eip712-budgeted-signer.mjs";

const prototypeRoot = resolve(import.meta.dirname, "..");
const outputRoot = resolve(prototypeRoot, "build", "ubca-integration");
const scalarField =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const researchScope = {
  authorization: "authorized defensive academic evaluation",
  environment: "in-process Ganache chain ID 31337",
  data: "synthetic vectors only",
  externalTargets: false,
  purpose:
    "validate the integrated uniqueness-receipt, enrollment-link, capture-provenance, full-vector proof, and atomic-lifecycle chain",
};

function hash(label) {
  return ethers.utils.keccak256(ethers.utils.toUtf8Bytes(label));
}

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

async function confirmed(transactionPromise) {
  const transaction = await transactionPromise;
  const receipt = await transaction.wait();
  if (receipt.status !== 1) throw new Error("local transaction failed");
  return receipt;
}

async function expectLocalRejection(operation, label) {
  try {
    await operation();
  } catch {
    return true;
  }
  throw new Error(`negative control unexpectedly succeeded: ${label}`);
}

function eventArgument(receipt, eventName, argumentName) {
  const event = receipt.events.find(({ event: name }) => name === eventName);
  if (!event) throw new Error(`missing local ${eventName} event`);
  return event.args[argumentName];
}

async function compileContracts() {
  const [
    lifecycleSource,
    gatewaySource,
    pinnedGatewaySource,
    adapterInterface,
    finalizationSourceInterface,
    finalizationAdapterSource,
    localFinalizationSource,
    verifierSource,
  ] = await Promise.all([
    readFile(resolve(prototypeRoot, "contracts", "UBCALifecycle.sol"), "utf8"),
    readFile(resolve(prototypeRoot, "contracts", "UBCAAuthGateway.sol"), "utf8"),
    readFile(resolve(prototypeRoot, "contracts", "BioZEROPinnedGateway.sol"), "utf8"),
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
  const input = {
    language: "Solidity",
    sources: {
      "UBCALifecycle.sol": { content: lifecycleSource },
      "UBCAAuthGateway.sol": { content: gatewaySource },
      "BioZEROPinnedGateway.sol": { content: pinnedGatewaySource },
      "interfaces/IBioZKFHEUniquenessAdapter.sol": {
        content: adapterInterface,
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
      metadata: { bytecodeHash: "none" },
      outputSelection: {
        "*": {
          "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"],
        },
      },
    },
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors ?? []).filter(({ severity }) => severity === "error");
  if (errors.length > 0) {
    throw new Error(errors.map(({ formattedMessage }) => formattedMessage).join("\n"));
  }
  return {
    gateway: output.contracts["BioZEROPinnedGateway.sol"].BioZEROPinnedGateway,
    adapter:
      output.contracts["BioZKFHEFinalizationAdapter.sol"]
        .BioZKFHEFinalizationAdapter,
    source:
      output.contracts["test/LocalBioZKFHEFinalizationSource.sol"]
        .LocalBioZKFHEFinalizationSource,
    verifier: output.contracts["Groth16Verifier.sol"].Groth16Verifier,
  };
}

function renderReport(result) {
  return `# Integrated UBCA local defensive evaluation

## Scope

This experiment ran entirely against researcher-owned contracts on an
in-process Ganache chain with synthetic vectors. It contacted no public network
or third-party service. The Groth16 key is benchmark-only. The adapter derives
receipts from a same-chain terminal-state interface; the source contract is a
local immutable-state fixture rather than the actual BioZKFHE deployment. The
capture key is a software-wallet mock rather than a hardware-isolated key.

## End-to-end chain

\`atomic source-session consumption and enrollment co-attestation
-> active credential/device/policy
-> context-bound full-vector Groth16 proof -> authorized capture statement
-> atomic challenge consumption\`

| Check | Result |
|---|---:|
| Unique receipt consumed by exactly the issued credential | ${result.securityControls.uniqueReceiptConsumed ? "PASS" : "FAIL"} |
| Receipt derived from validated same-chain terminal state | ${result.securityControls.sourceTerminalStateVerified ? "PASS" : "FAIL"} |
| Source session and destination credential change atomically | ${result.securityControls.sourceSessionConsumedAtomically ? "PASS" : "FAIL"} |
| Legacy owner receipt path permanently disabled | ${result.securityControls.legacyReceiptPathDisabled ? "PASS" : "FAIL"} |
| Full-vector proof verifies offline | ${result.securityControls.offlineGroth16Verified ? "PASS" : "FAIL"} |
| Capture signature outside authorized device identity rejected | ${result.securityControls.outsideCaptureSignerRejected ? "PASS" : "FAIL"} |
| Device revoked before submission rejects prepared authentication | ${result.securityControls.deviceRevokedBeforeSubmitRejected ? "PASS" : "FAIL"} |
| Credential revoked before submission rejects prepared authentication | ${result.securityControls.credentialRevokedBeforeSubmitRejected ? "PASS" : "FAIL"} |
| Policy revoked before submission rejects prepared authentication | ${result.securityControls.policyRevokedBeforeSubmitRejected ? "PASS" : "FAIL"} |
| Rejected controls preserve pending challenge | ${result.securityControls.rejectionsPreservedChallenge ? "PASS" : "FAIL"} |
| Authorized integrated authentication accepted | ${result.securityControls.integratedAuthenticationAccepted ? "PASS" : "FAIL"} |
| Acceptance consumes challenge and replay is rejected | ${result.securityControls.atomicConsumptionAndReplayRejection ? "PASS" : "FAIL"} |
| Old policy cannot issue a challenge after replacement | ${result.securityControls.oldPolicyChallengeRejected ? "PASS" : "FAIL"} |
| Wrong successor signature preserves new source receipt | ${result.securityControls.invalidSuccessorSignatureRejected && result.securityControls.successorReceiptPreservedOnFailure ? "PASS" : "FAIL"} |
| New receipt atomically supersedes the old credential | ${result.securityControls.oldCredentialSuperseded && result.securityControls.successorReceiptConsumed ? "PASS" : "FAIL"} |
| New-policy proof verifies and old-policy proof is rejected | ${result.securityControls.migrationProofVerified && result.securityControls.oldProofRejectedForSuccessor ? "PASS" : "FAIL"} |
| Old enrollment commitment fails under successor policy digest | ${result.securityControls.oldCommitmentCannotOpenUnderSuccessor ? "PASS" : "FAIL"} |
| Successor authentication consumes its challenge | ${result.securityControls.successorAuthenticationAccepted && result.securityControls.successorChallengeConsumed ? "PASS" : "FAIL"} |
| Budgeted EIP-712 signer replays exact bytes and blocks extra signatures | ${result.securityControls.initialBudgetReplayIdentical && result.securityControls.initialBudgetExhaustionRejected && result.securityControls.successorBudgetReplayIdentical && result.securityControls.successorBudgetExhaustionRejected ? "PASS" : "FAIL"} |
| Policy replacement revokes the old signing scope | ${result.securityControls.oldBudgetReplayRejected ? "PASS" : "FAIL"} |
| Local EIP-712 digests match gateway before and after migration | ${result.securityControls.initialLocalCaptureDigestMatchesGateway && result.securityControls.successorLocalCaptureDigestMatchesGateway ? "PASS" : "FAIL"} |

## Public observer view of cross-application migration

This view is derived from decoded public gateway logs and credential getters,
without using the fixture's vectors or salts. The old and successor
application IDs, policy hashes, enrollment commitments, and device signing
keys differ. Nevertheless, both authentication events expose the same holder,
both credential-issuance events expose the same lineage ID, and a
\`CredentialSuperseded\` event names the old and new credential IDs. An
observer can therefore link these two synthetic sessions directly. Distinct
commitment bytes do not imply whole-transcript unlinkability.

| Public observation | Result |
|---|---:|
| Different application IDs and policy hashes | ${result.observerView.controls.differentApplicationIds && result.observerView.controls.differentPolicyHashes ? "YES" : "NO"} |
| Different enrollment commitments and device signing keys | ${result.observerView.controls.differentCommitments && result.observerView.controls.differentDeviceKeys ? "YES" : "NO"} |
| Same holder address and lineage ID | ${result.observerView.controls.sameHolder && result.observerView.controls.sameLineage ? "YES" : "NO"} |
| Explicit old-to-new credential supersession link | ${result.observerView.controls.supersessionLinksCredentials ? "YES" : "NO"} |

This is an observer trace for one local migration, not a statistical privacy
experiment or a claim about separate users with no shared public metadata.

## Measurements

| Item | Value |
|---|---:|
| Gateway runtime bytecode | ${result.measurements.gatewayRuntimeBytes.toLocaleString()} bytes |
| Gateway deployment | ${result.measurements.gatewayDeploymentGas.toLocaleString()} gas |
| Source adapter runtime bytecode | ${result.measurements.adapterRuntimeBytes.toLocaleString()} bytes |
| Source adapter deployment | ${result.measurements.adapterDeploymentGas.toLocaleString()} gas |
| Local source fixture deployment | ${result.measurements.sourceDeploymentGas.toLocaleString()} gas |
| Canonical policy and threshold registration | ${result.measurements.registerCanonicalPolicyGas.toLocaleString()} gas |
| Device registration | ${result.measurements.registerDeviceGas.toLocaleString()} gas |
| Local source finalization record | ${result.measurements.recordSourceFinalizationGas.toLocaleString()} gas |
| Atomic receipt consumption and credential issuance | ${result.measurements.atomicIssuanceGas.toLocaleString()} gas |
| Challenge issuance | ${result.measurements.issueChallengeGas.toLocaleString()} gas |
| Integrated authentication | ${result.measurements.authenticationGas.toLocaleString()} gas |
| Witness plus proof generation | ${result.measurements.provingElapsedMs.toFixed(2)} ms |
| Canonical policy replacement | ${result.measurements.replaceCanonicalPolicyGas.toLocaleString()} gas |
| Atomic successor issuance | ${result.measurements.successorIssuanceGas.toLocaleString()} gas |
| Successor authentication | ${result.measurements.successorAuthenticationGas.toLocaleString()} gas |
| Successor witness plus proof | ${result.measurements.migrationProvingElapsedMs.toFixed(2)} ms |

## Interpretation and limits

This exercises the listed software-composition controls: the authentication
transaction reads the same monotonic credential, device, and policy state
created by atomic uniqueness-bound issuance. Adapter consumption, canonical
receipt checks, enrollment-link verification, and credential creation now share
one cross-contract EVM transaction. Canonical EVM ordering gives revocation
its intended meaning: a revocation transaction linearized before verification
causes the already-prepared proof and capture statement to fail.

The public proof threshold is now checked against its immutable policy mapping;
the separate strong-baseline evaluation covers threshold substitution and
compares the same gateway with an attested-matcher backend. These traces are
not a complete security proof or evidence of novelty over strong composition.

The local EIP-712 budget signer uses a durable SQLite counter and signs only
after reserving one unit. Exact transcript replay uses no new unit, and policy
replacement revokes the old signing scope. The host still computes cProbe
before requesting a signature and retains software key access in this fixture;
these checks are a signature budget, not pre-sensor exposure control.

This result exercises destination adapter logic and same-chain terminal
state checks, but does not claim that the local source fixture executed PVSC,
threshold decryption, or committee confirmation. The next source-side gate is
to expose the frozen view from the actual BioZKFHE contract. The hardware gate
remains a real sensor-to-commitment TCB instance.
`;
}

async function evaluate() {
  await mkdir(outputRoot, { recursive: true });
  console.log("AUTHORIZED LOCAL UBCA INTEGRATION EVALUATION");
  console.log(jsonWithBigInts(researchScope));

  const compiled = await compileContracts();
  const gatewayRuntimeBytes =
    compiled.gateway.evm.deployedBytecode.object.length / 2;
  const adapterRuntimeBytes =
    compiled.adapter.evm.deployedBytecode.object.length / 2;
  if (gatewayRuntimeBytes > 24_576) {
    throw new Error(`integrated gateway exceeds EIP-170: ${gatewayRuntimeBytes}`);
  }

  const eip1193 = ganache.provider({
    chain: { chainId: 31337, hardfork: "shanghai" },
    miner: { blockGasLimit: 30_000_000 },
    logging: { quiet: true },
    wallet: { deterministic: true, totalAccounts: 4 },
  });
  const provider = new ethers.providers.Web3Provider(eip1193);
  const accounts = Object.values(eip1193.getInitialAccounts());
  const owner = new ethers.Wallet(accounts[0].secretKey, provider);
  const device = new ethers.Wallet(accounts[1].secretKey, provider);
  const holder = new ethers.Wallet(accounts[2].secretKey, provider);
  const outsideSigner = new ethers.Wallet(accounts[3].secretKey, provider);
  const budgetDirectory = await mkdtemp(join(tmpdir(), "biozero-eip712-budget-"));
  const budgetDatabase = join(budgetDirectory, "capture.sqlite");
  const budgetSigners = [];

  try {
    const verifier = await factory(compiled.verifier, owner).deploy();
    await verifier.deployTransaction.wait();
    const source = await factory(compiled.source, owner).deploy();
    const sourceDeployment = await source.deployTransaction.wait();
    const adapter = await factory(compiled.adapter, owner).deploy(source.address);
    const adapterDeployment = await adapter.deployTransaction.wait();
    const gateway = await factory(compiled.gateway, owner).deploy(verifier.address);
    const gatewayDeployment = await gateway.deployTransaction.wait();
    const configureGatewayAdapter = await confirmed(
      gateway.configureUniquenessAdapter(adapter.address),
    );
    const configureAdapterConsumer = await confirmed(
      adapter.configureAuthorizedConsumer(gateway.address),
    );
    const disableLegacyReceiptPath = await confirmed(
      gateway.disableLegacyReceiptPath(),
    );

    const fixture = JSON.parse(
      await readFile(
        resolve(prototypeRoot, "inputs", "generated", "auth_distance_128.json"),
        "utf8",
      ),
    );
    const modelHash = hash("ubca/integrated/model/128/v1");
    const quantizationHash = hash("ubca/integrated/quant/u16/v1");
    const policySpec = syntheticPolicySpec({
      label: "ubca/integrated/policy/v1", modelHash, quantizationHash,
      epsilon: fixture.epsilon,
    });
    policySpec.circuitHash = await gateway.pinnedCircuitHash();
    if (Number(await gateway.pinnedDimension()) !== 128) {
      throw new Error("integration verifier is not the pinned 128-D profile");
    }
    const policyHash = await gateway.canonicalPolicyHash(policySpec);
    const firmwareMeasurement = hash("ubca/integrated/mock-firmware/v1");
    const lineageId = hash("ubca/integrated/lineage/v1");
    const enrollmentContext = hash("ubca/integrated/enrollment-context/v1");
    const policyDigest = (await gateway.policyFieldDigest(policyHash)).toString();

    const cEnroll = await poseidonCommitment({
      roleTag: DST_ENROLL,
      policyDigest: BigInt(policyDigest),
      contextDigest: 0n,
      dimension: 128,
      salt: BigInt(fixture.rEnroll),
      values: fixture.enrollment.map(BigInt),
      packSize: 15,
    });

    const policyReceipt = await confirmed(gateway.registerCanonicalPolicy(policySpec));
    const deviceReceipt = await confirmed(
      gateway.registerDevice(
        device.address,
        firmwareMeasurement,
        modelHash,
        quantizationHash,
        policyHash,
      ),
    );
    const deviceVersionId = eventArgument(
      deviceReceipt,
      "DeviceRegistered",
      "deviceVersionId",
    );
    const sourceSessionId = hash("ubca/integrated/source-session/v1");
    const sourceContextHash = hash("ubca/integrated/source-context/v1");
    const gallerySnapshotHash = hash("ubca/integrated/gallery-snapshot/v1");
    const queryCiphertextDigest = hash("ubca/integrated/C-identify/v1");
    const enrollmentCiphertextDigest = hash("ubca/integrated/C-enroll/v1");
    const verifiedOutputCollectionDigest = hash("ubca/integrated/outputs/v1");
    const finalizedAtBlock = (await provider.getBlock("latest")).number;
    const sourceSession = {
      operation: 1,
      finalized: true,
      uniquenessAccepted: true,
      expectedBlockCount: 4,
      verifiedBlockCount: 4,
      confirmationThreshold: 3,
      confirmationCount: 3,
      sourceContextHash,
      gallerySnapshotHash,
      queryCiphertextDigest,
      enrollmentCiphertextDigest,
      verifiedOutputCollectionDigest,
      modelHash,
      quantizationHash,
      finalizedAtBlock,
    };
    const sourceFinalizationRecord = await confirmed(
      source.recordImmutableSession(sourceSessionId, rememberFinalized(sourceSessionId, sourceSession)),
    );
    const finalizedReceipt =
      await adapter.previewFinalizedUniqueEnrollment(sourceSessionId, finalizedRecordFor(sourceSessionId));
    const receiptId = finalizedReceipt.receiptId;
    const uniqueInputDigest = finalizedReceipt.uniqueInputDigest;
    const sourceTerminalStateVerified =
      finalizedReceipt.sourceChainId.toNumber() === 31337 &&
      finalizedReceipt.sourceContract.toLowerCase() === source.address.toLowerCase() &&
      finalizedReceipt.sourceSessionId === sourceSessionId &&
      finalizedReceipt.queryCiphertextDigest === queryCiphertextDigest &&
      finalizedReceipt.enrollmentCiphertextDigest === enrollmentCiphertextDigest &&
      finalizedReceipt.verifiedOutputCollectionDigest ===
        verifiedOutputCollectionDigest &&
      (await gateway.finalizedReceiptId(
        31337,
        source.address,
        sourceSessionId,
        finalizedReceipt.finalizationDigest,
      )) === receiptId &&
      (await gateway.finalizedUniqueInputDigest(finalizedReceipt)) ===
        uniqueInputDigest;
    const issueRequest = {
      receiptId,
      lineageId,
      cEnroll: cEnroll.toString(),
      policyHash,
      modelHash,
      quantizationHash,
      templateVersion: 1,
      holder: holder.address,
      deviceVersionId,
      uniqueInputDigest,
      enrollmentContext,
    };
    const enrollmentDigest = await gateway.enrollmentLinkDigest(issueRequest);
    const enrollmentSignature = ethers.utils.joinSignature(
      device._signingKey().signDigest(enrollmentDigest),
    );
    const credentialId = await gateway.callStatic.issueFromFinalizedBioZKFHESession(
      sourceSessionId,
      finalizedRecordFor(sourceSessionId),
      issueRequest,
      enrollmentSignature,
    );
    const issueReceipt = await confirmed(
      gateway.issueFromFinalizedBioZKFHESession(
        sourceSessionId,
        finalizedRecordFor(sourceSessionId),
        issueRequest,
        enrollmentSignature,
      ),
    );
    const recordedReceipt = await gateway.uniqueReceipts(receiptId);
    const uniqueReceiptConsumed = recordedReceipt.consumedBy === credentialId;
    const consumerBinding = await gateway.receiptConsumerBinding(
      lineageId,
      holder.address,
    );
    const sourceSessionConsumedAtomically =
      (await adapter.consumedBy(sourceSessionId)) === consumerBinding;

    const latest = await provider.getBlock("latest");
    const deadline = latest.timestamp + 600;
    const action = hash("ubca/integrated/authorize-session");
    const challengeReceipt = await confirmed(
      gateway
        .connect(holder)
        .issueAuthenticationChallenge(
          action,
          credentialId,
          deviceVersionId,
          deadline,
        ),
    );
    const nonce = eventArgument(challengeReceipt, "UBCAAuthChallengeIssued", "nonce");
    const ctxHash = eventArgument(
      challengeReceipt,
      "UBCAAuthChallengeIssued",
      "ctxHash",
    ).toString();
    const registryEpochAtIssue = eventArgument(
      challengeReceipt,
      "UBCAAuthChallengeIssued",
      "registryEpochAtIssue",
    );
    const context = {
      beneficiary: holder.address,
      action,
      credentialId,
      deviceVersionId,
      registryEpochAtIssue,
      nonce,
      deadline,
    };
    const [encodedContextHash, recomputedCtxHash] =
      await gateway.computeAuthContextHash(context);
    if (recomputedCtxHash.toString() !== ctxHash) {
      throw new Error("integrated context hash mismatch");
    }

    const rProbe = randomFieldElement();
    const cProbe = await poseidonCommitment({
      roleTag: DST_PROBE,
      policyDigest: BigInt(policyDigest),
      contextDigest: BigInt(ctxHash),
      dimension: 128,
      salt: rProbe,
      values: fixture.probe.map(BigInt),
      packSize: 15,
    });
    const circuitInput = {
      ...fixture,
      cEnroll: cEnroll.toString(),
      cProbe: cProbe.toString(),
      policyDigest,
      ctxHash,
      rProbe: rProbe.toString(),
    };
    await writeFile(
      resolve(outputRoot, "input.json"),
      `${jsonWithBigInts(circuitInput)}\n`,
      "utf8",
    );
    const witnessPath = resolve(outputRoot, "witness.wtns");
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
    const verificationKey = JSON.parse(
      await readFile(
        resolve(
          prototypeRoot,
          "build",
          "proving",
          "auth_distance_128",
          "verification_key.json",
        ),
        "utf8",
      ),
    );
    const provingStarted = process.hrtime.bigint();
    await wtns.calculate(circuitInput, wasmPath, witnessPath, {});
    const { proof, publicSignals } = await groth16.prove(zkeyPath, witnessPath);
    const provingElapsedMs = Number(process.hrtime.bigint() - provingStarted) / 1e6;
    const offlineGroth16Verified = await groth16.verify(
      verificationKey,
      publicSignals,
      proof,
    );
    if (!offlineGroth16Verified) throw new Error("integrated proof failed offline");
    const proofArguments = JSON.parse(
      `[${await groth16.exportSolidityCallData(proof, publicSignals)}]`,
    );
    await writeFile(
      resolve(outputRoot, "proof.json"),
      `${jsonWithBigInts(proof)}\n`,
      "utf8",
    );
    await writeFile(
      resolve(outputRoot, "public.json"),
      `${jsonWithBigInts(publicSignals)}\n`,
      "utf8",
    );

    const capture = {
      cProbe: cProbe.toString(),
      ctxHash,
      credentialId,
      deviceVersionId,
      policyHash,
      modelHash,
      quantizationHash,
      firmwareMeasurement,
      registryEpochAtCapture: await gateway.registryEpoch(),
      counter: 1,
      notAfter: deadline,
    };
    const initialBudgetSigner = new Eip712BudgetedSigner({
      database: budgetDatabase,
      scope: {
        applicationId: policySpec.applicationId,
        holder: holder.address,
        credentialId,
        deviceVersionId,
        policyHash,
        budgetPolicyHash: policySpec.budgetPolicyHash,
        windowId: hash("ubca/integrated/budget-window/v1"),
      },
      wallet: device,
      chainId: (await provider.getNetwork()).chainId,
      gatewayAddress: gateway.address,
    });
    budgetSigners.push(initialBudgetSigner);
    initialBudgetSigner.provision(1);
    const budgetedCapture = await initialBudgetSigner.signCapture({
      attemptId: nonce, capture,
    });
    const captureSignature = budgetedCapture.signature;
    const initialBudgetReplayIdentical = initialBudgetSigner
      .retransmit(nonce).bytes.equals(budgetedCapture.bytes);
    const initialBudgetExhaustionRejected = await expectLocalRejection(
      () => initialBudgetSigner.signCapture({
        attemptId: hash("ubca/integrated/extra-signature"),
        capture: { ...capture, counter: 2 },
      }),
      "initial EIP-712 signing budget exhausted",
    );
    const captureDigest = await gateway.captureStatementDigest(capture);
    const initialLocalCaptureDigestMatchesGateway =
      initialBudgetSigner.captureDigest(capture) === captureDigest;
    if (!initialLocalCaptureDigestMatchesGateway) {
      throw new Error("local EIP-712 capture digest differs from gateway");
    }
    const outsideCaptureSignature = ethers.utils.joinSignature(
      outsideSigner._signingKey().signDigest(captureDigest),
    );
    const verifyArguments = [
      ...proofArguments,
      context,
      capture,
      captureSignature,
    ];

    const outsideCaptureSignerRejected = await expectLocalRejection(
      () =>
        gateway
          .connect(holder)
          .callStatic.verifyAndConsumeAuthentication(
            ...proofArguments,
            context,
            capture,
            outsideCaptureSignature,
          ),
      "outside capture signer",
    );

    async function evaluateRevocation(revokeTransaction, label) {
      const snapshot = await provider.send("evm_snapshot", []);
      await confirmed(revokeTransaction());
      const rejected = await expectLocalRejection(
        () =>
          gateway
            .connect(holder)
            .callStatic.verifyAndConsumeAuthentication(...verifyArguments),
        label,
      );
      const challengePreserved =
        (await gateway.pendingAuthContexts(nonce)).toLowerCase() ===
        encodedContextHash.toLowerCase();
      if (!(await provider.send("evm_revert", [snapshot]))) {
        throw new Error(`failed to restore local ${label} snapshot`);
      }
      return { rejected, challengePreserved };
    }

    const deviceRevocation = await evaluateRevocation(
      () => gateway.revokeDevice(deviceVersionId),
      "device revoked before submission",
    );
    const credentialRevocation = await evaluateRevocation(
      () => gateway.revokeCredential(credentialId),
      "credential revoked before submission",
    );
    const policyRevocation = await evaluateRevocation(
      () => gateway.revokePolicy(policyHash),
      "policy revoked before submission",
    );

    const integratedAuthenticationAccepted = await gateway
      .connect(holder)
      .callStatic.verifyAndConsumeAuthentication(...verifyArguments);
    if (!integratedAuthenticationAccepted) {
      throw new Error("integrated authentication positive control failed");
    }
    const authenticationReceipt = await confirmed(
      gateway
        .connect(holder)
        .verifyAndConsumeAuthentication(...verifyArguments),
    );
    const challengeConsumed =
      (await gateway.pendingAuthContexts(nonce)) === ethers.constants.HashZero;
    const replayRejected = await expectLocalRejection(
      () =>
        gateway
          .connect(holder)
          .callStatic.verifyAndConsumeAuthentication(...verifyArguments),
      "accepted integrated authentication replay",
    );

    // Migrate the same lineage to a distinct application domain. The source
    // fixture and capture signer remain local software test doubles.
    const successorSpec = {
      ...policySpec,
      applicationId: hash("ubca/integrated/application/v2"),
    };
    const successorPolicyHash = await gateway.canonicalPolicyHash(successorSpec);
    const successorPolicyReceipt = await confirmed(
      gateway.replaceCanonicalPolicy(policyHash, successorSpec),
    );
    initialBudgetSigner.revoke();
    const oldBudgetReplayRejected = await expectLocalRejection(
      () => initialBudgetSigner.retransmit(nonce),
      "revoked old policy signing scope",
    );
    const oldPolicyDeadline = (await provider.getBlock("latest")).timestamp + 600;
    const oldPolicyChallengeRejected = await expectLocalRejection(
      () => gateway.connect(holder).issueAuthenticationChallenge(
        hash("ubca/integrated/old-after-policy-change"),
        credentialId, deviceVersionId,
        oldPolicyDeadline,
      ),
      "old policy cannot issue challenge after replacement",
    );
    const successorDeviceReceipt = await confirmed(gateway.registerDevice(
      outsideSigner.address,
      hash("ubca/integrated/mock-firmware/v2"),
      modelHash, quantizationHash, successorPolicyHash,
    ));
    const successorDeviceVersionId = eventArgument(
      successorDeviceReceipt, "DeviceRegistered", "deviceVersionId",
    );
    let successorEnrollmentSalt = randomFieldElement();
    while (successorEnrollmentSalt === BigInt(fixture.rEnroll)) {
      successorEnrollmentSalt = randomFieldElement();
    }
    const successorPolicyDigest =
      (await gateway.policyFieldDigest(successorPolicyHash)).toString();
    const successorCEnroll = await poseidonCommitment({
      roleTag: DST_ENROLL,
      policyDigest: BigInt(successorPolicyDigest),
      contextDigest: 0n,
      dimension: 128,
      salt: successorEnrollmentSalt,
      values: fixture.enrollment.map(BigInt),
      packSize: 15,
    });
    if (successorCEnroll === cEnroll) {
      throw new Error("new policy and salt unexpectedly retained enrollment commitment");
    }

    const successorSourceSessionId = hash("ubca/integrated/source-session/v2");
    await confirmed(source.recordImmutableSession(successorSourceSessionId, rememberFinalized(successorSourceSessionId, {
      ...sourceSession,
      sourceContextHash: hash("ubca/integrated/source-context/v2"),
      gallerySnapshotHash: hash("ubca/integrated/gallery-snapshot/v2"),
      queryCiphertextDigest: hash("ubca/integrated/C-identify/v2"),
      enrollmentCiphertextDigest: hash("ubca/integrated/C-enroll/v2"),
      verifiedOutputCollectionDigest: hash("ubca/integrated/outputs/v2"),
      finalizedAtBlock: (await provider.getBlock("latest")).number,
    })));
    const successorSourceReceipt =
      await adapter.previewFinalizedUniqueEnrollment(successorSourceSessionId, finalizedRecordFor(successorSourceSessionId));
    const successorRequest = {
      ...issueRequest,
      receiptId: successorSourceReceipt.receiptId,
      cEnroll: successorCEnroll.toString(),
      policyHash: successorPolicyHash,
      templateVersion: 2,
      deviceVersionId: successorDeviceVersionId,
      uniqueInputDigest: successorSourceReceipt.uniqueInputDigest,
      enrollmentContext: hash("ubca/integrated/enrollment-context/v2"),
    };
    const successorEnrollmentDigest =
      await gateway.enrollmentLinkDigest(successorRequest);
    const successorSignature = ethers.utils.joinSignature(
      outsideSigner._signingKey().signDigest(successorEnrollmentDigest),
    );
    const wrongSuccessorSignature = ethers.utils.joinSignature(
      device._signingKey().signDigest(successorEnrollmentDigest),
    );
    const invalidSuccessorSignatureRejected = await expectLocalRejection(
      () => gateway.replaceTemplateFromFinalizedBioZKFHESession(
        credentialId, successorSourceSessionId, finalizedRecordFor(successorSourceSessionId), successorRequest,
        wrongSuccessorSignature,
      ),
      "wrong successor enrollment signer",
    );
    const successorReceiptPreservedOnFailure =
      (await adapter.consumedBy(successorSourceSessionId)) === ethers.constants.HashZero &&
      !(await gateway.uniqueReceipts(successorSourceReceipt.receiptId)).exists;
    const successorCredentialId = await gateway.callStatic
      .replaceTemplateFromFinalizedBioZKFHESession(
        credentialId, successorSourceSessionId, finalizedRecordFor(successorSourceSessionId), successorRequest,
        successorSignature,
      );
    const successorIssuanceReceipt = await confirmed(
      gateway.replaceTemplateFromFinalizedBioZKFHESession(
        credentialId, successorSourceSessionId, finalizedRecordFor(successorSourceSessionId), successorRequest,
        successorSignature,
      ),
    );
    const oldCredentialSuperseded =
      (await gateway.credentials(credentialId)).status === 2 &&
      (await gateway.credentials(credentialId)).successor === successorCredentialId &&
      (await gateway.activeCredentialByLineage(lineageId)) === successorCredentialId;
    const successorReceiptConsumed =
      (await gateway.uniqueReceipts(successorSourceReceipt.receiptId)).consumedBy ===
        successorCredentialId &&
      (await adapter.consumedBy(successorSourceSessionId)) === consumerBinding;

    const successorDeadline = (await provider.getBlock("latest")).timestamp + 600;
    const successorAction = hash("ubca/integrated/authorize-session/v2");
    const successorChallengeReceipt = await confirmed(gateway.connect(holder)
      .issueAuthenticationChallenge(
        successorAction, successorCredentialId, successorDeviceVersionId,
        successorDeadline,
      ));
    const successorCtxHash = eventArgument(
      successorChallengeReceipt, "UBCAAuthChallengeIssued", "ctxHash",
    ).toString();
    const successorContext = {
      beneficiary: holder.address,
      action: successorAction,
      credentialId: successorCredentialId,
      deviceVersionId: successorDeviceVersionId,
      registryEpochAtIssue: eventArgument(
        successorChallengeReceipt, "UBCAAuthChallengeIssued", "registryEpochAtIssue",
      ),
      nonce: eventArgument(successorChallengeReceipt, "UBCAAuthChallengeIssued", "nonce"),
      deadline: successorDeadline,
    };
    const successorProbeSalt = randomFieldElement();
    const successorCProbe = await poseidonCommitment({
      roleTag: DST_PROBE,
      policyDigest: BigInt(successorPolicyDigest),
      contextDigest: BigInt(successorCtxHash),
      dimension: 128,
      salt: successorProbeSalt,
      values: fixture.probe.map(BigInt),
      packSize: 15,
    });
    const successorCircuitInput = {
      ...fixture,
      cEnroll: successorCEnroll.toString(),
      cProbe: successorCProbe.toString(),
      policyDigest: successorPolicyDigest,
      ctxHash: successorCtxHash,
      rEnroll: successorEnrollmentSalt.toString(),
      rProbe: successorProbeSalt.toString(),
    };
    await writeFile(resolve(outputRoot, "migration-input.json"),
      `${jsonWithBigInts(successorCircuitInput)}\n`);
    const savedConsoleError = console.error;
    const witnessErrors = [];
    console.error = (...parts) => witnessErrors.push(parts.map(String).join(" "));
    let oldCommitmentCannotOpenUnderSuccessor;
    try {
      const invalidCalculator = await WitnessCalculatorBuilder(await readFile(wasmPath), {});
      oldCommitmentCannotOpenUnderSuccessor = await expectLocalRejection(
        () => invalidCalculator.calculateWTNSBin({
          ...successorCircuitInput, cEnroll: cEnroll.toString(),
        }),
        "old enrollment commitment under successor policy digest",
      );
    } finally {
      console.error = savedConsoleError;
    }
    if (!witnessErrors.some((message) =>
      message.includes("ERROR:  4") && message.includes("AuthDistance"))) {
      throw new Error(`old commitment failed for an unexpected reason: ${witnessErrors.join(" | ")}`);
    }
    const successorWitnessPath = resolve(outputRoot, "migration-witness.wtns");
    const migrationProofStarted = process.hrtime.bigint();
    await wtns.calculate(successorCircuitInput, wasmPath, successorWitnessPath, {});
    const successorProof = await groth16.prove(zkeyPath, successorWitnessPath);
    const migrationProvingElapsedMs =
      Number(process.hrtime.bigint() - migrationProofStarted) / 1e6;
    const migrationProofVerified = await groth16.verify(
      verificationKey, successorProof.publicSignals, successorProof.proof,
    );
    if (!migrationProofVerified) throw new Error("successor proof failed offline");
    const expectedSuccessorSignals = [
      successorCEnroll, successorCProbe, successorPolicyDigest,
      successorCtxHash, fixture.epsilon,
    ].map(String);
    if (!successorProof.publicSignals.every((signal, index) =>
      String(signal) === expectedSuccessorSignals[index])) {
      throw new Error("successor proof public signals do not match the new policy and challenge");
    }
    const successorProofArguments = JSON.parse(
      `[${await groth16.exportSolidityCallData(
        successorProof.proof, successorProof.publicSignals,
      )}]`,
    );
    await writeFile(resolve(outputRoot, "migration-proof.json"),
      `${jsonWithBigInts(successorProof.proof)}\n`);
    await writeFile(resolve(outputRoot, "migration-public.json"),
      `${jsonWithBigInts(successorProof.publicSignals)}\n`);
    const successorCapture = {
      cProbe: successorCProbe.toString(),
      ctxHash: successorCtxHash,
      credentialId: successorCredentialId,
      deviceVersionId: successorDeviceVersionId,
      policyHash: successorPolicyHash,
      modelHash,
      quantizationHash,
      firmwareMeasurement: hash("ubca/integrated/mock-firmware/v2"),
      registryEpochAtCapture: await gateway.registryEpoch(),
      counter: 1,
      notAfter: successorDeadline,
    };
    const successorBudgetSigner = new Eip712BudgetedSigner({
      database: budgetDatabase,
      scope: {
        applicationId: successorSpec.applicationId,
        holder: holder.address,
        credentialId: successorCredentialId,
        deviceVersionId: successorDeviceVersionId,
        policyHash: successorPolicyHash,
        budgetPolicyHash: successorSpec.budgetPolicyHash,
        windowId: hash("ubca/integrated/budget-window/v1"),
      },
      wallet: outsideSigner,
      chainId: (await provider.getNetwork()).chainId,
      gatewayAddress: gateway.address,
    });
    budgetSigners.push(successorBudgetSigner);
    successorBudgetSigner.provision(1);
    const budgetedSuccessorCapture = await successorBudgetSigner.signCapture({
      attemptId: successorContext.nonce,
      capture: successorCapture,
    });
    const successorCaptureSignature = budgetedSuccessorCapture.signature;
    const successorLocalCaptureDigestMatchesGateway =
      successorBudgetSigner.captureDigest(successorCapture) ===
        await gateway.captureStatementDigest(successorCapture);
    if (!successorLocalCaptureDigestMatchesGateway) {
      throw new Error("successor local EIP-712 digest differs from gateway");
    }
    const successorBudgetReplayIdentical = successorBudgetSigner
      .retransmit(successorContext.nonce).bytes.equals(
        budgetedSuccessorCapture.bytes,
      );
    const successorBudgetExhaustionRejected = await expectLocalRejection(
      () => successorBudgetSigner.signCapture({
        attemptId: hash("ubca/integrated/extra-successor-signature"),
        capture: { ...successorCapture, counter: 2 },
      }),
      "successor EIP-712 signing budget exhausted",
    );
    const oldProofRejectedForSuccessor = await expectLocalRejection(
      () => gateway.connect(holder).callStatic.verifyAndConsumeAuthentication(
        ...proofArguments, successorContext, successorCapture,
        successorCaptureSignature,
      ),
      "old policy proof with successor credential",
    );
    const successorAuthenticationAccepted = await gateway.connect(holder)
      .callStatic.verifyAndConsumeAuthentication(
        ...successorProofArguments, successorContext, successorCapture,
        successorCaptureSignature,
      );
    const successorAuthenticationReceipt = await confirmed(gateway.connect(holder)
      .verifyAndConsumeAuthentication(
        ...successorProofArguments, successorContext, successorCapture,
        successorCaptureSignature,
      ));
    const successorChallengeConsumed =
      (await gateway.pendingAuthContexts(successorContext.nonce)) ===
        ethers.constants.HashZero;
    const migrationControls = {
      oldPolicyChallengeRejected,
      invalidSuccessorSignatureRejected,
      successorReceiptPreservedOnFailure,
      oldCredentialSuperseded,
      successorReceiptConsumed,
      migrationProofVerified,
      oldProofRejectedForSuccessor,
      oldCommitmentCannotOpenUnderSuccessor,
      successorAuthenticationAccepted,
      successorChallengeConsumed,
      initialBudgetReplayIdentical,
      initialBudgetExhaustionRejected,
      oldBudgetReplayRejected,
      successorBudgetReplayIdentical,
      successorBudgetExhaustionRejected,
      initialLocalCaptureDigestMatchesGateway,
      successorLocalCaptureDigestMatchesGateway,
    };
    if (!Object.values(migrationControls).every(Boolean)) {
      throw new Error(`migration control failed: ${jsonWithBigInts(migrationControls)}`);
    }

    // Build the privacy observer view only from public contract logs/getters.
    // The fixture knows the underlying vectors; this view intentionally does not.
    const oldIssuedCredential = eventArgument(issueReceipt, "CredentialIssued", "credentialId");
    const successorIssuedCredential = eventArgument(
      successorIssuanceReceipt, "CredentialIssued", "credentialId",
    );
    const observedSupersededOld = eventArgument(
      successorIssuanceReceipt, "CredentialSuperseded", "oldCredentialId",
    );
    const observedSupersededNew = eventArgument(
      successorIssuanceReceipt, "CredentialSuperseded", "newCredentialId",
    );
    const oldCredentialState = await gateway.credentials(oldIssuedCredential);
    const successorCredentialState = await gateway.credentials(successorIssuedCredential);
    const observerView = {
      source: "decoded public gateway events and credential getters only",
      gateway: gateway.address,
      old: {
        applicationId: eventArgument(policyReceipt, "CanonicalPolicyRegistered", "applicationId"),
        policyHash: eventArgument(policyReceipt, "CanonicalPolicyRegistered", "policyHash"),
        credentialId: oldIssuedCredential,
        lineageId: eventArgument(issueReceipt, "CredentialIssued", "lineageId"),
        holder: eventArgument(authenticationReceipt, "UBCAAuthenticationAccepted", "beneficiary"),
        deviceVersionId: eventArgument(authenticationReceipt, "UBCAAuthenticationAccepted", "deviceVersionId"),
        deviceSigningKey: eventArgument(deviceReceipt, "DeviceRegistered", "signingKey"),
        cEnroll: oldCredentialState.cEnroll.toString(),
      },
      successor: {
        applicationId: eventArgument(successorPolicyReceipt, "CanonicalPolicyRegistered", "applicationId"),
        policyHash: eventArgument(successorPolicyReceipt, "CanonicalPolicyRegistered", "policyHash"),
        credentialId: successorIssuedCredential,
        lineageId: eventArgument(successorIssuanceReceipt, "CredentialIssued", "lineageId"),
        holder: eventArgument(successorAuthenticationReceipt, "UBCAAuthenticationAccepted", "beneficiary"),
        deviceVersionId: eventArgument(successorAuthenticationReceipt, "UBCAAuthenticationAccepted", "deviceVersionId"),
        deviceSigningKey: eventArgument(successorDeviceReceipt, "DeviceRegistered", "signingKey"),
        cEnroll: successorCredentialState.cEnroll.toString(),
      },
      explicitSupersession: {
        oldCredentialId: observedSupersededOld,
        newCredentialId: observedSupersededNew,
      },
    };
    observerView.controls = {
      differentApplicationIds: observerView.old.applicationId !== observerView.successor.applicationId,
      differentPolicyHashes: observerView.old.policyHash !== observerView.successor.policyHash,
      differentCommitments: observerView.old.cEnroll !== observerView.successor.cEnroll,
      differentDeviceKeys: observerView.old.deviceSigningKey !== observerView.successor.deviceSigningKey,
      sameHolder: observerView.old.holder === observerView.successor.holder,
      sameLineage: observerView.old.lineageId === observerView.successor.lineageId,
      supersessionLinksCredentials:
        observedSupersededOld === oldIssuedCredential &&
        observedSupersededNew === successorIssuedCredential,
      issuedCredentialIdsMatchRun:
        oldIssuedCredential === credentialId &&
        successorIssuedCredential === successorCredentialId,
    };
    if (!Object.values(observerView.controls).every(Boolean)) {
      throw new Error(`public observer-view control failed: ${jsonWithBigInts(observerView.controls)}`);
    }

    const result = {
      generatedAt: new Date().toISOString(),
      compiler: solc.version(),
      node: process.version,
      researchScope,
      systemProfile: {
        dimension: 128,
        gatewayProfile: "BioZEROPinnedGateway; solc 0.8.36 Shanghai; metadata.bytecodeHash=none",
        circuitR1csSha256: await gateway.pinnedCircuitHash(),
        verifierRuntimeCodeHash: ethers.utils.keccak256(await provider.getCode(verifier.address)),
        freshness: "stateful challenge",
        receiptVerifier:
          "same-chain terminal-state adapter over local immutable BioZKFHE source fixture",
        captureRoot: "software-wallet device mock",
        captureBudget: "SQLite-backed EIP-712 signature budget; host supplies cProbe; not pre-sensor accounting",
        provingKey: "benchmark-only",
        padInScope: false,
      },
      signingBudget: {
        oldScopeId: initialBudgetSigner.scopeId,
        successorScopeId: successorBudgetSigner.scopeId,
        oldUsage: initialBudgetSigner.usage(),
        successorUsage: successorBudgetSigner.usage(),
      },
      observerView,
      migration: {
        oldPolicyHash: policyHash,
        successorPolicyHash,
        successorApplicationId: successorSpec.applicationId,
        oldCredentialId: credentialId,
        successorCredentialId,
        oldEnrollmentCommitment: cEnroll.toString(),
        successorEnrollmentCommitment: successorCEnroll.toString(),
        enrollmentSaltChanged: successorEnrollmentSalt !== BigInt(fixture.rEnroll),
        successorSourceSessionId,
        successorReceiptId: successorSourceReceipt.receiptId,
      },
      securityControls: {
        uniqueReceiptConsumed,
        sourceTerminalStateVerified,
        sourceSessionConsumedAtomically,
        legacyReceiptPathDisabled: await gateway.legacyReceiptPathDisabled(),
        offlineGroth16Verified,
        outsideCaptureSignerRejected,
        deviceRevokedBeforeSubmitRejected: deviceRevocation.rejected,
        credentialRevokedBeforeSubmitRejected: credentialRevocation.rejected,
        policyRevokedBeforeSubmitRejected: policyRevocation.rejected,
        rejectionsPreservedChallenge:
          deviceRevocation.challengePreserved &&
          credentialRevocation.challengePreserved &&
          policyRevocation.challengePreserved,
        integratedAuthenticationAccepted,
        atomicConsumptionAndReplayRejection:
          challengeConsumed && replayRejected,
        oldPolicyChallengeRejected,
        invalidSuccessorSignatureRejected,
        successorReceiptPreservedOnFailure,
        oldCredentialSuperseded,
        successorReceiptConsumed,
        migrationProofVerified,
        oldProofRejectedForSuccessor,
        oldCommitmentCannotOpenUnderSuccessor,
        successorAuthenticationAccepted,
        successorChallengeConsumed,
        initialBudgetReplayIdentical,
        initialBudgetExhaustionRejected,
        oldBudgetReplayRejected,
        successorBudgetReplayIdentical,
        successorBudgetExhaustionRejected,
        initialLocalCaptureDigestMatchesGateway,
        successorLocalCaptureDigestMatchesGateway,
      },
      measurements: {
        gatewayRuntimeBytes,
        gatewayDeploymentGas: gatewayDeployment.gasUsed.toNumber(),
        adapterRuntimeBytes,
        adapterDeploymentGas: adapterDeployment.gasUsed.toNumber(),
        sourceDeploymentGas: sourceDeployment.gasUsed.toNumber(),
        registerCanonicalPolicyGas: policyReceipt.gasUsed.toNumber(),
        registerDeviceGas: deviceReceipt.gasUsed.toNumber(),
        configureGatewayAdapterGas: configureGatewayAdapter.gasUsed.toNumber(),
        configureAdapterConsumerGas: configureAdapterConsumer.gasUsed.toNumber(),
        disableLegacyReceiptPathGas:
          disableLegacyReceiptPath.gasUsed.toNumber(),
        recordSourceFinalizationGas: sourceFinalizationRecord.gasUsed.toNumber(),
        atomicIssuanceGas: issueReceipt.gasUsed.toNumber(),
        issueChallengeGas: challengeReceipt.gasUsed.toNumber(),
        authenticationGas: authenticationReceipt.gasUsed.toNumber(),
        provingElapsedMs,
        replaceCanonicalPolicyGas: successorPolicyReceipt.gasUsed.toNumber(),
        successorIssuanceGas: successorIssuanceReceipt.gasUsed.toNumber(),
        successorAuthenticationGas: successorAuthenticationReceipt.gasUsed.toNumber(),
        migrationProvingElapsedMs,
        squaredDistance: squaredDistance(
          fixture.enrollment,
          fixture.probe,
        ).toString(),
      },
      limitations: [
        "local source fixture does not execute BioZKFHE PVSC, threshold decryption, or committee confirmation",
        "actual BioZKFHE contract does not yet expose the frozen finalization view",
        "capture key is not hardware-isolated",
        "EIP-712 budget limits only this software signer; cProbe was computed before reservation and host can bypass the signer",
        "sensor-to-commitment path is not yet physically evaluated",
        "PAD/liveness is out of scope",
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
    for (const signer of budgetSigners) signer.close();
    await unlink(budgetDatabase).catch((error) => {
      if (error.code !== "ENOENT") throw error;
    });
    await rmdir(budgetDirectory);
    await eip1193.disconnect();
  }
}

evaluate()
  .then(async (result) => {
    console.log("\nLOCAL UBCA INTEGRATION COMPLETE");
    console.log(
      jsonWithBigInts({
        securityControls: result.securityControls,
        measurements: result.measurements,
        report: resolve(outputRoot, "REPORT.md"),
      }),
    );
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
