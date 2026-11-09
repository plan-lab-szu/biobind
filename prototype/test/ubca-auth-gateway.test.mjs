import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { ethers } from "ethers";
import ganache from "ganache";
import solc from "solc";
import { registerSyntheticPolicy, syntheticPolicySpec } from "../scripts/lib/canonical-policy.mjs";

const prototypeRoot = resolve(import.meta.dirname, "..");
const pA = [0, 0];
const pB = [[0, 0], [0, 0]];
const pC = [0, 0];

function hash(label) {
  return ethers.utils.keccak256(ethers.utils.toUtf8Bytes(label));
}

async function compileGateway() {
  const [lifecycle, gateway, adapterInterface] = await Promise.all([
    readFile(resolve(prototypeRoot, "contracts", "UBCALifecycle.sol"), "utf8"),
    readFile(resolve(prototypeRoot, "contracts", "UBCAAuthGateway.sol"), "utf8"),
    readFile(
      resolve(
        prototypeRoot,
        "contracts",
        "interfaces",
        "IBioZKFHEUniquenessAdapter.sol",
      ),
      "utf8",
    ),
  ]);
  const mock = `
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.24;
    contract LocalAcceptingVerifier {
      function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[5] calldata
      ) external pure returns (bool) { return true; }
    }
  `;
  const input = {
    language: "Solidity",
    sources: {
      "UBCALifecycle.sol": { content: lifecycle },
      "UBCAAuthGateway.sol": { content: gateway },
      "interfaces/IBioZKFHEUniquenessAdapter.sol": {
        content: adapterInterface,
      },
      "LocalAcceptingVerifier.sol": { content: mock },
    },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: "shanghai",
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
    gateway: output.contracts["UBCAAuthGateway.sol"].UBCAAuthGateway,
    verifier:
      output.contracts["LocalAcceptingVerifier.sol"].LocalAcceptingVerifier,
  };
}

async function confirmed(transactionPromise) {
  return (await transactionPromise).wait();
}

async function expectRevert(operation, label) {
  try {
    await operation();
  } catch {
    return;
  }
  assert.fail(`expected local rejection: ${label}`);
}

function eventArgument(receipt, eventName, argumentName) {
  const event = receipt.events.find(({ event: name }) => name === eventName);
  assert.ok(event, `missing ${eventName} event`);
  return event.args[argumentName];
}

async function deployFixture() {
  const compiled = await compileGateway();
  const runtimeBytes = compiled.gateway.evm.deployedBytecode.object.length / 2;
  assert.ok(runtimeBytes <= 24_576, `gateway runtime exceeds EIP-170: ${runtimeBytes}`);

  const eip1193 = ganache.provider({
    chain: { chainId: 31337, hardfork: "shanghai" },
    miner: { blockGasLimit: 30_000_000 },
    logging: { quiet: true },
    wallet: { deterministic: true, totalAccounts: 6 },
  });
  const provider = new ethers.providers.Web3Provider(eip1193);
  const wallets = Object.values(eip1193.getInitialAccounts()).map(
    ({ secretKey }) => new ethers.Wallet(secretKey, provider),
  );
  const verifierFactory = new ethers.ContractFactory(
    compiled.verifier.abi,
    `0x${compiled.verifier.evm.bytecode.object}`,
    wallets[0],
  );
  const verifier = await verifierFactory.deploy();
  await verifier.deployTransaction.wait();
  const gatewayFactory = new ethers.ContractFactory(
    compiled.gateway.abi,
    `0x${compiled.gateway.evm.bytecode.object}`,
    wallets[0],
  );
  const gateway = await gatewayFactory.deploy(verifier.address);
  await gateway.deployTransaction.wait();
  return { gateway, wallets, provider, eip1193, runtimeBytes };
}

async function createIssuedCredential(gateway, wallets, suffix, configureThreshold = true, deviceIndex = 1) {
  const modelHash = hash(`integrated/model/${suffix}`);
  const quantizationHash = hash(`integrated/quant/${suffix}`);
  const firmwareMeasurement = hash(`integrated/firmware/${suffix}`);
  const uniqueInputDigest = hash(`integrated/unique-input/${suffix}`);
  const receiptId = hash(`integrated/receipt/${suffix}`);
  const lineageId = hash(`integrated/lineage/${suffix}`);
  const cEnroll = BigInt(`123456789${suffix.length}`);

  let policyHash;
  if (configureThreshold) {
    ({ policyHash } = await registerSyntheticPolicy(gateway, {
      label: `integrated/policy/${suffix}`, modelHash, quantizationHash, epsilon: 271,
    }));
  } else {
    policyHash = hash(`integrated/legacy-policy/${suffix}`);
    await confirmed(gateway.registerPolicy(policyHash));
  }
  const deviceReceipt = await confirmed(
    gateway.registerDevice(
      wallets[deviceIndex].address,
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
  await confirmed(
    gateway.recordUniqueReceipt(
      receiptId,
      uniqueInputDigest,
      modelHash,
      quantizationHash,
    ),
  );
  const issueRequest = {
    receiptId,
    lineageId,
    cEnroll,
    policyHash,
    modelHash,
    quantizationHash,
    templateVersion: 1,
    holder: wallets[2].address,
    deviceVersionId,
    uniqueInputDigest,
    enrollmentContext: hash(`integrated/enrollment-context/${suffix}`),
  };
  const enrollmentDigest = await gateway.enrollmentLinkDigest(issueRequest);
  const enrollmentSignature = ethers.utils.joinSignature(
    wallets[deviceIndex]._signingKey().signDigest(enrollmentDigest),
  );
  const credentialId = await gateway.callStatic.issueFromUniqueReceipt(
    issueRequest,
    enrollmentSignature,
  );
  await confirmed(
    gateway.issueFromUniqueReceipt(issueRequest, enrollmentSignature),
  );
  return {
    policyHash,
    modelHash,
    quantizationHash,
    firmwareMeasurement,
    receiptId,
    lineageId,
    cEnroll,
    deviceVersionId,
    credentialId,
  };
}

async function issueAuthChallenge(gateway, holder, credential, provider, suffix) {
  const latest = await provider.getBlock("latest");
  const deadline = latest.timestamp + 600;
  const action = hash(`integrated/action/${suffix}`);
  const receipt = await confirmed(
    gateway
      .connect(holder)
      .issueAuthenticationChallenge(
        action,
        credential.credentialId,
        credential.deviceVersionId,
        deadline,
      ),
  );
  const nonce = eventArgument(receipt, "UBCAAuthChallengeIssued", "nonce");
  const ctxHash = eventArgument(receipt, "UBCAAuthChallengeIssued", "ctxHash");
  const registryEpochAtIssue = eventArgument(
    receipt,
    "UBCAAuthChallengeIssued",
    "registryEpochAtIssue",
  );
  return {
    context: {
      beneficiary: holder.address,
      action,
      credentialId: credential.credentialId,
      deviceVersionId: credential.deviceVersionId,
      registryEpochAtIssue,
      nonce,
      deadline,
    },
    ctxHash,
  };
}

async function signedCapture(
  gateway,
  deviceWallet,
  credential,
  challenge,
  counter,
) {
  const statement = {
    cProbe: BigInt(`987654321${counter}`),
    ctxHash: challenge.ctxHash,
    credentialId: credential.credentialId,
    deviceVersionId: credential.deviceVersionId,
    policyHash: credential.policyHash,
    modelHash: credential.modelHash,
    quantizationHash: credential.quantizationHash,
    firmwareMeasurement: credential.firmwareMeasurement,
    registryEpochAtCapture: await gateway.registryEpoch(),
    counter,
    notAfter: challenge.context.deadline,
  };
  const digest = await gateway.captureStatementDigest(statement);
  const signature = ethers.utils.joinSignature(
    deviceWallet._signingKey().signDigest(digest),
  );
  const policyField = await gateway.policyFieldDigest(credential.policyHash);
  const publicSignals = [
    credential.cEnroll,
    statement.cProbe,
    policyField,
    challenge.ctxHash,
    271,
  ];
  return { statement, signature, publicSignals };
}

test("integrated chain consumes receipt, validates capture, and atomically consumes freshness", async (t) => {
  const { gateway, wallets, provider, eip1193, runtimeBytes } =
    await deployFixture();
  t.after(() => eip1193.disconnect());
  assert.ok(runtimeBytes > 0);

  const credential = await createIssuedCredential(gateway, wallets, "happy");
  const uniqueReceipt = await gateway.uniqueReceipts(credential.receiptId);
  assert.equal(uniqueReceipt.consumedBy, credential.credentialId);

  const challenge = await issueAuthChallenge(
    gateway,
    wallets[2],
    credential,
    provider,
    "happy",
  );
  const capture = await signedCapture(
    gateway,
    wallets[1],
    credential,
    challenge,
    1,
  );

  const outsideDigest = await gateway.captureStatementDigest(capture.statement);
  const outsideSignature = ethers.utils.joinSignature(
    wallets[3]._signingKey().signDigest(outsideDigest),
  );
  await expectRevert(
    () =>
      gateway
        .connect(wallets[2])
        .callStatic.verifyAndConsumeAuthentication(
          pA,
          pB,
          pC,
          capture.publicSignals,
          challenge.context,
          capture.statement,
          outsideSignature,
        ),
    "capture statement signed outside the registered device",
  );
  assert.notEqual(
    await gateway.pendingAuthContexts(challenge.context.nonce),
    ethers.constants.HashZero,
  );

  const transplantedContext = {
    ...challenge.context,
    action: hash("integrated/action/transplanted"),
  };
  await expectRevert(
    () =>
      gateway
        .connect(wallets[2])
        .callStatic.verifyAndConsumeAuthentication(
          pA,
          pB,
          pC,
          capture.publicSignals,
          transplantedContext,
          capture.statement,
          capture.signature,
        ),
    "context transplant",
  );

  assert.equal(
    await gateway
      .connect(wallets[2])
      .callStatic.verifyAndConsumeAuthentication(
        pA,
        pB,
        pC,
        capture.publicSignals,
        challenge.context,
        capture.statement,
        capture.signature,
      ),
    true,
  );
  await confirmed(
    gateway
      .connect(wallets[2])
      .verifyAndConsumeAuthentication(
        pA,
        pB,
        pC,
        capture.publicSignals,
        challenge.context,
        capture.statement,
        capture.signature,
      ),
  );
  assert.equal(
    await gateway.pendingAuthContexts(challenge.context.nonce),
    ethers.constants.HashZero,
  );
  assert.equal(
    (await gateway.lastCaptureCounters(credential.deviceVersionId)).toNumber(),
    1,
  );
  await expectRevert(
    () =>
      gateway
        .connect(wallets[2])
        .callStatic.verifyAndConsumeAuthentication(
          pA,
          pB,
          pC,
          capture.publicSignals,
          challenge.context,
          capture.statement,
          capture.signature,
        ),
    "accepted challenge replay",
  );
});

test("device revocation ordered before submission rejects a prepared authentication", async (t) => {
  const { gateway, wallets, provider, eip1193 } = await deployFixture();
  t.after(() => eip1193.disconnect());
  const credential = await createIssuedCredential(gateway, wallets, "device-revoke");
  const challenge = await issueAuthChallenge(
    gateway,
    wallets[2],
    credential,
    provider,
    "device-revoke",
  );
  const capture = await signedCapture(
    gateway,
    wallets[1],
    credential,
    challenge,
    1,
  );

  await confirmed(gateway.revokeDevice(credential.deviceVersionId));
  await expectRevert(
    () =>
      gateway
        .connect(wallets[2])
        .callStatic.verifyAndConsumeAuthentication(
          pA,
          pB,
          pC,
          capture.publicSignals,
          challenge.context,
          capture.statement,
          capture.signature,
        ),
    "revoked-before-submit device",
  );
  assert.notEqual(
    await gateway.pendingAuthContexts(challenge.context.nonce),
    ethers.constants.HashZero,
  );
  await expectRevert(
    () =>
      gateway.registerDevice(
        wallets[1].address,
        credential.firmwareMeasurement,
        credential.modelHash,
        credential.quantizationHash,
        credential.policyHash,
      ),
    "terminal device key cannot be re-registered",
  );
});

test("device rotation invalidates old capture and admits a compatible new device", async (t) => {
  const { gateway, wallets, provider, eip1193 } = await deployFixture();
  t.after(() => eip1193.disconnect());
  const credential = await createIssuedCredential(gateway, wallets, "device-rotate");
  const oldChallenge = await issueAuthChallenge(
    gateway, wallets[2], credential, provider, "before-rotation",
  );
  const oldCapture = await signedCapture(
    gateway, wallets[1], credential, oldChallenge, 1,
  );

  await expectRevert(
    () => gateway.rotateDevice(
      credential.deviceVersionId,
      wallets[1].address,
      hash("device-rotate/reused-firmware"),
      credential.modelHash,
      credential.quantizationHash,
      credential.policyHash,
    ),
    "rotation cannot reuse a registered signing key",
  );
  assert.equal((await gateway.deviceVersions(credential.deviceVersionId)).status, 1);

  const newFirmwareMeasurement = hash("device-rotate/new-firmware");
  const rotationReceipt = await confirmed(gateway.rotateDevice(
    credential.deviceVersionId,
    wallets[3].address,
    newFirmwareMeasurement,
    credential.modelHash,
    credential.quantizationHash,
    credential.policyHash,
  ));
  const newDeviceVersionId = eventArgument(
    rotationReceipt, "DeviceRegistered", "deviceVersionId",
  );
  const oldDeviceState = await gateway.deviceVersions(credential.deviceVersionId);
  const newDeviceState = await gateway.deviceVersions(newDeviceVersionId);
  assert.equal(oldDeviceState.status, 3);
  assert.equal(newDeviceState.status, 1);
  assert.equal(
    oldDeviceState.revokedAtEpoch.toString(),
    newDeviceState.validFromEpoch.toString(),
  );
  assert.equal(
    await gateway.isAuthenticationStateActive(
      credential.credentialId, credential.deviceVersionId,
    ),
    false,
  );
  assert.equal(
    await gateway.isAuthenticationStateActive(
      credential.credentialId, newDeviceVersionId,
    ),
    true,
  );
  await expectRevert(
    () => gateway.connect(wallets[2]).callStatic.verifyAndConsumeAuthentication(
      pA, pB, pC, oldCapture.publicSignals, oldChallenge.context,
      oldCapture.statement, oldCapture.signature,
    ),
    "old prepared capture after rotation",
  );
  assert.notEqual(
    await gateway.pendingAuthContexts(oldChallenge.context.nonce),
    ethers.constants.HashZero,
  );
  assert.equal(
    (await gateway.lastCaptureCounters(credential.deviceVersionId)).toNumber(), 0,
  );
  await expectRevert(
    () => gateway.registerDevice(
      wallets[1].address,
      credential.firmwareMeasurement,
      credential.modelHash,
      credential.quantizationHash,
      credential.policyHash,
    ),
    "old signing key cannot be registered again",
  );

  const rotatedCredential = {
    ...credential,
    deviceVersionId: newDeviceVersionId,
    firmwareMeasurement: newFirmwareMeasurement,
  };
  const newChallenge = await issueAuthChallenge(
    gateway, wallets[2], rotatedCredential, provider, "after-rotation",
  );
  const newCapture = await signedCapture(
    gateway, wallets[3], rotatedCredential, newChallenge, 1,
  );
  const wrongKeySignature = ethers.utils.joinSignature(
    wallets[1]._signingKey().signDigest(
      await gateway.captureStatementDigest(newCapture.statement),
    ),
  );
  await expectRevert(
    () => gateway.connect(wallets[2]).callStatic.verifyAndConsumeAuthentication(
      pA, pB, pC, newCapture.publicSignals, newChallenge.context,
      newCapture.statement, wrongKeySignature,
    ),
    "old key cannot sign for the successor device",
  );
  assert.notEqual(
    await gateway.pendingAuthContexts(newChallenge.context.nonce),
    ethers.constants.HashZero,
  );
  await confirmed(gateway.connect(wallets[2]).verifyAndConsumeAuthentication(
    pA, pB, pC, newCapture.publicSignals, newChallenge.context,
    newCapture.statement, newCapture.signature,
  ));
  assert.equal(
    await gateway.pendingAuthContexts(newChallenge.context.nonce),
    ethers.constants.HashZero,
  );
  assert.equal((await gateway.lastCaptureCounters(newDeviceVersionId)).toNumber(), 1);
  assert.equal((await gateway.lastCaptureCounters(credential.deviceVersionId)).toNumber(), 0);
});

test("credential revocation ordered before submission rejects a prepared authentication", async (t) => {
  const { gateway, wallets, provider, eip1193 } = await deployFixture();
  t.after(() => eip1193.disconnect());
  const credential = await createIssuedCredential(
    gateway,
    wallets,
    "credential-revoke",
  );
  const challenge = await issueAuthChallenge(
    gateway,
    wallets[2],
    credential,
    provider,
    "credential-revoke",
  );
  const capture = await signedCapture(
    gateway,
    wallets[1],
    credential,
    challenge,
    1,
  );

  await confirmed(gateway.revokeCredential(credential.credentialId));
  await expectRevert(
    () =>
      gateway
        .connect(wallets[2])
        .callStatic.verifyAndConsumeAuthentication(
          pA,
          pB,
          pC,
          capture.publicSignals,
          challenge.context,
          capture.statement,
          capture.signature,
        ),
    "revoked-before-submit credential",
  );
  assert.notEqual(
    await gateway.pendingAuthContexts(challenge.context.nonce),
    ethers.constants.HashZero,
  );
});

test("match threshold is explicit, immutable, authorized, and checked before consuming freshness", async (t) => {
  const { gateway, wallets, provider, eip1193 } = await deployFixture();
  t.after(() => eip1193.disconnect());
  const legacyCredential = await createIssuedCredential(gateway, wallets, "threshold-legacy", false);
  await expectRevert(
    () => issueAuthChallenge(gateway, wallets[2], legacyCredential, provider, "opaque-policy"),
    "opaque policy cannot issue an authentication challenge",
  );
  await expectRevert(
    () => gateway.connect(wallets[2]).configureMatchThreshold(legacyCredential.policyHash, 271),
    "untrusted policy configuration",
  );
  await expectRevert(
    () => gateway.configureMatchThreshold(legacyCredential.policyHash, 1n << 48n),
    "threshold outside circuit range",
  );
  await confirmed(gateway.configureMatchThreshold(legacyCredential.policyHash, 271));
  await expectRevert(
    () => issueAuthChallenge(gateway, wallets[2], legacyCredential, provider, "configured-opaque"),
    "configuring epsilon does not make an opaque policy canonical",
  );
  const credential = await createIssuedCredential(gateway, wallets, "threshold-canonical", true, 3);
  await expectRevert(
    () => gateway.configureMatchThreshold(credential.policyHash, 1000000),
    "canonical policy threshold replacement",
  );
  const challenge = await issueAuthChallenge(gateway, wallets[2], credential, provider, "pinned");
  const capture = await signedCapture(gateway, wallets[3], credential, challenge, 1);
  const raisedThresholdSignals = [...capture.publicSignals];
  raisedThresholdSignals[4] = 1000000;
  await expectRevert(
    () => gateway.connect(wallets[2]).callStatic.verifyAndConsumeAuthentication(
      pA, pB, pC, raisedThresholdSignals, challenge.context, capture.statement, capture.signature,
    ),
    "valid verifier result with unauthorized threshold",
  );
  assert.notEqual(await gateway.pendingAuthContexts(challenge.context.nonce), ethers.constants.HashZero);
  assert.equal((await gateway.lastCaptureCounters(credential.deviceVersionId)).toNumber(), 0);
  assert.equal(await gateway.connect(wallets[2]).callStatic.verifyAndConsumeAuthentication(
    pA, pB, pC, capture.publicSignals, challenge.context, capture.statement, capture.signature,
  ), true);
});

test("canonical policy commits application and threshold and replacement revokes old credentials", async (t) => {
  const { gateway, wallets, provider, eip1193 } = await deployFixture();
  t.after(() => eip1193.disconnect());
  const credential = await createIssuedCredential(gateway, wallets, "policy-migrate");
  const stored = await gateway.canonicalPolicySpecs(credential.policyHash);
  assert.equal(stored.epsilon.toNumber(), 271);
  assert.equal(await gateway.canonicalPolicyRegistered(credential.policyHash), true);

  const base = syntheticPolicySpec({
    label: "integrated/policy/policy-migrate",
    modelHash: credential.modelHash,
    quantizationHash: credential.quantizationHash,
    epsilon: 271,
  });
  const anotherApplication = { ...base, applicationId: hash("another/application") };
  const anotherThreshold = { ...base, epsilon: 272 };
  assert.notEqual(await gateway.canonicalPolicyHash(base), await gateway.canonicalPolicyHash(anotherApplication));
  assert.notEqual(await gateway.canonicalPolicyHash(base), await gateway.canonicalPolicyHash(anotherThreshold));
  await expectRevert(() => gateway.registerCanonicalPolicy(base), "duplicate canonical policy");
  await expectRevert(() => gateway.connect(wallets[2]).registerCanonicalPolicy(anotherApplication), "non-owner policy");
  await expectRevert(() => gateway.registerCanonicalPolicy({ ...base, coordinateBits: 8 }), "wrong circuit coordinate width");

  const newHash = await gateway.canonicalPolicyHash(anotherApplication);
  await confirmed(gateway.replaceCanonicalPolicy(credential.policyHash, anotherApplication));
  assert.equal(await gateway.canonicalPolicyRegistered(newHash), true);
  assert.equal((await gateway.policyMatchThresholds(newHash)).toNumber(), 271);
  await expectRevert(
    () => issueAuthChallenge(gateway, wallets[2], credential, provider, "replaced-policy"),
    "credential under revoked old policy",
  );
});
