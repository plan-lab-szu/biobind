import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { ethers } from "ethers";
import ganache from "ganache";
import solc from "solc";

const prototypeRoot = resolve(import.meta.dirname, "..");

function hash(label) {
  return ethers.utils.keccak256(ethers.utils.toUtf8Bytes(label));
}

async function compileLifecycle() {
  const source = await readFile(
    resolve(prototypeRoot, "contracts", "UBCALifecycle.sol"),
    "utf8",
  );
  const input = {
    language: "Solidity",
    sources: { "UBCALifecycle.sol": { content: source } },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: "shanghai",
      outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } },
    },
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors ?? []).filter(({ severity }) => severity === "error");
  if (errors.length > 0) {
    throw new Error(errors.map(({ formattedMessage }) => formattedMessage).join("\n"));
  }
  return output.contracts["UBCALifecycle.sol"].UBCALifecycle;
}

async function deployFixture() {
  const compiled = await compileLifecycle();
  const eip1193 = ganache.provider({
    chain: { chainId: 31337, hardfork: "shanghai" },
    logging: { quiet: true },
    wallet: { deterministic: true, totalAccounts: 6 },
  });
  const provider = new ethers.providers.Web3Provider(eip1193);
  const accounts = Object.values(eip1193.getInitialAccounts());
  const wallets = accounts.map(({ secretKey }) => new ethers.Wallet(secretKey, provider));
  const factory = new ethers.ContractFactory(
    compiled.abi,
    `0x${compiled.evm.bytecode.object}`,
    wallets[0],
  );
  const lifecycle = await factory.deploy();
  await lifecycle.deployTransaction.wait();
  return { lifecycle, wallets, eip1193 };
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
  assert.fail(`expected revert: ${label}`);
}

function eventArgument(receipt, eventName, argumentName) {
  const event = receipt.events.find(({ event: name }) => name === eventName);
  assert.ok(event, `missing ${eventName} event`);
  return event.args[argumentName];
}

async function registerDevice(lifecycle, request) {
  const receipt = await confirmed(
    lifecycle.registerDevice(
      request.signingKey,
      request.firmwareMeasurement,
      request.modelHash,
      request.quantizationHash,
      request.policyHash,
    ),
  );
  return eventArgument(receipt, "DeviceRegistered", "deviceVersionId");
}

async function signedIssue(lifecycle, deviceWallet, request) {
  const digest = await lifecycle.enrollmentLinkDigest(request);
  const signature = ethers.utils.joinSignature(
    deviceWallet._signingKey().signDigest(digest),
  );
  const credentialId = await lifecycle.callStatic.issueFromUniqueReceipt(
    request,
    signature,
  );
  await confirmed(lifecycle.issueFromUniqueReceipt(request, signature));
  return { credentialId, signature };
}

test("unique receipt issuance binds the enrollment commitment", async (t) => {
  const { lifecycle, wallets, eip1193 } = await deployFixture();
  t.after(() => eip1193.disconnect());

  const policyHash = hash("policy/1");
  const modelHash = hash("model/1");
  const quantizationHash = hash("quant/1");
  const uniqueInputDigest = hash("biozkfhe/input/1");
  const receiptId = hash("biozkfhe/receipt/1");
  const lineageId = hash("lineage/1");

  await confirmed(lifecycle.registerPolicy(policyHash));
  const deviceVersionId = await registerDevice(lifecycle, {
    signingKey: wallets[1].address,
    firmwareMeasurement: hash("firmware/1"),
    modelHash,
    quantizationHash,
    policyHash,
  });
  await confirmed(
    lifecycle.recordUniqueReceipt(
      receiptId,
      uniqueInputDigest,
      modelHash,
      quantizationHash,
    ),
  );

  const request = {
    receiptId,
    lineageId,
    cEnroll: 123456789n,
    policyHash,
    modelHash,
    quantizationHash,
    templateVersion: 1,
    holder: wallets[2].address,
    deviceVersionId,
    uniqueInputDigest,
    enrollmentContext: hash("enrollment/context/1"),
  };
  const { credentialId, signature } = await signedIssue(
    lifecycle,
    wallets[1],
    request,
  );

  const receipt = await lifecycle.uniqueReceipts(receiptId);
  const credential = await lifecycle.credentials(credentialId);
  assert.equal(receipt.consumedBy, credentialId);
  assert.equal(credential.status, 1);
  assert.equal(await lifecycle.activeCredentialByLineage(lineageId), credentialId);
  assert.equal(
    await lifecycle.isAuthenticationStateActive(credentialId, deviceVersionId),
    true,
  );

  await expectRevert(
    () => lifecycle.issueFromUniqueReceipt(request, signature),
    "one uniqueness receipt cannot issue twice",
  );

  const secondReceiptId = hash("biozkfhe/receipt/2");
  await confirmed(
    lifecycle.recordUniqueReceipt(
      secondReceiptId,
      uniqueInputDigest,
      modelHash,
      quantizationHash,
    ),
  );
  const honestSecondRequest = {
    ...request,
    receiptId: secondReceiptId,
    lineageId: hash("lineage/2"),
  };
  const honestDigest = await lifecycle.enrollmentLinkDigest(honestSecondRequest);
  const honestSignature = ethers.utils.joinSignature(
    wallets[1]._signingKey().signDigest(honestDigest),
  );
  const substitutedRequest = {
    ...honestSecondRequest,
    cEnroll: 987654321n,
  };
  await expectRevert(
    () => lifecycle.issueFromUniqueReceipt(substitutedRequest, honestSignature),
    "changing C_enroll invalidates co-attestation",
  );
});

test("device and policy revocation are terminal and checked at submission", async (t) => {
  const { lifecycle, wallets, eip1193 } = await deployFixture();
  t.after(() => eip1193.disconnect());

  const policyHash = hash("policy/terminal");
  const modelHash = hash("model/terminal");
  const quantizationHash = hash("quant/terminal");
  const uniqueInputDigest = hash("input/terminal");
  const receiptId = hash("receipt/terminal");

  await confirmed(lifecycle.registerPolicy(policyHash));
  const deviceRequest = {
    signingKey: wallets[1].address,
    firmwareMeasurement: hash("firmware/terminal"),
    modelHash,
    quantizationHash,
    policyHash,
  };
  const deviceVersionId = await registerDevice(lifecycle, deviceRequest);
  await confirmed(
    lifecycle.recordUniqueReceipt(
      receiptId,
      uniqueInputDigest,
      modelHash,
      quantizationHash,
    ),
  );
  const request = {
    receiptId,
    lineageId: hash("lineage/terminal"),
    cEnroll: 111n,
    policyHash,
    modelHash,
    quantizationHash,
    templateVersion: 1,
    holder: wallets[2].address,
    deviceVersionId,
    uniqueInputDigest,
    enrollmentContext: hash("context/terminal"),
  };
  const { credentialId } = await signedIssue(lifecycle, wallets[1], request);

  await lifecycle.requireAuthenticationState(credentialId, deviceVersionId);
  await confirmed(lifecycle.revokeDevice(deviceVersionId));
  await expectRevert(
    () => lifecycle.requireAuthenticationState(credentialId, deviceVersionId),
    "capture made before device revocation cannot submit afterwards",
  );
  await expectRevert(
    () => registerDevice(lifecycle, deviceRequest),
    "a revoked signing key cannot be registered again",
  );
  await expectRevert(
    () => lifecycle.revokeDevice(deviceVersionId),
    "terminal device revocation cannot repeat",
  );

  await confirmed(lifecycle.revokePolicy(policyHash));
  const policy = await lifecycle.policies(policyHash);
  assert.equal(policy.status, 3);
  await expectRevert(
    () => lifecycle.registerPolicy(policyHash),
    "a revoked policy hash cannot be reactivated",
  );
});

test("successor transitions preserve one active credential per lineage", async (t) => {
  const { lifecycle, wallets, eip1193 } = await deployFixture();
  t.after(() => eip1193.disconnect());

  const policy1 = hash("policy/successor/1");
  const policy2 = hash("policy/successor/2");
  const modelHash = hash("model/successor");
  const quantizationHash = hash("quant/successor");
  const lineageId = hash("lineage/successor");
  const receipt1 = hash("receipt/successor/1");
  const input1 = hash("input/successor/1");

  await confirmed(lifecycle.registerPolicy(policy1));
  const device1 = await registerDevice(lifecycle, {
    signingKey: wallets[1].address,
    firmwareMeasurement: hash("firmware/successor/1"),
    modelHash,
    quantizationHash,
    policyHash: policy1,
  });
  await confirmed(
    lifecycle.recordUniqueReceipt(receipt1, input1, modelHash, quantizationHash),
  );
  const firstRequest = {
    receiptId: receipt1,
    lineageId,
    cEnroll: 222n,
    policyHash: policy1,
    modelHash,
    quantizationHash,
    templateVersion: 1,
    holder: wallets[2].address,
    deviceVersionId: device1,
    uniqueInputDigest: input1,
    enrollmentContext: hash("context/successor/1"),
  };
  const { credentialId: credential1 } = await signedIssue(
    lifecycle,
    wallets[1],
    firstRequest,
  );

  await confirmed(lifecycle.replacePolicy(policy1, policy2));
  const rotateReceipt = await confirmed(
    lifecycle.rotateDevice(
      device1,
      wallets[3].address,
      hash("firmware/successor/2"),
      modelHash,
      quantizationHash,
      policy2,
    ),
  );
  const device2 = eventArgument(
    rotateReceipt,
    "DeviceRegistered",
    "deviceVersionId",
  );
  const oldPolicy = await lifecycle.policies(policy1);
  const newPolicy = await lifecycle.policies(policy2);
  const oldDevice = await lifecycle.deviceVersions(device1);
  const newDevice = await lifecycle.deviceVersions(device2);
  assert.equal(oldPolicy.status, 3);
  assert.equal(newPolicy.status, 1);
  assert.equal(
    oldPolicy.revokedAtEpoch.toString(),
    newPolicy.validFromEpoch.toString(),
  );
  assert.equal(oldDevice.status, 3);
  assert.equal(newDevice.status, 1);
  assert.equal(
    oldDevice.revokedAtEpoch.toString(),
    newDevice.validFromEpoch.toString(),
  );

  await expectRevert(
    () => lifecycle.replaceMetadata(credential1, policy2),
    "policy rebinding cannot reuse a commitment that includes the old policy digest",
  );
  assert.equal((await lifecycle.credentials(credential1)).status, 1);
  assert.equal(await lifecycle.activeCredentialByLineage(lineageId), credential1);
  assert.equal(await lifecycle.isAuthenticationStateActive(credential1, device1), false);
  assert.equal(await lifecycle.isAuthenticationStateActive(credential1, device2), false);

  const receipt2 = hash("receipt/successor/2");
  const input2 = hash("input/successor/2");
  await confirmed(
    lifecycle.recordUniqueReceipt(receipt2, input2, modelHash, quantizationHash),
  );
  const templateRequest = {
    receiptId: receipt2,
    lineageId,
    cEnroll: 333n,
    policyHash: policy2,
    modelHash,
    quantizationHash,
    templateVersion: 2,
    holder: wallets[2].address,
    deviceVersionId: device2,
    uniqueInputDigest: input2,
    enrollmentContext: hash("context/successor/2"),
  };
  const digest = await lifecycle.enrollmentLinkDigest(templateRequest);
  const signature = ethers.utils.joinSignature(
    wallets[3]._signingKey().signDigest(digest),
  );
  const credential2 = await lifecycle.callStatic.replaceTemplate(
    credential1,
    templateRequest,
    signature,
  );
  await confirmed(
    lifecycle.replaceTemplate(credential1, templateRequest, signature),
  );
  assert.equal((await lifecycle.credentials(credential1)).status, 2);
  assert.equal((await lifecycle.credentials(credential1)).successor, credential2);
  assert.equal((await lifecycle.credentials(credential2)).status, 1);
  assert.equal(await lifecycle.activeCredentialByLineage(lineageId), credential2);
  assert.equal(await lifecycle.isAuthenticationStateActive(credential1, device2), false);
  assert.equal(await lifecycle.isAuthenticationStateActive(credential2, device2), true);

  await expectRevert(
    () => lifecycle.replaceMetadata(credential2, policy1),
    "an old revoked policy cannot be restored as a downgrade",
  );

  await confirmed(lifecycle.revokeCredential(credential2));
  assert.equal((await lifecycle.credentials(credential2)).status, 3);
  assert.equal(await lifecycle.activeCredentialByLineage(lineageId), ethers.constants.HashZero);
  await expectRevert(
    () => lifecycle.replaceMetadata(credential2, policy1),
    "revoked credential cannot be reactivated through update",
  );

  const receipt3 = hash("receipt/successor/3");
  const input3 = hash("input/successor/3");
  await confirmed(
    lifecycle.recordUniqueReceipt(receipt3, input3, modelHash, quantizationHash),
  );
  const reissueRequest = {
    ...templateRequest,
    receiptId: receipt3,
    cEnroll: 444n,
    templateVersion: 3,
    uniqueInputDigest: input3,
    enrollmentContext: hash("context/successor/3"),
  };
  const reissueDigest = await lifecycle.enrollmentLinkDigest(reissueRequest);
  const reissueSignature = ethers.utils.joinSignature(
    wallets[3]._signingKey().signDigest(reissueDigest),
  );
  await expectRevert(
    () => lifecycle.issueFromUniqueReceipt(reissueRequest, reissueSignature),
    "a revoked lineage cannot restart at credential version one",
  );
});
