import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { ethers } from "ethers";
import ganache from "ganache";
import solc from "solc";

const prototypeRoot = resolve(import.meta.dirname, "..");
let compilation;

function hash(label) {
  return ethers.utils.keccak256(ethers.utils.toUtf8Bytes(label));
}

function seededRandom(seed) {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
}

async function compileContracts() {
  compilation ??= (async () => {
    const [lifecycle, gateway, adapterInterface, localAdapter] = await Promise.all([
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
      readFile(
        resolve(
          prototypeRoot,
          "contracts",
          "test",
          "LocalFinalizedUniquenessAdapter.sol",
        ),
        "utf8",
      ),
    ]);
    const verifier = `
      // SPDX-License-Identifier: MIT
      pragma solidity ^0.8.24;
      contract LocalAcceptingVerifierForReceiptTest {
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
        "test/LocalFinalizedUniquenessAdapter.sol": { content: localAdapter },
        "LocalAcceptingVerifierForReceiptTest.sol": { content: verifier },
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
      throw new Error(
        errors.map(({ formattedMessage }) => formattedMessage).join("\n"),
      );
    }
    return {
      gateway: output.contracts["UBCAAuthGateway.sol"].UBCAAuthGateway,
      adapter:
        output.contracts["test/LocalFinalizedUniquenessAdapter.sol"]
          .LocalFinalizedUniquenessAdapter,
      verifier:
        output.contracts["LocalAcceptingVerifierForReceiptTest.sol"]
          .LocalAcceptingVerifierForReceiptTest,
    };
  })();
  return compilation;
}

function factory(compiled, signer) {
  return new ethers.ContractFactory(
    compiled.abi,
    `0x${compiled.evm.bytecode.object}`,
    signer,
  );
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
  assert.fail(`expected atomic local rejection: ${label}`);
}

function eventArgument(receipt, eventName, argumentName) {
  const event = receipt.events.find(({ event: name }) => name === eventName);
  assert.ok(event, `missing ${eventName} event`);
  return event.args[argumentName];
}

async function deployFixture() {
  const compiled = await compileContracts();
  const runtimeBytes = compiled.gateway.evm.deployedBytecode.object.length / 2;
  assert.ok(runtimeBytes <= 24_576, `gateway exceeds EIP-170: ${runtimeBytes}`);
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
  const verifier = await factory(compiled.verifier, wallets[0]).deploy();
  await verifier.deployTransaction.wait();
  const adapter = await factory(compiled.adapter, wallets[0]).deploy();
  await adapter.deployTransaction.wait();
  const gateway = await factory(compiled.gateway, wallets[0]).deploy(
    verifier.address,
  );
  await gateway.deployTransaction.wait();
  await confirmed(gateway.configureUniquenessAdapter(adapter.address));
  await confirmed(adapter.configureAuthorizedConsumer(gateway.address));
  await confirmed(gateway.disableLegacyReceiptPath());
  return { gateway, adapter, wallets, provider, eip1193, runtimeBytes };
}

async function registerIssuanceState(gateway, wallets, suffix) {
  const policyHash = hash(`atomic/policy/${suffix}`);
  const modelHash = hash(`atomic/model/${suffix}`);
  const quantizationHash = hash(`atomic/quant/${suffix}`);
  const firmwareMeasurement = hash(`atomic/firmware/${suffix}`);
  await confirmed(gateway.registerPolicy(policyHash));
  const deviceReceipt = await confirmed(
    gateway.registerDevice(
      wallets[1].address,
      firmwareMeasurement,
      modelHash,
      quantizationHash,
      policyHash,
    ),
  );
  return {
    policyHash,
    modelHash,
    quantizationHash,
    deviceVersionId: eventArgument(
      deviceReceipt,
      "DeviceRegistered",
      "deviceVersionId",
    ),
  };
}

async function createFinalizedReceipt(gateway, adapter, state, suffix) {
  const sourceChainId = 91_337;
  const sourceContract = walletsAddressForLabel(`source/${suffix}`);
  const sourceSessionId = hash(`atomic/source-session/${suffix}`);
  const finalizationDigest = hash(`atomic/finalization/${suffix}`);
  const partial = {
    receiptId: ethers.constants.HashZero,
    sourceChainId,
    sourceContract,
    sourceSessionId,
    sourceContextHash: hash(`atomic/source-context/${suffix}`),
    gallerySnapshotHash: hash(`atomic/gallery/${suffix}`),
    queryCiphertextDigest: hash(`atomic/C-identify/${suffix}`),
    enrollmentCiphertextDigest: hash(`atomic/C-enroll/${suffix}`),
    verifiedOutputCollectionDigest: hash(`atomic/outputs/${suffix}`),
    finalizationDigest,
    uniqueInputDigest: ethers.constants.HashZero,
    modelHash: state.modelHash,
    quantizationHash: state.quantizationHash,
    finalizedAtBlock: 1234,
  };
  const receiptId = await gateway.finalizedReceiptId(
    sourceChainId,
    sourceContract,
    sourceSessionId,
    finalizationDigest,
  );
  const uniqueInputDigest = await gateway.finalizedUniqueInputDigest(partial);
  const receipt = { ...partial, receiptId, uniqueInputDigest };
  await confirmed(adapter.recordLocalFinalizedUniqueEnrollment(receipt));
  return receipt;
}

function walletsAddressForLabel(label) {
  return ethers.utils.getAddress(`0x${hash(label).slice(-40)}`);
}

async function buildIssueRequest(gateway, deviceWallet, state, receipt, suffix) {
  const request = {
    receiptId: receipt.receiptId,
    lineageId: hash(`atomic/lineage/${suffix}`),
    cEnroll: BigInt(`123456789${suffix.length}`),
    policyHash: state.policyHash,
    modelHash: state.modelHash,
    quantizationHash: state.quantizationHash,
    templateVersion: 1,
    holder: walletsAddressForLabel(`holder/${suffix}`),
    deviceVersionId: state.deviceVersionId,
    uniqueInputDigest: receipt.uniqueInputDigest,
    enrollmentContext: hash(`atomic/enrollment-context/${suffix}`),
  };
  const digest = await gateway.enrollmentLinkDigest(request);
  const signature = ethers.utils.joinSignature(
    deviceWallet._signingKey().signDigest(digest),
  );
  return { request, signature };
}

test("finalized source session is consumed in the same transaction that issues the credential", async (t) => {
  const { gateway, adapter, wallets, eip1193, runtimeBytes } =
    await deployFixture();
  t.after(() => eip1193.disconnect());
  assert.ok(runtimeBytes > 0);
  assert.equal(await gateway.legacyReceiptPathDisabled(), true);
  await expectRevert(
    () =>
      gateway.recordUniqueReceipt(
        hash("legacy/receipt"),
        hash("legacy/input"),
        hash("legacy/model"),
        hash("legacy/quant"),
      ),
    "adapter-only profile blocks owner receipt injection",
  );

  const state = await registerIssuanceState(gateway, wallets, "success");
  const receipt = await createFinalizedReceipt(
    gateway,
    adapter,
    state,
    "success",
  );
  const { request, signature } = await buildIssueRequest(
    gateway,
    wallets[1],
    state,
    receipt,
    "success",
  );
  const credentialId = await gateway.callStatic.issueFromFinalizedBioZKFHESession(
    receipt.sourceSessionId,
    "0x",
    request,
    signature,
  );
  await confirmed(
    gateway.issueFromFinalizedBioZKFHESession(
      receipt.sourceSessionId,
      "0x",
      request,
      signature,
    ),
  );

  const expectedConsumerBinding = await gateway.receiptConsumerBinding(
    request.lineageId,
    request.holder,
  );
  assert.equal(
    await adapter.consumedBy(receipt.sourceSessionId),
    expectedConsumerBinding,
  );
  assert.equal((await gateway.uniqueReceipts(receipt.receiptId)).consumedBy, credentialId);
  assert.equal((await gateway.credentials(credentialId)).status, 1);
  await expectRevert(
    () =>
      gateway.issueFromFinalizedBioZKFHESession(
        receipt.sourceSessionId,
        "0x",
        request,
        signature,
      ),
    "one source session cannot issue twice",
  );
});

test("invalid enrollment-link signature rolls back adapter consumption and local receipt creation", async (t) => {
  const { gateway, adapter, wallets, eip1193 } = await deployFixture();
  t.after(() => eip1193.disconnect());
  const state = await registerIssuanceState(gateway, wallets, "rollback-signature");
  const receipt = await createFinalizedReceipt(
    gateway,
    adapter,
    state,
    "rollback-signature",
  );
  const valid = await buildIssueRequest(
    gateway,
    wallets[1],
    state,
    receipt,
    "rollback-signature",
  );
  const digest = await gateway.enrollmentLinkDigest(valid.request);
  const invalidSignature = ethers.utils.joinSignature(
    wallets[3]._signingKey().signDigest(digest),
  );

  await expectRevert(
    () =>
      gateway.issueFromFinalizedBioZKFHESession(
        receipt.sourceSessionId,
        "0x",
        valid.request,
        invalidSignature,
      ),
    "signature outside registered composite AFE",
  );
  assert.equal(
    await adapter.consumedBy(receipt.sourceSessionId),
    ethers.constants.HashZero,
  );
  assert.equal((await gateway.uniqueReceipts(receipt.receiptId)).exists, false);

  await confirmed(
    gateway.issueFromFinalizedBioZKFHESession(
      receipt.sourceSessionId,
      "0x",
      valid.request,
      valid.signature,
    ),
  );
  assert.notEqual(
    await adapter.consumedBy(receipt.sourceSessionId),
    ethers.constants.HashZero,
  );
});

test("receipt/request mismatch and terminal adapter revocation cannot leave partial issuance state", async (t) => {
  const { gateway, adapter, wallets, eip1193 } = await deployFixture();
  t.after(() => eip1193.disconnect());
  const state = await registerIssuanceState(gateway, wallets, "mismatch");
  const receipt = await createFinalizedReceipt(
    gateway,
    adapter,
    state,
    "mismatch",
  );
  const valid = await buildIssueRequest(
    gateway,
    wallets[1],
    state,
    receipt,
    "mismatch",
  );
  const mismatchedRequest = {
    ...valid.request,
    uniqueInputDigest: hash("atomic/incorrect-unique-input"),
  };
  const mismatchedDigest = await gateway.enrollmentLinkDigest(mismatchedRequest);
  const mismatchedSignature = ethers.utils.joinSignature(
    wallets[1]._signingKey().signDigest(mismatchedDigest),
  );
  await expectRevert(
    () =>
      gateway.issueFromFinalizedBioZKFHESession(
        receipt.sourceSessionId,
        "0x",
        mismatchedRequest,
        mismatchedSignature,
      ),
    "canonical receipt/request digest mismatch",
  );
  assert.equal(
    await adapter.consumedBy(receipt.sourceSessionId),
    ethers.constants.HashZero,
  );
  assert.equal((await gateway.uniqueReceipts(receipt.receiptId)).exists, false);

  await confirmed(gateway.revokeUniquenessAdapter());
  await expectRevert(
    () =>
      gateway.issueFromFinalizedBioZKFHESession(
        receipt.sourceSessionId,
        "0x",
        valid.request,
        valid.signature,
      ),
    "revoked adapter",
  );
  assert.equal(
    await adapter.consumedBy(receipt.sourceSessionId),
    ethers.constants.HashZero,
  );
  await expectRevert(
    () => gateway.configureUniquenessAdapter(adapter.address),
    "terminal adapter authorization cannot reactivate",
  );
});

test("template successor atomically consumes a new source receipt and preserves the old credential on failure", async (t) => {
  const { gateway, adapter, wallets, eip1193 } = await deployFixture();
  t.after(() => eip1193.disconnect());
  const state = await registerIssuanceState(gateway, wallets, "template-update");
  const initialReceipt = await createFinalizedReceipt(
    gateway,
    adapter,
    state,
    "template-update-initial",
  );
  const initial = await buildIssueRequest(
    gateway,
    wallets[1],
    state,
    initialReceipt,
    "template-update",
  );
  const oldCredentialId =
    await gateway.callStatic.issueFromFinalizedBioZKFHESession(
      initialReceipt.sourceSessionId,
      "0x",
      initial.request,
      initial.signature,
    );
  await confirmed(
    gateway.issueFromFinalizedBioZKFHESession(
      initialReceipt.sourceSessionId,
      "0x",
      initial.request,
      initial.signature,
    ),
  );

  const successorReceipt = await createFinalizedReceipt(
    gateway,
    adapter,
    state,
    "template-update-successor",
  );
  const successorRequest = {
    ...initial.request,
    receiptId: successorReceipt.receiptId,
    cEnroll: initial.request.cEnroll + 1n,
    templateVersion: 2,
    uniqueInputDigest: successorReceipt.uniqueInputDigest,
    enrollmentContext: hash("atomic/enrollment-context/template-update-successor"),
  };
  const successorDigest = await gateway.enrollmentLinkDigest(successorRequest);
  const validSuccessorSignature = ethers.utils.joinSignature(
    wallets[1]._signingKey().signDigest(successorDigest),
  );
  const invalidSuccessorSignature = ethers.utils.joinSignature(
    wallets[3]._signingKey().signDigest(successorDigest),
  );

  await expectRevert(
    () =>
      gateway.replaceTemplateFromFinalizedBioZKFHESession(
        oldCredentialId,
        successorReceipt.sourceSessionId,
        "0x",
        successorRequest,
        invalidSuccessorSignature,
      ),
    "failed successor issuance rolls back source consumption",
  );
  assert.equal(
    await adapter.consumedBy(successorReceipt.sourceSessionId),
    ethers.constants.HashZero,
  );
  assert.equal(
    (await gateway.uniqueReceipts(successorReceipt.receiptId)).exists,
    false,
  );
  assert.equal((await gateway.credentials(oldCredentialId)).status, 1);
  assert.equal(
    await gateway.activeCredentialByLineage(initial.request.lineageId),
    oldCredentialId,
  );

  const newCredentialId =
    await gateway.callStatic.replaceTemplateFromFinalizedBioZKFHESession(
      oldCredentialId,
      successorReceipt.sourceSessionId,
      "0x",
      successorRequest,
      validSuccessorSignature,
    );
  await confirmed(
    gateway.replaceTemplateFromFinalizedBioZKFHESession(
      oldCredentialId,
      successorReceipt.sourceSessionId,
      "0x",
      successorRequest,
      validSuccessorSignature,
    ),
  );
  assert.equal((await gateway.credentials(oldCredentialId)).status, 2);
  assert.equal((await gateway.credentials(oldCredentialId)).successor, newCredentialId);
  assert.equal((await gateway.credentials(newCredentialId)).status, 1);
  assert.equal(
    await gateway.activeCredentialByLineage(initial.request.lineageId),
    newCredentialId,
  );
  assert.notEqual(
    await adapter.consumedBy(successorReceipt.sourceSessionId),
    ethers.constants.HashZero,
  );
});

test("model-based successor interleavings preserve one active credential and never half-consume a receipt", async (t) => {
  const { gateway, adapter, wallets, eip1193 } = await deployFixture();
  t.after(() => eip1193.disconnect());
  const state = await registerIssuanceState(gateway, wallets, "state-machine");
  const initialReceipt = await createFinalizedReceipt(
    gateway,
    adapter,
    state,
    "state-machine-v1",
  );
  const initial = await buildIssueRequest(
    gateway,
    wallets[1],
    state,
    initialReceipt,
    "state-machine",
  );
  let currentRequest = initial.request;
  let currentCredentialId =
    await gateway.callStatic.issueFromFinalizedBioZKFHESession(
      initialReceipt.sourceSessionId,
      "0x",
      currentRequest,
      initial.signature,
    );
  await confirmed(
    gateway.issueFromFinalizedBioZKFHESession(
      initialReceipt.sourceSessionId,
      "0x",
      currentRequest,
      initial.signature,
    ),
  );
  const issuedCredentialIds = [currentCredentialId];

  for (let version = 2; version <= 5; version += 1) {
    const receipt = await createFinalizedReceipt(
      gateway,
      adapter,
      state,
      `state-machine-v${version}`,
    );
    const validRequest = {
      ...currentRequest,
      receiptId: receipt.receiptId,
      cEnroll: currentRequest.cEnroll + 1n,
      templateVersion: version,
      uniqueInputDigest: receipt.uniqueInputDigest,
      enrollmentContext: hash(`atomic/enrollment-context/state-machine-v${version}`),
    };
    const validDigest = await gateway.enrollmentLinkDigest(validRequest);
    const validSignature = ethers.utils.joinSignature(
      wallets[1]._signingKey().signDigest(validDigest),
    );

    let invalidRequest = validRequest;
    let invalidSignature = validSignature;
    if (version === 2) {
      invalidSignature = ethers.utils.joinSignature(
        wallets[3]._signingKey().signDigest(validDigest),
      );
    } else if (version === 3) {
      invalidRequest = { ...validRequest, templateVersion: version + 1 };
    } else if (version === 4) {
      invalidRequest = {
        ...validRequest,
        uniqueInputDigest: hash("atomic/state-machine/wrong-input"),
      };
      const invalidDigest = await gateway.enrollmentLinkDigest(invalidRequest);
      invalidSignature = ethers.utils.joinSignature(
        wallets[1]._signingKey().signDigest(invalidDigest),
      );
    } else {
      invalidRequest = {
        ...validRequest,
        lineageId: hash("atomic/state-machine/wrong-lineage"),
      };
    }

    await expectRevert(
      () =>
        gateway.replaceTemplateFromFinalizedBioZKFHESession(
          currentCredentialId,
          receipt.sourceSessionId,
          "0x",
          invalidRequest,
          invalidSignature,
        ),
      `invalid interleaving before template version ${version}`,
    );
    assert.equal(
      await adapter.consumedBy(receipt.sourceSessionId),
      ethers.constants.HashZero,
    );
    assert.equal((await gateway.uniqueReceipts(receipt.receiptId)).exists, false);
    assert.equal((await gateway.credentials(currentCredentialId)).status, 1);
    assert.equal(
      await gateway.activeCredentialByLineage(currentRequest.lineageId),
      currentCredentialId,
    );

    const newCredentialId =
      await gateway.callStatic.replaceTemplateFromFinalizedBioZKFHESession(
        currentCredentialId,
        receipt.sourceSessionId,
        "0x",
        validRequest,
        validSignature,
      );
    await confirmed(
      gateway.replaceTemplateFromFinalizedBioZKFHESession(
        currentCredentialId,
        receipt.sourceSessionId,
        "0x",
        validRequest,
        validSignature,
      ),
    );
    issuedCredentialIds.push(newCredentialId);
    currentCredentialId = newCredentialId;
    currentRequest = validRequest;

    for (let index = 0; index < issuedCredentialIds.length; index += 1) {
      const expectedStatus = index === issuedCredentialIds.length - 1 ? 1 : 2;
      assert.equal(
        (await gateway.credentials(issuedCredentialIds[index])).status,
        expectedStatus,
      );
    }
    assert.equal(
      await gateway.activeCredentialByLineage(currentRequest.lineageId),
      currentCredentialId,
    );
  }

  await confirmed(gateway.revokeCredential(currentCredentialId));
  assert.equal((await gateway.credentials(currentCredentialId)).status, 3);
  assert.equal(
    await gateway.activeCredentialByLineage(currentRequest.lineageId),
    ethers.constants.HashZero,
  );

  const postRevokeReceipt = await createFinalizedReceipt(
    gateway,
    adapter,
    state,
    "state-machine-post-revoke",
  );
  const postRevokeRequest = {
    ...currentRequest,
    receiptId: postRevokeReceipt.receiptId,
    cEnroll: currentRequest.cEnroll + 1n,
    templateVersion: 6,
    uniqueInputDigest: postRevokeReceipt.uniqueInputDigest,
    enrollmentContext: hash("atomic/enrollment-context/state-machine-post-revoke"),
  };
  const postRevokeDigest = await gateway.enrollmentLinkDigest(postRevokeRequest);
  const postRevokeSignature = ethers.utils.joinSignature(
    wallets[1]._signingKey().signDigest(postRevokeDigest),
  );
  await expectRevert(
    () =>
      gateway.replaceTemplateFromFinalizedBioZKFHESession(
        currentCredentialId,
        postRevokeReceipt.sourceSessionId,
        "0x",
        postRevokeRequest,
        postRevokeSignature,
      ),
    "revoked lineage cannot be revived through a new source receipt",
  );
  assert.equal(
    await adapter.consumedBy(postRevokeReceipt.sourceSessionId),
    ethers.constants.HashZero,
  );
  assert.equal(
    (await gateway.uniqueReceipts(postRevokeReceipt.receiptId)).exists,
    false,
  );
});

test("bounded seeded successor fuzz preserves receipt and single-active-lineage invariants", async (t) => {
  const { gateway, adapter, wallets, eip1193 } = await deployFixture();
  t.after(() => eip1193.disconnect());
  const state = await registerIssuanceState(gateway, wallets, "seeded-fuzz");
  const seeds = [0x1a2b3c4d, 0xdeadbeef, 0x9e3779b9, 0x5eed1234];
  const mutations = [
    "bad-signature",
    "bad-version",
    "bad-digest",
    "bad-lineage",
    "same-commitment",
    "bad-holder",
  ];
  let attemptedInvalidTransitions = 0;
  let successfulSuccessors = 0;

  for (const seed of seeds) {
    const random = seededRandom(seed);
    const suffix = `seeded-fuzz-${seed.toString(16)}`;
    const initialReceipt = await createFinalizedReceipt(
      gateway,
      adapter,
      state,
      `${suffix}-v1`,
    );
    const initial = await buildIssueRequest(
      gateway,
      wallets[1],
      state,
      initialReceipt,
      suffix,
    );
    let currentRequest = initial.request;
    let currentCredentialId =
      await gateway.callStatic.issueFromFinalizedBioZKFHESession(
        initialReceipt.sourceSessionId,
        "0x",
        currentRequest,
        initial.signature,
      );
    await confirmed(
      gateway.issueFromFinalizedBioZKFHESession(
        initialReceipt.sourceSessionId,
        "0x",
        currentRequest,
        initial.signature,
      ),
    );
    const issuedCredentialIds = [currentCredentialId];

    for (let version = 2; version <= 4; version += 1) {
      const receipt = await createFinalizedReceipt(
        gateway,
        adapter,
        state,
        `${suffix}-v${version}`,
      );
      const validRequest = {
        ...currentRequest,
        receiptId: receipt.receiptId,
        cEnroll: currentRequest.cEnroll + BigInt(1 + (random() % 7)),
        templateVersion: version,
        uniqueInputDigest: receipt.uniqueInputDigest,
        enrollmentContext: hash(
          `atomic/enrollment-context/${suffix}-v${version}`,
        ),
      };
      const validDigest = await gateway.enrollmentLinkDigest(validRequest);
      const validSignature = ethers.utils.joinSignature(
        wallets[1]._signingKey().signDigest(validDigest),
      );
      const mutation = mutations[random() % mutations.length];
      let invalidRequest = validRequest;
      let invalidSigner = wallets[1];
      if (mutation === "bad-signature") {
        invalidSigner = wallets[3];
      } else if (mutation === "bad-version") {
        invalidRequest = { ...validRequest, templateVersion: version + 1 };
      } else if (mutation === "bad-digest") {
        invalidRequest = {
          ...validRequest,
          uniqueInputDigest: hash(`atomic/${suffix}/wrong-input/${version}`),
        };
      } else if (mutation === "bad-lineage") {
        invalidRequest = {
          ...validRequest,
          lineageId: hash(`atomic/${suffix}/wrong-lineage/${version}`),
        };
      } else if (mutation === "same-commitment") {
        invalidRequest = { ...validRequest, cEnroll: currentRequest.cEnroll };
      } else {
        invalidRequest = {
          ...validRequest,
          holder: walletsAddressForLabel(
            `atomic/${suffix}/wrong-holder/${version}`,
          ),
        };
      }
      const invalidDigest = await gateway.enrollmentLinkDigest(invalidRequest);
      const invalidSignature = ethers.utils.joinSignature(
        invalidSigner._signingKey().signDigest(invalidDigest),
      );

      await expectRevert(
        () =>
          gateway.replaceTemplateFromFinalizedBioZKFHESession(
            currentCredentialId,
            receipt.sourceSessionId,
            "0x",
            invalidRequest,
            invalidSignature,
          ),
        `${mutation} under seed ${seed.toString(16)}`,
      );
      attemptedInvalidTransitions += 1;
      assert.equal(
        await adapter.consumedBy(receipt.sourceSessionId),
        ethers.constants.HashZero,
      );
      assert.equal((await gateway.uniqueReceipts(receipt.receiptId)).exists, false);
      assert.equal((await gateway.credentials(currentCredentialId)).status, 1);
      assert.equal(
        await gateway.activeCredentialByLineage(currentRequest.lineageId),
        currentCredentialId,
      );

      const newCredentialId =
        await gateway.callStatic.replaceTemplateFromFinalizedBioZKFHESession(
          currentCredentialId,
          receipt.sourceSessionId,
          "0x",
          validRequest,
          validSignature,
        );
      await confirmed(
        gateway.replaceTemplateFromFinalizedBioZKFHESession(
          currentCredentialId,
          receipt.sourceSessionId,
          "0x",
          validRequest,
          validSignature,
        ),
      );
      successfulSuccessors += 1;
      issuedCredentialIds.push(newCredentialId);
      currentCredentialId = newCredentialId;
      currentRequest = validRequest;

      const statuses = await Promise.all(
        issuedCredentialIds.map(async (credentialId) =>
          Number((await gateway.credentials(credentialId)).status),
        ),
      );
      assert.equal(statuses.filter((status) => status === 1).length, 1);
      assert.equal(statuses.at(-1), 1);
      assert.ok(statuses.slice(0, -1).every((status) => status === 2));
      assert.equal(
        await gateway.activeCredentialByLineage(currentRequest.lineageId),
        currentCredentialId,
      );
    }

    await confirmed(gateway.revokeCredential(currentCredentialId));
    assert.equal((await gateway.credentials(currentCredentialId)).status, 3);
    assert.equal(
      await gateway.activeCredentialByLineage(currentRequest.lineageId),
      ethers.constants.HashZero,
    );
  }

  assert.equal(attemptedInvalidTransitions, 12);
  assert.equal(successfulSuccessors, 12);
});
