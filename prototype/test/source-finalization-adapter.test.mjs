import { encodeFinalizedSession, finalizedRecordFor, rememberFinalized } from "../scripts/lib/finalized-record.mjs";
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

async function compileContracts() {
  compilation ??= (async () => {
    const [sourceInterface, adapterInterface, adapter, localSource] =
      await Promise.all([
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
          resolve(
            prototypeRoot,
            "contracts",
            "interfaces",
            "IBioZKFHEUniquenessAdapter.sol",
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
      ]);
    const harness = `
      // SPDX-License-Identifier: MIT
      pragma solidity ^0.8.24;
      import "interfaces/IBioZKFHEUniquenessAdapter.sol";
      contract FinalizationAdapterConsumerHarness {
        function consume(
          address adapter,
          bytes32 sourceSessionId,
          bytes32 consumerBinding,
          bytes calldata sourceRecord
        ) external returns (
          IBioZKFHEUniquenessAdapter.FinalizedUniqueEnrollment memory receipt
        ) {
          return IBioZKFHEUniquenessAdapter(adapter)
            .consumeFinalizedUniqueEnrollment(sourceSessionId, consumerBinding, sourceRecord);
        }
        function consumeThenRevert(
          address adapter,
          bytes32 sourceSessionId,
          bytes32 consumerBinding,
          bytes calldata sourceRecord
        ) external {
          IBioZKFHEUniquenessAdapter(adapter)
            .consumeFinalizedUniqueEnrollment(sourceSessionId, consumerBinding, sourceRecord);
          revert("downstream issuance rejected");
        }
      }
    `;
    const input = {
      language: "Solidity",
      sources: {
        "interfaces/IBioZKFHEFinalizationSource.sol": {
          content: sourceInterface,
        },
        "interfaces/IBioZKFHEUniquenessAdapter.sol": {
          content: adapterInterface,
        },
        "BioZKFHEFinalizationAdapter.sol": { content: adapter },
        "test/LocalBioZKFHEFinalizationSource.sol": { content: localSource },
        "FinalizationAdapterConsumerHarness.sol": { content: harness },
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
      source:
        output.contracts["test/LocalBioZKFHEFinalizationSource.sol"]
          .LocalBioZKFHEFinalizationSource,
      adapter:
        output.contracts["BioZKFHEFinalizationAdapter.sol"]
          .BioZKFHEFinalizationAdapter,
      harness:
        output.contracts["FinalizationAdapterConsumerHarness.sol"]
          .FinalizationAdapterConsumerHarness,
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
  assert.fail(`expected same-chain source rejection: ${label}`);
}

async function deployFixture() {
  const compiled = await compileContracts();
  const eip1193 = ganache.provider({
    chain: { chainId: 31337, hardfork: "shanghai" },
    miner: { blockGasLimit: 30_000_000 },
    logging: { quiet: true },
    wallet: { deterministic: true, totalAccounts: 4 },
  });
  const provider = new ethers.providers.Web3Provider(eip1193);
  const wallets = Object.values(eip1193.getInitialAccounts()).map(
    ({ secretKey }) => new ethers.Wallet(secretKey, provider),
  );
  const source = await factory(compiled.source, wallets[0]).deploy();
  await source.deployTransaction.wait();
  const adapter = await factory(compiled.adapter, wallets[0]).deploy(source.address);
  await adapter.deployTransaction.wait();
  const harness = await factory(compiled.harness, wallets[0]).deploy();
  await harness.deployTransaction.wait();
  await confirmed(adapter.configureAuthorizedConsumer(harness.address));
  return { source, adapter, harness, wallets, eip1193 };
}

function validSession(suffix, overrides = {}) {
  return {
    operation: 1,
    finalized: true,
    uniquenessAccepted: true,
    expectedBlockCount: 4,
    verifiedBlockCount: 4,
    confirmationThreshold: 3,
    confirmationCount: 3,
    sourceContextHash: hash(`source/context/${suffix}`),
    gallerySnapshotHash: hash(`source/gallery/${suffix}`),
    queryCiphertextDigest: hash(`source/query/${suffix}`),
    enrollmentCiphertextDigest: hash(`source/enrollment/${suffix}`),
    verifiedOutputCollectionDigest: hash(`source/outputs/${suffix}`),
    modelHash: hash(`source/model/${suffix}`),
    quantizationHash: hash(`source/quantization/${suffix}`),
    finalizedAtBlock: 1,
    ...overrides,
  };
}

test("same-chain adapter derives a canonical one-time receipt from finalized BioZKFHE state", async (t) => {
  const { source, adapter, harness, wallets, eip1193 } = await deployFixture();
  t.after(() => eip1193.disconnect());
  const sourceSessionId = hash("source/session/success");
  const session = validSession("success");
  const consumerBinding = hash("source/consumer/success");
  await confirmed(source.recordImmutableSession(sourceSessionId, rememberFinalized(sourceSessionId, session)));

  await expectRevert(
    () =>
      adapter
        .connect(wallets[2])
        .consumeFinalizedUniqueEnrollment(sourceSessionId, consumerBinding, finalizedRecordFor(sourceSessionId)),
    "only the configured UBCA consumer may consume",
  );

  const receipt = await harness.callStatic.consume(
    adapter.address,
    sourceSessionId,
    consumerBinding,
    finalizedRecordFor(sourceSessionId),
  );
  const expectedFinalizationDigest = await adapter.finalizationDigest(
    sourceSessionId,
    session,
  );
  const expectedReceiptId = ethers.utils.keccak256(
    ethers.utils.defaultAbiCoder.encode(
      ["string", "uint256", "address", "bytes32", "bytes32"],
      [
        "UBCA/BioZKFHE/receipt/v1",
        31337,
        source.address,
        sourceSessionId,
        expectedFinalizationDigest,
      ],
    ),
  );
  assert.equal(receipt.sourceChainId.toNumber(), 31337);
  assert.equal(receipt.sourceContract, source.address);
  assert.equal(receipt.sourceSessionId, sourceSessionId);
  assert.equal(receipt.finalizationDigest, expectedFinalizationDigest);
  assert.equal(receipt.receiptId, expectedReceiptId);
  assert.equal(receipt.queryCiphertextDigest, session.queryCiphertextDigest);
  assert.equal(
    receipt.enrollmentCiphertextDigest,
    session.enrollmentCiphertextDigest,
  );

  await confirmed(
    harness.consume(adapter.address, sourceSessionId, consumerBinding, finalizedRecordFor(sourceSessionId)),
  );
  assert.equal(await adapter.consumedBy(sourceSessionId), consumerBinding);
  await expectRevert(
    () => harness.consume(adapter.address, sourceSessionId, consumerBinding, finalizedRecordFor(sourceSessionId)),
    "a finalized session is consumable once",
  );
});

test("adapter rejects non-enrollment, non-finalized, non-unique, incomplete, and under-confirmed sessions", async (t) => {
  const { source, adapter, harness, eip1193 } = await deployFixture();
  t.after(() => eip1193.disconnect());
  const malformed = [
    ["login", { operation: 2 }],
    ["not-finalized", { finalized: false }],
    ["not-unique", { uniquenessAccepted: false }],
    ["incomplete-coverage", { verifiedBlockCount: 3 }],
    ["under-confirmed", { confirmationCount: 2 }],
    ["missing-enrollment-ciphertext", { enrollmentCiphertextDigest: ethers.constants.HashZero }],
    ["future-finalization-block", { finalizedAtBlock: 1_000_000 }],
  ];

  for (const [label, overrides] of malformed) {
    const sourceSessionId = hash(`source/session/${label}`);
    await confirmed(
      source.recordImmutableSession(
        sourceSessionId,
        rememberFinalized(sourceSessionId, validSession(label, overrides)),
      ),
    );
    await expectRevert(
      () =>
        harness.consume(
          adapter.address,
          sourceSessionId,
          hash(`source/consumer/${label}`),
          finalizedRecordFor(sourceSessionId),
        ),
      label,
    );
    assert.equal(
      await adapter.consumedBy(sourceSessionId),
      ethers.constants.HashZero,
    );
  }
});

test("a downstream failure rolls back adapter consumption and consumer revocation is terminal", async (t) => {
  const { source, adapter, harness, eip1193 } = await deployFixture();
  t.after(() => eip1193.disconnect());
  const sourceSessionId = hash("source/session/downstream-rollback");
  const consumerBinding = hash("source/consumer/downstream-rollback");
  await confirmed(
    source.recordImmutableSession(
      sourceSessionId,
      rememberFinalized(sourceSessionId, validSession("downstream-rollback")),
    ),
  );

  await expectRevert(
    () =>
      harness.consumeThenRevert(
        adapter.address,
        sourceSessionId,
        consumerBinding,
        finalizedRecordFor(sourceSessionId),
      ),
    "downstream credential issuance failure",
  );
  assert.equal(
    await adapter.consumedBy(sourceSessionId),
    ethers.constants.HashZero,
  );

  await confirmed(adapter.revokeAuthorizedConsumer());
  await expectRevert(
    () => harness.consume(adapter.address, sourceSessionId, consumerBinding, finalizedRecordFor(sourceSessionId)),
    "revoked consumer",
  );
  await expectRevert(
    () => adapter.configureAuthorizedConsumer(harness.address),
    "consumer cannot be reconfigured after terminal revocation",
  );
  assert.equal(
    await adapter.consumedBy(sourceSessionId),
    ethers.constants.HashZero,
  );
});

test("adapter accepts only the calldata record whose encoding matches the stored digest", async (t) => {
  const { source, adapter, harness, eip1193 } = await deployFixture();
  t.after(() => eip1193.disconnect());
  const sourceSessionId = hash("source/session/calldata-record");
  const consumerBinding = hash("source/consumer/calldata-record");
  const stored = validSession("calldata-record");
  await confirmed(source.recordImmutableSession(sourceSessionId, stored));

  // Each altered field, and a session id with no stored digest, must be rejected.
  const altered = [
    ["enrollment digest", { enrollmentCiphertextDigest: hash("source/enrollment/other") }],
    ["output collection", { verifiedOutputCollectionDigest: hash("source/outputs/other") }],
    ["gallery snapshot", { gallerySnapshotHash: hash("source/gallery/other") }],
    ["finalized block", { finalizedAtBlock: 2 }],
  ];
  for (const [label, overrides] of altered) {
    const record = encodeFinalizedSession({ ...stored, ...overrides });
    await expectRevert(() => adapter.previewFinalizedUniqueEnrollment(sourceSessionId, record), label);
    await expectRevert(() => harness.consume(adapter.address, sourceSessionId, consumerBinding, record), label);
  }
  await expectRevert(
    () => adapter.previewFinalizedUniqueEnrollment(hash("source/session/absent"), encodeFinalizedSession(stored)),
    "no stored digest",
  );
  assert.equal(await adapter.consumedBy(sourceSessionId), ethers.constants.HashZero);

  // Trailing bytes decode to the same record and are re-encoded canonically,
  // so they neither break nor change the accepted receipt.
  const canonical = encodeFinalizedSession(stored);
  const padded = `${canonical}${"00".repeat(32)}`;
  const a = await adapter.previewFinalizedUniqueEnrollment(sourceSessionId, canonical);
  const b = await adapter.previewFinalizedUniqueEnrollment(sourceSessionId, padded);
  assert.equal(a.receiptId, b.receiptId);
  await confirmed(harness.consume(adapter.address, sourceSessionId, consumerBinding, canonical));
  assert.equal(await adapter.consumedBy(sourceSessionId), consumerBinding);
});
