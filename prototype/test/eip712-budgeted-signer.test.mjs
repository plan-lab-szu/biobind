import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, unlink, rmdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ethers } from "ethers";
import { BudgetSignerError, Eip712BudgetedSigner,
  budgetScopeId } from "../scripts/lib/eip712-budgeted-signer.mjs";

const field = (value, bytes = 32) => ethers.utils.hexZeroPad(
  ethers.utils.hexlify(value), bytes);
const hash = ethers.utils.id;
const wallet = ethers.Wallet.createRandom();
const gatewayAddress = ethers.Wallet.createRandom().address;
const chainId = 31337;
const scope = {
  applicationId: field(1), holder: field(2, 20), credentialId: field(3),
  deviceVersionId: field(4), policyHash: field(5),
  budgetPolicyHash: field(6), windowId: field(7),
};
assert.equal(budgetScopeId(scope),
  "d5225c90c3f63e397a598c1b7dcfad1bbebb244122f90ea0d231e94fbe0b53c3");
const capture = {
  cProbe: "101", ctxHash: "202", credentialId: scope.credentialId,
  deviceVersionId: scope.deviceVersionId, policyHash: scope.policyHash,
  modelHash: hash("model"), quantizationHash: hash("u16"),
  firmwareMeasurement: hash("firmware"), registryEpochAtCapture: "1",
  counter: "1", notAfter: "9999999",
};
async function fixture(t, limit = 1) {
  const directory = await mkdtemp(join(tmpdir(), "biozero-budget-signer-"));
  const database = join(directory, "budget.sqlite");
  const signer = new Eip712BudgetedSigner({ database, scope, wallet,
    chainId, gatewayAddress });
  const signers = [signer];
  signer.provision(limit);
  t.after(async () => {
    for (const instance of signers) instance.close();
    await unlink(database);
    await rmdir(directory);
  });
  return { signer, database, track: (instance) => signers.push(instance) };
}

test("EIP-712 digest signing spends one unit and replay returns identical bytes", async (t) => {
  const { signer, database, track } = await fixture(t);
  const attemptId = field(10);
  const signed = await signer.signCapture({ attemptId, capture });
  const recovered = ethers.utils.recoverAddress(
    signer.captureDigest(signed.capture), signed.signature);
  assert.equal(recovered, wallet.address);
  assert.deepEqual(signer.usage(), { used: 1, maxExposures: 1, active: true });

  const restarted = new Eip712BudgetedSigner({ database, scope, wallet,
    chainId, gatewayAddress });
  track(restarted);
  const replay = restarted.retransmit(attemptId);
  assert.deepEqual(replay.bytes, signed.bytes);
  await assert.rejects(() => restarted.signCapture({ attemptId: field(11), capture }),
    BudgetSignerError);
  assert.deepEqual(restarted.usage(), { used: 1, maxExposures: 1, active: true });
});

test("invalid scoped request cannot sign and post-reservation failure costs a unit", async (t) => {
  const { signer } = await fixture(t);
  await assert.rejects(() => signer.signCapture({
    attemptId: field(12), capture: { ...capture, policyHash: field(99) },
  }), BudgetSignerError);
  assert.equal(signer.usage().used, 0);
  await assert.rejects(() => signer.signCapture({
    attemptId: field(13), capture: { ...capture, cProbe: "invalid-integer" },
  }));
  assert.equal(signer.usage().used, 1);
  assert.throws(() => signer.retransmit(field(13)), BudgetSignerError);
  await assert.rejects(() => signer.signCapture({
    attemptId: field(14), capture,
  }), /budget exhausted/);
});

test("revoked policy scope cannot replay and successor scope signs separately", async (t) => {
  const { signer, database, track } = await fixture(t);
  const initial = await signer.signCapture({ attemptId: field(15), capture });
  signer.revoke();
  assert.throws(() => signer.retransmit(field(15)), BudgetSignerError);
  const successorScope = { ...scope, applicationId: field(21),
    credentialId: field(22), deviceVersionId: field(23), policyHash: field(24) };
  assert.notEqual(budgetScopeId(scope), budgetScopeId(successorScope));
  const successor = new Eip712BudgetedSigner({
    database, scope: successorScope, wallet, chainId, gatewayAddress,
  });
  track(successor);
  successor.provision(1);
  const next = await successor.signCapture({ attemptId: field(16),
    capture: { ...capture, credentialId: successorScope.credentialId,
      deviceVersionId: successorScope.deviceVersionId,
      policyHash: successorScope.policyHash } });
  assert.notEqual(next.signature, initial.signature);
  assert.equal(successor.usage().used, 1);
  await assert.rejects(() => successor.signCapture({
    attemptId: field(15), capture: next.capture,
  }), BudgetSignerError);
});

test("concurrent sign requests never exceed provisioned budget", async (t) => {
  const { signer } = await fixture(t, 3);
  const attempts = await Promise.allSettled(Array.from({ length: 12 }, (_, index) =>
    signer.signCapture({ attemptId: field(100 + index),
      capture: { ...capture, counter: String(index + 1) } })));
  assert.equal(attempts.filter(({ status }) => status === "fulfilled").length, 3);
  assert.equal(signer.usage().used, 3);
});
