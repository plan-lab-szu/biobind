import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import { ethers } from "ethers";

import { MESSAGE_ENROLL, computeSessionBinding, createTrustedCapturePacket } from "../scripts/trusted-capture-wire.mjs";
import { ScmvGallery, innerProduct, prepare, scmvBase, syntheticPeople } from "../scripts/lib/scmv-model.mjs";
import { BioZKFHESourceModel, standInCiphertext } from "../scripts/lib/biozkfhe-source-model.mjs";
import { EnrollmentBridge, canonicalReceiptIds, toU16 } from "../scripts/lib/enrollment-bridge.mjs";

const hash = ethers.utils.id;
const L = 128, GAMMA = 128;
const PARAMS = { L, d: 4, n: 3, gamma: GAMMA, T: scmvBase(GAMMA, L) };
const TAU = 8192n;

test("SCMV base matches the paper's operating points and recovery is exact", () => {
  assert.equal(scmvBase(128, 128), 35729n);
  assert.equal(scmvBase(512, 512), 547715n);
  const people = syntheticPeople(3, L);
  const gallery = new ScmvGallery(PARAMS);
  const enrolled = [];
  for (let i = 0; i < 14; i++) { // crosses the nd=12 append boundary
    const v = people.capture(i, GAMMA);
    gallery.update(prepare(v, gallery.N, PARAMS).Venroll);
    enrolled.push(v);
  }
  const probe = people.capture(5, GAMMA);
  const scores = gallery.identify(prepare(probe, 0, PARAMS).Videntify);
  scores.forEach((s, r) => assert.equal(s, innerProduct(probe, enrolled[r])));
  assert.ok(scores[5] >= TAU && scores.every((s, r) => r === 5 || s < TAU));
});

test("paper request binding: divergent C_enroll lets one identity obtain two uniqueness results", () => {
  const people = syntheticPeople(4, L);
  const src = new BioZKFHESourceModel({ mode: "paper", params: PARAMS, chainId: 31337,
    sourceContract: ethers.constants.AddressZero, tau: TAU });
  const enroll = (v, enrollVector) => {
    const { ctx } = src.createSession();
    src.bindRequest(ctx.sid, {
      cIdentify: standInCiphertext("identify", prepare(v, ctx.galleryCount, PARAMS).Videntify, hash("r1")),
      cEnroll: standInCiphertext("enroll", prepare(enrollVector, ctx.galleryCount, PARAMS).Venroll, hash("r2")),
    });
    return src.finalize(ctx.sid).uniquenessAccepted;
  };
  assert.equal(enroll(people.capture("A", GAMMA), Array(L).fill(0)), true);
  const recapture = people.capture("A", GAMMA);
  assert.equal(enroll(recapture, recapture), true);
});

function setup() {
  const derivationKey = ethers.Wallet.createRandom();
  const mcuKeys = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const channelKey = Buffer.alloc(32, 7);
  const mcu = { deviceVersionId: hash("mcu"), firmwareMeasurement: hash("fw"), channelId: hash("channel"),
    publicKey: mcuKeys.publicKey, channelKey };
  const profile = { policyHash: hash("policy"), modelHash: hash("model"), quantizationHash: hash("quant") };
  const sourceContract = `0x${hash("source").slice(-40)}`;
  const gateway = `0x${hash("gateway").slice(-40)}`;
  const bridge = new EnrollmentBridge({ derivationKey, deviceVersionId: hash("device-version"), ...profile,
    policyDigest: "12345", scmv: PARAMS, mcu });
  const src = new BioZKFHESourceModel({ mode: "bound", params: PARAMS, chainId: 31337, sourceContract,
    registeredBridges: [derivationKey.address], tau: TAU });
  const people = syntheticPeople(9, L);
  let counter = 0n;
  const newSession = (label) => {
    const s = src.createSession();
    const binding = { sourceChainId: 31337, sourceContract, sourceSessionId: s.ctx.sid,
      sourceContextHash: s.contextHash, destinationChainId: 31337, destinationGateway: gateway,
      holder: `0x${hash(`holder/${label}`).slice(-40)}`, lineageId: hash(`lineage/${label}`),
      enrollmentContext: hash(`ctx/${label}`), ...profile };
    return { ...s, binding };
  };
  const packet = (binding, person) => createTrustedCapturePacket({ messageType: MESSAGE_ENROLL,
    vector: toU16(people.capture(person, GAMMA)), channelKey, signingPrivateKey: mcuKeys.privateKey,
    metadata: { ...mcu, ...profile, sessionBinding: computeSessionBinding(binding), counter: ++counter,
      notAfter: 4_000_000_000n, coordinateBits: 16 } });
  // Off-chain receipt with the adapter's canonical identifiers.
  const receiptFor = (session, prep) => {
    const r = { sourceChainId: "31337", sourceContract, sourceSessionId: session.ctx.sid,
      sourceContextHash: session.contextHash, gallerySnapshotHash: session.ctx.gallerySnapshotHash,
      queryCiphertextDigest: prep.cIdentify.digest, enrollmentCiphertextDigest: prep.cEnroll.digest,
      verifiedOutputCollectionDigest: hash("outputs"), finalizationDigest: hash(`final/${session.ctx.sid}`),
      modelHash: profile.modelHash, quantizationHash: profile.quantizationHash, finalizedAtBlock: "1" };
    return { ...r, ...canonicalReceiptIds(r) };
  };
  const requestFor = (session, receipt, prep) => ({ receiptId: receipt.receiptId, lineageId: session.binding.lineageId,
    cEnroll: prep.cEnrollPoseidon, ...profile, templateVersion: 1, holder: session.binding.holder,
    deviceVersionId: hash("device-version"), uniqueInputDigest: receipt.uniqueInputDigest,
    enrollmentContext: session.binding.enrollmentContext });
  return { bridge, src, newSession, packet, receiptFor, requestFor, destination: { chainId: 31337, gateway } };
}

const rejectsWith = async (fn, code) => assert.rejects(async () => fn(), (e) => e.code === code);

test("bridge links only the receipt and request derived from its own sealed capture", async () => {
  const { bridge, src, newSession, packet, receiptFor, requestFor, destination } = setup();
  let sealed = bridge.initialize();
  const s = newSession("a");
  const prep = await bridge.prepareEnrollment(sealed, { packet: packet(s.binding, "P"), binding: s.binding,
    sourceContext: s.ctx });
  sealed = prep.sealed;
  src.bindRequest(s.ctx.sid, { cIdentify: prep.cIdentify, cEnroll: prep.cEnroll, attestation: prep.attestation });
  assert.equal(src.finalize(s.ctx.sid).status, "Finalized");
  const receipt = receiptFor(s, prep), request = requestFor(s, receipt, prep);

  await rejectsWith(() => bridge.signEnrollmentLink(sealed, { receipt: { ...receipt,
    enrollmentCiphertextDigest: hash("other") }, request, destination }), "RECEIPT_MISMATCH");
  await rejectsWith(() => bridge.signEnrollmentLink(sealed, { receipt,
    request: { ...request, holder: `0x${hash("x").slice(-40)}` }, destination }), "REQUEST_MISMATCH");
  const before = sealed;
  const link = bridge.signEnrollmentLink(sealed, { receipt, request, destination });
  sealed = link.sealed;
  assert.equal(bridge.signEnrollmentLink(sealed, { receipt, request, destination }).signature, link.signature);
  await rejectsWith(() => bridge.signEnrollmentLink(sealed, { receipt, request: { ...request, templateVersion: 2 },
    destination }), "SESSION_ALREADY_LINKED");
  await rejectsWith(() => bridge.signEnrollmentLink(before, { receipt, request: { ...request, templateVersion: 2 },
    destination }), "ROLLBACK_DETECTED");
  await rejectsWith(() => bridge.prepareEnrollment(sealed, { packet: packet(s.binding, "Q"), binding: s.binding,
    sourceContext: s.ctx }), "SESSION_ALREADY_USED");
});

test("bridge rejects session mixing and a forged gallery count before deriving anything", async () => {
  const { bridge, newSession, packet } = setup();
  const sealed = bridge.initialize();
  const s = newSession("a"), other = newSession("b");
  const pkt = packet(s.binding, "P");
  await rejectsWith(() => bridge.prepareEnrollment(sealed, { packet: pkt, binding: other.binding,
    sourceContext: other.ctx }), "SESSION_BINDING_MISMATCH");
  await rejectsWith(() => bridge.prepareEnrollment(sealed, { packet: pkt, binding: s.binding,
    sourceContext: { ...s.ctx, galleryCount: s.ctx.galleryCount + 3 } }), "SOURCE_CONTEXT_MISMATCH");
});

test("bound source aborts a stale slot and accepts a fresh retry", async () => {
  const { bridge, src, newSession, packet } = setup();
  let sealed = bridge.initialize();
  const prepared = [];
  for (const label of ["E", "F"]) {
    const s = newSession(label);
    const p = await bridge.prepareEnrollment(sealed, { packet: packet(s.binding, label), binding: s.binding,
      sourceContext: s.ctx });
    sealed = p.sealed;
    src.bindRequest(s.ctx.sid, { cIdentify: p.cIdentify, cEnroll: p.cEnroll, attestation: p.attestation });
    prepared.push(s);
  }
  assert.equal(src.finalize(prepared[0].ctx.sid).status, "Finalized");
  assert.equal(src.finalize(prepared[1].ctx.sid).status, "AbortedStaleSlot");
  sealed = bridge.abortEnrollment(sealed, { sourceSessionId: prepared[1].ctx.sid, reason: "stale" }).sealed;
  const retry = newSession("F-retry");
  const p = await bridge.prepareEnrollment(sealed, { packet: packet(retry.binding, "F"), binding: retry.binding,
    sourceContext: retry.ctx });
  src.bindRequest(retry.ctx.sid, { cIdentify: p.cIdentify, cEnroll: p.cEnroll, attestation: p.attestation });
  assert.equal(src.finalize(retry.ctx.sid).status, "Finalized");
  assert.equal(src.gallery.N, 2);
});
