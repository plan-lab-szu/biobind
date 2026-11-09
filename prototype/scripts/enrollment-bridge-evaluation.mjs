// L2 same-enrollment bridge evaluation. Researcher-owned local prototype,
// synthetic vectors, in-process Ganache 31337, no remote RPC.
//
// Part A: BioZKFHE enrollment semantics (SCMV plaintext model) under the
//         paper's request binding vs the proposed bound request.
// Part B: bridge state-machine controls (binding, mixing, substitution,
//         retry, abort, sealed-state rollback).
// Part C: bridge output -> finalized source fixture -> adapter -> atomic
//         UBCA issuance -> real Groth16 authentication from the bridge opening.

import { finalizedRecordFor, rememberFinalized } from "./lib/finalized-record.mjs";
import assert from "node:assert/strict";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { createHash, generateKeyPairSync } from "node:crypto";
import ganache from "ganache";
import solc from "solc";
import { ethers } from "ethers";
import { groth16, wtns } from "snarkjs";
import { DST_PROBE, poseidonCommitment, squaredDistance } from "./commitment.mjs";
import { MESSAGE_ENROLL, computeSessionBinding, createP256ECDHKeyPair, createTrustedCapturePacket,
  deriveChannelKey, deriveP256SharedSecret } from "./trusted-capture-wire.mjs";
import { ScmvGallery, inQuantizationProfile, prepare, scmvBase, syntheticPeople } from "./lib/scmv-model.mjs";
import { BioZKFHESourceModel, standInCiphertext } from "./lib/biozkfhe-source-model.mjs";
import { BridgeError, EnrollmentBridge, canonicalReceiptIds, enrollmentLinkDigest, toU16 }
  from "./lib/enrollment-bridge.mjs";
import { registerSyntheticPolicy } from "./lib/canonical-policy.mjs";

const root = resolve(import.meta.dirname, "..");
const out = resolve(root, "build", "enrollment-bridge");
const hash = ethers.utils.id;
const json = (v) => JSON.stringify(v, (_, x) => typeof x === "bigint" ? x.toString() : x, 2);
const confirmed = async (tx) => (await tx).wait();
const event = (r, name, arg) => r.events.find((e) => e.event === name).args[arg];
const zero32 = `0x${"00".repeat(32)}`;

const GAMMA = 128, L = 128;
const PARAMS = { L, d: 4, n: 3, gamma: GAMMA, T: scmvBase(GAMMA, L) };
const TAU = BigInt(GAMMA * GAMMA / 2);
const EPSILON = 2000; // squared u16 distance; synthetic recapture noise only

async function bridgeRejects(call, code) {
  try { await call(); } catch (e) {
    assert.ok(e instanceof BridgeError, `expected BridgeError ${code}, got ${e.message}`);
    assert.equal(e.code, code, e.message);
    return code;
  }
  assert.fail(`expected ${code}`);
}
function sourceRejects(call, message) {
  try { call(); } catch (e) { assert.equal(e.message, message); return message; }
  assert.fail(`expected ${message}`);
}
async function evmRejects(call, contract, errorName) {
  try { await call(); } catch (error) {
    const selector = contract.interface.getSighash(errorName);
    const values = [error.data, error.error?.data, error.error?.error?.data];
    assert.ok(values.some((v) => typeof v === "string" && v.startsWith(selector)),
      `expected ${errorName}, got ${error.message}`);
    return errorName;
  }
  assert.fail(`expected ${errorName}`);
}

/// 1:N login identification (argmax) and uniqueness check over a gallery.
function identifyArgmax(gallery, v) {
  const scores = gallery.identify(prepare(v, 0, PARAMS).Videntify);
  let best = -1, bestScore = null;
  scores.forEach((s, r) => { if (bestScore === null || s > bestScore) { best = r; bestScore = s; } });
  return { index: best, score: bestScore, duplicate: scores.some((s) => s >= TAU) };
}

// Plain (non-bridge) client used only for Part A paper-semantics runs.
function clientRequest(v, N, { enrollVector = v, declaredN = N } = {}) {
  const rand = () => `0x${createHash("sha256").update(String(Math.random())).digest("hex")}`;
  const { Videntify } = prepare(v, N, PARAMS);
  const { Venroll } = prepare(enrollVector, declaredN, PARAMS);
  return { cIdentify: standInCiphertext("identify", Videntify, rand()),
    cEnroll: standInCiphertext("enroll", Venroll, rand()) };
}

function partA_paper() {
  const people = syntheticPeople(11, L);
  const results = {};
  const fresh = (count) => {
    const src = new BioZKFHESourceModel({ mode: "paper", params: PARAMS, chainId: 31337,
      sourceContract: ethers.constants.AddressZero, tau: TAU });
    for (let i = 0; i < count; i++) {
      const { ctx } = src.createSession();
      src.bindRequest(ctx.sid, clientRequest(people.capture(`p${i}`, GAMMA), ctx.galleryCount));
      assert.equal(src.finalize(ctx.sid).uniquenessAccepted, true);
    }
    return src;
  };

  // A0 honest clients: every distinct person accepted, every recapture rejected,
  // login identifies each recapture as its own index.
  const honest = fresh(30);
  let recaptureRejected = 0, loginCorrect = 0;
  for (let i = 0; i < 30; i++) {
    const r = identifyArgmax(honest.gallery, people.capture(`p${i}`, GAMMA));
    if (r.duplicate) recaptureRejected++;
    if (r.index === i) loginCorrect++;
  }
  results.A0_honest = { enrolled: honest.gallery.N, blocks: honest.gallery.blocks.length,
    recaptureRejected, loginCorrect };

  // A1 identify/enroll divergence: C_identify from v_A, C_enroll from a zero
  // vector. Uniqueness is decided on C_identify only, so A is accepted, never
  // stored, and A's later recapture is accepted again (two receipts, one person).
  {
    const src = fresh(10);
    const { ctx } = src.createSession();
    src.bindRequest(ctx.sid, clientRequest(people.capture("A", GAMMA), ctx.galleryCount,
      { enrollVector: Array(L).fill(0) }));
    const first = src.finalize(ctx.sid).uniquenessAccepted;
    const again = src.createSession();
    src.bindRequest(again.ctx.sid, clientRequest(people.capture("A", GAMMA), again.ctx.galleryCount));
    const second = src.finalize(again.ctx.sid).uniquenessAccepted;
    results.A1_divergence_paper = { firstAccepted: first, sameIdentitySecondAccepted: second,
      uniquenessReceiptsForOnePerson: Number(first) + Number(second) };
    assert.equal(second, true);
  }

  // A2 slot placement: honest content, wrong declared N (=1). The merge adds
  // v_A onto person 1's occupied slot; index N stays empty; A's login now
  // returns person 1's identity index.
  {
    const src = fresh(10);
    const { ctx } = src.createSession();
    const vA = people.capture("A2", GAMMA);
    src.bindRequest(ctx.sid, clientRequest(vA, ctx.galleryCount, { declaredN: 1 }));
    const accepted = src.finalize(ctx.sid).uniquenessAccepted;
    const login = identifyArgmax(src.gallery, people.capture("A2", GAMMA));
    const victim = identifyArgmax(src.gallery, people.capture("p1", GAMMA));
    results.A2_wrong_slot_paper = { accepted, intendedIndex: 10, attackerLoginIndex: login.index,
      victimLoginIndex: victim.index, galleryCount: src.gallery.N };
    assert.equal(login.index, 1);
  }

  // A3 concurrent honest sessions at the same N (paper text does not state
  // whether the source serializes enrollment sessions; open question).
  {
    const src = fresh(10);
    const s1 = src.createSession(), s2 = src.createSession();
    const vB = people.capture("B", GAMMA), vC = people.capture("C", GAMMA);
    src.bindRequest(s1.ctx.sid, clientRequest(vB, s1.ctx.galleryCount));
    src.bindRequest(s2.ctx.sid, clientRequest(vC, s2.ctx.galleryCount));
    const r1 = src.finalize(s1.ctx.sid).uniquenessAccepted;
    const r2 = src.finalize(s2.ctx.sid).uniquenessAccepted;
    results.A3_concurrent_paper = { bothAccepted: r1 && r2, preparedAtSameN: s1.ctx.galleryCount === s2.ctx.galleryCount,
      loginB: identifyArgmax(src.gallery, people.capture("B", GAMMA)).index,
      loginC: identifyArgmax(src.gallery, people.capture("C", GAMMA)).index,
      expected: { B: 10, C: 11 } };
  }
  return results;
}

async function compile() {
  const paths = ["UBCALifecycle.sol", "UBCAAuthGateway.sol",
    "interfaces/IBioZKFHEUniquenessAdapter.sol", "interfaces/IBioZKFHEFinalizationSource.sol",
    "BioZKFHEFinalizationAdapter.sol", "test/LocalBioZKFHEFinalizationSource.sol",
    "generated/Groth16Verifier128.sol"];
  const sources = Object.fromEntries(await Promise.all(paths.map(async (p) =>
    [p, { content: await readFile(resolve(root, "contracts", p), "utf8") }])));
  const result = JSON.parse(solc.compile(JSON.stringify({ language: "Solidity", sources,
    settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: "shanghai",
      outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } } } })));
  const errors = (result.errors ?? []).filter((e) => e.severity === "error");
  assert.equal(errors.length, 0, errors.map((e) => e.formattedMessage).join("\n"));
  return result.contracts;
}

const RECEIPT_FIELDS = ["receiptId", "sourceChainId", "sourceContract", "sourceSessionId",
  "sourceContextHash", "gallerySnapshotHash", "queryCiphertextDigest", "enrollmentCiphertextDigest",
  "verifiedOutputCollectionDigest", "finalizationDigest", "uniqueInputDigest", "modelHash",
  "quantizationHash", "finalizedAtBlock"];
const plainReceipt = (r) => Object.fromEntries(RECEIPT_FIELDS.map((f) => [f, r[f].toString()]));

async function partBC(contracts) {
  const chain = ganache.provider({ chain: { chainId: 31337, hardfork: "shanghai" },
    logging: { quiet: true }, miner: { blockGasLimit: 30000000 },
    wallet: { deterministic: true, totalAccounts: 4 } });
  const provider = new ethers.providers.Web3Provider(chain);
  const [owner, holder1, holder2] = Object.values(chain.getInitialAccounts())
    .map(({ secretKey }) => new ethers.Wallet(secretKey, provider));
  const deploy = async (path, name, ...args) => {
    const c = contracts[path][name];
    const x = await new ethers.ContractFactory(c.abi, `0x${c.evm.bytecode.object}`, owner).deploy(...args);
    await x.deployTransaction.wait();
    return x;
  };
  try {
    const verifier = await deploy("generated/Groth16Verifier128.sol", "Groth16Verifier");
    const gateway = await deploy("UBCAAuthGateway.sol", "UBCAAuthGateway", verifier.address);
    const source = await deploy("test/LocalBioZKFHEFinalizationSource.sol", "LocalBioZKFHEFinalizationSource");
    const adapter = await deploy("BioZKFHEFinalizationAdapter.sol", "BioZKFHEFinalizationAdapter", source.address);
    await confirmed(gateway.configureUniquenessAdapter(adapter.address));
    await confirmed(adapter.configureAuthorizedConsumer(gateway.address));
    await confirmed(gateway.disableLegacyReceiptPath());

    const modelHash = hash("bridge/model/synthetic-FaceNet-shaped-128");
    const quantizationHash = hash("bridge/quant/L2-gamma128-round/u16-offset32768/v1");
    const { policyHash } = await registerSyntheticPolicy(gateway, {
      label: "bridge/policy/sqdist-2000/u16-offset/128/v1",
      modelHash, quantizationHash, epsilon: EPSILON,
    });
    const policyDigest = (await gateway.policyFieldDigest(policyHash)).toString();

    // R1 composite: MCU (P-256 packet key) + host TEE bridge (EVM derivation key).
    const derivationKey = ethers.Wallet.createRandom();
    const mcuKeys = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const afeStack = hash("bridge/AFE-stack/software-reference-NOT-hardware");
    const deviceVersionId = event(await confirmed(gateway.registerDevice(derivationKey.address, afeStack,
      modelHash, quantizationHash, policyHash)), "DeviceRegistered", "deviceVersionId");
    const mcu = { deviceVersionId: hash("bridge/mcu-version"), firmwareMeasurement: hash("bridge/mcu-fw"),
      channelId: hash("bridge/attested-channel") };
    const mcuECDH = createP256ECDHKeyPair(), teeECDH = createP256ECDHKeyPair();
    const shared = deriveP256SharedSecret(mcuECDH.privateKey, teeECDH.publicKey);
    assert.deepEqual(shared, deriveP256SharedSecret(teeECDH.privateKey, mcuECDH.publicKey));
    // Per-session channel keys are derived on demand from the attested ECDH secret.
    const keyFor = (binding) => deriveChannelKey(shared, mcu.channelId, computeSessionBinding(binding));
    const bridgeConfig = { derivationKey, deviceVersionId, modelHash, quantizationHash, policyHash,
      policyDigest, scmv: PARAMS, mcu: { ...mcu, publicKey: mcuKeys.publicKey } };

    const srcBound = new BioZKFHESourceModel({ mode: "bound", params: PARAMS, chainId: 31337,
      sourceContract: source.address, registeredBridges: [derivationKey.address], tau: TAU });
    const srcPaper = new BioZKFHESourceModel({ mode: "paper", params: PARAMS, chainId: 31337,
      sourceContract: source.address, tau: TAU });
    const people = syntheticPeople(23, L);
    let mcuCounter = 0n;
    const now = async () => (await provider.getBlock("latest")).timestamp;

    // The bridge needs the session key; a per-binding channel key models one
    // attested channel whose HKDF info includes the session binding.
    const bridge = new EnrollmentBridge(bridgeConfig);
    let sealed = bridge.initialize();
    const prepareWith = async (binding, sourceContext, packet) => {
      bridge.config.mcu.channelKey = keyFor(binding);
      return bridge.prepareEnrollment(sealed, { packet, binding, sourceContext, now: await now() });
    };

    const bindingFor = (src, holder, lineageLabel) => ({
      sourceChainId: 31337, sourceContract: source.address, sourceSessionId: src.ctx.sid,
      sourceContextHash: src.contextHash, destinationChainId: 31337, destinationGateway: gateway.address,
      holder: holder.address, lineageId: hash(lineageLabel), enrollmentContext: hash(`${lineageLabel}/ctx`),
      policyHash, modelHash, quantizationHash });
    const packetFor = (binding, vector, counter = ++mcuCounter) => createTrustedCapturePacket({
      messageType: MESSAGE_ENROLL, vector,
      metadata: { ...mcu, modelHash, quantizationHash, policyHash, sessionBinding: computeSessionBinding(binding),
        counter, notAfter: 4_000_000_000n, coordinateBits: 16 },
      channelKey: keyFor(binding), signingPrivateKey: mcuKeys.privateKey });

    async function recordAndPreview(src, sid) {
      const finalizedAtBlock = await provider.getBlockNumber();
      await confirmed(source.recordImmutableSession(sid,
        rememberFinalized(sid, src.finalizedSessionStruct(sid, { modelHash, quantizationHash, finalizedAtBlock }))));
      return plainReceipt(await adapter.previewFinalizedUniqueEnrollment(sid, finalizedRecordFor(sid)));
    }
    const requestFor = (binding, receipt, cEnroll, templateVersion = 1) => ({
      receiptId: receipt.receiptId, lineageId: binding.lineageId, cEnroll, policyHash, modelHash,
      quantizationHash, templateVersion, holder: binding.holder, deviceVersionId,
      uniqueInputDigest: receipt.uniqueInputDigest, enrollmentContext: binding.enrollmentContext });
    const destination = { chainId: 31337, gateway: gateway.address };

    // Full honest bound-mode enrollment through the bridge.
    async function enrollThroughBridge(person, holder, lineageLabel, src = srcBound) {
      const session = src.createSession();
      const binding = bindingFor(session, holder, lineageLabel);
      const prep = await prepareWith(binding, session.ctx, packetFor(binding, toU16(people.capture(person, GAMMA))));
      sealed = prep.sealed;
      src.bindRequest(session.ctx.sid, { cIdentify: prep.cIdentify, cEnroll: prep.cEnroll, attestation: prep.attestation });
      const fin = src.finalize(session.ctx.sid);
      return { session, binding, prep, fin };
    }

    const B = {}, C = {};

    // ---- C1: honest end-to-end issuance for person P1 / holder1.
    const e1 = await enrollThroughBridge("P1", holder1, "lineage/P1");
    assert.equal(e1.fin.status, "Finalized");
    const receipt1 = await recordAndPreview(srcBound, e1.session.ctx.sid);
    const request1 = requestFor(e1.binding, receipt1, e1.prep.cEnrollPoseidon);
    C.localEip712MatchesContract = enrollmentLinkDigest(request1, 31337, gateway.address)
      === await gateway.enrollmentLinkDigest(request1);
    assert.equal(C.localEip712MatchesContract, true);
    C.canonicalIdsMatchAdapter = canonicalReceiptIds(receipt1).receiptId === receipt1.receiptId
      && canonicalReceiptIds(receipt1).uniqueInputDigest === receipt1.uniqueInputDigest;
    assert.equal(C.canonicalIdsMatchAdapter, true);
    const preLinkSealed = sealed;
    const link1 = bridge.signEnrollmentLink(sealed, { receipt: receipt1, request: request1, destination });
    sealed = link1.sealed;

    // ---- B9 idempotent retry and no fork.
    const retry = bridge.signEnrollmentLink(sealed, { receipt: receipt1, request: request1, destination });
    B.B9_identicalRetrySameSignature = retry.retried && retry.signature === link1.signature;
    assert.equal(B.B9_identicalRetrySameSignature, true);
    B.B9_differentRequestAfterLink = await bridgeRejects(() => bridge.signEnrollmentLink(sealed,
      { receipt: receipt1, request: { ...request1, templateVersion: 2 }, destination }), "SESSION_ALREADY_LINKED");
    // ---- B11 rollback to the pre-link sealed state, and tampering.
    B.B11_rollbackToPreLinkState = await bridgeRejects(() => bridge.signEnrollmentLink(preLinkSealed,
      { receipt: receipt1, request: { ...request1, templateVersion: 2 }, destination }), "ROLLBACK_DETECTED");
    const tampered = { ...sealed, body: (sealed.body[0] === "0" ? "1" : "0") + sealed.body.slice(1) };
    B.B11_tamperedSeal = await bridgeRejects(() => bridge.signEnrollmentLink(tampered,
      { receipt: receipt1, request: request1, destination }), "SEAL_INVALID");

    const issueTx = await confirmed(gateway.issueFromFinalizedBioZKFHESession(e1.session.ctx.sid, finalizedRecordFor(e1.session.ctx.sid), request1, link1.signature));
    C.issuanceGas = issueTx.gasUsed.toNumber();
    const credentialId = event(issueTx, "FinalizedUniquenessReceiptIssued", "credentialId");
    C.issued = true;

    // ---- B1 packet for session S presented with another session's binding.
    {
      const s = srcBound.createSession(), other = srcBound.createSession();
      const b = bindingFor(s, holder2, "lineage/B1"), bo = bindingFor(other, holder2, "lineage/B1");
      const pkt = packetFor(b, toU16(people.capture("Q1", GAMMA)));
      B.B1_sessionMixAtPrepare = await bridgeRejects(() => prepareWith(bo, other.ctx, pkt), "SESSION_BINDING_MISMATCH");
      // ---- B2 host lies about gallery count N in the source-context preimage.
      B.B2_galleryCountLie = await bridgeRejects(() => prepareWith(b,
        { ...s.ctx, galleryCount: s.ctx.galleryCount + 5 }, pkt), "SOURCE_CONTEXT_MISMATCH");
      // ---- B5 MCU-authenticated vector outside the quantization profile.
      const doubled = people.capture("Q1", GAMMA).map((x) => 2 * x);
      assert.equal(inQuantizationProfile(doubled, GAMMA), false);
      B.B5_outOfProfileVector = await bridgeRejects(() => prepareWith(b, s.ctx,
        packetFor(b, toU16(doubled))), "VECTOR_OUT_OF_PROFILE");
      // Valid prepare, then B3 second capture for the same session and B4 stale counter.
      const ok = await prepareWith(b, s.ctx, pkt);
      sealed = ok.sealed;
      B.B3_secondCaptureSameSession = await bridgeRejects(() => prepareWith(b, s.ctx,
        packetFor(b, toU16(people.capture("Q2", GAMMA)))), "SESSION_ALREADY_USED");
      const s3 = srcBound.createSession();
      const b3 = bindingFor(s3, holder2, "lineage/B4");
      B.B4_staleCaptureCounter = await bridgeRejects(() => prepareWith(b3, s3.ctx,
        packetFor(b3, toU16(people.capture("Q3", GAMMA)), 1n)), "STALE_CAPTURE_COUNTER");
    }

    // ---- A1/B6 on an UNHARDENED (paper-mode) source: host binds the bridge's
    // C_identify with its own zero-vector C_enroll. The source accepts and
    // finalizes; the bridge refuses the UBCA link. The BioZKFHE gallery is
    // nevertheless left without the person's template.
    {
      const s = srcPaper.createSession();
      const b = bindingFor(s, holder2, "lineage/B6");
      const prep = await prepareWith(b, s.ctx, packetFor(b, toU16(people.capture("D", GAMMA))));
      sealed = prep.sealed;
      const substituted = standInCiphertext("enroll", prepare(Array(L).fill(0), s.ctx.galleryCount, PARAMS).Venroll, zero32);
      srcPaper.bindRequest(s.ctx.sid, { cIdentify: prep.cIdentify, cEnroll: substituted });
      const fin = srcPaper.finalize(s.ctx.sid);
      const receipt = await recordAndPreview(srcPaper, s.ctx.sid);
      B.B6_substitutedEnrollCiphertext = await bridgeRejects(() => bridge.signEnrollmentLink(sealed,
        { receipt, request: requestFor(b, receipt, prep.cEnrollPoseidon), destination }), "RECEIPT_MISMATCH");
      B.B6_paperSourceStillAccepted = fin.uniquenessAccepted;
      B.B6_personMissingFromPaperGallery = !identifyArgmax(srcPaper.gallery, people.capture("D", GAMMA)).duplicate;
      // Same substitution against the BOUND source is rejected at request time.
      const sb = srcBound.createSession();
      const bb = bindingFor(sb, holder2, "lineage/B6b");
      const prepB = await prepareWith(bb, sb.ctx, packetFor(bb, toU16(people.capture("D", GAMMA))));
      sealed = prepB.sealed;
      B.B6_boundSourceRejectsSubstitution = sourceRejects(() => srcBound.bindRequest(sb.ctx.sid,
        { cIdentify: prepB.cIdentify, cEnroll: substituted, attestation: prepB.attestation }), "UnregisteredBridge");
      // A2 analogue against the bound source: an attestation over a different
      // declared N cannot be produced without lying to the bridge (B2), and a
      // replayed attestation from an earlier N is rejected.
      sealed = bridge.abortEnrollment(sealed, { sourceSessionId: sb.ctx.sid, reason: "source rejected" }).sealed;
    }

    // ---- B7/B8 mixing and request substitution using P1's state and a second prepared session.
    {
      const e2 = await enrollThroughBridge("P2", holder2, "lineage/P2");
      const receipt2 = await recordAndPreview(srcBound, e2.session.ctx.sid);
      B.B7_requestFromOtherSession = await bridgeRejects(() => bridge.signEnrollmentLink(sealed,
        { receipt: receipt2, request: request1, destination }), "REQUEST_MISMATCH");
      B.B7_receiptFieldsSpliced = await bridgeRejects(() => bridge.signEnrollmentLink(sealed,
        { receipt: { ...receipt2, enrollmentCiphertextDigest: receipt1.enrollmentCiphertextDigest }, request: request1,
          destination }), "RECEIPT_MISMATCH");
      const base2 = requestFor(e2.binding, receipt2, e2.prep.cEnrollPoseidon);
      for (const [name, req, dest] of [
        ["otherCommitment", { ...base2, cEnroll: (BigInt(base2.cEnroll) + 1n).toString() }, destination],
        ["otherHolder", { ...base2, holder: holder1.address }, destination],
        ["otherLineage", { ...base2, lineageId: hash("lineage/other") }, destination],
        ["otherGateway", base2, { chainId: 31337, gateway: holder1.address }],
      ]) B[`B8_${name}`] = await bridgeRejects(() => bridge.signEnrollmentLink(sealed,
        { receipt: receipt2, request: req, destination: dest }), "REQUEST_MISMATCH");
      // A host-substituted request that the bridge never signed fails on chain too.
      const link2 = bridge.signEnrollmentLink(sealed, { receipt: receipt2, request: base2, destination });
      sealed = link2.sealed;
      B.B8_onChainSignatureReuseForOtherCommitment = await evmRejects(() => gateway.callStatic
        .issueFromFinalizedBioZKFHESession(e2.session.ctx.sid,
          finalizedRecordFor(e2.session.ctx.sid),
          { ...base2, cEnroll: (BigInt(base2.cEnroll) + 1n).toString() }, link2.signature), gateway, "InvalidEnrollmentLink");
    }

    // ---- B10 non-unique source result -> abort -> no link; then A3-bound stale slot -> retry.
    {
      const dup = await enrollThroughBridge("P1", holder2, "lineage/dup");
      B.B10_duplicateRejectedBySource = dup.fin.uniquenessAccepted === false;
      await confirmed(source.recordImmutableSession(dup.session.ctx.sid, rememberFinalized(dup.session.ctx.sid, srcBound.finalizedSessionStruct(
        dup.session.ctx.sid, { modelHash, quantizationHash, finalizedAtBlock: await provider.getBlockNumber() }))));
      B.B10_adapterRefusesNonUnique = await evmRejects(() => adapter.previewFinalizedUniqueEnrollment(dup.session.ctx.sid, finalizedRecordFor(dup.session.ctx.sid)),
        adapter, "InvalidSourceSession");
      const blobBeforeAbort = sealed;
      sealed = bridge.abortEnrollment(sealed, { sourceSessionId: dup.session.ctx.sid, reason: "non-unique" }).sealed;
      const forged = { ...receipt1, sourceSessionId: dup.session.ctx.sid };
      B.B10_linkAfterAbort = await bridgeRejects(() => bridge.signEnrollmentLink(sealed,
        { receipt: forged, request: request1, destination }), "SESSION_NOT_LINKABLE");
      B.B10_rollbackToPreAbortState = await bridgeRejects(() => bridge.signEnrollmentLink(blobBeforeAbort,
        { receipt: forged, request: request1, destination }), "ROLLBACK_DETECTED");
      B.B10_reprepareAbortedSession = await bridgeRejects(() => prepareWith(dup.binding, dup.session.ctx,
        packetFor(dup.binding, toU16(people.capture("P1", GAMMA)))), "SESSION_ALREADY_USED");
    }
    const A3 = {};
    {
      // Two honest bridge sessions prepared at the same gallery count.
      const s1 = srcBound.createSession(), s2 = srcBound.createSession();
      const b1 = bindingFor(s1, holder2, "lineage/E"), b2 = bindingFor(s2, holder2, "lineage/F");
      const p1 = await prepareWith(b1, s1.ctx, packetFor(b1, toU16(people.capture("E", GAMMA)))); sealed = p1.sealed;
      const p2 = await prepareWith(b2, s2.ctx, packetFor(b2, toU16(people.capture("F", GAMMA)))); sealed = p2.sealed;
      srcBound.bindRequest(s1.ctx.sid, { cIdentify: p1.cIdentify, cEnroll: p1.cEnroll, attestation: p1.attestation });
      srcBound.bindRequest(s2.ctx.sid, { cIdentify: p2.cIdentify, cEnroll: p2.cEnroll, attestation: p2.attestation });
      A3.firstFinalized = srcBound.finalize(s1.ctx.sid).status;
      A3.secondStatus = srcBound.finalize(s2.ctx.sid).status;
      assert.equal(A3.secondStatus, "AbortedStaleSlot");
      sealed = bridge.abortEnrollment(sealed, { sourceSessionId: s2.ctx.sid, reason: "stale slot" }).sealed;
      // Retry = new source session + new capture; issue on chain for holder2.
      const retryEnroll = await enrollThroughBridge("F", holder2, "lineage/F-retry");
      A3.retryStatus = retryEnroll.fin.status;
      const r = await recordAndPreview(srcBound, retryEnroll.session.ctx.sid);
      const q = requestFor(retryEnroll.binding, r, retryEnroll.prep.cEnrollPoseidon);
      const l = bridge.signEnrollmentLink(sealed, { receipt: r, request: q, destination });
      sealed = l.sealed;
      await confirmed(gateway.issueFromFinalizedBioZKFHESession(retryEnroll.session.ctx.sid, finalizedRecordFor(retryEnroll.session.ctx.sid), q, l.signature));
      A3.retryIssuedOnChain = true;
    }

    // Bound-source gallery integrity: every enrolled person logs in as own index.
    const boundOrder = [["P1", 0], ["P2", 1], ["E", 2], ["F", 3]];
    C.boundGalleryCount = srcBound.gallery.N;
    C.boundLoginCorrect = boundOrder.every(([p, i]) => identifyArgmax(srcBound.gallery, people.capture(p, GAMMA)).index === i);
    assert.equal(C.boundLoginCorrect, true);

    // ---- C2: authenticate P1 with a real Groth16 proof from the bridge opening.
    // Auth-time capture is still the software signer (not part of L2).
    const deadline = (await now()) + 600;
    const challenge = await confirmed(gateway.connect(holder1).issueAuthenticationChallenge(
      hash("bridge/action"), credentialId, deviceVersionId, deadline));
    const nonce = event(challenge, "UBCAAuthChallengeIssued", "nonce");
    const ctxHash = event(challenge, "UBCAAuthChallengeIssued", "ctxHash").toString();
    const context = { beneficiary: holder1.address, action: hash("bridge/action"), credentialId, deviceVersionId,
      registryEpochAtIssue: event(challenge, "UBCAAuthChallengeIssued", "registryEpochAtIssue"), nonce, deadline };
    const probe = toU16(people.capture("P1", GAMMA)).map(String);
    C.genuineSquaredDistance = squaredDistance(e1.prep.opening.values, probe).toString();
    const rProbe = "424242";
    const cProbe = (await poseidonCommitment({ roleTag: DST_PROBE, policyDigest, contextDigest: ctxHash,
      dimension: L, salt: rProbe, values: probe })).toString();
    const input = { cEnroll: e1.prep.cEnrollPoseidon, cProbe, policyDigest, ctxHash, epsilon: String(EPSILON),
      rEnroll: e1.prep.opening.salt, rProbe, enrollment: e1.prep.opening.values, probe };
    const wasm = resolve(root, "build/auth_distance_128/auth_distance_128_js/auth_distance_128.wasm");
    const zkey = resolve(root, "build/proving/auth_distance_128/auth_distance_128_benchmark_final.zkey");
    await wtns.calculate(input, wasm, resolve(out, "genuine.wtns"), {});
    const { proof, publicSignals } = await groth16.prove(zkey, resolve(out, "genuine.wtns"));
    const call = JSON.parse(`[${await groth16.exportSolidityCallData(proof, publicSignals)}]`);
    const capture = { cProbe, ctxHash, credentialId, deviceVersionId, policyHash, modelHash, quantizationHash,
      firmwareMeasurement: afeStack, registryEpochAtCapture: await gateway.registryEpoch(), counter: 1, notAfter: deadline };
    const captureSig = ethers.utils.joinSignature(derivationKey._signingKey().signDigest(
      await gateway.captureStatementDigest(capture)));
    const auth = await confirmed(gateway.connect(holder1).verifyAndConsumeAuthentication(...call, context, capture, captureSig));
    C.authenticationGas = auth.gasUsed.toNumber();
    // Impostor probe cannot even produce a witness against P1's commitment.
    const impostor = toU16(people.capture("P2", GAMMA)).map(String);
    C.impostorSquaredDistance = squaredDistance(e1.prep.opening.values, impostor).toString();
    // Fresh commitment for the impostor probe so that ONLY the distance
    // constraint (auth_distance.circom line 83) can fail.
    const impostorCProbe = (await poseidonCommitment({ roleTag: DST_PROBE, policyDigest, contextDigest: ctxHash,
      dimension: L, salt: rProbe, values: impostor })).toString();
    const errors = [];
    const origError = console.error;
    console.error = (...a) => errors.push(a.join(" "));
    try {
      await wtns.calculate({ ...input, cProbe: impostorCProbe, probe: impostor }, wasm,
        resolve(out, "impostor.wtns"), {});
      C.impostorWitnessRejected = false;
    } catch { C.impostorWitnessRejected = true; } finally { console.error = origError; }
    C.impostorFailingConstraint = errors.join(" ").match(/line: \d+/)?.[0] ?? "unreported";
    assert.equal(C.impostorFailingConstraint, "line: 83");
    assert.equal(C.impostorWitnessRejected, true);
    return { B, C, A3_bound: A3 };
  } finally { await chain.disconnect(); }
}

async function main() {
  await mkdir(out, { recursive: true });
  assert.equal(scmvBase(128, 128), 35729n); // paper, FaceNet operating point
  assert.equal(scmvBase(512, 512), 547715n); // paper, MobileFaceNet operating point
  const A = partA_paper();
  console.log(json(A));
  const BC = await partBC(await compile());
  console.log(json(BC));
  const files = ["scripts/lib/scmv-model.mjs", "scripts/lib/biozkfhe-source-model.mjs",
    "scripts/lib/enrollment-bridge.mjs", "scripts/enrollment-bridge-evaluation.mjs", "contracts/UBCAAuthGateway.sol"];
  const sourceSha256 = Object.fromEntries(await Promise.all(files.map(async (f) =>
    [f, createHash("sha256").update(await readFile(resolve(root, f))).digest("hex")])));
  const result = { generatedAt: new Date().toISOString(), node: process.version, compiler: solc.version(),
    params: { ...PARAMS, T: PARAMS.T.toString(), tau: TAU.toString(), epsilon: EPSILON },
    scope: "local synthetic; SCMV plaintext semantics (no BGV); software bridge/TEE model; fixture source; benchmark-only proving key",
    partA_paperSemantics: A, ...BC, sourceSha256,
    limits: [
      "No real BGV, PVSC, committee, TEE, MCU, or BioZKFHE contract was run",
      "Paper-mode A1/A2 require a malicious enrollment client, which BioZKFHE's model excludes; they are composition obligations, not BioZKFHE vulnerabilities",
      "A3 depends on whether the real source serializes enrollment sessions; the paper text does not say",
      "SCMV d=4 is far below a real BGV slot count; layout semantics are unchanged",
      "Sealed-state rollback relies on a modelled hardware monotonic counter",
    ] };
  await writeFile(resolve(out, "result.json"), json(result));
  console.log("wrote", resolve(out, "result.json"));
}

main().catch((e) => { console.error(e); process.exitCode = 1; })
  .finally(async () => { if (globalThis.curve_bn128?.terminate) await globalThis.curve_bn128.terminate(); });
