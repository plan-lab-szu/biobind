// Software reference model of the R1 host-TEE enrollment bridge (L2).
//
// From ONE authenticated MCU vector the bridge derives, inside one call:
//   SCMV (V_identify, V_enroll) for BioZKFHE, both ciphertexts, and the UBCA
//   Poseidon enrollment commitment. It seals a pending record, later checks
//   the finalized BioZKFHE receipt against that record, and only then signs
//   the UBCA EnrollmentLink statement.
//
// Not modelled: real TEE isolation/attestation, real BGV (transparent
// stand-in ciphertexts), RNG quality, side channels. The monotonic counter
// object stands in for hardware non-rollback state; the host stores sealed
// blobs and may replay or tamper with them.

import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { ethers } from "ethers";
import { DST_ENROLL, poseidonCommitment, poseidonCommitmentWide } from "../commitment.mjs";
import { MESSAGE_ENROLL, computeSessionBinding, verifyAndOpenTrustedCapturePacket } from "../trusted-capture-wire.mjs";
import { SOURCE_OP_ENROLL, inQuantizationProfile, prepare } from "./scmv-model.mjs";
import { enrollRequestDigest, sourceContextHash, standInCiphertext } from "./biozkfhe-source-model.mjs";

const { keccak256, defaultAbiCoder: abi, joinSignature, _TypedDataEncoder } = ethers.utils;
const BN254 = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/// v1 representation map between BioZKFHE signed coordinates and the UBCA
/// unsigned 16-bit wire/circuit encoding. Squared distance is invariant.
export const U16_OFFSET = 32768;
export const toU16 = (v) => v.map((x) => x + U16_OFFSET);
export const fromU16 = (u) => u.map((x) => Number(x) - U16_OFFSET);

/// Circuit-side encoding of the enrollment commitment. v1 (default) is the
/// original 16-bit, packSize-15, Poseidon(3)-chain format; v2 matches
/// circuits/auth_private_v2.circom (Poseidon(16) chain) at any coordinate width.
/// The MCU packet transport stays u16 in both cases.
export const COMMITMENT_V1 = { format: 1, bits: 16, packSize: 15, offset: U16_OFFSET };
export const commitmentV2 = (bits) => ({ format: 2, bits, packSize: Math.floor(240 / bits), offset: 1 << (bits - 1) });

export class BridgeError extends Error {
  constructor(code, detail = "") { super(`${code}${detail ? `: ${detail}` : ""}`); this.code = code; }
}
const fail = (code, detail) => { throw new BridgeError(code, detail); };
const eq = (a, b) => String(a).toLowerCase() === String(b).toLowerCase();

export class MonotonicCounter {
  #value = 0n;
  read() { return this.#value; }
  increment() { this.#value += 1n; return this.#value; }
}

const ENROLL_LINK_TYPES = { EnrollmentLink: [
  { name: "receiptId", type: "bytes32" }, { name: "lineageId", type: "bytes32" },
  { name: "cEnroll", type: "uint256" }, { name: "uniqueInputDigest", type: "bytes32" },
  { name: "modelHash", type: "bytes32" }, { name: "quantizationHash", type: "bytes32" },
  { name: "policyHash", type: "bytes32" }, { name: "templateVersion", type: "uint32" },
  { name: "holder", type: "address" }, { name: "deviceVersionId", type: "bytes32" },
  { name: "enrollmentContext", type: "bytes32" },
] };

/// Local EIP-712 digest; must equal UBCALifecycle.enrollmentLinkDigest.
export function enrollmentLinkDigest(request, chainId, gateway) {
  return _TypedDataEncoder.hash({ name: "UBCA Enrollment Link", version: "1", chainId,
    verifyingContract: gateway }, ENROLL_LINK_TYPES, request);
}

/// Same formulas as UBCAAuthGateway.finalizedReceiptId / finalizedUniqueInputDigest.
/// Same encoding as PrivateAuthGateway.linkDigest.
export function privateEnrollmentLinkDigest({ chainId, gateway, receiptId, uniqueInputDigest, cEnroll, idc, policyDigest, templateVersion }) {
  return keccak256(abi.encode(
    ["string", "uint256", "address", "bytes32", "bytes32", "uint256", "uint256", "uint256", "uint256"],
    ["BioBind/private-enrollment-link/v1", chainId, gateway, receiptId, uniqueInputDigest, cEnroll, idc, policyDigest, templateVersion]));
}

export function canonicalReceiptIds(r) {
  return {
    receiptId: keccak256(abi.encode(["string", "uint256", "address", "bytes32", "bytes32"],
      ["UBCA/BioZKFHE/receipt/v1", r.sourceChainId, r.sourceContract, r.sourceSessionId,
        r.finalizationDigest])),
    uniqueInputDigest: keccak256(abi.encode(
      ["string", "uint256", "address", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
      ["UBCA/BioZKFHE/input/v1", r.sourceChainId, r.sourceContract, r.sourceSessionId,
        r.sourceContextHash, r.gallerySnapshotHash, r.queryCiphertextDigest,
        r.enrollmentCiphertextDigest, r.modelHash, r.quantizationHash])),
  };
}

const requestHash = (q) => keccak256(abi.encode(
  ["bytes32", "bytes32", "uint256", "bytes32", "bytes32", "bytes32", "uint32", "address", "bytes32", "bytes32", "bytes32"],
  [q.receiptId, q.lineageId, q.cEnroll, q.policyHash, q.modelHash, q.quantizationHash,
    q.templateVersion, q.holder, q.deviceVersionId, q.uniqueInputDigest, q.enrollmentContext]));

export class EnrollmentBridge {
  #derivationKey; #sealKey; #counter; #rng;

  /// config: { derivationKey (ethers Wallet; = on-chain device signingKey),
  ///   deviceVersionId (on-chain composite version), mcu: { publicKey,
  ///   deviceVersionId, firmwareMeasurement, channelId, channelKey },
  ///   modelHash, quantizationHash, policyHash, policyDigest, scmv: {L,d,n,T,gamma} }
  constructor(config, { counter = new MonotonicCounter(), rng = randomBytes } = {}) {
    this.config = config;
    this.#derivationKey = config.derivationKey;
    this.#sealKey = randomBytes(32);
    this.#counter = counter;
    this.#rng = rng;
  }

  get address() { return this.#derivationKey.address; }

  initialize() { return this.#seal({ lastPacketCounter: "0", sessions: {} }); }

  #seal(state) {
    const version = this.#counter.increment();
    const iv = this.#rng(12);
    const cipher = createCipheriv("aes-256-gcm", this.#sealKey, iv);
    cipher.setAAD(Buffer.from(`UBCA/bridge-seal/v1/${version}`));
    const body = Buffer.concat([cipher.update(JSON.stringify(state)), cipher.final()]);
    return { version: version.toString(), iv: iv.toString("hex"), body: body.toString("hex"),
      tag: cipher.getAuthTag().toString("hex") };
  }

  #unseal(blob) {
    let state;
    try {
      const decipher = createDecipheriv("aes-256-gcm", this.#sealKey, Buffer.from(blob.iv, "hex"));
      decipher.setAAD(Buffer.from(`UBCA/bridge-seal/v1/${blob.version}`));
      decipher.setAuthTag(Buffer.from(blob.tag, "hex"));
      state = JSON.parse(Buffer.concat([decipher.update(Buffer.from(blob.body, "hex")),
        decipher.final()]).toString());
    } catch { fail("SEAL_INVALID"); }
    if (BigInt(blob.version) !== this.#counter.read()) fail("ROLLBACK_DETECTED", `blob ${blob.version} != counter ${this.#counter.read()}`);
    return state;
  }

  /// Phase 1. Host supplies the packet, the claimed session binding fields,
  /// and the BioZKFHE session-context preimage (including gallery count N).
  async prepareEnrollment(sealed, { packet, binding, sourceContext, now }) {
    const state = this.#unseal(sealed);
    const c = this.config;
    if (sourceContext.op !== SOURCE_OP_ENROLL) fail("NOT_ENROLL_OPERATION");
    if (!eq(sourceContext.sid, binding.sourceSessionId) || !eq(sourceContext.sourceContract, binding.sourceContract)
      || String(sourceContext.chainId) !== String(binding.sourceChainId)
      || !eq(sourceContextHash(sourceContext), binding.sourceContextHash)) fail("SOURCE_CONTEXT_MISMATCH");
    if (!eq(binding.policyHash, c.policyHash) || !eq(binding.modelHash, c.modelHash)
      || !eq(binding.quantizationHash, c.quantizationHash)) fail("PROFILE_MISMATCH");
    const key = binding.sourceSessionId.toLowerCase();
    if (state.sessions[key]) fail("SESSION_ALREADY_USED");

    let opened;
    try {
      opened = verifyAndOpenTrustedCapturePacket({ packet, channelKey: c.mcu.channelKey,
        signingPublicKey: c.mcu.publicKey, now, expected: {
          messageType: MESSAGE_ENROLL, deviceVersionId: c.mcu.deviceVersionId,
          firmwareMeasurement: c.mcu.firmwareMeasurement, modelHash: c.modelHash,
          quantizationHash: c.quantizationHash, policyHash: c.policyHash,
          sessionBinding: computeSessionBinding(binding), channelId: c.mcu.channelId,
          minimumCounter: BigInt(state.lastPacketCounter) } });
    } catch (error) {
      fail(/^sessionBinding /.test(error.message) ? "SESSION_BINDING_MISMATCH"
        : /stale/i.test(error.message) ? "STALE_CAPTURE_COUNTER" : "PACKET_INVALID", error.message);
    }
    const v = fromU16(opened.vector);
    if (v.length !== c.scmv.L || !inQuantizationProfile(v, c.scmv.gamma)) fail("VECTOR_OUT_OF_PROFILE");

    // Every downstream representation is derived from the same accepted v.
    const N = Number(sourceContext.galleryCount);
    const { Videntify, Venroll, h, k } = prepare(v, N, c.scmv);
    const hex32 = () => `0x${this.#rng(32).toString("hex")}`;
    const cIdentify = standInCiphertext("identify", Videntify, hex32());
    const cEnroll = standInCiphertext("enroll", Venroll, hex32());
    const rEnroll = (BigInt(hex32()) % BN254).toString();
    const enc = c.commitment ?? COMMITMENT_V1;
    const u = v.map((x) => x + enc.offset);
    const commit = enc.format === 2 ? poseidonCommitmentWide : poseidonCommitment;
    const cEnrollPoseidon = (await commit({ roleTag: DST_ENROLL, policyDigest: c.policyDigest,
      contextDigest: 0, dimension: u.length, salt: rEnroll, values: u, bits: enc.bits, packSize: enc.packSize })).toString();
    const statement = { chainId: sourceContext.chainId, sourceContract: sourceContext.sourceContract,
      sid: sourceContext.sid, sourceContextHash: binding.sourceContextHash, galleryCount: N,
      queryCiphertextDigest: cIdentify.digest, enrollmentCiphertextDigest: cEnroll.digest, h, k };
    const attestation = { galleryCount: N, h, k, signature: joinSignature(
      this.#derivationKey._signingKey().signDigest(enrollRequestDigest(statement))) };

    state.lastPacketCounter = opened.counter.toString();
    state.sessions[key] = { status: "Prepared", binding, galleryCount: N,
      packetDigest: opened.packetDigest, queryCiphertextDigest: cIdentify.digest,
      enrollmentCiphertextDigest: cEnroll.digest, gallerySnapshotHash: sourceContext.gallerySnapshotHash,
      cEnroll: cEnrollPoseidon, rEnrollDigest: createHash("sha256").update(rEnroll).digest("hex") };
    // Seal before releasing anything derived from the capture.
    return { sealed: this.#seal(state), cIdentify, cEnroll, attestation, cEnrollPoseidon,
      // P0: the holder-side prover receives the opening (not hidden from host).
      opening: { values: u.map(String), salt: rEnroll } };
  }

  /// Phase 2. receipt = adapter.previewFinalizedUniqueEnrollment(sid) (as read
  /// by the host); request = the UBCA IssueRequest the host intends to submit.
  signEnrollmentLink(sealed, { receipt, request, destination }) {
    const state = this.#unseal(sealed);
    const { p, b, ids } = this.#checkReceipt(state, receipt);
    const requestOk = eq(request.receiptId, ids.receiptId) && eq(request.uniqueInputDigest, ids.uniqueInputDigest)
      && String(request.cEnroll) === p.cEnroll && eq(request.lineageId, b.lineageId)
      && eq(request.holder, b.holder) && eq(request.enrollmentContext, b.enrollmentContext)
      && eq(request.policyHash, b.policyHash) && eq(request.modelHash, b.modelHash)
      && eq(request.quantizationHash, b.quantizationHash)
      && eq(request.deviceVersionId, this.config.deviceVersionId) && Number(request.templateVersion) >= 1
      && String(destination.chainId) === String(b.destinationChainId) && eq(destination.gateway, b.destinationGateway);
    if (!requestOk) fail("REQUEST_MISMATCH");

    const rh = requestHash(request);
    if (p.status === "Linked") {
      // Idempotent retry after a failed/unmined transaction; never a fork.
      if (p.requestHash !== rh) fail("SESSION_ALREADY_LINKED");
      return { sealed, signature: p.signature, retried: true };
    }
    const signature = joinSignature(this.#derivationKey._signingKey().signDigest(
      enrollmentLinkDigest(request, destination.chainId, destination.gateway)));
    Object.assign(p, { status: "Linked", requestHash: rh, signature });
    return { sealed: this.#seal(state), signature, retried: false };
  }

  /// Phase 2 for PrivateAuthGateway (dev-workspace/notes/unlinkability-design.md §2.1):
  /// signs (receipt, the bridge's own C_e, the holder's identity commitment idc,
  /// policy field digest, template version) for the destination gateway. The
  /// commitment comes from the sealed pending record, never from the host.
  signPrivateEnrollmentLink(sealed, { receipt, idc, policyDigest, destination, templateVersion = 1 }) {
    const state = this.#unseal(sealed);
    const { p, b, ids } = this.#checkReceipt(state, receipt);
    const idcValue = BigInt(idc);
    if (idcValue === 0n || idcValue >= BN254 || String(policyDigest) !== String(this.config.policyDigest)
      || String(destination.chainId) !== String(b.destinationChainId) || !eq(destination.gateway, b.destinationGateway)
      || Number(templateVersion) !== 1) fail("REQUEST_MISMATCH");
    const digest = privateEnrollmentLinkDigest({ chainId: destination.chainId, gateway: destination.gateway,
      receiptId: ids.receiptId, uniqueInputDigest: ids.uniqueInputDigest, cEnroll: p.cEnroll, idc: idcValue,
      policyDigest, templateVersion });
    if (p.status === "Linked") {
      if (p.requestHash !== digest) fail("SESSION_ALREADY_LINKED");
      return { sealed, signature: p.signature, cEnroll: p.cEnroll, retried: true };
    }
    const signature = joinSignature(this.#derivationKey._signingKey().signDigest(digest));
    Object.assign(p, { status: "Linked", requestHash: digest, signature });
    return { sealed: this.#seal(state), signature, cEnroll: p.cEnroll, retried: false };
  }

  #checkReceipt(state, receipt) {
    const sid = receipt.sourceSessionId;
    const p = state.sessions[sid.toLowerCase()];
    if (!p) fail("UNKNOWN_SESSION");
    if (p.status === "Aborted") fail("SESSION_NOT_LINKABLE");
    const b = p.binding;
    const ids = canonicalReceiptIds(receipt);
    const receiptOk = String(receipt.sourceChainId) === String(b.sourceChainId)
      && eq(receipt.sourceContract, b.sourceContract) && eq(sid, b.sourceSessionId)
      && eq(receipt.sourceContextHash, b.sourceContextHash)
      && eq(receipt.gallerySnapshotHash, p.gallerySnapshotHash)
      && eq(receipt.queryCiphertextDigest, p.queryCiphertextDigest)
      && eq(receipt.enrollmentCiphertextDigest, p.enrollmentCiphertextDigest)
      && eq(receipt.modelHash, b.modelHash) && eq(receipt.quantizationHash, b.quantizationHash)
      && !/^0x0+$/.test(receipt.finalizationDigest) && Number(receipt.finalizedAtBlock) > 0
      && eq(receipt.receiptId, ids.receiptId) && eq(receipt.uniqueInputDigest, ids.uniqueInputDigest);
    if (!receiptOk) fail("RECEIPT_MISMATCH");
    return { p, b, ids };
  }

  /// Host-requested abort (source rejected, expired, or stale slot). Only
  /// affects availability; an aborted session can never be linked again.
  abortEnrollment(sealed, { sourceSessionId, reason }) {
    const state = this.#unseal(sealed);
    const key = sourceSessionId.toLowerCase();
    const p = state.sessions[key];
    if (!p) fail("UNKNOWN_SESSION");
    if (p.status === "Linked") fail("SESSION_ALREADY_LINKED");
    state.sessions[key] = { status: "Aborted", reason, binding: p.binding };
    return { sealed: this.#seal(state) };
  }
}
