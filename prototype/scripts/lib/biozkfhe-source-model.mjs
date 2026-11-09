// Off-chain model of a BioZKFHE enrollment session at the SCMV plaintext level.
//
// mode "paper": Algorithm 1 as published. The request binds
//   h_id = H(ctx || C_identify) only; uniqueness is decided on C_identify;
//   SCMV.Update merges whatever C_enroll the client supplied. The paper states
//   an honest-client assumption, so these semantics are correct in its model.
// mode "bound": proposed minimal source-side change for UBCA composition.
//   A registered enrollment bridge attests (declared N, both ciphertext
//   digests, slot); the source binds both digests at request time, requires
//   declared N == current N, and aborts the update if N moved before
//   finalization (stale slot), so the client must retry with a new session.
//
// Ciphertexts are transparent stand-ins {rows, digest}; PVSC, committee
// decryption, and gas are not modelled.

import { ethers } from "ethers";
import { ScmvGallery, SOURCE_OP_ENROLL } from "./scmv-model.mjs";

const { keccak256, defaultAbiCoder: abi, recoverAddress } = ethers.utils;

export function sourceContextHash(ctx) {
  return keccak256(abi.encode(
    ["string", "uint256", "address", "bytes32", "uint8", "uint64", "bytes32", "bytes32"],
    ["BioZKFHE/session-context/v1", ctx.chainId, ctx.sourceContract, ctx.sid, ctx.op,
      ctx.galleryCount, ctx.gallerySnapshotHash, ctx.ledgerMetaHash]));
}

/// Transparent ciphertext stand-in. The digest covers role, rows, and fresh
/// encryption randomness, mirroring a hash over real BGV ciphertext bytes.
export function standInCiphertext(role, rows, randomness) {
  const ct = { role, rows, randomness };
  return { ...ct, digest: ciphertextDigest(ct) };
}

export function ciphertextDigest({ role, rows, randomness }) {
  return keccak256(abi.encode(["string", "string", "string", "bytes32"],
    ["UBCA/stand-in-ciphertext/v1", role,
      JSON.stringify(rows, (_, x) => typeof x === "bigint" ? x.toString() : x), randomness]));
}

export function enrollRequestDigest(r) {
  return keccak256(abi.encode(
    ["string", "uint256", "address", "bytes32", "bytes32", "uint64", "bytes32", "bytes32", "uint16", "uint16"],
    ["UBCA/BioZKFHE/enroll-request/v1", r.chainId, r.sourceContract, r.sid, r.sourceContextHash,
      r.galleryCount, r.queryCiphertextDigest, r.enrollmentCiphertextDigest, r.h, r.k]));
}

export class BioZKFHESourceModel {
  constructor({ mode, params, chainId, sourceContract, registeredBridges = [], tau }) {
    this.mode = mode;
    this.gallery = new ScmvGallery(params);
    this.chainId = chainId;
    this.sourceContract = sourceContract;
    this.registeredBridges = new Set(registeredBridges.map((a) => a.toLowerCase()));
    this.tau = tau; // duplicate iff some recovered similarity >= tau
    this.sessions = new Map();
    this.counter = 0;
  }

  snapshotHash() {
    return keccak256(abi.encode(["string", "uint64", "string"],
      ["BioZKFHE/gallery-snapshot/v1", this.gallery.N,
        JSON.stringify(this.gallery.blocks, (_, x) => typeof x === "bigint" ? x.toString() : x)]));
  }

  createSession(op = SOURCE_OP_ENROLL) {
    const sid = keccak256(abi.encode(["string", "string", "address", "uint256"],
      ["BioZKFHE/sid/v1", this.mode, this.sourceContract, ++this.counter]));
    const ctx = { chainId: this.chainId, sourceContract: this.sourceContract, sid, op,
      galleryCount: this.gallery.N, gallerySnapshotHash: this.snapshotHash(),
      ledgerMetaHash: keccak256(abi.encode(["string", "uint256"], ["ledger", this.counter])) };
    const record = { ctx, contextHash: sourceContextHash(ctx), status: "Created" };
    this.sessions.set(sid, record);
    return { ctx, contextHash: record.contextHash };
  }

  bindRequest(sid, { cIdentify, cEnroll, attestation }) {
    const s = this.sessions.get(sid);
    if (!s || s.status !== "Created") throw new Error("SourceSessionNotOpen");
    // The source hashes what it receives; caller-supplied digests are ignored.
    cIdentify = { ...cIdentify, digest: ciphertextDigest(cIdentify) };
    cEnroll = { ...cEnroll, digest: ciphertextDigest(cEnroll) };
    if (cIdentify.role !== "identify" || cEnroll.role !== "enroll") throw new Error("CiphertextRole");
    if (this.mode === "bound") {
      const a = attestation;
      if (!a) throw new Error("MissingBridgeAttestation");
      const statement = { chainId: this.chainId, sourceContract: this.sourceContract, sid,
        sourceContextHash: s.contextHash, galleryCount: s.ctx.galleryCount,
        queryCiphertextDigest: cIdentify.digest, enrollmentCiphertextDigest: cEnroll.digest,
        h: a.h, k: a.k };
      const signer = recoverAddress(enrollRequestDigest(statement), a.signature);
      if (!this.registeredBridges.has(signer.toLowerCase())) throw new Error("UnregisteredBridge");
      if (a.galleryCount !== s.ctx.galleryCount || a.galleryCount !== this.gallery.N) {
        throw new Error("DeclaredGalleryCountMismatch");
      }
      s.declared = a;
    }
    s.hId = keccak256(abi.encode(["bytes32", "bytes32"], [s.contextHash, cIdentify.digest]));
    s.cIdentify = cIdentify;
    s.cEnroll = cEnroll;
    s.status = "Bound";
  }

  /// Coverage, PVSC, and t-of-n confirmation are assumed to succeed honestly.
  finalize(sid, { finalizedAtBlock = 1 } = {}) {
    const s = this.sessions.get(sid);
    if (!s || s.status !== "Bound") throw new Error("SourceSessionNotBound");
    const scores = this.gallery.identify(s.cIdentify.rows);
    const maxScore = scores.reduce((m, x) => (x > m ? x : m), -(1n << 200n));
    s.uniquenessAccepted = scores.every((x) => x < this.tau);
    s.maxScore = scores.length ? maxScore : null;
    if (s.uniquenessAccepted && this.mode === "bound" && this.gallery.N !== s.declared.galleryCount) {
      s.status = "AbortedStaleSlot";
      return s;
    }
    if (s.uniquenessAccepted) this.gallery.update(s.cEnroll.rows);
    s.status = "Finalized";
    s.finalizedAtBlock = finalizedAtBlock;
    return s;
  }

  /// Shape expected by LocalBioZKFHEFinalizationSource.recordImmutableSession.
  finalizedSessionStruct(sid, { modelHash, quantizationHash, finalizedAtBlock }) {
    const s = this.sessions.get(sid);
    return {
      operation: SOURCE_OP_ENROLL, finalized: s.status === "Finalized",
      uniquenessAccepted: Boolean(s.uniquenessAccepted),
      expectedBlockCount: Math.max(1, this.gallery.blocks.length),
      verifiedBlockCount: Math.max(1, this.gallery.blocks.length),
      confirmationThreshold: 3, confirmationCount: 3,
      sourceContextHash: s.contextHash, gallerySnapshotHash: s.ctx.gallerySnapshotHash,
      queryCiphertextDigest: s.cIdentify.digest, enrollmentCiphertextDigest: s.cEnroll.digest,
      verifiedOutputCollectionDigest: keccak256(abi.encode(["string", "bytes32"], ["outputs", s.hId])),
      modelHash, quantizationHash, finalizedAtBlock,
    };
  }
}
