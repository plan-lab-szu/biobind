import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import { ethers } from "ethers";

import {
  HEADER_BYTES,
  MESSAGE_ENROLL,
  PACKET_OVERHEAD_BYTES,
  computeSessionBinding,
  createP256ECDHKeyPair,
  createTrustedCapturePacket,
  deriveChannelKey,
  derivePacketNonce,
  deriveP256SharedSecret,
  verifyAndOpenTrustedCapturePacket,
} from "../scripts/trusted-capture-wire.mjs";

function hash(label) {
  return ethers.utils.keccak256(ethers.utils.toUtf8Bytes(label));
}

function address(label) {
  return `0x${hash(label).slice(-40)}`;
}

function fixture(dimension = 128) {
  const sessionContext = {
    sourceChainId: 31_337,
    sourceContract: address("source-contract"),
    sourceSessionId: hash("source-session"),
    sourceContextHash: hash("source-context"),
    destinationChainId: 31_337,
    destinationGateway: address("destination-gateway"),
    holder: address("holder"),
    lineageId: hash("lineage"),
    enrollmentContext: hash("enrollment-context"),
    policyHash: hash("policy"),
    modelHash: hash("model"),
    quantizationHash: hash("quantization"),
  };
  const sessionBinding = computeSessionBinding(sessionContext);
  const channelId = hash("attested-channel");
  const deviceECDH = createP256ECDHKeyPair();
  const teeECDH = createP256ECDHKeyPair();
  const deviceShared = deriveP256SharedSecret(
    deviceECDH.privateKey,
    teeECDH.publicKey,
  );
  const teeShared = deriveP256SharedSecret(
    teeECDH.privateKey,
    deviceECDH.publicKey,
  );
  assert.deepEqual(deviceShared, teeShared);
  const channelKey = deriveChannelKey(deviceShared, channelId, sessionBinding);
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const vector = Array.from(
    { length: dimension },
    (_, index) => (10_000 + index * 257) % 65_536,
  );
  const metadata = {
    deviceVersionId: hash("device-version"),
    firmwareMeasurement: hash("mcu-firmware"),
    modelHash: sessionContext.modelHash,
    quantizationHash: sessionContext.quantizationHash,
    policyHash: sessionContext.policyHash,
    sessionBinding,
    channelId,
    counter: 7n,
    notAfter: 2_000_000_000n,
    coordinateBits: 16,
  };
  const packet = createTrustedCapturePacket({
    messageType: MESSAGE_ENROLL,
    metadata,
    vector,
    channelKey,
    signingPrivateKey: privateKey,
    nonce: Buffer.alloc(12, 0x5a),
  });
  return {
    sessionContext,
    metadata,
    vector,
    packet,
    channelKey,
    publicKey,
    deviceECDH,
    teeECDH,
  };
}

test("128D and 512D packets round-trip with fixed, auditable overhead", () => {
  for (const dimension of [128, 512]) {
    const state = fixture(dimension);
    const opened = verifyAndOpenTrustedCapturePacket({
      packet: state.packet,
      channelKey: state.channelKey,
      signingPublicKey: state.publicKey,
      expected: {
        messageType: MESSAGE_ENROLL,
        ...state.metadata,
        minimumCounter: 6n,
      },
      now: 1_900_000_000n,
    });
    assert.deepEqual(opened.vector, state.vector);
    assert.equal(state.packet.length, dimension * 2 + PACKET_OVERHEAD_BYTES);
  }
  assert.equal(HEADER_BYTES, 268);
  assert.equal(PACKET_OVERHEAD_BYTES, 348);
});

test("untrusted transport cannot alter encrypted vector or authenticated metadata", () => {
  const state = fixture();
  for (const offset of [20, HEADER_BYTES + 9]) {
    const modified = Buffer.from(state.packet);
    modified[offset] ^= 0x01;
    assert.throws(
      () =>
        verifyAndOpenTrustedCapturePacket({
          packet: modified,
          channelKey: state.channelKey,
          signingPublicKey: state.publicKey,
        }),
      /signature|expected session state/,
    );
  }
});

test("session transplantation, stale counters, and expiry are rejected", () => {
  const state = fixture();
  assert.throws(
    () =>
      verifyAndOpenTrustedCapturePacket({
        packet: state.packet,
        channelKey: state.channelKey,
        signingPublicKey: state.publicKey,
        expected: { sessionBinding: hash("other-session") },
      }),
    /sessionBinding/,
  );
  assert.throws(
    () =>
      verifyAndOpenTrustedCapturePacket({
        packet: state.packet,
        channelKey: state.channelKey,
        signingPublicKey: state.publicKey,
        expected: { minimumCounter: 7n },
      }),
    /counter is stale/,
  );
  assert.throws(
    () =>
      verifyAndOpenTrustedCapturePacket({
        packet: state.packet,
        channelKey: state.channelKey,
        signingPublicKey: state.publicKey,
        now: 2_000_000_001n,
      }),
    /expired/,
  );
});

test("a different attested TEE channel cannot decrypt the packet", () => {
  const state = fixture();
  const otherTEE = createP256ECDHKeyPair();
  const wrongShared = deriveP256SharedSecret(
    otherTEE.privateKey,
    state.deviceECDH.publicKey,
  );
  const wrongKey = deriveChannelKey(
    wrongShared,
    state.metadata.channelId,
    state.metadata.sessionBinding,
  );
  assert.throws(
    () =>
      verifyAndOpenTrustedCapturePacket({
        packet: state.packet,
        channelKey: wrongKey,
        signingPublicKey: state.publicKey,
      }),
    /authenticate data|bad decrypt|Unsupported state/i,
  );
});

test("wire profile rejects invalid dimensions and coordinates before signing", () => {
  const state = fixture();
  assert.throws(
    () =>
      createTrustedCapturePacket({
        messageType: MESSAGE_ENROLL,
        metadata: state.metadata,
        vector: [65_536],
        channelKey: state.channelKey,
        signingPrivateKey: generateKeyPairSync("ec", {
          namedCurve: "prime256v1",
        }).privateKey,
      }),
    /outside uint16/,
  );
});

test("AEAD nonce is domain-derived from channel identity and monotonic counter", () => {
  const channelId = hash("nonce-channel");
  assert.deepEqual(
    derivePacketNonce(channelId, 1n),
    derivePacketNonce(channelId, 1n),
  );
  assert.notDeepEqual(
    derivePacketNonce(channelId, 1n),
    derivePacketNonce(channelId, 2n),
  );
  assert.equal(derivePacketNonce(channelId, 1n).length, 12);
});
