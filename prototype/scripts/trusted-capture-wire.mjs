import {
  createCipheriv,
  createDecipheriv,
  createECDH,
  createHash,
  hkdfSync,
  sign,
  verify,
} from "node:crypto";

export const WIRE_VERSION = 1;
export const MESSAGE_ENROLL = 1;
export const MESSAGE_AUTHENTICATE = 2;
export const HEADER_BYTES = 268;
export const TAG_BYTES = 16;
export const SIGNATURE_BYTES = 64;
export const PACKET_OVERHEAD_BYTES =
  HEADER_BYTES + TAG_BYTES + SIGNATURE_BYTES;

const MAGIC = Buffer.from("UBCP", "ascii");
const SESSION_DOMAIN = Buffer.from("UBCA/session-binding/v1\0", "ascii");
const CHANNEL_DOMAIN = Buffer.from("UBCA/channel-key/v1\0", "ascii");
const NONCE_DOMAIN = Buffer.from("UBCA/aead-nonce/v1\0", "ascii");
const SIGNATURE_DOMAIN = Buffer.from("UBCA/MCU-packet-sign/v1\0", "ascii");

function fixedHex(value, length, name) {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]+$/.test(value)) {
    throw new Error(`${name} must be a hex string`);
  }
  const bytes = Buffer.from(value.slice(2), "hex");
  if (bytes.length !== length) {
    throw new Error(`${name} must be ${length} bytes`);
  }
  return bytes;
}

function unsigned(value, length, name) {
  const integer = BigInt(value);
  if (integer < 0n || integer >= 1n << BigInt(length * 8)) {
    throw new Error(`${name} is outside uint${length * 8}`);
  }
  const output = Buffer.alloc(length);
  for (let index = length - 1, remaining = integer; index >= 0; index -= 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}

function hex(bytes) {
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

function sha256(...parts) {
  const digest = createHash("sha256");
  for (const part of parts) digest.update(part);
  return digest.digest();
}

export function computeSessionBinding(context) {
  return hex(
    sha256(
      SESSION_DOMAIN,
      unsigned(context.sourceChainId, 32, "sourceChainId"),
      fixedHex(context.sourceContract, 20, "sourceContract"),
      fixedHex(context.sourceSessionId, 32, "sourceSessionId"),
      fixedHex(context.sourceContextHash, 32, "sourceContextHash"),
      unsigned(context.destinationChainId, 32, "destinationChainId"),
      fixedHex(context.destinationGateway, 20, "destinationGateway"),
      fixedHex(context.holder, 20, "holder"),
      fixedHex(context.lineageId, 32, "lineageId"),
      fixedHex(context.enrollmentContext, 32, "enrollmentContext"),
      fixedHex(context.policyHash, 32, "policyHash"),
      fixedHex(context.modelHash, 32, "modelHash"),
      fixedHex(context.quantizationHash, 32, "quantizationHash"),
    ),
  );
}

export function createP256ECDHKeyPair() {
  const ecdh = createECDH("prime256v1");
  ecdh.generateKeys();
  return {
    privateKey: ecdh.getPrivateKey(),
    publicKey: ecdh.getPublicKey(undefined, "uncompressed"),
  };
}

export function deriveP256SharedSecret(privateKey, peerPublicKey) {
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(privateKey);
  return ecdh.computeSecret(peerPublicKey);
}

export function deriveChannelKey(sharedSecret, channelId, sessionBinding) {
  return Buffer.from(
    hkdfSync(
      "sha256",
      sharedSecret,
      fixedHex(channelId, 32, "channelId"),
      Buffer.concat([
        CHANNEL_DOMAIN,
        fixedHex(sessionBinding, 32, "sessionBinding"),
      ]),
      32,
    ),
  );
}

export function derivePacketNonce(channelId, counter) {
  return sha256(
    NONCE_DOMAIN,
    fixedHex(channelId, 32, "channelId"),
    unsigned(counter, 8, "counter"),
  ).subarray(0, 12);
}

export function encodeQuantizedVector(values, coordinateBits = 16) {
  if (coordinateBits !== 16) {
    throw new Error("wire profile v1 supports only unsigned 16-bit coordinates");
  }
  if (!Array.isArray(values) || values.length === 0 || values.length > 65_535) {
    throw new Error("vector dimension must be in 1..65535");
  }
  const encoded = Buffer.alloc(values.length * 2);
  values.forEach((value, index) => {
    const coordinate = BigInt(value);
    if (coordinate < 0n || coordinate > 65_535n) {
      throw new Error(`coordinate ${index} is outside uint16`);
    }
    encoded.writeUInt16BE(Number(coordinate), index * 2);
  });
  return encoded;
}

export function decodeQuantizedVector(encoded, dimension, coordinateBits = 16) {
  if (coordinateBits !== 16 || encoded.length !== dimension * 2) {
    throw new Error("encoded vector length/profile mismatch");
  }
  return Array.from({ length: dimension }, (_, index) =>
    encoded.readUInt16BE(index * 2),
  );
}

function buildHeader({
  messageType,
  deviceVersionId,
  firmwareMeasurement,
  modelHash,
  quantizationHash,
  policyHash,
  sessionBinding,
  channelId,
  counter,
  notAfter,
  dimension,
  coordinateBits,
  ciphertextLength,
  nonce,
}) {
  if (![MESSAGE_ENROLL, MESSAGE_AUTHENTICATE].includes(messageType)) {
    throw new Error("unsupported message type");
  }
  if (dimension <= 0 || dimension > 65_535) {
    throw new Error("dimension is outside uint16 profile");
  }
  if (counter <= 0n) throw new Error("capture counter must be positive");
  if (nonce.length !== 12) throw new Error("AES-GCM nonce must be 12 bytes");

  const header = Buffer.alloc(HEADER_BYTES);
  let offset = 0;
  MAGIC.copy(header, offset);
  offset += 4;
  header.writeUInt16BE(WIRE_VERSION, offset);
  offset += 2;
  header.writeUInt8(messageType, offset++);
  header.writeUInt8(0, offset++);
  for (const [value, name] of [
    [deviceVersionId, "deviceVersionId"],
    [firmwareMeasurement, "firmwareMeasurement"],
    [modelHash, "modelHash"],
    [quantizationHash, "quantizationHash"],
    [policyHash, "policyHash"],
    [sessionBinding, "sessionBinding"],
    [channelId, "channelId"],
  ]) {
    fixedHex(value, 32, name).copy(header, offset);
    offset += 32;
  }
  unsigned(counter, 8, "counter").copy(header, offset);
  offset += 8;
  unsigned(notAfter, 8, "notAfter").copy(header, offset);
  offset += 8;
  header.writeUInt16BE(dimension, offset);
  offset += 2;
  header.writeUInt8(coordinateBits, offset++);
  header.writeUInt8(0, offset++);
  header.writeUInt32BE(ciphertextLength, offset);
  offset += 4;
  nonce.copy(header, offset);
  offset += 12;
  if (offset !== HEADER_BYTES) throw new Error("internal header size mismatch");
  return header;
}

export function createTrustedCapturePacket({
  messageType,
  metadata,
  vector,
  channelKey,
  signingPrivateKey,
  nonce,
}) {
  if (!Buffer.isBuffer(channelKey) || channelKey.length !== 32) {
    throw new Error("channelKey must be 32 bytes");
  }
  const coordinateBits = metadata.coordinateBits ?? 16;
  const packetNonce =
    nonce ?? derivePacketNonce(metadata.channelId, BigInt(metadata.counter));
  const plaintext = encodeQuantizedVector(vector, coordinateBits);
  const header = buildHeader({
    messageType,
    ...metadata,
    counter: BigInt(metadata.counter),
    notAfter: BigInt(metadata.notAfter),
    dimension: vector.length,
    coordinateBits,
    ciphertextLength: plaintext.length,
    nonce: packetNonce,
  });
  const cipher = createCipheriv("aes-256-gcm", channelKey, packetNonce);
  cipher.setAAD(header);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const signedTranscript = Buffer.concat([
    SIGNATURE_DOMAIN,
    header,
    ciphertext,
    tag,
  ]);
  const signature = sign("sha256", signedTranscript, {
    key: signingPrivateKey,
    dsaEncoding: "ieee-p1363",
  });
  if (signature.length !== SIGNATURE_BYTES) {
    throw new Error("unexpected P-256 signature length");
  }
  return Buffer.concat([header, ciphertext, tag, signature]);
}

function parseHeader(packet) {
  if (packet.length < PACKET_OVERHEAD_BYTES) throw new Error("packet is truncated");
  if (!packet.subarray(0, 4).equals(MAGIC)) throw new Error("invalid packet magic");
  if (packet.readUInt16BE(4) !== WIRE_VERSION) {
    throw new Error("unsupported packet version");
  }
  if (packet.readUInt8(7) !== 0 || packet.readUInt8(251) !== 0) {
    throw new Error("reserved packet bits are nonzero");
  }
  const messageType = packet.readUInt8(6);
  if (![MESSAGE_ENROLL, MESSAGE_AUTHENTICATE].includes(messageType)) {
    throw new Error("unsupported packet message type");
  }
  let offset = 8;
  const next32 = () => {
    const value = hex(packet.subarray(offset, offset + 32));
    offset += 32;
    return value;
  };
  const parsed = {
    messageType,
    deviceVersionId: next32(),
    firmwareMeasurement: next32(),
    modelHash: next32(),
    quantizationHash: next32(),
    policyHash: next32(),
    sessionBinding: next32(),
    channelId: next32(),
    counter: packet.readBigUInt64BE(offset),
  };
  offset += 8;
  parsed.notAfter = packet.readBigUInt64BE(offset);
  offset += 8;
  parsed.dimension = packet.readUInt16BE(offset);
  offset += 2;
  parsed.coordinateBits = packet.readUInt8(offset++);
  offset += 1;
  parsed.ciphertextLength = packet.readUInt32BE(offset);
  offset += 4;
  parsed.nonce = Buffer.from(packet.subarray(offset, offset + 12));
  const expectedLength =
    HEADER_BYTES + parsed.ciphertextLength + TAG_BYTES + SIGNATURE_BYTES;
  if (packet.length !== expectedLength) throw new Error("packet length mismatch");
  return parsed;
}

function requireExpected(actual, expected, name) {
  if (expected !== undefined && actual.toString().toLowerCase() !== expected.toString().toLowerCase()) {
    throw new Error(`${name} does not match expected session state`);
  }
}

export function verifyAndOpenTrustedCapturePacket({
  packet,
  channelKey,
  signingPublicKey,
  expected = {},
  now,
}) {
  const bytes = Buffer.from(packet);
  const parsed = parseHeader(bytes);
  requireExpected(parsed.messageType, expected.messageType, "messageType");
  for (const name of [
    "deviceVersionId",
    "firmwareMeasurement",
    "modelHash",
    "quantizationHash",
    "policyHash",
    "sessionBinding",
    "channelId",
  ]) {
    requireExpected(parsed[name], expected[name], name);
  }
  if (expected.minimumCounter !== undefined && parsed.counter <= BigInt(expected.minimumCounter)) {
    throw new Error("capture counter is stale");
  }
  if (now !== undefined && parsed.notAfter < BigInt(now)) {
    throw new Error("capture packet is expired");
  }

  const ciphertextStart = HEADER_BYTES;
  const ciphertextEnd = ciphertextStart + parsed.ciphertextLength;
  const ciphertext = bytes.subarray(ciphertextStart, ciphertextEnd);
  const tag = bytes.subarray(ciphertextEnd, ciphertextEnd + TAG_BYTES);
  const signature = bytes.subarray(ciphertextEnd + TAG_BYTES);
  const signedTranscript = Buffer.concat([
    SIGNATURE_DOMAIN,
    bytes.subarray(0, HEADER_BYTES),
    ciphertext,
    tag,
  ]);
  if (
    !verify(
      "sha256",
      signedTranscript,
      { key: signingPublicKey, dsaEncoding: "ieee-p1363" },
      signature,
    )
  ) {
    throw new Error("capture packet signature is invalid");
  }
  if (!Buffer.isBuffer(channelKey) || channelKey.length !== 32) {
    throw new Error("channelKey must be 32 bytes");
  }
  const decipher = createDecipheriv("aes-256-gcm", channelKey, parsed.nonce);
  decipher.setAAD(bytes.subarray(0, HEADER_BYTES));
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);
  const vector = decodeQuantizedVector(
    plaintext,
    parsed.dimension,
    parsed.coordinateBits,
  );
  return {
    ...parsed,
    vector,
    packetDigest: hex(sha256(bytes)),
  };
}
