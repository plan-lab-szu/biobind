import { buildPoseidon } from "circomlibjs";

export const FORMAT_VERSION = 1n;
export const DST_ENROLL = 1n;
export const DST_PROBE = 2n;
export const DEFAULT_BITS = 16;
export const DEFAULT_PACK_SIZE = 15;

let poseidonPromise;

export function getPoseidon() {
  poseidonPromise ??= buildPoseidon();
  return poseidonPromise;
}

export function packCoordinates(values, bits = DEFAULT_BITS, packSize = DEFAULT_PACK_SIZE) {
  if (!Number.isInteger(bits) || bits <= 0) {
    throw new Error("bits must be a positive integer");
  }
  if (!Number.isInteger(packSize) || packSize <= 0 || bits * packSize > 240) {
    throw new Error("packSize must keep packed blocks at or below 240 bits");
  }

  const limit = 1n << BigInt(bits);
  const coordinates = values.map((value) => BigInt(value));
  const blocks = [];

  for (let start = 0; start < coordinates.length; start += packSize) {
    let packed = 0n;
    for (let offset = 0; offset < packSize; offset += 1) {
      const coordinate = coordinates[start + offset] ?? 0n;
      if (coordinate < 0n || coordinate >= limit) {
        throw new Error(`coordinate ${start + offset} is outside ${bits}-bit range`);
      }
      packed += coordinate << BigInt(bits * offset);
    }
    blocks.push(packed);
  }

  if (blocks.length % 2 !== 0) {
    blocks.push(0n);
  }
  return blocks;
}

export async function poseidonCommitment({
  roleTag,
  policyDigest,
  contextDigest,
  dimension,
  salt,
  values,
  bits = DEFAULT_BITS,
  packSize = DEFAULT_PACK_SIZE,
}) {
  if (values.length !== Number(dimension)) {
    throw new Error("dimension does not match coordinate count");
  }

  const poseidon = await getPoseidon();
  const field = poseidon.F;
  const blocks = packCoordinates(values, bits, packSize);

  let chain = poseidon([
    BigInt(roleTag),
    FORMAT_VERSION,
    BigInt(policyDigest),
    BigInt(contextDigest),
    BigInt(dimension),
    BigInt(salt),
  ]);

  for (let i = 0; i < blocks.length; i += 2) {
    chain = poseidon([chain, blocks[i], blocks[i + 1]]);
  }

  return BigInt(field.toObject(chain));
}

/// Commitment format v2 (circuits/auth_private_v2.circom PoseidonWideCommitment):
/// same header and packing as v1 with FORMAT_VERSION = 2, but the chain absorbs
/// 15 packed blocks per Poseidon(16) call; the last chunk is zero-padded and the
/// block list is not padded to an even length.
export async function poseidonCommitmentWide({
  roleTag,
  policyDigest,
  contextDigest,
  dimension,
  salt,
  values,
  bits = DEFAULT_BITS,
  packSize = DEFAULT_PACK_SIZE,
}) {
  if (values.length !== Number(dimension)) {
    throw new Error("dimension does not match coordinate count");
  }
  const poseidon = await getPoseidon();
  const field = poseidon.F;
  const blocks = packCoordinates(values, bits, packSize).slice(0, Math.ceil(values.length / packSize));
  let chain = poseidon([BigInt(roleTag), 2n, BigInt(policyDigest), BigInt(contextDigest), BigInt(dimension), BigInt(salt)]);
  for (let i = 0; i < blocks.length; i += 15) {
    const chunk = blocks.slice(i, i + 15);
    while (chunk.length < 15) chunk.push(0n);
    chain = poseidon([chain, ...chunk]);
  }
  return BigInt(field.toObject(chain));
}

export function squaredDistance(left, right) {
  if (left.length !== right.length) {
    throw new Error("vectors must have the same dimension");
  }
  return left.reduce((sum, value, index) => {
    const difference = BigInt(value) - BigInt(right[index]);
    return sum + difference * difference;
  }, 0n);
}

