// Calldata encoding of IBioZKFHEFinalizationSource.FinalizedSession.
// Sources store only keccak256(abi.encode(record)); callers pass the record to
// the adapter (and through the gateway) as `bytes sourceRecord`.
import { ethers } from "ethers";

export const FINALIZED_SESSION_FIELDS = [
  ["uint8", "operation"],
  ["bool", "finalized"],
  ["bool", "uniquenessAccepted"],
  ["uint32", "expectedBlockCount"],
  ["uint32", "verifiedBlockCount"],
  ["uint32", "confirmationThreshold"],
  ["uint32", "confirmationCount"],
  ["bytes32", "sourceContextHash"],
  ["bytes32", "gallerySnapshotHash"],
  ["bytes32", "queryCiphertextDigest"],
  ["bytes32", "enrollmentCiphertextDigest"],
  ["bytes32", "verifiedOutputCollectionDigest"],
  ["bytes32", "modelHash"],
  ["bytes32", "quantizationHash"],
  ["uint64", "finalizedAtBlock"],
];
export const FINALIZED_SESSION_TYPE =
  `tuple(${FINALIZED_SESSION_FIELDS.map(([t, n]) => `${t} ${n}`).join(",")})`;

const ZERO_RECORD = Object.fromEntries(FINALIZED_SESSION_FIELDS.map(([t, n]) =>
  [n, t === "bool" ? false : t === "bytes32" ? ethers.constants.HashZero : 0]));

export function encodeFinalizedSession(record) {
  const plain = Object.fromEntries(FINALIZED_SESSION_FIELDS.map(([, n]) => [n, record[n]]));
  return ethers.utils.defaultAbiCoder.encode([FINALIZED_SESSION_TYPE], [plain]);
}

// Process-local memo of records written to a source, keyed by session id, so
// callers can supply the calldata record later. Unknown ids encode the zero
// record, which no source digest matches.
const memo = new Map();
export function rememberFinalized(sourceSessionId, record) {
  memo.set(String(sourceSessionId).toLowerCase(), record);
  return record;
}
export function finalizedRecordFor(sourceSessionId) {
  return encodeFinalizedSession(memo.get(String(sourceSessionId).toLowerCase()) ?? ZERO_RECORD);
}
