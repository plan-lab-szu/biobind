// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal same-chain view that a BioZKFHE deployment or extension
///         exposes after its existing proof, coverage, decryption, and
///         confirmation gates have completed.
/// @dev The source stores only keccak256(abi.encode(FinalizedSession)); the
///      record itself travels in calldata and consumers check it against this
///      digest. A finalized digest MUST be immutable. Operation value 1 means
///      enrollment and value 2 means login.
interface IBioZKFHEFinalizationSource {
    struct FinalizedSession {
        uint8 operation;
        bool finalized;
        bool uniquenessAccepted;
        uint32 expectedBlockCount;
        uint32 verifiedBlockCount;
        uint32 confirmationThreshold;
        uint32 confirmationCount;
        bytes32 sourceContextHash;
        bytes32 gallerySnapshotHash;
        bytes32 queryCiphertextDigest;
        bytes32 enrollmentCiphertextDigest;
        bytes32 verifiedOutputCollectionDigest;
        bytes32 modelHash;
        bytes32 quantizationHash;
        uint64 finalizedAtBlock;
    }

    /// @return digest keccak256(abi.encode(session)) of the finalized record,
    ///         or zero if the session has no finalized record.
    function finalizedSessionDigest(bytes32 sourceSessionId)
        external
        view
        returns (bytes32 digest);
}
