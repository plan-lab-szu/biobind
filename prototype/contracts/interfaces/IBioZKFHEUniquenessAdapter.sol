// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Proposed cross-paper ABI; the accepted BioZKFHE paper does not
///         currently standardize this interface.
/// @dev A conforming adapter MUST authorize its UBCA consumer, accept only a
///      finalized `enroll` session whose threshold-confirmed decision is
///      unique, and atomically make each source session consumable once.
interface IBioZKFHEUniquenessAdapter {
    struct FinalizedUniqueEnrollment {
        bytes32 receiptId;
        uint256 sourceChainId;
        address sourceContract;
        bytes32 sourceSessionId;
        bytes32 sourceContextHash;
        bytes32 gallerySnapshotHash;
        bytes32 queryCiphertextDigest;
        bytes32 enrollmentCiphertextDigest;
        bytes32 verifiedOutputCollectionDigest;
        bytes32 finalizationDigest;
        bytes32 uniqueInputDigest;
        bytes32 modelHash;
        bytes32 quantizationHash;
        uint64 finalizedAtBlock;
    }

    /// @notice Derives the canonical receipt without consuming the source
    ///         session. A TEE/prover uses this view to construct the
    ///         enrollment-link statement. Issuance MUST still call the
    ///         consuming method, which revalidates current terminal state.
    /// @param sourceRecord Source-specific finalized record (calldata); the
    ///        adapter checks it against the digest the source stores.
    function previewFinalizedUniqueEnrollment(
        bytes32 sourceSessionId,
        bytes calldata sourceRecord
    ) external view returns (FinalizedUniqueEnrollment memory receipt);

    /// @param sourceSessionId Finalized BioZKFHE enrollment session.
    /// @param consumerBinding Domain-separated binding to the destination
    ///        chain, UBCA gateway, lineage, and holder.
    /// @return receipt A canonical receipt. `uniqueInputDigest` must bind both
    ///         query and conditional-enrollment ciphertext digests; it does not
    ///         by itself prove their plaintext equals the UBCA commitment.
    function consumeFinalizedUniqueEnrollment(
        bytes32 sourceSessionId,
        bytes32 consumerBinding,
        bytes calldata sourceRecord
    ) external returns (FinalizedUniqueEnrollment memory receipt);

    function consumedBy(bytes32 sourceSessionId)
        external
        view
        returns (bytes32 consumerBinding);
}
