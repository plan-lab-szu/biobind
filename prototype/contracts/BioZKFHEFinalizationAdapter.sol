// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./interfaces/IBioZKFHEFinalizationSource.sol";
import "./interfaces/IBioZKFHEUniquenessAdapter.sol";

/// @notice Same-chain adapter from an immutable BioZKFHE finalized-session
///         view to UBCA's one-time uniqueness-receipt ABI.
/// @dev This contract does not re-run PVSC or threshold decryption. It verifies
///      that the configured BioZKFHE source contract has already crossed all
///      required terminal gates and derives every receipt digest itself.
contract BioZKFHEFinalizationAdapter is IBioZKFHEUniquenessAdapter {
    uint8 public constant ENROLL_OPERATION = 1;

    error Unauthorized();
    error InvalidConfiguration();
    error InvalidSourceSession();

    address public immutable owner;
    IBioZKFHEFinalizationSource public immutable source;
    address public authorizedConsumer;
    bool public consumerEverConfigured;
    bool public consumerActive;

    mapping(bytes32 sourceSessionId => bytes32 consumerBinding)
        public
        override
        consumedBy;

    event AuthorizedConsumerConfigured(address indexed consumer);
    event AuthorizedConsumerRevoked(address indexed consumer);
    event FinalizedSourceSessionConsumed(
        bytes32 indexed sourceSessionId,
        bytes32 indexed consumerBinding,
        bytes32 indexed receiptId
    );

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    constructor(address sourceAddress) {
        if (sourceAddress == address(0) || sourceAddress.code.length == 0) {
            revert InvalidConfiguration();
        }
        owner = msg.sender;
        source = IBioZKFHEFinalizationSource(sourceAddress);
    }

    function configureAuthorizedConsumer(address consumer) external onlyOwner {
        if (
            consumerEverConfigured ||
            consumer == address(0) ||
            consumer.code.length == 0
        ) revert InvalidConfiguration();
        authorizedConsumer = consumer;
        consumerEverConfigured = true;
        consumerActive = true;
        emit AuthorizedConsumerConfigured(consumer);
    }

    function revokeAuthorizedConsumer() external onlyOwner {
        if (!consumerActive) revert InvalidConfiguration();
        consumerActive = false;
        emit AuthorizedConsumerRevoked(authorizedConsumer);
    }

    function finalizationDigest(
        bytes32 sourceSessionId,
        IBioZKFHEFinalizationSource.FinalizedSession memory session
    ) public view returns (bytes32) {
        bytes32 gateDigest = keccak256(
            abi.encode(
                "BioZKFHE/finalization-gates/v1",
                session.operation,
                session.finalized,
                session.uniquenessAccepted,
                session.expectedBlockCount,
                session.verifiedBlockCount,
                session.confirmationThreshold,
                session.confirmationCount
            )
        );
        bytes32 transcriptDigest = keccak256(
            abi.encode(
                "BioZKFHE/finalization-transcript/v1",
                session.sourceContextHash,
                session.gallerySnapshotHash,
                session.queryCiphertextDigest,
                session.enrollmentCiphertextDigest,
                session.verifiedOutputCollectionDigest
            )
        );
        return
            keccak256(
                abi.encode(
                    "BioZKFHE/finalized-enrollment/v1",
                    block.chainid,
                    address(source),
                    sourceSessionId,
                    gateDigest,
                    transcriptDigest,
                    session.modelHash,
                    session.quantizationHash,
                    session.finalizedAtBlock
                )
            );
    }

    function consumeFinalizedUniqueEnrollment(
        bytes32 sourceSessionId,
        bytes32 consumerBinding,
        bytes calldata sourceRecord
    ) external returns (FinalizedUniqueEnrollment memory receipt) {
        if (msg.sender != authorizedConsumer || !consumerActive) {
            revert Unauthorized();
        }
        if (
            sourceSessionId == bytes32(0) ||
            consumerBinding == bytes32(0) ||
            consumedBy[sourceSessionId] != bytes32(0)
        ) revert InvalidSourceSession();

        receipt = _readValidatedReceipt(sourceSessionId, sourceRecord);
        consumedBy[sourceSessionId] = consumerBinding;
        emit FinalizedSourceSessionConsumed(
            sourceSessionId,
            consumerBinding,
            receipt.receiptId
        );
    }

    function previewFinalizedUniqueEnrollment(
        bytes32 sourceSessionId,
        bytes calldata sourceRecord
    ) external view returns (FinalizedUniqueEnrollment memory receipt) {
        receipt = _readValidatedReceipt(sourceSessionId, sourceRecord);
    }

    function _readValidatedReceipt(
        bytes32 sourceSessionId,
        bytes calldata sourceRecord
    ) internal view returns (FinalizedUniqueEnrollment memory receipt) {
        if (sourceSessionId == bytes32(0)) revert InvalidSourceSession();
        IBioZKFHEFinalizationSource.FinalizedSession memory session = abi.decode(
            sourceRecord,
            (IBioZKFHEFinalizationSource.FinalizedSession)
        );
        // Re-encode rather than hash the raw bytes, so a non-canonical encoding
        // of the same record cannot pass for a different one.
        bytes32 storedDigest = source.finalizedSessionDigest(sourceSessionId);
        if (storedDigest == bytes32(0) || storedDigest != keccak256(abi.encode(session))) {
            revert InvalidSourceSession();
        }
        if (
            session.operation != ENROLL_OPERATION ||
            !session.finalized ||
            !session.uniquenessAccepted ||
            session.expectedBlockCount == 0 ||
            session.verifiedBlockCount != session.expectedBlockCount ||
            session.confirmationThreshold == 0 ||
            session.confirmationCount < session.confirmationThreshold ||
            session.sourceContextHash == bytes32(0) ||
            session.gallerySnapshotHash == bytes32(0) ||
            session.queryCiphertextDigest == bytes32(0) ||
            session.enrollmentCiphertextDigest == bytes32(0) ||
            session.verifiedOutputCollectionDigest == bytes32(0) ||
            session.modelHash == bytes32(0) ||
            session.quantizationHash == bytes32(0) ||
            session.finalizedAtBlock == 0 ||
            session.finalizedAtBlock > block.number
        ) revert InvalidSourceSession();

        uint256 sourceChainId = block.chainid;
        bytes32 finalizedDigest = finalizationDigest(sourceSessionId, session);
        bytes32 receiptId = keccak256(
            abi.encode(
                "UBCA/BioZKFHE/receipt/v1",
                sourceChainId,
                address(source),
                sourceSessionId,
                finalizedDigest
            )
        );
        bytes32 uniqueInputDigest = keccak256(
            abi.encode(
                "UBCA/BioZKFHE/input/v1",
                sourceChainId,
                address(source),
                sourceSessionId,
                session.sourceContextHash,
                session.gallerySnapshotHash,
                session.queryCiphertextDigest,
                session.enrollmentCiphertextDigest,
                session.modelHash,
                session.quantizationHash
            )
        );

        receipt = FinalizedUniqueEnrollment({
            receiptId: receiptId,
            sourceChainId: sourceChainId,
            sourceContract: address(source),
            sourceSessionId: sourceSessionId,
            sourceContextHash: session.sourceContextHash,
            gallerySnapshotHash: session.gallerySnapshotHash,
            queryCiphertextDigest: session.queryCiphertextDigest,
            enrollmentCiphertextDigest: session.enrollmentCiphertextDigest,
            verifiedOutputCollectionDigest: session.verifiedOutputCollectionDigest,
            finalizationDigest: finalizedDigest,
            uniqueInputDigest: uniqueInputDigest,
            modelHash: session.modelHash,
            quantizationHash: session.quantizationHash,
            finalizedAtBlock: session.finalizedAtBlock
        });
    }
}
