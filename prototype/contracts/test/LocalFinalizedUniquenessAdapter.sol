// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../interfaces/IBioZKFHEUniquenessAdapter.sol";

/// @notice Deterministic local test double for the proposed BioZKFHE adapter.
/// @dev Not a production finalization verifier. It is used only on local test
///      chains to exercise atomic cross-contract consumption and rollback.
contract LocalFinalizedUniquenessAdapter is IBioZKFHEUniquenessAdapter {
    error Unauthorized();
    error InvalidConfiguration();
    error InvalidSourceSession();

    address public immutable owner;
    address public authorizedConsumer;
    mapping(bytes32 sourceSessionId => FinalizedUniqueEnrollment) private receipts;
    mapping(bytes32 sourceSessionId => bytes32 consumerBinding) public override consumedBy;

    event LocalFinalizedSessionRecorded(bytes32 indexed sourceSessionId);
    event AuthorizedConsumerConfigured(address indexed consumer);
    event LocalSourceSessionConsumed(
        bytes32 indexed sourceSessionId,
        bytes32 indexed consumerBinding
    );

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function configureAuthorizedConsumer(address consumer) external onlyOwner {
        if (
            authorizedConsumer != address(0) ||
            consumer == address(0) ||
            consumer.code.length == 0
        ) revert InvalidConfiguration();
        authorizedConsumer = consumer;
        emit AuthorizedConsumerConfigured(consumer);
    }

    function recordLocalFinalizedUniqueEnrollment(
        FinalizedUniqueEnrollment calldata receipt
    ) external onlyOwner {
        if (
            receipt.receiptId == bytes32(0) ||
            receipt.sourceSessionId == bytes32(0) ||
            receipts[receipt.sourceSessionId].receiptId != bytes32(0)
        ) revert InvalidConfiguration();
        receipts[receipt.sourceSessionId] = receipt;
        emit LocalFinalizedSessionRecorded(receipt.sourceSessionId);
    }

    function consumeFinalizedUniqueEnrollment(
        bytes32 sourceSessionId,
        bytes32 consumerBinding,
        bytes calldata
    ) external returns (FinalizedUniqueEnrollment memory receipt) {
        if (msg.sender != authorizedConsumer) revert Unauthorized();
        if (
            consumerBinding == bytes32(0) ||
            consumedBy[sourceSessionId] != bytes32(0) ||
            receipts[sourceSessionId].receiptId == bytes32(0)
        ) revert InvalidSourceSession();
        consumedBy[sourceSessionId] = consumerBinding;
        receipt = receipts[sourceSessionId];
        emit LocalSourceSessionConsumed(sourceSessionId, consumerBinding);
    }

    function previewFinalizedUniqueEnrollment(bytes32 sourceSessionId, bytes calldata)
        external
        view
        returns (FinalizedUniqueEnrollment memory receipt)
    {
        receipt = receipts[sourceSessionId];
        if (receipt.receiptId == bytes32(0)) revert InvalidSourceSession();
    }
}
