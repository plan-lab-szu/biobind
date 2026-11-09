// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../interfaces/IBioZKFHEFinalizationSource.sol";

/// @notice Local immutable-state fixture for adapter conformance tests.
/// @dev It deliberately permits malformed records so rejection branches can
///      be tested. It is not a BioZKFHE proof or committee implementation.
contract LocalBioZKFHEFinalizationSource is IBioZKFHEFinalizationSource {
    error Unauthorized();
    error InvalidConfiguration();

    address public immutable owner;
    mapping(bytes32 sourceSessionId => bool) public exists;
    mapping(bytes32 sourceSessionId => bytes32) private sessionDigests;

    constructor() {
        owner = msg.sender;
    }

    function recordImmutableSession(
        bytes32 sourceSessionId,
        FinalizedSession calldata session
    ) external {
        if (msg.sender != owner) revert Unauthorized();
        if (sourceSessionId == bytes32(0) || exists[sourceSessionId]) {
            revert InvalidConfiguration();
        }
        exists[sourceSessionId] = true;
        sessionDigests[sourceSessionId] = keccak256(abi.encode(session));
    }

    function finalizedSessionDigest(bytes32 sourceSessionId) external view returns (bytes32) {
        return sessionDigests[sourceSessionId];
    }
}
