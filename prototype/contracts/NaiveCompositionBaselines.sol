// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./interfaces/IBioZKFHEUniquenessAdapter.sol";

interface INaiveCompositionVerifier {
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[5] calldata publicSignals
    ) external view returns (bool);
}

/// @notice Locally evaluated composition pattern that consumes a sound
///         uniqueness result but lets the applicant independently choose the
///         authentication commitment.
/// @dev The omission is subtle: receipt authenticity and one-time use are
///      enforced, but there is no same-input enrollment linkage. This contract
///      represents no named paper or deployed service.
contract BooleanReceiptEnrollmentBaseline {
    struct Credential {
        bytes32 receiptId;
        bytes32 uniqueInputDigest;
        uint256 cEnroll;
        uint256 policyDigest;
        address holder;
        bool active;
    }

    error InvalidState();
    error InvalidProof();

    INaiveCompositionVerifier public immutable verifier;
    IBioZKFHEUniquenessAdapter public immutable uniquenessAdapter;
    mapping(bytes32 credentialId => Credential) public credentials;
    mapping(bytes32 nullifier => bool) public usedNullifiers;

    constructor(address verifierAddress, address adapterAddress) {
        if (
            verifierAddress == address(0) ||
            adapterAddress == address(0) ||
            adapterAddress.code.length == 0
        ) revert InvalidState();
        verifier = INaiveCompositionVerifier(verifierAddress);
        uniquenessAdapter = IBioZKFHEUniquenessAdapter(adapterAddress);
    }

    function issueFromUniqueReceipt(
        bytes32 sourceSessionId,
        bytes calldata sourceRecord,
        bytes32 credentialId,
        uint256 applicantChosenEnrollmentCommitment,
        uint256 policyDigest,
        address holder
    ) external {
        if (
            credentialId == bytes32(0) ||
            holder == address(0) ||
            credentials[credentialId].active
        ) revert InvalidState();
        bytes32 consumerBinding = keccak256(
            abi.encode(
                "NAIVE/unique-receipt-consumer/v1",
                block.chainid,
                address(this),
                credentialId,
                holder
            )
        );
        IBioZKFHEUniquenessAdapter.FinalizedUniqueEnrollment memory receipt =
            uniquenessAdapter.consumeFinalizedUniqueEnrollment(
                sourceSessionId,
                consumerBinding,
                sourceRecord
            );
        credentials[credentialId] = Credential(
            receipt.receiptId,
            receipt.uniqueInputDigest,
            applicantChosenEnrollmentCommitment,
            policyDigest,
            holder,
            true
        );
    }

    function authenticate(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[5] calldata publicSignals,
        bytes32 credentialId,
        bytes32 nullifier
    ) external returns (bool) {
        Credential storage credential = credentials[credentialId];
        if (
            !credential.active ||
            credential.holder != msg.sender ||
            credential.cEnroll != publicSignals[0] ||
            credential.policyDigest != publicSignals[2] ||
            usedNullifiers[nullifier]
        ) revert InvalidState();
        if (!verifier.verifyProof(pA, pB, pC, publicSignals)) {
            revert InvalidProof();
        }
        usedNullifiers[nullifier] = true;
        return true;
    }
}

/// @notice Locally evaluated time-of-check/time-of-use composition pattern.
///         Eligibility is cached while active, but submission verifies only
///         the cached authorization rather than current live state.
/// @dev It represents no named paper or deployed service.
contract HistoricalAuthorizationBaseline {
    struct Credential {
        uint256 cEnroll;
        uint256 policyDigest;
        address holder;
        bool active;
    }

    struct CachedAuthorization {
        uint256 cEnroll;
        uint256 policyDigest;
        uint256 ctxHash;
        address holder;
        bool exists;
        bool consumed;
    }

    error Unauthorized();
    error InvalidState();
    error InvalidProof();

    address public immutable owner;
    INaiveCompositionVerifier public immutable verifier;
    mapping(bytes32 credentialId => Credential) public credentials;
    mapping(bytes32 authorizationId => CachedAuthorization) public authorizations;

    constructor(address verifierAddress) {
        if (verifierAddress == address(0)) revert InvalidState();
        owner = msg.sender;
        verifier = INaiveCompositionVerifier(verifierAddress);
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    function configureCredential(
        bytes32 credentialId,
        uint256 cEnroll,
        uint256 policyDigest,
        address holder
    ) external onlyOwner {
        if (credentialId == bytes32(0) || holder == address(0)) {
            revert InvalidState();
        }
        credentials[credentialId] = Credential(
            cEnroll,
            policyDigest,
            holder,
            true
        );
    }

    function cacheAuthorization(
        bytes32 authorizationId,
        bytes32 credentialId,
        uint256 ctxHash
    ) external {
        Credential storage credential = credentials[credentialId];
        if (
            !credential.active ||
            credential.holder != msg.sender ||
            authorizationId == bytes32(0) ||
            authorizations[authorizationId].exists
        ) revert InvalidState();
        authorizations[authorizationId] = CachedAuthorization(
            credential.cEnroll,
            credential.policyDigest,
            ctxHash,
            msg.sender,
            true,
            false
        );
    }

    function revokeCredential(bytes32 credentialId) external onlyOwner {
        Credential storage credential = credentials[credentialId];
        if (!credential.active) revert InvalidState();
        credential.active = false;
    }

    function authenticateFromCachedAuthorization(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[5] calldata publicSignals,
        bytes32 authorizationId
    ) external returns (bool) {
        CachedAuthorization storage authorization = authorizations[authorizationId];
        if (
            !authorization.exists ||
            authorization.consumed ||
            authorization.holder != msg.sender ||
            authorization.cEnroll != publicSignals[0] ||
            authorization.policyDigest != publicSignals[2] ||
            authorization.ctxHash != publicSignals[3]
        ) revert InvalidState();
        if (!verifier.verifyProof(pA, pB, pC, publicSignals)) {
            revert InvalidProof();
        }
        authorization.consumed = true;
        return true;
    }
}
