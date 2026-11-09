// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IBaselineGroth16Verifier {
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[5] calldata publicSignals
    ) external view returns (bool);
}

/// @notice Deliberately incomplete local comparison baseline.
/// @dev This contract is not a production service or a representation of a
///      named third-party system. It exists only for authorized defensive
///      evaluation on an in-process Ganache chain. It validates a registered
///      enrollment commitment, a Groth16 proof, the caller, policy, and a
///      one-time nullifier, but deliberately omits an authenticated source for
///      the private probe witness.
contract ProvenanceOmissionBaseline {
    struct Credential {
        uint256 cEnroll;
        uint256 policyDigest;
        address holder;
        bool active;
    }

    error Unauthorized();
    error InvalidConfiguration();
    error InvalidCredential();
    error Replay();
    error InvalidProof();

    address public immutable owner;
    IBaselineGroth16Verifier public immutable verifier;
    mapping(bytes32 credentialId => Credential) public credentials;
    mapping(bytes32 nullifier => bool) public usedNullifiers;

    event BaselineAuthenticationAccepted(
        bytes32 indexed credentialId,
        address indexed holder,
        bytes32 indexed nullifier
    );

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    constructor(address verifierAddress) {
        if (verifierAddress == address(0)) revert InvalidConfiguration();
        owner = msg.sender;
        verifier = IBaselineGroth16Verifier(verifierAddress);
    }

    function configureCredential(
        bytes32 credentialId,
        uint256 cEnroll,
        uint256 policyDigest,
        address holder
    ) external onlyOwner {
        if (credentialId == bytes32(0) || holder == address(0)) {
            revert InvalidConfiguration();
        }
        credentials[credentialId] = Credential(
            cEnroll,
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
            credential.policyDigest != publicSignals[2]
        ) revert InvalidCredential();
        if (usedNullifiers[nullifier]) revert Replay();
        if (!verifier.verifyProof(pA, pB, pC, publicSignals)) {
            revert InvalidProof();
        }
        usedNullifiers[nullifier] = true;
        emit BaselineAuthenticationAccepted(credentialId, msg.sender, nullifier);
        return true;
    }
}
