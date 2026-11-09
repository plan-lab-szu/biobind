// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ICircuitVerifier {
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[5] calldata pubSignals
    ) external view returns (bool);
}

/// @notice Complete on-chain verifier for CircuitCheck with the same state handling as
///         HomomorphicCompleteVerifier: enrollment record, nonce check and update, and a
///         per-transaction digest chi = H(ctx || id || nonce) bound as a public input.
/// @dev Benchmark code; the Groth16 keys come from a local benchmark-only setup.
contract CircuitCompleteVerifier {
    uint256 internal constant R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    uint256 public immutable threshold;
    uint256 public immutable policyDigest;
    bytes32 public immutable ctxHash;
    ICircuitVerifier public immutable verifier;

    mapping(uint256 => uint256) public enrollmentCommitment;
    mapping(uint256 => uint256) public lastNonce;

    event Enrolled(uint256 indexed id);
    event Authenticated(uint256 indexed id, uint256 nonce);

    error AlreadyEnrolled();
    error NotEnrolled();
    error StaleNonce();
    error ProofRejected();

    constructor(uint256 tau, uint256 pol, uint256 n, ICircuitVerifier v) {
        threshold = tau;
        policyDigest = pol;
        verifier = v;
        ctxHash = keccak256(abi.encode("BioZero/circ/v1", block.chainid, address(this), n, tau, pol));
    }

    function enroll(uint256 id, uint256 gammaE) external {
        if (enrollmentCommitment[id] != 0) revert AlreadyEnrolled();
        enrollmentCommitment[id] = gammaE;
        emit Enrolled(id);
    }

    function digestOf(uint256 id, uint256 nonce) public view returns (uint256) {
        return uint256(keccak256(abi.encode(ctxHash, id, nonce))) % R;
    }

    function authenticate(
        uint256 id,
        uint256 nonce,
        uint256 gammaP,
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC
    ) external {
        uint256 gammaE = enrollmentCommitment[id];
        if (gammaE == 0) revert NotEnrolled();
        if (nonce <= lastNonce[id]) revert StaleNonce();
        uint256[5] memory pub = [gammaE, gammaP, policyDigest, digestOf(id, nonce), threshold];
        if (!verifier.verifyProof(pA, pB, pC, pub)) revert ProofRejected();
        lastNonce[id] = nonce;
        emit Authenticated(id, nonce);
    }
}
