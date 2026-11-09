// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./interfaces/IBioZKFHEUniquenessAdapter.sol";
import "./PoseidonMerkleTree.sol";

interface IPoseidon5 {
    function poseidon(uint256[5] calldata inputs) external pure returns (uint256);
}

interface IPrivateAuthVerifier {
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[9] calldata pubSignals
    ) external view returns (bool);
}

/// @notice Unlinkable authentication gateway (dev-workspace/notes/unlinkability-design.md).
/// @dev Issuance publicly consumes one finalized uniqueness receipt and, in the
///      same transaction, inserts the credential leaf
///      Poseidon(4, C_e, idc, policyDigest, templateVersion) into the credential
///      tree; the enrollment station's link signature covers idc. Authentication
///      names no credential and no device: the circuit proves membership in both
///      trees and verifies the device's capture signature. Revocation zeroes the
///      leaf and invalidates every earlier root. Benchmark code; never deploy.
contract PrivateAuthGateway {
    uint256 internal constant R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant DST_LEAF = 4;

    struct Policy {
        uint256 epsilon;
        bool active;
    }

    struct Challenge {
        address beneficiary;
        uint256 policyDigest;
        uint256 scope;
        bool oneTime;
        uint64 deadline;
    }

    struct Credential {
        uint256 leaf;
        uint64 index;
        bool active;
    }

    error Unauthorized();
    error InvalidRequest();
    error InvalidLink();
    error InvalidChallenge();
    error InvalidRoot();
    error InvalidStatement();
    error NullifierUsed();
    error ProofRejected();

    event CredentialIssued(bytes32 indexed receiptId, uint64 index, uint256 leaf);
    event CredentialRevoked(uint64 indexed index);
    event DeviceRegistered(
        uint64 indexed index,
        uint256 leaf,
        uint256 ax,
        uint256 ay,
        uint256 firmware,
        uint256 model,
        uint256 quantization,
        uint256 policyDigest
    );
    event DeviceRevoked(uint64 indexed index);
    event ChallengeIssued(bytes32 indexed nonce, address beneficiary, uint256 policyDigest, uint256 scope, bool oneTime, uint64 deadline);
    event Authenticated(bytes32 indexed nonce, uint256 scope, uint256 nullifier);

    address public immutable owner;
    IBioZKFHEUniquenessAdapter public immutable adapter;
    IPrivateAuthVerifier public immutable verifier;
    IPoseidon5 public immutable poseidon5;
    PoseidonMerkleTree public credentialTree;
    PoseidonMerkleTree public deviceTree;

    mapping(address => bool) public isEnrollmentStation;
    mapping(uint256 policyDigest => Policy) public policies;
    mapping(bytes32 receiptId => Credential) public credentials;
    mapping(uint64 index => uint256) public deviceLeaves;
    mapping(bytes32 nonce => Challenge) public challenges;
    mapping(uint256 nullifier => bool) public usedNullifiers;
    uint256 private challengeCounter;

    constructor(
        IBioZKFHEUniquenessAdapter uniquenessAdapter,
        IPrivateAuthVerifier proofVerifier,
        IPoseidon5 p5,
        uint8 credentialDepth,
        uint8 deviceDepth,
        uint64 rootHistory
    ) {
        owner = msg.sender;
        adapter = uniquenessAdapter;
        verifier = proofVerifier;
        poseidon5 = p5;
        credentialTree = new PoseidonMerkleTree(credentialDepth, rootHistory, address(this));
        deviceTree = new PoseidonMerkleTree(deviceDepth, rootHistory, address(this));
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    // ------------------------------------------------------------ registry

    function registerEnrollmentStation(address station) external onlyOwner {
        isEnrollmentStation[station] = true;
    }

    function registerPolicy(uint256 policyDigest, uint256 epsilon) external onlyOwner {
        if (policyDigest == 0 || policyDigest >= R || policies[policyDigest].active) revert InvalidRequest();
        policies[policyDigest] = Policy(epsilon, true);
    }

    /// @param leaf Poseidon(DST_DEV, ax, ay, firmware, model, quantization, policyDigest),
    ///        computed off chain by the device-certification authority (the owner):
    ///        the circomlibjs generator cannot emit a 7-input Poseidon contract
    ///        (EVM stack depth), so the chain does not recompute it. The fields are
    ///        emitted so anyone can check the leaf off chain.
    function registerDevice(
        uint256 leaf,
        uint256 ax,
        uint256 ay,
        uint256 firmware,
        uint256 model,
        uint256 quantization,
        uint256 policyDigest
    ) external onlyOwner returns (uint64 index) {
        if (!policies[policyDigest].active || leaf == 0 || leaf >= R) revert InvalidRequest();
        index = uint64(deviceTree.insert(leaf));
        deviceLeaves[index] = leaf;
        emit DeviceRegistered(index, leaf, ax, ay, firmware, model, quantization, policyDigest);
    }

    function revokeDevice(uint64 index, uint256[] calldata siblings) external onlyOwner {
        uint256 leaf = deviceLeaves[index];
        if (leaf == 0) revert InvalidRequest();
        deviceTree.zero(index, leaf, siblings);
        deviceLeaves[index] = 0;
        emit DeviceRevoked(index);
    }

    // ------------------------------------------------------------ issuance

    function linkDigest(
        bytes32 receiptId,
        bytes32 uniqueInputDigest,
        uint256 cEnroll,
        uint256 idc,
        uint256 policyDigest,
        uint256 templateVersion
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                "BioBind/private-enrollment-link/v1",
                block.chainid,
                address(this),
                receiptId,
                uniqueInputDigest,
                cEnroll,
                idc,
                policyDigest,
                templateVersion
            )
        );
    }

    /// @notice Atomically consumes one finalized uniqueness receipt and inserts
    ///         the credential leaf. The station's link signature covers idc.
    function issue(
        bytes32 sourceSessionId,
        bytes calldata sourceRecord,
        uint256 cEnroll,
        uint256 idc,
        uint256 policyDigest,
        bytes calldata stationSignature
    ) external returns (uint64 index) {
        if (!policies[policyDigest].active || cEnroll == 0 || cEnroll >= R || idc == 0 || idc >= R) {
            revert InvalidRequest();
        }
        bytes32 binding = keccak256(abi.encode("BioBind/private-consumer/v1", block.chainid, address(this), idc));
        IBioZKFHEUniquenessAdapter.FinalizedUniqueEnrollment memory receipt =
            adapter.consumeFinalizedUniqueEnrollment(sourceSessionId, binding, sourceRecord);
        bytes32 digest = linkDigest(receipt.receiptId, receipt.uniqueInputDigest, cEnroll, idc, policyDigest, 1);
        if (!isEnrollmentStation[_recover(digest, stationSignature)]) revert InvalidLink();
        if (credentials[receipt.receiptId].leaf != 0) revert InvalidRequest();

        uint256 leaf = poseidon5.poseidon([DST_LEAF, cEnroll, idc, policyDigest, 1]);
        index = uint64(credentialTree.insert(leaf));
        credentials[receipt.receiptId] = Credential(leaf, index, true);
        emit CredentialIssued(receipt.receiptId, index, leaf);
    }

    function revokeCredential(bytes32 receiptId, uint256[] calldata siblings) external onlyOwner {
        Credential storage c = credentials[receiptId];
        if (!c.active) revert InvalidRequest();
        credentialTree.zero(c.index, c.leaf, siblings);
        c.active = false;
        emit CredentialRevoked(c.index);
    }

    // ------------------------------------------------------------ authentication

    function scopeFor(bytes32 appId, bytes32 action, bool oneTime) public pure returns (uint256) {
        return oneTime
            ? uint256(keccak256(abi.encode("BioBind/scope/action/v1", appId, action))) % R
            : uint256(keccak256(abi.encode("BioBind/scope/app/v1", appId))) % R;
    }

    function ctxHashOf(bytes32 nonce) public view returns (uint256) {
        Challenge storage c = challenges[nonce];
        return uint256(
            keccak256(
                abi.encode(
                    "BioBind/private-challenge/v1",
                    block.chainid,
                    address(this),
                    nonce,
                    c.beneficiary,
                    c.policyDigest,
                    c.scope,
                    c.oneTime,
                    c.deadline
                )
            )
        ) % R;
    }

    /// @param beneficiary one-time address that must submit the proof
    function issueChallenge(
        address beneficiary,
        uint256 policyDigest,
        bytes32 appId,
        bytes32 action,
        bool oneTime,
        uint64 deadline
    ) external returns (bytes32 nonce) {
        if (beneficiary == address(0) || !policies[policyDigest].active || deadline <= block.timestamp) {
            revert InvalidChallenge();
        }
        nonce = keccak256(abi.encode("BioBind/private-nonce/v1", address(this), ++challengeCounter));
        uint256 scope = scopeFor(appId, action, oneTime);
        challenges[nonce] = Challenge(beneficiary, policyDigest, scope, oneTime, deadline);
        emit ChallengeIssued(nonce, beneficiary, policyDigest, scope, oneTime, deadline);
    }

    /// @param pub [credRoot, devRoot, cProbe, policyDigest, ctxHash, epsilon, notAfter, scope, nullifier]
    function authenticate(
        bytes32 nonce,
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[9] calldata pub
    ) external {
        Challenge storage c = challenges[nonce];
        if (c.beneficiary == address(0) || msg.sender != c.beneficiary || block.timestamp > c.deadline) {
            revert InvalidChallenge();
        }
        if (!credentialTree.isValidRoot(pub[0]) || !deviceTree.isValidRoot(pub[1])) revert InvalidRoot();
        Policy storage p = policies[c.policyDigest];
        if (
            !p.active ||
            pub[3] != c.policyDigest ||
            pub[4] != ctxHashOf(nonce) ||
            pub[5] != p.epsilon ||
            pub[6] < block.timestamp ||
            pub[6] > c.deadline ||
            pub[7] != c.scope
        ) revert InvalidStatement();
        if (c.oneTime) {
            if (usedNullifiers[pub[8]]) revert NullifierUsed();
            usedNullifiers[pub[8]] = true;
        }
        if (!verifier.verifyProof(pA, pB, pC, pub)) revert ProofRejected();
        emit Authenticated(nonce, pub[7], pub[8]);
        delete challenges[nonce];
    }

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) return address(0);
        return ecrecover(digest, v, r, s);
    }
}
