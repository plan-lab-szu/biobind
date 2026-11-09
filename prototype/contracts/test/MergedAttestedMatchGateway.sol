// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../UBCAAuthGateway.sol";

/// @notice B1' comparison: the capture TCB itself performs the full-vector
///         match and signs ONE statement (capture fields + C_enroll + epsilon).
/// @dev Research comparison only. The device key is trusted to have read the
///      sensor, verified the holder-supplied opening of C_enroll, and checked
///      the distance against epsilon. C_probe is never published. Issuance,
///      challenge, lifecycle, and freshness are inherited unchanged. Deploy
///      with a non-contract verifier address so the inherited ZK entrypoint
///      cannot accept anything in this profile.
contract MergedAttestedMatchGateway is UBCAAuthGateway {
    bytes32 public constant ATTESTED_MATCH_TYPEHASH = keccak256(
        "UBCAAttestedMatch(uint256 cEnroll,uint256 ctxHash,bytes32 credentialId,bytes32 deviceVersionId,bytes32 policyHash,bytes32 modelHash,bytes32 quantizationHash,bytes32 firmwareMeasurement,uint64 registryEpochAtCapture,uint64 counter,uint64 notAfter,uint256 epsilon)"
    );
    bytes32 public immutable matchDomainSeparator;

    struct AttestedMatchStatement {
        uint256 cEnroll;
        uint256 ctxHash;
        bytes32 credentialId;
        bytes32 deviceVersionId;
        bytes32 policyHash;
        bytes32 modelHash;
        bytes32 quantizationHash;
        bytes32 firmwareMeasurement;
        uint64 registryEpochAtCapture;
        uint64 counter;
        uint64 notAfter;
        uint256 epsilon;
    }

    constructor(address disabledVerifier) UBCAAuthGateway(disabledVerifier) {
        // A distinct EIP-712 name keeps capture-only signatures from being
        // reinterpreted as match attestations, and vice versa.
        matchDomainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("UBCA Attested Match"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    function attestedMatchDigest(AttestedMatchStatement calldata statement)
        public
        view
        returns (bytes32)
    {
        return
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    matchDomainSeparator,
                    keccak256(abi.encode(ATTESTED_MATCH_TYPEHASH, statement))
                )
            );
    }

    function verifyAndConsumeAttestedMatch(
        UBCAAuthContext calldata context,
        AttestedMatchStatement calldata statement,
        bytes calldata signature
    ) external returns (bool) {
        if (msg.sender != context.beneficiary) revert Unauthorized();
        if (block.timestamp > context.deadline) revert AuthChallengeExpired();

        bytes32 encodedContextHash = _hashAuthContext(context);
        if (pendingAuthContexts[context.nonce] != encodedContextHash) {
            revert InvalidAuthContext();
        }
        uint256 ctxHash = uint256(encodedContextHash) % SNARK_SCALAR_FIELD;

        Credential storage credential = credentials[context.credentialId];
        DeviceVersion storage device = deviceVersions[context.deviceVersionId];
        if (
            credential.holder != context.beneficiary ||
            !isAuthenticationStateActive(
                context.credentialId,
                context.deviceVersionId
            ) ||
            statement.cEnroll != credential.cEnroll ||
            !policyMatchThresholdConfigured[credential.policyHash] ||
            statement.epsilon != policyMatchThresholds[credential.policyHash]
        ) revert InvalidAuthCredential();

        if (
            statement.ctxHash != ctxHash ||
            statement.credentialId != context.credentialId ||
            statement.deviceVersionId != context.deviceVersionId ||
            statement.policyHash != credential.policyHash ||
            statement.modelHash != credential.modelHash ||
            statement.quantizationHash != credential.quantizationHash ||
            statement.firmwareMeasurement != device.firmwareMeasurement ||
            statement.registryEpochAtCapture < context.registryEpochAtIssue ||
            statement.registryEpochAtCapture > registryEpoch ||
            block.timestamp > statement.notAfter ||
            statement.notAfter > context.deadline ||
            statement.counter <= lastCaptureCounters[context.deviceVersionId]
        ) revert InvalidCaptureStatement();
        if (
            _recoverCapture(attestedMatchDigest(statement), signature) !=
            device.signingKey
        ) revert InvalidCaptureStatement();

        delete pendingAuthContexts[context.nonce];
        lastCaptureCounters[context.deviceVersionId] = statement.counter;
        emit UBCAAuthenticationAccepted(
            context.beneficiary,
            context.credentialId,
            context.nonce,
            context.deviceVersionId,
            context.action,
            statement.registryEpochAtCapture,
            statement.counter
        );
        return true;
    }
}
