// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./UBCALifecycle.sol";
import "./interfaces/IBioZKFHEUniquenessAdapter.sol";

interface IUBCAGroth16Verifier {
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[5] calldata publicSignals
    ) external view returns (bool);
}

/// @notice Integrated research gateway for uniqueness-bound capture authentication.
/// @dev The production profile permanently disables the inherited owner receipt
///      recorder and consumes finalized source sessions through the configured
///      adapter. The source finalization verifier and capture signing key remain
///      local test doubles until their real deployments are evaluated.
contract UBCAAuthGateway is UBCALifecycle {
    uint256 public constant MAX_AUTH_CHALLENGE_TTL = 15 minutes;

    bytes32 public constant AUTH_CONTEXT_TYPEHASH = keccak256(
        "UBCAAuthContext(address beneficiary,bytes32 action,uint256 chainId,address gateway,bytes32 credentialId,bytes32 deviceVersionId,uint64 registryEpochAtIssue,bytes32 nonce,uint64 deadline)"
    );
    bytes32 public constant CAPTURE_STATEMENT_TYPEHASH = keccak256(
        "UBCACapture(uint256 cProbe,uint256 ctxHash,bytes32 credentialId,bytes32 deviceVersionId,bytes32 policyHash,bytes32 modelHash,bytes32 quantizationHash,bytes32 firmwareMeasurement,uint64 registryEpochAtCapture,uint64 counter,uint64 notAfter)"
    );
    bytes32 private constant CAPTURE_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant CAPTURE_NAME_HASH = keccak256("UBCA Capture");
    bytes32 private constant CAPTURE_VERSION_HASH = keccak256("1");
    uint256 private constant CAPTURE_SECP256K1_HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    struct UBCAAuthContext {
        address beneficiary;
        bytes32 action;
        bytes32 credentialId;
        bytes32 deviceVersionId;
        uint64 registryEpochAtIssue;
        bytes32 nonce;
        uint64 deadline;
    }

    struct UBCACaptureStatement {
        uint256 cProbe;
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
    }

    /// @notice One immutable application-scoped policy preimage.
    /// @dev The active verifier's runtime code hash, chain and gateway address
    ///      are also included by canonicalPolicyHash(). Metric 1 is squared
    ///      Euclidean distance; format 1 is the current Poseidon header.
    struct CanonicalPolicySpec {
        bytes32 applicationId;
        bytes32 modelHash;
        bytes32 preprocessingHash;
        bytes32 quantizationHash;
        bytes32 circuitHash;
        bytes32 budgetPolicyHash;
        uint32 dimension;
        uint16 coordinateBits;
        uint32 quantizedMax;
        uint8 metricId;
        uint8 commitmentFormatVersion;
        uint8 distanceBits;
        uint256 epsilon;
    }

    error InvalidVerifier();
    error InvalidAuthContext();
    error AuthChallengeExpired();
    error InvalidAuthCredential();
    error InvalidCaptureStatement();
    error InvalidAuthProof();
    error InvalidUniquenessAdapter();
    error InvalidFinalizedReceipt();
    error ReceiptIssuanceReentrancy();
    error InvalidMatchPolicy();

    IUBCAGroth16Verifier public immutable authVerifier;
    bytes32 public immutable captureDomainSeparator;
    IBioZKFHEUniquenessAdapter public uniquenessAdapter;
    bool public uniquenessAdapterEverConfigured;
    bool public uniquenessAdapterActive;
    uint256 private receiptIssuanceLock;

    mapping(address beneficiary => uint256 counter) public authChallengeCounters;
    mapping(bytes32 nonce => bytes32 contextHash) public pendingAuthContexts;
    mapping(bytes32 deviceVersionId => uint64 counter) public lastCaptureCounters;
    mapping(bytes32 policyHash => uint256 epsilon) public policyMatchThresholds;
    mapping(bytes32 policyHash => bool configured) public policyMatchThresholdConfigured;
    mapping(bytes32 policyHash => bool registered) public canonicalPolicyRegistered;
    mapping(bytes32 policyHash => CanonicalPolicySpec spec) public canonicalPolicySpecs;

    event CanonicalPolicyRegistered(
        bytes32 indexed policyHash,
        bytes32 indexed applicationId,
        bytes32 circuitHash,
        bytes32 verifierCodeHash
    );

    event MatchThresholdConfigured(bytes32 indexed policyHash, uint256 epsilon);

    event UBCAAuthChallengeIssued(
        address indexed beneficiary,
        bytes32 indexed credentialId,
        bytes32 indexed nonce,
        bytes32 deviceVersionId,
        uint256 ctxHash,
        uint64 registryEpochAtIssue,
        uint64 deadline
    );
    event UBCAAuthenticationAccepted(
        address indexed beneficiary,
        bytes32 indexed credentialId,
        bytes32 indexed nonce,
        bytes32 deviceVersionId,
        bytes32 action,
        uint64 registryEpochAtCapture,
        uint64 captureCounter
    );
    event UBCAAuthChallengeCancelled(bytes32 indexed nonce, address indexed cleaner);
    event UniquenessAdapterConfigured(address indexed adapter);
    event UniquenessAdapterRevoked(address indexed adapter);
    event FinalizedUniquenessReceiptIssued(
        bytes32 indexed sourceSessionId,
        bytes32 indexed receiptId,
        bytes32 indexed credentialId,
        bytes32 consumerBinding
    );
    event FinalizedUniquenessReceiptReplacedTemplate(
        bytes32 indexed sourceSessionId,
        bytes32 indexed oldCredentialId,
        bytes32 indexed newCredentialId,
        bytes32 receiptId,
        bytes32 consumerBinding
    );

    constructor(address verifierAddress) {
        if (verifierAddress == address(0)) revert InvalidVerifier();
        authVerifier = IUBCAGroth16Verifier(verifierAddress);
        captureDomainSeparator = keccak256(
            abi.encode(
                CAPTURE_DOMAIN_TYPEHASH,
                CAPTURE_NAME_HASH,
                CAPTURE_VERSION_HASH,
                block.chainid,
                address(this)
            )
        );
    }

    /// @notice Collision-resistant mapping from the lifecycle policy identifier
    ///         into the BN254 scalar field used by the circuit.
    function policyFieldDigest(bytes32 policyHash) public pure returns (uint256) {
        return
            uint256(keccak256(abi.encode("UBCA/policy-field/v1", policyHash))) %
            SNARK_SCALAR_FIELD;
    }

    function canonicalPolicyHash(CanonicalPolicySpec calldata spec)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(
            "BioZERO/policy/v1",
            block.chainid,
            address(this),
            address(authVerifier).codehash,
            spec
        ));
    }

    function registerCanonicalPolicy(CanonicalPolicySpec calldata spec)
        external
        onlyOwner
        returns (bytes32 policyHash)
    {
        _validateCanonicalPolicy(spec);
        policyHash = canonicalPolicyHash(spec);
        _registerPolicy(policyHash);
        _storeCanonicalPolicy(policyHash, spec);
    }

    function replaceCanonicalPolicy(
        bytes32 oldPolicyHash,
        CanonicalPolicySpec calldata spec
    ) external onlyOwner returns (bytes32 newPolicyHash) {
        if (!canonicalPolicyRegistered[oldPolicyHash]) revert InvalidMatchPolicy();
        _validateCanonicalPolicy(spec);
        newPolicyHash = canonicalPolicyHash(spec);
        _replacePolicy(oldPolicyHash, newPolicyHash);
        _storeCanonicalPolicy(newPolicyHash, spec);
    }

    function _validateCanonicalPolicy(CanonicalPolicySpec calldata spec)
        internal
        view
        virtual
    {
        if (
            spec.applicationId == bytes32(0) ||
            spec.modelHash == bytes32(0) ||
            spec.preprocessingHash == bytes32(0) ||
            spec.quantizationHash == bytes32(0) ||
            spec.circuitHash == bytes32(0) ||
            spec.budgetPolicyHash == bytes32(0) ||
            (spec.dimension != 128 && spec.dimension != 512) ||
            spec.coordinateBits != 16 ||
            spec.quantizedMax != 65535 ||
            spec.metricId != 1 ||
            spec.commitmentFormatVersion != 1 ||
            spec.distanceBits != 48 ||
            spec.epsilon >= (uint256(1) << 48)
        ) revert InvalidMatchPolicy();
    }

    function _storeCanonicalPolicy(
        bytes32 policyHash,
        CanonicalPolicySpec calldata spec
    ) internal {
        canonicalPolicyRegistered[policyHash] = true;
        canonicalPolicySpecs[policyHash] = spec;
        policyMatchThresholds[policyHash] = spec.epsilon;
        policyMatchThresholdConfigured[policyHash] = true;
        emit MatchThresholdConfigured(policyHash, spec.epsilon);
        emit CanonicalPolicyRegistered(
            policyHash,
            spec.applicationId,
            spec.circuitHash,
            address(authVerifier).codehash
        );
    }

    /// @notice Bind a policy identifier to its immutable squared-distance limit.
    /// @dev Both current 128D/512D circuits constrain epsilon to 48 bits.
    ///      Changing this limit requires a new policy identifier and lifecycle
    ///      transition; a public proof input is not an authorized policy value.
    function configureMatchThreshold(bytes32 policyHash, uint256 epsilon)
        external
        onlyOwner
    {
        if (
            policies[policyHash].status != Status.Active ||
            policyMatchThresholdConfigured[policyHash] ||
            epsilon >= (uint256(1) << 48)
        ) revert InvalidMatchPolicy();
        policyMatchThresholds[policyHash] = epsilon;
        policyMatchThresholdConfigured[policyHash] = true;
        emit MatchThresholdConfigured(policyHash, epsilon);
    }

    function configureUniquenessAdapter(address adapterAddress) external onlyOwner {
        if (
            uniquenessAdapterEverConfigured ||
            adapterAddress == address(0) ||
            adapterAddress.code.length == 0
        ) revert InvalidUniquenessAdapter();
        uniquenessAdapter = IBioZKFHEUniquenessAdapter(adapterAddress);
        uniquenessAdapterEverConfigured = true;
        uniquenessAdapterActive = true;
        emit UniquenessAdapterConfigured(adapterAddress);
    }

    function revokeUniquenessAdapter() external onlyOwner {
        if (!uniquenessAdapterActive) revert InvalidUniquenessAdapter();
        uniquenessAdapterActive = false;
        emit UniquenessAdapterRevoked(address(uniquenessAdapter));
    }

    function receiptConsumerBinding(bytes32 lineageId, address holder)
        public
        view
        returns (bytes32)
    {
        return
            keccak256(
                abi.encode(
                    "UBCA/receipt-consumer/v1",
                    block.chainid,
                    address(this),
                    lineageId,
                    holder
                )
            );
    }

    function finalizedReceiptId(
        uint256 sourceChainId,
        address sourceContract,
        bytes32 sourceSessionId,
        bytes32 finalizationDigest
    ) public pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    "UBCA/BioZKFHE/receipt/v1",
                    sourceChainId,
                    sourceContract,
                    sourceSessionId,
                    finalizationDigest
                )
            );
    }

    function finalizedUniqueInputDigest(
        IBioZKFHEUniquenessAdapter.FinalizedUniqueEnrollment calldata receipt
    ) public pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    "UBCA/BioZKFHE/input/v1",
                    receipt.sourceChainId,
                    receipt.sourceContract,
                    receipt.sourceSessionId,
                    receipt.sourceContextHash,
                    receipt.gallerySnapshotHash,
                    receipt.queryCiphertextDigest,
                    receipt.enrollmentCiphertextDigest,
                    receipt.modelHash,
                    receipt.quantizationHash
                )
            );
    }

    /// @notice Atomically consumes one finalized BioZKFHE source session and
    ///         creates its destination UBCA credential.
    function issueFromFinalizedBioZKFHESession(
        bytes32 sourceSessionId,
        bytes calldata sourceRecord,
        IssueRequest calldata request,
        bytes calldata enrollmentLinkSignature
    ) external returns (bytes32 credentialId) {
        if (
            lineageEverIssued[request.lineageId] ||
            activeCredentialByLineage[request.lineageId] != bytes32(0)
        ) revert InvalidTransition();

        (bytes32 receiptId, bytes32 consumerBinding) =
            _consumeAndRecordFinalizedReceipt(sourceSessionId, sourceRecord, request);
        credentialId = _issue(request, 1, enrollmentLinkSignature);
        receiptIssuanceLock = 0;
        emit FinalizedUniquenessReceiptIssued(
            sourceSessionId,
            receiptId,
            credentialId,
            consumerBinding
        );
    }

    /// @notice Atomically consumes a new finalized BioZKFHE source session,
    ///         issues the next template version, and supersedes the old one.
    function replaceTemplateFromFinalizedBioZKFHESession(
        bytes32 oldCredentialId,
        bytes32 sourceSessionId,
        bytes calldata sourceRecord,
        IssueRequest calldata request,
        bytes calldata enrollmentLinkSignature
    ) external returns (bytes32 newCredentialId) {
        Credential storage oldCredential = credentials[oldCredentialId];
        if (
            oldCredential.status != Status.Active ||
            activeCredentialByLineage[oldCredential.lineageId] != oldCredentialId ||
            request.lineageId != oldCredential.lineageId ||
            request.templateVersion != oldCredential.templateVersion + 1 ||
            request.cEnroll == oldCredential.cEnroll ||
            request.holder != oldCredential.holder
        ) revert InvalidTransition();

        (bytes32 receiptId, bytes32 consumerBinding) =
            _consumeAndRecordFinalizedReceipt(sourceSessionId, sourceRecord, request);
        newCredentialId = _issue(
            request,
            oldCredential.credentialVersion + 1,
            enrollmentLinkSignature
        );
        _supersede(oldCredentialId, newCredentialId);
        receiptIssuanceLock = 0;
        emit FinalizedUniquenessReceiptReplacedTemplate(
            sourceSessionId,
            oldCredentialId,
            newCredentialId,
            receiptId,
            consumerBinding
        );
    }

    function _consumeAndRecordFinalizedReceipt(
        bytes32 sourceSessionId,
        bytes calldata sourceRecord,
        IssueRequest calldata request
    ) internal returns (bytes32 receiptId, bytes32 consumerBinding) {
        if (receiptIssuanceLock != 0) revert ReceiptIssuanceReentrancy();
        if (!uniquenessAdapterActive) revert InvalidUniquenessAdapter();

        receiptIssuanceLock = 1;
        consumerBinding = receiptConsumerBinding(request.lineageId, request.holder);
        IBioZKFHEUniquenessAdapter.FinalizedUniqueEnrollment memory receipt =
            uniquenessAdapter.consumeFinalizedUniqueEnrollment(
                sourceSessionId,
                consumerBinding,
                sourceRecord
            );

        bytes32 expectedReceiptId = finalizedReceiptId(
            receipt.sourceChainId,
            receipt.sourceContract,
            receipt.sourceSessionId,
            receipt.finalizationDigest
        );
        bytes32 expectedInputDigest = keccak256(
            abi.encode(
                "UBCA/BioZKFHE/input/v1",
                receipt.sourceChainId,
                receipt.sourceContract,
                receipt.sourceSessionId,
                receipt.sourceContextHash,
                receipt.gallerySnapshotHash,
                receipt.queryCiphertextDigest,
                receipt.enrollmentCiphertextDigest,
                receipt.modelHash,
                receipt.quantizationHash
            )
        );
        if (
            receipt.sourceChainId == 0 ||
            receipt.sourceContract == address(0) ||
            receipt.sourceSessionId != sourceSessionId ||
            receipt.sourceContextHash == bytes32(0) ||
            receipt.gallerySnapshotHash == bytes32(0) ||
            receipt.queryCiphertextDigest == bytes32(0) ||
            receipt.enrollmentCiphertextDigest == bytes32(0) ||
            receipt.verifiedOutputCollectionDigest == bytes32(0) ||
            receipt.finalizationDigest == bytes32(0) ||
            receipt.finalizedAtBlock == 0 ||
            receipt.receiptId != expectedReceiptId ||
            receipt.uniqueInputDigest != expectedInputDigest ||
            request.receiptId != expectedReceiptId ||
            request.uniqueInputDigest != expectedInputDigest ||
            request.modelHash != receipt.modelHash ||
            request.quantizationHash != receipt.quantizationHash
        ) revert InvalidFinalizedReceipt();

        _recordUniqueReceipt(
            receipt.receiptId,
            receipt.uniqueInputDigest,
            receipt.modelHash,
            receipt.quantizationHash
        );
        receiptId = receipt.receiptId;
    }

    function issueAuthenticationChallenge(
        bytes32 action,
        bytes32 credentialId,
        bytes32 deviceVersionId,
        uint64 deadline
    ) external returns (bytes32 nonce, uint256 ctxHash) {
        if (
            deadline <= block.timestamp ||
            deadline > block.timestamp + MAX_AUTH_CHALLENGE_TTL
        ) revert AuthChallengeExpired();

        Credential storage credential = credentials[credentialId];
        if (
            credential.holder != msg.sender ||
            !canonicalPolicyRegistered[credential.policyHash] ||
            credential.modelHash != canonicalPolicySpecs[credential.policyHash].modelHash ||
            credential.quantizationHash != canonicalPolicySpecs[credential.policyHash].quantizationHash ||
            !policyMatchThresholdConfigured[credential.policyHash] ||
            !isAuthenticationStateActive(credentialId, deviceVersionId)
        ) revert InvalidAuthCredential();

        uint64 epoch = registryEpoch;
        uint256 counter = ++authChallengeCounters[msg.sender];
        nonce = keccak256(
            abi.encode(
                "UBCA/auth-nonce/v1",
                address(this),
                msg.sender,
                credentialId,
                deviceVersionId,
                epoch,
                counter,
                block.prevrandao,
                blockhash(block.number - 1)
            )
        );
        UBCAAuthContext memory context = UBCAAuthContext({
            beneficiary: msg.sender,
            action: action,
            credentialId: credentialId,
            deviceVersionId: deviceVersionId,
            registryEpochAtIssue: epoch,
            nonce: nonce,
            deadline: deadline
        });
        bytes32 encodedContextHash = _hashAuthContext(context);
        pendingAuthContexts[nonce] = encodedContextHash;
        ctxHash = uint256(encodedContextHash) % SNARK_SCALAR_FIELD;
        emit UBCAAuthChallengeIssued(
            msg.sender,
            credentialId,
            nonce,
            deviceVersionId,
            ctxHash,
            epoch,
            deadline
        );
    }

    function computeAuthContextHash(UBCAAuthContext calldata context)
        external
        view
        returns (bytes32 encodedContextHash, uint256 ctxHash)
    {
        encodedContextHash = _hashAuthContext(context);
        ctxHash = uint256(encodedContextHash) % SNARK_SCALAR_FIELD;
    }

    function captureStatementDigest(UBCACaptureStatement calldata statement)
        external
        view
        returns (bytes32)
    {
        return _captureStatementDigest(statement);
    }

    function cancelAuthenticationChallenge(UBCAAuthContext calldata context) external {
        bytes32 encodedContextHash = _hashAuthContext(context);
        if (pendingAuthContexts[context.nonce] != encodedContextHash) {
            revert InvalidAuthContext();
        }
        if (msg.sender != context.beneficiary && block.timestamp <= context.deadline) {
            revert Unauthorized();
        }
        delete pendingAuthContexts[context.nonce];
        emit UBCAAuthChallengeCancelled(context.nonce, msg.sender);
    }

    function verifyAndConsumeAuthentication(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[5] calldata publicSignals,
        UBCAAuthContext calldata context,
        UBCACaptureStatement calldata capture,
        bytes calldata captureSignature
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
        CanonicalPolicySpec storage policySpec = canonicalPolicySpecs[credential.policyHash];
        if (
            credential.holder != context.beneficiary ||
            !canonicalPolicyRegistered[credential.policyHash] ||
            credential.modelHash != policySpec.modelHash ||
            credential.quantizationHash != policySpec.quantizationHash ||
            !isAuthenticationStateActive(
                context.credentialId,
                context.deviceVersionId
            ) ||
            publicSignals[0] != credential.cEnroll ||
            publicSignals[2] != policyFieldDigest(credential.policyHash) ||
            !policyMatchThresholdConfigured[credential.policyHash] ||
            publicSignals[4] != policyMatchThresholds[credential.policyHash] ||
            publicSignals[3] != ctxHash
        ) revert InvalidAuthCredential();

        if (
            capture.cProbe != publicSignals[1] ||
            capture.ctxHash != ctxHash ||
            capture.credentialId != context.credentialId ||
            capture.deviceVersionId != context.deviceVersionId ||
            capture.policyHash != credential.policyHash ||
            capture.modelHash != credential.modelHash ||
            capture.quantizationHash != credential.quantizationHash ||
            capture.firmwareMeasurement != device.firmwareMeasurement ||
            capture.registryEpochAtCapture < context.registryEpochAtIssue ||
            capture.registryEpochAtCapture > registryEpoch ||
            block.timestamp > capture.notAfter ||
            capture.notAfter > context.deadline ||
            capture.counter <= lastCaptureCounters[context.deviceVersionId]
        ) revert InvalidCaptureStatement();
        if (
            _recoverCapture(
                _captureStatementDigest(capture),
                captureSignature
            ) != device.signingKey
        ) revert InvalidCaptureStatement();
        if (!authVerifier.verifyProof(pA, pB, pC, publicSignals)) {
            revert InvalidAuthProof();
        }

        // Freshness consumption, device counter advancement, and acceptance
        // share one EVM state transition.
        delete pendingAuthContexts[context.nonce];
        lastCaptureCounters[context.deviceVersionId] = capture.counter;
        emit UBCAAuthenticationAccepted(
            context.beneficiary,
            context.credentialId,
            context.nonce,
            context.deviceVersionId,
            context.action,
            capture.registryEpochAtCapture,
            capture.counter
        );
        return true;
    }

    function _hashAuthContext(UBCAAuthContext memory context)
        internal
        view
        returns (bytes32)
    {
        return
            keccak256(
                abi.encode(
                    AUTH_CONTEXT_TYPEHASH,
                    context.beneficiary,
                    context.action,
                    block.chainid,
                    address(this),
                    context.credentialId,
                    context.deviceVersionId,
                    context.registryEpochAtIssue,
                    context.nonce,
                    context.deadline
                )
            );
    }

    function _captureStatementDigest(UBCACaptureStatement calldata statement)
        private
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                CAPTURE_STATEMENT_TYPEHASH,
                statement.cProbe,
                statement.ctxHash,
                statement.credentialId,
                statement.deviceVersionId,
                statement.policyHash,
                statement.modelHash,
                statement.quantizationHash,
                statement.firmwareMeasurement,
                statement.registryEpochAtCapture,
                statement.counter,
                statement.notAfter
            )
        );
        return
            keccak256(
                abi.encodePacked("\x19\x01", captureDomainSeparator, structHash)
            );
    }

    function _recoverCapture(bytes32 digest, bytes calldata signature)
        internal
        pure
        returns (address)
    {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (
            uint256(s) > CAPTURE_SECP256K1_HALF_ORDER ||
            (v != 27 && v != 28)
        ) return address(0);
        return ecrecover(digest, v, r, s);
    }
}
