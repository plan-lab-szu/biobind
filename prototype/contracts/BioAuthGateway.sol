// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IGroth16Verifier {
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[5] calldata publicSignals
    ) external view returns (bool);
}

contract BioAuthGateway {
    uint256 public constant MAX_CHALLENGE_TTL = 15 minutes;
    uint256 public constant MAX_ANCHOR_AGE = 64;
    uint256 public constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 private constant SECP256K1_HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    bytes32 public constant CONTEXT_TYPEHASH = keccak256(
        "AuthContext(address beneficiary,bytes32 action,uint256 chainId,address verifierContract,bytes32 credentialId,uint32 credentialVersion,uint32 templateVersion,uint32 policyVersion,uint256 policyDigest,bytes32 nonce,uint64 deadline)"
    );
    bytes32 public constant CAPTURE_TYPEHASH = keccak256(
        "Capture(uint256 cProbe,uint256 ctxHash,uint256 policyDigest,bytes32 modelHash,bytes32 firmwareMeasurement,address device,uint64 counter,uint64 notAfter)"
    );
    bytes32 public constant ANCHORED_CONTEXT_TYPEHASH = keccak256(
        "AnchoredAuthContext(address beneficiary,bytes32 action,uint256 chainId,address verifierContract,bytes32 credentialId,uint32 credentialVersion,uint32 templateVersion,uint32 policyVersion,uint256 policyDigest,uint64 authCounter,uint64 anchorBlock,bytes32 anchorHash)"
    );
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant NAME_HASH = keccak256("BioZERO Capture");
    bytes32 private constant VERSION_HASH = keccak256("1");

    struct Credential {
        uint256 cEnroll;
        uint256 policyDigest;
        uint32 credentialVersion;
        uint32 templateVersion;
        uint32 policyVersion;
        bool active;
    }

    struct DeviceAuthorization {
        bytes32 firmwareMeasurement;
        bytes32 modelHash;
        uint256 policyDigest;
        uint64 validFrom;
        uint64 validUntil;
        bool active;
    }

    struct AuthContext {
        address beneficiary;
        bytes32 action;
        bytes32 credentialId;
        uint32 credentialVersion;
        uint32 templateVersion;
        uint32 policyVersion;
        uint256 policyDigest;
        bytes32 nonce;
        uint64 deadline;
    }

    struct CaptureEvidence {
        uint256 cProbe;
        uint256 ctxHash;
        uint256 policyDigest;
        bytes32 modelHash;
        bytes32 firmwareMeasurement;
        address device;
        uint64 counter;
        uint64 notAfter;
        bytes signature;
    }

    struct AnchoredAuthContext {
        address beneficiary;
        bytes32 action;
        bytes32 credentialId;
        uint32 credentialVersion;
        uint32 templateVersion;
        uint32 policyVersion;
        uint256 policyDigest;
        uint64 authCounter;
        uint64 anchorBlock;
        bytes32 anchorHash;
    }

    error Unauthorized();
    error InvalidConfiguration();
    error InvalidContext();
    error Expired();
    error InvalidCredential();
    error InvalidDevice();
    error InvalidCapture();
    error InvalidProof();

    address public immutable owner;
    IGroth16Verifier public immutable verifier;
    bytes32 public immutable domainSeparator;

    mapping(bytes32 credentialId => Credential) public credentials;
    mapping(address device => DeviceAuthorization) public devices;
    mapping(address beneficiary => uint256) public challengeCounters;
    mapping(bytes32 nonce => bytes32 encodedContextHash) public pendingContexts;
    mapping(bytes32 credentialSubject => uint64 nextCounter) public authCounters;

    event CredentialConfigured(bytes32 indexed credentialId, bool active);
    event DeviceConfigured(address indexed device, bool active);
    event ChallengeIssued(
        address indexed beneficiary,
        bytes32 indexed nonce,
        uint256 ctxHash,
        uint64 deadline
    );
    event ChallengeCancelled(bytes32 indexed nonce, address indexed cleaner);
    event AuthenticationAccepted(
        address indexed beneficiary,
        bytes32 indexed credentialId,
        bytes32 indexed nonce,
        bytes32 action,
        address device,
        uint64 captureCounter
    );
    event AnchoredAuthenticationAccepted(
        address indexed beneficiary,
        bytes32 indexed credentialId,
        uint64 indexed authCounter,
        bytes32 action,
        address device,
        uint64 captureCounter,
        uint64 anchorBlock
    );

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    constructor(address verifierAddress) {
        if (verifierAddress == address(0)) revert InvalidConfiguration();
        owner = msg.sender;
        verifier = IGroth16Verifier(verifierAddress);
        domainSeparator = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                NAME_HASH,
                VERSION_HASH,
                block.chainid,
                address(this)
            )
        );
    }

    function configureCredential(
        bytes32 credentialId,
        uint256 cEnroll,
        uint256 policyDigest,
        uint32 credentialVersion,
        uint32 templateVersion,
        uint32 policyVersion,
        bool active
    ) external onlyOwner {
        if (
            credentialId == bytes32(0) ||
            cEnroll >= SNARK_SCALAR_FIELD ||
            policyDigest >= SNARK_SCALAR_FIELD
        ) revert InvalidConfiguration();
        credentials[credentialId] = Credential({
            cEnroll: cEnroll,
            policyDigest: policyDigest,
            credentialVersion: credentialVersion,
            templateVersion: templateVersion,
            policyVersion: policyVersion,
            active: active
        });
        emit CredentialConfigured(credentialId, active);
    }

    function configureDevice(
        address device,
        bytes32 firmwareMeasurement,
        bytes32 modelHash,
        uint256 policyDigest,
        uint64 validFrom,
        uint64 validUntil,
        bool active
    ) external onlyOwner {
        if (
            device == address(0) ||
            firmwareMeasurement == bytes32(0) ||
            modelHash == bytes32(0) ||
            policyDigest >= SNARK_SCALAR_FIELD ||
            validUntil <= validFrom
        ) revert InvalidConfiguration();
        devices[device] = DeviceAuthorization({
            firmwareMeasurement: firmwareMeasurement,
            modelHash: modelHash,
            policyDigest: policyDigest,
            validFrom: validFrom,
            validUntil: validUntil,
            active: active
        });
        emit DeviceConfigured(device, active);
    }

    function issueChallenge(
        bytes32 action,
        bytes32 credentialId,
        uint32 credentialVersion,
        uint32 templateVersion,
        uint32 policyVersion,
        uint256 policyDigest,
        uint64 deadline
    ) external returns (bytes32 nonce, uint256 ctxHash) {
        if (deadline <= block.timestamp || deadline > block.timestamp + MAX_CHALLENGE_TTL) {
            revert Expired();
        }
        Credential storage credential = credentials[credentialId];
        if (
            !credential.active ||
            credential.credentialVersion != credentialVersion ||
            credential.templateVersion != templateVersion ||
            credential.policyVersion != policyVersion ||
            credential.policyDigest != policyDigest
        ) revert InvalidCredential();
        uint256 counter = ++challengeCounters[msg.sender];
        nonce = keccak256(
            abi.encode(
                "BIO-AUTH-NONCE-v1",
                address(this),
                msg.sender,
                counter,
                block.prevrandao,
                blockhash(block.number - 1)
            )
        );
        AuthContext memory context = AuthContext({
            beneficiary: msg.sender,
            action: action,
            credentialId: credentialId,
            credentialVersion: credentialVersion,
            templateVersion: templateVersion,
            policyVersion: policyVersion,
            policyDigest: policyDigest,
            nonce: nonce,
            deadline: deadline
        });
        bytes32 encodedContextHash = _hashContext(context);
        pendingContexts[nonce] = encodedContextHash;
        ctxHash = uint256(encodedContextHash) % SNARK_SCALAR_FIELD;
        emit ChallengeIssued(msg.sender, nonce, ctxHash, deadline);
    }

    function computeContextHash(AuthContext calldata context)
        external
        view
        returns (bytes32 encodedContextHash, uint256 ctxHash)
    {
        encodedContextHash = _hashContext(context);
        ctxHash = uint256(encodedContextHash) % SNARK_SCALAR_FIELD;
    }

    function cancelChallenge(AuthContext calldata context) external {
        bytes32 encodedContextHash = _hashContext(context);
        if (pendingContexts[context.nonce] != encodedContextHash) revert InvalidContext();
        if (msg.sender != context.beneficiary && block.timestamp <= context.deadline) {
            revert Unauthorized();
        }
        delete pendingContexts[context.nonce];
        emit ChallengeCancelled(context.nonce, msg.sender);
    }

    function verifyAndConsume(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[5] calldata publicSignals,
        AuthContext calldata context,
        CaptureEvidence calldata capture
    ) external returns (bool) {
        if (msg.sender != context.beneficiary) revert Unauthorized();
        if (block.timestamp > context.deadline) revert Expired();

        bytes32 encodedContextHash = _hashContext(context);
        if (pendingContexts[context.nonce] != encodedContextHash) revert InvalidContext();
        uint256 ctxHash = uint256(encodedContextHash) % SNARK_SCALAR_FIELD;

        _checkCredential(context, publicSignals, ctxHash);
        _checkCapture(context, capture, publicSignals, ctxHash);
        if (!verifier.verifyProof(pA, pB, pC, publicSignals)) revert InvalidProof();

        delete pendingContexts[context.nonce];
        emit AuthenticationAccepted(
            context.beneficiary,
            context.credentialId,
            context.nonce,
            context.action,
            capture.device,
            capture.counter
        );
        return true;
    }

    function computeAnchoredContextHash(AnchoredAuthContext calldata context)
        external
        view
        returns (bytes32 encodedContextHash, uint256 ctxHash)
    {
        encodedContextHash = _hashAnchoredContext(context);
        ctxHash = uint256(encodedContextHash) % SNARK_SCALAR_FIELD;
    }

    function verifyAnchored(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[5] calldata publicSignals,
        AnchoredAuthContext calldata context,
        CaptureEvidence calldata capture
    ) external returns (bool) {
        if (msg.sender != context.beneficiary) revert Unauthorized();
        if (
            context.anchorBlock >= block.number ||
            block.number - context.anchorBlock > MAX_ANCHOR_AGE ||
            context.anchorHash == bytes32(0) ||
            blockhash(context.anchorBlock) != context.anchorHash
        ) revert InvalidContext();

        bytes32 subject = keccak256(
            abi.encode(context.beneficiary, context.credentialId)
        );
        uint64 expectedCounter = authCounters[subject];
        if (context.authCounter != expectedCounter) revert InvalidContext();

        bytes32 encodedContextHash = _hashAnchoredContext(context);
        uint256 ctxHash = uint256(encodedContextHash) % SNARK_SCALAR_FIELD;
        _checkAnchoredCredential(context, publicSignals, ctxHash);
        _checkAnchoredCapture(context, capture, publicSignals, ctxHash);
        if (!verifier.verifyProof(pA, pB, pC, publicSignals)) revert InvalidProof();

        authCounters[subject] = expectedCounter + 1;
        emit AnchoredAuthenticationAccepted(
            context.beneficiary,
            context.credentialId,
            expectedCounter,
            context.action,
            capture.device,
            capture.counter,
            context.anchorBlock
        );
        return true;
    }

    function _checkCredential(
        AuthContext calldata context,
        uint256[5] calldata publicSignals,
        uint256 ctxHash
    ) private view {
        Credential storage credential = credentials[context.credentialId];
        if (
            !credential.active ||
            credential.credentialVersion != context.credentialVersion ||
            credential.templateVersion != context.templateVersion ||
            credential.policyVersion != context.policyVersion ||
            credential.policyDigest != context.policyDigest ||
            publicSignals[0] != credential.cEnroll ||
            publicSignals[2] != context.policyDigest ||
            publicSignals[3] != ctxHash
        ) revert InvalidCredential();
    }

    function _checkCapture(
        AuthContext calldata context,
        CaptureEvidence calldata capture,
        uint256[5] calldata publicSignals,
        uint256 ctxHash
    ) private view {
        DeviceAuthorization storage device = devices[capture.device];
        if (
            !device.active ||
            block.timestamp < device.validFrom ||
            block.timestamp > device.validUntil ||
            device.firmwareMeasurement != capture.firmwareMeasurement ||
            device.modelHash != capture.modelHash ||
            device.policyDigest != context.policyDigest
        ) revert InvalidDevice();
        if (
            block.timestamp > capture.notAfter ||
            capture.notAfter > context.deadline ||
            capture.cProbe != publicSignals[1] ||
            capture.ctxHash != ctxHash ||
            capture.policyDigest != context.policyDigest
        ) revert InvalidCapture();

        bytes32 structHash = keccak256(
            abi.encode(
                CAPTURE_TYPEHASH,
                capture.cProbe,
                capture.ctxHash,
                capture.policyDigest,
                capture.modelHash,
                capture.firmwareMeasurement,
                capture.device,
                capture.counter,
                capture.notAfter
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        if (_recover(digest, capture.signature) != capture.device) revert InvalidCapture();
    }

    function _checkAnchoredCredential(
        AnchoredAuthContext calldata context,
        uint256[5] calldata publicSignals,
        uint256 ctxHash
    ) private view {
        Credential storage credential = credentials[context.credentialId];
        if (
            !credential.active ||
            credential.credentialVersion != context.credentialVersion ||
            credential.templateVersion != context.templateVersion ||
            credential.policyVersion != context.policyVersion ||
            credential.policyDigest != context.policyDigest ||
            publicSignals[0] != credential.cEnroll ||
            publicSignals[2] != context.policyDigest ||
            publicSignals[3] != ctxHash
        ) revert InvalidCredential();
    }

    function _checkAnchoredCapture(
        AnchoredAuthContext calldata context,
        CaptureEvidence calldata capture,
        uint256[5] calldata publicSignals,
        uint256 ctxHash
    ) private view {
        DeviceAuthorization storage device = devices[capture.device];
        if (
            !device.active ||
            block.timestamp < device.validFrom ||
            block.timestamp > device.validUntil ||
            device.firmwareMeasurement != capture.firmwareMeasurement ||
            device.modelHash != capture.modelHash ||
            device.policyDigest != context.policyDigest
        ) revert InvalidDevice();
        if (
            block.timestamp > capture.notAfter ||
            capture.notAfter > block.timestamp + MAX_CHALLENGE_TTL ||
            capture.cProbe != publicSignals[1] ||
            capture.ctxHash != ctxHash ||
            capture.policyDigest != context.policyDigest
        ) revert InvalidCapture();

        bytes32 structHash = keccak256(
            abi.encode(
                CAPTURE_TYPEHASH,
                capture.cProbe,
                capture.ctxHash,
                capture.policyDigest,
                capture.modelHash,
                capture.firmwareMeasurement,
                capture.device,
                capture.counter,
                capture.notAfter
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        if (_recover(digest, capture.signature) != capture.device) revert InvalidCapture();
    }

    function _hashContext(AuthContext memory context) private view returns (bytes32) {
        return keccak256(
            abi.encode(
                CONTEXT_TYPEHASH,
                context.beneficiary,
                context.action,
                block.chainid,
                address(this),
                context.credentialId,
                context.credentialVersion,
                context.templateVersion,
                context.policyVersion,
                context.policyDigest,
                context.nonce,
                context.deadline
            )
        );
    }

    function _hashAnchoredContext(AnchoredAuthContext memory context)
        private
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                ANCHORED_CONTEXT_TYPEHASH,
                context.beneficiary,
                context.action,
                block.chainid,
                address(this),
                context.credentialId,
                context.credentialVersion,
                context.templateVersion,
                context.policyVersion,
                context.policyDigest,
                context.authCounter,
                context.anchorBlock,
                context.anchorHash
            )
        );
    }

    function _recover(bytes32 digest, bytes calldata signature) private pure returns (address) {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (uint256(s) > SECP256K1_HALF_ORDER || (v != 27 && v != 28)) {
            return address(0);
        }
        return ecrecover(digest, v, r, s);
    }
}
