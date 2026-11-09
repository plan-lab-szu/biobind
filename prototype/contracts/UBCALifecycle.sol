// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Research prototype for the monotonic UBCA credential lifecycle.
/// @dev The owner models the uniqueness-result adapter and credential issuer.
///      Production governance and the BioZKFHE receipt verifier remain separate.
contract UBCALifecycle {
    uint256 public constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 private constant SECP256K1_HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    bytes32 public constant ENROLL_LINK_TYPEHASH = keccak256(
        "EnrollmentLink(bytes32 receiptId,bytes32 lineageId,uint256 cEnroll,bytes32 uniqueInputDigest,bytes32 modelHash,bytes32 quantizationHash,bytes32 policyHash,uint32 templateVersion,address holder,bytes32 deviceVersionId,bytes32 enrollmentContext)"
    );
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant NAME_HASH = keccak256("UBCA Enrollment Link");
    bytes32 private constant VERSION_HASH = keccak256("1");

    enum Status {
        Absent,
        Active,
        Superseded,
        Revoked
    }

    struct Policy {
        Status status;
        uint64 validFromEpoch;
        uint64 revokedAtEpoch;
    }

    struct DeviceVersion {
        address signingKey;
        bytes32 firmwareMeasurement;
        bytes32 modelHash;
        bytes32 quantizationHash;
        bytes32 policyHash;
        Status status;
        uint64 validFromEpoch;
        uint64 revokedAtEpoch;
    }

    struct UniqueReceipt {
        bytes32 uniqueInputDigest;
        bytes32 modelHash;
        bytes32 quantizationHash;
        bytes32 consumedBy;
        uint64 recordedAtEpoch;
        bool exists;
    }

    struct Credential {
        bytes32 lineageId;
        bytes32 receiptId;
        uint256 cEnroll;
        bytes32 modelHash;
        bytes32 quantizationHash;
        bytes32 policyHash;
        bytes32 successor;
        address holder;
        uint32 credentialVersion;
        uint32 templateVersion;
        Status status;
    }

    struct IssueRequest {
        bytes32 receiptId;
        bytes32 lineageId;
        uint256 cEnroll;
        bytes32 policyHash;
        bytes32 modelHash;
        bytes32 quantizationHash;
        uint32 templateVersion;
        address holder;
        bytes32 deviceVersionId;
        bytes32 uniqueInputDigest;
        bytes32 enrollmentContext;
    }

    error Unauthorized();
    error InvalidConfiguration();
    error InvalidTransition();
    error InvalidReceipt();
    error InvalidEnrollmentLink();
    error InactiveAuthenticationState();

    address public immutable owner;
    bytes32 public immutable domainSeparator;
    uint64 public registryEpoch;
    uint256 public uniqueReceiptCount;
    bool public legacyReceiptPathDisabled;

    mapping(bytes32 policyHash => Policy) public policies;
    mapping(bytes32 deviceVersionId => DeviceVersion) public deviceVersions;
    mapping(address signingKey => bool) public signingKeyEverRegistered;
    mapping(bytes32 receiptId => UniqueReceipt) public uniqueReceipts;
    mapping(bytes32 credentialId => Credential) public credentials;
    mapping(bytes32 lineageId => bytes32 credentialId) public activeCredentialByLineage;
    mapping(bytes32 lineageId => bool) public lineageEverIssued;

    event PolicyRegistered(bytes32 indexed policyHash, uint64 indexed epoch);
    event PolicyRevoked(bytes32 indexed policyHash, uint64 indexed epoch);
    event DeviceRegistered(
        bytes32 indexed deviceVersionId,
        address indexed signingKey,
        uint64 indexed epoch
    );
    event DeviceRevoked(bytes32 indexed deviceVersionId, uint64 indexed epoch);
    event UniqueReceiptRecorded(bytes32 indexed receiptId, uint64 indexed epoch);
    event UniqueReceiptConsumed(
        bytes32 indexed receiptId,
        bytes32 indexed credentialId,
        uint64 indexed epoch
    );
    event CredentialIssued(
        bytes32 indexed credentialId,
        bytes32 indexed lineageId,
        uint32 credentialVersion,
        uint32 templateVersion,
        uint64 epoch
    );
    event CredentialSuperseded(
        bytes32 indexed oldCredentialId,
        bytes32 indexed newCredentialId,
        uint64 indexed epoch
    );
    event CredentialRevoked(bytes32 indexed credentialId, uint64 indexed epoch);
    event LegacyReceiptPathPermanentlyDisabled();

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    constructor() {
        owner = msg.sender;
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

    function registerPolicy(bytes32 policyHash) external onlyOwner {
        _registerPolicy(policyHash);
    }

    function _registerPolicy(bytes32 policyHash) internal {
        if (policyHash == bytes32(0) || policies[policyHash].status != Status.Absent) {
            revert InvalidConfiguration();
        }
        uint64 epoch = _nextEpoch();
        policies[policyHash] = Policy(Status.Active, epoch, 0);
        emit PolicyRegistered(policyHash, epoch);
    }

    function revokePolicy(bytes32 policyHash) external onlyOwner {
        Policy storage policy = policies[policyHash];
        if (policy.status != Status.Active) revert InvalidTransition();
        uint64 epoch = _nextEpoch();
        policy.status = Status.Revoked;
        policy.revokedAtEpoch = epoch;
        emit PolicyRevoked(policyHash, epoch);
    }

    function replacePolicy(bytes32 oldPolicyHash, bytes32 newPolicyHash)
        external
        onlyOwner
    {
        _replacePolicy(oldPolicyHash, newPolicyHash);
    }

    function _replacePolicy(bytes32 oldPolicyHash, bytes32 newPolicyHash)
        internal
    {
        Policy storage oldPolicy = policies[oldPolicyHash];
        if (
            oldPolicy.status != Status.Active ||
            newPolicyHash == bytes32(0) ||
            policies[newPolicyHash].status != Status.Absent
        ) revert InvalidTransition();
        uint64 epoch = _nextEpoch();
        oldPolicy.status = Status.Revoked;
        oldPolicy.revokedAtEpoch = epoch;
        policies[newPolicyHash] = Policy(Status.Active, epoch, 0);
        emit PolicyRevoked(oldPolicyHash, epoch);
        emit PolicyRegistered(newPolicyHash, epoch);
    }

    function registerDevice(
        address signingKey,
        bytes32 firmwareMeasurement,
        bytes32 modelHash,
        bytes32 quantizationHash,
        bytes32 policyHash
    ) external onlyOwner returns (bytes32 deviceVersionId) {
        if (
            signingKey == address(0) ||
            signingKeyEverRegistered[signingKey] ||
            firmwareMeasurement == bytes32(0) ||
            modelHash == bytes32(0) ||
            quantizationHash == bytes32(0) ||
            policies[policyHash].status != Status.Active
        ) revert InvalidConfiguration();

        uint64 epoch = _nextEpoch();
        deviceVersionId = keccak256(
            abi.encode(
                "UBCA/device/v1",
                signingKey,
                firmwareMeasurement,
                modelHash,
                quantizationHash,
                policyHash,
                epoch
            )
        );
        deviceVersions[deviceVersionId] = DeviceVersion({
            signingKey: signingKey,
            firmwareMeasurement: firmwareMeasurement,
            modelHash: modelHash,
            quantizationHash: quantizationHash,
            policyHash: policyHash,
            status: Status.Active,
            validFromEpoch: epoch,
            revokedAtEpoch: 0
        });
        signingKeyEverRegistered[signingKey] = true;
        emit DeviceRegistered(deviceVersionId, signingKey, epoch);
    }

    function revokeDevice(bytes32 deviceVersionId) external onlyOwner {
        DeviceVersion storage device = deviceVersions[deviceVersionId];
        if (device.status != Status.Active) revert InvalidTransition();
        uint64 epoch = _nextEpoch();
        device.status = Status.Revoked;
        device.revokedAtEpoch = epoch;
        emit DeviceRevoked(deviceVersionId, epoch);
    }

    function rotateDevice(
        bytes32 oldDeviceVersionId,
        address newSigningKey,
        bytes32 newFirmwareMeasurement,
        bytes32 newModelHash,
        bytes32 newQuantizationHash,
        bytes32 newPolicyHash
    ) external onlyOwner returns (bytes32 newDeviceVersionId) {
        DeviceVersion storage oldDevice = deviceVersions[oldDeviceVersionId];
        if (
            oldDevice.status != Status.Active ||
            newSigningKey == address(0) ||
            signingKeyEverRegistered[newSigningKey] ||
            newFirmwareMeasurement == bytes32(0) ||
            newModelHash == bytes32(0) ||
            newQuantizationHash == bytes32(0) ||
            policies[newPolicyHash].status != Status.Active
        ) revert InvalidTransition();

        uint64 epoch = _nextEpoch();
        oldDevice.status = Status.Revoked;
        oldDevice.revokedAtEpoch = epoch;
        newDeviceVersionId = keccak256(
            abi.encode(
                "UBCA/device/v1",
                newSigningKey,
                newFirmwareMeasurement,
                newModelHash,
                newQuantizationHash,
                newPolicyHash,
                epoch
            )
        );
        deviceVersions[newDeviceVersionId] = DeviceVersion({
            signingKey: newSigningKey,
            firmwareMeasurement: newFirmwareMeasurement,
            modelHash: newModelHash,
            quantizationHash: newQuantizationHash,
            policyHash: newPolicyHash,
            status: Status.Active,
            validFromEpoch: epoch,
            revokedAtEpoch: 0
        });
        signingKeyEverRegistered[newSigningKey] = true;
        emit DeviceRevoked(oldDeviceVersionId, epoch);
        emit DeviceRegistered(newDeviceVersionId, newSigningKey, epoch);
    }

    function recordUniqueReceipt(
        bytes32 receiptId,
        bytes32 uniqueInputDigest,
        bytes32 modelHash,
        bytes32 quantizationHash
    ) external onlyOwner {
        if (legacyReceiptPathDisabled) revert InvalidTransition();
        _recordUniqueReceipt(
            receiptId,
            uniqueInputDigest,
            modelHash,
            quantizationHash
        );
    }

    function _recordUniqueReceipt(
        bytes32 receiptId,
        bytes32 uniqueInputDigest,
        bytes32 modelHash,
        bytes32 quantizationHash
    ) internal {
        if (
            receiptId == bytes32(0) ||
            uniqueInputDigest == bytes32(0) ||
            modelHash == bytes32(0) ||
            quantizationHash == bytes32(0) ||
            uniqueReceipts[receiptId].exists
        ) revert InvalidConfiguration();
        uint64 epoch = _nextEpoch();
        uniqueReceipts[receiptId] = UniqueReceipt({
            uniqueInputDigest: uniqueInputDigest,
            modelHash: modelHash,
            quantizationHash: quantizationHash,
            consumedBy: bytes32(0),
            recordedAtEpoch: epoch,
            exists: true
        });
        uniqueReceiptCount += 1;
        emit UniqueReceiptRecorded(receiptId, epoch);
    }

    /// @notice Irreversibly selects the adapter-only issuance profile.
    /// @dev It can be enabled only before any receipt has entered this registry.
    function disableLegacyReceiptPath() external onlyOwner {
        if (legacyReceiptPathDisabled || uniqueReceiptCount != 0) {
            revert InvalidTransition();
        }
        legacyReceiptPathDisabled = true;
        emit LegacyReceiptPathPermanentlyDisabled();
    }

    function issueFromUniqueReceipt(IssueRequest calldata request, bytes calldata signature)
        external
        returns (bytes32 credentialId)
    {
        if (legacyReceiptPathDisabled) revert InvalidTransition();
        if (
            lineageEverIssued[request.lineageId] ||
            activeCredentialByLineage[request.lineageId] != bytes32(0)
        ) {
            revert InvalidTransition();
        }
        credentialId = _issue(request, 1, signature);
    }

    function replaceTemplate(
        bytes32 oldCredentialId,
        IssueRequest calldata request,
        bytes calldata signature
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

        newCredentialId = _issue(
            request,
            oldCredential.credentialVersion + 1,
            signature
        );
        _supersede(oldCredentialId, newCredentialId);
    }

    /// @notice Disabled for policy-bound enrollment commitments.
    /// @dev The old API reused cEnroll under a new policyHash even though the
    ///      circuit commitment includes policyFieldDigest(policyHash). A policy
    ///      migration must create a fresh commitment and signed IssueRequest
    ///      through replaceTemplate instead.
    function replaceMetadata(bytes32, bytes32)
        external
        onlyOwner
        returns (bytes32)
    {
        revert InvalidTransition();
    }

    function revokeCredential(bytes32 credentialId) external onlyOwner {
        Credential storage credential = credentials[credentialId];
        if (credential.status != Status.Active) revert InvalidTransition();
        uint64 epoch = _nextEpoch();
        credential.status = Status.Revoked;
        activeCredentialByLineage[credential.lineageId] = bytes32(0);
        emit CredentialRevoked(credentialId, epoch);
    }

    function isAuthenticationStateActive(
        bytes32 credentialId,
        bytes32 deviceVersionId
    ) public view returns (bool) {
        Credential storage credential = credentials[credentialId];
        DeviceVersion storage device = deviceVersions[deviceVersionId];
        return
            credential.status == Status.Active &&
            activeCredentialByLineage[credential.lineageId] == credentialId &&
            policies[credential.policyHash].status == Status.Active &&
            device.status == Status.Active &&
            device.modelHash == credential.modelHash &&
            device.quantizationHash == credential.quantizationHash &&
            device.policyHash == credential.policyHash;
    }

    function requireAuthenticationState(
        bytes32 credentialId,
        bytes32 deviceVersionId
    ) external view {
        if (!isAuthenticationStateActive(credentialId, deviceVersionId)) {
            revert InactiveAuthenticationState();
        }
    }

    function enrollmentLinkDigest(IssueRequest calldata request)
        external
        view
        returns (bytes32)
    {
        return _enrollmentLinkDigest(request);
    }

    function _issue(
        IssueRequest calldata request,
        uint32 credentialVersion,
        bytes calldata signature
    ) internal returns (bytes32 credentialId) {
        UniqueReceipt storage receipt = uniqueReceipts[request.receiptId];
        DeviceVersion storage device = deviceVersions[request.deviceVersionId];
        if (
            request.lineageId == bytes32(0) ||
            request.cEnroll >= SNARK_SCALAR_FIELD ||
            request.holder == address(0) ||
            request.templateVersion == 0 ||
            !receipt.exists ||
            receipt.consumedBy != bytes32(0) ||
            receipt.uniqueInputDigest != request.uniqueInputDigest ||
            receipt.modelHash != request.modelHash ||
            receipt.quantizationHash != request.quantizationHash
        ) revert InvalidReceipt();
        if (
            policies[request.policyHash].status != Status.Active ||
            device.status != Status.Active ||
            device.modelHash != request.modelHash ||
            device.quantizationHash != request.quantizationHash ||
            device.policyHash != request.policyHash
        ) revert InvalidConfiguration();
        if (_recover(_enrollmentLinkDigest(request), signature) != device.signingKey) {
            revert InvalidEnrollmentLink();
        }

        credentialId = _credentialId(
            request.lineageId,
            request.cEnroll,
            request.modelHash,
            request.quantizationHash,
            request.policyHash,
            credentialVersion,
            request.templateVersion,
            request.holder
        );
        if (credentials[credentialId].status != Status.Absent) {
            revert InvalidConfiguration();
        }

        uint64 epoch = _nextEpoch();
        receipt.consumedBy = credentialId;
        credentials[credentialId] = Credential({
            lineageId: request.lineageId,
            receiptId: request.receiptId,
            cEnroll: request.cEnroll,
            modelHash: request.modelHash,
            quantizationHash: request.quantizationHash,
            policyHash: request.policyHash,
            successor: bytes32(0),
            holder: request.holder,
            credentialVersion: credentialVersion,
            templateVersion: request.templateVersion,
            status: Status.Active
        });
        activeCredentialByLineage[request.lineageId] = credentialId;
        lineageEverIssued[request.lineageId] = true;
        emit UniqueReceiptConsumed(request.receiptId, credentialId, epoch);
        emit CredentialIssued(
            credentialId,
            request.lineageId,
            credentialVersion,
            request.templateVersion,
            epoch
        );
    }

    function _supersede(bytes32 oldCredentialId, bytes32 newCredentialId) internal {
        _supersedeAtEpoch(oldCredentialId, newCredentialId, registryEpoch);
    }

    function _supersedeAtEpoch(
        bytes32 oldCredentialId,
        bytes32 newCredentialId,
        uint64 epoch
    ) private {
        Credential storage oldCredential = credentials[oldCredentialId];
        oldCredential.status = Status.Superseded;
        oldCredential.successor = newCredentialId;
        activeCredentialByLineage[oldCredential.lineageId] = newCredentialId;
        emit CredentialSuperseded(oldCredentialId, newCredentialId, epoch);
    }

    function _credentialId(
        bytes32 lineageId,
        uint256 cEnroll,
        bytes32 modelHash,
        bytes32 quantizationHash,
        bytes32 policyHash,
        uint32 credentialVersion,
        uint32 templateVersion,
        address holder
    ) private view returns (bytes32) {
        return keccak256(
            abi.encode(
                "UBCA/credential/v1",
                address(this),
                lineageId,
                cEnroll,
                modelHash,
                quantizationHash,
                policyHash,
                credentialVersion,
                templateVersion,
                holder
            )
        );
    }

    function _enrollmentLinkDigest(IssueRequest calldata request)
        private
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                ENROLL_LINK_TYPEHASH,
                request.receiptId,
                request.lineageId,
                request.cEnroll,
                request.uniqueInputDigest,
                request.modelHash,
                request.quantizationHash,
                request.policyHash,
                request.templateVersion,
                request.holder,
                request.deviceVersionId,
                request.enrollmentContext
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    function _nextEpoch() private returns (uint64 epoch) {
        epoch = ++registryEpoch;
    }

    function _recover(bytes32 digest, bytes calldata signature)
        private
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
        if (uint256(s) > SECP256K1_HALF_ORDER || (v != 27 && v != 28)) {
            return address(0);
        }
        return ecrecover(digest, v, r, s);
    }
}
