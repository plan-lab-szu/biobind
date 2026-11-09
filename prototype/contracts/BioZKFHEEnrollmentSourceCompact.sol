// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./interfaces/IBioZKFHEFinalizationSource.sol";

/// @notice Storage-compact variant of BioZKFHEEnrollmentSource with the same
///         checks (bound request, snapshot verdict, stale abort, gallery root
///         migration). See dev-workspace/notes/enrollment-source-contract.md.
/// @dev While a session is open, only keccak256(record) is stored; the record
///      itself is emitted in events and supplied back as calldata. On
///      Finalized, only keccak256(abi.encode(FinalizedSession)) is stored and
///      the record is emitted; consumers pass it back as calldata.
///      Benchmark code; never deploy.
contract BioZKFHEEnrollmentSourceCompact is IBioZKFHEFinalizationSource {
    uint8 public constant ENROLL_OPERATION = 1;

    uint8 internal constant CREATED = 1;
    uint8 internal constant BOUND = 2;
    uint8 internal constant FINALIZED = 3;
    uint8 internal constant ABORTED_STALE_SLOT = 4;
    uint8 internal constant DUPLICATE = 5;

    /// Open-session record; only its hash is stored.
    struct Record {
        bytes32 sid;
        uint8 status;
        uint64 galleryCount; // N at session creation (snapshot)
        uint32 blockCount; // M at session creation
        bytes32 gallerySnapshotHash;
        bytes32 snapshotLastCommitment;
        bytes32 contextHash;
        bytes32 queryDigest;
        bytes32 enrollDigest;
    }

    error Unauthorized();
    error InvalidConfiguration();
    error InvalidSessionState();
    error UnregisteredBridge();
    error DeclaredCountMismatch();
    error SlotMismatch();
    error InsufficientConfirmations();
    error AppendMismatch();

    event SessionCreated(bytes32 indexed sid, Record record, bytes32 ledgerMetaHash);
    event RequestBound(bytes32 indexed sid, Record record);
    event SessionClosed(bytes32 indexed sid, uint8 status, bytes32 outputDigest);
    event SessionFinalized(bytes32 indexed sid, FinalizedSession record);
    event GalleryMigrated(bytes32 indexed sid, uint32 blockIndex, bytes32 uOld, bytes32 uNew, uint64 galleryCount);

    address public immutable owner;
    uint256 public immutable slotsPerBlock;
    uint256 public immutable columns;
    uint32 public immutable threshold;
    bytes32 public immutable modelHash;
    bytes32 public immutable quantizationHash;

    mapping(address => bool) public isCommitteeMember;
    mapping(address => bool) public isRegisteredBridge;

    uint64 public galleryCount;
    uint32 public blockCount;
    bytes32 public closedBlocksChain;
    bytes32 public lastBlockCommitment;
    uint256 private sessionCounter;

    mapping(bytes32 sid => bytes32) public recordDigest;
    mapping(bytes32 sid => bytes32) public finalizedSessionDigest;

    constructor(
        address[] memory committee,
        uint32 t,
        uint256 n,
        uint256 d,
        bytes32 model,
        bytes32 quantization
    ) {
        if (t == 0 || committee.length < t || n == 0 || d == 0) revert InvalidConfiguration();
        for (uint256 i = 0; i < committee.length; i++) {
            if (committee[i] == address(0) || isCommitteeMember[committee[i]]) revert InvalidConfiguration();
            isCommitteeMember[committee[i]] = true;
        }
        owner = msg.sender;
        threshold = t;
        slotsPerBlock = n * d;
        columns = d;
        modelHash = model;
        quantizationHash = quantization;
    }

    function registerBridge(address bridge) external {
        if (msg.sender != owner) revert Unauthorized();
        if (bridge == address(0)) revert InvalidConfiguration();
        isRegisteredBridge[bridge] = true;
    }

    function gallerySnapshotHash() public view returns (bytes32) {
        return keccak256(
            abi.encode("BioBind/gallery-snapshot/v1", closedBlocksChain, lastBlockCommitment, blockCount, galleryCount)
        );
    }

    function sourceContextHash(bytes32 sid, uint64 count, bytes32 snapshot, bytes32 ledgerMeta)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                "BioZKFHE/session-context/v1",
                block.chainid,
                address(this),
                sid,
                ENROLL_OPERATION,
                count,
                snapshot,
                ledgerMeta
            )
        );
    }

    function createSession() external returns (bytes32 sid) {
        uint256 counter = ++sessionCounter;
        sid = keccak256(abi.encode("BioZKFHE/sid/v1", address(this), counter));
        bytes32 snapshot = gallerySnapshotHash();
        bytes32 ledgerMeta = keccak256(abi.encode("ledger", block.number, counter));
        Record memory r = Record({
            sid: sid,
            status: CREATED,
            galleryCount: galleryCount,
            blockCount: blockCount,
            gallerySnapshotHash: snapshot,
            snapshotLastCommitment: lastBlockCommitment,
            contextHash: sourceContextHash(sid, galleryCount, snapshot, ledgerMeta),
            queryDigest: bytes32(0),
            enrollDigest: bytes32(0)
        });
        recordDigest[sid] = keccak256(abi.encode(r));
        emit SessionCreated(sid, r, ledgerMeta);
    }

    function enrollRequestDigest(
        bytes32 sid,
        bytes32 ctxHash,
        uint64 count,
        bytes32 queryDigest,
        bytes32 enrollDigest,
        uint16 h,
        uint16 k
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                "UBCA/BioZKFHE/enroll-request/v1",
                block.chainid,
                address(this),
                sid,
                ctxHash,
                count,
                queryDigest,
                enrollDigest,
                h,
                k
            )
        );
    }

    function bindRequest(
        Record calldata record,
        bytes32 queryDigest,
        bytes32 enrollDigest,
        uint64 declaredCount,
        uint16 h,
        uint16 k,
        bytes calldata bridgeSignature
    ) external {
        _requireRecord(record, CREATED);
        if (declaredCount != record.galleryCount || declaredCount != galleryCount) revert DeclaredCountMismatch();
        uint256 a = uint256(declaredCount) % slotsPerBlock;
        if (h != a % columns || k != a / columns) revert SlotMismatch();
        bytes32 digest =
            enrollRequestDigest(record.sid, record.contextHash, declaredCount, queryDigest, enrollDigest, h, k);
        if (!isRegisteredBridge[_recover(digest, bridgeSignature)]) revert UnregisteredBridge();
        Record memory r = record;
        r.status = BOUND;
        r.queryDigest = queryDigest;
        r.enrollDigest = enrollDigest;
        recordDigest[record.sid] = keccak256(abi.encode(r));
        emit RequestBound(record.sid, r);
    }

    function confirmationDigest(
        Record calldata record,
        bool unique,
        bytes32 outputDigest,
        uint32 blockIndex,
        bytes32 uOld,
        bytes32 uNew
    ) public view returns (bytes32) {
        // Two-level encoding (stack depth); covers the same fields as v1.
        bytes32 sessionPart = keccak256(
            abi.encode(record.sid, record.contextHash, record.queryDigest, record.enrollDigest, record.galleryCount)
        );
        return keccak256(
            abi.encode(
                "BioBind/BioZKFHE/confirmation/v1-compact",
                block.chainid,
                address(this),
                sessionPart,
                unique,
                outputDigest,
                blockIndex,
                uOld,
                uNew
            )
        );
    }

    function finalize(
        Record calldata record,
        bool unique,
        bytes32 outputDigest,
        bytes32 uNew,
        bytes[] calldata signatures
    ) external returns (uint8 status) {
        _requireRecord(record, BOUND);
        bool append = uint256(record.galleryCount) % slotsPerBlock == 0;
        uint32 blockIndex = append ? record.blockCount : record.blockCount - 1;
        bytes32 uOld = append ? bytes32(0) : record.snapshotLastCommitment;
        if (!unique) uNew = bytes32(0);
        _requireConfirmations(confirmationDigest(record, unique, outputDigest, blockIndex, uOld, uNew), signatures);
        if (!unique) {
            status = DUPLICATE;
        } else if (galleryCount != record.galleryCount) {
            status = ABORTED_STALE_SLOT;
        } else {
            if (append) {
                if (uNew != record.enrollDigest) revert AppendMismatch();
                if (blockCount > 0) {
                    closedBlocksChain = keccak256(abi.encode(closedBlocksChain, lastBlockCommitment));
                }
                blockCount += 1;
            }
            lastBlockCommitment = uNew;
            galleryCount += 1;
            status = FINALIZED;
            FinalizedSession memory f = _finalizedRecord(record, outputDigest);
            finalizedSessionDigest[record.sid] = keccak256(abi.encode(f));
            emit SessionFinalized(record.sid, f);
            emit GalleryMigrated(record.sid, blockIndex, uOld, uNew, galleryCount);
        }
        // Closed sessions keep a terminal digest so they cannot be reopened.
        recordDigest[record.sid] = keccak256(abi.encode("closed", status));
        emit SessionClosed(record.sid, status, outputDigest);
    }

    function _finalizedRecord(Record calldata record, bytes32 outputDigest)
        internal
        view
        returns (FinalizedSession memory r)
    {
        uint32 blocks = record.blockCount == 0 ? 1 : record.blockCount;
        r = FinalizedSession({
            operation: ENROLL_OPERATION,
            finalized: true,
            uniquenessAccepted: true,
            expectedBlockCount: blocks,
            verifiedBlockCount: blocks,
            confirmationThreshold: threshold,
            confirmationCount: threshold,
            sourceContextHash: record.contextHash,
            gallerySnapshotHash: record.gallerySnapshotHash,
            queryCiphertextDigest: record.queryDigest,
            enrollmentCiphertextDigest: record.enrollDigest,
            verifiedOutputCollectionDigest: outputDigest,
            modelHash: modelHash,
            quantizationHash: quantizationHash,
            finalizedAtBlock: uint64(block.number)
        });
    }

    function _requireRecord(Record calldata record, uint8 expectedStatus) internal view {
        if (record.status != expectedStatus || recordDigest[record.sid] != keccak256(abi.encode(record))) {
            revert InvalidSessionState();
        }
    }

    function _requireConfirmations(bytes32 digest, bytes[] calldata signatures) internal view {
        if (signatures.length < threshold) revert InsufficientConfirmations();
        address previous = address(0);
        uint256 valid = 0;
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = _recover(digest, signatures[i]);
            if (signer <= previous) revert InsufficientConfirmations();
            previous = signer;
            if (isCommitteeMember[signer]) valid += 1;
        }
        if (valid < threshold) revert InsufficientConfirmations();
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
