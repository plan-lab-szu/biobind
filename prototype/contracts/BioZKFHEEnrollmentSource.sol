// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./interfaces/IBioZKFHEFinalizationSource.sol";

/// @notice BioZKFHE enrollment-session extension for BioBind composition
///         (dev-workspace/notes/biobind-security-model.md I1-I3,
///         dev-workspace/notes/gallery-root-migration.md).
/// @dev The public BioZKFHE repository has no enrollment path; this contract
///      implements one on top of the paper's session semantics:
///      - bound request: a registered enrollment bridge signs (sid, ctx, N,
///        query/enrollment ciphertext digests, slot) at request time (I1);
///      - snapshot: the ordered block-commitment state is bound into ctx at
///        session creation, and the verdict is relative to that snapshot;
///      - stale abort: a unique verdict is finalized only if N has not moved
///        since the snapshot, otherwise the session aborts (I3);
///      - root migration: append is checked on chain (u_new == enrollment
///        digest); merge relies on the same >= t roster confirmations that
///        finalize the verdict, extended with (u_old, u_new, slot, N) (I2(b)).
///      PVSC block proofs, coverage, and threshold decryption are performed by
///      the committee off chain and attested in its confirmation; their on-chain
///      verification cost is NOT included here. Benchmark code; never deploy.
contract BioZKFHEEnrollmentSource is IBioZKFHEFinalizationSource {
    uint8 public constant ENROLL_OPERATION = 1;

    enum Status {
        None,
        Created,
        Bound,
        Finalized,
        AbortedStaleSlot,
        Duplicate
    }

    struct Session {
        Status status;
        uint64 galleryCount;
        uint32 blockCount;
        bytes32 gallerySnapshotHash;
        bytes32 snapshotLastCommitment; // u_{M-1} at session creation
        bytes32 contextHash;
        bytes32 queryDigest;
        bytes32 enrollDigest;
        bytes32 outputDigest;
        uint64 finalizedAtBlock;
    }

    error Unauthorized();
    error InvalidConfiguration();
    error InvalidSessionState();
    error UnregisteredBridge();
    error DeclaredCountMismatch();
    error SlotMismatch();
    error InsufficientConfirmations();
    error AppendMismatch();

    event SessionCreated(
        bytes32 indexed sid,
        uint64 galleryCount,
        bytes32 gallerySnapshotHash,
        bytes32 ledgerMetaHash,
        bytes32 contextHash
    );
    event RequestBound(bytes32 indexed sid, bytes32 queryDigest, bytes32 enrollDigest);
    event SessionClosed(bytes32 indexed sid, Status status);
    event GalleryMigrated(bytes32 indexed sid, uint32 blockIndex, bytes32 uOld, bytes32 uNew, uint64 galleryCount);

    address public immutable owner;
    uint256 public immutable slotsPerBlock; // n * d
    uint256 public immutable columns; // d
    uint32 public immutable threshold; // t
    bytes32 public immutable modelHash;
    bytes32 public immutable quantizationHash;

    mapping(address => bool) public isCommitteeMember;
    mapping(address => bool) public isRegisteredBridge;

    uint64 public galleryCount; // N, authenticated count
    uint32 public blockCount; // M
    bytes32 public closedBlocksChain; // hash chain over u_0 .. u_{M-2}
    bytes32 public lastBlockCommitment; // u_{M-1}
    uint256 private sessionCounter;

    mapping(bytes32 sid => Session) private sessions;

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

    /// Same encoding as scripts/lib/biozkfhe-source-model.mjs sourceContextHash.
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
        sid = keccak256(abi.encode("BioZKFHE/sid/v1", address(this), ++sessionCounter));
        bytes32 snapshot = gallerySnapshotHash();
        bytes32 ledgerMeta = keccak256(abi.encode("ledger", block.number, sessionCounter));
        bytes32 ctxHash = sourceContextHash(sid, galleryCount, snapshot, ledgerMeta);
        sessions[sid] = Session({
            status: Status.Created,
            galleryCount: galleryCount,
            blockCount: blockCount,
            gallerySnapshotHash: snapshot,
            snapshotLastCommitment: lastBlockCommitment,
            contextHash: ctxHash,
            queryDigest: bytes32(0),
            enrollDigest: bytes32(0),
            outputDigest: bytes32(0),
            finalizedAtBlock: 0
        });
        emit SessionCreated(sid, galleryCount, snapshot, ledgerMeta, ctxHash);
    }

    /// Same encoding as scripts/lib/biozkfhe-source-model.mjs enrollRequestDigest.
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

    /// I1(a): the bridge declaration is required at request time, and the
    /// declared count and slot must equal the session snapshot.
    function bindRequest(
        bytes32 sid,
        bytes32 queryDigest,
        bytes32 enrollDigest,
        uint64 declaredCount,
        uint16 h,
        uint16 k,
        bytes calldata bridgeSignature
    ) external {
        Session storage s = sessions[sid];
        if (s.status != Status.Created) revert InvalidSessionState();
        if (declaredCount != s.galleryCount || declaredCount != galleryCount) revert DeclaredCountMismatch();
        uint256 a = uint256(declaredCount) % slotsPerBlock;
        if (h != a % columns || k != a / columns) revert SlotMismatch();
        bytes32 digest = enrollRequestDigest(sid, s.contextHash, declaredCount, queryDigest, enrollDigest, h, k);
        if (!isRegisteredBridge[_recover(digest, bridgeSignature)]) revert UnregisteredBridge();
        s.queryDigest = queryDigest;
        s.enrollDigest = enrollDigest;
        s.status = Status.Bound;
        emit RequestBound(sid, queryDigest, enrollDigest);
    }

    /// Committee confirmation: verdict, output collection, and the gallery
    /// migration it implies are signed together (gallery-root-migration.md §3.5).
    function confirmationDigest(
        bytes32 sid,
        bool unique,
        bytes32 outputDigest,
        uint32 blockIndex,
        bytes32 uOld,
        bytes32 uNew
    ) public view returns (bytes32) {
        Session storage s = sessions[sid];
        return keccak256(
            abi.encode(
                "BioBind/BioZKFHE/confirmation/v1",
                block.chainid,
                address(this),
                sid,
                s.contextHash,
                s.queryDigest,
                s.enrollDigest,
                unique,
                outputDigest,
                blockIndex,
                uOld,
                uNew,
                s.galleryCount
            )
        );
    }

    /// @param signatures committee signatures over confirmationDigest; signers
    ///        must be distinct roster members in strictly ascending address order.
    function finalize(
        bytes32 sid,
        bool unique,
        bytes32 outputDigest,
        bytes32 uNew,
        bytes[] calldata signatures
    ) external returns (Status) {
        Session storage s = sessions[sid];
        if (s.status != Status.Bound) revert InvalidSessionState();
        bool append = uint256(s.galleryCount) % slotsPerBlock == 0;
        uint32 blockIndex = append ? s.blockCount : s.blockCount - 1;
        // The committee computes the migration against the session snapshot.
        bytes32 uOld = append ? bytes32(0) : s.snapshotLastCommitment;
        if (!unique) uNew = bytes32(0);
        _requireConfirmations(confirmationDigest(sid, unique, outputDigest, blockIndex, uOld, uNew), signatures);
        s.outputDigest = outputDigest;
        s.finalizedAtBlock = uint64(block.number);
        if (!unique) {
            s.status = Status.Duplicate;
        } else if (galleryCount != s.galleryCount) {
            // I3: the gallery moved since the snapshot this verdict refers to.
            s.status = Status.AbortedStaleSlot;
        } else {
            if (append) {
                if (uNew != s.enrollDigest) revert AppendMismatch();
                if (blockCount > 0) {
                    closedBlocksChain = keccak256(abi.encode(closedBlocksChain, lastBlockCommitment));
                }
                blockCount += 1;
            }
            lastBlockCommitment = uNew;
            galleryCount += 1;
            s.status = Status.Finalized;
            emit GalleryMigrated(sid, blockIndex, uOld, uNew, galleryCount);
        }
        emit SessionClosed(sid, s.status);
        return s.status;
    }

    function sessionStatus(bytes32 sid) external view returns (Status) {
        return sessions[sid].status;
    }

    function finalizedSessionDigest(bytes32 sid) external view returns (bytes32) {
        if (sessions[sid].status != Status.Finalized) return bytes32(0);
        return keccak256(abi.encode(getFinalizedSession(sid)));
    }

    /// Full record, reconstructed from storage (v1 keeps every field on chain).
    function getFinalizedSession(bytes32 sid) public view returns (FinalizedSession memory r) {
        Session storage s = sessions[sid];
        bool done = s.status == Status.Finalized;
        uint32 blocks = s.blockCount == 0 ? 1 : s.blockCount;
        r = FinalizedSession({
            operation: ENROLL_OPERATION,
            finalized: done,
            uniquenessAccepted: done,
            expectedBlockCount: blocks,
            verifiedBlockCount: done ? blocks : 0,
            confirmationThreshold: threshold,
            confirmationCount: done ? threshold : 0,
            sourceContextHash: s.contextHash,
            gallerySnapshotHash: s.gallerySnapshotHash,
            queryCiphertextDigest: s.queryDigest,
            enrollmentCiphertextDigest: s.enrollDigest,
            verifiedOutputCollectionDigest: s.outputDigest,
            modelHash: modelHash,
            quantizationHash: quantizationHash,
            finalizedAtBlock: s.finalizedAtBlock
        });
    }

    function _requireConfirmations(bytes32 digest, bytes[] calldata signatures) internal view {
        if (signatures.length < threshold) revert InsufficientConfirmations();
        address previous = address(0);
        uint256 valid = 0;
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = _recover(digest, signatures[i]);
            if (signer <= previous) revert InsufficientConfirmations(); // distinct, ascending
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
