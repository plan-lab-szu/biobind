// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./PoseidonT3.sol";

/// @notice Incremental Poseidon(2) Merkle tree with leaf zeroing and an epoch-tagged
///         root history (dev-workspace/notes/unlinkability-design.md §2.2).
/// @dev Insertions append at nextIndex; zeroing takes the leaf's sibling path,
///      checks it against the current root, and recomputes with a zero leaf. Every
///      change advances `epoch`; zeroing also raises `minValidRootEpoch`, so roots
///      from before a revocation are rejected immediately. Only the owner (the
///      gateway) changes the tree. Hashing uses the internal PoseidonT3 library
///      (generated inline assembly, checked against circomlibjs by
///      scripts/poseidon-t3-check.mjs). Benchmark code; never deploy.
contract PoseidonMerkleTree {
    error Unauthorized();
    error TreeFull();
    error InvalidPath();

    event LeafInserted(uint256 indexed index, uint256 leaf, uint256 root, uint64 epoch);
    event LeafZeroed(uint256 indexed index, uint256 root, uint64 epoch);

    address public immutable owner;
    uint8 public immutable depth;
    uint64 public immutable rootHistory; // roots older than this many epochs expire

    uint256[] public zeros; // zeros[i] = root of an empty subtree of height i
    uint256[] public filledSubtrees; // left node on the frontier at each level
    uint256 public nextIndex;
    uint256 public currentRoot;
    uint64 public epoch;
    uint64 public minValidRootEpoch;
    mapping(uint256 root => uint64) public rootEpochPlusOne;

    constructor(uint8 treeDepth, uint64 history, address treeOwner) {
        depth = treeDepth;
        rootHistory = history;
        owner = treeOwner;
        uint256 z = 0;
        for (uint8 i = 0; i < treeDepth; i++) {
            zeros.push(z);
            filledSubtrees.push(z);
            z = PoseidonT3.hash(z, z);
        }
        zeros.push(z);
        currentRoot = z;
        rootEpochPlusOne[z] = 1;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    function isValidRoot(uint256 root) public view returns (bool) {
        uint64 e = rootEpochPlusOne[root];
        if (e == 0) return false;
        e -= 1;
        return e >= minValidRootEpoch && e + rootHistory > epoch;
    }

    function insert(uint256 leaf) external onlyOwner returns (uint256 index) {
        index = nextIndex;
        if (index >= (uint256(1) << depth)) revert TreeFull();
        uint256 node = leaf;
        uint256 idx = index;
        for (uint8 i = 0; i < depth; i++) {
            if (idx & 1 == 0) {
                filledSubtrees[i] = node;
                node = PoseidonT3.hash(node, zeros[i]);
            } else {
                node = PoseidonT3.hash(filledSubtrees[i], node);
            }
            idx >>= 1;
        }
        nextIndex = index + 1;
        _setRoot(node, false);
        emit LeafInserted(index, leaf, node, epoch);
    }

    /// @param leaf current value at `index` (checked against the current root)
    /// @param siblings sibling at each level, bottom-up
    function zero(uint256 index, uint256 leaf, uint256[] calldata siblings) external onlyOwner {
        if (index >= nextIndex || siblings.length != depth || leaf == 0) revert InvalidPath();
        uint256 oldNode = leaf;
        uint256 newNode = 0;
        uint256 idx = index;
        uint256 last = nextIndex - 1;
        for (uint8 i = 0; i < depth; i++) {
            // Keep the insertion frontier consistent: the frontier node at level i
            // sits at the even position covering the last inserted leaf.
            uint256 frontier = (last >> i) & ~uint256(1);
            if (idx == frontier) filledSubtrees[i] = newNode;
            if (idx & 1 == 0) {
                oldNode = PoseidonT3.hash(oldNode, siblings[i]);
                newNode = PoseidonT3.hash(newNode, siblings[i]);
            } else {
                oldNode = PoseidonT3.hash(siblings[i], oldNode);
                newNode = PoseidonT3.hash(siblings[i], newNode);
            }
            idx >>= 1;
        }
        if (oldNode != currentRoot) revert InvalidPath();
        _setRoot(newNode, true);
        emit LeafZeroed(index, newNode, epoch);
    }

    function _setRoot(uint256 root, bool revocation) internal {
        epoch += 1;
        currentRoot = root;
        rootEpochPlusOne[root] = epoch + 1;
        if (revocation) minValidRootEpoch = epoch;
    }
}
