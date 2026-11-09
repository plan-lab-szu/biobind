// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IThresholdVerifier {
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[5] calldata pubSignals
    ) external view returns (bool);
}

/// @notice Complete on-chain verifier for the homomorphic strategies (FullCheck when
///         sampleCount == N, SpotCheck otherwise): nonce state, enrollment digest,
///         Fiat-Shamir challenge over all commitments and first messages, sample
///         derivation from block randomness, per-coordinate equations, distance
///         reconstruction, and the threshold Groth16 verifier.
/// @dev Benchmark code. The generator h = 5G has a known discrete log, which is insecure
///      for a real Pedersen commitment but has the same EVM cost. Group-operation helpers
///      match PedersenSamplingVerifier so that the two measurements are comparable.
contract HomomorphicCompleteVerifier {
    uint256 internal constant Q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 internal constant R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant HX =
        10744596414106452074759370245733544594153395043370666422502510773307029471145;
    uint256 internal constant HY =
        848677436511517736191562425154572367705380862894644942948681172815252343932;

    struct Point {
        uint256 x;
        uint256 y;
    }

    /// Per-coordinate arrays have length N; alpha and beta have length 3N indexed 3i+l
    /// for l in (ee, pp, ep); z has length 9N indexed 9i+3l+k for k in (m, r, u).
    struct Transcript {
        Point[] ce;
        Point[] cp;
        Point[] cee;
        Point[] cpp;
        Point[] cep;
        Point[] alpha;
        Point[] beta;
        uint256[] z;
        uint256[2] pA;
        uint256[2][2] pB;
        uint256[2] pC;
    }

    uint256 public immutable vectorLength;
    uint256 public immutable sampleCount;
    uint256 public immutable threshold;
    bytes32 public immutable ctxHash;
    IThresholdVerifier public immutable thresholdVerifier;

    mapping(uint256 => bytes32) public enrollmentDigest;
    mapping(uint256 => uint256) public lastNonce;

    event Enrolled(uint256 indexed id);
    event Authenticated(uint256 indexed id, uint256 nonce);

    error AlreadyEnrolled();
    error NotEnrolled();
    error StaleNonce();
    error InvalidLength();
    error EnrollmentMismatch();
    error InvalidConsistencyProof(uint256 index);
    error ThresholdProofRejected();

    constructor(uint256 n, uint256 t, uint256 tau, IThresholdVerifier verifier) {
        require(n > 0 && t > 0 && t <= n, "bad parameters");
        vectorLength = n;
        sampleCount = t;
        threshold = tau;
        thresholdVerifier = verifier;
        ctxHash = keccak256(abi.encode("BioZero/hom/v1", block.chainid, address(this), n, tau, HX, HY));
    }

    function enroll(uint256 id, Point[] calldata ce) external {
        if (enrollmentDigest[id] != bytes32(0)) revert AlreadyEnrolled();
        if (ce.length != vectorLength) revert InvalidLength();
        enrollmentDigest[id] = keccak256(abi.encode(ce));
        emit Enrolled(id);
    }

    function challengeOf(uint256 id, uint256 nonce, Transcript calldata tr) public view returns (uint256) {
        // Two chained hashes (stack depth); binds the same inputs as one hash.
        bytes32 h1 = keccak256(abi.encode(ctxHash, id, nonce, tr.ce, tr.cp, tr.cee));
        return uint256(keccak256(abi.encode(h1, tr.cpp, tr.cep, tr.alpha, tr.beta))) % R;
    }

    function authenticate(uint256 id, uint256 nonce, Transcript calldata tr) external {
        bytes32 digest = enrollmentDigest[id];
        if (digest == bytes32(0)) revert NotEnrolled();
        if (nonce <= lastNonce[id]) revert StaleNonce();
        uint256 n = vectorLength;
        if (
            tr.ce.length != n || tr.cp.length != n || tr.cee.length != n || tr.cpp.length != n ||
            tr.cep.length != n || tr.alpha.length != 3 * n || tr.beta.length != 3 * n || tr.z.length != 9 * n
        ) revert InvalidLength();
        if (keccak256(abi.encode(tr.ce)) != digest) revert EnrollmentMismatch();

        uint256 eps = challengeOf(id, nonce, tr);
        if (sampleCount == n) {
            for (uint256 i = 0; i < n; ++i) _checkCoordinate(tr, i, eps);
        } else {
            bytes32 seed = keccak256(abi.encode(eps, id, nonce, block.prevrandao));
            bool[] memory seen = new bool[](n);
            uint256 found;
            for (uint256 j = 0; found < sampleCount; ++j) {
                uint256 i = uint256(keccak256(abi.encode(seed, j))) % n;
                if (seen[i]) continue;
                seen[i] = true;
                ++found;
                _checkCoordinate(tr, i, eps);
            }
        }

        Point memory d = _reconstruct(tr, n);
        uint256[5] memory pub = [d.x >> 128, d.x & type(uint128).max, d.y >> 128, d.y & type(uint128).max, threshold];
        if (!thresholdVerifier.verifyProof(tr.pA, tr.pB, tr.pC, pub)) revert ThresholdProofRejected();

        lastNonce[id] = nonce;
        emit Authenticated(id, nonce);
    }

    function _checkCoordinate(Transcript calldata tr, uint256 i, uint256 eps) private view {
        Point memory g = Point(1, 2);
        Point memory h = Point(HX, HY);
        // ee: anchor ce, base ce; pp: anchor cp, base cp; ep: anchor cp, base ce
        if (
            !_relation(g, h, tr.ce[i], tr.ce[i], tr.cee[i], tr, 3 * i, 9 * i, eps) ||
            !_relation(g, h, tr.cp[i], tr.cp[i], tr.cpp[i], tr, 3 * i + 1, 9 * i + 3, eps) ||
            !_relation(g, h, tr.cp[i], tr.ce[i], tr.cep[i], tr, 3 * i + 2, 9 * i + 6, eps)
        ) revert InvalidConsistencyProof(i);
    }

    function _relation(
        Point memory g,
        Point memory h,
        Point memory anchor,
        Point memory base,
        Point memory target,
        Transcript calldata tr,
        uint256 fm,
        uint256 zi,
        uint256 eps
    ) private view returns (bool) {
        return
            _equation(g, h, anchor, tr.alpha[fm], tr.z[zi], tr.z[zi + 1], eps) &&
            _equation(base, h, target, tr.beta[fm], tr.z[zi], tr.z[zi + 2], eps);
    }

    function _equation(
        Point memory b1,
        Point memory b2,
        Point memory target,
        Point memory first,
        uint256 s1,
        uint256 s2,
        uint256 eps
    ) private view returns (bool) {
        Point memory left = _ecAdd(_ecMul(b1, s1), _ecMul(b2, s2));
        Point memory right = _ecAdd(first, _ecMul(target, eps));
        return left.x == right.x && left.y == right.y;
    }

    function _reconstruct(Transcript calldata tr, uint256 n) private view returns (Point memory d) {
        d = Point(0, 0);
        for (uint256 i = 0; i < n; ++i) {
            d = _ecAdd(d, tr.cee[i]);
            d = _ecAdd(d, tr.cpp[i]);
            Point memory twice = _ecAdd(tr.cep[i], tr.cep[i]);
            d = _ecAdd(d, _negate(twice));
        }
    }

    function _negate(Point memory p) private pure returns (Point memory) {
        if (p.x == 0 && p.y == 0) return p;
        return Point(p.x, p.y == 0 ? 0 : Q - p.y);
    }

    function _ecAdd(Point memory a, Point memory b) private view returns (Point memory result) {
        uint256[4] memory input = [a.x, a.y, b.x, b.y];
        bool success;
        assembly ("memory-safe") {
            success := staticcall(sub(gas(), 2000), 6, input, 128, result, 64)
        }
        require(success, "BN254 add failed");
    }

    function _ecMul(Point memory p, uint256 s) private view returns (Point memory result) {
        uint256[3] memory input = [p.x, p.y, s];
        bool success;
        assembly ("memory-safe") {
            success := staticcall(sub(gas(), 2000), 7, input, 96, result, 64)
        }
        require(success, "BN254 mul failed");
    }
}
