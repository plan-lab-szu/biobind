// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Measurement kernel for the legacy BioZero Pedersen spot-check path.
/// @dev This is benchmark code, not a production verifier. It instantiates
///      Pedersen-style equations in the EVM BN254 G1 group and checks the six
///      equations used for each sampled coordinate in the old manuscript.
contract PedersenSamplingVerifier {
    uint256 internal constant BN254_BASE_FIELD =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct Point {
        uint256 x;
        uint256 y;
    }

    struct RelationProof {
        Point alpha;
        Point beta;
        uint256 zM;
        uint256 zR;
        uint256 zU;
    }

    struct SampleProof {
        uint256 index;
        Point c0;
        Point c1;
        RelationProof square0;
        RelationProof square1;
        RelationProof cross01;
    }

    struct Transcript {
        uint256 challenge;
        Point[] c00;
        Point[] c11;
        Point[] c01;
        SampleProof[] samples;
    }

    uint256 public immutable vectorLength;

    error InvalidLength();
    error InvalidSample();
    error InvalidConsistencyProof();

    constructor(uint256 vectorLength_) {
        require(vectorLength_ > 0, "empty vector");
        vectorLength = vectorLength_;
    }

    /// @return distanceDigest Hash of the reconstructed full-vector distance commitment.
    function verifySpot(
        Transcript calldata transcript
    ) external view returns (bytes32 distanceDigest) {
        uint256 length = vectorLength;
        if (
            transcript.c00.length != length ||
            transcript.c11.length != length ||
            transcript.c01.length != length ||
            transcript.samples.length > length
        ) {
            revert InvalidLength();
        }

        Point memory distance = _reconstructDistance(transcript, length);
        _verifySamples(transcript, length);
        return keccak256(abi.encode(distance.x, distance.y));
    }

    function _reconstructDistance(
        Transcript calldata transcript,
        uint256 length
    ) private view returns (Point memory distance) {
        distance = Point(0, 0);
        for (uint256 i = 0; i < length; ++i) {
            distance = _ecAdd(distance, transcript.c00[i]);
            distance = _ecAdd(distance, transcript.c11[i]);
            Point memory doubledCross = _ecAdd(transcript.c01[i], transcript.c01[i]);
            distance = _ecAdd(distance, _negate(doubledCross));
        }
    }

    function _verifySamples(
        Transcript calldata transcript,
        uint256 length
    ) private view {
        uint256 previousIndex;
        for (uint256 j = 0; j < transcript.samples.length; ++j) {
            SampleProof calldata sample = transcript.samples[j];
            uint256 index = sample.index;
            if (index >= length || (j > 0 && index <= previousIndex)) {
                revert InvalidSample();
            }
            previousIndex = index;

            if (
                !_verifySample(
                    sample,
                    transcript.c00[index],
                    transcript.c11[index],
                    transcript.c01[index],
                    transcript.challenge
                )
            ) {
                revert InvalidConsistencyProof();
            }
        }
    }

    function _verifySample(
        SampleProof calldata sample,
        Point calldata target00,
        Point calldata target11,
        Point calldata target01,
        uint256 challenge
    ) private view returns (bool) {
        Point memory g = Point(1, 2);
        // H = 5*G. Knowing this discrete-log relation makes this benchmark
        // generator pair insecure for deployment, but does not change EVM cost.
        Point memory h = Point(
            10744596414106452074759370245733544594153395043370666422502510773307029471145,
            848677436511517736191562425154572367705380862894644942948681172815252343932
        );
        return
            _verifyRelation(
                g,
                h,
                sample.c0,
                sample.c0,
                target00,
                sample.square0,
                challenge
            ) &&
            _verifyRelation(
                g,
                h,
                sample.c1,
                sample.c1,
                target11,
                sample.square1,
                challenge
            ) &&
            _verifyRelation(
                g,
                h,
                sample.c1,
                sample.c0,
                target01,
                sample.cross01,
                challenge
            );
    }

    function _verifyRelation(
        Point memory g,
        Point memory h,
        Point memory source,
        Point memory multiplicationBase,
        Point memory target,
        RelationProof calldata proof,
        uint256 challenge
    ) private view returns (bool) {
        return
            _equation(
                g,
                h,
                source,
                proof.alpha,
                proof.zM,
                proof.zR,
                challenge
            ) &&
            _equation(
                multiplicationBase,
                h,
                target,
                proof.beta,
                proof.zM,
                proof.zU,
                challenge
            );
    }

    function _equation(
        Point memory base1,
        Point memory base2,
        Point memory target,
        Point memory firstMessage,
        uint256 response1,
        uint256 response2,
        uint256 challenge
    ) private view returns (bool) {
        Point memory left = _ecAdd(
            _ecMul(base1, response1),
            _ecMul(base2, response2)
        );
        Point memory right = _ecAdd(
            firstMessage,
            _ecMul(target, challenge)
        );
        return left.x == right.x && left.y == right.y;
    }

    function _negate(Point memory point) private pure returns (Point memory) {
        if (point.x == 0 && point.y == 0) return point;
        return Point(point.x, point.y == 0 ? 0 : BN254_BASE_FIELD - point.y);
    }

    function _ecAdd(
        Point memory a,
        Point memory b
    ) private view returns (Point memory result) {
        uint256[4] memory input = [a.x, a.y, b.x, b.y];
        bool success;
        assembly ("memory-safe") {
            success := staticcall(sub(gas(), 2000), 6, input, 128, result, 64)
        }
        require(success, "BN254 add failed");
    }

    function _ecMul(
        Point memory point,
        uint256 scalar
    ) private view returns (Point memory result) {
        uint256[3] memory input = [point.x, point.y, scalar];
        bool success;
        assembly ("memory-safe") {
            success := staticcall(sub(gas(), 2000), 7, input, 96, result, 64)
        }
        require(success, "BN254 mul failed");
    }
}
