pragma circom 2.2.3;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "./lib/vector_packing.circom";

template DistanceOnly(n, bits, qSpan, distanceBits) {
    assert(n > 0);
    assert(distanceBits > 0);
    assert(distanceBits <= 251);
    assert(n * qSpan * qSpan < 2 ** distanceBits);

    signal input epsilon;
    signal input enrollment[n];
    signal input probe[n];

    component enrollmentRange[n];
    component probeRange[n];
    signal difference[n];
    signal square[n];
    signal sum[n + 1];
    sum[0] <== 0;

    for (var coordinate = 0; coordinate < n; coordinate++) {
        enrollmentRange[coordinate] = CanonicalCoordinate(bits, qSpan);
        enrollmentRange[coordinate].in <== enrollment[coordinate];
        probeRange[coordinate] = CanonicalCoordinate(bits, qSpan);
        probeRange[coordinate].in <== probe[coordinate];

        difference[coordinate] <== enrollment[coordinate] - probe[coordinate];
        square[coordinate] <== difference[coordinate] * difference[coordinate];
        sum[coordinate + 1] <== sum[coordinate] + square[coordinate];
    }

    component distanceRange = Num2Bits(distanceBits);
    distanceRange.in <== sum[n];

    component epsilonRange = Num2Bits(distanceBits);
    epsilonRange.in <== epsilon;

    component withinThreshold = LessEqThan(distanceBits + 1);
    withinThreshold.in[0] <== sum[n];
    withinThreshold.in[1] <== epsilon;
    withinThreshold.out === 1;
}

