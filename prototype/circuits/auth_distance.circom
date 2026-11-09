pragma circom 2.2.3;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "./lib/vector_packing.circom";
include "./lib/poseidon_chain.circom";

template AuthDistance(n, bits, qSpan, packSize, nBlocks, paddedBlocks, distanceBits) {
    var DST_ENROLL = 1;
    var DST_PROBE = 2;
    var FORMAT_VERSION = 1;

    assert(n > 0);
    assert(distanceBits > 0);
    assert(distanceBits <= 251);
    assert(n * qSpan * qSpan < 2 ** distanceBits);

    signal input cEnroll;
    signal input cProbe;
    signal input policyDigest;
    signal input ctxHash;
    signal input epsilon;

    signal input rEnroll;
    signal input rProbe;
    signal input enrollment[n];
    signal input probe[n];

    component packedEnrollment =
        PackedVector(n, bits, qSpan, packSize, nBlocks, paddedBlocks);
    component packedProbe =
        PackedVector(n, bits, qSpan, packSize, nBlocks, paddedBlocks);

    for (var i = 0; i < n; i++) {
        packedEnrollment.in[i] <== enrollment[i];
        packedProbe.in[i] <== probe[i];
    }

    component enrollmentCommitment = PoseidonChainCommitment(paddedBlocks);
    enrollmentCommitment.roleTag <== DST_ENROLL;
    enrollmentCommitment.formatVersion <== FORMAT_VERSION;
    enrollmentCommitment.policyDigest <== policyDigest;
    enrollmentCommitment.contextDigest <== 0;
    enrollmentCommitment.dimension <== n;
    enrollmentCommitment.salt <== rEnroll;

    component probeCommitment = PoseidonChainCommitment(paddedBlocks);
    probeCommitment.roleTag <== DST_PROBE;
    probeCommitment.formatVersion <== FORMAT_VERSION;
    probeCommitment.policyDigest <== policyDigest;
    probeCommitment.contextDigest <== ctxHash;
    probeCommitment.dimension <== n;
    probeCommitment.salt <== rProbe;

    for (var block = 0; block < paddedBlocks; block++) {
        enrollmentCommitment.packed[block] <== packedEnrollment.packed[block];
        probeCommitment.packed[block] <== packedProbe.packed[block];
    }

    enrollmentCommitment.out === cEnroll;
    probeCommitment.out === cProbe;

    signal difference[n];
    signal square[n];
    signal sum[n + 1];
    sum[0] <== 0;

    for (var coordinate = 0; coordinate < n; coordinate++) {
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
