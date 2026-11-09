pragma circom 2.2.3;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

template CanonicalCoordinate(bits, qSpan) {
    assert(bits > 0);
    assert(bits <= 240);
    assert(qSpan >= 0);
    assert(qSpan < 2 ** bits);

    signal input in;

    component bitRange = Num2Bits(bits);
    bitRange.in <== in;

    // Num2Bits(bits) already proves 0 <= in <= 2^bits-1.  Only add the
    // comparator when the policy uses a strict sub-range of that interval.
    // The MVP profile has qSpan=65535 and bits=16, so the old unconditional
    // comparator was redundant for every coordinate.
    if (qSpan < 2 ** bits - 1) {
        component exactRange = LessEqThan(bits + 1);
        exactRange.in[0] <== in;
        exactRange.in[1] <== qSpan;
        exactRange.out === 1;
    }
}

template PackedVector(n, bits, qSpan, packSize, nBlocks, paddedBlocks) {
    assert(n > 0);
    assert(packSize > 0);
    assert(bits * packSize <= 240);
    assert(nBlocks * packSize >= n);
    assert((nBlocks - 1) * packSize < n);
    assert(paddedBlocks >= nBlocks);
    assert(paddedBlocks % 2 == 0);

    signal input in[n];
    signal output packed[paddedBlocks];
    signal accumulator[nBlocks][packSize + 1];

    component coordinates[n];
    for (var i = 0; i < n; i++) {
        coordinates[i] = CanonicalCoordinate(bits, qSpan);
        coordinates[i].in <== in[i];
    }

    for (var block = 0; block < nBlocks; block++) {
        accumulator[block][0] <== 0;
        for (var offset = 0; offset < packSize; offset++) {
            var coordinateIndex = block * packSize + offset;
            if (coordinateIndex < n) {
                accumulator[block][offset + 1] <==
                    accumulator[block][offset] +
                    in[coordinateIndex] * (2 ** (bits * offset));
            } else {
                accumulator[block][offset + 1] <== accumulator[block][offset];
            }
        }
        packed[block] <== accumulator[block][packSize];
    }

    for (var pad = nBlocks; pad < paddedBlocks; pad++) {
        packed[pad] <== 0;
    }
}
