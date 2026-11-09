pragma circom 2.2.3;

// R_priv with two constraint optimizations (dev-workspace/notes/biometric-lfw-results.md §7):
//  * commitment format v2: the Poseidon chain absorbs 15 packed blocks per
//    Poseidon(16) call instead of 2 per Poseidon(3) call (FORMAT_VERSION = 2,
//    domain-separated from v1; JS: commitment.mjs poseidonCommitmentWide);
//  * Merkle inclusion computes the right child linearly from the left child.
// Statement, trees, signature, and nullifier are otherwise identical to auth_private.circom.

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/eddsaposeidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "./lib/vector_packing.circom";

template PoseidonWideCommitment(nBlocks) {
    var WIDTH = 15;
    var chunks = (nBlocks + WIDTH - 1) \ WIDTH;
    signal input roleTag;
    signal input policyDigest;
    signal input contextDigest;
    signal input dimension;
    signal input salt;
    signal input packed[nBlocks];
    signal output out;

    signal chain[chunks + 1];
    component init = Poseidon(6);
    init.inputs[0] <== roleTag;
    init.inputs[1] <== 2; // FORMAT_VERSION
    init.inputs[2] <== policyDigest;
    init.inputs[3] <== contextDigest;
    init.inputs[4] <== dimension;
    init.inputs[5] <== salt;
    chain[0] <== init.out;

    component absorb[chunks];
    for (var c = 0; c < chunks; c++) {
        absorb[c] = Poseidon(WIDTH + 1);
        absorb[c].inputs[0] <== chain[c];
        for (var j = 0; j < WIDTH; j++) {
            var b = c * WIDTH + j;
            if (b < nBlocks) {
                absorb[c].inputs[j + 1] <== packed[b];
            } else {
                absorb[c].inputs[j + 1] <== 0;
            }
        }
        chain[c + 1] <== absorb[c].out;
    }
    out <== chain[chunks];
}

template MerkleInclusionLinear(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal output root;

    component hashers[depth];
    signal left[depth];
    signal node[depth + 1];
    node[0] <== leaf;
    for (var i = 0; i < depth; i++) {
        pathIndices[i] * (pathIndices[i] - 1) === 0;
        left[i] <== node[i] + pathIndices[i] * (pathElements[i] - node[i]);
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== left[i];
        hashers[i].inputs[1] <== node[i] + pathElements[i] - left[i];
        node[i + 1] <== hashers[i].out;
    }
    root <== node[depth];
}

template AuthPrivateV2(n, bits, qSpan, packSize, nBlocks, distanceBits, credDepth, devDepth) {
    var DST_ENROLL = 1;
    var DST_PROBE = 2;
    var DST_ID = 3;
    var DST_LEAF = 4;
    var DST_DEV = 5;
    var DST_CAPTURE = 6;
    var DST_NULLIFIER = 7;
    assert(n * qSpan * qSpan < 2 ** distanceBits);

    signal input credRoot;
    signal input devRoot;
    signal input cProbe;
    signal input policyDigest;
    signal input ctxHash;
    signal input epsilon;
    signal input notAfter;
    signal input scope;
    signal input nullifier;

    signal input identitySecret;
    signal input templateVersion;
    signal input cEnroll;
    signal input rEnroll;
    signal input rProbe;
    signal input enrollment[n];
    signal input probe[n];
    signal input credPathElements[credDepth];
    signal input credPathIndices[credDepth];
    signal input devAx;
    signal input devAy;
    signal input devFirmware;
    signal input devModel;
    signal input devQuantization;
    signal input devPathElements[devDepth];
    signal input devPathIndices[devDepth];
    signal input sigR8x;
    signal input sigR8y;
    signal input sigS;

    // 1. Packing with canonical coordinate ranges, v2 commitments, full-vector distance.
    var padded = nBlocks + (nBlocks % 2);
    component packE = PackedVector(n, bits, qSpan, packSize, nBlocks, padded);
    component packP = PackedVector(n, bits, qSpan, packSize, nBlocks, padded);
    for (var i = 0; i < n; i++) {
        packE.in[i] <== enrollment[i];
        packP.in[i] <== probe[i];
    }
    component comE = PoseidonWideCommitment(nBlocks);
    component comP = PoseidonWideCommitment(nBlocks);
    comE.roleTag <== DST_ENROLL;
    comE.policyDigest <== policyDigest;
    comE.contextDigest <== 0;
    comE.dimension <== n;
    comE.salt <== rEnroll;
    comP.roleTag <== DST_PROBE;
    comP.policyDigest <== policyDigest;
    comP.contextDigest <== ctxHash;
    comP.dimension <== n;
    comP.salt <== rProbe;
    for (var b = 0; b < nBlocks; b++) {
        comE.packed[b] <== packE.packed[b];
        comP.packed[b] <== packP.packed[b];
    }
    comE.out === cEnroll;
    comP.out === cProbe;

    signal difference[n];
    signal square[n];
    signal sum[n + 1];
    sum[0] <== 0;
    for (var i = 0; i < n; i++) {
        difference[i] <== enrollment[i] - probe[i];
        square[i] <== difference[i] * difference[i];
        sum[i + 1] <== sum[i] + square[i];
    }
    // Every coordinate is range-checked, so sum[n] < n*qSpan^2 < 2^distanceBits
    // without a separate Num2Bits; epsilon is pinned to the policy by the gateway.
    component epsilonRange = Num2Bits(distanceBits);
    epsilonRange.in <== epsilon;
    component within = LessEqThan(distanceBits + 1);
    within.in[0] <== sum[n];
    within.in[1] <== epsilon;
    within.out === 1;

    // 2. Credential leaf and membership.
    component idc = Poseidon(2);
    idc.inputs[0] <== DST_ID;
    idc.inputs[1] <== identitySecret;
    component leaf = Poseidon(5);
    leaf.inputs[0] <== DST_LEAF;
    leaf.inputs[1] <== cEnroll;
    leaf.inputs[2] <== idc.out;
    leaf.inputs[3] <== policyDigest;
    leaf.inputs[4] <== templateVersion;
    component credInclusion = MerkleInclusionLinear(credDepth);
    credInclusion.leaf <== leaf.out;
    for (var i = 0; i < credDepth; i++) {
        credInclusion.pathElements[i] <== credPathElements[i];
        credInclusion.pathIndices[i] <== credPathIndices[i];
    }
    credInclusion.root === credRoot;

    // 3. Device leaf and membership.
    component devLeaf = Poseidon(7);
    devLeaf.inputs[0] <== DST_DEV;
    devLeaf.inputs[1] <== devAx;
    devLeaf.inputs[2] <== devAy;
    devLeaf.inputs[3] <== devFirmware;
    devLeaf.inputs[4] <== devModel;
    devLeaf.inputs[5] <== devQuantization;
    devLeaf.inputs[6] <== policyDigest;
    component devInclusion = MerkleInclusionLinear(devDepth);
    devInclusion.leaf <== devLeaf.out;
    for (var i = 0; i < devDepth; i++) {
        devInclusion.pathElements[i] <== devPathElements[i];
        devInclusion.pathIndices[i] <== devPathIndices[i];
    }
    devInclusion.root === devRoot;

    // 4. Capture statement signed by that device.
    component captureMessage = Poseidon(8);
    captureMessage.inputs[0] <== DST_CAPTURE;
    captureMessage.inputs[1] <== cProbe;
    captureMessage.inputs[2] <== ctxHash;
    captureMessage.inputs[3] <== policyDigest;
    captureMessage.inputs[4] <== devModel;
    captureMessage.inputs[5] <== devQuantization;
    captureMessage.inputs[6] <== devFirmware;
    captureMessage.inputs[7] <== notAfter;
    component signature = EdDSAPoseidonVerifier();
    signature.enabled <== 1;
    signature.Ax <== devAx;
    signature.Ay <== devAy;
    signature.S <== sigS;
    signature.R8x <== sigR8x;
    signature.R8y <== sigR8y;
    signature.M <== captureMessage.out;

    // 5. Scope nullifier.
    component nf = Poseidon(3);
    nf.inputs[0] <== DST_NULLIFIER;
    nf.inputs[1] <== identitySecret;
    nf.inputs[2] <== scope;
    nf.out === nullifier;
}
