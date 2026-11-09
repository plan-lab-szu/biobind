pragma circom 2.2.3;

// Unlinkable authentication relation R_priv (dev-workspace/notes/unlinkability-design.md §2.4).
// The full-vector match and both commitments reuse AuthDistance unchanged; the
// enrollment commitment becomes private and is bound only through a credential
// leaf in the credential tree. The capture signature is verified in circuit
// against a device key that is a member of the device tree, so neither the
// credential nor the device appears in the public statement.

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/eddsaposeidon.circom";
include "./auth_distance.circom";

// Poseidon(2) Merkle inclusion; pathIndices[i] = 1 means the running node is the right child.
template MerkleInclusion(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal output root;

    component hashers[depth];
    signal left[depth];
    signal right[depth];
    signal node[depth + 1];
    node[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        pathIndices[i] * (pathIndices[i] - 1) === 0;
        left[i] <== node[i] + pathIndices[i] * (pathElements[i] - node[i]);
        right[i] <== pathElements[i] + pathIndices[i] * (node[i] - pathElements[i]);
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== left[i];
        hashers[i].inputs[1] <== right[i];
        node[i + 1] <== hashers[i].out;
    }
    root <== node[depth];
}

template AuthPrivate(n, bits, qSpan, packSize, nBlocks, paddedBlocks, distanceBits, credDepth, devDepth) {
    var DST_ID = 3;
    var DST_LEAF = 4;
    var DST_DEV = 5;
    var DST_CAPTURE = 6;
    var DST_NULLIFIER = 7;

    // Public statement.
    signal input credRoot;
    signal input devRoot;
    signal input cProbe;
    signal input policyDigest;
    signal input ctxHash;
    signal input epsilon;
    signal input notAfter;
    signal input scope;
    signal input nullifier;

    // Credential witness.
    signal input identitySecret;
    signal input templateVersion;
    signal input cEnroll;
    signal input rEnroll;
    signal input rProbe;
    signal input enrollment[n];
    signal input probe[n];
    signal input credPathElements[credDepth];
    signal input credPathIndices[credDepth];

    // Device witness.
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

    // 1. Full-vector match between the private enrollment commitment and the probe.
    component match = AuthDistance(n, bits, qSpan, packSize, nBlocks, paddedBlocks, distanceBits);
    match.cEnroll <== cEnroll;
    match.cProbe <== cProbe;
    match.policyDigest <== policyDigest;
    match.ctxHash <== ctxHash;
    match.epsilon <== epsilon;
    match.rEnroll <== rEnroll;
    match.rProbe <== rProbe;
    for (var i = 0; i < n; i++) {
        match.enrollment[i] <== enrollment[i];
        match.probe[i] <== probe[i];
    }

    // 2. Credential leaf and membership in the credential tree.
    component idc = Poseidon(2);
    idc.inputs[0] <== DST_ID;
    idc.inputs[1] <== identitySecret;

    component leaf = Poseidon(5);
    leaf.inputs[0] <== DST_LEAF;
    leaf.inputs[1] <== cEnroll;
    leaf.inputs[2] <== idc.out;
    leaf.inputs[3] <== policyDigest;
    leaf.inputs[4] <== templateVersion;

    component credInclusion = MerkleInclusion(credDepth);
    credInclusion.leaf <== leaf.out;
    for (var i = 0; i < credDepth; i++) {
        credInclusion.pathElements[i] <== credPathElements[i];
        credInclusion.pathIndices[i] <== credPathIndices[i];
    }
    credInclusion.root === credRoot;

    // 3. Device leaf and membership in the device tree.
    component devLeaf = Poseidon(7);
    devLeaf.inputs[0] <== DST_DEV;
    devLeaf.inputs[1] <== devAx;
    devLeaf.inputs[2] <== devAy;
    devLeaf.inputs[3] <== devFirmware;
    devLeaf.inputs[4] <== devModel;
    devLeaf.inputs[5] <== devQuantization;
    devLeaf.inputs[6] <== policyDigest;

    component devInclusion = MerkleInclusion(devDepth);
    devInclusion.leaf <== devLeaf.out;
    for (var i = 0; i < devDepth; i++) {
        devInclusion.pathElements[i] <== devPathElements[i];
        devInclusion.pathIndices[i] <== devPathIndices[i];
    }
    devInclusion.root === devRoot;

    // 4. Capture statement signed by that device; it carries no credential identifier.
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
