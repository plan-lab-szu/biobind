pragma circom 2.2.3;
// Research baseline: same public leakage as AuthPrivateV2; matching is attested
// by the capture TCB. ZK remains necessary to hide the device and credential.
include "./auth_private_v2.circom";

template AuthPrivateAttested(credDepth, devDepth) {
    var DST_ENROLL = 1;
    var DST_PROBE = 2;
    var DST_ID = 3;
    var DST_LEAF = 4;
    var DST_DEV = 5;
    var DST_CAPTURE = 6;
    var DST_NULLIFIER = 7;

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

    // Matching/opening checks are trusted operations of the capture device.
    // Domain 8 cannot be confused with the capture-only statement (domain 6).
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
    component captureMessage = Poseidon(10);
    captureMessage.inputs[0] <== 8; // DST_ATTESTED_MATCH
    captureMessage.inputs[1] <== cEnroll;
    captureMessage.inputs[2] <== cProbe;
    captureMessage.inputs[3] <== ctxHash;
    captureMessage.inputs[4] <== policyDigest;
    captureMessage.inputs[5] <== devModel;
    captureMessage.inputs[6] <== devQuantization;
    captureMessage.inputs[7] <== devFirmware;
    captureMessage.inputs[8] <== notAfter;
    captureMessage.inputs[9] <== epsilon;
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
