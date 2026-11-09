pragma circom 2.2.3;

include "circomlib/circuits/poseidon.circom";

template PoseidonChainCommitment(paddedBlocks) {
    assert(paddedBlocks > 0);
    assert(paddedBlocks % 2 == 0);

    signal input roleTag;
    signal input formatVersion;
    signal input policyDigest;
    signal input contextDigest;
    signal input dimension;
    signal input salt;
    signal input packed[paddedBlocks];
    signal output out;

    var rounds = paddedBlocks / 2;
    signal chain[rounds + 1];

    component init = Poseidon(6);
    init.inputs[0] <== roleTag;
    init.inputs[1] <== formatVersion;
    init.inputs[2] <== policyDigest;
    init.inputs[3] <== contextDigest;
    init.inputs[4] <== dimension;
    init.inputs[5] <== salt;
    chain[0] <== init.out;

    component absorb[rounds];
    for (var i = 0; i < rounds; i++) {
        absorb[i] = Poseidon(3);
        absorb[i].inputs[0] <== chain[i];
        absorb[i].inputs[1] <== packed[2 * i];
        absorb[i].inputs[2] <== packed[2 * i + 1];
        chain[i + 1] <== absorb[i].out;
    }

    out <== chain[rounds];
}

