pragma circom 2.2.3;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

// Measurement stand-in for the threshold statement of the homomorphic strategies.
// Public inputs: the reconstructed distance commitment c'_delta as four 128-bit limbs
// and the threshold tau. The circuit range-checks delta and enforces delta <= tau but
// does NOT prove that c'_delta opens to delta (that needs non-native BN254 arithmetic).
// Groth16 verification gas depends only on the number of public inputs, so the on-chain
// cost equals that of a full opening-and-range circuit with the same five inputs.
template ThresholdStandIn() {
    signal input cxHi;
    signal input cxLo;
    signal input cyHi;
    signal input cyLo;
    signal input tau;
    signal input delta;

    component deltaBits = Num2Bits(48);
    deltaBits.in <== delta;
    component tauBits = Num2Bits(48);
    tauBits.in <== tau;
    component le = LessEqThan(48);
    le.in[0] <== delta;
    le.in[1] <== tau;
    le.out === 1;

    // Tie the limbs into the constraint system.
    signal bindX;
    signal bindY;
    bindX <== cxHi * cxLo;
    bindY <== cyHi * cyLo;
}

component main {public [cxHi, cxLo, cyHi, cyLo, tau]} = ThresholdStandIn();
