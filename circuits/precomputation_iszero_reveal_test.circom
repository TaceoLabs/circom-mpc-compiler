pragma circom 2.2.2;

include "taceo/precomputations.circom";

template Main() {
    signal input in;
    signal output out;

    signal isZeroOut <== TACEO_PRECOMPUTATION_IsZero()(in);
    signal revealed[1] <== TACEO_REVEAL(1)([isZeroOut]);
    out <== revealed[0];
}

component main = Main();
