pragma circom 2.2.2;

include "taceo/precomputations.circom";

template Main() {
    signal input in[2];
    signal output out[2];

    signal isZeroOut[2];
    isZeroOut[0] <== TACEO_PRECOMPUTATION_IsZero()(in[0]);
    isZeroOut[1] <== TACEO_PRECOMPUTATION_IsZero()(in[1]);

    signal revealed0[1] <== TACEO_REVEAL(1)([isZeroOut[0]]);
    signal revealed1[1] <== TACEO_REVEAL(1)([isZeroOut[1]]);
    out[0] <== revealed0[0];
    out[1] <== revealed1[0];
}

component main = Main();
