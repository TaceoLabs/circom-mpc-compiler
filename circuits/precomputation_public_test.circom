pragma circom 2.2.2;

include "taceo/precomputations.circom";

template PublicPrecomputation() {
    signal input a;
    signal input b;
    signal output out;

    component za = TACEO_PRECOMPUTATION_IsZero();
    component zb = TACEO_PRECOMPUTATION_IsZero();
    za.in <== a;
    zb.in <== b;
    out <== za.out * zb.out;
}

component main {public [a, b]} = PublicPrecomputation();
