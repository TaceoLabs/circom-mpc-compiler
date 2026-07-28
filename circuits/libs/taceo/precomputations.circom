pragma circom 2.2.2;

include "poseidon2.circom";
include "aliascheck.circom";
include "bitify.circom";
include "comparators.circom";

template TACEO_PRECOMPUTATION_Poseidon2(T) {
    signal input in[T];
    signal output out[T];

    out <== Poseidon2(T)(in);
}

template TACEO_PRECOMPUTATION_Num2Bits(n) {
    signal input in;
    signal output out[n];

    out <== Num2Bits(n)(in);
}

template TACEO_PRECOMPUTATION_AliasCheck() {
    signal input in[254];

    AliasCheck()(in);
}

template TACEO_PRECOMPUTATION_IsZero() {
    signal input in;
    signal output out;

    out <== IsZero()(in);
}
