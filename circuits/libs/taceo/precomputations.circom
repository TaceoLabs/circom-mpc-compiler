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

// Declassifies `in` to every MPC party in the clear. A pure identity in-circuit (no constraint this
// compiler's own R1CS depends on beyond `out === in`), recognized by name the same way the four
// `TACEO_PRECOMPUTATION_*` gadgets above are - a real, explicit declassification decision, never
// inferred from dataflow. Revealing a Pedersen-style commitment (its randomizer stays secret) does
// not reveal the value it commits to; that is the intended use.
template TACEO_REVEAL(n) {
    signal input in[n];
    signal output out[n];

    out <== in;
}
