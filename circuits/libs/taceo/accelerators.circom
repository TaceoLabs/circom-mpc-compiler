pragma circom 2.2.2;

include "poseidon2.circom";
include "aliascheck.circom";
include "bitify.circom";
include "comparators.circom";

// Name-only wrappers for the std-lib gadgets this compiler services out of band
// (`vm::gadgets`). The compiler recognizes these gadgets by their own circom name
// (`Poseidon2`/`Num2Bits`/`IsZero`/`AliasCheck`) regardless of whether a wrapper encloses them, so
// these templates exist purely to document intent at merces' call sites - not for compiler
// recognition. Kept as a separate include from `precomputations.circom` (whose
// `TACEO_PRECOMPUTATION_Poseidon2` marks the unrelated, host-precomputed case) so a circuit that
// only wants accelerator wrappers doesn't pull in the precomputation/reveal marker too.

template TACEO_ACCELERATOR_Poseidon2(T) {
    signal input in[T];
    signal output out[T];

    out <== Poseidon2(T)(in);
}

template TACEO_ACCELERATOR_Num2Bits(n) {
    signal input in;
    signal output out[n];

    out <== Num2Bits(n)(in);
}

template TACEO_ACCELERATOR_AliasCheck() {
    signal input in[254];

    AliasCheck()(in);
}

template TACEO_ACCELERATOR_IsZero() {
    signal input in;
    signal output out;

    out <== IsZero()(in);
}
