pragma circom 2.2.2;

include "bitify.circom";

// A malformed `TACEO_INJECTED_Poseidon2` that actually wraps `Num2Bits` - the frontend must reject
// this rather than silently treating it as an injected `Num2Bits` site (which isn't injectable at
// all). A real `TACEO_INJECTED_Poseidon2` never looks like this (`taceo/precomputations.circom`'s
// own definition always wraps `Poseidon2`); this file defines its own same-named template instead
// of including the real one, purely to exercise `handle_create_cmp_bucket`'s wrapper/kind check.
template TACEO_INJECTED_Poseidon2(n) {
    signal input in;
    signal output out[n];

    out <== Num2Bits(n)(in);
}

component main = TACEO_INJECTED_Poseidon2(8);
