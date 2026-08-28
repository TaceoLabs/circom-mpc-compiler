pragma circom 2.2.2;

include "taceo/poseidon2.circom";

// The driver-serviced twin of `precomputation_mixed_domain_test.circom` - same signal layout
// (`a` public, `b`/`c` secret), an unwrapped `Poseidon2` call instead of the
// `TACEO_PRECOMPUTATION_Poseidon2` wrapper. `TACEO_PRECOMPUTATION_Poseidon2` is byte-for-byte the
// same template as `Poseidon2`, so the two circuits produce identical witnesses.
template MixedDomainGadget() {
    signal input a;
    signal input b;
    signal input c;
    signal output out[3];

    out <== Poseidon2(3)([a, b, c]);
}

component main {public [a]} = MixedDomainGadget();
