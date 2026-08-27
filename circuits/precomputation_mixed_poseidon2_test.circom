pragma circom 2.2.2;

include "taceo/precomputations.circom";
include "taceo/poseidon2.circom";

// One host-precomputed and one accelerated (driver-serviced) Poseidon2 site, independent of each
// other so both land in the same network stage - they must still end up in two different batches,
// since a host-precomputed site's trace comes from the host and an accelerated one is serviced by
// the driver.
template MixedPoseidon2() {
    signal input a[3];
    signal input b[3];
    signal output precomputed[3];
    signal output computed[3];

    precomputed <== TACEO_PRECOMPUTATION_Poseidon2(3)(a);
    computed <== Poseidon2(3)(b);
}

component main = MixedPoseidon2();
