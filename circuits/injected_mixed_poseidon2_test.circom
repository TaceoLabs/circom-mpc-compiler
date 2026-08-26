pragma circom 2.2.2;

include "taceo/precomputations.circom";

// One injected and one non-injected Poseidon2 site, independent of each other so both land in the
// same network stage - they must still end up in two different batches, since an injected site's
// trace comes from the host and a non-injected one is serviced by the driver.
template MixedPoseidon2() {
    signal input a[3];
    signal input b[3];
    signal output injected[3];
    signal output computed[3];

    injected <== TACEO_INJECTED_Poseidon2(3)(a);
    computed <== TACEO_PRECOMPUTATION_Poseidon2(3)(b);
}

component main = MixedPoseidon2();
