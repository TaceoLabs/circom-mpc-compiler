pragma circom 2.2.2;

include "taceo/precomputations.circom";

// A host-precomputed site with an all-Public input: nothing for the host to precompute, so this
// must be rejected at codegen rather than silently compiled as if it were an accelerated site.
component main {public [in]} = TACEO_PRECOMPUTATION_Poseidon2(3);
