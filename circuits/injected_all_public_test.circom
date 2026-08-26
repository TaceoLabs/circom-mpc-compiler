pragma circom 2.2.2;

include "taceo/precomputations.circom";

// An injected site with an all-Public input: nothing for the host to precompute, so this must be
// rejected at codegen rather than silently compiled as if it were a `TACEO_PRECOMPUTATION_*` site.
component main {public [in]} = TACEO_INJECTED_Poseidon2(3);
