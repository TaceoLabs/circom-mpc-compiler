pragma circom 2.2.2;

include "@taceo/circom-lib/circuits/precomputations.circom";

// A host-precomputed site with an all-Public input: nothing for the host to precompute, so this
// compiles as an ordinary driver-serviced Poseidon2 site instead - the wrapper is a hint the
// domain analysis is free to ignore, not a hard requirement on the caller (e.g.
// `Poseidon2SpongeWithPrecomputation`, in `@taceo/circom-lib`'s `compression.circom`, wraps every
// permutation the same way regardless of whether its input ends up Public or Shared).
component main {public [in]} = TACEO_PRECOMPUTATION_Poseidon2(3);
