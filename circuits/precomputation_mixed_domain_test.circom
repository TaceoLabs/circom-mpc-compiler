pragma circom 2.2.2;

include "@taceo/circom-lib/circuits/precomputations.circom";

// A host-precomputed site whose inputs mix Public and Shared: `a` is public (e.g. a domain
// separator), `b`/`c` are secret. At least one Shared input is still required (see
// `precomputation_all_public_test`), but a host-precomputed site need not be all-Shared.
template MixedDomainPrecomputation() {
    signal input a;
    signal input b;
    signal input c;
    signal output out[3];

    out <== TACEO_PRECOMPUTATION_Poseidon2(3)([a, b, c]);
}

component main {public [a]} = MixedDomainPrecomputation();
