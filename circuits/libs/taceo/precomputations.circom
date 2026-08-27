pragma circom 2.2.2;

include "poseidon2.circom";

// `TACEO_PRECOMPUTATION_Poseidon2` is byte-for-byte the same template as an unwrapped `Poseidon2`
// call - same signals, same R1CS, same witness layout, so swapping a call site between the two
// invalidates nothing (no new zkey needed). The wrapper name is the only thing that differs, and it
// changes what the compiler does with the site: instead of `vm::gadgets` servicing it at run time,
// the host supplies its trace up front and `Machine::run_with_precomputation` inlines it. See
// `GadgetSite::precomputed`. Poseidon2 is the only gadget this compiler allows to be
// host-precomputed - see `GadgetKind::Poseidon2`'s eligibility in `handle_create_cmp_bucket`.
//
// Standard-library gadgets (`Num2Bits`, `IsZero`, `AliasCheck`) need no wrapper at all: the compiler
// recognizes them by their own circom name and always cuts them into a gadget site. An
// unwrapped `Poseidon2` is recognized and serviced the same way.

template TACEO_PRECOMPUTATION_Poseidon2(T) {
    signal input in[T];
    signal output out[T];

    out <== Poseidon2(T)(in);
}

// Declassifies `in` to every MPC party in the clear. A pure identity in-circuit (no constraint this
// compiler's own R1CS depends on beyond `out === in`), recognized by name the same way
// `TACEO_PRECOMPUTATION_Poseidon2` is - a real, explicit declassification decision, never inferred
// from dataflow. Revealing a Pedersen-style commitment (its randomizer stays secret) does not
// reveal the value it commits to; that is the intended use.
template TACEO_REVEAL(n) {
    signal input in[n];
    signal output out[n];

    out <== in;
}
