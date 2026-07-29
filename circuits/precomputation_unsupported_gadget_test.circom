pragma circom 2.2.2;

// A gadget this compiler has no precomputation implementation for (only Poseidon2, Num2Bits,
// IsZero, IsEqual and AliasCheck are recognized - see docs/ARCHITECTURE.md, "Precomputation"),
// wrapped in the TACEO_PRECOMPUTATION_* naming convention regardless. An unrecognized name just
// compiles its body like any ordinary template - `Doubler`'s body is deliberately pure Add/Sub/Mul
// so that succeeds rather than failing deeper on some unrelated gap, which is exactly the situation
// the vendored `merkle_root_4.circom` is in with its `Arity4CMux`.
template Doubler() {
    signal input in;
    signal output out;

    out <== in + in;
}

template TACEO_PRECOMPUTATION_Doubler() {
    signal input in;
    signal output out;

    out <== Doubler()(in);
}

component main = TACEO_PRECOMPUTATION_Doubler();
