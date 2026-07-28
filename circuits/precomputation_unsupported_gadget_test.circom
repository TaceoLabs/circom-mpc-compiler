pragma circom 2.2.2;

// A TACEO_PRECOMPUTATION_* wrapper around a gadget this compiler has no precomputation
// implementation for (only Poseidon2, Num2Bits, IsZero, IsEqual and AliasCheck are recognized - see
// docs/ARCHITECTURE.md, "Precomputation"). Exercises both halves of
// `CompilerConfig::unknown_precompute_gadget`:
//
//   - `Error` (the default): a typed `Unsupported::PrecomputeGadget` naming `Doubler`.
//   - `Warn`: a warning, then the wrapped body is compiled like any ordinary template.
//
// `Doubler`'s body is deliberately pure Add/Sub/Mul so the `Warn` path *succeeds* rather than failing
// deeper on some unrelated gap - which is exactly the situation the vendored `merkle_root_4.circom`
// is in with its unrecognized `TACEO_PRECOMPUTATION_Arity4CMux` wrapper, the real circuit this knob
// exists for.
//
// (This fixture used to wrap `IsEqual`, which stopped being unrecognized once `PrecomputeKind`
// gained an `IsEqual` variant for the bare-gadget path.)
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
