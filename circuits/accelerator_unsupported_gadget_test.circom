pragma circom 2.2.2;

// A gadget this compiler has no accelerator implementation for (only Poseidon2, Num2Bits, IsZero,
// IsEqual and AliasCheck are recognized, matched by their own circom name - see
// `handle_create_cmp_bucket` in `frontend/build.rs`). An unrecognized name just compiles its body
// like any ordinary template - `Doubler`'s body is deliberately pure Add/Sub/Mul so that succeeds
// rather than failing deeper on some unrelated gap, which is exactly the situation the vendored
// `merkle_root_4.circom` is in with its `Arity4CMux`.
template Doubler() {
    signal input in;
    signal output out;

    out <== in + in;
}

template WrapDoubler() {
    signal input in;
    signal output out;

    out <== Doubler()(in);
}

component main = WrapDoubler();
