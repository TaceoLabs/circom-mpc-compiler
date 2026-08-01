//! Frontend behaviours a prove+verify test cannot express: the *typed* errors this compiler
//! produces for circom constructs it deliberately doesn't support, and the input metadata it derives
//! alongside the graph. The positive value cases live in `tests/proving.rs`.
//!

use ark_bn254::Bn254;
use circom_mpc_compiler::vm::program::Bank;
use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig};

mod common;

use common::{circuit_path, libs_path};

fn config() -> CompilerConfig {
    let mut config = CompilerConfig::default();
    config.link_library.push(libs_path());
    config
}

fn expect_unsupported(circuit: &str) -> String {
    match CoCircomCompiler::<Bn254>::parse(circuit_path(circuit), config()) {
        Ok(_) => panic!(
            "{circuit} compiled unexpectedly - if this is a genuine new capability, move it to a \
             witness-comparison test in tests/circom_ir.rs instead of deleting this assertion"
        ),
        Err(e) => e.to_string(),
    }
}

/// `IsZero`'s `inv <-- in!=0 ? 1/in : 0` branches on a genuine circuit value. Constant-condition
/// folding (`frontend/build.rs::handle_branch_bucket`, covered by `control_flow` in
/// `tests/circom_ir.rs`) deliberately does *not* reach this: there is no select/mux `ir::Op` to
/// arithmetize a secret-dependent branch into, so this must stay a clean error rather than become
/// a silently-wrong witness.
#[test]
fn non_constant_branch_condition_is_a_typed_error() {
    let msg = expect_unsupported("iszero");
    assert!(
        msg.contains("branch (if/else on a non-constant condition)"),
        "expected the non-constant-branch error, got: {msg}"
    );
}

/// Unconstrained function calls (`Instruction::Call`) remain unimplemented.
#[test]
fn function_call_is_a_typed_error() {
    let msg = expect_unsupported("functions");
    assert!(
        msg.contains("call to function"),
        "expected the function-call error, got: {msg}"
    );
}

/// The removed operator surface: `Num2Bits`' `(in >> i) & 1` on a genuine circuit input.
#[test]
fn non_constant_bitwise_operator_is_a_typed_error() {
    let msg = expect_unsupported("sum_test");
    assert!(
        msg.contains("only supported on compile-time constants"),
        "expected the non-constant-operator error, got: {msg}"
    );
}

/// `Graph::input_list` must be 0-based over the circuit's inputs, not in circom's witness numbering
/// (where the first input sits at `1 + num_outputs`, after the reserved constant and main's outputs).
/// Comparing the two numberings directly would misclassify a declared-public input as `Shared`
/// with one main output, or a secret input as public with more than one - which `Machine::run`
/// rejects.
#[test]
fn input_list_offsets_are_zero_based_and_public_inputs_are_classified_public() {
    let graph = CoCircomCompiler::<Bn254>::parse(circuit_path("multiplier2_public"), config())
        .expect("multiplier2_public compiles");
    assert_eq!(graph.public_inputs, vec!["a".to_owned()]);
    let mut offsets: Vec<(String, usize, usize)> = graph.input_list.clone();
    offsets.sort_by_key(|(_, start, _)| *start);
    assert_eq!(
        offsets,
        vec![("a".to_owned(), 0, 1), ("b".to_owned(), 1, 1)],
        "input offsets must be 0-based over inputs"
    );

    // And the classification that depends on them.
    let program = CoCircomCompiler::<Bn254>::compile(circuit_path("multiplier2_public"), config())
        .expect("multiplier2_public compiles");
    assert_eq!(
        program.input_domains,
        vec![Bank::Public, Bank::Shared],
        "`a` is declared public, `b` is not"
    );
}
