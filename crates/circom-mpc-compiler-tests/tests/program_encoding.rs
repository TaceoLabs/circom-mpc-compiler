//! `Program::validate_encoding` against real compiled circuits, mutated into deliberately
//! malformed shapes via `Program::into_parts`.

use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig};
use circom_mpc_program::{Opcode, Program};

fn program(circuit: &str) -> Program {
    let root = env!("CARGO_MANIFEST_DIR");
    let mut config = CompilerConfig::default();
    config
        .link_library
        .push(format!("{root}/../../circuits/libs/").into());
    CoCircomCompiler::compile(format!("{root}/../../circuits/{circuit}.circom"), config).unwrap()
}

#[test]
fn accepts_a_freshly_compiled_program() {
    program("multiplier2").validate_encoding().unwrap();
    program("precomputation_iszero_test")
        .validate_encoding()
        .unwrap();
}

#[test]
fn rejects_an_input_domain_count_mismatch() {
    let mut parts = program("multiplier2").into_parts();
    parts.input_domains.pop();
    assert!(Program::new(parts).validate_encoding().is_err());
}

#[test]
fn rejects_an_instruction_slot_out_of_bank_bounds() {
    let mut parts = program("multiplier2").into_parts();
    let shared = parts.slots.shared;
    let instruction = parts
        .instructions
        .iter_mut()
        .find(|instruction| instruction.op == Opcode::MulLocal)
        .expect("multiplier2's product is a genuine secret x secret multiplication");
    instruction.a = shared;
    assert!(Program::new(parts).validate_encoding().is_err());
}

#[test]
fn rejects_an_instruction_referencing_a_missing_round() {
    let mut parts = program("multiplier2").into_parts();
    let rounds_len = parts.rounds.len() as u32;
    let instruction = parts
        .instructions
        .iter_mut()
        .find(|instruction| instruction.op == Opcode::Reshare)
        .expect("multiplier2's product needs one reshare round");
    instruction.a = rounds_len;
    assert!(Program::new(parts).validate_encoding().is_err());
}

#[test]
fn rejects_a_precompute_batch_with_wrong_input_count() {
    let mut parts = program("precomputation_iszero_test").into_parts();
    parts.precompute_batches[0].input_slots.pop();
    assert!(Program::new(parts).validate_encoding().is_err());
}
