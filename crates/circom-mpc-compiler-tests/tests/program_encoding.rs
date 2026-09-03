//! `Program::validate_encoding` against real compiled circuits, mutated into deliberately
//! malformed shapes via `Program::into_parts`.

use circom_mpc_compiler::CompilerConfig;
use circom_mpc_program::{Instruction, Program, RoundIdx, Slot};

fn program(circuit: &str) -> Program {
    let root = env!("CARGO_MANIFEST_DIR");
    let mut config = CompilerConfig::default();
    config
        .link_library
        .push(format!("{root}/../../circuits/node_modules/").into());
    circom_mpc_compiler::compile(format!("{root}/../../circuits/{circuit}.circom"), &config).unwrap()
}

#[test]
fn accepts_a_freshly_compiled_program() {
    program("multiplier2").validate_encoding().unwrap();
    program("gadget_iszero_test")
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
        .find(|instruction| matches!(instruction, Instruction::Arith { op: circom_mpc_program::Opcode::MulLocal, .. }))
        .expect("multiplier2's product is a genuine secret x secret multiplication");
    let Instruction::Arith { a, .. } = instruction else {
        unreachable!("just matched above")
    };
    *a = Slot::new(shared);
    assert!(Program::new(parts).validate_encoding().is_err());
}

#[test]
fn rejects_an_instruction_referencing_a_missing_round() {
    let mut parts = program("multiplier2").into_parts();
    let rounds_len = parts.rounds.len() as u32;
    let instruction = parts
        .instructions
        .iter_mut()
        .find(|instruction| matches!(instruction, Instruction::Reshare(_)))
        .expect("multiplier2's product needs one reshare round");
    *instruction = Instruction::Reshare(RoundIdx::new(rounds_len));
    assert!(Program::new(parts).validate_encoding().is_err());
}

#[test]
fn rejects_a_precompute_batch_with_wrong_input_count() {
    let mut parts = program("gadget_iszero_test").into_parts();
    parts.gadget_batches[0].input_slots.pop();
    assert!(Program::new(parts).validate_encoding().is_err());
}
