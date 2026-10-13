//! `Program::new`'s encoding checks against real compiled circuits, mutated into deliberately
//! malformed shapes via `Program::into_parts`.

use circom_mpc_compiler::CompilerConfig;
use circom_mpc_program::{Instruction, Program, RoundIdx, Slot};

fn program(circuit: &str) -> Program {
    let root = env!("CARGO_MANIFEST_DIR");
    let mut config = CompilerConfig::default();
    config
        .link_library
        .push(format!("{root}/../../circuits/node_modules/").into());
    circom_mpc_compiler::compile(format!("{root}/../../circuits/{circuit}.circom"), &config)
        .unwrap()
}

#[test]
fn accepts_a_freshly_compiled_program() {
    for circuit in ["multiplier2", "gadget_iszero_test"] {
        Program::new(program(circuit).into_parts()).unwrap();
    }
}

#[test]
fn rejects_an_input_domain_count_mismatch() {
    let mut parts = program("multiplier2").into_parts();
    parts.input_domains.pop();
    let err = Program::new(parts).expect_err("one input domain per input");
    assert!(err.to_string().contains("input domain table has"), "{err}");
}

#[test]
fn rejects_an_instruction_slot_out_of_bank_bounds() {
    let mut parts = program("multiplier2").into_parts();
    let shared = parts.slots.shared;
    let instruction = parts
        .instructions
        .iter_mut()
        .find(|instruction| {
            matches!(
                instruction,
                Instruction::Arith {
                    op: circom_mpc_program::Opcode::MulLocal,
                    ..
                }
            )
        })
        .expect("multiplier2's product is a genuine secret x secret multiplication");
    let Instruction::Arith { a, .. } = instruction else {
        unreachable!("just matched above")
    };
    *a = Slot::new(shared);
    let err = Program::new(parts).expect_err("a slot past the Shared bank is out of bounds");
    assert!(err.to_string().contains("bank size is"), "{err}");
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
    let err = Program::new(parts).expect_err("a reshare of a missing round is malformed");
    assert!(err.to_string().contains("missing round"), "{err}");
}

#[test]
fn rejects_a_precompute_batch_with_wrong_input_count() {
    let mut parts = program("gadget_iszero_test").into_parts();
    parts.gadget_batches[0].input_slots.pop();
    let err = Program::new(parts).expect_err("a batch must have t inputs per site");
    assert!(err.to_string().contains("inputs, expected"), "{err}");
}
