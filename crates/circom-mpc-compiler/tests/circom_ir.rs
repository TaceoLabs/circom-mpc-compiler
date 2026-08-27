use ark_bn254::Fr;
use circom_mpc_vm::driver::plain::PlainDriver;
use circom_mpc_vm::Machine;
use circom_mpc_compiler::CoCircomCompiler;
use circom_mpc_compiler::CompilerConfig;
use circom_mpc_compiler::OptLevel;

mod common;

use common::{circuit_path, inputs_from_test_name, libs_path};

/// Every opt level exercises `CoCircomCompiler::compile`'s unconditional MPC lowering and codegen
/// (there is no plaintext-only path), so this matrix makes every test below also a correctness
/// test for lowering and codegen, not just the frontend and the classical passes. The oracle is
/// agreement across opt levels; `tests/proving.rs`'s prove+verify tests are the value oracle.
const OPT_LEVELS: [OptLevel; 3] = [OptLevel::O0, OptLevel::O1, OptLevel::O2];

macro_rules! witness_extension_test_plain {
    ($name: ident) => {
        #[test]
        fn $name() {
            let inputs = inputs_from_test_name(stringify!($name));
            for input in &inputs {
                let mut prev: Option<Vec<Fr>> = None;
                for opt_level in OPT_LEVELS {
                    let mut config = CompilerConfig::default();
                    config.link_library.push(libs_path());
                    config.opt_level = opt_level;
                    let program =
                        CoCircomCompiler::compile(circuit_path(stringify!($name)), config).unwrap();

                    assert_eq!(program.statistics().inputs, input.len());

                    let classified = program.classify_inputs(input, |v| v);
                    let mut driver = PlainDriver;
                    let witness = Machine::run(&program, &mut driver, &classified).unwrap();

                    if let Some(prev) = &prev {
                        assert_eq!(&witness, prev, "opt_level {opt_level:?} disagrees with O0");
                    }
                    prev = Some(witness);
                }
            }
        }
    };
}

witness_extension_test_plain!(multiplier2);
witness_extension_test_plain!(multiplier3);
witness_extension_test_plain!(multiplier16);
witness_extension_test_plain!(loop_unrolling);
witness_extension_test_plain!(dead_code);
witness_extension_test_plain!(multiplier2_public);
witness_extension_test_plain!(constants_test);
witness_extension_test_plain!(babycheck_test);
// Exercises constant-condition `if`/`else` (`frontend/build.rs::handle_branch_bucket`).
witness_extension_test_plain!(control_flow);

#[test]
fn repeated_dynamic_operands_are_safe_at_o2() {
    let values = inputs_from_test_name("repeated_operands_o2").remove(0);
    let mut config = CompilerConfig::default();
    config.link_library.push(libs_path());
    config.opt_level = OptLevel::O2;
    let program = CoCircomCompiler::compile(circuit_path("repeated_operands_o2"), config).unwrap();
    let inputs = program.classify_inputs(&values, |v| v);
    let witness = Machine::run(&program, &mut PlainDriver, &inputs).unwrap();
    assert_eq!(witness[1], Fr::from(436u64));
}

fn run_o2_without_inputs(circuit: &str) -> Vec<Fr> {
    let mut config = CompilerConfig::default();
    config.link_library.push(libs_path());
    config.opt_level = OptLevel::O2;
    let program = CoCircomCompiler::compile(circuit_path(circuit), config).unwrap();
    assert_eq!(program.statistics().inputs, 0);
    let mut driver = PlainDriver;
    Machine::run(&program, &mut driver, &[]).unwrap()
}

#[test]
fn static_comparisons_use_circoms_signed_field_order_at_o2() {
    let witness = run_o2_without_inputs("static_signed_condition");
    assert_eq!(
        &witness[1..4],
        &[Fr::from(7u64), Fr::from(7u64), Fr::from(9u64)]
    );
}

#[test]
fn static_arithmetic_branch_roots_fold_at_o2() {
    let witness = run_o2_without_inputs("static_arithmetic_condition");
    assert_eq!(
        &witness[1..4],
        &[Fr::from(7u64), Fr::from(8u64), Fr::from(9u64)]
    );
}

#[test]
fn nested_component_at_absolute_offset_zero_is_not_the_root_at_o2() {
    // The main wrapper declares no signals, so Leaf's absolute signal offset is zero. Compiling and
    // running must still resolve Leaf's input from its caller rather than treating it as a main
    // input (which used to produce an out-of-bounds VM input index).
    run_o2_without_inputs("zero_offset_subcomponent");
}

// Only the circuits this compiler can actually run are wired up. The precomputation gadgets
// aren't wired up here - `tests/proving.rs`'s prove+verify tests cover them instead.
