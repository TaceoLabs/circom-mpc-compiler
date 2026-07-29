use ark_bn254::{Bn254, Fr};
use circom_mpc_compiler::vm::driver::plain::PlainDriver;
use circom_mpc_compiler::vm::Machine;
use circom_mpc_compiler::CoCircomCompiler;
use circom_mpc_compiler::CompilerConfig;
use circom_mpc_compiler::OptLevel;

mod common;

use common::{circuit_path, inputs_from_test_name, libs_path};

/// Every opt level exercises `CoCircomCompiler::compile`'s unconditional MPC lowering and codegen
/// (see `docs/ARCHITECTURE.md`, "MPC lowering", "Bytecode and the slot machine") - there is no
/// plaintext-only path any more, so this matrix is what makes every test below also a correctness
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
                        CoCircomCompiler::<Bn254>::compile(circuit_path(stringify!($name)), config)
                            .unwrap();

                    assert_eq!(program.num_inputs, input.len());

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

// Only the circuits this compiler can actually run are wired up. `circuits/` and `kats/` still
// hold fixtures for everything it can't yet (the removed operator surface, unconstrained function
// calls, non-constant branches) - those stay as ready-made fixtures for when support lands. The
// inventory of what's missing lives in `docs/ARCHITECTURE.md`, "Known gaps", not in this file's
// failure list. The precomputation gadgets aren't wired up here - `tests/proving.rs`'s
// prove+verify tests cover them instead.
