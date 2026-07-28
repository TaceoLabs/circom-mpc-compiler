use ark_bn254::Bn254;
use circom_mpc_compiler::vm::driver::plain::PlainDriver;
use circom_mpc_compiler::vm::Machine;
use circom_mpc_compiler::CoCircomCompiler;
use circom_mpc_compiler::CompilerConfig;
use circom_mpc_compiler::OptLevel;

mod common;

use common::{circuit_path, from_test_name, libs_path, TestInputs};

/// Every opt level exercises `CoCircomCompiler::compile`'s unconditional MPC lowering and codegen
/// (see `docs/ARCHITECTURE.md`, "MPC lowering", "Bytecode and the slot machine") - there is no
/// plaintext-only path any more, so this matrix is what makes every KAT below also a correctness
/// test for lowering and codegen, not just the frontend and the classical passes.
const OPT_LEVELS: [OptLevel; 3] = [OptLevel::O0, OptLevel::O1, OptLevel::O2];

macro_rules! witness_extension_test_plain {
    ($name: ident) => {
        #[test]
        fn $name() {
            let inp: TestInputs = from_test_name(stringify!($name));
            for opt_level in OPT_LEVELS {
                for i in 0..inp.inputs.len() {
                    let mut config = CompilerConfig::default();
                    config.simplification = circom_mpc_compiler::SimplificationLevel::O2(usize::MAX);
                    config.link_library.push(libs_path());
                    config.opt_level = opt_level;
                    let program =
                        CoCircomCompiler::<Bn254>::compile(circuit_path(stringify!($name)), config)
                            .unwrap();

                    assert_eq!(program.num_inputs, inp.inputs[i].len());

                    let inputs = program.classify_inputs(&inp.inputs[i], |v| v);
                    let mut driver = PlainDriver;
                    let witness = Machine::run(&program, &mut driver, &inputs).unwrap();

                    assert_eq!(witness, inp.witnesses[i].values, "opt_level {opt_level:?}, input {i}");
                }
            }
        }
    };
}

/// Same shape as `witness_extension_test_plain!`, but at `SimplificationLevel::O0` instead of
/// `O2(usize::MAX)`. The `TACEO_PRECOMPUTATION_*` wrapper circuits below have a genuine subtree
/// under the wrapped (inner) component - the wrapper's own I/O plus the inner component's own I/O
/// both land in the witness (see `ir::PrecomputeKind`, `vm::gadgets`) - and *how much* of that
/// subtree survives into the witness is simplification-level-sensitive (confirmed empirically:
/// `circom --O0` on the exact same vendored circom revision this crate depends on produces a
/// witness whose length matches this crate's own `Program::signal_to_witness.len()` exactly at
/// `O0`; other levels do not). The golden `.wtns` fixtures below were generated the same way, so
/// this must match. See `docs/ARCHITECTURE.md`, "Precomputation".
macro_rules! witness_extension_test_precompute {
    ($name: ident) => {
        #[test]
        fn $name() {
            let inp: TestInputs = from_test_name(stringify!($name));
            for opt_level in OPT_LEVELS {
                for i in 0..inp.inputs.len() {
                    let mut config = CompilerConfig::default();
                    config.simplification = circom_mpc_compiler::SimplificationLevel::O0;
                    config.link_library.push(libs_path());
                    config.opt_level = opt_level;
                    let program =
                        CoCircomCompiler::<Bn254>::compile(circuit_path(stringify!($name)), config)
                            .unwrap();

                    assert_eq!(program.num_inputs, inp.inputs[i].len());

                    let inputs = program.classify_inputs(&inp.inputs[i], |v| v);
                    let mut driver = PlainDriver;
                    let witness = Machine::run(&program, &mut driver, &inputs).unwrap();

                    assert_eq!(witness, inp.witnesses[i].values, "opt_level {opt_level:?}, input {i}");
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
// failure list.
witness_extension_test_precompute!(precomputation_poseidon2_test);
witness_extension_test_precompute!(precomputation_num2bits_test);
witness_extension_test_precompute!(precomputation_iszero_test);
witness_extension_test_precompute!(precomputation_aliascheck_test);
