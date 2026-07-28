use ark_bn254::Bn254;
use circom_mpc_compiler::interpreter::Interpreter;
use circom_mpc_compiler::CoCircomCompiler;
use circom_mpc_compiler::CompilerConfig;
use circom_mpc_compiler::OptLevel;

mod common;
mod misc;

use common::{circuit_path, from_test_name, libs_path, TestInputs};

/// Every opt level exercises `CoCircomCompiler::parse`'s unconditional MPC lowering (see
/// `docs/ARCHITECTURE.md`, "MPC lowering") - there is no plaintext-only path any more, so this
/// matrix is what makes every KAT below also a correctness test for the lowering, not just the
/// frontend and the classical passes.
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
                    let ast = CoCircomCompiler::<Bn254>::parse(circuit_path(stringify!($name)), config)
                        .unwrap();

                    assert_eq!(ast.num_inputs, inp.inputs[i].len());

                    let mut interpreter = Interpreter::new(ast, inp.inputs[i].clone());
                    let witness = interpreter.run();

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
// Every fixture below is wired up deliberately red: `ir::Op` only has Add/Sub/Mul as runtime ops
// (see docs/ARCHITECTURE.md), so most of these fail with a typed `unsupported operator: ...`
// error naming exactly which circom operator/instruction is missing. That failure list is the
// visible worklist for what the compiler doesn't support yet - do not delete a failing line
// without checking whether it's a real gap or something newly fixed.
witness_extension_test_plain!(mux1_1);
witness_extension_test_plain!(binsum_test);
witness_extension_test_plain!(binsub_test);
witness_extension_test_plain!(lessthan);
witness_extension_test_plain!(sum_test);
witness_extension_test_plain!(mux2_1);
witness_extension_test_plain!(mux3_1);
witness_extension_test_plain!(mux4_1);
witness_extension_test_plain!(greaterthan);
witness_extension_test_plain!(greatereqthan);
witness_extension_test_plain!(lesseqthan);
witness_extension_test_plain!(aliascheck_test);
witness_extension_test_plain!(babyadd_tester);
witness_extension_test_plain!(babycheck_test);
witness_extension_test_plain!(babypbk_test);
witness_extension_test_plain!(control_flow);
witness_extension_test_plain!(eddsa_test);
witness_extension_test_plain!(eddsa_verify);
witness_extension_test_plain!(eddsamimc_test);
witness_extension_test_plain!(eddsaposeidon_test);
witness_extension_test_plain!(edwards2montgomery);
witness_extension_test_plain!(escalarmul_test);
witness_extension_test_plain!(escalarmul_test_min);
witness_extension_test_plain!(escalarmulany_test);
witness_extension_test_plain!(escalarmulfix_test);
// escalarmulw4table (no _test suffix) has neither a circuit nor a kats dir - only
// escalarmulw4table_test / escalarmulw4table_test3 exist. Not wired up: there's nothing to load.
witness_extension_test_plain!(escalarmulw4table_test);
witness_extension_test_plain!(escalarmulw4table_test3);
witness_extension_test_plain!(functions);
witness_extension_test_plain!(isequal);
witness_extension_test_plain!(iszero);
witness_extension_test_plain!(mimc_hasher);
witness_extension_test_plain!(mimc_sponge_hash_test);
witness_extension_test_plain!(mimc_sponge_test);
witness_extension_test_plain!(mimc_test);
witness_extension_test_plain!(montgomery2edwards);
witness_extension_test_plain!(montgomeryadd);
witness_extension_test_plain!(montgomerydouble);
witness_extension_test_plain!(pedersen2_test);
witness_extension_test_plain!(pedersen_hasher);
witness_extension_test_plain!(pedersen_test);
witness_extension_test_plain!(pointbits_loopback);
witness_extension_test_plain!(poseidon3_test);
witness_extension_test_plain!(poseidon6_test);
witness_extension_test_plain!(poseidon_hasher1);
witness_extension_test_plain!(poseidon_hasher16);
witness_extension_test_plain!(poseidon_hasher2);
witness_extension_test_plain!(poseidonex_test);
witness_extension_test_plain!(sha256_2_test);
witness_extension_test_plain!(sha256_test448);
witness_extension_test_plain!(sha256_test512);
witness_extension_test_plain!(shared_control_flow);
witness_extension_test_plain!(shared_control_flow_arrays);
witness_extension_test_plain!(sign_test);
witness_extension_test_plain!(sqrt_test);
witness_extension_test_plain!(smtprocessor10_test);
witness_extension_test_plain!(smtverifier10_test);
witness_extension_test_plain!(winner);
witness_extension_test_plain!(bitonic_sort);
witness_extension_test_plain!(num2bits_accelerator);
