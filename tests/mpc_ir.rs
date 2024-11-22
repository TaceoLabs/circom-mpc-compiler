use ark_bn254::Bn254;
use ark_ff::PrimeField;
use circom_mpc_compiler::mpc::plain::PlainExecutor;
use circom_mpc_compiler::mpc::rep3::Rep3Executor;
use circom_mpc_compiler::mpc_interpreter::MpcInterpreter;
use circom_mpc_compiler::CoCircomCompiler;
use circom_mpc_compiler::CompilerConfig;
use co_circom_snarks::SharedWitness;
use core::panic;
use itertools::izip;
use misc::Rep3TestNetwork;
use misc::Witness;
use mpc_core::protocols::rep3::combine_field_elements;
use mpc_core::protocols::rep3::share_field_elements;
use mpc_core::protocols::rep3::Rep3PrimeFieldShare;
use rand::thread_rng;
use std::{
    fs::{self, File},
    str::FromStr,
    thread,
};

mod misc;

#[derive(Debug)]
pub struct TestInputs {
    inputs: Vec<Vec<ark_bn254::Fr>>,
    witnesses: Vec<Witness<ark_bn254::Fr>>,
}

fn read_field_element(s: &str) -> ark_bn254::Fr {
    if let Some(striped) = s.strip_prefix('-') {
        -ark_bn254::Fr::from_str(striped).unwrap()
    } else {
        ark_bn254::Fr::from_str(s).unwrap()
    }
}

fn convert_witness<F: PrimeField>(mut witness: SharedWitness<F, F>) -> Vec<F> {
    witness.public_inputs.extend(witness.witness);
    witness.public_inputs
}

fn combine_field_elements_for_vm<F: PrimeField>(
    a: SharedWitness<F, Rep3PrimeFieldShare<F>>,
    b: SharedWitness<F, Rep3PrimeFieldShare<F>>,
    c: SharedWitness<F, Rep3PrimeFieldShare<F>>,
) -> Vec<F> {
    let mut res = Vec::with_capacity(a.public_inputs.len() + a.witness.len());
    for (a, b, c) in izip!(a.public_inputs, b.public_inputs, c.public_inputs) {
        assert_eq!(a, b);
        assert_eq!(b, c);
        res.push(a);
    }
    res.extend(combine_field_elements(a.witness, b.witness, c.witness));
    res
}

macro_rules! witness_extension_test_plain {
    ($name: ident) => {
        #[test]
        fn $name() {
            let inp: TestInputs = from_test_name(stringify!($name));
            for i in 0..inp.inputs.len() {
                let mut config = CompilerConfig::default();
                config.simplification = circom_mpc_compiler::SimplificationLevel::O2(usize::MAX);
                config.link_library.push("./circuits/libs/".into());
                let ast = CoCircomCompiler::<Bn254>::parse(
                    format!("./circuits/{}.circom", stringify!($name)),
                    config,
                )
                .unwrap();

                assert_eq!(ast.num_inputs, inp.inputs[i].len());

                let ast = circom_mpc_compiler::passes::mpc_ir_translation::translate(ast).unwrap();

                let mut interpreter =
                    MpcInterpreter::new(PlainExecutor::default(), ast, inp.inputs[i].clone());

                let witness = interpreter.run().unwrap();

                let values = convert_witness(witness);

                assert_eq!(values, inp.witnesses[i].values);
            }
        }
    };
}

macro_rules! witness_extension_test_rep3 {
    ($name: ident) => {
        #[test]
        fn $name() {
            let inp: TestInputs = from_test_name(stringify!($name));
            for i in 0..inp.inputs.len() {
                let mut rng = thread_rng();
                let num_inputs = inp.inputs[i].len();
                let inputs = share_field_elements(&inp.inputs[i], &mut rng);
                let test_network = Rep3TestNetwork::default();
                let mut threads = vec![];

                for (net, input) in test_network.get_party_networks().into_iter().zip(inputs) {
                    threads.push(thread::spawn(move || {
                        let mut config = CompilerConfig::default();
                        config.simplification =
                            circom_mpc_compiler::SimplificationLevel::O2(usize::MAX);
                        config.link_library.push("./circuits/libs/".into());
                        let ast = CoCircomCompiler::<Bn254>::parse(
                            format!("./circuits/{}.circom", stringify!($name)),
                            config,
                        )
                        .unwrap();

                        assert_eq!(ast.num_inputs, num_inputs);

                        let ast = circom_mpc_compiler::passes::mpc_ir_translation::translate(ast)
                            .unwrap();

                        dbg!(&ast);

                        let mut interpreter =
                            MpcInterpreter::new(Rep3Executor::new(net).unwrap(), ast, input);

                        interpreter.run().unwrap()
                    }));
                }
                let result3 = threads.pop().unwrap().join().unwrap();
                let result2 = threads.pop().unwrap().join().unwrap();
                let result1 = threads.pop().unwrap().join().unwrap();

                let is_signals = combine_field_elements_for_vm(result1, result2, result3);

                assert_eq!(is_signals, inp.witnesses[i].values);
            }
        }
    };
}

pub fn from_test_name(fn_name: &str) -> TestInputs {
    let mut witnesses: Vec<Witness<ark_bn254::Fr>> = Vec::new();
    let mut inputs: Vec<Vec<ark_bn254::Fr>> = Vec::new();
    let mut i = 0;
    loop {
        if fs::metadata(format!("./kats/{}/witness{}.wtns", fn_name, i)).is_err() {
            break;
        }
        let witness = File::open(format!("./kats/{}/witness{}.wtns", fn_name, i)).unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        witnesses.push(should_witness);
        let input_file = File::open(format!("./kats/{}/input{}.json", fn_name, i)).unwrap();
        let json_str: serde_json::Value = serde_json::from_reader(input_file).unwrap();
        let input = json_str
            .get("in")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|s| read_field_element(s.as_str().unwrap()))
            .collect::<Vec<_>>();
        inputs.push(input);
        i += 1
    }
    if i == 0 {
        panic!("no test for {fn_name}");
    }
    TestInputs { inputs, witnesses }
}

mod plain {
    use super::*;

    witness_extension_test_plain!(multiplier2);
    witness_extension_test_plain!(multiplier3);
    witness_extension_test_plain!(multiplier16);
    witness_extension_test_plain!(loop_unrolling);
    witness_extension_test_plain!(dead_code);
    witness_extension_test_plain!(multiplier2_public);
}
//witness_extension_test_plain!(aliascheck_test);
//witness_extension_test_plain!(babyadd_tester);
//witness_extension_test_plain!(babycheck_test);
//witness_extension_test_plain!(babypbk_test);
//witness_extension_test_plain!(binsub_test);
//witness_extension_test_plain!(binsum_test);
//witness_extension_test_plain!(constants_test);
//witness_extension_test_plain!(control_flow);
//witness_extension_test_plain!(eddsa_test);
//witness_extension_test_plain!(eddsa_verify);
//witness_extension_test_plain!(eddsamimc_test);
//witness_extension_test_plain!(eddsaposeidon_test);
//witness_extension_test_plain!(edwards2montgomery);
//witness_extension_test_plain!(escalarmul_test);
//witness_extension_test_plain!(escalarmul_test_min);
//witness_extension_test_plain!(escalarmulany_test);
//witness_extension_test_plain!(escalarmulfix_test);
//witness_extension_test_plain!(escalarmulw4table);
//witness_extension_test_plain!(escalarmulw4table_test);
//witness_extension_test_plain!(escalarmulw4table_test3);
//witness_extension_test_plain!(functions);
//witness_extension_test_plain!(greatereqthan);
//witness_extension_test_plain!(greaterthan);
//witness_extension_test_plain!(isequal);
//witness_extension_test_plain!(iszero);
//witness_extension_test_plain!(lesseqthan);
//witness_extension_test_plain!(lessthan);
//witness_extension_test_plain!(mimc_hasher);
//witness_extension_test_plain!(mimc_sponge_hash_test);
//witness_extension_test_plain!(mimc_sponge_test);
//witness_extension_test_plain!(mimc_test);
//witness_extension_test_plain!(montgomery2edwards);
//witness_extension_test_plain!(montgomeryadd);
//witness_extension_test_plain!(montgomerydouble);
//witness_extension_test_plain!(multiplier16);
//witness_extension_test_plain!(multiplier2);
//witness_extension_test_plain!(mux1_1);
//witness_extension_test_plain!(mux2_1);
//witness_extension_test_plain!(mux3_1);
//witness_extension_test_plain!(mux4_1);
//witness_extension_test_plain!(pedersen2_test);
//witness_extension_test_plain!(pedersen_hasher);
//witness_extension_test_plain!(pedersen_test);
//witness_extension_test_plain!(pointbits_loopback);
//witness_extension_test_plain!(poseidon3_test);
//witness_extension_test_plain!(poseidon6_test);
//witness_extension_test_plain!(poseidon_hasher1);
//witness_extension_test_plain!(poseidon_hasher16);
//witness_extension_test_plain!(poseidon_hasher2);
//witness_extension_test_plain!(poseidonex_test);
//witness_extension_test_plain!(sha256_2_test);
//witness_extension_test_plain!(sha256_test448);
//witness_extension_test_plain!(sha256_test512);
//witness_extension_test_plain!(shared_control_flow);
//witness_extension_test_plain!(shared_control_flow_arrays);
//witness_extension_test_plain!(sign_test);
//witness_extension_test_plain!(sqrt_test);
//witness_extension_test_plain!(smtprocessor10_test);
//witness_extension_test_plain!(smtverifier10_test);
//witness_extension_test_plain!(sum_test);
//witness_extension_test_plain!(winner);
//witness_extension_test_plain!(bitonic_sort);
//witness_extension_test_plain!(num2bits_accelerator);

mod rep3 {
    use super::*;

    witness_extension_test_rep3!(multiplier2);
    witness_extension_test_rep3!(multiplier3);
    witness_extension_test_rep3!(multiplier16);
    witness_extension_test_rep3!(loop_unrolling);
    witness_extension_test_rep3!(dead_code);
    // TODO should work if we can handle public inputs in tests
    // witness_extension_test_rep3!(multiplier2_public);
}
