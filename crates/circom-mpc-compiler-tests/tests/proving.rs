//! The default test oracle for every circuit this compiler can compile: compute the witness, prove
//! it against a real zkey, verify the proof. A verifying proof checks the witness values *and* the
//! R1CS layout against circom simultaneously.
//!
//! Each circuit needs its generated zkey (`kats/proving/<name>.zkey`). Regenerate all of them with
//! `just gen-proving-artifacts`; missing keys are an error because these proof tests are mandatory.
use ark_bn254::{Bn254, Fr};
use circom_mpc_compiler::CompilerConfig;
use circom_mpc_vm::{Program, Vm, program::Bank};
use circom_types::CheckElement;
use co_groth16::{CircomReduction, ConstraintMatrices, Groth16, ProvingKey, Rep3CoGroth16};
use mpc_core::protocols::rep3::{
    Rep3PrimeFieldShare, Rep3State, combine_field_elements, conversion::A2BType,
    share_field_element,
};
use mpc_net::local::LocalNetwork;
use rand::thread_rng;

mod common;

use common::{circuit_path, inputs_from_test_name, libs_path, manifest_dir};

fn compiled(name: &str) -> Program {
    let mut config = CompilerConfig::default();
    config.link_library.push(libs_path());
    circom_mpc_compiler::compile(circuit_path(name), &config)
        .unwrap_or_else(|e| panic!("{name} must compile: {e}"))
}

/// `kats/proving/<name>.zkey`: a snarkjs-format zkey over a locally-generated toy powers-of-tau (see
/// `scripts/gen-proving-artifacts.sh`). `None` if it hasn't been generated - every caller skips
/// cleanly rather than failing in that case.
fn zkey(name: &str) -> (ConstraintMatrices<Fr>, ProvingKey<Bn254>) {
    let path = format!("{}/kats/proving/{name}.zkey", manifest_dir());
    let file = std::fs::File::open(&path).unwrap_or_else(|e| {
        panic!("missing mandatory proving key {path}: {e}; run `just gen-proving-artifacts`")
    });
    circom_types::groth16::Zkey::<Bn254>::from_reader(file, CheckElement::No)
        .unwrap_or_else(|e| panic!("parsing {path}: {e}"))
        .into()
}

/// The full pipeline for one circuit, over every input fixture it has: plain witness, 3-party rep3
/// witness (cross-checked against plain), then a real co-groth16 proof that must verify.
fn prove_and_verify(name: &str) {
    let (matrices, pkey) = zkey(name);
    let program = compiled(name);
    assert_eq!(
        program.statistics().witness_values,
        matrices.num_instance_variables + matrices.num_witness_variables,
        "{name}: this compiler's witness length disagrees with the zkey's - they were not built \
         from the same compilation"
    );
    // The authoritative split point between cleartext public inputs and the shared remainder -
    // `Vm::run` derives this from the program itself; cross-check it against the zkey's own count.
    assert_eq!(
        program.num_public_witness() as usize,
        matrices.num_instance_variables,
        "{name}: this compiler's public witness count disagrees with the zkey's"
    );

    for (i, values) in inputs_from_test_name(name).into_iter().enumerate() {
        let plain = {
            let inputs = program.classify_inputs(&values, |v| v);
            Vm::plain(&program).run(&inputs).unwrap().into_full()
        };

        let mut rng = thread_rng();
        let shares: Vec<[Rep3PrimeFieldShare<Fr>; 3]> = program
            .input_domains()
            .iter()
            .zip(&values)
            .filter(|(bank, _)| matches!(bank, Bank::Shared))
            .map(|(_, &v)| share_field_element(v, &mut rng))
            .collect();

        // Each party needs one connection for witness extension and one for proving.
        let extension = LocalNetwork::new(3);
        let proving = LocalNetwork::new(3);

        let program = &program;
        let values = &values;
        let matrices = &matrices;
        let pkey = &pkey;
        let results: Vec<(Vec<Rep3PrimeFieldShare<Fr>>, _, Vec<Fr>)> =
            std::thread::scope(|scope| {
                extension
                    .into_iter()
                    .zip(proving)
                    .enumerate()
                    .map(|(party, (ext, p))| {
                        let shares = &shares;
                        scope.spawn(move || {
                            let mut state = Rep3State::new(&ext, A2BType::default()).unwrap();
                            let vm = Vm::rep3(program, &ext, &mut state).unwrap();
                            let mut next = 0;
                            let inputs = program.classify_inputs(values, |_v| {
                                let s = shares[next][party];
                                next += 1;
                                s
                            });
                            let witness = vm.run(&inputs).unwrap();
                            let secret = witness.witness.clone();
                            let public_inputs = witness.public_inputs.clone();
                            let shared = co_circom_types::SharedWitness {
                                public_inputs: public_inputs.clone(),
                                witness: witness.witness,
                            };
                            let proof =
                                Rep3CoGroth16::prove_with_shamir_bridge::<_, CircomReduction>(
                                    &p, pkey, matrices, shared,
                                )
                                .unwrap();
                            (secret, proof, public_inputs)
                        })
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .map(|h| h.join().unwrap())
                    .collect()
            });

        let [(w0, _, _), (w1, _, _), (w2, _, _)]: [_; 3] = results
            .clone()
            .try_into()
            .unwrap_or_else(|_| panic!("{name}: expected 3 parties"));
        let mut rep3 = results[0].2.clone();
        rep3.extend(combine_field_elements(&w0, &w1, &w2));
        assert_eq!(
            rep3, plain,
            "{name}: input {i}: rep3 reconstruction disagrees with plain"
        );

        let (_, proof, public) = &results[0];
        for (_, _, other) in &results[1..] {
            assert_eq!(
                public, other,
                "{name}: input {i}: parties disagree on the public inputs"
            );
        }
        let vk = pkey.vk.clone();
        Groth16::<Bn254>::verify(&vk, proof, &public[1..]).unwrap_or_else(|e| {
            panic!(
                "{name}: input {i}: the proof did not verify: {e}\n\
                 the R1CS came from circom, so the fault is this compiler's witness (layout or a \
                 gadget), not the input fixture."
            )
        });
    }
}

macro_rules! prove_and_verify_test {
    ($name: ident) => {
        #[test]
        fn $name() {
            prove_and_verify(stringify!($name));
        }
    };
}

prove_and_verify_test!(multiplier3);
prove_and_verify_test!(multiplier16);
prove_and_verify_test!(loop_unrolling);
prove_and_verify_test!(dead_code);
prove_and_verify_test!(multiplier2_public);
prove_and_verify_test!(constants_test);
prove_and_verify_test!(babycheck_test);
prove_and_verify_test!(control_flow);

prove_and_verify_test!(gadget_poseidon2_test);
prove_and_verify_test!(gadget_num2bits_test);
prove_and_verify_test!(gadget_iszero_test);
prove_and_verify_test!(gadget_aliascheck_test);

/// The split itself, against the plain driver - isolates a bad `num_public_witness` from a
/// networking or proving problem if a prove+verify test above ever fails.
#[test]
fn plain_witness_splits_at_the_zkey_boundary() {
    let (matrices, _) = zkey("multiplier2_public");
    let program = compiled("multiplier2_public");
    assert_eq!(
        program.num_public_witness() as usize,
        matrices.num_instance_variables
    );

    let values = vec![Fr::from(7u64), Fr::from(6u64)];
    let inputs = program.classify_inputs(&values, |v| v);
    let witness = Vm::plain(&program).run(&inputs).unwrap();

    assert_eq!(
        witness.public_inputs,
        vec![Fr::from(1u64), Fr::from(42u64), Fr::from(7u64)]
    );
    assert_eq!(witness.len(), program.statistics().witness_values);
}
