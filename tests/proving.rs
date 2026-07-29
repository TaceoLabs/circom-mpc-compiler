//! The default test oracle for every circuit this compiler can compile: compute the witness, prove
//! it against a real zkey, verify the proof. A verifying proof checks the witness values *and* the
//! R1CS layout against circom simultaneously - strictly more than a golden `.wtns` byte comparison
//! (`tests/circom_ir.rs`) can, and the only oracle available for a circuit with no golden witness at
//! all (the `precomputation_*_test` gadgets below - see `docs/ARCHITECTURE.md`, "Known gaps").
//!
//! Each circuit needs its own checked-in zkey (`kats/proving/<name>.zkey`) from a locally-generated
//! toy powers-of-tau - fine for exercising plumbing, never for anything real. Regenerate all of them
//! with `scripts/gen-proving-artifacts.sh`; a test whose zkey is missing skips with a printed note
//! rather than failing, so `cargo test` stays green on a fresh clone before that script has run.
#![cfg(feature = "rep3")]

use ark_bn254::{Bn254, Fr};
use circom_mpc_compiler::vm::driver::plain::PlainDriver;
use circom_mpc_compiler::vm::driver::rep3::Rep3Driver;
use circom_mpc_compiler::vm::program::Bank;
use circom_mpc_compiler::vm::witness::split_witness;
use circom_mpc_compiler::vm::{Machine, Program};
use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig};
use circom_types::CheckElement;
use co_groth16::{CircomReduction, ConstraintMatrices, Groth16, ProvingKey, Rep3CoGroth16};
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::rep3::{
    combine_field_elements, share_field_element, Rep3PrimeFieldShare, Rep3State,
};
use mpc_net::local::LocalNetwork;
use rand::thread_rng;

mod common;

use common::{circuit_path, inputs_from_test_name, libs_path, manifest_dir};

fn compiled(name: &str) -> Program<Fr> {
    let mut config = CompilerConfig::default();
    config.link_library.push(libs_path());
    CoCircomCompiler::<Bn254>::compile(circuit_path(name), config)
        .unwrap_or_else(|e| panic!("{name} must compile: {e}"))
}

/// `kats/proving/<name>.zkey`: a snarkjs-format zkey over a locally-generated toy powers-of-tau (see
/// `scripts/gen-proving-artifacts.sh`). `None` if it hasn't been generated - every caller skips
/// cleanly rather than failing in that case.
fn zkey(name: &str) -> Option<(ConstraintMatrices<Fr>, ProvingKey<Bn254>)> {
    let path = format!("{}/kats/proving/{name}.zkey", manifest_dir());
    let file = std::fs::File::open(&path).ok()?;
    Some(
        circom_types::groth16::Zkey::<Bn254>::from_reader(file, CheckElement::No)
            .unwrap_or_else(|e| panic!("parsing {path}: {e}"))
            .into(),
    )
}

/// `kats/<name>/witness<i>.wtns`, if this circuit still has one - the `precomputation_*_test`
/// circuits don't (see the module doc), and proving does not need it, but comparing against it here
/// costs nothing extra for the circuits that do.
fn golden_witness(name: &str, i: usize) -> Option<Vec<Fr>> {
    let path = format!("{}/kats/{name}/witness{i}.wtns", manifest_dir());
    let file = std::fs::File::open(path).ok()?;
    Some(circom_types::Witness::<Fr>::from_reader(file).unwrap().values)
}

/// The full pipeline for one circuit, over every input fixture it has: plain witness (cross-checked
/// against the golden `.wtns` when one exists), 3-party rep3 witness (cross-checked against plain),
/// then a real co-groth16 proof that must verify.
fn prove_and_verify(name: &str) {
    let Some((matrices, pkey)) = zkey(name) else {
        eprintln!(
            "note: {name}: no kats/proving/{name}.zkey - run scripts/gen-proving-artifacts.sh. \
             skipping prove+verify."
        );
        return;
    };
    let program = compiled(name);
    // The authoritative split point between cleartext public inputs and the shared remainder - see
    // `vm::witness`'s module doc for why this comes from the zkey and not from `input_domains`.
    let n_pub = matrices.num_instance_variables;
    assert_eq!(
        program.signal_to_witness.len(),
        matrices.num_instance_variables + matrices.num_witness_variables,
        "{name}: this compiler's witness length disagrees with the zkey's - they were not built \
         from the same compilation"
    );

    for (i, values) in inputs_from_test_name(name).into_iter().enumerate() {
        let plain = {
            let inputs = program.classify_inputs(&values, |v| v);
            let mut driver = PlainDriver;
            Machine::run(&program, &mut driver, &inputs).unwrap()
        };
        if let Some(golden) = golden_witness(name, i) {
            assert_eq!(plain, golden, "{name}: input {i}: disagrees with circom's own witness");
        }

        let mut rng = thread_rng();
        let shares: Vec<[Rep3PrimeFieldShare<Fr>; 3]> = program
            .input_domains
            .iter()
            .zip(&values)
            .filter(|(bank, _)| matches!(bank, Bank::Shared))
            .map(|(_, &v)| share_field_element(v, &mut rng))
            .collect();

        // Each party needs one connection for witness extension and two for proving.
        let extension = LocalNetwork::new(3);
        let proving0 = LocalNetwork::new(3);
        let proving1 = LocalNetwork::new(3);

        let program = &program;
        let values = &values;
        let matrices = &matrices;
        let pkey = &pkey;
        let results: Vec<(Vec<Rep3PrimeFieldShare<Fr>>, _, Vec<Fr>)> = std::thread::scope(|scope| {
            extension
                .into_iter()
                .zip(proving0)
                .zip(proving1)
                .enumerate()
                .map(|(party, ((ext, p0), p1))| {
                    let shares = &shares;
                    scope.spawn(move || {
                        let mut state = Rep3State::new(&ext, A2BType::default()).unwrap();
                        let mut driver = Rep3Driver::new(&ext, &mut state);
                        let mut next = 0;
                        let inputs = program.classify_inputs(values, |_v| {
                            let s = shares[next][party];
                            next += 1;
                            s
                        });
                        let witness = Machine::run(program, &mut driver, &inputs).unwrap();
                        let full_witness = witness.clone();
                        let (public_inputs, secret) =
                            split_witness(&mut driver, witness, n_pub).unwrap();
                        let shared = co_circom_types::SharedWitness {
                            public_inputs: public_inputs.clone(),
                            witness: secret,
                        };
                        let proof = Rep3CoGroth16::prove::<_, CircomReduction>(
                            &p0, &p1, pkey, matrices, shared,
                        )
                        .unwrap();
                        (full_witness, proof, public_inputs)
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect()
        });

        let [(w0, _, _), (w1, _, _), (w2, _, _)]: [_; 3] =
            results.clone().try_into().unwrap_or_else(|_| panic!("{name}: expected 3 parties"));
        let rep3 = combine_field_elements(&w0, &w1, &w2);
        assert_eq!(rep3, plain, "{name}: input {i}: rep3 reconstruction disagrees with plain");

        let (_, proof, public) = &results[0];
        for (_, _, other) in &results[1..] {
            assert_eq!(public, other, "{name}: input {i}: parties disagree on the public inputs");
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

prove_and_verify_test!(multiplier2);
prove_and_verify_test!(multiplier3);
prove_and_verify_test!(multiplier16);
prove_and_verify_test!(loop_unrolling);
prove_and_verify_test!(dead_code);
prove_and_verify_test!(multiplier2_public);
prove_and_verify_test!(constants_test);
prove_and_verify_test!(babycheck_test);
prove_and_verify_test!(control_flow);

// No golden `.wtns` for these four (see the module doc) - `prove_and_verify` still runs the full
// plain/rep3/prove/verify pipeline, it just skips the golden-witness comparison.
prove_and_verify_test!(precomputation_poseidon2_test);
prove_and_verify_test!(precomputation_num2bits_test);
prove_and_verify_test!(precomputation_iszero_test);
prove_and_verify_test!(precomputation_aliascheck_test);

/// The split itself, against the plain driver - isolates a bad `n_pub` from a networking or proving
/// problem if `multiplier2`'s prove+verify test above ever fails.
#[test]
fn plain_witness_splits_at_the_zkey_boundary() {
    let Some((matrices, _)) = zkey("multiplier2") else {
        eprintln!("note: no kats/proving/multiplier2.zkey - run scripts/gen-proving-artifacts.sh. skipping.");
        return;
    };
    let program = compiled("multiplier2");
    let n_pub = matrices.num_instance_variables;

    let values = vec![Fr::from(7u64), Fr::from(6u64)];
    let inputs = program.classify_inputs(&values, |v| v);
    let mut driver = PlainDriver;
    let witness = Machine::run(&program, &mut driver, &inputs).unwrap();

    let (public, secret) = split_witness(&mut driver, witness.clone(), n_pub).unwrap();
    assert_eq!(public, vec![Fr::from(1u64), Fr::from(42u64)]);
    assert_eq!(public.len() + secret.len(), witness.len());
}
