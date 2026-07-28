//! Proves and verifies a real co-groth16 proof over a witness this VM produced, end to end:
//! 3-party rep3 witness extension -> `vm::witness::to_shared_witness` -> `Rep3CoGroth16::prove` ->
//! `Groth16::verify`.
//!
//! Uses `multiplier2` and a **checked-in 2.5 KB zkey** (`kats/proving/`) so the path is permanently
//! covered with no external prerequisites. `tests/merces.rs`'s proving test is the same pipeline on a
//! real circuit, but its zkey is far too large to commit and has to be generated
//! (`scripts/gen-merces-artifacts.sh`), so it skips by default - which would otherwise leave this
//! whole integration untested.
//!
//! The zkey comes from a toy powers-of-tau generated locally
//! (`snarkjs powersoftau new bn128 8`, one contribution). That is fine here and *only* here: the
//! point is to exercise the plumbing, not to be a trusted setup. Never reuse it for anything real.
//!
//! Regenerate with:
//! ```text
//! circom circuits/multiplier2.circom --r1cs --O2 -o kats/proving
//! snarkjs powersoftau new bn128 8 pot0.ptau
//! snarkjs powersoftau contribute pot0.ptau pot1.ptau --name=probe -e=entropy
//! snarkjs powersoftau prepare phase2 pot1.ptau pot.ptau
//! snarkjs groth16 setup kats/proving/multiplier2.r1cs pot.ptau kats/proving/multiplier2.zkey
//! ```
#![cfg(feature = "proving")]

use ark_bn254::{Bn254, Fr};
use circom_mpc_compiler::vm::driver::plain::PlainDriver;
use circom_mpc_compiler::vm::driver::rep3::Rep3Driver;
use circom_mpc_compiler::vm::program::Bank;
use circom_mpc_compiler::vm::witness::{split_witness, to_shared_witness};
use circom_mpc_compiler::vm::{Machine, Program};
use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig, SimplificationLevel};
use circom_types::CheckElement;
use co_groth16::{CircomReduction, ConstraintMatrices, Groth16, ProvingKey, Rep3CoGroth16};
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::rep3::{share_field_element, Rep3PrimeFieldShare, Rep3State};
use mpc_net::local::LocalNetwork;
use rand::thread_rng;

fn manifest_dir() -> &'static str {
    env!("CARGO_MANIFEST_DIR")
}

fn multiplier2() -> Program<Fr> {
    let mut config = CompilerConfig::default();
    config.simplification = SimplificationLevel::O2(usize::MAX);
    config
        .link_library
        .push(format!("{}/circuits/libs/", manifest_dir()).into());
    CoCircomCompiler::<Bn254>::compile(
        format!("{}/circuits/multiplier2.circom", manifest_dir()),
        config,
    )
    .expect("multiplier2 compiles")
}

fn zkey() -> (ConstraintMatrices<Fr>, ProvingKey<Bn254>) {
    let path = format!("{}/kats/proving/multiplier2.zkey", manifest_dir());
    let file = std::fs::File::open(&path).unwrap_or_else(|e| panic!("opening {path}: {e}"));
    circom_types::groth16::Zkey::<Bn254>::from_reader(file, CheckElement::No)
        .expect("parsing the checked-in zkey")
        .into()
}

/// The full pipeline, on three real parties.
#[test]
fn rep3_witness_proves_and_verifies() {
    let program = multiplier2();
    let (matrices, pkey) = zkey();
    // The authoritative split point - see `vm::witness`'s module doc for why it comes from the zkey.
    let n_pub = matrices.num_instance_variables;

    let values = vec![Fr::from(7u64), Fr::from(6u64)];
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

    let results = std::thread::scope(|scope| {
        extension
            .into_iter()
            .zip(proving0)
            .zip(proving1)
            .enumerate()
            .map(|(party, ((ext, p0), p1))| {
                let shares = &shares;
                let program = &program;
                let values = &values;
                let pkey = &pkey;
                let matrices = &matrices;
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
                    let shared = to_shared_witness(&mut driver, witness, n_pub).unwrap();
                    let public = shared.public_inputs.clone();
                    let proof =
                        Rep3CoGroth16::prove::<_, CircomReduction>(&p0, &p1, pkey, matrices, shared)
                            .unwrap();
                    (proof, public)
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });

    let (proof, public) = &results[0];
    for (_, other) in &results[1..] {
        assert_eq!(public, other, "every party must open the same public inputs");
    }
    // multiplier2 is `c <== a*b` with `c` the only output, so the public inputs are the reserved 1
    // followed by 7*6.
    assert_eq!(public, &vec![Fr::from(1u64), Fr::from(42u64)]);

    Groth16::<Bn254>::verify(&pkey.vk, proof, &public[1..])
        .expect("a proof over a correctly-split witness must verify");
}

/// The split itself, against the plain driver - isolates a bad `n_pub` from a networking or proving
/// problem if the test above ever fails.
#[test]
fn plain_witness_splits_at_the_zkey_boundary() {
    let program = multiplier2();
    let (matrices, _) = zkey();
    let n_pub = matrices.num_instance_variables;

    let values = vec![Fr::from(7u64), Fr::from(6u64)];
    let inputs = program.classify_inputs(&values, |v| v);
    let mut driver = PlainDriver;
    let witness = Machine::run(&program, &mut driver, &inputs).unwrap();

    let (public, secret) = split_witness(&mut driver, witness.clone(), n_pub).unwrap();
    assert_eq!(public, vec![Fr::from(1u64), Fr::from(42u64)]);
    assert_eq!(public.len() + secret.len(), witness.len());
}
