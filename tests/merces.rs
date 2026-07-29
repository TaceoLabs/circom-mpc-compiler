//! Every check here runs the circuits under a real rep3 driver, so the whole file is gated on the
//! feature that provides one - otherwise `cargo test --no-default-features` (the plain-only build) fails
//! to compile this file rather than skipping it.
#![cfg(feature = "rep3")]

//! End-to-end checks for the real-world circuits vendored from `~/repos/merces/circom`
//! (`circuits/merces/`). **No vendored circuit is patched** - the compiler adapts to the circuits as
//! merces ships them, which is the property that keeps this a meaningful compile target.
//!
//! The two server mains (`transfer_arity4_batch{1,8}`) compile and run: `merkle_root_4.circom`'s
//! `Arity4CMux` compiles like any ordinary template (its body is pure `Add`/`Sub`/`Mul`, so
//! `passes::mpc::round_schedule` batches its multiplications automatically), and its bare
//! `IsEqual()` call is recognized as a precomputation site the same way a
//! `TACEO_PRECOMPUTATION_IsEqual` wrapper would be.
//!
//! `transfer_client_compressed` still does not compile; see [`client_main_is_still_unsupported`].
//!
//! # What is checked, and what that needs
//!
//! Always: both mains compile, run under `PlainDriver`, run under real 3-party `Rep3Driver` over
//! `mpc_net::local::LocalNetwork`, and the two witnesses agree. That last comparison is the strongest
//! check available without external artifacts - `PlainDriver`'s `reshare` is the identity and its
//! slots start zeroed, so it cannot detect a mis-ordered precomputation batch, whereas three real
//! parties either deadlock or diverge.
//!
//! With `artifacts/` present (see `scripts/gen-merces-artifacts.sh`) the test additionally compares
//! against circom's own witness and, under `--features proving`, produces and verifies a real
//! co-groth16 proof. Those steps **skip with a message** rather than failing when the artifacts are
//! absent, so `cargo test` stays green on a fresh clone.
//!
//! # The inputs are placeholders
//!
//! `fixtures::merces_server_inputs` produces arbitrary values that nonetheless satisfy the circuit's
//! `===` constraints - which a *proof* needs even though witness extension does not. See that
//! module's doc for the four constraint families and how each is satisfied. Real protocol values drop
//! in by replacing that one function.

use ark_bn254::{Bn254, Fr};
use circom_mpc_compiler::fixtures::{flatten, merces_server_inputs};
use circom_mpc_compiler::vm::driver::plain::PlainDriver;
use circom_mpc_compiler::vm::driver::rep3::Rep3Driver;
use circom_mpc_compiler::vm::program::Bank;
use circom_mpc_compiler::vm::{codegen, Machine, Program};
use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig, SimplificationLevel};
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::rep3::{
    combine_field_elements, share_field_element, Rep3PrimeFieldShare, Rep3State,
};
use mpc_net::local::LocalNetwork;
use rand::thread_rng;

/// Both vendored server mains use MAX_DEPTH = 13.
const MAX_DEPTH: usize = 13;
/// Matches `examples/gen-merces-input.rs`, so this test and the golden artifacts agree.
const SEED: u64 = 42;

fn manifest_dir() -> &'static str {
    env!("CARGO_MANIFEST_DIR")
}

fn merces_circuit_path(name: &str) -> String {
    format!("{}/circuits/merces/main/{name}.circom", manifest_dir())
}

fn merces_config() -> CompilerConfig {
    let mut config = CompilerConfig::default();
    // The vendored circuits are `pragma circom 2.2.2` verbatim.
    config.version = "2.2.2".to_owned();
    config.simplification = SimplificationLevel::O2(usize::MAX);
    // Two link libraries, mirroring how merces itself compiles these (`-l circom/node_modules
    // -l circom`): `circuits/libs/` resolves circomlib + the vendored `taceo/` subtree,
    // `circuits/merces/` the `merces/`/`oblivious_vector/` cross-references.
    config
        .link_library
        .push(format!("{}/circuits/libs/", manifest_dir()).into());
    config
        .link_library
        .push(format!("{}/circuits/merces/", manifest_dir()).into());
    config
}

/// Runs `values` through real 3-party rep3 and reconstructs the witness.
fn run_rep3(program: &Program<Fr>, values: &[Fr]) -> Vec<Fr> {
    let mut rng = thread_rng();
    let secret_shares: Vec<[Rep3PrimeFieldShare<Fr>; 3]> = program
        .input_domains
        .iter()
        .zip(values)
        .filter(|(bank, _)| matches!(bank, Bank::Shared))
        .map(|(_, &v)| share_field_element(v, &mut rng))
        .collect();

    let networks = LocalNetwork::new(3);
    let witnesses: Vec<Vec<Rep3PrimeFieldShare<Fr>>> = std::thread::scope(|scope| {
        networks
            .into_iter()
            .enumerate()
            .map(|(party, net)| {
                let secret_shares = &secret_shares;
                scope.spawn(move || {
                    let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                    let mut driver = Rep3Driver::new(&net, &mut state);
                    let mut next = 0;
                    let inputs = program.classify_inputs(values, |_v| {
                        let s = secret_shares[next][party];
                        next += 1;
                        s
                    });
                    Machine::run(program, &mut driver, &inputs).unwrap()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect()
    });

    let [w0, w1, w2]: [Vec<Rep3PrimeFieldShare<Fr>>; 3] = witnesses.try_into().unwrap();
    combine_field_elements(&w0, &w1, &w2)
}

/// Where `scripts/gen-merces-artifacts.sh` puts a main's reference artifacts, if it has been run.
fn artifact_dir(main: &str) -> std::path::PathBuf {
    std::path::Path::new(manifest_dir())
        .join("artifacts")
        .join(main)
}

/// Compiles a main, builds its placeholder inputs, and returns both.
fn compile_with_inputs(main: &str, n: usize) -> (Program<Fr>, Vec<Fr>) {
    let graph = CoCircomCompiler::<Bn254>::parse(merces_circuit_path(main), merces_config())
        .unwrap_or_else(|e| panic!("{main} must compile: {e}"));
    let named = merces_server_inputs::<Fr>(n, MAX_DEPTH, SEED);
    let values = flatten(&named, &graph.input_list)
        .unwrap_or_else(|e| panic!("{main}: building inputs: {e}"));
    let program = codegen::compile(&graph).unwrap_or_else(|e| panic!("{main}: codegen: {e}"));
    assert_eq!(program.num_inputs, values.len());
    (program, values)
}

/// The core end-to-end assertion, for one main.
fn witness_extension_agrees(main: &str, n: usize) {
    let (program, values) = compile_with_inputs(main, n);

    let plain = {
        let inputs = program.classify_inputs(&values, |v| v);
        let mut driver = PlainDriver;
        Machine::run(&program, &mut driver, &inputs)
            .unwrap_or_else(|e| panic!("{main}: plain run: {e}"))
    };
    assert_eq!(
        plain.len(),
        program.signal_to_witness.len(),
        "{main}: witness length"
    );

    assert_eq!(
        run_rep3(&program, &values),
        plain,
        "{main}: 3-party rep3 must reconstruct the same witness the plain driver computes"
    );

    // Optional: circom's own witness, when the reference artifacts have been generated.
    let wtns = artifact_dir(main).join("witness.wtns");
    match std::fs::File::open(&wtns) {
        Ok(file) => {
            let golden = circom_types::Witness::<Fr>::from_reader(file)
                .unwrap_or_else(|e| panic!("{main}: parsing {}: {e}", wtns.display()));
            assert_eq!(
                plain, golden.values,
                "{main}: witness must match circom's own"
            );
        }
        Err(_) => eprintln!(
            "note: {main}: no {} - skipping the golden-witness comparison. \
             Run scripts/gen-merces-artifacts.sh to enable it.",
            wtns.display()
        ),
    }
}

#[test]
fn transfer_arity4_batch1_runs_end_to_end() {
    witness_extension_agrees("transfer_arity4_batch1", 1);
}

#[test]
fn transfer_arity4_batch8_runs_end_to_end() {
    witness_extension_agrees("transfer_arity4_batch8", 8);
}

/// Precomputation batching, on a real circuit rather than a synthetic fixture: these circuits have
/// hundreds of sites, and the whole point of grouping by `(kind, stage)` is that they cost far fewer
/// driver calls than that. Asserted as a strict inequality rather than an exact count so the test
/// tracks the *claim* and not today's scheduling arithmetic.
#[test]
fn batching_collapses_many_sites_into_few_driver_calls() {
    for (main, n) in [("transfer_arity4_batch1", 1), ("transfer_arity4_batch8", 8)] {
        let (program, _) = compile_with_inputs(main, n);
        let sites: usize = program.precompute_batches.iter().map(|b| b.sites).sum();
        let batches = program.precompute_batches.len();
        assert!(
            sites > 50,
            "{main}: expected a site-heavy circuit, got {sites}"
        );
        assert!(
            batches * 4 < sites,
            "{main}: {sites} sites collapsed into only {batches} batches - batching regressed"
        );
    }
}

/// `transfer_client_compressed` remains unsupported, and must fail with a *typed* error rather than a
/// panic. Its blockers are deeper than the server mains': a bare `IsZero` in `escalarmulany.circom`,
/// bare `Num2Bits` calls reached through `BabyJubJubIsInFr`, and genuine non-constant field `Div` in
/// `montgomery.circom` - i.e. the whole deliberately-removed operator surface (see
/// `docs/ARCHITECTURE.md`, "Known gaps"), not something a config knob routes around.
#[test]
fn client_main_is_still_unsupported() {
    match CoCircomCompiler::<Bn254>::parse(
        merces_circuit_path("transfer_client_compressed"),
        merces_config(),
    ) {
        Ok(_) => panic!(
            "transfer_client_compressed compiled - if the operator gaps have closed, promote it to a \
             real end-to-end test alongside the server mains instead of deleting this assertion"
        ),
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("unsupported operator")
                    || msg.contains("unsupported instruction")
                    || msg.contains("unsupported mapped location")
                    || msg.contains("is only supported on compile-time constants"),
                "must fail with a typed Unsupported error, not something else: {msg}"
            );
        }
    }
}

/// A real co-groth16 proof over the secret-shared witness, when a zkey has been generated.
///
/// This is where placeholder inputs stop being free: the proof only *verifies* if the witness
/// satisfies the R1CS, which is why `fixtures::merces_server_inputs` respects the circuit's `===`
/// constraints. A verification failure here means those choices are incomplete, not that proving is
/// broken - and is reported as such.
#[cfg(feature = "proving")]
#[test]
fn transfer_arity4_batch1_proves_and_verifies() {
    use circom_mpc_compiler::vm::witness::to_shared_witness;
    use circom_types::CheckElement;
    use co_groth16::{CircomReduction, Groth16, Rep3CoGroth16};

    let main = "transfer_arity4_batch1";
    let zkey_path = artifact_dir(main).join(format!("{main}.zkey"));
    let Ok(zkey_file) = std::fs::File::open(&zkey_path) else {
        eprintln!(
            "note: no {} - skipping prove+verify. Run scripts/gen-merces-artifacts.sh with PTAU set.",
            zkey_path.display()
        );
        return;
    };

    let zkey = circom_types::groth16::Zkey::<Bn254>::from_reader(zkey_file, CheckElement::No)
        .expect("reading the zkey");
    let (matrices, pkey) = zkey.into();
    // The authoritative split point between cleartext public inputs and the shared remainder - see
    // `vm::witness`'s module doc for why this comes from the zkey and not from `input_domains`.
    let n_pub = matrices.num_instance_variables;

    let (program, values) = compile_with_inputs(main, 1);

    let mut rng = thread_rng();
    let secret_shares: Vec<[Rep3PrimeFieldShare<Fr>; 3]> = program
        .input_domains
        .iter()
        .zip(&values)
        .filter(|(bank, _)| matches!(bank, Bank::Shared))
        .map(|(_, &v)| share_field_element(v, &mut rng))
        .collect();

    // Each party needs two connections: one for witness extension, one for proving.
    let extension_nets = LocalNetwork::new(3);
    let proving_nets0 = LocalNetwork::new(3);
    let proving_nets1 = LocalNetwork::new(3);

    let proofs = std::thread::scope(|scope| {
        extension_nets
            .into_iter()
            .zip(proving_nets0)
            .zip(proving_nets1)
            .enumerate()
            .map(|(party, ((ext_net, p0), p1))| {
                let secret_shares = &secret_shares;
                let program = &program;
                let values = &values;
                let pkey = &pkey;
                let matrices = &matrices;
                scope.spawn(move || {
                    let mut state = Rep3State::new(&ext_net, A2BType::default()).unwrap();
                    let mut driver = Rep3Driver::new(&ext_net, &mut state);
                    let mut next = 0;
                    let inputs = program.classify_inputs(values, |_v| {
                        let s = secret_shares[next][party];
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

    // Every party must derive the same public inputs, and any party's proof must verify.
    let (proof, public) = &proofs[0];
    for (_, other) in &proofs[1..] {
        assert_eq!(public, other, "parties disagree on the public inputs");
    }
    let vk = pkey.vk.clone();
    Groth16::<Bn254>::verify(&vk, proof, &public[1..]).unwrap_or_else(|e| {
        panic!(
            "the proof did not verify: {e}\n\
             The proof itself was produced fine, so this means the placeholder inputs from \
             fixtures::merces_server_inputs do not satisfy every R1CS constraint. See that module's \
             doc for the constraint families it accounts for; one of them is incomplete."
        )
    });
}
