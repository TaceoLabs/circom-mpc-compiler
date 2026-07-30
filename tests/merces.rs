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
//! # The inputs are a real protocol run
//!
//! `inputs/<main>_<scenario>.json` (via `fixtures::MERCES_SCENARIOS`) are real merces protocol
//! values, not placeholders: 4 scenarios per server main, covering deposit, withdraw, an invalid
//! (zero output-flag) withdraw, and a transfer that links a withdraw root to a deposit root - the one
//! `===` family (`server.circom:159`) that arbitrary values cannot satisfy. See `fixtures`'s module
//! doc for the full constraint table.
//!
//! # What is checked, and what that needs
//!
//! Always: every scenario compiles under both mains, runs under `PlainDriver`, runs under real
//! 3-party `Rep3Driver` over `mpc_net::local::LocalNetwork`, and the two witnesses agree. That
//! comparison is the strongest check available without external artifacts - `PlainDriver`'s
//! `reshare` is the identity and its slots start zeroed, so it cannot detect a mis-ordered
//! precomputation batch, whereas three real parties either deadlock or diverge.
//!
//! With `inputs/zkey/<main>.arks.zkey` present (the merces ceremony proving key - too large to
//! commit, see `.gitignore`), a scenario additionally produces and verifies a real co-groth16
//! proof - this skips with a message rather than failing when the key is absent, so `cargo test`
//! stays green on a fresh clone.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use ark_bn254::{Bn254, Fr};
use circom_mpc_compiler::fixtures;
use circom_mpc_compiler::ir::InputList;
use circom_mpc_compiler::vm::driver::plain::PlainDriver;
use circom_mpc_compiler::vm::driver::rep3::Rep3Driver;
use circom_mpc_compiler::vm::program::Bank;
use circom_mpc_compiler::vm::witness::split_witness;
use circom_mpc_compiler::vm::{codegen, Machine, Program};
use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig};
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::rep3::{
    combine_field_elements, share_field_element, Rep3PrimeFieldShare, Rep3State,
};
use mpc_net::local::LocalNetwork;
use rand::thread_rng;

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
    // Two link libraries, mirroring how merces itself compiles these (`-l circom/node_modules
    // -l circom`): `circuits/libs/` resolves circomlib + the vendored `taceo/` subtree,
    // `circuits/merces/` the `merces/`/`oblivious_vector/` cross-references.
    config
        .link_library
        .push(format!("{}/circuits/libs/", manifest_dir()).into());
    config
        .link_library
        .push(format!("{}/circuits/merces/", manifest_dir()).into());
    config.mpc_public_inputs = fixtures::merces_mpc_public_inputs();
    config
}

/// Compiles a merces main once and shares it across every scenario in this test binary -
/// `CoCircomCompiler::parse` costs seconds on `transfer_arity4_batch8`, and nothing about parsing or
/// codegen depends on the scenario's input values.
fn compiled(main: &str) -> &'static (Program<Fr>, InputList) {
    fn build(main: &str) -> (Program<Fr>, InputList) {
        let graph = CoCircomCompiler::<Bn254>::parse(merces_circuit_path(main), merces_config())
            .unwrap_or_else(|e| panic!("{main} must compile: {e}"));
        let input_list = graph.input_list.clone();
        let program = codegen::compile(&graph).unwrap_or_else(|e| panic!("{main}: codegen: {e}"));
        (program, input_list)
    }
    static BATCH1: OnceLock<(Program<Fr>, InputList)> = OnceLock::new();
    static BATCH8: OnceLock<(Program<Fr>, InputList)> = OnceLock::new();
    match main {
        "transfer_arity4_batch1" => BATCH1.get_or_init(|| build(main)),
        "transfer_arity4_batch8" => BATCH8.get_or_init(|| build(main)),
        other => panic!("not a cached merces main: {other}"),
    }
}

/// One scenario's inputs, flattened against `main`'s declared `input_list`.
fn scenario_values(main: &str, name: &str) -> Vec<Fr> {
    let (_, input_list) = compiled(main);
    fixtures::scenario(main, name)
        .and_then(|s| s.values(input_list))
        .unwrap_or_else(|e| panic!("{main}/{name}: {e}"))
}

fn plain_witness(program: &Program<Fr>, values: &[Fr]) -> Vec<Fr> {
    let inputs = program.classify_inputs(values, |v| v);
    let mut driver = PlainDriver;
    Machine::run(program, &mut driver, &inputs).unwrap_or_else(|e| panic!("plain run: {e}"))
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

/// The core end-to-end assertion, for one (main, scenario) pair.
fn witness_extension_agrees(main: &str, scenario: &str) {
    let (program, _) = compiled(main);
    let values = scenario_values(main, scenario);

    let plain = plain_witness(program, &values);
    assert_eq!(
        plain.len(),
        program.signal_to_witness.len(),
        "{main}/{scenario}: witness length"
    );

    assert_eq!(
        run_rep3(program, &values),
        plain,
        "{main}/{scenario}: 3-party rep3 must reconstruct the same witness the plain driver computes"
    );
}

#[test]
fn transfer_arity4_batch1_all_scenarios_run_end_to_end() {
    for scenario in ["deposit", "withdraw", "invalid_withdraw", "transfer"] {
        witness_extension_agrees("transfer_arity4_batch1", scenario);
    }
}

#[test]
fn transfer_arity4_batch8_all_scenarios_run_end_to_end() {
    for scenario in ["full_batch", "partial_batch", "multi_withdraw", "invalid_slot"] {
        witness_extension_agrees("transfer_arity4_batch8", scenario);
    }
}

/// Precomputation batching, on a real circuit rather than a synthetic fixture: these circuits have
/// hundreds of sites, and the whole point of grouping by `(kind, stage, domain)` is that they cost
/// far fewer driver calls than that. Asserted as a strict inequality rather than an exact count so
/// the test tracks the *claim* and not today's scheduling arithmetic.
///
/// Counts only batches that actually need a `VmDriver` call (any `Shared`-bank input) - since
/// `CompilerConfig::mpc_public_inputs` and `TACEO_REVEAL` (see `merces_config`, `hash.circom`,
/// `server.circom`) legitimately split what used to be one batch into an all-public one (zero
/// network cost, `Machine::run_batch`'s plain-gadget path) and a genuinely shared one, `batches`
/// alone no longer tracks driver-call cost - only the shared subset does.
#[test]
fn batching_collapses_many_sites_into_few_driver_calls() {
    for main in ["transfer_arity4_batch1", "transfer_arity4_batch8"] {
        let (program, _) = compiled(main);
        let sites: usize = program.precompute_batches.iter().map(|b| b.sites).sum();
        let shared_batches = program
            .precompute_batches
            .iter()
            .filter(|b| b.input_slots.iter().any(|input| input.bank == Bank::Shared))
            .count();
        assert!(sites > 50, "{main}: expected a site-heavy circuit, got {sites}");
        assert!(
            shared_batches * 4 < sites,
            "{main}: {sites} sites collapsed into only {shared_batches} MPC-driver batches - \
             batching regressed"
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

/// `inputs/zkey/<main>.arks.zkey`: the merces ceremony proving key. Ark-serialized *uncompressed*
/// (`convert-zkey-to-ark --uncompressed` in merces' own build), unlike the snarkjs-format zkey
/// `tests/proving.rs` reads. Too large to commit (13-178 MB) - gitignored, so this returns `None` on
/// a fresh clone rather than failing.
fn ceremony_zkey(
    main: &str,
) -> Option<(
    co_groth16::ConstraintMatrices<Fr>,
    co_groth16::ProvingKey<Bn254>,
)> {
    use ark_serialize::{CanonicalDeserialize, Compress, Validate};
    use circom_types::groth16::ArkZkey;

    let path: PathBuf = Path::new(manifest_dir())
        .join("inputs")
        .join("zkey")
        .join(format!("{main}.arks.zkey"));
    let bytes = std::fs::read(&path).ok()?;
    // `Validate::No`: validating hundreds of MB of group elements costs far more than the proof
    // itself, and a bad zkey shows up immediately as a proof that fails to verify.
    let ark = ArkZkey::<Bn254>::deserialize_with_mode(bytes.as_slice(), Compress::No, Validate::No)
        .unwrap_or_else(|e| panic!("parsing {}: {e}", path.display()));
    Some(ark.into_inner())
}

/// A real co-groth16 proof over the secret-shared witness, for one (main, scenario) pair.
///
/// This is where the input values stop being free to choose: the proof only *verifies* if the
/// witness satisfies the R1CS. If this fails while `witness_extension_agrees` for the same scenario
/// passes, the fault is in this compiler's witness (the layout or a gadget), not in the inputs.
fn proves_and_verifies(main: &str, scenario: &str) {
    use co_groth16::{CircomReduction, Groth16, Rep3CoGroth16};

    let Some((matrices, pkey)) = ceremony_zkey(main) else {
        eprintln!(
            "note: {main}: no inputs/zkey/{main}.arks.zkey - skipping prove+verify for {scenario}."
        );
        return;
    };
    // The authoritative split point between cleartext public inputs and the shared remainder - see
    // `vm::witness`'s module doc for why this comes from the zkey and not from `input_domains`.
    let n_pub = matrices.num_instance_variables;

    let (program, input_list) = compiled(main);
    let values = fixtures::scenario(main, scenario)
        .and_then(|s| s.values(input_list))
        .unwrap_or_else(|e| panic!("{main}/{scenario}: {e}"));
    assert_eq!(
        program.signal_to_witness.len(),
        matrices.num_instance_variables + matrices.num_witness_variables,
        "{main}: this compiler's witness length disagrees with the zkey's - they were not built \
         from the same compilation"
    );

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

    let matrices = &matrices;
    let pkey = &pkey;
    let proofs = std::thread::scope(|scope| {
        extension_nets
            .into_iter()
            .zip(proving_nets0)
            .zip(proving_nets1)
            .enumerate()
            .map(|(party, ((ext_net, p0), p1))| {
                let secret_shares = &secret_shares;
                let values = &values;
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
                    let (public_inputs, secret) = split_witness(&mut driver, witness, n_pub).unwrap();
                    let shared = co_circom_types::SharedWitness {
                        public_inputs: public_inputs.clone(),
                        witness: secret,
                    };
                    let public = public_inputs;
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
        assert_eq!(public, other, "{main}/{scenario}: parties disagree on the public inputs");
    }
    let vk = pkey.vk.clone();
    Groth16::<Bn254>::verify(&vk, proof, &public[1..]).unwrap_or_else(|e| {
        panic!(
            "{main}/{scenario}: the proof did not verify: {e}\n\
             the R1CS came from circom, so the fault is this compiler's witness (layout or a \
             gadget), not fixtures::MERCES_SCENARIOS."
        )
    });
}

#[test]
fn transfer_arity4_batch1_all_scenarios_prove_and_verify() {
    for scenario in ["deposit", "withdraw", "invalid_withdraw", "transfer"] {
        proves_and_verifies("transfer_arity4_batch1", scenario);
    }
}

/// `transfer_arity4_batch8`'s zkey is 178 MB and its witness has 139k entries: proving four of them
/// costs minutes and several GB of RAM, so this is opt-in (`cargo test -- --ignored`) rather than
/// part of the default suite.
#[test]
#[ignore = "178 MB zkey, 139k-entry witness x4 - minutes and several GB of RAM; run with --ignored"]
fn transfer_arity4_batch8_all_scenarios_prove_and_verify() {
    for scenario in ["full_batch", "partial_batch", "multi_withdraw", "invalid_slot"] {
        proves_and_verifies("transfer_arity4_batch8", scenario);
    }
}
