//! End-to-end checks for the real-world circuits vendored under `circuits/merces/`. No vendored
//! circuit is patched - the compiler adapts to the circuits as merces ships them.
//!
//! Every scenario (real protocol inputs, see `fixtures`) compiles under both server mains, runs
//! under `PlainDriver` and under real 3-party `Rep3Driver`, and the two witnesses must agree -
//! the strongest check available without external artifacts, since `PlainDriver` cannot detect a
//! mis-ordered gadget batch (its `reshare` is the identity) while three real parties
//! either deadlock or diverge. With `inputs/zkey/<main>.arks.zkey` present (gitignored, too large
//! to commit), a scenario additionally produces and verifies a real co-groth16 proof.
//!
//! `transfer_client_compressed` still does not compile; see [`client_main_is_still_unsupported`].
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use ark_bn254::{Bn254, Fr};
use circom_mpc_compiler::CoCircomCompiler;
use circom_mpc_compiler::codegen;
use circom_mpc_compiler_tests::fixtures::{
    self, merces_config, merces_main_path, rep3::run_witness,
};
use circom_mpc_vm::driver::plain::PlainDriver;
use circom_mpc_vm::driver::rep3::Rep3Driver;
use circom_mpc_vm::split_witness;
use circom_mpc_vm::{Machine, Program};
use mpc_core::protocols::rep3::Rep3State;
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_net::local::LocalNetwork;

fn manifest_dir() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../..")
}

/// Compiles a merces main once and shares it across every scenario in this test binary -
/// `CoCircomCompiler::parse` costs seconds on `transfer_arity4_batch8`, and nothing about parsing or
/// codegen depends on the scenario's input values.
fn compiled(main: &str) -> &'static Program {
    fn build(main: &str) -> Program {
        let graph = CoCircomCompiler::parse(merces_main_path(main), merces_config())
            .unwrap_or_else(|e| panic!("{main} must compile: {e}"));
        codegen::compile(&graph).unwrap_or_else(|e| panic!("{main}: codegen: {e}"))
    }
    static BATCH1: OnceLock<Program> = OnceLock::new();
    static BATCH8: OnceLock<Program> = OnceLock::new();
    match main {
        "transfer_arity4_batch1" => BATCH1.get_or_init(|| build(main)),
        "transfer_arity4_batch8" => BATCH8.get_or_init(|| build(main)),
        other => panic!("not a cached merces main: {other}"),
    }
}

/// One scenario's inputs, flattened against `main`'s declared input signals.
fn scenario_values(main: &str, name: &str) -> Vec<Fr> {
    let program = compiled(main);
    fixtures::scenario(main, name)
        .and_then(|s| s.values(program.input_signals()))
        .unwrap_or_else(|e| panic!("{main}/{name}: {e}"))
}

fn plain_witness(program: &Program, values: &[Fr]) -> Vec<Fr> {
    let inputs = program.classify_inputs(values, |v| v);
    let mut driver = PlainDriver;
    Machine::run(program, &mut driver, &inputs).unwrap_or_else(|e| panic!("plain run: {e}"))
}

/// The core end-to-end assertion, for one (main, scenario) pair.
fn witness_extension_agrees(main: &str, scenario: &str) {
    let program = compiled(main);
    let values = scenario_values(main, scenario);

    let plain = plain_witness(program, &values);
    assert_eq!(
        plain.len(),
        program.statistics().witness_values,
        "{main}/{scenario}: witness length"
    );

    assert_eq!(
        run_witness(program, &values),
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
    for scenario in [
        "full_batch",
        "partial_batch",
        "multi_withdraw",
        "invalid_slot",
    ] {
        witness_extension_agrees("transfer_arity4_batch8", scenario);
    }
}

#[test]
fn server_mains_separate_preprocessing_from_online_rounds() {
    use circom_mpc_compiler_tests::fixtures::rep3::run_witness_counted;

    for (main, scenario) in [
        ("transfer_arity4_batch1", "deposit"),
        ("transfer_arity4_batch8", "full_batch"),
    ] {
        let program = compiled(main);
        let values = scenario_values(main, scenario);
        let (_, preprocessing, online) = run_witness_counted(program, &values);
        let combined: [usize; 3] =
            std::array::from_fn(|party| preprocessing[party] + online[party]);

        assert_eq!(preprocessing, [3, 3, 3], "{main}: preprocessing rounds");
        assert_eq!(online, [69, 71, 71], "{main}: online rounds");
        assert_eq!(combined, [72, 74, 74], "{main}: combined rounds");
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
        let program = compiled(main);
        let sites = program.statistics().gadget_sites;
        let shared_batches = program.statistics().shared_gadget_batches;
        assert!(
            sites > 50,
            "{main}: expected a site-heavy circuit, got {sites}"
        );
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
/// `montgomery.circom` - i.e. the whole deliberately-removed operator surface, not something a
/// config knob routes around.
#[test]
fn client_main_is_still_unsupported() {
    match CoCircomCompiler::parse(
        merces_main_path("transfer_client_compressed"),
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

    let program = compiled(main);
    let values = fixtures::scenario(main, scenario)
        .and_then(|s| s.values(program.input_signals()))
        .unwrap_or_else(|e| panic!("{main}/{scenario}: {e}"));
    assert_eq!(
        program.statistics().witness_values,
        matrices.num_instance_variables + matrices.num_witness_variables,
        "{main}: this compiler's witness length disagrees with the zkey's - they were not built \
         from the same compilation"
    );

    let secret_shares = fixtures::rep3::share_inputs(program, &values);

    // Each party needs two connections: one for witness extension, one for proving.
    let extension_nets = LocalNetwork::new(3);
    let proving_nets = LocalNetwork::new(3);

    let matrices = &matrices;
    let pkey = &pkey;
    let proofs = std::thread::scope(|scope| {
        extension_nets
            .into_iter()
            .zip(proving_nets)
            .enumerate()
            .map(|(party, (ext_net, p))| {
                let secret_shares = &secret_shares;
                let values = &values;
                scope.spawn(move || {
                    let mut state = Rep3State::new(&ext_net, A2BType::default()).unwrap();
                    let mut driver =
                        Rep3Driver::new_for_run(&ext_net, &mut state, program).unwrap();
                    let mut next = 0;
                    let inputs = program.classify_inputs(values, |_v| {
                        let s = secret_shares[next][party];
                        next += 1;
                        s
                    });
                    let witness = Machine::run(program, &mut driver, &inputs).unwrap();
                    let (public_inputs, secret) =
                        split_witness(&mut driver, witness, n_pub).unwrap();
                    let shared = co_circom_types::SharedWitness {
                        public_inputs: public_inputs.clone(),
                        witness: secret,
                    };
                    let public = public_inputs;
                    let proof = Rep3CoGroth16::prove_with_shamir_bridge::<_, CircomReduction>(
                        &p, pkey, matrices, shared,
                    )
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
        assert_eq!(
            public, other,
            "{main}/{scenario}: parties disagree on the public inputs"
        );
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
    for scenario in [
        "full_batch",
        "partial_batch",
        "multi_withdraw",
        "invalid_slot",
    ] {
        proves_and_verifies("transfer_arity4_batch8", scenario);
    }
}
