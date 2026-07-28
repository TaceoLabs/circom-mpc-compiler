//! Verifies `TACEO_PRECOMPUTATION_*` handling: `PrecomputationMode::Extract` (the default) turns
//! each of the four vendored precomputation-wrapper test circuits
//! (`circuits/precomputation_*_test.circom`, from `~/repos/taceo-circom-lib/tests/circuits/`)
//! into exactly one `ir::PrecomputeSite` with the expected shape, and `PrecomputationMode::Inline`
//! still fails the same way the wrapped gadget would unwrapped. See `docs/ARCHITECTURE.md`,
//! "Precomputation".

use ark_bn254::{Bn254, Fr};
use circom_mpc_compiler::interpreter::{Interpreter, NoPrecomputation};
use circom_mpc_compiler::{
    CoCircomCompiler, CompilerConfig, PrecomputationMode, SimplificationLevel,
};

fn manifest_dir() -> &'static str {
    env!("CARGO_MANIFEST_DIR")
}

fn circuit_path(name: &str) -> String {
    format!("{}/circuits/{name}.circom", manifest_dir())
}

fn config(mode: PrecomputationMode) -> CompilerConfig {
    let mut config = CompilerConfig::default();
    // No upstream simplification: signal_span_matches_independent_total cross-checks this
    // crate's own span computation (frontend::compute_signal_spans) against circom's own
    // `total_number_of_signals` - simplification could shrink either independently, so O0 keeps
    // both counted over the same, unmodified signal set.
    config.simplification = SimplificationLevel::O0;
    config.precomputation = mode;
    config
        .link_library
        .push(format!("{}/circuits/libs/", manifest_dir()).into());
    config
}

struct Wrapper {
    circuit: &'static str,
    inner_name: &'static str,
    num_inputs: usize,
    num_outputs: usize,
}

const WRAPPERS: &[Wrapper] = &[
    Wrapper {
        circuit: "precomputation_poseidon2_test",
        inner_name: "Poseidon2",
        num_inputs: 3,
        num_outputs: 3,
    },
    Wrapper {
        circuit: "precomputation_num2bits_test",
        inner_name: "Num2Bits",
        num_inputs: 1,
        num_outputs: 8,
    },
    Wrapper {
        circuit: "precomputation_iszero_test",
        inner_name: "IsZero",
        num_inputs: 1,
        num_outputs: 1,
    },
    Wrapper {
        circuit: "precomputation_aliascheck_test",
        inner_name: "AliasCheck",
        num_inputs: 254,
        num_outputs: 0,
    },
];

#[test]
fn extract_yields_one_site_per_wrapper() {
    for w in WRAPPERS {
        let graph =
            CoCircomCompiler::<Bn254>::parse(circuit_path(w.circuit), config(PrecomputationMode::Extract))
                .unwrap_or_else(|e| panic!("{}: {e}", w.circuit));
        let sites = graph.precompute_sites();
        assert_eq!(
            sites.len(),
            1,
            "{}: expected exactly one precompute site",
            w.circuit
        );
        let site = &sites[0];
        assert_eq!(site.name, w.inner_name, "{}", w.circuit);
        assert_eq!(site.num_inputs, w.num_inputs, "{}", w.circuit);
        assert_eq!(site.num_outputs, w.num_outputs, "{}", w.circuit);
    }
}

#[test]
fn signal_span_matches_independent_total() {
    for w in WRAPPERS {
        let graph =
            CoCircomCompiler::<Bn254>::parse(circuit_path(w.circuit), config(PrecomputationMode::Extract))
                .unwrap_or_else(|e| panic!("{}: {e}", w.circuit));
        let site = &graph.precompute_sites()[0];
        // main *is* the wrapper for each of these circuits, so the whole circuit's signal count
        // (minus the reserved constant-1 slot) must equal the wrapper's own I/O plus the site's
        // full result span.
        let expected =
            graph.num_inputs + graph.num_outputs + site.num_inputs + site.num_outputs + site.num_intermediates;
        assert_eq!(graph.num_signals - 1, expected, "{}", w.circuit);
    }
}

#[test]
fn no_precomputation_provider_errors_naming_the_site() {
    let graph = CoCircomCompiler::<Bn254>::parse(
        circuit_path("precomputation_iszero_test"),
        config(PrecomputationMode::Extract),
    )
    .unwrap();
    let site_name = graph.precompute_sites()[0].name.clone();
    let num_inputs = graph.num_inputs;
    let mut interpreter = Interpreter::new(graph, vec![Fr::from(0u64); num_inputs]);
    let err = interpreter.run_with(&mut NoPrecomputation).unwrap_err();
    assert!(
        err.to_string().contains(&site_name),
        "error should name the site: {err}"
    );
}

#[test]
fn inline_mode_fails_the_same_way_the_unwrapped_gadget_would() {
    for w in WRAPPERS {
        let err = CoCircomCompiler::<Bn254>::parse(circuit_path(w.circuit), config(PrecomputationMode::Inline))
            .err()
            .unwrap_or_else(|| {
                panic!(
                    "{}: Inline mode compiled successfully - if the gadget's operator/instruction \
                     gaps have been closed, replace this with a real witness-comparison test",
                    w.circuit
                )
            });
        let msg = err.to_string();
        assert!(
            msg.contains("unsupported operator")
                || msg.contains("unsupported instruction")
                || msg.contains("unsupported mapped location")
                || msg.contains("is only supported on compile-time constants"),
            "{}: failed for an unexpected reason (not a typed Unsupported error): {msg}",
            w.circuit
        );
    }
}
