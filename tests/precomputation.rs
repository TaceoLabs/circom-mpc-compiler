//! Verifies `TACEO_PRECOMPUTATION_*` handling: `PrecomputationMode::Extract` (the default) turns
//! each of the four vendored precomputation-wrapper test circuits
//! (`circuits/precomputation_*_test.circom`, from `~/repos/taceo-circom-lib/tests/circuits/`)
//! into exactly one `ir::PrecomputeSite` with the expected shape, and `PrecomputationMode::Inline`
//! still fails the same way the wrapped gadget would unwrapped. See `docs/ARCHITECTURE.md`,
//! "Precomputation".

use ark_bn254::{Bn254, Fr};
use circom_mpc_compiler::ir::PrecomputeKind;
use circom_mpc_compiler::vm::driver::plain::PlainDriver;
use circom_mpc_compiler::vm::Machine;
use circom_mpc_compiler::{
    CoCircomCompiler, CompilerConfig, PrecomputationMode, SimplificationLevel,
    UnknownPrecomputeGadget,
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
    kind: PrecomputeKind,
    num_inputs: usize,
    num_outputs: usize,
}

const WRAPPERS: &[Wrapper] = &[
    Wrapper {
        circuit: "precomputation_poseidon2_test",
        inner_name: "Poseidon2",
        kind: PrecomputeKind::Poseidon2 { t: 3 },
        num_inputs: 3,
        num_outputs: 3,
    },
    Wrapper {
        circuit: "precomputation_num2bits_test",
        inner_name: "Num2Bits",
        kind: PrecomputeKind::Num2Bits { n: 8 },
        num_inputs: 1,
        num_outputs: 8,
    },
    Wrapper {
        circuit: "precomputation_iszero_test",
        inner_name: "IsZero",
        kind: PrecomputeKind::IsZero,
        num_inputs: 1,
        num_outputs: 1,
    },
    Wrapper {
        circuit: "precomputation_aliascheck_test",
        inner_name: "AliasCheck",
        kind: PrecomputeKind::AliasCheck,
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
        assert_eq!(site.kind, w.kind, "{}", w.circuit);
        assert_eq!(site.num_inputs, w.num_inputs, "{}", w.circuit);
        assert_eq!(site.num_outputs, w.num_outputs, "{}", w.circuit);
    }
}

/// The default (`UnknownPrecomputeGadget::Error`): a wrapper naming a gadget this compiler has no
/// implementation for is a typed error naming it.
#[test]
fn unrecognized_gadget_is_a_typed_error() {
    let err = CoCircomCompiler::<Bn254>::parse(
        circuit_path("precomputation_unsupported_gadget_test"),
        config(PrecomputationMode::Extract),
    )
    .err()
    .expect("an unrecognized TACEO_PRECOMPUTATION_* gadget must be rejected by default");
    let msg = err.to_string();
    assert!(
        msg.contains("Doubler") && msg.contains("TACEO_PRECOMPUTATION"),
        "error should name the unrecognized gadget: {msg}"
    );
}

/// `UnknownPrecomputeGadget::Warn`: the same wrapper compiles instead, with its body treated like any
/// ordinary template and no site created. This is what lets `circuits/merces/` compile unmodified -
/// its `TACEO_PRECOMPUTATION_Arity4CMux` wrapper is exactly this shape (unrecognized name, but a body
/// made only of `Add`/`Sub`/`Mul`).
#[test]
fn unrecognized_gadget_falls_through_to_the_body_when_warning() {
    let mut cfg = config(PrecomputationMode::Extract);
    cfg.unknown_precompute_gadget = UnknownPrecomputeGadget::Warn;
    let graph = CoCircomCompiler::<Bn254>::parse(
        circuit_path("precomputation_unsupported_gadget_test"),
        cfg,
    )
    .expect("Warn must compile the wrapped body instead of failing");
    assert!(
        graph.precompute_sites().is_empty(),
        "the fall-through path must not create a site"
    );

    // And the compiled body is correct: Doubler(in) = in + in.
    let mut cfg = config(PrecomputationMode::Extract);
    cfg.unknown_precompute_gadget = UnknownPrecomputeGadget::Warn;
    let program = CoCircomCompiler::<Bn254>::compile(
        circuit_path("precomputation_unsupported_gadget_test"),
        cfg,
    )
    .unwrap();
    let values = [Fr::from(21u64)];
    let inputs = program.classify_inputs(&values, |v| v);
    let mut driver = PlainDriver;
    let witness = Machine::run(&program, &mut driver, &inputs).unwrap();
    assert_eq!(witness[1], Fr::from(42u64), "witness: {witness:?}");
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
fn extract_mode_runs_end_to_end_through_the_plain_driver() {
    // Every recognized TACEO_PRECOMPUTATION_* kind must actually be serviceable by
    // `PlainDriver` - unlike the deleted `Interpreter`, there's no injectable
    // `PrecomputeProvider` a caller can simply omit, so this asserts the whole VM pipeline
    // (codegen -> Machine::precompute -> the main instruction stream) runs to completion.
    // This is a smoke test only (all-zero inputs, no golden witness yet - see
    // tests/circom_ir.rs's plain KATs and `docs/ARCHITECTURE.md`'s "Known gaps" for why a real
    // golden-witness comparison for these circuits is still future work).
    for w in WRAPPERS {
        let program =
            CoCircomCompiler::<Bn254>::compile(circuit_path(w.circuit), config(PrecomputationMode::Extract))
                .unwrap_or_else(|e| panic!("{}: {e}", w.circuit));
        let values = vec![Fr::from(0u64); program.num_inputs];
        let inputs = program.classify_inputs(&values, |v| v);
        let mut driver = PlainDriver;
        // All four kinds work with or without the `rep3` feature: every gadget's plain path is this
        // crate's own field arithmetic now that `vm::gadgets::poseidon2` derives its trace from the
        // circuit instead of wrapping mpc-core's hasher.
        Machine::run(&program, &mut driver, &inputs)
            .unwrap_or_else(|e| panic!("{}: {e}", w.circuit));
    }
}

/// Two same-kind sites chained through secret multiplications cannot share a driver call, so they
/// must land in two batches - and the second one's inputs only exist partway through the instruction
/// stream, which is what staged precomputation exists for. An implementation that ran every batch up
/// front, or keyed batches on multiplicative depth alone, would get this wrong.
///
/// See `circuits/precomputation_staged_test.circom` and `passes::mpc::level`.
#[test]
fn chained_same_kind_sites_are_staged_into_separate_batches() {
    let graph = CoCircomCompiler::<Bn254>::parse(
        circuit_path("precomputation_staged_test"),
        config(PrecomputationMode::Extract),
    )
    .unwrap();
    let summary = graph.mpc_summary();
    assert_eq!(summary.precompute_sites, 2);
    assert_eq!(
        summary.precompute_batches, 2,
        "dependent sites must not be batched together: {summary:?}"
    );

    // And it runs: a*b == 0 for these inputs, so the first IsZero returns 1.
    let program = CoCircomCompiler::<Bn254>::compile(
        circuit_path("precomputation_staged_test"),
        config(PrecomputationMode::Extract),
    )
    .unwrap();
    let values = vec![Fr::from(0u64), Fr::from(7u64)];
    let inputs = program.classify_inputs(&values, |v| v);
    let mut driver = PlainDriver;
    let witness = Machine::run(&program, &mut driver, &inputs).unwrap();
    // p = 0*7 = 0, so z = IsZero(0) = 1; q = z*a = 1*0 = 0, so out = IsZero(0) = 1.
    assert_eq!(witness[1], Fr::from(1u64), "out should be 1: {witness:?}");
}

/// The counterpart: independent same-kind sites *do* share one driver call. Without this, the
/// staging test above would pass even if batching had been broken into one-call-per-site.
#[test]
fn independent_same_kind_sites_share_one_batch() {
    let graph = CoCircomCompiler::<Bn254>::parse(
        circuit_path("precomputation_iszero_test"),
        config(PrecomputationMode::Extract),
    )
    .unwrap();
    let summary = graph.mpc_summary();
    assert_eq!(summary.precompute_sites, 1);
    assert_eq!(summary.precompute_batches, 1);
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
