//! Verifies gadget-gadget recognition: `Poseidon2`, `Num2Bits`, `IsZero` and `AliasCheck` are
//! each cut into exactly one `ir::GadgetSite` with the expected shape, matched by their own
//! circom name regardless of what (if anything) wraps them - except (for
//! `unsupported_gadget_test`'s `Doubler`) an unrecognized name, which is not
//! recognized at all.

use ark_bn254::Fr;
use circom_mpc_compiler::ir::GadgetKind;
use circom_mpc_compiler::CompilerConfig;
use circom_mpc_vm::Machine;
use circom_mpc_vm::driver::plain::PlainDriver;

mod common;

use common::{circuit_path, libs_path};

fn config() -> CompilerConfig {
    let mut config = CompilerConfig::default();
    config.link_library.push(libs_path());
    config
}

struct Wrapper {
    circuit: &'static str,
    inner_name: &'static str,
    kind: GadgetKind,
    num_inputs: usize,
    num_outputs: usize,
}

fn wrappers() -> Vec<Wrapper> {
    vec![
        Wrapper {
            circuit: "gadget_poseidon2_test",
            inner_name: "Poseidon2",
            kind: GadgetKind::Poseidon2 {
                t: circom_mpc_program::Poseidon2Width::new(3).expect("3 is a supported width"),
            },
            num_inputs: 3,
            num_outputs: 3,
        },
        Wrapper {
            circuit: "gadget_num2bits_test",
            inner_name: "Num2Bits",
            kind: GadgetKind::Num2Bits { n: 8 },
            num_inputs: 1,
            num_outputs: 8,
        },
        Wrapper {
            circuit: "gadget_iszero_test",
            inner_name: "IsZero",
            kind: GadgetKind::IsZero,
            num_inputs: 1,
            num_outputs: 1,
        },
        Wrapper {
            circuit: "gadget_aliascheck_test",
            inner_name: "AliasCheck",
            kind: GadgetKind::AliasCheck,
            num_inputs: 254,
            num_outputs: 0,
        },
    ]
}

#[test]
fn extract_yields_one_site_per_wrapper() {
    for w in &wrappers() {
        let graph = circom_mpc_compiler::parse(circuit_path(w.circuit), &config())
            .unwrap_or_else(|e| panic!("{}: {e}", w.circuit));
        let sites = graph.gadget_sites();
        assert_eq!(
            sites.len(),
            1,
            "{}: expected exactly one gadget site",
            w.circuit
        );
        let site = &sites[0];
        assert!(
            site.header.starts_with(w.inner_name),
            "{}: expected header starting with `{}`, got `{}`",
            w.circuit,
            w.inner_name,
            site.header
        );
        assert_eq!(site.kind, w.kind, "{}", w.circuit);
        assert_eq!(site.num_inputs, w.num_inputs, "{}", w.circuit);
        assert_eq!(site.num_outputs, w.num_outputs, "{}", w.circuit);
    }
}

/// An unrecognized name (wrapped or not) simply compiles its body like any other template - here,
/// `Doubler`, a gadget this compiler has no gadget implementation for. Its body is
/// deliberately pure `Add`/`Sub`/`Mul`, so this succeeds rather than failing deeper on some
/// unrelated gap - exactly the situation the vendored `merkle_root_4.circom` is in with its
/// `Arity4CMux`.
#[test]
fn unrecognized_gadget_compiles_its_body() {
    let graph = circom_mpc_compiler::parse(
        circuit_path("unsupported_gadget_test"),
        &config(),
    )
    .expect("an unrecognized gadget must compile its body");
    assert!(
        graph.gadget_sites().is_empty(),
        "an unrecognized gadget must not create a site"
    );

    // And the compiled body is correct: Doubler(in) = in + in.
    let program = circom_mpc_compiler::compile(
        circuit_path("unsupported_gadget_test"),
        &config(),
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
    for w in &wrappers() {
        let graph = circom_mpc_compiler::parse(circuit_path(w.circuit), &config())
            .unwrap_or_else(|e| panic!("{}: {e}", w.circuit));
        let site = &graph.gadget_sites()[0];
        // main *is* the wrapper for each of these circuits, so the whole circuit's signal count
        // (minus the reserved constant-1 slot) must equal the wrapper's own I/O plus the site's
        // full result span.
        let expected = graph.num_inputs()
            + graph.num_outputs()
            + site.num_inputs
            + site.num_outputs
            + site.num_intermediates;
        assert_eq!(graph.num_signals() - 1, expected, "{}", w.circuit);
    }
}

#[test]
fn extract_mode_runs_end_to_end_through_the_plain_driver() {
    // Every recognized gadget kind must actually be serviceable by `PlainDriver` - this asserts the
    // whole VM pipeline (codegen -> Opcode::Gadget dispatch -> the main instruction stream) runs to
    // completion. This is a smoke test only (all-zero inputs) - see tests/proving.rs's prove+verify
    // tests for a real value comparison.
    for w in &wrappers() {
        let program = circom_mpc_compiler::compile(circuit_path(w.circuit), &config())
            .unwrap_or_else(|e| panic!("{}: {e}", w.circuit));
        let values = vec![Fr::from(0u64); program.statistics().inputs];
        let inputs = program.classify_inputs(&values, |v| v);
        let mut driver = PlainDriver;
        Machine::run(&program, &mut driver, &inputs)
            .unwrap_or_else(|e| panic!("{}: {e}", w.circuit));
    }
}

/// Two same-kind sites chained through secret multiplications cannot share a driver call, so they
/// must land in two batches - and the second one's inputs only exist partway through the instruction
/// stream, which is what staged batching exists for. An implementation that ran every batch up
/// front, or keyed batches on multiplicative depth alone, would get this wrong.
///
/// See `circuits/gadget_staged_test.circom` and `passes::mpc::level`.
#[test]
fn chained_same_kind_sites_are_staged_into_separate_batches() {
    let graph = circom_mpc_compiler::parse(circuit_path("gadget_staged_test"), &config()).unwrap();
    let summary = graph.mpc_summary();
    assert_eq!(summary.gadget_sites, 2);
    assert_eq!(
        summary.gadget_batches, 2,
        "dependent sites must not be batched together: {summary:?}"
    );

    // And it runs: a*b == 0 for these inputs, so the first IsZero returns 1.
    let program =
        circom_mpc_compiler::compile(circuit_path("gadget_staged_test"), &config()).unwrap();
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
    let graph = circom_mpc_compiler::parse(circuit_path("gadget_iszero_test"), &config()).unwrap();
    let summary = graph.mpc_summary();
    assert_eq!(summary.gadget_sites, 1);
    assert_eq!(summary.gadget_batches, 1);
}

#[test]
fn num2bits_zero_returns_an_empty_trace_without_panicking() {
    let program =
        circom_mpc_compiler::compile(circuit_path("gadget_num2bits_zero_test"), &config())
            .unwrap();
    let values = [Fr::from(0u64)];
    let inputs = program.classify_inputs(&values, |v| v);
    let witness = Machine::run(&program, &mut PlainDriver, &inputs).unwrap();
    assert!(witness[1..].iter().all(ark_ff::Zero::is_zero));
}

#[test]
fn all_public_gadgets_stay_public_through_downstream_multiplication() {
    let mut cfg = config();
    cfg.opt_level = circom_mpc_compiler::OptLevel::O2;
    let graph = circom_mpc_compiler::parse(circuit_path("gadget_public_test"), &cfg).unwrap();
    let summary = graph.mpc_summary();
    assert_eq!(summary.rounds, 0, "{summary:?}");
    assert_eq!(summary.local_muls, 0, "{summary:?}");
    assert_eq!(summary.public_muls, 1, "{summary:?}");

    let program = circom_mpc_compiler::compile(circuit_path("gadget_public_test"), &cfg).unwrap();
    assert_eq!(program.statistics().gadget_batches, 1);
    assert!(program.statistics().public_gadget_results > 0);
    let values = [Fr::from(0u64), Fr::from(9u64)];
    let inputs = program.classify_inputs(&values, |v| v);
    let witness = Machine::run(&program, &mut PlainDriver, &inputs).unwrap();
    assert_eq!(witness[1], Fr::from(0u64));
}
