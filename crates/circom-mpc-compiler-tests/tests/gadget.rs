//! Verifies gadget recognition: `Poseidon2`, `Num2Bits`, `IsZero` and `AliasCheck` are each cut
//! into exactly one gadget site, matched by their own circom name regardless of what (if anything)
//! wraps them - except (for `unsupported_gadget_test`'s `Doubler`) an unrecognized name, which is
//! not recognized at all.

use ark_bn254::Fr;
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

/// The gadget-wrapper circuits: `main` wraps exactly one recognized gadget each, matched by its
/// own circom name regardless of the wrapper.
fn wrappers() -> Vec<&'static str> {
    vec![
        "gadget_poseidon2_test",
        "gadget_num2bits_test",
        "gadget_iszero_test",
        "gadget_aliascheck_test",
    ]
}

/// An unrecognized name (wrapped or not) simply compiles its body like any other template - here,
/// `Doubler`, a gadget this compiler has no gadget implementation for. Its body is
/// deliberately pure `Add`/`Sub`/`Mul`, so this succeeds rather than failing deeper on some
/// unrelated gap - exactly the situation the vendored `merkle_root_4.circom` is in with its
/// `Arity4CMux`.
#[test]
fn unrecognized_gadget_compiles_its_body() {
    let program = circom_mpc_compiler::compile(
        circuit_path("unsupported_gadget_test"),
        &config(),
    )
    .expect("an unrecognized gadget must compile its body");
    assert_eq!(
        program.statistics().gadget_sites,
        0,
        "an unrecognized gadget must not create a site"
    );

    // And the compiled body is correct: Doubler(in) = in + in.
    let values = [Fr::from(21u64)];
    let inputs = program.classify_inputs(&values, |v| v);
    let mut driver = PlainDriver;
    let witness = Machine::run(&program, &mut driver, &inputs).unwrap();
    assert_eq!(witness[1], Fr::from(42u64), "witness: {witness:?}");
}

#[test]
fn extract_mode_runs_end_to_end_through_the_plain_driver() {
    // Every recognized gadget kind must actually be serviceable by `PlainDriver` - this asserts the
    // whole VM pipeline (codegen -> Opcode::Gadget dispatch -> the main instruction stream) runs to
    // completion. This is a smoke test only (all-zero inputs) - see tests/proving.rs's prove+verify
    // tests for a real value comparison.
    for circuit in wrappers() {
        let program = circom_mpc_compiler::compile(circuit_path(circuit), &config())
            .unwrap_or_else(|e| panic!("{circuit}: {e}"));
        let values = vec![Fr::from(0u64); program.statistics().inputs];
        let inputs = program.classify_inputs(&values, |v| v);
        let mut driver = PlainDriver;
        Machine::run(&program, &mut driver, &inputs).unwrap_or_else(|e| panic!("{circuit}: {e}"));
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
    let program =
        circom_mpc_compiler::compile(circuit_path("gadget_staged_test"), &config()).unwrap();
    let stats = program.statistics();
    assert_eq!(stats.gadget_sites, 2);
    assert_eq!(
        stats.gadget_batches, 2,
        "dependent sites must not be batched together: {stats:?}"
    );

    // And it runs: a*b == 0 for these inputs, so the first IsZero returns 1.
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
    let program =
        circom_mpc_compiler::compile(circuit_path("gadget_iszero_test"), &config()).unwrap();
    let stats = program.statistics();
    assert_eq!(stats.gadget_sites, 1);
    assert_eq!(stats.gadget_batches, 1);
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
    let program = circom_mpc_compiler::compile(circuit_path("gadget_public_test"), &cfg).unwrap();
    let stats = program.statistics();
    assert_eq!(stats.multiplication_rounds, 0, "{stats:?}");
    assert_eq!(stats.multiplication_elements, 0, "{stats:?}");
    assert_eq!(stats.public_multiplications, 1, "{stats:?}");
    assert_eq!(stats.gadget_batches, 1);
    assert!(stats.public_gadget_results > 0);
    let values = [Fr::from(0u64), Fr::from(9u64)];
    let inputs = program.classify_inputs(&values, |v| v);
    let witness = Machine::run(&program, &mut PlainDriver, &inputs).unwrap();
    assert_eq!(witness[1], Fr::from(0u64));
}
