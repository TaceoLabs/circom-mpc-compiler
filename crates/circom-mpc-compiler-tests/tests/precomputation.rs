//! `TACEO_PRECOMPUTATION_Poseidon2` sites: the host precomputes Poseidon2's trace and hands it to
//! `Machine::run_with_precomputation` instead of the driver computing it. Poseidon2 is the only
//! gadget that can be host-precomputed. Covers batching (a host-precomputed site never shares a
//! batch with a driver-serviced one), plain-driver equivalence against the unwrapped `Poseidon2`
//! twin, and the error paths around a malformed or missing precomputation.

use ark_bn254::Fr;

use circom_mpc_compiler::CompilerConfig;
use circom_mpc_program::GadgetKind;
use circom_mpc_vm::driver::plain::PlainDriver;
use circom_mpc_vm::gadgets::poseidon2;
use circom_mpc_vm::program::BatchKind;
use circom_mpc_vm::{GadgetPrecomputation, InputValue, Machine, SiteTrace};

mod common;

use common::{circuit_path, libs_path};

/// Wraps every value as `InputValue::Secret` - the all-shared case most of this file's tests
/// exercise; the mixed-domain case gets its own test below.
fn secret(values: &[Fr]) -> Vec<InputValue<Fr>> {
    values.iter().copied().map(InputValue::Secret).collect()
}

fn config() -> CompilerConfig {
    let mut config = CompilerConfig::default();
    config.link_library.push(libs_path());
    config
}

#[test]
fn precomputed_poseidon2_site_is_its_own_batch() {
    let program =
        circom_mpc_compiler::compile(circuit_path("precomputation_poseidon2_test"), &config()).unwrap();
    assert_eq!(program.statistics().gadget_batches, 1);
    assert_eq!(program.statistics().precomputed_batches, 1);
    let batches = program.precomputed_batches().unwrap();
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].kind, GadgetKind::Poseidon2 { t: circom_mpc_program::Poseidon2Width::new(3).expect("3 is a supported width") });
    assert_eq!(batches[0].sites, 1);
}

/// A host-precomputed and a driver-serviced Poseidon2 site, at the same network stage, must land
/// in two different batches - a host-precomputed site's trace comes from the host, so it can
/// never share a driver call with one the driver still has to service.
#[test]
fn mixed_precomputed_and_gadget_sites_never_share_a_batch() {
    let program = circom_mpc_compiler::compile(
        circuit_path("precomputation_mixed_poseidon2_test"),
        &config(),
    )
    .unwrap();
    let stats = program.statistics();
    assert_eq!(stats.gadget_batches, 2, "{stats:?}");
    assert_eq!(stats.precomputed_batches, 1, "{stats:?}");
    let precomputed = program.precomputed_batches().unwrap();
    assert_eq!(precomputed.len(), 1);
    assert_eq!(precomputed[0].kind, GadgetKind::Poseidon2 { t: circom_mpc_program::Poseidon2Width::new(3).expect("3 is a supported width") });
}

/// The same circuit, computed once through an unwrapped, driver-serviced `Poseidon2` and once
/// through `TACEO_PRECOMPUTATION_Poseidon2` fed the host-precomputed trace, must produce
/// byte-identical witnesses.
#[test]
fn precomputed_poseidon2_matches_the_gadget_twin() {
    let gadget_program =
        circom_mpc_compiler::compile(circuit_path("gadget_poseidon2_test"), &config()).unwrap();
    let precomputed_program =
        circom_mpc_compiler::compile(circuit_path("precomputation_poseidon2_test"), &config()).unwrap();

    let values = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let expected = {
        let inputs = gadget_program.classify_inputs(&values, |v| v);
        Machine::run(&gadget_program, &mut PlainDriver, &inputs).unwrap()
    };

    let inputs = precomputed_program.classify_inputs(&values, |v| v);
    let mut precomputation = GadgetPrecomputation::new();
    precomputation.push_batch(poseidon2::plain_trace(3, &secret(&values)).unwrap());
    let got = Machine::run_with_precomputation(
        &precomputed_program,
        &mut PlainDriver,
        &inputs,
        precomputation,
    )
    .unwrap();
    assert_eq!(got, expected);
}

/// A host-precomputed site may mix Public and Shared inputs - only an all-Public site is rejected
/// (see `an_all_public_precomputed_site_is_rejected_at_compile_time`). The host builds the trace
/// from the same mix of `InputValue::Public`/`InputValue::Secret` the program itself classifies
/// its inputs into, and the resulting witness must match the driver-serviced twin.
#[test]
fn precomputed_poseidon2_with_a_mixed_public_and_shared_input_matches_the_gadget_twin() {
    let gadget_program =
        circom_mpc_compiler::compile(circuit_path("gadget_poseidon2_mixed_domain_test"), &config())
            .unwrap();
    let precomputed_program =
        circom_mpc_compiler::compile(circuit_path("precomputation_mixed_domain_test"), &config())
            .unwrap();

    let values = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let expected = {
        let inputs = gadget_program.classify_inputs(&values, |v| v);
        Machine::run(&gadget_program, &mut PlainDriver, &inputs).unwrap()
    };

    let inputs = precomputed_program.classify_inputs(&values, |v| v);
    let mut precomputation = GadgetPrecomputation::new();
    let states = [
        InputValue::Public(values[0]),
        InputValue::Secret(values[1]),
        InputValue::Secret(values[2]),
    ];
    precomputation.push_batch(poseidon2::plain_trace(3, &states).unwrap());
    let got = Machine::run_with_precomputation(
        &precomputed_program,
        &mut PlainDriver,
        &inputs,
        precomputation,
    )
    .unwrap();
    assert_eq!(got, expected);
}

#[test]
fn machine_run_errors_on_a_program_with_precomputed_batches() {
    let program =
        circom_mpc_compiler::compile(circuit_path("precomputation_poseidon2_test"), &config()).unwrap();
    let values = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let inputs = program.classify_inputs(&values, |v| v);
    let err = Machine::run(&program, &mut PlainDriver, &inputs).unwrap_err();
    assert!(
        err.to_string().contains("missing precomputed trace"),
        "{err}"
    );
}

#[test]
fn wrong_site_count_is_rejected() {
    let program =
        circom_mpc_compiler::compile(circuit_path("precomputation_poseidon2_test"), &config()).unwrap();
    let values = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let inputs = program.classify_inputs(&values, |v| v);
    let mut precomputation = GadgetPrecomputation::new();
    let mut traces = poseidon2::plain_trace(3, &secret(&values)).unwrap();
    traces.push(traces[0].clone());
    precomputation.push_batch(traces);
    let err = Machine::run_with_precomputation(&program, &mut PlainDriver, &inputs, precomputation)
        .unwrap_err();
    assert!(err.to_string().contains("expected 1"), "{err}");
}

#[test]
fn short_intermediate_is_rejected() {
    let program =
        circom_mpc_compiler::compile(circuit_path("precomputation_poseidon2_test"), &config()).unwrap();
    let values = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let inputs = program.classify_inputs(&values, |v| v);
    let mut precomputation = GadgetPrecomputation::new();
    let traces = poseidon2::plain_trace(3, &secret(&values)).unwrap();
    precomputation.push_batch(vec![SiteTrace::new(traces[0].output.clone(), Vec::new())]);
    let err = Machine::run_with_precomputation(&program, &mut PlainDriver, &inputs, precomputation)
        .unwrap_err();
    assert!(
        err.to_string().contains("requested intermediate slot"),
        "{err}"
    );
}

#[test]
fn leftover_precomputation_after_the_run_is_rejected() {
    let program =
        circom_mpc_compiler::compile(circuit_path("precomputation_poseidon2_test"), &config()).unwrap();
    let values = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let inputs = program.classify_inputs(&values, |v| v);
    let mut precomputation = GadgetPrecomputation::new();
    precomputation.push_batch(poseidon2::plain_trace(3, &secret(&values)).unwrap());
    precomputation.push_batch(poseidon2::plain_trace(3, &secret(&values)).unwrap());
    let err = Machine::run_with_precomputation(&program, &mut PlainDriver, &inputs, precomputation)
        .unwrap_err();
    assert!(err.to_string().contains("unconsumed batch"), "{err}");
}

#[test]
fn an_all_public_precomputed_site_falls_back_to_an_ordinary_gadget() {
    // Nothing for the host to precompute, so the wrapper is ignored rather than rejected - the
    // site compiles exactly as if it had called `Poseidon2` directly.
    let program =
        circom_mpc_compiler::compile(circuit_path("precomputation_all_public_test"), &config())
            .unwrap();
    assert_eq!(program.statistics().precomputed_batches, 0);
    assert!(program.precomputed_batches().unwrap().is_empty());
}

#[test]
fn a_wrapper_kind_mismatch_is_rejected_at_compile_time() {
    let err = circom_mpc_compiler::compile(
        circuit_path("precomputation_wrapper_mismatch_test"),
        &config(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("host-precomputed"), "{err}");
}

#[test]
fn batch_kind_precomputed_poseidon2_is_never_used_for_a_gadget_site() {
    let program =
        circom_mpc_compiler::compile(circuit_path("gadget_poseidon2_test"), &config()).unwrap();
    assert_eq!(program.statistics().precomputed_batches, 0);
    // `precomputed_batches()` walks `BatchKind::PrecomputedPoseidon2` specifically - confirm the
    // ordinary driver-serviced path never produces one.
    assert!(program.precomputed_batches().unwrap().is_empty());
    let _ = BatchKind::Gadget(GadgetKind::Poseidon2 { t: circom_mpc_program::Poseidon2Width::new(3).expect("3 is a supported width") }); // kept in scope for the import
}
