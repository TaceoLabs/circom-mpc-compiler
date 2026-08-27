//! `TACEO_INJECTED_Poseidon2` sites: the host precomputes Poseidon2's trace and hands it to
//! `Machine::run_with_injection` instead of the driver computing it. Poseidon2 is the only
//! injectable gadget. Covers batching (an injected site never shares a batch with a
//! driver-serviced one), plain-driver equivalence against the `TACEO_PRECOMPUTATION_Poseidon2`
//! twin, and the error paths around a malformed or missing injection.

use ark_bn254::Fr;

use circom_mpc_compiler::ir::PrecomputeKind;
use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig};
use circom_mpc_vm::driver::plain::PlainDriver;
use circom_mpc_vm::gadgets::poseidon2;
use circom_mpc_vm::program::BatchKind;
use circom_mpc_vm::{GadgetInjection, Machine, SiteTrace};

mod common;

use common::{circuit_path, libs_path};

fn config() -> CompilerConfig {
    let mut config = CompilerConfig::default();
    config.link_library.push(libs_path());
    config
}

#[test]
fn injected_poseidon2_site_is_its_own_batch() {
    let program =
        CoCircomCompiler::compile(circuit_path("injected_poseidon2_test"), config()).unwrap();
    assert_eq!(program.statistics().precompute_batches, 1);
    assert_eq!(program.statistics().injected_batches, 1);
    let batches = program.injected_batches().unwrap();
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].kind, PrecomputeKind::Poseidon2 { t: 3 });
    assert_eq!(batches[0].sites, 1);
}

/// An injected and a non-injected Poseidon2 site, at the same network stage, must land in two
/// different batches - an injected site's trace comes from the host, so it can never share a
/// driver call with one the driver still has to service.
#[test]
fn mixed_injected_and_normal_sites_never_share_a_batch() {
    let program =
        CoCircomCompiler::compile(circuit_path("injected_mixed_poseidon2_test"), config()).unwrap();
    let stats = program.statistics();
    assert_eq!(stats.precompute_batches, 2, "{stats:?}");
    assert_eq!(stats.injected_batches, 1, "{stats:?}");
    let injected = program.injected_batches().unwrap();
    assert_eq!(injected.len(), 1);
    assert_eq!(injected[0].kind, PrecomputeKind::Poseidon2 { t: 3 });
}

/// The same circuit, computed once through `TACEO_PRECOMPUTATION_Poseidon2` and once through
/// `TACEO_INJECTED_Poseidon2` fed the host-precomputed trace, must produce byte-identical
/// witnesses.
#[test]
fn injected_poseidon2_matches_the_precomputation_twin() {
    let plain_program =
        CoCircomCompiler::compile(circuit_path("precomputation_poseidon2_test"), config()).unwrap();
    let injected_program =
        CoCircomCompiler::compile(circuit_path("injected_poseidon2_test"), config()).unwrap();

    let values = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let expected = {
        let inputs = plain_program.classify_inputs(&values, |v| v);
        Machine::run(&plain_program, &mut PlainDriver, &inputs).unwrap()
    };

    let inputs = injected_program.classify_inputs(&values, |v| v);
    let mut injection = GadgetInjection::new();
    injection.push_batch(poseidon2::plain_trace(3, &values).unwrap());
    let got = Machine::run_with_injection(&injected_program, &mut PlainDriver, &inputs, injection)
        .unwrap();
    assert_eq!(got, expected);
}

#[test]
fn machine_run_errors_on_a_program_with_injected_batches() {
    let program =
        CoCircomCompiler::compile(circuit_path("injected_poseidon2_test"), config()).unwrap();
    let values = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let inputs = program.classify_inputs(&values, |v| v);
    let err = Machine::run(&program, &mut PlainDriver, &inputs).unwrap_err();
    assert!(err.to_string().contains("missing injected trace"), "{err}");
}

#[test]
fn wrong_site_count_is_rejected() {
    let program =
        CoCircomCompiler::compile(circuit_path("injected_poseidon2_test"), config()).unwrap();
    let values = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let inputs = program.classify_inputs(&values, |v| v);
    let mut injection = GadgetInjection::new();
    let mut traces = poseidon2::plain_trace(3, &values).unwrap();
    traces.push(traces[0].clone());
    injection.push_batch(traces);
    let err =
        Machine::run_with_injection(&program, &mut PlainDriver, &inputs, injection).unwrap_err();
    assert!(err.to_string().contains("expected 1"), "{err}");
}

#[test]
fn short_intermediate_is_rejected() {
    let program =
        CoCircomCompiler::compile(circuit_path("injected_poseidon2_test"), config()).unwrap();
    let values = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let inputs = program.classify_inputs(&values, |v| v);
    let mut injection = GadgetInjection::new();
    let traces = poseidon2::plain_trace(3, &values).unwrap();
    injection.push_batch(vec![SiteTrace::new(traces[0].output.clone(), Vec::new())]);
    let err =
        Machine::run_with_injection(&program, &mut PlainDriver, &inputs, injection).unwrap_err();
    assert!(
        err.to_string().contains("requested intermediate slot"),
        "{err}"
    );
}

#[test]
fn leftover_injection_after_the_run_is_rejected() {
    let program =
        CoCircomCompiler::compile(circuit_path("injected_poseidon2_test"), config()).unwrap();
    let values = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let inputs = program.classify_inputs(&values, |v| v);
    let mut injection = GadgetInjection::new();
    injection.push_batch(poseidon2::plain_trace(3, &values).unwrap());
    injection.push_batch(poseidon2::plain_trace(3, &values).unwrap());
    let err =
        Machine::run_with_injection(&program, &mut PlainDriver, &inputs, injection).unwrap_err();
    assert!(err.to_string().contains("unconsumed batch"), "{err}");
}

#[test]
fn an_all_public_injected_site_is_rejected_at_compile_time() {
    let err =
        CoCircomCompiler::compile(circuit_path("injected_all_public_test"), config()).unwrap_err();
    assert!(err.to_string().contains("all-Public"), "{err}");
}

#[test]
fn a_wrapper_kind_mismatch_is_rejected_at_compile_time() {
    let err = CoCircomCompiler::compile(circuit_path("injected_wrapper_mismatch_test"), config())
        .unwrap_err();
    assert!(err.to_string().contains("injectable gadget"), "{err}");
}

#[test]
fn batch_kind_injected_is_never_used_for_a_non_injected_site() {
    let program =
        CoCircomCompiler::compile(circuit_path("precomputation_poseidon2_test"), config()).unwrap();
    assert_eq!(program.statistics().injected_batches, 0);
    // `injected_batches()` walks `BatchKind::InjectedPoseidon2` specifically - confirm the
    // ordinary precomputation path never produces one.
    assert!(program.injected_batches().unwrap().is_empty());
    let _ = BatchKind::Precompute(PrecomputeKind::Poseidon2 { t: 3 }); // kept in scope for the import
}
