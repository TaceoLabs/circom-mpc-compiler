//! Proves the MPC lowering pipeline's headline claim - independent secret multiplications at the
//! same multiplicative depth batch into a single network round - against three synthetic circuits
//! with known round structure (`circuits/bench_{chain,tree,widesum}.circom`). No golden witness is
//! needed here: `Graph::mpc_summary` reports round *shape*, which a witness comparison can't see.
//! See `docs/ARCHITECTURE.md`, "MPC lowering".
//!
//! These are synthetic because the circuits that currently compile at all are small (only
//! `Add`/`Sub`/`Mul` are supported - see `docs/ARCHITECTURE.md`, "Known gaps") - there is no large
//! real circuit yet to measure round batching against.

use ark_bn254::Bn254;
use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig};

fn manifest_dir() -> &'static str {
    env!("CARGO_MANIFEST_DIR")
}

fn circuit_path(name: &str) -> String {
    format!("{}/circuits/{name}.circom", manifest_dir())
}

fn config() -> CompilerConfig {
    let mut config = CompilerConfig::default();
    config
        .link_library
        .push(format!("{}/circuits/libs/", manifest_dir()).into());
    config
}

#[test]
fn chain_of_dependent_products_needs_one_round_per_depth() {
    let graph = CoCircomCompiler::<Bn254>::parse(circuit_path("bench_chain"), config()).unwrap();
    let summary = graph.mpc_summary();
    assert_eq!(summary.rounds, 3, "{summary:?}");
    assert_eq!(summary.reshare_elements, 3, "{summary:?}");
    assert_eq!(summary.min_slots_per_round, Some(1), "{summary:?}");
    assert_eq!(summary.max_slots_per_round, Some(1), "{summary:?}");
}

#[test]
fn balanced_tree_batches_each_level_into_one_round() {
    let graph = CoCircomCompiler::<Bn254>::parse(circuit_path("bench_tree"), config()).unwrap();
    let summary = graph.mpc_summary();
    assert_eq!(summary.rounds, 3, "{summary:?}");
    assert_eq!(summary.reshare_elements, 4 + 2 + 1, "{summary:?}");
    assert_eq!(summary.max_slots_per_round, Some(4), "{summary:?}");
    assert_eq!(summary.min_slots_per_round, Some(1), "{summary:?}");
}

#[test]
fn independent_products_batch_into_a_single_round() {
    let graph = CoCircomCompiler::<Bn254>::parse(circuit_path("bench_widesum"), config()).unwrap();
    let summary = graph.mpc_summary();
    assert_eq!(summary.rounds, 1, "{summary:?}");
    assert_eq!(summary.reshare_elements, 4, "{summary:?}");
    assert_eq!(summary.max_slots_per_round, Some(4), "{summary:?}");
}
