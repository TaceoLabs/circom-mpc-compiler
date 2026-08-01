//! Proves the MPC lowering pipeline's headline claim - independent secret multiplications at the
//! same multiplicative depth batch into a single network round - against three synthetic circuits
//! with known round structure (`circuits/bench_{chain,tree,widesum}.circom`). No witness value
//! oracle is needed here: `Graph::mpc_summary` reports round *shape*, which a value comparison
//! can't see.
//!
//! Synthetic, because round shape must be known in advance to assert on; `tests/merces.rs`
//! covers batching on the real circuits.

use ark_bn254::Bn254;
use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig};

mod common;

use common::{circuit_path, libs_path};

fn config() -> CompilerConfig {
    let mut config = CompilerConfig::default();
    config.link_library.push(libs_path());
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
