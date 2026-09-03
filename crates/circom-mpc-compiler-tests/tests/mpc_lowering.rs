//! Proves the MPC lowering pipeline's headline claim - independent secret multiplications at the
//! same multiplicative depth batch into a single network round - against three synthetic circuits
//! with known round structure (`circuits/bench_{chain,tree,widesum}.circom`). No witness value
//! oracle is needed here: `Program::statistics` reports round *shape*, which a value comparison
//! can't see.
//!
//! Synthetic, because round shape must be known in advance to assert on.

use circom_mpc_compiler::CompilerConfig;

mod common;

use common::{circuit_path, libs_path};

fn config() -> CompilerConfig {
    let mut config = CompilerConfig::default();
    config.link_library.push(libs_path());
    config
}

#[test]
fn chain_of_dependent_products_needs_one_round_per_depth() {
    let program = circom_mpc_compiler::compile(circuit_path("bench_chain"), &config()).unwrap();
    let stats = program.statistics();
    assert_eq!(stats.multiplication_rounds, 3, "{stats:?}");
    assert_eq!(stats.multiplication_elements, 3, "{stats:?}");
    assert_eq!(stats.min_slots_per_round, Some(1), "{stats:?}");
    assert_eq!(stats.max_slots_per_round, Some(1), "{stats:?}");
}

#[test]
fn balanced_tree_batches_each_level_into_one_round() {
    let program = circom_mpc_compiler::compile(circuit_path("bench_tree"), &config()).unwrap();
    let stats = program.statistics();
    assert_eq!(stats.multiplication_rounds, 3, "{stats:?}");
    assert_eq!(stats.multiplication_elements, 4 + 2 + 1, "{stats:?}");
    assert_eq!(stats.max_slots_per_round, Some(4), "{stats:?}");
    assert_eq!(stats.min_slots_per_round, Some(1), "{stats:?}");
}

#[test]
fn independent_products_batch_into_a_single_round() {
    let program = circom_mpc_compiler::compile(circuit_path("bench_widesum"), &config()).unwrap();
    let stats = program.statistics();
    assert_eq!(stats.multiplication_rounds, 1, "{stats:?}");
    assert_eq!(stats.multiplication_elements, 4, "{stats:?}");
    assert_eq!(stats.max_slots_per_round, Some(4), "{stats:?}");
}
