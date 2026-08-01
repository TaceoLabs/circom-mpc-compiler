//! MPC lowering: turns a plain value-graph into one whose secret multiplications are expressed as
//! local-part/network-part pairs batched into as few rounds as possible. Unlike the classical
//! passes in `super`, this is a lowering *sequence*, run once, not a fixpoint - every public entry
//! point runs it unconditionally; there is no plaintext-only end state.

pub(crate) mod domain;
pub(crate) mod level;
mod mul_split;
pub(crate) mod precompute_schedule;
mod round_schedule;

use ark_ff::PrimeField;

use super::PassFn;

/// The lowering pipeline, in order: split every secret multiplication into its local and network
/// parts, then batch the resulting rounds by multiplicative depth.
pub(super) fn pipeline<F: PrimeField>() -> Vec<(&'static str, PassFn<F>)> {
    vec![
        ("mpc::mul_split", mul_split::run),
        ("mpc::round_schedule", round_schedule::run),
    ]
}
