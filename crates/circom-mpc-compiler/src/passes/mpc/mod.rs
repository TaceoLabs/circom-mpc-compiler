//! MPC lowering: turns a plain value-graph into one whose secret multiplications are expressed as
//! local-part/network-part pairs batched into as few rounds as possible. Unlike the classical
//! passes in `super`, this is a lowering *sequence*, run once, not a fixpoint - every public entry
//! point runs it unconditionally; there is no plaintext-only end state.

pub(crate) mod domain;
pub(crate) mod gadget_schedule;
pub(crate) mod level;
mod mul_split;
mod round_schedule;
mod wide_schedule;

use super::PassFn;

/// The lowering pipeline, in order: split every secret multiplication into its local and network
/// parts, batch the resulting rounds by multiplicative depth, then widen independent same-depth
/// *public* gadget batches the same way - see `wide_schedule`'s module doc for why it must run
/// last, after `round_schedule` has already established the `Round`/`RoundResult` adjacency it
/// depends on.
pub(super) fn pipeline() -> Vec<(&'static str, PassFn)> {
    vec![
        ("mpc::mul_split", mul_split::run),
        ("mpc::round_schedule", round_schedule::run),
        ("mpc::wide_schedule", wide_schedule::run),
    ]
}
