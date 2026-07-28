//! MPC lowering: turns a plain value-graph into one whose secret multiplications are expressed as
//! local-part/network-part pairs batched into as few rounds as possible. Unlike the classical
//! passes in `super`, this is a lowering *sequence*, run once, not a fixpoint - every public entry
//! point (`CoCircomCompiler::parse`, via `PassManager::run`) runs it unconditionally; there is no
//! plaintext-only end state. See `docs/ARCHITECTURE.md`, "MPC lowering".

pub(crate) mod domain;
pub(crate) mod level;
mod mul_split;
mod round_schedule;

use ark_ff::PrimeField;

use super::Pass;

/// The lowering pipeline, in order: split every secret multiplication into its local and network
/// parts, then batch the resulting rounds by multiplicative depth.
pub(crate) fn pipeline<F: PrimeField>() -> Vec<Box<dyn Pass<F>>> {
    vec![
        Box::new(mul_split::MulSplit),
        Box::new(round_schedule::RoundSchedule),
    ]
}
