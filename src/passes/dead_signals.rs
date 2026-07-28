//! Drops every `outputs` entry that cannot reach the final witness, so `Graph::gc` (the very next
//! pass, `dead_code::DeadCode`) can delete the now-unreferenced producer nodes.
//!
//! `Graph::gc`'s reverse-liveness sweep already implements one half of "a value is live": read by
//! some ordinary node. The other half - "bound to a witness position" - is the one this pass adds,
//! and it reduces to a filter on `outputs` (`gc`'s own root list), because `outputs` is exactly
//! where a signal's value reaches `Machine::run`'s `stores`/witness projection. Nothing about
//! `gc`'s sweep changes; this pass only shrinks its root set first.
//!
//! This matters because most of a recognized precomputation gadget's result slots are *not*
//! witness positions: circom's own `--O2` constraint simplification removes the vast majority of a
//! Poseidon2 trace from the witness, keeping only what downstream constraints actually need. Before
//! this pass, every one of those dead result slots was still bound into `outputs`, kept alive
//! through every later pass, reserved a real codegen slot, and copied into `Machine::run`'s
//! `signals` array - see `docs/ARCHITECTURE.md`, "Real-world target circuits", for the measured
//! scale on the merces mains (roughly 90% of every Poseidon2 trace is witness-dead).

use ark_ff::PrimeField;

use crate::ir::Graph;

use super::{Changed, Pass, PassContext};

pub(super) struct DeadSignals;

impl<F: PrimeField> Pass<F> for DeadSignals {
    fn name(&self) -> &'static str {
        "dead_signals"
    }

    fn run(&mut self, graph: &mut Graph<F>, _ctx: &mut PassContext) -> eyre::Result<Changed> {
        // Hand-built graphs (pass unit tests, codegen tests, `Graph::from_parts` callers that never
        // populated `signal_to_witness`) pass `vec![]` here. Pruning against an empty witness would
        // delete every output, so this pass is a no-op wherever there is no witness projection to
        // prune against - not just an optimization that happens to do nothing.
        if graph.signal_to_witness.is_empty() {
            return Ok(false);
        }

        // `Machine::run` reserves index 0 for the constant `1` and places every genuine `SignalIdx`
        // `s` at `s + 1` - `signal_to_witness` already indexes into that same offset-by-one space
        // (see `vm/machine.rs`), so the mask must match it exactly.
        let mut witness_mask = vec![false; graph.num_signals];
        for &idx in &graph.signal_to_witness {
            if let Some(slot) = witness_mask.get_mut(idx) {
                *slot = true;
            }
        }

        let changed = graph.retain_outputs(|signal, _value| {
            witness_mask.get(signal.index() + 1).copied().unwrap_or(false)
        });
        Ok(changed)
    }
}
