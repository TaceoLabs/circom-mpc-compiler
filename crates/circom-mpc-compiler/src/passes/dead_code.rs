//! Dead code elimination: drops every `outputs` entry that cannot reach the final witness, then
//! runs [`Graph::gc`]'s reverse-liveness sweep to delete the now-unreferenced producers.
//!
//! The output pruning matters because most of a recognized gadget gadget's result slots
//! are *not* witness positions: circom's own `--O2` constraint simplification removes the vast
//! majority of e.g. a Poseidon2 trace from the witness - often the great majority. Without
//! pruning, every dead result slot would stay bound into `outputs`, survive every later pass,
//! reserve a real codegen slot, and be copied around by `Machine::run`.

use crate::ir::Graph;

#[allow(
    clippy::unnecessary_wraps,
    reason = "must match the shared PassFn signature every pass in the pipeline implements, even though this pass never fails today"
)]
pub(super) fn run(graph: &mut Graph) -> eyre::Result<bool> {
    // Hand-built graphs (pass unit tests, codegen tests) pass an empty `signal_to_witness`.
    // Pruning against an empty witness would delete every output, so skip the pruning there.
    let mut changed = false;
    if !graph.signal_to_witness.is_empty() {
        // `Machine::run` reserves index 0 for the constant `1` and places every genuine
        // `SignalIdx` `s` at `s + 1`; `signal_to_witness` indexes into that same offset-by-one
        // space, so the mask must match it exactly.
        let mut witness_mask = vec![false; graph.num_signals()];
        for &idx in &graph.signal_to_witness {
            if let Some(slot) = witness_mask.get_mut(idx) {
                *slot = true;
            }
        }
        changed |= graph.retain_outputs(|signal, _value| {
            witness_mask
                .get(signal.index() + 1)
                .copied()
                .unwrap_or(false)
        });
    }

    let before = graph.len();
    graph.gc();
    Ok(changed || graph.len() != before)
}
