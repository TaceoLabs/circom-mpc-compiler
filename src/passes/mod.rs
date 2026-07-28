//! Pass infrastructure: a [`Pass`] trait, a [`PassManager`] that drives passes to a fixpoint, and
//! the [`OptLevel`] config knob that selects which passes run. See `docs/ARCHITECTURE.md`, "Pass
//! infrastructure", for why this exists and how `Graph::rewrite` (`src/ir.rs`) is what makes each
//! pass a small, self-contained node rewrite instead of hand-rolled `ValueId` bookkeeping.

mod const_fold;
mod dead_code;

use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};

use crate::ir::Graph;

/// Whether a [`Pass::run`] call actually modified the graph. Drives the [`PassManager`]'s
/// fixpoint loop: passes keep re-running while any one of them reports `true`.
pub type Changed = bool;

/// Which passes [`PassManager::for_opt_level`] runs. Deliberately distinct from
/// `SimplificationLevel` (`src/lib.rs`), which configures upstream circom constraint
/// simplification, not this crate's own IR passes.
#[derive(
    Debug, Default, Copy, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash,
)]
pub enum OptLevel {
    /// Dead code elimination only.
    O0,
    /// Dead code elimination + constant folding.
    #[default]
    O1,
    /// Reserved for CSE/GVN, algebraic simplification, and rep3-specific passes as they land (see
    /// `docs/ARCHITECTURE.md`, "Where this is headed") - identical to O1 today.
    O2,
}

/// Shared, cross-pass state: an opt-level driving pass selection today, and where cached analyses
/// (e.g. a future share-kind assignment) will live as `Option<T>` fields once a pass needs one.
/// Kept as typed fields rather than a type-erased map, since there will be a handful of these, not
/// dozens.
#[derive(Debug, Default)]
pub(crate) struct PassContext {
    #[allow(dead_code)] // consulted once a pass needs to branch on opt level, not yet true of either pass
    pub(crate) opt: OptLevel,
}

/// One rewrite or analysis over the IR. Implementations should build their transformation on
/// [`Graph::rewrite`] rather than hand-rolling `ValueId` remapping - see its docs in `src/ir.rs`
/// for why that matters in this IR (a node's `ValueId` is its position, so deleting or replacing
/// any node shifts every later reference).
pub(crate) trait Pass<F: PrimeField> {
    /// Short, human-readable name, used only in `tracing` diagnostics.
    fn name(&self) -> &'static str;

    /// Runs the pass once, returning whether it changed the graph. [`PassManager`] re-runs the
    /// whole pipeline while any pass returns `true`, so a pass may assume it will get another
    /// chance to see the effects of passes that ran after it.
    fn run(&mut self, graph: &mut Graph<F>, ctx: &mut PassContext) -> eyre::Result<Changed>;
}

/// Drives a fixed list of passes to a fixpoint, bounded by `max_iterations` so a pass that (by
/// mistake) oscillates between two states cannot hang the compiler.
pub(crate) struct PassManager<F: PrimeField> {
    passes: Vec<Box<dyn Pass<F>>>,
    max_iterations: usize,
}

impl<F: PrimeField> PassManager<F> {
    pub(crate) fn for_opt_level(opt: OptLevel) -> Self {
        let mut passes: Vec<Box<dyn Pass<F>>> = vec![Box::new(dead_code::DeadCode)];
        if opt >= OptLevel::O1 {
            passes.push(Box::new(const_fold::ConstFold));
        }
        Self {
            passes,
            max_iterations: 4,
        }
    }

    /// Runs the pipeline to a fixpoint. `graph` must already have passed [`Graph::verify`] once -
    /// this re-verifies after every pass, but only in debug builds (`verify` walks every node, and
    /// a pass that broke an invariant should fail loudly and immediately rather than surface as a
    /// confusing error several passes later).
    pub(crate) fn run(&mut self, graph: &mut Graph<F>) -> eyre::Result<()> {
        let mut ctx = PassContext::default();
        for _ in 0..self.max_iterations {
            let mut changed = false;
            for pass in &mut self.passes {
                let before = graph.len();
                let pass_changed = pass.run(graph, &mut ctx)?;
                if cfg!(debug_assertions) {
                    graph.verify()?;
                }
                tracing::debug!(
                    "pass {}: {before} -> {} nodes ({})",
                    pass.name(),
                    graph.len(),
                    if pass_changed { "changed" } else { "no-op" }
                );
                changed |= pass_changed;
            }
            if !changed {
                break;
            }
        }
        Ok(())
    }
}
