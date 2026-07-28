//! Pass infrastructure: a [`Pass`] trait, a [`PassManager`] that drives passes to a fixpoint, and
//! the [`OptLevel`] config knob that selects which passes run. See `docs/ARCHITECTURE.md`, "Pass
//! infrastructure", for why this exists and how `Graph::rewrite` (`src/ir.rs`) is what makes each
//! pass a small, self-contained node rewrite instead of hand-rolled `ValueId` bookkeeping.

mod algebraic;
mod const_fold;
mod cse;
mod dead_code;
mod mpc;
mod normalize;
mod poly;

use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};

use crate::ir::Graph;

/// Whether a [`Pass::run`] call actually modified the graph. Drives the [`PassManager`]'s
/// fixpoint loop: passes keep re-running while any one of them reports `true`.
pub type Changed = bool;

/// Which *classical* passes [`PassManager::for_opt_level`] runs, in its fixpoint stage.
/// Deliberately distinct from `SimplificationLevel` (`src/lib.rs`), which configures upstream
/// circom constraint simplification, not this crate's own IR passes. Independent of MPC lowering
/// (`passes::mpc`), which always runs regardless of opt level - see `docs/ARCHITECTURE.md`, "MPC
/// lowering".
#[derive(
    Debug, Default, Copy, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash,
)]
pub enum OptLevel {
    /// Dead code elimination only.
    O0,
    /// Dead code elimination + constant folding.
    #[default]
    O1,
    /// Adds CSE/GVN, commutative-operand canonicalization, and affine normalization.
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

/// Drives the classical passes to a fixpoint (bounded by `max_iterations`, so a pass that - by
/// mistake - oscillates between two states cannot hang the compiler), then runs the MPC lowering
/// pipeline once, unconditionally. Two stages, not one fixpoint, because lowering is not an
/// optimization to converge on - it's the compiler's actual output, and it only makes sense to run
/// once the classical passes are done simplifying the plain graph they operate over. See
/// `docs/ARCHITECTURE.md`, "MPC lowering".
pub(crate) struct PassManager<F: PrimeField> {
    optimize: Vec<Box<dyn Pass<F>>>,
    lower: Vec<Box<dyn Pass<F>>>,
    max_iterations: usize,
}

impl<F: PrimeField> PassManager<F> {
    pub(crate) fn for_opt_level(opt: OptLevel) -> Self {
        let mut optimize: Vec<Box<dyn Pass<F>>> = vec![Box::new(dead_code::DeadCode)];
        if opt >= OptLevel::O1 {
            optimize.push(Box::new(const_fold::ConstFold));
        }
        if opt >= OptLevel::O2 {
            optimize.push(Box::new(cse::Cse));
            optimize.push(Box::new(algebraic::Algebraic));
            optimize.push(Box::new(normalize::Normalize));
        }
        Self {
            optimize,
            lower: mpc::pipeline(),
            max_iterations: 4,
        }
    }

    /// Runs the classical passes to a fixpoint, then the MPC lowering pipeline once, then marks
    /// the graph lowered. `graph` must already have passed [`Graph::verify`] once - this
    /// re-verifies after every pass, but only in debug builds (`verify` walks every node, and a
    /// pass that broke an invariant should fail loudly and immediately rather than surface as a
    /// confusing error several passes later).
    pub(crate) fn run(&mut self, graph: &mut Graph<F>) -> eyre::Result<()> {
        let mut ctx = PassContext::default();
        for _ in 0..self.max_iterations {
            let mut changed = false;
            for pass in &mut self.optimize {
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

        // Marked before the lowering passes run, not after: the first of them (mul_split) already
        // introduces MPC ops, and the debug-build `verify()` below must not mistake that for a
        // Stage::Plain graph carrying ops it shouldn't have.
        graph.mark_lowered();
        for pass in &mut self.lower {
            let before = graph.len();
            pass.run(graph, &mut ctx)?;
            if cfg!(debug_assertions) {
                graph.verify()?;
            }
            tracing::debug!("lowering pass {}: {before} -> {} nodes", pass.name(), graph.len());
        }
        Ok(())
    }
}
