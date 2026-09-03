//! Pass infrastructure: a [`PassManager`] that drives the classical passes to a fixpoint, then
//! runs MPC lowering once. Passes are plain functions built on `Graph::rewrite` (`src/ir.rs`).

mod const_fold;
mod cse;
mod dead_code;
// pub(crate), not private: `vm::codegen` reuses `mpc::domain` and `mpc::gadget_schedule`.
pub(crate) mod mpc;

use serde::{Deserialize, Serialize};

use crate::ir::Graph;

/// Which *classical* passes the pass manager runs in its fixpoint stage. Distinct from upstream
/// circom's own constraint simplification (always run at full `--O2`), and independent of MPC
/// lowering, which always runs regardless of opt level.
#[derive(
    Debug, Default, Copy, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash,
)]
pub enum OptLevel {
    /// Dead code elimination only.
    O0,
    /// Dead code elimination + constant folding.
    #[default]
    O1,
    /// Adds CSE/GVN.
    O2,
}

/// One pass: runs once over the graph, returns whether it changed anything.
type PassFn = fn(&mut Graph) -> eyre::Result<bool>;

/// Drives the classical passes to a fixpoint (bounded, so an oscillating pass cannot hang the
/// compiler), then runs the MPC lowering pipeline once, unconditionally - lowering is the
/// compiler's actual output, not an optimization to converge on.
pub(crate) struct PassManager {
    optimize: Vec<(&'static str, PassFn)>,
    lower: Vec<(&'static str, PassFn)>,
    max_iterations: usize,
}

impl PassManager {
    pub(crate) fn for_opt_level(opt: OptLevel) -> Self {
        let mut optimize: Vec<(&'static str, PassFn)> = vec![("dead_code", dead_code::run)];
        if opt >= OptLevel::O1 {
            optimize.push(("const_fold", const_fold::run));
        }
        if opt >= OptLevel::O2 {
            optimize.push(("cse", cse::run));
        }
        Self {
            optimize,
            lower: mpc::pipeline(),
            max_iterations: 4,
        }
    }

    /// Runs the classical passes to a fixpoint, then the MPC lowering pipeline once.
    pub(crate) fn run(&mut self, graph: &mut Graph) -> eyre::Result<()> {
        for _ in 0..self.max_iterations {
            let mut changed = false;
            for (name, pass) in &self.optimize {
                let before = graph.len();
                let pass_changed = pass(graph)?;
                tracing::debug!(
                    "pass {name}: {before} -> {} nodes ({})",
                    graph.len(),
                    if pass_changed { "changed" } else { "no-op" }
                );
                changed |= pass_changed;
            }
            if !changed {
                break;
            }
        }

        for (name, pass) in &self.lower {
            let before = graph.len();
            pass(graph)?;
            tracing::debug!("lowering pass {name}: {before} -> {} nodes", graph.len());
        }
        Ok(())
    }
}
