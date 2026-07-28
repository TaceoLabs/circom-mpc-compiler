//! Wraps [`Graph::gc`] as a [`Pass`] - dead code elimination is already a single reverse-liveness
//! sweep (`src/ir.rs`); this just gives it the shared `Pass` interface so it can sit in the same
//! pipeline as everything else.

use ark_ff::PrimeField;

use crate::ir::Graph;

use super::{Changed, Pass, PassContext};

pub(super) struct DeadCode;

impl<F: PrimeField> Pass<F> for DeadCode {
    fn name(&self) -> &'static str {
        "dead_code"
    }

    fn run(&mut self, graph: &mut Graph<F>, _ctx: &mut PassContext) -> eyre::Result<Changed> {
        let before = graph.len();
        graph.gc();
        Ok(graph.len() != before)
    }
}
