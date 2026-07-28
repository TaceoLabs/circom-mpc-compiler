//! Splits every secret x secret `Mul` into its free local part (`Op::MulLocal`) and a network part
//! (a singleton `Op::Round` + `Op::RoundResult(0)`), one round per product. A `Mul` with any
//! `Public` operand is left alone - it's already free, rep3's `mul_public`.
//!
//! This alone is a correct, independently testable lowering: it's exactly `rep3::arithmetic::mul`
//! called once per secret product (`local_mul` then `reshare`). `round_schedule`, the next pass in
//! the pipeline, is what batches these singleton rounds into fewer, wider ones - see
//! `docs/ARCHITECTURE.md`, "MPC lowering".
//!
//! Computes [`Domain`] incrementally, in new-space, as it rewrites - not from a precomputed
//! old-space array. `Graph::rewrite` remaps every node's inputs to *new*-space ids before this
//! pass's callback ever sees them (so an `EmitMany` earlier in the same rewrite shifts every later
//! index), so an old-space domain table computed up front couldn't be indexed by the ids this
//! callback actually receives. Recomputing alongside `new_nodes` keeps the two in lockstep for
//! free.

use ark_ff::PrimeField;

use crate::ir::{Graph, Node, Op, RewriteAction, RoundDesc, RoundId, RoundKind, ValueId};
use crate::passes::{Changed, Pass, PassContext};

use super::domain::{signal_domain, Domain};

pub(crate) struct MulSplit;

impl<F: PrimeField> Pass<F> for MulSplit {
    fn name(&self) -> &'static str {
        "mpc::mul_split"
    }

    fn run(&mut self, graph: &mut Graph<F>, _ctx: &mut PassContext) -> eyre::Result<Changed> {
        // Copied out before `rewrite` takes `&mut graph`, so `signal_domain` doesn't need to
        // borrow `graph` from inside the rewrite closure - see its own doc.
        let num_outputs = graph.num_outputs;
        let input_list = graph.input_list.clone();
        let public_inputs = graph.public_inputs.clone();

        // Domain of each *new-space* value, grown by exactly one entry per node pushed to
        // `new_nodes` inside `Graph::rewrite` - see the module doc for why this can't be a
        // precomputed old-space array.
        let mut domain: Vec<Domain> = Vec::with_capacity(graph.len());
        let mut rounds: Vec<RoundDesc> = Vec::new();

        let changed = graph.rewrite(|_id, node, _emitted| match &node.op {
            Op::Mul
                if domain[node.inputs[0].index()] == Domain::Shared
                    && domain[node.inputs[1].index()] == Domain::Shared =>
            {
                let mul_local_id = ValueId::new(domain.len());
                let round_new_id = ValueId::new(domain.len() + 1);
                let round_id = RoundId::new(rounds.len());
                rounds.push(RoundDesc {
                    kind: RoundKind::Reshare,
                    len: 1,
                    level: 0, // recomputed structurally by round_schedule; unused until then
                });
                domain.push(Domain::Local); // MulLocal
                domain.push(Domain::Public); // Round's own value is never read directly
                domain.push(Domain::Shared); // RoundResult(0)
                RewriteAction::EmitMany(vec![
                    Node::new(Op::MulLocal, node.inputs.clone()),
                    Node::new(Op::Round(round_id), vec![mul_local_id]),
                    Node::new(Op::RoundResult(0), vec![round_new_id]),
                ])
            }
            Op::Constant(_) => {
                domain.push(Domain::Public);
                RewriteAction::Keep
            }
            Op::Input(sig) => {
                domain.push(signal_domain(num_outputs, &input_list, &public_inputs, *sig));
                RewriteAction::Keep
            }
            Op::Add | Op::Sub | Op::Mul => {
                let d = domain[node.inputs[0].index()].join(domain[node.inputs[1].index()]);
                domain.push(d);
                RewriteAction::Keep
            }
            // Never read directly (see Op::Precompute's own doc) - the domain recorded here is
            // never consulted by anything.
            Op::Precompute(_) => {
                domain.push(Domain::Public);
                RewriteAction::Keep
            }
            Op::PrecomputeResult(_) => {
                domain.push(Domain::Shared);
                RewriteAction::Keep
            }
            // mul_split runs before any of these exist (frontend never produces them, and it's the
            // first lowering pass) - handled defensively so this match stays exhaustive as Op
            // grows, not because it's reachable today.
            Op::MulLocal => {
                domain.push(Domain::Local);
                RewriteAction::Keep
            }
            Op::Round(_) => {
                domain.push(Domain::Public);
                RewriteAction::Keep
            }
            Op::RoundResult(_) => {
                domain.push(Domain::Shared);
                RewriteAction::Keep
            }
        });

        graph.set_rounds(rounds);
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;

    use crate::ir::{Node, Op, SignalIdx, ValueId};

    use super::*;

    fn graph_of(nodes: Vec<Node<Fr>>, output: ValueId) -> Graph<Fr> {
        Graph::from_parts(
            nodes,
            vec![(SignalIdx::new(0), output)],
            vec![],
            vec![],
            vec![],
            vec![],
            2,
            1,
            3,
        )
    }

    #[test]
    fn splits_secret_times_secret() {
        // x0 = Input(0); x1 = Input(1); x2 = Mul(x0, x1) -- both secret, must split
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // num_outputs=1, so signal 1 is input 0
            Node::new(Op::Input(SignalIdx::new(2)), vec![]),
            Node::new(Op::Mul, vec![ValueId::new(0), ValueId::new(1)]),
        ];
        let mut graph = graph_of(nodes, ValueId::new(2));
        let mut pass = MulSplit;
        let changed = Pass::run(&mut pass, &mut graph, &mut PassContext::default()).unwrap();
        assert!(changed);
        assert_eq!(graph.len(), 5); // Input, Input, MulLocal, Round, RoundResult
        assert!(matches!(graph.node(ValueId::new(2)).op, Op::MulLocal));
        assert!(matches!(graph.node(ValueId::new(3)).op, Op::Round(_)));
        assert!(matches!(graph.node(ValueId::new(4)).op, Op::RoundResult(0)));
        assert_eq!(graph.rounds().len(), 1);
        assert_eq!(graph.rounds()[0].len, 1);
    }

    #[test]
    fn leaves_public_multiplication_alone() {
        // x0 = Constant(2); x1 = Input(0); x2 = Mul(x0, x1) -- one operand public, stays free
        let nodes = vec![
            Node::new(Op::Constant(Fr::from(2u64)), vec![]),
            Node::new(Op::Input(SignalIdx::new(1)), vec![]),
            Node::new(Op::Mul, vec![ValueId::new(0), ValueId::new(1)]),
        ];
        let mut graph = graph_of(nodes, ValueId::new(2));
        let mut pass = MulSplit;
        let changed = Pass::run(&mut pass, &mut graph, &mut PassContext::default()).unwrap();
        assert!(!changed);
        assert_eq!(graph.len(), 3);
        assert!(matches!(graph.node(ValueId::new(2)).op, Op::Mul));
        assert!(graph.rounds().is_empty());
    }
}
