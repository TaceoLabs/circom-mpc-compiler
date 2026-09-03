//! Splits every secret x secret `Mul` into its free local part (`Op::MulLocal`) and a network part
//! (a singleton `Op::Round` + `Op::RoundResult(0)`), one round per product. A `Mul` with any
//! `Public` operand is left alone - it's already free, rep3's `mul_public`.
//!
//! This alone is a correct, independently testable lowering: it's exactly `rep3::arithmetic::mul`
//! called once per secret product (`local_mul` then `reshare`). `round_schedule`, the next pass in
//! the pipeline, batches these singleton rounds into fewer, wider ones.

use crate::ir::{Graph, Node, Op, RewriteAction, RoundId, ValueId};

use super::domain::{compute_domains, Domain};

#[allow(
    clippy::unnecessary_wraps,
    reason = "must match the shared PassFn signature every pass in the pipeline implements, even though this pass never fails today"
)]
pub(crate) fn run(graph: &mut Graph) -> eyre::Result<bool> {
    // The split decision depends only on the *old* graph, so classify it up front. Inside the
    // rewrite closure only the old-space node id is stable (`Graph::rewrite` remaps inputs to
    // new-space ids), so the decision is looked up by that id.
    let domains = compute_domains(graph);
    let should_split: Vec<bool> = graph
        .nodes()
        .iter()
        .map(|node| {
            matches!(node.op, Op::Mul)
                && domains[node.inputs[0].index()] == Domain::Shared
                && domains[node.inputs[1].index()] == Domain::Shared
        })
        .collect();

    let mut num_rounds = 0;
    let changed = graph.rewrite(|id, node, emitted| {
        if !should_split[id.index()] {
            return RewriteAction::Keep;
        }
        // `emitted.len()` is the new-space id the next emitted node will get.
        let mul_local_id = ValueId::new(emitted.len());
        let round_new_id = ValueId::new(emitted.len() + 1);
        let round_id = RoundId::new(num_rounds);
        num_rounds += 1;
        RewriteAction::EmitMany(vec![
            Node::new(Op::MulLocal, node.inputs.clone()),
            Node::new(Op::Round(round_id), vec![mul_local_id]),
            Node::new(Op::RoundResult(0), vec![round_new_id]),
        ])
    });

    graph.set_num_rounds(num_rounds);
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;

    use crate::ir::{GraphParts, Node, Op, SignalIdx, ValueId};

    use super::*;

    fn graph_of(nodes: Vec<Node>, output: ValueId) -> Graph {
        Graph::from_parts(GraphParts {
            nodes,
            outputs: vec![(SignalIdx::new(0), output)],
            num_inputs: 2,
            num_outputs: 1,
            num_signals: 3,
            ..Default::default()
        })
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
        let changed = run(&mut graph).expect("run should not fail on this test graph");
        assert!(changed);
        assert_eq!(graph.len(), 5); // Input, Input, MulLocal, Round, RoundResult
        assert!(matches!(graph.nodes()[ValueId::new(2).index()].op, Op::MulLocal));
        assert!(matches!(graph.nodes()[ValueId::new(3).index()].op, Op::Round(_)));
        assert!(matches!(graph.nodes()[ValueId::new(4).index()].op, Op::RoundResult(0)));
        assert_eq!(graph.num_rounds(), 1);
        assert_eq!(graph.round_slots(), vec![1]);
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
        let changed = run(&mut graph).expect("run should not fail on this test graph");
        assert!(!changed);
        assert_eq!(graph.len(), 3);
        assert!(matches!(graph.nodes()[ValueId::new(2).index()].op, Op::Mul));
        assert_eq!(graph.num_rounds(), 0);
    }
}
