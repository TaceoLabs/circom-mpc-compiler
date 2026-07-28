//! Merges every singleton `Op::Round` `mul_split` created into as few, as-wide rounds as possible:
//! one round per distinct multiplicative depth, via ASAP list scheduling. This is the headline MPC
//! transform - message count drops from one-per-secret-mul to one-per-depth-level. See
//! `docs/ARCHITECTURE.md`, "MPC lowering".
//!
//! Implemented as a direct depth-bucketed reconstruction, not a [`Graph::rewrite`] consumer:
//! merging several existing rounds into one changes arity (which no rewrite callback can express),
//! and an early product's final round is only fully known once every *other* product at its depth
//! has been seen - which can be later in the original node order, a forward reference a single
//! forward pass cannot express. [`Graph::gc`] sets the precedent for reaching past `rewrite` when
//! it doesn't fit the shape of the transformation.

use ark_ff::PrimeField;

use crate::ir::{Graph, Node, Op, RoundDesc, RoundId, RoundKind, ValueId};
use crate::passes::{Changed, Pass, PassContext};

pub(crate) struct RoundSchedule;

impl<F: PrimeField> Pass<F> for RoundSchedule {
    fn name(&self) -> &'static str {
        "mpc::round_schedule"
    }

    fn run(&mut self, graph: &mut Graph<F>, _ctx: &mut PassContext) -> eyre::Result<Changed> {
        let nodes = graph.nodes();
        if nodes.is_empty() {
            return Ok(false);
        }

        // MPC depth per (old-space) value: 0 for anything before the first round boundary, a round
        // crossing bumps depth by one. See docs/ARCHITECTURE.md, "MPC lowering", for the formula.
        let mut depth = vec![0usize; nodes.len()];
        for (i, node) in nodes.iter().enumerate() {
            depth[i] = match &node.op {
                Op::Input(_) | Op::Constant(_) | Op::Precompute(_) | Op::PrecomputeResult(_) => 0,
                Op::Add | Op::Sub | Op::Mul | Op::MulLocal => {
                    node.inputs.iter().map(|v| depth[v.index()]).max().unwrap_or(0)
                }
                // Same depth as the local product(s) that feed it - "this round crosses a
                // boundary at this depth".
                Op::Round(_) => node.inputs.iter().map(|v| depth[v.index()]).max().unwrap_or(0),
                Op::RoundResult(_) => depth[node.inputs[0].index()] + 1,
            };
        }

        // Every singleton round mul_split created, grouped by depth, in original creation order -
        // that order is also each round's slot order in the merged round. mul_split always emits
        // [MulLocal, Round, RoundResult(0)] as three consecutive nodes, so the RoundResult always
        // immediately follows its Round (relied on below), checked defensively.
        let mut by_depth: Vec<Vec<(ValueId, usize)>> = Vec::new();
        for (i, node) in nodes.iter().enumerate() {
            if let Op::Round(_) = &node.op {
                debug_assert!(
                    nodes.len() > i + 1 && matches!(nodes[i + 1].op, Op::RoundResult(0)),
                    "mul_split invariant violated: Round not immediately followed by RoundResult(0)"
                );
                let d = depth[i];
                if by_depth.len() <= d {
                    by_depth.resize(d + 1, Vec::new());
                }
                by_depth[d].push((node.inputs[0], i + 1));
            }
        }

        if by_depth.iter().all(Vec::is_empty) {
            return Ok(false); // no secret muls at all - nothing to merge
        }

        let old_len = nodes.len();
        let mut remap: Vec<Option<ValueId>> = vec![None; old_len];
        let mut new_nodes: Vec<Node<F>> = Vec::with_capacity(old_len);
        let mut new_rounds: Vec<RoundDesc> = Vec::new();
        let max_depth = depth.iter().copied().max().unwrap_or(0);

        for d in 0..=max_depth {
            for (i, node) in nodes.iter().enumerate() {
                if depth[i] != d || matches!(node.op, Op::Round(_) | Op::RoundResult(_)) {
                    continue;
                }
                let remapped_inputs = node
                    .inputs
                    .iter()
                    .map(|v| remap[v.index()].expect("round_schedule: input not yet placed"))
                    .collect();
                remap[i] = Some(ValueId::new(new_nodes.len()));
                new_nodes.push(Node::new(node.op.clone(), remapped_inputs));
            }
            if let Some(slots) = by_depth.get(d).filter(|s| !s.is_empty()) {
                let round_id = RoundId::new(new_rounds.len());
                new_rounds.push(RoundDesc {
                    kind: RoundKind::Reshare,
                    len: slots.len(),
                    depth: d,
                });
                let round_inputs = slots
                    .iter()
                    .map(|(mul_local, _)| {
                        remap[mul_local.index()].expect("round_schedule: MulLocal not yet placed")
                    })
                    .collect();
                let round_new_id = ValueId::new(new_nodes.len());
                new_nodes.push(Node::new(Op::Round(round_id), round_inputs));
                for (k, (_, old_round_result_idx)) in slots.iter().enumerate() {
                    let k32 = u32::try_from(k).expect("round has more than u32::MAX slots");
                    remap[*old_round_result_idx] = Some(ValueId::new(new_nodes.len()));
                    new_nodes.push(Node::new(Op::RoundResult(k32), vec![round_new_id]));
                }
            }
        }

        graph.rebuild_nodes(new_nodes, &remap);
        graph.set_rounds(new_rounds);
        Ok(true)
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
            3,
            1,
            4,
        )
    }

    // A chain of 3 secret products already split by mul_split: depth 0, 1, 2 - one round each,
    // and round_schedule must not be able to merge any of them (each depends on the previous).
    #[test]
    fn chain_of_products_stays_one_round_per_depth() {
        use super::super::mul_split::MulSplit;

        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0: a
            Node::new(Op::Input(SignalIdx::new(2)), vec![]), // 1: b
            Node::new(Op::Input(SignalIdx::new(3)), vec![]), // 2: c
            Node::new(Op::Mul, vec![ValueId::new(0), ValueId::new(1)]), // 3: a*b
            Node::new(Op::Mul, vec![ValueId::new(3), ValueId::new(2)]), // 4: (a*b)*c
        ];
        let mut graph = graph_of(nodes, ValueId::new(4));
        Pass::run(&mut MulSplit, &mut graph, &mut PassContext::default()).unwrap();
        let changed = Pass::run(&mut RoundSchedule, &mut graph, &mut PassContext::default()).unwrap();
        assert!(changed);
        assert_eq!(graph.rounds().len(), 2);
        assert!(graph.rounds().iter().all(|r| r.len == 1));
    }

    // Two independent secret products at the same depth must merge into a single round.
    #[test]
    fn independent_products_at_same_depth_merge() {
        use super::super::mul_split::MulSplit;

        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0: a
            Node::new(Op::Input(SignalIdx::new(2)), vec![]), // 1: b
            Node::new(Op::Input(SignalIdx::new(3)), vec![]), // 2: c
            Node::new(Op::Mul, vec![ValueId::new(0), ValueId::new(1)]), // 3: a*b
            Node::new(Op::Mul, vec![ValueId::new(1), ValueId::new(2)]), // 4: b*c
            Node::new(Op::Add, vec![ValueId::new(3), ValueId::new(4)]), // 5: a*b + b*c
        ];
        let mut graph = graph_of(nodes, ValueId::new(5));
        Pass::run(&mut MulSplit, &mut graph, &mut PassContext::default()).unwrap();
        let changed = Pass::run(&mut RoundSchedule, &mut graph, &mut PassContext::default()).unwrap();
        assert!(changed);
        assert_eq!(graph.rounds().len(), 1);
        assert_eq!(graph.rounds()[0].len, 2);
    }
}
