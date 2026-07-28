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

        // Network level per (old-space) value - see `super::level`, which owns the formula because
        // `vm::codegen` and `Graph::mpc_summary` need the identical numbers. Crucially this charges a
        // level for crossing a *precomputation site* as well as a round: a site's results are not
        // available at the same instant as its inputs (every rep3 `VmDriver::*_traces` gadget
        // communicates), and pretending otherwise made the depth-bucketed rebuild below emit a
        // forward reference whenever a site's inputs were computed rather than bare `Op::Input`s.
        let depth = super::level::network_levels(graph);

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
                    level: d,
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

    use crate::ir::{Node, Op, PrecomputeId, PrecomputeKind, PrecomputeSite, SignalIdx, ValueId};

    use super::*;

    fn graph_of(nodes: Vec<Node<Fr>>, output: ValueId) -> Graph<Fr> {
        graph_with_sites(nodes, output, vec![])
    }

    fn graph_with_sites(
        nodes: Vec<Node<Fr>>,
        output: ValueId,
        sites: Vec<PrecomputeSite>,
    ) -> Graph<Fr> {
        Graph::from_parts(
            nodes,
            vec![(SignalIdx::new(0), output)],
            sites,
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

    /// Regression for a genuine panic (`round_schedule: input not yet placed`, an `expect` so it
    /// fired in release too). A precomputation site whose inputs are *computed* rather than bare
    /// `Op::Input`s used to be pinned to level 0 while its inputs sat deeper, so the rebuild below
    /// visited the site before the values it reads. This is the shape
    /// `circuits/merces/merces/dependencies/merkle_root_4.circom` has - `Arity4CMux` multiplies
    /// secret selector bits, feeds a Poseidon2 site, and that site's result feeds the next level -
    /// so it blocked every merces circuit before `level::network_levels` charged for a site.
    #[test]
    fn site_between_two_products_does_not_panic() {
        use super::super::mul_split::MulSplit;

        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0: a
            Node::new(Op::Input(SignalIdx::new(2)), vec![]), // 1: b
            Node::new(Op::Mul, vec![ValueId::new(0), ValueId::new(1)]), // 2: a*b (round 0)
            // The site consumes a value that only exists after round 0.
            Node::new(Op::Precompute(PrecomputeId::new(0)), vec![ValueId::new(2)]), // 3
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(3)]),              // 4
            // ... and its result feeds a further product, which therefore needs its own round.
            Node::new(Op::Mul, vec![ValueId::new(4), ValueId::new(0)]), // 5
        ];
        let mut graph = graph_with_sites(
            nodes,
            ValueId::new(5),
            vec![PrecomputeSite {
                kind: PrecomputeKind::IsZero,
                name: "IsZero".to_owned(),
                header: "IsZero_0".to_owned(),
                num_inputs: 1,
                num_outputs: 1,
                num_intermediates: 1,
            }],
        );
        Pass::run(&mut MulSplit, &mut graph, &mut PassContext::default()).unwrap();
        let changed = Pass::run(&mut RoundSchedule, &mut graph, &mut PassContext::default()).unwrap();
        assert!(changed);
        // Two products separated by a site service: they can never share a round.
        assert_eq!(graph.rounds().len(), 2);
        assert!(graph.rounds().iter().all(|r| r.len == 1));
        // The site sits between them on the same axis, so the second round is two levels later.
        assert_eq!(graph.rounds()[0].level, 0);
        assert_eq!(graph.rounds()[1].level, 2);
    }
}
