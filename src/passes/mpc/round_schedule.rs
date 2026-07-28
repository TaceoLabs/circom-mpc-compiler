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

use super::domain::compute_domains;

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

        // Network level per (old-space) value. Crossing a shared precomputation site advances the
        // axis; a public result remains at its producer's level and relies on preserved source order
        // within that bucket. Feeding the existing domain table into both computations keeps round
        // scheduling and precompute planning on the same cost model.
        let domains = compute_domains(graph);
        let depth = super::level::network_levels_with_domains(graph, &domains);

        // Bucket every node once. Iterating these buckets below, rather than rescanning all nodes
        // for every distinct level, keeps reconstruction linear in the graph size. Insertion order
        // is source order, so nodes within one level remain deterministic and topological.
        let max_depth = depth.iter().copied().max().unwrap_or(0);
        let mut nodes_by_depth: Vec<Vec<usize>> = (0..=max_depth).map(|_| Vec::new()).collect();

        // Every singleton round mul_split created, grouped by depth, in original creation order -
        // that order is also each round's slot order in the merged round. mul_split always emits
        // [MulLocal, Round, RoundResult(0)] as three consecutive nodes, so the RoundResult always
        // immediately follows its Round (relied on below), checked defensively.
        let mut rounds_by_depth: Vec<Vec<(ValueId, usize)>> =
            (0..=max_depth).map(|_| Vec::new()).collect();
        for (i, node) in nodes.iter().enumerate() {
            match &node.op {
                Op::Round(_) => {
                    debug_assert!(
                        nodes.len() > i + 1 && matches!(nodes[i + 1].op, Op::RoundResult(0)),
                        "mul_split invariant violated: Round not immediately followed by RoundResult(0)"
                    );
                    rounds_by_depth[depth[i]].push((node.inputs[0], i + 1));
                }
                // Re-emitted alongside the merged round that produces it.
                Op::RoundResult(_) => {}
                _ => nodes_by_depth[depth[i]].push(i),
            }
        }

        let has_rounds = rounds_by_depth.iter().any(|rounds| !rounds.is_empty());
        let already_level_sorted = depth.windows(2).all(|pair| pair[0] <= pair[1]);
        if !has_rounds && already_level_sorted {
            return Ok(false);
        }

        let old_len = nodes.len();
        let mut remap: Vec<Option<ValueId>> = vec![None; old_len];
        let mut new_nodes: Vec<Node<F>> = Vec::with_capacity(old_len);
        let mut new_rounds: Vec<RoundDesc> = Vec::new();

        for (d, (level_nodes, level_rounds)) in
            nodes_by_depth.iter().zip(&rounds_by_depth).enumerate()
        {
            for &i in level_nodes {
                let node = &nodes[i];
                let remapped_inputs = node
                    .inputs
                    .iter()
                    .map(|v| remap[v.index()].expect("round_schedule: input not yet placed"))
                    .collect();
                remap[i] = Some(ValueId::new(new_nodes.len()));
                new_nodes.push(Node::new(node.op.clone(), remapped_inputs));
            }
            if !level_rounds.is_empty() {
                let round_id = RoundId::new(new_rounds.len());
                new_rounds.push(RoundDesc {
                    kind: RoundKind::Reshare,
                    len: level_rounds.len(),
                    level: d,
                });
                let round_inputs = level_rounds
                    .iter()
                    .map(|(mul_local, _)| {
                        remap[mul_local.index()].expect("round_schedule: MulLocal not yet placed")
                    })
                    .collect();
                let round_new_id = ValueId::new(new_nodes.len());
                new_nodes.push(Node::new(Op::Round(round_id), round_inputs));
                for (k, (_, old_round_result_idx)) in level_rounds.iter().enumerate() {
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
        let changed =
            Pass::run(&mut RoundSchedule, &mut graph, &mut PassContext::default()).unwrap();
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
        let changed =
            Pass::run(&mut RoundSchedule, &mut graph, &mut PassContext::default()).unwrap();
        assert!(changed);
        assert_eq!(graph.rounds().len(), 1);
        assert_eq!(graph.rounds()[0].len, 2);
    }

    /// A precomputation site whose inputs are *computed* rather than bare `Op::Input`s must be
    /// placed strictly after the level that produces those inputs, or the rebuild below would visit
    /// the site before the values it reads (a real panic: `round_schedule: input not yet placed`).
    /// This is the shape `circuits/merces/merces/dependencies/merkle_root_4.circom` has -
    /// `Arity4CMux` multiplies secret selector bits, feeds a Poseidon2 site, and that site's result
    /// feeds the next level.
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
                header: "IsZero_0".to_owned(),
                num_inputs: 1,
                num_outputs: 1,
                num_intermediates: 1,
            }],
        );
        Pass::run(&mut MulSplit, &mut graph, &mut PassContext::default()).unwrap();
        let changed =
            Pass::run(&mut RoundSchedule, &mut graph, &mut PassContext::default()).unwrap();
        assert!(changed);
        // Two products separated by a site service: they can never share a round.
        assert_eq!(graph.rounds().len(), 2);
        assert!(graph.rounds().iter().all(|r| r.len == 1));
        // The site sits between them on the same axis, so the second round is two levels later.
        assert_eq!(graph.rounds()[0].level, 0);
        assert_eq!(graph.rounds()[1].level, 2);
    }

    /// Even without secret multiplications, level sorting is required to put every independent
    /// site in a batch before the first consumer of that batch's results. In source order site 0's
    /// consumer precedes site 1, so codegen cannot anchor their shared batch unless the scheduler
    /// moves the independent later site forward.
    #[test]
    fn zero_round_sites_move_before_an_early_result_consumer() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0: x
            Node::new(Op::Input(SignalIdx::new(2)), vec![]), // 1: y
            Node::new(Op::Precompute(PrecomputeId::new(0)), vec![ValueId::new(0)]), // 2: A
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(2)]), // 3: A.result
            Node::new(Op::Add, vec![ValueId::new(3), ValueId::new(0)]), // 4: early consumer
            Node::new(Op::Precompute(PrecomputeId::new(1)), vec![ValueId::new(1)]), // 5: B
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(5)]), // 6: B.result
            Node::new(Op::Add, vec![ValueId::new(4), ValueId::new(6)]), // 7: output
        ];
        let sites = (0..2)
            .map(|site| PrecomputeSite {
                kind: PrecomputeKind::IsZero,
                header: format!("IsZero_{site}"),
                num_inputs: 1,
                num_outputs: 1,
                num_intermediates: 1,
            })
            .collect();
        let mut graph = graph_with_sites(nodes, ValueId::new(7), sites);

        let changed =
            Pass::run(&mut RoundSchedule, &mut graph, &mut PassContext::default()).unwrap();
        assert!(changed);
        assert!(graph.rounds().is_empty());

        let later_site = graph
            .nodes()
            .iter()
            .position(|node| matches!(&node.op, Op::Precompute(site) if site.index() == 1))
            .unwrap();
        let first_consumer = graph
            .nodes()
            .iter()
            .position(|node| matches!(node.op, Op::Add))
            .unwrap();
        assert!(
            later_site < first_consumer,
            "site B at {later_site} must precede site A's consumer at {first_consumer}"
        );

        // This used to fail the batch anchor/deadline check in codegen.
        graph.mark_lowered();
        let program = crate::vm::codegen::compile(&graph).unwrap();
        assert_eq!(program.precompute_batches.len(), 1);
    }

    /// A deep chain exercises one distinct network level per round. Reconstruction must visit each
    /// node once rather than scanning the complete graph again for every level.
    #[test]
    fn deep_round_chain_rebuilds_all_levels() {
        const DEPTH: usize = 4_096;

        let mut nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]),
            Node::new(Op::Input(SignalIdx::new(2)), vec![]),
        ];
        let rhs = ValueId::new(1);
        let mut value = ValueId::new(0);
        for round in 0..DEPTH {
            let local = ValueId::new(nodes.len());
            nodes.push(Node::new(Op::MulLocal, vec![value, rhs]));
            let round_node = ValueId::new(nodes.len());
            nodes.push(Node::new(Op::Round(RoundId::new(round)), vec![local]));
            value = ValueId::new(nodes.len());
            nodes.push(Node::new(Op::RoundResult(0), vec![round_node]));
        }

        let mut graph = graph_of(nodes, value);
        let changed =
            Pass::run(&mut RoundSchedule, &mut graph, &mut PassContext::default()).unwrap();
        assert!(changed);
        assert_eq!(graph.rounds().len(), DEPTH);
        for (level, round) in graph.rounds().iter().enumerate() {
            assert_eq!(round.level, level);
            assert_eq!(round.len, 1);
        }
    }
}
