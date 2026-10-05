//! Reorders the graph by `(network_level, full_level)` so independent same-depth public gadget
//! sites become adjacent and `gadget_schedule` merges them into one batch. `network_levels` keeps
//! public chains at one level, so two independent public chains are otherwise indistinguishable
//! from one long chain.
//!
//! Runs after `round_schedule`: each `Round` and its `RoundResult` block move as one unit,
//! preserving the adjacency codegen relies on. Sorting on the pair keeps every stage-s shared site
//! ahead of every stage-s+1 node, so shared batches never split.

use std::ops::Range;

use super::{domain::compute_domains, level};
use crate::ir::{Graph, Node, Op, ValueId};

pub(crate) fn run(graph: &mut Graph) -> bool {
    let nodes = graph.nodes();
    if nodes.is_empty() {
        return false;
    }

    let net = level::network_levels(graph, &compute_domains(graph));
    let full = level::full_levels(graph);

    // A `Round` and its `RoundResult` block form one unit.
    let mut units: Vec<Range<usize>> = Vec::new();
    let mut i = 0;
    while i < nodes.len() {
        let len = match &nodes[i].op {
            Op::Round(_) => {
                let slots = nodes[i].inputs.len();
                debug_assert!(
                    i + slots < nodes.len()
                        && (0..slots).all(|k| matches!(
                            nodes[i + 1 + k].op,
                            Op::RoundResult(slot) if slot as usize == k
                        )),
                    "wide_schedule: Round at {i} not followed by its RoundResult block"
                );
                1 + slots
            }
            Op::RoundResult(_) => unreachable!("consumed with its Round"),
            _ => 1,
        };
        units.push(i..i + len);
        i += len;
    }

    let key = |unit: &Range<usize>| (net[unit.start], full[unit.start]);
    if units.is_sorted_by_key(key) {
        return false;
    }
    units.sort_by_key(key);

    let old_len = nodes.len();
    let mut remap: Vec<Option<ValueId>> = vec![None; old_len];
    let mut new_nodes: Vec<Node> = Vec::with_capacity(old_len);

    for idx in units.into_iter().flatten() {
        let node = &nodes[idx];
        let remapped_inputs = node
            .inputs
            .iter()
            .map(|v| remap[v.index()].expect("wide_schedule: input not yet placed"))
            .collect();
        remap[idx] = Some(ValueId::new(new_nodes.len()));
        new_nodes.push(Node::new(node.op.clone(), remapped_inputs));
    }

    graph.rebuild_nodes(new_nodes, &remap);
    true
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;

    use super::*;
    use crate::{
        ir::{GadgetId, GadgetKind, GadgetSite, GraphParts, RoundId, SignalIdx},
        passes::mpc::{
            domain::{Domain, compute_domains},
            gadget_schedule::{self, ScheduledBatch},
            round_schedule,
        },
    };

    fn site(kind: GadgetKind) -> GadgetSite {
        GadgetSite {
            kind,
            precomputed: false,
        }
    }

    fn graph_of(nodes: Vec<Node>, output: ValueId, sites: Vec<GadgetSite>) -> Graph {
        Graph::from_parts(GraphParts {
            nodes,
            outputs: vec![(SignalIdx::new(0), output)],
            gadget_sites: sites,
            num_inputs: 0,
            num_outputs: 1,
            num_signals: 1,
            ..Default::default()
        })
    }

    fn batches(graph: &Graph, domain: Domain) -> Vec<usize> {
        let domains = compute_domains(graph);
        gadget_schedule::plan_gadget_batches(graph, &domains)
            .iter()
            .filter_map(|plan| match plan {
                ScheduledBatch::Gadget(plan) if plan.domain == domain => Some(plan.sites.len()),
                _ => None,
            })
            .collect()
    }

    /// Two independent public chains emitted depth-first merge level by level.
    #[test]
    fn widens_independent_public_chains() {
        let nodes = vec![
            Node::new(Op::Constant(Fr::from(0u64)), vec![]), // 0: chain A leaf
            Node::new(Op::Gadget(GadgetId::new(0)), vec![ValueId::new(0)]), // 1: A level 1
            Node::new(Op::GadgetResult(0), vec![ValueId::new(1)]), // 2
            Node::new(Op::Gadget(GadgetId::new(1)), vec![ValueId::new(2)]), // 3: A level 2
            Node::new(Op::GadgetResult(0), vec![ValueId::new(3)]), // 4
            Node::new(Op::Constant(Fr::from(1u64)), vec![]), // 5: chain B leaf
            Node::new(Op::Gadget(GadgetId::new(2)), vec![ValueId::new(5)]), // 6: B level 1
            Node::new(Op::GadgetResult(0), vec![ValueId::new(6)]), // 7
            Node::new(Op::Gadget(GadgetId::new(3)), vec![ValueId::new(7)]), // 8: B level 2
            Node::new(Op::GadgetResult(0), vec![ValueId::new(8)]), // 9
            Node::new(Op::Add, vec![ValueId::new(4), ValueId::new(9)]), // 10
        ];
        let sites = vec![site(GadgetKind::IsZero); 4];
        let mut graph = graph_of(nodes, ValueId::new(10), sites);

        assert_eq!(batches(&graph, Domain::Public).len(), 3);
        assert!(run(&mut graph));
        assert_eq!(batches(&graph, Domain::Public), vec![2, 2]);
    }

    #[test]
    fn leaves_a_lone_public_chain_untouched() {
        let nodes = vec![
            Node::new(Op::Constant(Fr::from(0u64)), vec![]), // 0
            Node::new(Op::Gadget(GadgetId::new(0)), vec![ValueId::new(0)]), // 1
            Node::new(Op::GadgetResult(0), vec![ValueId::new(1)]), // 2
            Node::new(Op::Gadget(GadgetId::new(1)), vec![ValueId::new(2)]), // 3
            Node::new(Op::GadgetResult(0), vec![ValueId::new(3)]), // 4
        ];
        let sites = vec![site(GadgetKind::IsZero), site(GadgetKind::IsZero)];
        let mut graph = graph_of(nodes, ValueId::new(4), sites);
        assert!(!run(&mut graph));
    }

    /// Sorting by `full_levels` alone would move X's reader ahead of Y (stage 0, full depth 2)
    /// and split the shared batch.
    #[test]
    fn keeps_same_stage_shared_sites_in_one_batch() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0: secret a
            Node::new(Op::Input(SignalIdx::new(2)), vec![]), // 1: secret b
            Node::new(Op::Constant(Fr::from(0u64)), vec![]), // 2: public c
            Node::new(Op::Gadget(GadgetId::new(0)), vec![ValueId::new(0)]), // 3: X
            Node::new(Op::GadgetResult(0), vec![ValueId::new(3)]), // 4
            Node::new(Op::Add, vec![ValueId::new(4), ValueId::new(4)]), // 5: X's reader
            Node::new(Op::Gadget(GadgetId::new(1)), vec![ValueId::new(2)]), // 6: P1
            Node::new(Op::GadgetResult(0), vec![ValueId::new(6)]), // 7
            Node::new(Op::Gadget(GadgetId::new(2)), vec![ValueId::new(7)]), // 8: P2
            Node::new(Op::GadgetResult(0), vec![ValueId::new(8)]), // 9
            Node::new(Op::Add, vec![ValueId::new(1), ValueId::new(9)]), // 10
            Node::new(Op::Gadget(GadgetId::new(3)), vec![ValueId::new(10)]), // 11: Y
            Node::new(Op::GadgetResult(0), vec![ValueId::new(11)]), // 12
            Node::new(Op::Add, vec![ValueId::new(5), ValueId::new(12)]), // 13
        ];
        let sites = vec![site(GadgetKind::IsZero); 4];
        let mut graph = graph_of(nodes, ValueId::new(13), sites);
        round_schedule::run(&mut graph);

        assert_eq!(batches(&graph, Domain::Shared), vec![2]);
        run(&mut graph);
        assert_eq!(batches(&graph, Domain::Shared), vec![2]);
    }

    /// A `Round` moves together with its `RoundResult`s.
    #[test]
    fn moves_a_round_and_its_results_as_one_block() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0: secret a
            Node::new(Op::Input(SignalIdx::new(2)), vec![]), // 1: secret b
            Node::new(Op::MulLocal, vec![ValueId::new(0), ValueId::new(1)]), // 2
            Node::new(Op::Round(RoundId::new(0)), vec![ValueId::new(2)]), // 3
            Node::new(Op::RoundResult(0), vec![ValueId::new(3)]), // 4
            Node::new(Op::Constant(Fr::from(0u64)), vec![]), // 5: public chain leaf
            Node::new(Op::Gadget(GadgetId::new(0)), vec![ValueId::new(5)]), // 6
            Node::new(Op::GadgetResult(0), vec![ValueId::new(6)]), // 7
            Node::new(Op::Gadget(GadgetId::new(1)), vec![ValueId::new(7)]), // 8
            Node::new(Op::GadgetResult(0), vec![ValueId::new(8)]), // 9
            Node::new(Op::Add, vec![ValueId::new(4), ValueId::new(9)]), // 10
        ];
        let sites = vec![site(GadgetKind::IsZero), site(GadgetKind::IsZero)];
        let mut graph = graph_of(nodes, ValueId::new(10), sites);
        round_schedule::run(&mut graph);
        run(&mut graph);

        let round = graph
            .nodes()
            .iter()
            .position(|n| matches!(n.op, Op::Round(_)))
            .expect("Round must survive reordering");
        assert!(matches!(graph.nodes()[round + 1].op, Op::RoundResult(0)));
    }
}
