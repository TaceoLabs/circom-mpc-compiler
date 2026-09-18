//! Per-value **network level**: how many communicating events must complete before a value exists.
//! An event is either a reshare round ([`Op::Round`]) or a shared gadget batch service
//! ([`Op::Gadget`]); public services execute locally at their inputs' level while retaining
//! ordinary instruction order.
//!
//! A shared site's *results* ([`Op::GadgetResult`]) sit one level above its inputs because its
//! MPC batch must communicate. Public gadget results stay at their inputs' level: they are ordinary
//! deterministic local work, and charging a network level would split otherwise batchable shared
//! work. Source order still keeps each public result after its producer.
//!
//! **One axis, not two.** Rounds and shared batch services use a single counter rather than getting a
//! `(depth, stage)` pair. Two consequences make this the right trade:
//!
//! - Two shared sites at the same level are mutually independent because a dependency forces `+1`.
//!   Public sites at one level may depend on each other, so the batch planner additionally enforces
//!   each batch's anchor/deadline window. The level distinction cannot be recovered from
//!   multiplicative depth alone: a chain like `Num2Bits(254)` -> `AliasCheck` -> `IsZero` has
//!   **zero multiplications between the gadgets**, so all three sit at identical multiplicative
//!   depth despite being sequentially dependent.
//! - A shared result at `+1` cannot be read at its producer's level. Public results may be read at
//!   the same level, but source order and the planner's placement window retain that local order.
//!
//! The cost, accepted deliberately for a shared site `S`: an unrelated product at `S`'s input level
//! cannot merge with a product reading `S`'s result. A 2D scheme could sometimes save that reshare,
//! but would split expensive shared gadget batches more aggressively. Public sites do not pay this
//! cost because their results stay at the same level.

use super::domain::Domain;
use crate::ir::{Graph, Op};

/// Shared skeleton for [`network_levels`] and [`full_levels`]: both are one forward pass where
/// every rule is `max(inputs)` or `max(inputs) + 1`, and differ only in how much a `GadgetResult`
/// costs. `domains` selects that difference: `Some` exempts a `Domain::Public` producer from
/// crossing a level ([`network_levels`]' rule), `None` always charges one ([`full_levels`]' rule).
fn levels_with(graph: &Graph, domains: Option<&[Domain]>) -> Vec<usize> {
    let nodes = graph.nodes();
    let mut level = vec![0usize; nodes.len()];
    for (i, node) in nodes.iter().enumerate() {
        let max_input = || {
            node.inputs
                .iter()
                .map(|v| level[v.index()])
                .max()
                .unwrap_or(0)
        };
        level[i] = match &node.op {
            // Available before any network event.
            Op::Input(_) | Op::Constant(_) => 0,
            // Free local work in every domain (no event of its own), or the network event itself,
            // which sits at the level of the values it consumes - crossing it is what costs a
            // level, which is what the two `*Result` arms below charge for.
            Op::Add | Op::Sub | Op::Mul | Op::MulLocal | Op::Round(_) | Op::Gadget(_) => {
                max_input()
            }
            Op::RoundResult(_) => level[node.inputs[0].index()] + 1,
            Op::GadgetResult(_) => {
                let gadget_idx = node.inputs[0].index();
                match domains {
                    // A public gadget is ordinary deterministic local work. Its result must
                    // remain after its producer in graph order, but it must not advance the
                    // communication axis or split otherwise batchable shared work. Shared gadgets
                    // remain real network events.
                    //
                    // Keyed on the *producing* `Op::Gadget` node's own domain
                    // (`domains[gadget_idx]`), not the result's own (`domains[i]`). For every kind
                    // but `Reveal` the two coincide - `passes::mpc::domain::compute_domains`
                    // copies a site's domain straight onto its results - so this is unobservable
                    // there. `Reveal` is the one kind whose *result* domain is unconditionally
                    // `Public` (that is its entire purpose) while its *site* can still genuinely
                    // be `Shared` - and a genuine open is a real network event that must still
                    // charge a level, exactly as if the result stayed `Shared`.
                    Some(domains) => match domains[gadget_idx] {
                        Domain::Public => level[gadget_idx],
                        // `Local` is an invalid lowered graph, rejected later with a proper
                        // codegen error; charging it the same level as `Shared` keeps this
                        // analysis total so diagnostics never turn that rejection into a panic.
                        Domain::Shared | Domain::Local => level[gadget_idx] + 1,
                    },
                    None => level[gadget_idx] + 1,
                }
            }
        };
    }
    level
}

/// The network level of every value in `graph`, indexed by [`crate::ir::ValueId`]. `domains` is
/// the graph's [`super::domain::compute_domains`] result.
///
/// Relies only on the graph's topological order: every node's inputs have
/// smaller indices, so one forward pass suffices. Every rule is `max(inputs)` or `max(inputs) + 1`,
/// so the result is non-decreasing along every edge. `round_schedule` preserves source order within
/// a level, keeping same-level public gadget dependencies topological.
pub(crate) fn network_levels(graph: &Graph, domains: &[Domain]) -> Vec<usize> {
    debug_assert_eq!(
        graph.nodes().len(),
        domains.len(),
        "domains must have one entry per node"
    );
    levels_with(graph, Some(domains))
}

/// Like [`network_levels`], but does not exempt `Domain::Public` gadget results from crossing a
/// level - every `GadgetResult` advances the counter, regardless of its producing site's domain.
///
/// `network_levels`' Public exemption is deliberate (see the module doc) and stays exactly as is
/// for round scheduling. But it means two independent same-shape *public* gadget chains - e.g. two
/// unrelated Merkle-path hashes - both sit at level 0 for their entire length, since public work
/// never advances that axis. That makes `network_levels` useless for telling "these two public
/// sites are at the same dependency depth" apart from "these two public sites are ten levels
/// apart in the same chain" - a distinction [`super::wide_schedule`] needs to find independent
/// same-depth public work worth widening into one batch, without touching the round-scheduling
/// metric everything else already relies on.
pub(crate) fn full_levels(graph: &Graph) -> Vec<usize> {
    levels_with(graph, None)
}

/// The **stage** of every gadget site, indexed by [`crate::ir::GadgetId`] - the level of
/// its [`Op::Gadget`] node, i.e. how many network events must complete before the site can be
/// serviced.
///
/// Sites sharing a stage are mutually independent (see the module doc), so
/// `(kind, stage, domain)` is a sound batch key: everything in one batch can be serviced together.
///
/// Panics if a site has no `Op::Gadget` node - the frontend emits exactly one per site.
pub(crate) fn site_stages(graph: &Graph, domains: &[Domain]) -> Vec<usize> {
    let level = network_levels(graph, domains);
    let mut stages = vec![None; graph.gadget_sites().len()];
    for (i, node) in graph.nodes().iter().enumerate() {
        if let Op::Gadget(site) = &node.op {
            stages[site.index()] = Some(level[i]);
        }
    }
    stages
        .into_iter()
        .enumerate()
        .map(|(site, stage)| {
            stage.unwrap_or_else(|| panic!("gadget site {site} has no Op::Gadget node"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;

    use super::{super::domain::compute_domains, *};
    use crate::ir::{GadgetId, GadgetKind, GadgetSite, GraphParts, Node, SignalIdx, ValueId};

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
            num_inputs: 3,
            num_outputs: 1,
            num_signals: 4,
            ..Default::default()
        })
    }

    /// A site's results sit one level above its inputs, never the same level.
    #[test]
    fn site_results_are_one_level_above_their_inputs() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0
            Node::new(Op::Gadget(GadgetId::new(0)), vec![ValueId::new(0)]), // 1
            Node::new(Op::GadgetResult(0), vec![ValueId::new(1)]), // 2
        ];
        let graph = graph_of(nodes, ValueId::new(2), vec![site(GadgetKind::IsZero)]);
        assert_eq!(
            network_levels(&graph, &compute_domains(&graph)),
            vec![0, 0, 1]
        );
        assert_eq!(site_stages(&graph, &compute_domains(&graph)), vec![0]);
    }

    /// The `server.circom` shape: `Num2Bits` -> `AliasCheck` -> `IsZero`, chained with **no
    /// multiplication between them**. Any scheme keyed on multiplicative depth would put all three
    /// at depth 0 and batch dependent sites together; levels must separate them.
    #[test]
    fn chained_sites_with_no_multiplication_get_distinct_stages() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0
            Node::new(Op::Gadget(GadgetId::new(0)), vec![ValueId::new(0)]), // 1
            Node::new(Op::GadgetResult(0), vec![ValueId::new(1)]), // 2
            Node::new(Op::Gadget(GadgetId::new(1)), vec![ValueId::new(2)]), // 3
            Node::new(Op::GadgetResult(0), vec![ValueId::new(3)]), // 4
            Node::new(Op::Gadget(GadgetId::new(2)), vec![ValueId::new(4)]), // 5
            Node::new(Op::GadgetResult(0), vec![ValueId::new(5)]), // 6
        ];
        let graph = graph_of(
            nodes,
            ValueId::new(6),
            vec![
                site(GadgetKind::Num2Bits { n: 1 }),
                site(GadgetKind::AliasCheck),
                site(GadgetKind::IsZero),
            ],
        );
        assert_eq!(
            network_levels(&graph, &compute_domains(&graph)),
            vec![0, 0, 1, 1, 2, 2, 3]
        );
        assert_eq!(site_stages(&graph, &compute_domains(&graph)), vec![0, 1, 2]);
    }

    /// Two sites reading the same input share a stage, so they can share one driver call.
    #[test]
    fn independent_sites_share_a_stage() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0
            Node::new(Op::Gadget(GadgetId::new(0)), vec![ValueId::new(0)]), // 1
            Node::new(Op::GadgetResult(0), vec![ValueId::new(1)]), // 2
            Node::new(Op::Gadget(GadgetId::new(1)), vec![ValueId::new(0)]), // 3
            Node::new(Op::GadgetResult(0), vec![ValueId::new(3)]), // 4
            Node::new(Op::Add, vec![ValueId::new(2), ValueId::new(4)]), // 5
        ];
        let graph = graph_of(
            nodes,
            ValueId::new(5),
            vec![site(GadgetKind::IsZero), site(GadgetKind::IsZero)],
        );
        assert_eq!(site_stages(&graph, &compute_domains(&graph)), vec![0, 0]);
    }

    #[test]
    fn public_gadget_does_not_split_shared_batches() {
        let nodes = vec![
            Node::new(Op::Constant(Fr::from(0u64)), vec![]), // 0
            Node::new(Op::Gadget(GadgetId::new(0)), vec![ValueId::new(0)]), // 1: public
            Node::new(Op::GadgetResult(0), vec![ValueId::new(1)]), // 2
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 3: shared
            Node::new(Op::Gadget(GadgetId::new(1)), vec![ValueId::new(3)]), // 4: shared A
            Node::new(Op::GadgetResult(0), vec![ValueId::new(4)]), // 5
            Node::new(Op::Add, vec![ValueId::new(3), ValueId::new(2)]), // 6
            Node::new(Op::Gadget(GadgetId::new(2)), vec![ValueId::new(6)]), // 7: shared B
            Node::new(Op::GadgetResult(0), vec![ValueId::new(7)]), // 8
            Node::new(Op::Add, vec![ValueId::new(5), ValueId::new(8)]), // 9
        ];
        let graph = graph_of(
            nodes,
            ValueId::new(9),
            vec![
                site(GadgetKind::IsZero),
                site(GadgetKind::IsZero),
                site(GadgetKind::IsZero),
            ],
        );

        assert_eq!(
            network_levels(&graph, &compute_domains(&graph)),
            vec![0, 0, 0, 0, 0, 1, 0, 0, 1, 1]
        );
        assert_eq!(site_stages(&graph, &compute_domains(&graph)), vec![0, 0, 0]);

        let domains = super::super::domain::compute_domains(&graph);
        let plans = super::super::gadget_schedule::plan_gadget_batches(&graph, &domains);
        assert_eq!(plans.len(), 2, "one public service and one shared service");
        assert!(plans.iter().any(|plan| matches!(
            plan,
            super::super::gadget_schedule::ScheduledBatch::Gadget(plan)
                if plan.domain == Domain::Shared && plan.sites.len() == 2
        )));
    }

    /// `full_levels` climbs one per `GadgetResult` even when every site along the chain is
    /// public - the exact case `network_levels` collapses to all-zero (see
    /// `chained_sites_with_no_multiplication_get_distinct_stages`, which uses this same shape).
    #[test]
    fn full_levels_climbs_through_an_all_public_chain() {
        let nodes = vec![
            Node::new(Op::Constant(Fr::from(0u64)), vec![]), // 0: public
            Node::new(Op::Gadget(GadgetId::new(0)), vec![ValueId::new(0)]), // 1
            Node::new(Op::GadgetResult(0), vec![ValueId::new(1)]), // 2
            Node::new(Op::Gadget(GadgetId::new(1)), vec![ValueId::new(2)]), // 3
            Node::new(Op::GadgetResult(0), vec![ValueId::new(3)]), // 4
        ];
        let graph = graph_of(
            nodes,
            ValueId::new(4),
            vec![site(GadgetKind::IsZero), site(GadgetKind::IsZero)],
        );
        // Every site here is public (no `Shared` input anywhere), so `network_levels` puts
        // everything at 0 - the point of this test is that `full_levels` does not.
        assert_eq!(
            network_levels(&graph, &compute_domains(&graph)),
            vec![0, 0, 0, 0, 0]
        );
        assert_eq!(full_levels(&graph), vec![0, 0, 1, 1, 2]);
    }

    /// Two independent public chains of the same length reach the same `full_levels` depth at
    /// their corresponding step, mirroring `independent_products_at_same_depth_merge`
    /// (`round_schedule.rs`) for the public case: that is exactly the signal `wide_schedule` needs
    /// to recognize them as batchable together.
    #[test]
    fn full_levels_agree_across_independent_public_chains_of_equal_length() {
        let nodes = vec![
            Node::new(Op::Constant(Fr::from(0u64)), vec![]), // 0: chain A's leaf, public
            Node::new(Op::Constant(Fr::from(1u64)), vec![]), // 1: chain B's leaf, public
            Node::new(Op::Gadget(GadgetId::new(0)), vec![ValueId::new(0)]), // 2: A level 1
            Node::new(Op::GadgetResult(0), vec![ValueId::new(2)]), // 3
            Node::new(Op::Gadget(GadgetId::new(1)), vec![ValueId::new(1)]), // 4: B level 1
            Node::new(Op::GadgetResult(0), vec![ValueId::new(4)]), // 5
            Node::new(Op::Gadget(GadgetId::new(2)), vec![ValueId::new(3)]), // 6: A level 2
            Node::new(Op::GadgetResult(0), vec![ValueId::new(6)]), // 7
            Node::new(Op::Gadget(GadgetId::new(3)), vec![ValueId::new(5)]), // 8: B level 2
            Node::new(Op::GadgetResult(0), vec![ValueId::new(8)]), // 9
        ];
        let graph = graph_of(
            nodes,
            ValueId::new(9),
            vec![
                site(GadgetKind::IsZero),
                site(GadgetKind::IsZero),
                site(GadgetKind::IsZero),
                site(GadgetKind::IsZero),
            ],
        );
        let full = full_levels(&graph);
        // A's level-1 result (node 3) and B's level-1 result (node 5) agree; so do A's level-2
        // (node 7) and B's level-2 (node 9) - despite chain A and chain B being interleaved
        // one-node-apart in source order, not adjacent.
        assert_eq!(full[3], full[5]);
        assert_eq!(full[7], full[9]);
        assert!(full[3] < full[7]);
    }

    /// A round costs a level exactly as a batch service does, and linear ops cost nothing.
    #[test]
    fn rounds_and_linear_ops_charge_as_expected() {
        use crate::ir::RoundId;

        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0
            Node::new(Op::Input(SignalIdx::new(2)), vec![]), // 1
            Node::new(Op::MulLocal, vec![ValueId::new(0), ValueId::new(1)]), // 2
            Node::new(Op::Round(RoundId::new(0)), vec![ValueId::new(2)]), // 3
            Node::new(Op::RoundResult(0), vec![ValueId::new(3)]), // 4
            Node::new(Op::Add, vec![ValueId::new(4), ValueId::new(0)]), // 5
        ];
        let mut graph = graph_of(nodes, ValueId::new(5), vec![]);
        graph.set_num_rounds(1);
        // MulLocal is free; crossing the round costs one; the trailing Add is free.
        assert_eq!(
            network_levels(&graph, &compute_domains(&graph)),
            vec![0, 0, 0, 0, 1, 1]
        );
    }
}
