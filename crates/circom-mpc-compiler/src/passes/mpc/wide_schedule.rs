//! Widens independent same-depth **public** gadget batches that `gadget_schedule.rs` would
//! otherwise see one at a time.
//!
//! `round_schedule.rs` already merges independent *shared* computations at the same
//! `network_levels` depth into one round (see its `independent_products_at_same_depth_merge`
//! test) - two unrelated secret Merkle-path hashes at the same tree level already end up
//! batched together today. Public chains get no such treatment: `network_levels` deliberately
//! keeps every public `GadgetResult` at its producer's level (see `level.rs`'s module doc), so an
//! entire public chain - e.g. a 13-level Merkle hash whose leaf has already been revealed - sits
//! at level 0 from top to bottom. Two independent public chains are therefore indistinguishable,
//! by that metric, from ten levels of one single chain, and `gadget_schedule.rs`'s
//! `append_to`/deadline window (correctly) refuses to merge a site with the very next site in
//! *source* order once that next site turns out to be the chain's own next level - so every site
//! ends up in its own singleton batch instead of joining its counterparts in every *other*
//! independent chain at the same depth.
//!
//! This pass reorders the graph by [`level::full_levels`] - the same shape of metric as
//! `network_levels`, but one that does climb through public `GadgetResult`s - so that independent
//! same-depth public sites (and everything else at that depth) become adjacent in node order,
//! exactly the arrangement `gadget_schedule.rs` already needs to merge them. It changes no
//! scheduling logic there or in codegen: once nodes are in the right order, the existing
//! `(kind, stage, domain, precomputed)` batch key and admission window do the rest, the same way
//! they already do for the shared case.
//!
//! Run after `round_schedule`, not before: `round_schedule` is the pass that establishes the
//! final invariant codegen's `emit_round` relies on (a `Round` node immediately followed by
//! exactly its own `RoundResult(0..len)` block) - reordering by a *different* depth metric would
//! break that adjacency unless every such block is moved as one atomic unit, which is exactly what
//! this pass does, but only because it can rely on that invariant already holding when it starts.
//! (`Op::Gadget`/`Op::GadgetResult` carry no equivalent contiguity contract - `gadget_schedule.rs`
//! already tolerates them landing anywhere valid, which is what makes reordering them the point of
//! this pass instead of a hazard.)

use crate::ir::{Graph, Node, Op, ValueId};

use super::level::full_levels;

pub(crate) fn run(graph: &mut Graph) -> bool {
    let nodes = graph.nodes();
    if nodes.is_empty() {
        return false;
    }

    let depth = full_levels(graph);
    let max_depth = depth.iter().copied().max().unwrap_or(0);

    // One "unit" per (start, len): len 1 for an ordinary node, or `1 + slots` for a `Round` and
    // its immediately-following `RoundResult(0..slots)` block, moved together so codegen's
    // adjacency contract survives the reorder. Bucketed by the depth of the unit's first node
    // (for a `Round` group, the `Round` node's own depth - `RoundResult`s are never bucketed on
    // their own, so they cannot end up separated from it).
    let mut units_by_depth: Vec<Vec<(usize, usize)>> =
        (0..=max_depth).map(|_| Vec::new()).collect();
    let mut already_depth_sorted = true;
    let mut prev_depth = 0;
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
                    "wide_schedule: Round at {i} not immediately followed by its own \
                     RoundResult(0..{slots}) block - this pass must run after round_schedule"
                );
                1 + slots
            }
            Op::RoundResult(_) => {
                unreachable!("consumed as part of the RoundResult block its own Round starts")
            }
            _ => 1,
        };
        let unit_depth = depth[i];
        if unit_depth < prev_depth {
            already_depth_sorted = false;
        }
        prev_depth = unit_depth;
        units_by_depth[unit_depth].push((i, len));
        i += len;
    }

    if already_depth_sorted {
        return false;
    }

    let old_len = nodes.len();
    let mut remap: Vec<Option<ValueId>> = vec![None; old_len];
    let mut new_nodes: Vec<Node> = Vec::with_capacity(old_len);

    for bucket in &units_by_depth {
        for &(start, len) in bucket {
            for offset in 0..len {
                let idx = start + offset;
                let node = &nodes[idx];
                let remapped_inputs = node
                    .inputs
                    .iter()
                    .map(|v| remap[v.index()].expect("wide_schedule: input not yet placed"))
                    .collect();
                remap[idx] = Some(ValueId::new(new_nodes.len()));
                new_nodes.push(Node::new(node.op.clone(), remapped_inputs));
            }
        }
    }

    graph.rebuild_nodes(new_nodes, &remap);
    true
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;

    use super::*;
    use crate::ir::{GadgetId, GadgetKind, GadgetSite, GraphParts, RoundId, SignalIdx};
    use crate::passes::mpc::{domain::compute_domains, gadget_schedule, level, round_schedule};

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

    /// Two independent public chains (the shape a revealed-leaf Merkle hash has), each emitted
    /// *fully depth-first* before the next starts - exactly how circom emits N structurally
    /// identical component instances, and exactly the shape that defeats `gadget_schedule.rs`'s
    /// admission window today: chain A's own level-2 site (its result's only reader) appears
    /// immediately after A's level-1 site, in source order, long before chain B's level-1 site
    /// is even reached, so A's batch closes before it can ever meet B's.
    #[test]
    fn widens_independent_public_chains_that_gadget_schedule_could_not_merge_before() {
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
        let sites = vec![
            site(GadgetKind::IsZero),
            site(GadgetKind::IsZero),
            site(GadgetKind::IsZero),
            site(GadgetKind::IsZero),
        ];
        let mut graph = graph_of(nodes, ValueId::new(10), sites);

        // Before: `network_levels` (what `gadget_schedule.rs` actually keys on) puts this entire
        // all-public shape at stage 0, so gadget_schedule has no notion of "layer" here at all -
        // it merges whatever fits its anchor/deadline window regardless of which chain or level a
        // site belongs to. That happens to fold A's level-2 site together with B's level-1 site
        // (a valid merge - they truly are independent - but not an organized-by-layer one), for 3
        // batches rather than 4 clean singletons. The point of this pass is to replace that
        // incidental grouping with a deliberate one.
        let domains_before = compute_domains(&graph);
        let plans_before = gadget_schedule::plan_gadget_batches(&graph, &domains_before);
        assert_eq!(
            plans_before.len(),
            3,
            "gadget_schedule already merges by happenstance here"
        );

        let changed = run(&mut graph);
        assert!(changed);

        let domains_after = compute_domains(&graph);
        let plans_after = gadget_schedule::plan_gadget_batches(&graph, &domains_after);
        assert_eq!(
            plans_after.len(),
            2,
            "level 1 (A+B) and level 2 (A+B) should now each be one two-site batch, cleanly \
             separated by layer instead of merged by happenstance"
        );
        for plan in &plans_after {
            let gadget_schedule::ScheduledBatch::Gadget(plan) = plan else {
                panic!("expected an ordinary Gadget batch");
            };
            assert_eq!(
                plan.sites.len(),
                2,
                "each widened batch should hold both chains' sites"
            );
        }
    }

    /// A single public chain (no independent sibling) must stay exactly as sequential as it always
    /// was - `full_levels` strictly increases along it, so there is nothing to widen, and the pass
    /// should report no change.
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

    /// A `Round` (post `round_schedule`) must move as one atomic block with its `RoundResult`s -
    /// this is the hazard the module doc calls out. Shape: two secret products at depth 0 (merged
    /// into one round by `round_schedule`), each product's local part interleaved with an
    /// unrelated *public* chain long enough to force `full_levels` to place the round's own depth
    /// below some of the public chain's later levels, so this pass must actually move the round
    /// forward, not just leave it where `round_schedule` put it.
    #[test]
    fn moves_a_round_and_its_results_as_one_block() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0: secret a
            Node::new(Op::Input(SignalIdx::new(2)), vec![]), // 1: secret b
            Node::new(Op::MulLocal, vec![ValueId::new(0), ValueId::new(1)]), // 2: a*b local part
            Node::new(Op::Round(RoundId::new(0)), vec![ValueId::new(2)]), // 3
            Node::new(Op::RoundResult(0), vec![ValueId::new(3)]), // 4: a*b shared
            Node::new(Op::Constant(Fr::from(0u64)), vec![]), // 5: public chain leaf
            Node::new(Op::Gadget(GadgetId::new(0)), vec![ValueId::new(5)]), // 6
            Node::new(Op::GadgetResult(0), vec![ValueId::new(6)]), // 7
            Node::new(Op::Gadget(GadgetId::new(1)), vec![ValueId::new(7)]), // 8
            Node::new(Op::GadgetResult(0), vec![ValueId::new(8)]), // 9
            Node::new(Op::Add, vec![ValueId::new(4), ValueId::new(9)]), // 10
        ];
        let sites = vec![site(GadgetKind::IsZero), site(GadgetKind::IsZero)];
        let mut graph = graph_of(nodes, ValueId::new(10), sites);
        // Normalizes the graph into "post round_schedule" form (its own `Round`/`RoundResult`
        // adjacency contract) - this pass must run after it regardless of whether round_schedule
        // itself reports a change, which it always does whenever any round exists at all.
        round_schedule::run(&mut graph);

        // The round's own inputs are raw `Input` nodes (depth 0), well below the public chain's
        // second level - so this pass's bucketing genuinely moves the round relative to the
        // public chain's tail, not a no-op that happens to leave it in place.
        let round_before = graph
            .nodes()
            .iter()
            .position(|n| matches!(n.op, Op::Round(_)))
            .expect("a Round node must exist before reordering");
        let full = level::full_levels(&graph);
        let last_depth = *full.last().expect("graph has at least one node");
        assert!(full[round_before] < last_depth);

        run(&mut graph);

        let moved_round_idx = graph
            .nodes()
            .iter()
            .position(|n| matches!(n.op, Op::Round(_)))
            .expect("a Round node must still exist");
        assert!(
            matches!(graph.nodes()[moved_round_idx + 1].op, Op::RoundResult(0)),
            "Round must still be immediately followed by its RoundResult(0) after reordering"
        );
    }
}
