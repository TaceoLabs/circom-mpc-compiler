//! Per-value **network level**: how many network events must complete before a value exists, where
//! an event is either a reshare round ([`Op::Round`]) or one precomputation batch service
//! ([`Op::Precompute`]). See `docs/ARCHITECTURE.md`, "MPC lowering" and "Precomputation".
//!
//! This replaces what used to be an inline "multiplicative depth" formula in [`super::
//! round_schedule`]. The rename is not cosmetic: the old formula pinned [`Op::Precompute`] and
//! [`Op::PrecomputeResult`] to depth 0, which asserted that a site's *results* are available at the
//! same instant as its *inputs*. That is false for every rep3 gadget (all four `VmDriver::*_traces`
//! methods take a `&Network` and genuinely communicate), and it made `round_schedule`'s
//! depth-bucketed reconstruction produce a forward reference - a real panic on any circuit whose
//! site inputs are computed rather than bare `Op::Input`s, which is exactly what the vendored merces
//! circuits do (`circuits/merces/merces/dependencies/merkle_root_4.circom` chains `MAX_DEPTH`
//! Poseidon2 sites through secret multiplications).
//!
//! **One axis, not two.** Rounds and batch services share a single counter rather than getting a
//! `(depth, stage)` pair. Two consequences make this the right trade:
//!
//! - Two sites at the same level are *provably* mutually independent, because any dependency between
//!   them forces `+1`. That is precisely the property needed to fold N sites into one driver call,
//!   and it cannot be recovered from multiplicative depth alone: `circuits/merces/merces/
//!   server.circom` chains `Num2Bits(254)` -> `AliasCheck` -> `IsZero` with **zero multiplications
//!   between them**, so all three sit at identical multiplicative depth despite being sequentially
//!   dependent.
//! - With `PrecomputeResult` at `+1`, no node at level `d` can read a level-`d` site's result, so
//!   each level is schedulable as `[ordinary nodes] [this level's batches] [this level's round]` -
//!   `round_schedule`'s existing two-phase shape plus one event slot, with no intra-level sub-order.
//!
//! The cost, accepted deliberately: for "site `S`, an unrelated product `A` at `S`'s input level, and
//! a product `B` reading `S`'s result", this emits round `{A}`, batch, round `{B}` where a 2D scheme
//! could emit batch, round `{A,B}` - one extra reshare message. A 2D scheme loses more by splitting
//! batches harder (its key would be `(kind, depth, stage)`, so two independent same-kind sites
//! reached via different mixes of rounds and batches land in *different* batches), and a batch
//! service costs strictly more than one reshare.
//!
//! Not a registered [`Pass`](super::super::Pass): it mutates nothing, and has three consumers
//! ([`super::round_schedule`] for bucketing, `vm::codegen` for batch grouping, and
//! `ir::Graph::mpc_summary` for diagnostics). It follows [`super::domain`]'s precedent - a small
//! library of pure functions, not cached in `PassContext`, because an old-space array is invalidated
//! by the very rewrite that consumes it.

use ark_ff::PrimeField;

use crate::ir::{Graph, Op};

/// The network level of every value in `graph`, indexed by [`crate::ir::ValueId`].
///
/// Relies only on the topological-order invariant ([`Graph::verify`]): every node's inputs have
/// smaller indices, so one forward pass suffices. Every rule is `max(inputs)` or `max(inputs) + 1`,
/// so the result is non-decreasing along every edge - the sole property `round_schedule`'s rebuild
/// needs to stay topological.
pub(crate) fn network_levels<F: PrimeField>(graph: &Graph<F>) -> Vec<usize> {
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
            // Free local work in every domain - no event of its own.
            Op::Add | Op::Sub | Op::Mul | Op::MulLocal => max_input(),
            // The event itself sits at the level of the values it consumes; crossing it is what
            // costs a level, which is what the two `*Result` arms below charge for.
            Op::Round(_) | Op::Precompute(_) => max_input(),
            Op::RoundResult(_) | Op::PrecomputeResult(_) => level[node.inputs[0].index()] + 1,
        };
    }
    level
}

/// The **stage** of every precomputation site, indexed by [`crate::ir::PrecomputeId`] - the level of
/// its [`Op::Precompute`] node, i.e. how many network events must complete before the site can be
/// serviced.
///
/// Sites sharing a stage are mutually independent (see the module doc), so `(kind, stage)` is a
/// sound batch key: everything in one batch can be serviced by a single driver call.
///
/// Panics if a site has no `Op::Precompute` node, which [`Graph::verify`] rules out.
pub(crate) fn site_stages<F: PrimeField>(graph: &Graph<F>) -> Vec<usize> {
    let level = network_levels(graph);
    let mut stages = vec![None; graph.precompute_sites().len()];
    for (i, node) in graph.nodes().iter().enumerate() {
        if let Op::Precompute(site) = &node.op {
            stages[site.index()] = Some(level[i]);
        }
    }
    stages
        .into_iter()
        .enumerate()
        .map(|(site, stage)| {
            stage.unwrap_or_else(|| {
                panic!("precompute site {site} has no Op::Precompute node - Graph::verify should have rejected this")
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;

    use super::*;
    use crate::ir::{Node, PrecomputeId, PrecomputeKind, PrecomputeSite, SignalIdx, ValueId};

    fn site(kind: PrecomputeKind, num_inputs: usize, num_outputs: usize) -> PrecomputeSite {
        PrecomputeSite {
            kind,
            name: "Gadget".to_owned(),
            header: "Gadget_0".to_owned(),
            num_inputs,
            num_outputs,
            num_intermediates: 0,
        }
    }

    fn graph_of(nodes: Vec<Node<Fr>>, output: ValueId, sites: Vec<PrecomputeSite>) -> Graph<Fr> {
        let mut graph = Graph::from_parts(
            nodes,
            vec![(SignalIdx::new(0), output)],
            sites,
            vec![],
            vec![],
            vec![],
            3,
            1,
            4,
        );
        graph.mark_lowered();
        graph
    }

    /// A site's results are one level above its inputs - the whole point of the change. Under the
    /// old formula both were 0, which is what let `round_schedule` build a forward reference.
    #[test]
    fn site_results_are_one_level_above_their_inputs() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0
            Node::new(Op::Precompute(PrecomputeId::new(0)), vec![ValueId::new(0)]), // 1
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(1)]), // 2
        ];
        let graph = graph_of(nodes, ValueId::new(2), vec![site(PrecomputeKind::IsZero, 1, 1)]);
        assert_eq!(network_levels(&graph), vec![0, 0, 1]);
        assert_eq!(site_stages(&graph), vec![0]);
    }

    /// The `server.circom` shape: `Num2Bits` -> `AliasCheck` -> `IsZero`, chained with **no
    /// multiplication between them**. Any scheme keyed on multiplicative depth would put all three
    /// at depth 0 and batch dependent sites together; levels must separate them.
    #[test]
    fn chained_sites_with_no_multiplication_get_distinct_stages() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0
            Node::new(Op::Precompute(PrecomputeId::new(0)), vec![ValueId::new(0)]), // 1
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(1)]), // 2
            Node::new(Op::Precompute(PrecomputeId::new(1)), vec![ValueId::new(2)]), // 3
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(3)]), // 4
            Node::new(Op::Precompute(PrecomputeId::new(2)), vec![ValueId::new(4)]), // 5
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(5)]), // 6
        ];
        let graph = graph_of(
            nodes,
            ValueId::new(6),
            vec![
                site(PrecomputeKind::Num2Bits { n: 1 }, 1, 1),
                site(PrecomputeKind::AliasCheck, 1, 1),
                site(PrecomputeKind::IsZero, 1, 1),
            ],
        );
        assert_eq!(network_levels(&graph), vec![0, 0, 1, 1, 2, 2, 3]);
        assert_eq!(site_stages(&graph), vec![0, 1, 2]);
    }

    /// Two sites reading the same input share a stage, so they can share one driver call.
    #[test]
    fn independent_sites_share_a_stage() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0
            Node::new(Op::Precompute(PrecomputeId::new(0)), vec![ValueId::new(0)]), // 1
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(1)]), // 2
            Node::new(Op::Precompute(PrecomputeId::new(1)), vec![ValueId::new(0)]), // 3
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(3)]), // 4
            Node::new(Op::Add, vec![ValueId::new(2), ValueId::new(4)]), // 5
        ];
        let graph = graph_of(
            nodes,
            ValueId::new(5),
            vec![
                site(PrecomputeKind::IsZero, 1, 1),
                site(PrecomputeKind::IsZero, 1, 1),
            ],
        );
        assert_eq!(site_stages(&graph), vec![0, 0]);
    }

    /// A round costs a level exactly as a batch service does, and linear ops cost nothing.
    #[test]
    fn rounds_and_linear_ops_charge_as_expected() {
        use crate::ir::{RoundDesc, RoundId, RoundKind};

        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0
            Node::new(Op::Input(SignalIdx::new(2)), vec![]), // 1
            Node::new(Op::MulLocal, vec![ValueId::new(0), ValueId::new(1)]), // 2
            Node::new(Op::Round(RoundId::new(0)), vec![ValueId::new(2)]), // 3
            Node::new(Op::RoundResult(0), vec![ValueId::new(3)]), // 4
            Node::new(Op::Add, vec![ValueId::new(4), ValueId::new(0)]), // 5
        ];
        let mut graph = graph_of(nodes, ValueId::new(5), vec![]);
        graph.set_rounds(vec![RoundDesc {
            kind: RoundKind::Reshare,
            len: 1,
            level: 0,
        }]);
        // MulLocal is free; crossing the round costs one; the trailing Add is free.
        assert_eq!(network_levels(&graph), vec![0, 0, 0, 0, 1, 1]);
    }
}
