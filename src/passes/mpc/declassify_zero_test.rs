//! Rewrites an `IsZero`/`IsEqual` precomputation site's kind to a cheaper, 1-round variant when the
//! circuit itself reveals the site's `out` result right after computing it - `IsZeroRevealed`/
//! `IsEqualRevealed`'s protocol (`vm::gadgets::iszero::rep3_trace_revealed`) leaks exactly the bit
//! `TACEO_REVEAL` already publishes to every party, so paying the full secret-comparison protocol
//! for it (`eq_public_many` + `inv_vec`, ~29 rounds) buys nothing this compiler's own cost model
//! (`docs/ARCHITECTURE.md`, "The cost model") doesn't already have for free. See
//! `docs/ARCHITECTURE.md`, "Precomputation", for the full leak argument.
//!
//! This is not inferring a declassification - `ir::PrecomputeKind::Reveal` is only ever produced
//! from a literal `TACEO_REVEAL` call in the source (`frontend/build.rs`), and this pass only reads
//! that existing decision, one hop away: it matches a site's `out` (`Op::PrecomputeResult(0)`) being
//! read directly by a `Reveal` site's inputs, exactly the shape `server.circom`'s
//! `RangeCheckWithOutputFlag` already writes (`TACEO_PRECOMPUTATION_IsZero()(sum)` immediately
//! followed by `TACEO_REVEAL(1)([isZeroOut])`). No transitive reasoning through an intervening
//! linear op - if a real circuit needs that, extend the match rather than approximate it.
//!
//! Not a `Graph::rewrite` consumer: it never adds, removes, or reorders a node, only relabels an
//! entry in `Graph::precompute_sites` via `Graph::precompute_sites_mut` - `Graph::rewrite`'s
//! new-space bookkeeping isn't needed for a change that doesn't touch node shape or count.
//!
//! Placed first in `pipeline()` (`super::pipeline`): `kind` only feeds the batch key
//! (`precompute_schedule`) and the runtime dispatch (`vm::machine`), both downstream of every
//! lowering pass here, so placement isn't load-bearing - first is simply the natural place to read
//! an unlowered graph's own gadget-call shape.

use ark_ff::PrimeField;
use rustc_hash::FxHashMap;

use crate::ir::{Graph, Op, PrecomputeKind};
use crate::passes::{Changed, Pass, PassContext};

pub(crate) struct DeclassifyZeroTest;

impl<F: PrimeField> Pass<F> for DeclassifyZeroTest {
    fn name(&self) -> &'static str {
        "mpc::declassify_zero_test"
    }

    fn run(&mut self, graph: &mut Graph<F>, _ctx: &mut PassContext) -> eyre::Result<Changed> {
        let nodes = graph.nodes();
        let sites = graph.precompute_sites();

        // Node index of each `IsZero`/`IsEqual` site's own slot-0 (`out`) result, keyed by the
        // result node's index - `None` for a site whose `out` is witness-dead (already pruned by
        // `dead_signals`/`gc`), which can never be what a live `Reveal` site reads anyway.
        let mut result_owner: FxHashMap<usize, usize> = FxHashMap::default();
        for (i, node) in nodes.iter().enumerate() {
            let Op::PrecomputeResult(0) = node.op else { continue };
            let Op::Precompute(site_id) = &nodes[node.inputs[0].index()].op else {
                continue;
            };
            if matches!(
                sites[site_id.index()].kind,
                PrecomputeKind::IsZero | PrecomputeKind::IsEqual
            ) {
                result_owner.insert(i, site_id.index());
            }
        }

        // A site is declassified iff some `Reveal` site's own inputs read its `out` result
        // directly.
        let mut declassified = vec![false; sites.len()];
        for node in nodes {
            let Op::Precompute(reveal_site_id) = &node.op else { continue };
            if !matches!(sites[reveal_site_id.index()].kind, PrecomputeKind::Reveal { .. }) {
                continue;
            }
            for input in &node.inputs {
                if let Some(&site_id) = result_owner.get(&input.index()) {
                    declassified[site_id] = true;
                }
            }
        }

        let mut changed = false;
        for (site_id, site) in graph.precompute_sites_mut().iter_mut().enumerate() {
            if !declassified[site_id] {
                continue;
            }
            site.kind = match site.kind {
                PrecomputeKind::IsZero => PrecomputeKind::IsZeroRevealed,
                PrecomputeKind::IsEqual => PrecomputeKind::IsEqualRevealed,
                _ => unreachable!("declassified is only ever set for IsZero/IsEqual sites"),
            };
            changed = true;
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;

    use crate::ir::{Node, PrecomputeId, PrecomputeSite, SignalIdx, ValueId};

    use super::*;

    /// `IsZero(x)` whose `out` (slot 0) feeds a `Reveal(1)` site directly - the `server.circom`
    /// `RangeCheckWithOutputFlag` shape.
    fn graph_with_revealed_iszero() -> Graph<Fr> {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0: x
            Node::new(Op::Precompute(PrecomputeId::new(0)), vec![ValueId::new(0)]), // 1: IsZero site
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(1)]), // 2: out
            Node::new(Op::PrecomputeResult(1), vec![ValueId::new(1)]), // 3: inv
            Node::new(Op::Precompute(PrecomputeId::new(1)), vec![ValueId::new(2)]), // 4: Reveal(1) site
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(4)]), // 5: revealed[0]
        ];
        let sites = vec![
            PrecomputeSite {
                kind: PrecomputeKind::IsZero,
                header: "IsZero".into(),
                num_inputs: 1,
                num_outputs: 1,
                num_intermediates: 1,
            },
            PrecomputeSite {
                kind: PrecomputeKind::Reveal { n: 1 },
                header: "TACEO_REVEAL_1".into(),
                num_inputs: 1,
                num_outputs: 1,
                num_intermediates: 0,
            },
        ];
        Graph::from_parts(
            nodes,
            vec![(SignalIdx::new(0), ValueId::new(5))],
            sites,
            vec![],
            vec![],
            vec![],
            1,
            0,
            2,
        )
    }

    #[test]
    fn rewrites_an_iszero_site_revealed_immediately_after() {
        let mut graph = graph_with_revealed_iszero();
        let mut pass = DeclassifyZeroTest;
        let changed = Pass::run(&mut pass, &mut graph, &mut PassContext::default()).unwrap();
        assert!(changed);
        assert!(matches!(
            graph.precompute_sites()[0].kind,
            PrecomputeKind::IsZeroRevealed
        ));
        // The Reveal site itself is untouched.
        assert!(matches!(
            graph.precompute_sites()[1].kind,
            PrecomputeKind::Reveal { n: 1 }
        ));
    }

    #[test]
    fn leaves_an_unrevealed_iszero_site_alone() {
        // Same shape, but the Reveal site's input is `inv` (value 3), not `out` (value 2) - not the
        // pattern this pass matches.
        let nodes: Vec<Node<Fr>> = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0: x
            Node::new(Op::Precompute(PrecomputeId::new(0)), vec![ValueId::new(0)]), // 1: IsZero site
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(1)]), // 2: out
            Node::new(Op::PrecomputeResult(1), vec![ValueId::new(1)]), // 3: inv
            Node::new(Op::Precompute(PrecomputeId::new(1)), vec![ValueId::new(3)]), // 4: Reveal(1) site over inv
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(4)]), // 5: revealed[0]
        ];
        let sites = vec![
            PrecomputeSite {
                kind: PrecomputeKind::IsZero,
                header: "IsZero".into(),
                num_inputs: 1,
                num_outputs: 1,
                num_intermediates: 1,
            },
            PrecomputeSite {
                kind: PrecomputeKind::Reveal { n: 1 },
                header: "TACEO_REVEAL_1".into(),
                num_inputs: 1,
                num_outputs: 1,
                num_intermediates: 0,
            },
        ];
        let mut graph = Graph::from_parts(
            nodes,
            vec![(SignalIdx::new(0), ValueId::new(5))],
            sites,
            vec![],
            vec![],
            vec![],
            1,
            0,
            2,
        );
        let mut pass = DeclassifyZeroTest;
        let changed = Pass::run(&mut pass, &mut graph, &mut PassContext::default()).unwrap();
        assert!(!changed);
        assert!(matches!(graph.precompute_sites()[0].kind, PrecomputeKind::IsZero));
    }

    #[test]
    fn leaves_a_never_revealed_iszero_site_alone() {
        // A bare IsZero with no Reveal site at all in the graph.
        let nodes: Vec<Node<Fr>> = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]),
            Node::new(Op::Precompute(PrecomputeId::new(0)), vec![ValueId::new(0)]),
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(1)]),
        ];
        let sites = vec![PrecomputeSite {
            kind: PrecomputeKind::IsZero,
            header: "IsZero".into(),
            num_inputs: 1,
            num_outputs: 1,
            num_intermediates: 1,
        }];
        let mut graph = Graph::from_parts(
            nodes,
            vec![(SignalIdx::new(0), ValueId::new(2))],
            sites,
            vec![],
            vec![],
            vec![],
            1,
            0,
            1,
        );
        let mut pass = DeclassifyZeroTest;
        let changed = Pass::run(&mut pass, &mut graph, &mut PassContext::default()).unwrap();
        assert!(!changed);
        assert!(matches!(graph.precompute_sites()[0].kind, PrecomputeKind::IsZero));
    }
}
