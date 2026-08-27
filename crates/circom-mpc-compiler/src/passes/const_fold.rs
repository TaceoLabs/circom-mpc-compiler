//! General constant folding + algebraic identities over `Add`/`Sub`/`Mul`. Complements two
//! narrower, pre-existing folds that are deliberately *not* generalized into this pass:
//! `frontend/fold.rs::fold_binary` (folds the operators removed from the runtime IR, before a
//! node ever exists) and `GraphCompiler::eval_constant_node` (address-position-only, used for
//! array/signal/component addressing at lowering time). This is the first fold that runs as a
//! real pass over the graph itself.

use ark_bn254::Fr;
use ark_ff::{One, Zero};

use crate::ir::{Graph, Node, Op, RewriteAction, ValueId};

#[allow(
    clippy::unnecessary_wraps,
    reason = "must match the shared PassFn signature every pass in the pipeline implements, even though this pass never fails today"
)]
pub(super) fn run(graph: &mut Graph) -> eyre::Result<bool> {
    Ok(graph.rewrite(|_id, node, emitted| fold_node(node, emitted)))
}

/// Returns `Some(c)` iff `v`'s producer (already emitted, so present in `emitted`) is a resolved
/// constant.
fn constant_of(emitted: &[Node], v: ValueId) -> Option<Fr> {
    match &emitted[v.index()].op {
        Op::Constant(c) => Some(*c),
        _ => None,
    }
}

fn fold_node(node: &Node, emitted: &[Node]) -> RewriteAction {
    match &node.op {
        Op::Add => {
            let (a, b) = (node.inputs[0], node.inputs[1]);
            match (constant_of(emitted, a), constant_of(emitted, b)) {
                (Some(x), Some(y)) => RewriteAction::Emit(Node::new(Op::Constant(x + y), vec![])),
                (Some(x), None) if x == Fr::zero() => RewriteAction::ReplaceWith(b),
                (None, Some(y)) if y == Fr::zero() => RewriteAction::ReplaceWith(a),
                _ => RewriteAction::Keep,
            }
        }
        Op::Sub => {
            let (a, b) = (node.inputs[0], node.inputs[1]);
            match (constant_of(emitted, a), constant_of(emitted, b)) {
                (Some(x), Some(y)) => RewriteAction::Emit(Node::new(Op::Constant(x - y), vec![])),
                (None, Some(y)) if y == Fr::zero() => RewriteAction::ReplaceWith(a),
                _ => RewriteAction::Keep,
            }
        }
        Op::Mul => {
            let (a, b) = (node.inputs[0], node.inputs[1]);
            match (constant_of(emitted, a), constant_of(emitted, b)) {
                (Some(x), Some(y)) => RewriteAction::Emit(Node::new(Op::Constant(x * y), vec![])),
                (Some(x), _) | (_, Some(x)) if x == Fr::zero() => {
                    RewriteAction::Emit(Node::new(Op::Constant(Fr::zero()), vec![]))
                }
                (Some(x), None) if x == Fr::one() => RewriteAction::ReplaceWith(b),
                (None, Some(y)) if y == Fr::one() => RewriteAction::ReplaceWith(a),
                _ => RewriteAction::Keep,
            }
        }
        _ => RewriteAction::Keep,
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;

    use crate::ir::{Node, Op, SignalIdx, ValueId};

    use super::*;

    fn graph_of(nodes: Vec<Node>, output: ValueId) -> Graph {
        Graph::from_parts(
            nodes,
            vec![(SignalIdx::new(0), output)],
            vec![],
            vec![],
            vec![],
            vec![],
            1,
            1,
            2,
        )
    }

    #[test]
    fn folds_constant_arithmetic() {
        // x0 = Constant(2); x1 = Constant(3); x2 = Add(x0, x1)
        let nodes = vec![
            Node::new(Op::Constant(Fr::from(2u64)), vec![]),
            Node::new(Op::Constant(Fr::from(3u64)), vec![]),
            Node::new(Op::Add, vec![ValueId::new(0), ValueId::new(1)]),
        ];
        let mut graph = graph_of(nodes, ValueId::new(2));
        let changed = run(&mut graph).expect("run should not fail on this test graph");
        assert!(changed);
        graph.gc();
        assert_eq!(graph.len(), 1);
        assert!(matches!(graph.nodes()[ValueId::new(0).index()].op, Op::Constant(c) if c == Fr::from(5u64)));
    }

    #[test]
    fn aliases_additive_identity() {
        // x0 = Input(0); x1 = Constant(0); x2 = Add(x0, x1) -- should become an alias for x0
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(0)), vec![]),
            Node::new(Op::Constant(Fr::from(0u64)), vec![]),
            Node::new(Op::Add, vec![ValueId::new(0), ValueId::new(1)]),
        ];
        let mut graph = graph_of(nodes, ValueId::new(2));
        let changed = run(&mut graph).expect("run should not fail on this test graph");
        assert!(changed);
        graph.gc();
        // only the Input node should survive - the Add collapsed into an alias for it
        assert_eq!(graph.len(), 1);
        assert!(matches!(graph.nodes()[ValueId::new(0).index()].op, Op::Input(_)));
    }

    #[test]
    fn leaves_non_foldable_arithmetic_unchanged() {
        // x0 = Input(0); x1 = Input(1); x2 = Mul(x0, x1) -- neither operand is constant
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(0)), vec![]),
            Node::new(Op::Input(SignalIdx::new(1)), vec![]),
            Node::new(Op::Mul, vec![ValueId::new(0), ValueId::new(1)]),
        ];
        let mut graph = graph_of(nodes, ValueId::new(2));
        let changed = run(&mut graph).expect("run should not fail on this test graph");
        assert!(!changed);
        assert_eq!(graph.len(), 3);
    }
}
