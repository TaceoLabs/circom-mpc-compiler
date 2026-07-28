//! Canonical operand order for commutative ops (`Add`, `Mul`): a constant operand moves to the
//! right, otherwise operands are ordered by `ValueId`. This doesn't fold anything by itself - it
//! exists so `cse` (and `passes/normalize.rs`, which treats a `Mul` of two non-constant atoms as an
//! opaque leaf) see `a+b` and `b+a` as the same expression regardless of which order circom's
//! inliner happened to emit them in.

use ark_ff::PrimeField;

use crate::ir::{Graph, Node, Op, RewriteAction, ValueId};

use super::{Changed, Pass, PassContext};

pub(super) struct Algebraic;

impl<F: PrimeField> Pass<F> for Algebraic {
    fn name(&self) -> &'static str {
        "algebraic"
    }

    fn run(&mut self, graph: &mut Graph<F>, _ctx: &mut PassContext) -> eyre::Result<Changed> {
        Ok(graph.rewrite(|_id, node, emitted| {
            if !matches!(node.op, Op::Add | Op::Mul) {
                return RewriteAction::Keep;
            }
            let (a, b) = (node.inputs[0], node.inputs[1]);
            let canonical = canonical_order(emitted, a, b);
            if canonical == (a, b) {
                RewriteAction::Keep
            } else {
                RewriteAction::Emit(Node::new(node.op.clone(), vec![canonical.0, canonical.1]))
            }
        }))
    }
}

/// Constant operand goes right; otherwise order by `ValueId` ascending.
fn canonical_order<F: PrimeField>(
    emitted: &[Node<F>],
    a: ValueId,
    b: ValueId,
) -> (ValueId, ValueId) {
    let a_const = matches!(emitted[a.index()].op, Op::Constant(_));
    let b_const = matches!(emitted[b.index()].op, Op::Constant(_));
    match (a_const, b_const) {
        (true, false) => (b, a),
        (false, true) | (true, true) => (a, b),
        (false, false) => {
            if a <= b {
                (a, b)
            } else {
                (b, a)
            }
        }
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
            1,
            1,
            2,
        )
    }

    #[test]
    fn moves_constant_operand_right() {
        // x2 = Add(Constant(5), x0) -- constant is on the left, should swap
        let nodes = vec![
            Node::new(Op::Constant(Fr::from(5u64)), vec![]),
            Node::new(Op::Input(SignalIdx::new(0)), vec![]),
            Node::new(Op::Add, vec![ValueId::new(0), ValueId::new(1)]),
        ];
        let mut graph = graph_of(nodes, ValueId::new(2));
        let changed = Pass::run(&mut Algebraic, &mut graph, &mut PassContext::default()).unwrap();
        assert!(changed);
        assert_eq!(graph.len(), 3); // Emit replaces the node in place, no extra node added
        let node = graph.node(ValueId::new(2));
        assert_eq!(node.inputs, vec![ValueId::new(1), ValueId::new(0)]);
    }

    #[test]
    fn leaves_already_canonical_order_unchanged() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(0)), vec![]),
            Node::new(Op::Input(SignalIdx::new(1)), vec![]),
            Node::new(Op::Add, vec![ValueId::new(0), ValueId::new(1)]),
        ];
        let mut graph = graph_of(nodes, ValueId::new(2));
        let changed = Pass::run(&mut Algebraic, &mut graph, &mut PassContext::default()).unwrap();
        assert!(!changed);
        assert_eq!(graph.len(), 3);
    }
}
