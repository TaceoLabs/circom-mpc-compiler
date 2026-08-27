//! Common subexpression elimination by hash-consing: every pure node (`Op::is_pure`) is deduped
//! against every other node with the same op and the same inputs, seen so far in this rewrite.
//! Commutative ops (`Add`, `Mul`) have their inputs sorted first, so `a+b` and `b+a` hash-cons to
//! the same entry.
//!
//! Skips every impure op (`Op::Gadget`/`Op::GadgetResult`/`Op::MulLocal`/`Op::Round`/
//! `Op::RoundResult`) - merging two of those would change how many traces/rounds the runtime must
//! supply, not just fold away redundant computation.

use rustc_hash::FxHashMap;

use crate::ir::{Graph, Op, RewriteAction, ValueId};

#[allow(
    clippy::unnecessary_wraps,
    reason = "must match the shared PassFn signature every pass in the pipeline implements, even though this pass never fails today"
)]
pub(super) fn run(graph: &mut Graph) -> eyre::Result<bool> {
    let mut seen: FxHashMap<(Op, Vec<ValueId>), ValueId> = FxHashMap::default();
    Ok(graph.rewrite(|_id, node, emitted| {
        if !node.op.is_pure() {
            return RewriteAction::Keep;
        }
        let key_inputs = canonical_inputs(&node.op, &node.inputs);
        let key = (node.op.clone(), key_inputs);
        if let Some(&existing) = seen.get(&key) {
            RewriteAction::ReplaceWith(existing)
        } else {
            // `emitted`'s length is exactly this node's prospective new-space id: `rewrite`
            // pushes a `Keep` node at position `emitted.len()`, before it calls us again.
            seen.insert(key, ValueId::new(emitted.len()));
            RewriteAction::Keep
        }
    }))
}

/// The key inputs used for hash-consing: sorted for commutative ops, so operand order doesn't
/// defeat deduplication.
fn canonical_inputs(op: &Op, inputs: &[ValueId]) -> Vec<ValueId> {
    match op {
        Op::Add | Op::Mul => {
            let mut v = inputs.to_vec();
            v.sort();
            v
        }
        _ => inputs.to_vec(),
    }
}

#[cfg(test)]
mod tests {
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
    fn dedupes_identical_additions() {
        // x0 = Input(0); x1 = Input(1); x2 = Add(x0,x1); x3 = Add(x0,x1) -- x3 is redundant
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(0)), vec![]),
            Node::new(Op::Input(SignalIdx::new(1)), vec![]),
            Node::new(Op::Add, vec![ValueId::new(0), ValueId::new(1)]),
            Node::new(Op::Add, vec![ValueId::new(0), ValueId::new(1)]),
        ];
        let mut graph = graph_of(nodes, ValueId::new(3));
        let changed = run(&mut graph).expect("run should not fail on this test graph");
        assert!(changed);
        graph.gc();
        assert_eq!(graph.len(), 3); // two inputs + one Add survive
    }

    #[test]
    fn dedupes_commutative_operand_order() {
        // x2 = Add(x0,x1); x3 = Add(x1,x0) -- same value, different operand order
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(0)), vec![]),
            Node::new(Op::Input(SignalIdx::new(1)), vec![]),
            Node::new(Op::Add, vec![ValueId::new(0), ValueId::new(1)]),
            Node::new(Op::Add, vec![ValueId::new(1), ValueId::new(0)]),
        ];
        let mut graph = graph_of(nodes, ValueId::new(3));
        let changed = run(&mut graph).expect("run should not fail on this test graph");
        assert!(changed);
        graph.gc();
        assert_eq!(graph.len(), 3);
    }
}
