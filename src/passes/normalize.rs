//! Affine normalization: collapses each maximal `Add`/`Sub`/mul-by-constant tree into one
//! `passes::poly::Affine` and rebuilds a canonical spine, materializing only what's actually
//! needed. Subsumes cross-chain constant folding, cancellation (`(a+b)-a -> b`, which circom's own
//! simplifier leaves behind), and reassociation of arbitrarily-nested chains - all in one pass,
//! since they're the same operation (combine into one `Affine`) applied transitively.
//!
//! Not a [`crate::ir::Graph::rewrite`] consumer: eliding a node that turned out not to be needed
//! (see below) means a *later* original node may need a materialized id for something that was
//! never given one at its own turn - `rewrite`'s automatic per-node input remapping requires every
//! visited index to resolve to something immediately, which is incompatible with "maybe emit
//! nothing, decide via anyone else's need". So this is a direct two-phase reconstruction, in the
//! same family as `passes::mpc::round_schedule` and `Graph::gc`.
//!
//! # Which nodes get elided
//!
//! A node is a **self-atom** if its own `Affine` form is exactly itself (`atom(i)`) - this is true
//! exactly for `Input`, `PrecomputeResult`, and a genuine secret*secret `Mul` (i.e. everything that
//! isn't `Add`/`Sub`/`Constant`/a mul-by-constant). Self-atoms are always materialized verbatim,
//! since they're the leaves the algebra bottoms out at. Everything else (`Add`, `Sub`, `Constant`,
//! mul-by-constant) is **foldable**: materialized only if `force[i]` is set, i.e. it's bound to a
//! circuit output, or it feeds a self-atom node directly (an operand of a genuine `Mul`, or an
//! input of `Op::Precompute`) - both computed once, up front, before any node is materialized, so
//! there's no ordering hazard between "does this need to exist" and "what does it look like".

use ark_ff::PrimeField;

use crate::ir::{Graph, Node, Op, ValueId};

use super::poly::Affine;
use super::{Changed, Pass, PassContext};

pub(super) struct Normalize;

impl<F: PrimeField> Pass<F> for Normalize {
    fn name(&self) -> &'static str {
        "normalize"
    }

    fn run(&mut self, graph: &mut Graph<F>, _ctx: &mut PassContext) -> eyre::Result<Changed> {
        let nodes = graph.nodes();
        let old_len = nodes.len();
        if old_len == 0 {
            return Ok(false);
        }

        // Phase 1: which original ids must materialize, and each original id's Affine form.
        let mut force = vec![false; old_len];
        for &(_, v) in graph.outputs() {
            force[v.index()] = true;
        }
        let mut affine: Vec<Affine<F>> = Vec::with_capacity(old_len);
        for (i, node) in nodes.iter().enumerate() {
            let a = match &node.op {
                Op::Constant(c) => Affine::constant(*c),
                Op::Add => affine[node.inputs[0].index()].add(&affine[node.inputs[1].index()]),
                Op::Sub => affine[node.inputs[0].index()].sub(&affine[node.inputs[1].index()]),
                Op::Mul => {
                    let (a0, a1) = (&affine[node.inputs[0].index()], &affine[node.inputs[1].index()]);
                    if let Some(c) = a0.as_constant() {
                        a1.scale(c)
                    } else if let Some(c) = a1.as_constant() {
                        a0.scale(c)
                    } else {
                        force[node.inputs[0].index()] = true;
                        force[node.inputs[1].index()] = true;
                        Affine::atom(ValueId::new(i))
                    }
                }
                // Everything else (Input, Precompute, PrecomputeResult, and - defensively, since
                // normalize runs before MPC lowering and should never actually see them -
                // MulLocal/Round/RoundResult) is an opaque atom; every one of its own inputs must
                // materialize, since it's about to become a real node referencing them directly.
                _ => {
                    for input in &node.inputs {
                        force[input.index()] = true;
                    }
                    Affine::atom(ValueId::new(i))
                }
            };
            affine.push(a);
        }

        // Phase 2: materialize exactly what's needed, in original order (every dependency - an
        // atom a foldable form's terms reference, or a self-atom's own raw inputs - has a strictly
        // smaller index, and is therefore already handled by the time we reach it).
        let mut new_nodes: Vec<Node<F>> = Vec::with_capacity(old_len);
        let mut materialized: Vec<Option<ValueId>> = vec![None; old_len];
        for (i, node) in nodes.iter().enumerate() {
            let is_self_atom = affine[i].as_atom() == Some(ValueId::new(i));
            if is_self_atom {
                let remapped = node
                    .inputs
                    .iter()
                    .map(|v| materialized[v.index()].expect("normalize: input not yet materialized"))
                    .collect();
                materialized[i] = Some(push(&mut new_nodes, node.op.clone(), remapped));
            } else if force[i] {
                materialized[i] = Some(materialize_affine(&affine[i], &materialized, &mut new_nodes));
            }
            // else: purely absorbed into some later Affine, never materialized.
        }

        if new_nodes.len() > old_len {
            // Guard: a wide, all-non-trivial-coefficient sum can in principle need as many Mul
            // nodes as it has terms - revert rather than risk a pathological blow-up.
            return Ok(false);
        }

        let changed = new_nodes.len() != old_len;
        if changed {
            graph.rebuild_nodes(new_nodes, &materialized);
        }
        Ok(changed)
    }
}

fn push<F: PrimeField>(new_nodes: &mut Vec<Node<F>>, op: Op<F>, inputs: Vec<ValueId>) -> ValueId {
    let id = ValueId::new(new_nodes.len());
    new_nodes.push(Node::new(op, inputs));
    id
}

/// Emits the fewest nodes representing `affine`, reusing already-materialized atom ids.
fn materialize_affine<F: PrimeField>(
    affine: &Affine<F>,
    materialized: &[Option<ValueId>],
    new_nodes: &mut Vec<Node<F>>,
) -> ValueId {
    if let Some(c) = affine.as_constant() {
        return push(new_nodes, Op::Constant(c), vec![]);
    }
    if let Some(atom) = affine.as_atom() {
        return materialized[atom.index()].expect("normalize: atom materialized before use");
    }

    let mut acc: Option<ValueId> = None;
    if affine.constant != F::zero() {
        acc = Some(push(new_nodes, Op::Constant(affine.constant), vec![]));
    }
    for &(coeff, atom) in &affine.terms {
        let atom_id = materialized[atom.index()].expect("normalize: atom materialized before use");
        acc = Some(if coeff == F::one() {
            match acc {
                None => atom_id,
                Some(prev) => push(new_nodes, Op::Add, vec![prev, atom_id]),
            }
        } else if coeff == -F::one() {
            match acc {
                None => {
                    let zero = push(new_nodes, Op::Constant(F::zero()), vec![]);
                    push(new_nodes, Op::Sub, vec![zero, atom_id])
                }
                Some(prev) => push(new_nodes, Op::Sub, vec![prev, atom_id]),
            }
        } else {
            let cid = push(new_nodes, Op::Constant(coeff), vec![]);
            let scaled = push(new_nodes, Op::Mul, vec![cid, atom_id]);
            match acc {
                None => scaled,
                Some(prev) => push(new_nodes, Op::Add, vec![prev, scaled]),
            }
        });
    }
    acc.expect("non-constant, non-atom affine form must have at least one term")
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
            2,
            1,
            3,
        )
    }

    #[test]
    fn cancels_across_a_chain() {
        // x0=Input(0); x1=Input(1); x2=Add(x0,x1); x3=Sub(x2,x0) -- collapses to just x1
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]),
            Node::new(Op::Input(SignalIdx::new(2)), vec![]),
            Node::new(Op::Add, vec![ValueId::new(0), ValueId::new(1)]),
            Node::new(Op::Sub, vec![ValueId::new(2), ValueId::new(0)]),
        ];
        let mut graph = graph_of(nodes, ValueId::new(3));
        let changed = Pass::run(&mut Normalize, &mut graph, &mut PassContext::default()).unwrap();
        assert!(changed);
        graph.gc();
        assert_eq!(graph.len(), 1); // only x1 (Input 1) survives
    }

    #[test]
    fn does_not_expand_product_of_two_sums() {
        // (a+b) * (c+d): neither side is a constant, so this must stay a single Mul of two
        // materialized linear forms, not expand into 4 cross terms.
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0: a
            Node::new(Op::Input(SignalIdx::new(2)), vec![]), // 1: b
            Node::new(Op::Input(SignalIdx::new(3)), vec![]), // 2: c
            Node::new(Op::Input(SignalIdx::new(4)), vec![]), // 3: d
            Node::new(Op::Add, vec![ValueId::new(0), ValueId::new(1)]), // 4: a+b
            Node::new(Op::Add, vec![ValueId::new(2), ValueId::new(3)]), // 5: c+d
            Node::new(Op::Mul, vec![ValueId::new(4), ValueId::new(5)]), // 6: (a+b)*(c+d)
        ];
        let mut graph: Graph<Fr> = Graph::from_parts(
            nodes,
            vec![(SignalIdx::new(0), ValueId::new(6))],
            vec![],
            vec![],
            vec![],
            vec![],
            4,
            1,
            5,
        );
        Pass::run(&mut Normalize, &mut graph, &mut PassContext::default()).unwrap();
        graph.gc();
        // 4 inputs + one Add for (a+b) + one Add for (c+d) + one Mul = 7, unchanged in shape
        assert_eq!(graph.len(), 7);
        let mul = graph.nodes().last().unwrap();
        assert!(matches!(mul.op, Op::Mul));
    }
}
