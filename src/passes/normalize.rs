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

pub(super) fn run<F: PrimeField>(graph: &mut Graph<F>) -> eyre::Result<bool> {
    let nodes = graph.nodes();
    let old_len = nodes.len();
    if old_len == 0 {
        return Ok(false);
    }

    // Phase 1: which original ids must materialize, and each live original id's Affine form.
    // An input occurrence is one use even when both operands name the same value. On its last
    // use, the form is moved into its consumer; only fan-out (or the synthetic use retained for
    // phase 2) requires a clone. This keeps a single-use chain from retaining every prefix.
    let mut force = vec![false; old_len];
    let mut remaining_uses = vec![0usize; old_len];
    for node in nodes {
        for input in &node.inputs {
            remaining_uses[input.index()] += 1;
        }
    }
    for &(_, v) in graph.outputs() {
        retain_for_materialization(v, &mut force, &mut remaining_uses);
    }
    let mut affine: Vec<Option<Affine<F>>> = Vec::with_capacity(old_len);
    let mut self_atom = vec![false; old_len];
    for (i, node) in nodes.iter().enumerate() {
        let a = match &node.op {
            Op::Constant(c) => Affine::constant(*c),
            Op::Add => {
                let lhs = consume_affine(node.inputs[0], &mut affine, &mut remaining_uses);
                let rhs = consume_affine(node.inputs[1], &mut affine, &mut remaining_uses);
                lhs.add(rhs)
            }
            Op::Sub => {
                let lhs = consume_affine(node.inputs[0], &mut affine, &mut remaining_uses);
                let rhs = consume_affine(node.inputs[1], &mut affine, &mut remaining_uses);
                lhs.sub(rhs)
            }
            Op::Mul => {
                let lhs_constant = affine[node.inputs[0].index()]
                    .as_ref()
                    .expect("normalize: missing live left operand")
                    .as_constant();
                let rhs_constant = affine[node.inputs[1].index()]
                    .as_ref()
                    .expect("normalize: missing live right operand")
                    .as_constant();
                if lhs_constant.is_none() && rhs_constant.is_none() {
                    // Decide this before consuming either edge: on a last use, retaining the
                    // operand adds the phase-2 ownership that prevents it being moved away.
                    retain_for_materialization(node.inputs[0], &mut force, &mut remaining_uses);
                    retain_for_materialization(node.inputs[1], &mut force, &mut remaining_uses);
                }
                let lhs = consume_affine(node.inputs[0], &mut affine, &mut remaining_uses);
                let rhs = consume_affine(node.inputs[1], &mut affine, &mut remaining_uses);
                if let Some(c) = lhs_constant {
                    rhs.scale(c)
                } else if let Some(c) = rhs_constant {
                    lhs.scale(c)
                } else {
                    self_atom[i] = true;
                    Affine::atom(ValueId::new(i))
                }
            }
            // Everything else (Input, Precompute, PrecomputeResult, and - defensively, since
            // normalize runs before MPC lowering and should never actually see them -
            // MulLocal/Round/RoundResult) is an opaque atom; every one of its own inputs must
            // materialize, since it's about to become a real node referencing them directly.
            _ => {
                for input in &node.inputs {
                    retain_for_materialization(*input, &mut force, &mut remaining_uses);
                }
                for input in &node.inputs {
                    drop(consume_affine(*input, &mut affine, &mut remaining_uses));
                }
                self_atom[i] = true;
                Affine::atom(ValueId::new(i))
            }
        };
        // A dead form with no future or materialization use need not occupy a slot at all.
        affine.push((remaining_uses[i] != 0).then_some(a));
    }

    // Phase 2: materialize exactly what's needed, in original order (every dependency - an
    // atom a foldable form's terms reference, or a self-atom's own raw inputs - has a strictly
    // smaller index, and is therefore already handled by the time we reach it).
    let mut new_nodes: Vec<Node<F>> = Vec::with_capacity(old_len);
    let mut materialized: Vec<Option<ValueId>> = vec![None; old_len];
    for (i, node) in nodes.iter().enumerate() {
        if self_atom[i] {
            let remapped = node
                .inputs
                .iter()
                .map(|v| {
                    materialized[v.index()].expect("normalize: input not yet materialized")
                })
                .collect();
            materialized[i] = Some(push(&mut new_nodes, node.op.clone(), remapped));
        } else if force[i] {
            materialized[i] = Some(materialize_affine(
                affine[i]
                    .as_ref()
                    .expect("normalize: forced affine form was not retained"),
                &materialized,
                &mut new_nodes,
            ));
        }
        // else: purely absorbed into some later Affine, never materialized.
    }

    if new_nodes.len() > old_len {
        // Guard: a wide, all-non-trivial-coefficient sum can in principle need as many Mul
        // nodes as it has terms - revert rather than risk a pathological blow-up.
        return Ok(false);
    }

    // Node count is only a growth guard, not a change detector: `x - x` and its replacement
    // `0` both occupy one result node before the next GC pass. Compare structure and output
    // remaps so equal-sized canonical rewrites are committed and an already-canonical graph
    // still converges.
    let nodes_unchanged = new_nodes.len() == old_len
        && nodes
            .iter()
            .zip(&new_nodes)
            .all(|(old, new)| old.op == new.op && old.inputs == new.inputs);
    let outputs_unchanged = graph
        .outputs()
        .iter()
        .all(|&(_, output)| materialized[output.index()] == Some(output));
    let changed = !nodes_unchanged || !outputs_unchanged;
    if changed {
        graph.rebuild_nodes(new_nodes, &materialized);
    }
    Ok(changed)
}

/// Adds one phase-2 use the first time a value is forced to materialize.
fn retain_for_materialization(value: ValueId, force: &mut [bool], remaining_uses: &mut [usize]) {
    if !force[value.index()] {
        force[value.index()] = true;
        remaining_uses[value.index()] += 1;
    }
}

/// Obtains one input occurrence's form, moving it on the final use and cloning only for fan-out or
/// when phase 2 owns the retained copy.
fn consume_affine<F: PrimeField>(
    value: ValueId,
    affine: &mut [Option<Affine<F>>],
    remaining_uses: &mut [usize],
) -> Affine<F> {
    let uses = &mut remaining_uses[value.index()];
    assert_ne!(
        *uses, 0,
        "normalize: consumed an affine form too many times"
    );
    *uses -= 1;
    if *uses == 0 {
        affine[value.index()]
            .take()
            .expect("normalize: missing affine form on final use")
    } else {
        affine[value.index()]
            .as_ref()
            .expect("normalize: missing shared affine form")
            .clone()
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
    for (coeff, atom) in affine.sorted_terms() {
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
        let changed = run(&mut graph).unwrap();
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
        run(&mut graph).unwrap();
        graph.gc();
        // 4 inputs + one Add for (a+b) + one Add for (c+d) + one Mul = 7, unchanged in shape
        assert_eq!(graph.len(), 7);
        let mul = graph.nodes().last().unwrap();
        assert!(matches!(mul.op, Op::Mul));
    }

    #[test]
    fn commits_equal_sized_rewrite_and_then_converges() {
        // The input is retained until the next GC, so replacing the one Sub node with one Constant
        // does not change the graph's length. The structural rewrite must still be committed.
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]),
            Node::new(Op::Sub, vec![ValueId::new(0), ValueId::new(0)]),
        ];
        let mut graph = graph_of(nodes, ValueId::new(1));

        let changed = run(&mut graph).unwrap();
        assert!(changed);
        assert!(matches!(
            graph.nodes()[1].op,
            Op::Constant(c) if c == Fr::from(0u64)
        ));
        assert!(graph.nodes()[1].inputs.is_empty());

        let changed_again =
            run(&mut graph).unwrap();
        assert!(!changed_again, "canonical zero must be a fixpoint");
    }

    #[test]
    fn counts_fanout_edges_independently() {
        // p = a+b; q = p+a; out = q-p. The two uses of p must each consume one ownership count,
        // while its shared form remains available for the second edge. Everything cancels to a.
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]),
            Node::new(Op::Input(SignalIdx::new(2)), vec![]),
            Node::new(Op::Add, vec![ValueId::new(0), ValueId::new(1)]),
            Node::new(Op::Add, vec![ValueId::new(2), ValueId::new(0)]),
            Node::new(Op::Sub, vec![ValueId::new(3), ValueId::new(2)]),
        ];
        let mut graph = graph_of(nodes, ValueId::new(4));

        assert!(run(&mut graph).unwrap());
        graph.gc();
        assert_eq!(graph.len(), 1);
        assert!(matches!(graph.nodes()[0].op, Op::Input(_)));
    }

    #[test]
    fn counts_repeated_binary_operand_edges_independently() {
        // p*p names the same nontrivial affine form twice. Both input occurrences are real uses,
        // and p also needs a retained phase-2 copy because the genuine Mul consumes it directly.
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]),
            Node::new(Op::Input(SignalIdx::new(2)), vec![]),
            Node::new(Op::Add, vec![ValueId::new(0), ValueId::new(1)]),
            Node::new(Op::Mul, vec![ValueId::new(2), ValueId::new(2)]),
        ];
        let mut graph = graph_of(nodes, ValueId::new(3));

        let changed = run(&mut graph).unwrap();
        assert!(!changed, "the already-canonical graph should be preserved");
        assert_eq!(
            graph.nodes()[3].inputs,
            vec![ValueId::new(2), ValueId::new(2)]
        );
    }

    #[test]
    fn long_single_use_sum_does_not_retain_affine_prefixes() {
        // This size is intentionally large enough that retaining every prefix would require tens
        // of millions of field entries. It uses no timing assertion: completing the ordinary pass
        // and preserving the already-canonical graph is the regression check.
        const TERMS: usize = 8_192;
        let mut nodes = Vec::with_capacity(2 * TERMS - 1);
        for i in 0..TERMS {
            nodes.push(Node::new(Op::Input(SignalIdx::new(i + 1)), vec![]));
        }
        let mut sum = ValueId::new(0);
        for atom in 1..TERMS {
            let next = ValueId::new(nodes.len());
            nodes.push(Node::new(Op::Add, vec![sum, ValueId::new(atom)]));
            sum = next;
        }
        let mut graph = graph_of(nodes, sum);

        let changed = run(&mut graph).unwrap();
        assert!(!changed);
        assert_eq!(graph.len(), 2 * TERMS - 1);
    }
}
