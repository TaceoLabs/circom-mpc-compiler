use ark_ff::PrimeField;

use crate::circom_ir::types::{CircomAST, Op};

pub(crate) fn dead_code_elimination<F: PrimeField>(
    ast: CircomAST<F>,
) -> eyre::Result<CircomAST<F>> {
    let CircomAST {
        mut nodes,
        signal_to_witness,
        num_inputs,
        num_outputs,
        num_signals,
        amount_wires,
        input_list,
        public_inputs,
    } = ast;

    // remove trailing nodes that are not stores
    let num_trailng = nodes
        .iter()
        .rev()
        .take_while(|node| !matches!(node.op, Op::Output(_)))
        .count();
    println!("removing {num_trailng} trailing nodes");
    nodes.truncate(nodes.len() - num_trailng);

    // find dead nodes and wires
    let mut keep_wires = vec![false; amount_wires];
    let mut keep_nodes = vec![false; nodes.len()];

    for (i, node) in nodes.iter().rev().enumerate() {
        // correct node index
        let i = nodes.len() - i - 1;
        // keep output nodes and mark their inputs as keep
        if let Op::Output(_) = node.op {
            keep_nodes[i] = true;
            keep_wires[*node.input.first().unwrap()] = true;
        } else {
            // if not store, check if any output wire is marked as keep
            for out_wire in node.output.iter() {
                // if we keep the node, keep all its inputs
                if keep_wires[*out_wire] {
                    keep_nodes[i] = true;
                    for in_wire in node.input.iter() {
                        keep_wires[*in_wire] = true;
                    }
                    break;
                }
            }
        }
    }

    // dbg!(&keep_wires);
    // dbg!(&keep_nodes);

    let num_nodes = nodes.len();

    // remove dead code
    let mut keep_nodes = keep_nodes.iter();
    nodes.retain(|_| *keep_nodes.next().unwrap());

    let num_nodes = num_nodes - nodes.len();

    println!("removed {num_nodes} dead nodes");

    Ok(CircomAST {
        nodes,
        signal_to_witness,
        num_inputs,
        num_outputs,
        num_signals,
        amount_wires,
        input_list,
        public_inputs,
    })
}
