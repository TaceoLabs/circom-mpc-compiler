use ark_ff::PrimeField;
use intmap::IntMap;

use crate::circom_ir::types::{CircomAST, Op};

pub(crate) fn load_elimination<F: PrimeField>(ast: CircomAST<F>) -> eyre::Result<CircomAST<F>> {
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

    let mut keep_nodes = vec![true; nodes.len()];
    let mut rewire = IntMap::new();

    for (i, node) in nodes.iter_mut().enumerate() {
        // remove load nodes and keep track of the wires we need to rewire
        if let Op::Load = node.op {
            keep_nodes[i] = false;
            if let Some(entry) = rewire.remove(*node.input.first().unwrap() as u64) {
                rewire.insert(*node.output.first().unwrap() as u64, entry);
            } else {
                rewire.insert(
                    *node.output.first().unwrap() as u64,
                    *node.input.first().unwrap(),
                );
            }
        } else {
            for in_wire in node.input.iter_mut() {
                if let Some(new_in_wire) = rewire.get(*in_wire as u64) {
                    *in_wire = *new_in_wire;
                }
            }
        }
    }

    let num_nodes = nodes.len();

    // remove load nodes
    let mut keep_nodes = keep_nodes.iter();
    nodes.retain(|_| *keep_nodes.next().unwrap());

    let num_nodes = num_nodes - nodes.len();

    println!("removed {num_nodes} load nodes");

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
