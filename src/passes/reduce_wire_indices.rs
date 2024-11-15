use ark_ff::PrimeField;
use intmap::IntMap;

use crate::circom_ir::types::CircomAST;

pub(crate) fn reduce_wire_indices<F: PrimeField>(ast: CircomAST<F>) -> eyre::Result<CircomAST<F>> {
    let CircomAST {
        mut nodes,
        signal_to_witness,
        num_inputs,
        num_outputs,
        num_signals,
        amount_wires,
    } = ast;

    println!("amount wires = {amount_wires}");

    let mut indices = IntMap::new();
    let mut wire_index = 0;

    for node in nodes.iter_mut() {
        for wire in node.input.iter_mut().chain(node.output.iter_mut()) {
            if indices.insert_checked(*wire as u64, wire_index) {
                wire_index += 1;
            }
            *wire = *indices.get(*wire as u64).unwrap();
        }
    }

    let amount_wires = wire_index;

    println!("amount wires after = {amount_wires}");

    Ok(CircomAST {
        nodes,
        signal_to_witness,
        num_inputs,
        num_outputs,
        num_signals,
        amount_wires,
    })
}
