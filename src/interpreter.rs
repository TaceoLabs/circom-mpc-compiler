//! Plaintext reference evaluator over [`ir::Graph`], used for debugging and as the oracle for the
//! plain-path KAT tests until the bytecode VM (a later step) takes over that role.

use ark_ff::PrimeField;

use crate::ir::{self, Op};

pub struct Interpreter<F: PrimeField> {
    graph: ir::Graph<F>,
    signals: Vec<F>,
    values: Vec<F>,
}

impl<F: PrimeField> Interpreter<F> {
    pub fn new(graph: ir::Graph<F>, input_signals: Vec<F>) -> Self {
        let mut signals = vec![F::zero(); graph.num_signals];
        signals[0] = F::one();
        signals[1 + graph.num_outputs..1 + graph.num_outputs + graph.num_inputs]
            .clone_from_slice(&input_signals);
        let values = vec![F::zero(); graph.len()];
        Self {
            graph,
            signals,
            values,
        }
    }

    fn output_mapping(&self) -> Vec<F> {
        self.graph
            .signal_to_witness
            .iter()
            .map(|&idx| self.signals[idx])
            .collect()
    }

    pub fn run(&mut self) -> Vec<F> {
        for (id, node) in self.graph.nodes().iter().enumerate() {
            tracing::trace!("node {id} = {node:?}");
            let value = match &node.op {
                Op::Input(signal) => self.signals[signal.index() + 1],
                Op::Constant(c) => *c,
                Op::Add => {
                    self.values[node.inputs[0].index()] + self.values[node.inputs[1].index()]
                }
                Op::Sub => {
                    self.values[node.inputs[0].index()] - self.values[node.inputs[1].index()]
                }
                Op::Mul => {
                    let lhs = self.values[node.inputs[0].index()];
                    let rhs = self.values[node.inputs[1].index()];
                    tracing::trace!("{lhs}*{rhs} = {}", lhs * rhs);
                    lhs * rhs
                }
            };
            self.values[id] = value;
        }
        for &(signal, value) in self.graph.outputs() {
            self.signals[signal.index() + 1] = self.values[value.index()];
        }
        self.output_mapping()
    }
}
