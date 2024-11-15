use ark_ff::PrimeField;

use crate::circom_ir::types::{CircomAST, Op};

pub struct Interpreter<F: PrimeField> {
    ast: CircomAST<F>,
    signals: Vec<F>,
    wires: Vec<F>,
}

impl<F: PrimeField> Interpreter<F> {
    pub fn new(ast: CircomAST<F>, input_signals: Vec<F>) -> Self {
        let mut wires = vec![];
        let mut signals = vec![];
        wires.resize(ast.amount_wires, F::zero());
        signals.resize(ast.num_signals, F::zero());
        signals[0] = F::one();
        signals[1 + ast.num_outputs..1 + ast.num_outputs + ast.num_inputs]
            .clone_from_slice(&input_signals);
        Self {
            ast,
            signals,
            wires,
        }
    }

    fn output_mapping(&mut self) -> Vec<F> {
        let mut witness = Vec::with_capacity(self.ast.signal_to_witness.len());
        for idx in self.ast.signal_to_witness.iter() {
            witness.push(self.signals[*idx]);
        }
        witness
    }

    pub fn run(&mut self) -> Vec<F> {
        // println!("{:?}", self.ast);
        for node in self.ast.nodes.iter() {
            tracing::info!("node = {node:?}");
            match node.op {
                Op::LoadSubCmp(_, _) => unreachable!("is removed"),
                Op::StoreSubCmp(_, _) => unreachable!("is removed"),
                Op::Input(input) => {
                    assert!(node.input.is_empty());
                    assert_eq!(node.output.len(), 1);
                    let value = self.signals[input + 1];
                    let out_wire = node.output[0];
                    self.wires[out_wire] = value;
                }
                Op::Output(idx) => {
                    assert_eq!(node.input.len(), 1);
                    assert_eq!(node.output.len(), 1);
                    let in_wire = node.input[0];
                    let out_wire = node.output[0];
                    let value = self.wires[in_wire];
                    self.signals[idx + 1] = value;
                    self.wires[out_wire] = value;
                }
                Op::Constant(c) => {
                    assert!(node.input.is_empty());
                    assert_eq!(node.output.len(), 1);
                    let out_wire = *node.output.first().unwrap();
                    self.wires[out_wire] = c;
                }
                Op::Add => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs_wire = node.input[0];
                    let rhs_wire = node.input[1];
                    let out_wire = node.output[0];
                    let lhs = self.wires[lhs_wire];
                    let rhs = self.wires[rhs_wire];
                    self.wires[out_wire] = lhs + rhs;
                }
                Op::Mul => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs_wire = node.input[0];
                    let rhs_wire = node.input[1];
                    let out_wire = node.output[0];
                    let lhs = self.wires[lhs_wire];
                    let rhs = self.wires[rhs_wire];
                    tracing::trace!("{lhs}*{rhs} = {}", lhs * rhs);
                    self.wires[out_wire] = lhs * rhs;
                }
                Op::Sub => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs_wire = node.input[0];
                    let rhs_wire = node.input[1];
                    let out_wire = node.output[0];
                    let lhs = self.wires[lhs_wire];
                    let rhs = self.wires[rhs_wire];
                    self.wires[out_wire] = lhs - rhs;
                }
                Op::Div => todo!(),
                Op::Pow => todo!(),
                Op::IntDiv => todo!(),
                Op::ShiftL => todo!(),
                Op::ShiftR => todo!(),
                Op::BitOr => todo!(),
                Op::BitAnd => todo!(),
                Op::BitXor => todo!(),
                Op::Load => {
                    // for the time being
                    unreachable!("removed");
                }
            }
        }
        self.output_mapping()
    }
}
