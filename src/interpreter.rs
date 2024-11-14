use ark_ff::PrimeField;
use intmap::IntMap;

use crate::circom_ir::types::{CircomAST, Op, Wire, WireType};

pub struct Interpreter<F: PrimeField> {
    ast: CircomAST<F>,
    signals: Vec<F>,
    wires: IntMap<F>,
}

impl<F: PrimeField> Interpreter<F> {
    pub fn new(ast: CircomAST<F>, signals: Vec<F>) -> Self {
        Self {
            ast,
            signals,
            wires: IntMap::new(),
        }
    }

    fn get_in_wire(&mut self, wire: Wire) -> Option<F> {
        let info = self.ast.wires[wire];
        match info.ty {
            WireType::Input => Some(self.signals[wire + 1]),
            WireType::Output => panic!(),
            WireType::Intermediate => self.wires.get(wire as u64).copied(),
        }
    }

    fn set_out_wire(&mut self, wire: Wire, value: F) {
        let info = self.ast.wires[wire];
        match info.ty {
            WireType::Input => panic!(),
            WireType::Output => self.signals[wire + 1] = value,
            WireType::Intermediate => {
                assert!(self.wires.insert(wire as u64, value).is_none());
            }
        }
    }

    pub fn run(&mut self) -> Vec<F> {
        // TODO we dont need to clone
        for node in self.ast.nodes.clone() {
            tracing::info!("node = {node:?}");
            match node.op {
                Op::LoadSubCmp(_, _) => todo!(),
                Op::Load => {
                    assert_eq!(node.input.len(), 1);
                    assert_eq!(node.output.len(), 1);
                    let in_wire = *node.input.first().unwrap();
                    let out_wire = *node.output.first().unwrap();
                    let value = self.get_in_wire(in_wire).unwrap();
                    self.set_out_wire(out_wire, value);
                }
                Op::StoreSubCmp(_, _) => todo!(),
                Op::Store(idx) => {
                    assert_eq!(node.input.len(), 1);
                    assert!(node.output.is_empty());
                    let in_wire = *node.input.first().unwrap();
                    let value = self.get_in_wire(in_wire).unwrap();
                    self.signals[idx + 1] = value;
                }
                Op::Constant(c) => {
                    assert!(node.input.is_empty());
                    assert_eq!(node.output.len(), 1);
                    let out_wire = *node.output.first().unwrap();
                    self.set_out_wire(out_wire, c);
                }
                Op::Add => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs_wire = *node.input.first().unwrap();
                    let rhs_wire = *node.input.get(1).unwrap();
                    let out_wire = *node.output.first().unwrap();
                    let lhs = self.get_in_wire(lhs_wire).unwrap();
                    let rhs = self.get_in_wire(rhs_wire).unwrap();
                    self.set_out_wire(out_wire, lhs + rhs);
                }
                Op::Mul => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs_wire = *node.input.first().unwrap();
                    let rhs_wire = *node.input.get(1).unwrap();
                    let out_wire = *node.output.first().unwrap();
                    let lhs = self.get_in_wire(lhs_wire).unwrap();
                    let rhs = self.get_in_wire(rhs_wire).unwrap();
                    self.set_out_wire(out_wire, lhs * rhs);
                }
                Op::Sub => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs_wire = *node.input.first().unwrap();
                    let rhs_wire = *node.input.get(1).unwrap();
                    let out_wire = *node.output.first().unwrap();
                    let lhs = self.get_in_wire(lhs_wire).unwrap();
                    let rhs = self.get_in_wire(rhs_wire).unwrap();
                    self.set_out_wire(out_wire, lhs - rhs);
                }
            }
        }
        self.signals.clone()
    }
}
