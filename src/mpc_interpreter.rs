use core::panic;

use ark_ff::PrimeField;
use co_circom_snarks::SharedWitness;

use crate::{
    mpc::traits::MpcExecutor,
    mpc_ir::types::{MpcCircomAST, Op, WireType},
};

pub struct MpcInterpreter<F: PrimeField, T: MpcExecutor<F>> {
    inner: T,
    ast: MpcCircomAST<F>,
    signals: Vec<T::ArithmeticShare>,
    public_wires: Vec<F>,
    arithmetic_wires: Vec<T::ArithmeticShare>,
    binary_wires: Vec<T::BinaryShare>,
}

impl<F: PrimeField, T: MpcExecutor<F>> MpcInterpreter<F, T> {
    pub fn new(inner: T, ast: MpcCircomAST<F>, input_signals: Vec<T::ArithmeticShare>) -> Self {
        let amount_wires = ast.wires.len();
        let mut public_wires = vec![];
        let mut arithmetic_wires = vec![];
        let mut binary_wires = vec![];
        let mut signals = vec![];
        // TODO index wires per type so we can use the right size and not total
        public_wires.resize(amount_wires, F::default());
        arithmetic_wires.resize(amount_wires, T::ArithmeticShare::default());
        binary_wires.resize(amount_wires, T::BinaryShare::default());
        signals.resize(ast.num_signals, T::ArithmeticShare::default());
        signals[0] = T::embed_public(F::one());
        signals[1 + ast.num_outputs..1 + ast.num_outputs + ast.num_inputs]
            .clone_from_slice(&input_signals);
        Self {
            inner,
            ast,
            signals,
            public_wires,
            arithmetic_wires,
            binary_wires,
        }
    }

    fn output_mapping(&mut self) -> eyre::Result<SharedWitness<F, T::ArithmeticShare>> {
        dbg!(&self.ast.signal_to_witness);
        // TODO get this from compiler
        let amount_public_inputs = 0;
        let total_public_amount = self.ast.num_outputs + amount_public_inputs + 1;
        let mut public_inputs = Vec::with_capacity(total_public_amount);
        let mut witness = Vec::with_capacity(self.ast.signal_to_witness.len());
        for (count, idx) in self.ast.signal_to_witness.iter().enumerate() {
            if count < total_public_amount {
                public_inputs.push(T::get_public(self.signals[*idx].clone()));
            } else {
                witness.push(self.signals[*idx].clone());
            }
        }
        Ok(SharedWitness {
            public_inputs,
            witness,
        })
    }

    pub fn run(&mut self) -> eyre::Result<SharedWitness<F, T::ArithmeticShare>> {
        // println!("{:?}", self.ast);
        for node in self.ast.nodes.iter() {
            tracing::info!("node = {node:?}");
            match node.op {
                Op::Input(input) => {
                    assert!(node.input.is_empty());
                    assert_eq!(node.output.len(), 1);
                    let out_wire = node.output[0];
                    let value = self.signals[input + 1].clone();
                    // out wires of input nodes are set while generating the mpc_ir, so we can read them here
                    match self.ast.wires[out_wire] {
                        WireType::Public => {
                            self.public_wires[out_wire] = T::get_public(value);
                        }
                        WireType::ArithmeticShare => self.arithmetic_wires[out_wire] = value,
                        _ => panic!("input nodes should never have binary wires"),
                    }
                }
                Op::Output(idx) => {
                    assert_eq!(node.input.len(), 1);
                    assert_eq!(node.output.len(), 1);
                    let in_wire = node.input[0];
                    let out_wire = node.output[0];
                    match self.ast.wires[in_wire] {
                        WireType::Public => {
                            let value = self.public_wires[in_wire];
                            self.signals[idx + 1] = T::embed_public(value);
                            // TODO do we need out wires here?
                            self.public_wires[out_wire] = value;
                        }
                        WireType::ArithmeticShare => {
                            let value = self.arithmetic_wires[in_wire].clone();
                            self.signals[idx + 1] = value.clone();
                            // TODO do we need out wires here?
                            self.arithmetic_wires[out_wire] = value;
                        }
                        _ => panic!("output nodes should never have binary inputs"),
                    }
                }
                Op::Constant(c) => {
                    assert!(node.input.is_empty());
                    assert_eq!(node.output.len(), 1);
                    let out_wire = *node.output.first().unwrap();
                    self.public_wires[out_wire] = c;
                }
                Op::A2B => {
                    assert_eq!(node.input.len(), 1);
                    assert_eq!(node.output.len(), 1);
                    let input = self.arithmetic_wires[node.input[0]].clone();
                    self.binary_wires[node.output[0]] = self.inner.a2b(input)?;
                }
                Op::B2A => {
                    assert_eq!(node.input.len(), 1);
                    assert_eq!(node.output.len(), 1);
                    let input = self.binary_wires[node.input[0]].clone();
                    self.arithmetic_wires[node.output[0]] = self.inner.b2a(input)?;
                }
                Op::OpenArihmetic => {
                    assert_eq!(node.input.len(), 1);
                    assert_eq!(node.output.len(), 1);
                    let input = self.arithmetic_wires[node.input[0]].clone();
                    self.public_wires[node.output[0]] = self.inner.open_arithmetic(input)?;
                }
                Op::OpenBinary => {
                    assert_eq!(node.input.len(), 1);
                    assert_eq!(node.output.len(), 1);
                    let input = &self.binary_wires[node.input[0]];
                    self.public_wires[node.output[0]] = self.inner.open_binary(input)?;
                }
                Op::Add => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = self.public_wires[node.input[0]];
                    let rhs = self.public_wires[node.input[1]];
                    self.public_wires[node.output[0]] = self.inner.add(lhs, rhs);
                }
                Op::AddSecretPublic => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = self.arithmetic_wires[node.input[0]].clone();
                    let rhs = self.public_wires[node.input[1]];
                    self.arithmetic_wires[node.output[0]] = self.inner.add_secret_public(lhs, rhs);
                }
                Op::AddSecretSecret => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = self.arithmetic_wires[node.input[0]].clone();
                    let rhs = self.arithmetic_wires[node.input[1]].clone();
                    self.arithmetic_wires[node.output[0]] = self.inner.add_secret_secret(lhs, rhs);
                }
                Op::Sub => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = self.public_wires[node.input[0]];
                    let rhs = self.public_wires[node.input[1]];
                    self.public_wires[node.output[0]] = self.inner.sub(lhs, rhs);
                }
                Op::SubPublicSecret => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = self.public_wires[node.input[0]];
                    let rhs = self.arithmetic_wires[node.input[1]].clone();
                    self.arithmetic_wires[node.output[0]] = self.inner.sub_public_secret(lhs, rhs);
                }
                Op::SubSecretPublic => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = self.arithmetic_wires[node.input[0]].clone();
                    let rhs = self.public_wires[node.input[1]];
                    self.arithmetic_wires[node.output[0]] = self.inner.sub_secret_public(lhs, rhs);
                }
                Op::SubSecretSecret => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = self.arithmetic_wires[node.input[0]].clone();
                    let rhs = self.arithmetic_wires[node.input[1]].clone();
                    self.arithmetic_wires[node.output[0]] = self.inner.sub_secret_secret(lhs, rhs);
                }
                Op::Mul => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = self.public_wires[node.input[0]];
                    let rhs = self.public_wires[node.input[1]];
                    self.public_wires[node.output[0]] = self.inner.mul(lhs, rhs);
                }
                Op::MulSecretPublic => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = self.arithmetic_wires[node.input[0]].clone();
                    let rhs = self.public_wires[node.input[1]];
                    self.arithmetic_wires[node.output[0]] = self.inner.mul_secret_public(lhs, rhs);
                }
                Op::MulSecretSecret => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = self.arithmetic_wires[node.input[0]].clone();
                    let rhs = self.arithmetic_wires[node.input[1]].clone();
                    self.arithmetic_wires[node.output[0]] =
                        self.inner.mul_secret_secret(lhs, rhs)?;
                }
                Op::Div => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = self.public_wires[node.input[0]];
                    let rhs = self.public_wires[node.input[1]];
                    self.public_wires[node.output[0]] = self.inner.div(lhs, rhs);
                }
                Op::DivPublicSecret => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = self.public_wires[node.input[0]];
                    let rhs = self.arithmetic_wires[node.input[1]].clone();
                    self.arithmetic_wires[node.output[0]] =
                        self.inner.div_public_secret(lhs, rhs)?;
                }
                Op::DivSecretPublic => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = self.arithmetic_wires[node.input[0]].clone();
                    let rhs = self.public_wires[node.input[1]];
                    self.arithmetic_wires[node.output[0]] =
                        self.inner.div_secret_public(lhs, rhs)?;
                }
                Op::DivSecretSecret => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = self.arithmetic_wires[node.input[0]].clone();
                    let rhs = self.arithmetic_wires[node.input[1]].clone();
                    self.arithmetic_wires[node.output[0]] =
                        self.inner.div_secret_secret(lhs, rhs)?;
                }
                Op::IntDiv => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = self.public_wires[node.input[0]];
                    let rhs = self.public_wires[node.input[1]];
                    self.public_wires[node.output[0]] = self.inner.int_div(lhs, rhs)?;
                }
                Op::Pow => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = self.public_wires[node.input[0]];
                    let rhs = self.public_wires[node.input[1]];
                    self.public_wires[node.output[0]] = self.inner.pow(lhs, rhs);
                }
                Op::PowSecretPublic => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = self.arithmetic_wires[node.input[0]].clone();
                    let rhs = self.public_wires[node.input[1]];
                    self.arithmetic_wires[node.output[0]] =
                        self.inner.pow_secret_public(lhs, rhs)?;
                }
                Op::ShiftL => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = self.public_wires[node.input[0]];
                    let rhs = self.public_wires[node.input[1]];
                    self.public_wires[node.output[0]] = self.inner.lshift(lhs, rhs)?;
                }
                Op::ShiftLSecretPublic => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = self.arithmetic_wires[node.input[0]].clone();
                    let rhs = self.public_wires[node.input[1]];
                    self.arithmetic_wires[node.output[0]] =
                        self.inner.lshift_secret_public(lhs, rhs)?;
                }
                Op::ShiftR => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = self.public_wires[node.input[0]];
                    let rhs = self.public_wires[node.input[1]];
                    self.public_wires[node.output[0]] = self.inner.rshift(lhs, rhs)?;
                }
                Op::ShiftRSecretPublic => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = self.arithmetic_wires[node.input[0]].clone();
                    let rhs = self.public_wires[node.input[1]];
                    self.arithmetic_wires[node.output[0]] =
                        self.inner.rshift_secret_public(lhs, rhs)?;
                }
                Op::BitOr => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = self.public_wires[node.input[0]];
                    let rhs = self.public_wires[node.input[1]];
                    self.public_wires[node.output[0]] = self.inner.bit_or(lhs, rhs);
                }
                Op::BitOrSecretPublic => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = &self.binary_wires[node.input[0]];
                    let rhs = self.public_wires[node.input[1]];
                    self.binary_wires[node.output[0]] = self.inner.bit_or_secret_public(lhs, rhs);
                }
                Op::BitOrSecretSecret => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = &self.binary_wires[node.input[0]];
                    let rhs = &self.binary_wires[node.input[1]];
                    self.binary_wires[node.output[0]] =
                        self.inner.bit_or_secret_secret(lhs, rhs)?;
                }
                Op::BitAnd => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = self.public_wires[node.input[0]];
                    let rhs = self.public_wires[node.input[1]];
                    self.public_wires[node.output[0]] = self.inner.bit_and(lhs, rhs);
                }
                Op::BitAndSecretPublic => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = &self.binary_wires[node.input[0]];
                    let rhs = self.public_wires[node.input[1]];
                    self.binary_wires[node.output[0]] = self.inner.bit_and_secret_public(lhs, rhs);
                }
                Op::BitAndSecretSecret => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = &self.binary_wires[node.input[0]];
                    let rhs = &self.binary_wires[node.input[1]];
                    self.binary_wires[node.output[0]] =
                        self.inner.bit_and_secret_secret(lhs, rhs)?;
                }
                Op::BitXor => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = self.public_wires[node.input[0]];
                    let rhs = self.public_wires[node.input[1]];
                    self.public_wires[node.output[0]] = self.inner.bit_xor(lhs, rhs);
                }
                Op::BitXorSecretPublic => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = &self.binary_wires[node.input[0]];
                    let rhs = self.public_wires[node.input[1]];
                    self.binary_wires[node.output[0]] = self.inner.bit_xor_secret_public(lhs, rhs);
                }
                Op::BitXorSecretSecret => {
                    assert_eq!(node.input.len(), 2);
                    assert_eq!(node.output.len(), 1);
                    let lhs = &self.binary_wires[node.input[0]];
                    let rhs = &self.binary_wires[node.input[1]];
                    self.binary_wires[node.output[0]] = self.inner.bit_xor_secret_secret(lhs, rhs);
                }
            }
        }
        self.output_mapping()
    }
}
