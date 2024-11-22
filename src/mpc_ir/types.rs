use std::collections::HashSet;

use ark_ff::PrimeField;
use intmap::IntMap;

pub(crate) type Wire = usize;
pub(crate) type NodeId = usize;

macro_rules! to_u64 {
    ($x: expr) => {
        u64::try_from($x).expect("fits into u64")
    };
}

#[derive(Debug, Clone, Copy)]
pub enum WireType {
    Public,
    ArithmeticShare,
    BinaryShare,
}

#[derive(Clone)]
pub(crate) struct Node<F: PrimeField> {
    pub(crate) op: Op<F>,
    pub(crate) input: Vec<Wire>,
    pub(crate) output: Vec<Wire>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op<F: PrimeField> {
    Input(usize),
    Output(usize),
    Constant(F),
    A2B,
    B2A,
    OpenArihmetic,
    OpenBinary,
    Add,
    AddSecretPublic,
    AddSecretSecret,
    Sub,
    SubPublicSecret,
    SubSecretPublic,
    SubSecretSecret,
    Mul,
    MulSecretPublic,
    MulSecretSecret,
    Div,
    DivPublicSecret,
    DivSecretPublic,
    DivSecretSecret,
    IntDiv,
    Pow,
    PowSecretPublic,
    ShiftR,
    ShiftRSecretPublic,
    ShiftL,
    ShiftLSecretPublic,
    BitOr,
    BitOrSecretPublic,
    BitOrSecretSecret,
    BitAnd,
    BitAndSecretPublic,
    BitAndSecretSecret,
    BitXor,
    BitXorSecretPublic,
    BitXorSecretSecret,
}

#[derive(Clone)]
pub struct MpcCircomAST<F: PrimeField> {
    pub(crate) nodes: Vec<Node<F>>,
    pub signal_to_witness: Vec<usize>,
    pub num_inputs: usize,
    pub num_outputs: usize,
    pub num_signals: usize,
    pub wires: Vec<WireType>,
}

impl<F: PrimeField> Node<F> {
    pub(crate) fn inline(mut self, signal_offset: usize, wire: Wire) -> Self {
        if let Op::Output(loc) = &mut self.op {
            *loc += signal_offset;
        }
        #[allow(unused_mut)]
        for mut input in self.input.iter_mut() {
            *input += wire;
        }

        #[allow(unused_mut)]
        for mut output in self.output.iter_mut() {
            *output += wire;
        }
        self
    }

    pub(crate) fn input(signal: usize, output: Wire) -> Self {
        Node {
            op: Op::Input(signal),
            input: vec![],
            output: vec![output],
        }
    }

    pub(crate) fn output(signal: usize, input: Wire, output: Wire) -> Self {
        Node {
            op: Op::Output(signal),
            input: vec![input],
            output: vec![output],
        }
    }

    pub(crate) fn bin_op(op: Op<F>, lhs: Wire, rhs: Wire, output: Wire) -> Self {
        Self {
            op,
            input: vec![lhs, rhs],
            output: vec![output],
        }
    }

    pub(crate) fn open(op: Op<F>, input: Wire, output: Wire) -> Self {
        assert!(matches!(op, Op::OpenArihmetic | Op::OpenBinary));
        Self {
            op,
            input: vec![input],
            output: vec![output],
        }
    }

    pub(crate) fn conversion(op: Op<F>, input: Wire, output: Wire) -> Self {
        assert!(matches!(op, Op::A2B | Op::B2A));
        Self {
            op,
            input: vec![input],
            output: vec![output],
        }
    }

    pub(crate) fn constant(constant: F, output: Wire) -> Self {
        Self {
            op: Op::Constant(constant),
            input: vec![],
            output: vec![output],
        }
    }

    pub(crate) fn get_constant(&self) -> F {
        if let Op::Constant(constant) = self.op {
            constant
        } else {
            panic!("cannot get constant from non constant op")
        }
    }
}

impl<F: PrimeField> std::fmt::Debug for Node<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Op::Constant(constant) = self.op {
            let constant = if constant.is_zero() {
                "0".to_string()
            } else {
                constant.to_string()
            };
            f.debug_struct("Node")
                .field("op", &format!("Constant ({constant})"))
                .field("fan-in", &self.input)
                .field("fan-out", &self.output)
                .finish()
        } else {
            f.debug_struct("Node")
                .field("op", &self.op)
                .field("fan-in", &self.input)
                .field("fan-out", &self.output)
                .finish()
        }
    }
}

impl<F: PrimeField> std::fmt::Debug for MpcCircomAST<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== CoCircom AST ===")?;

        for (idx, n) in self.nodes.iter().enumerate() {
            writeln!(f, "{idx:0>4}: {n:?}")?;
        }
        Ok(())
    }
}
