use core::panic;

use ark_ff::PrimeField;

pub(crate) type Wire = usize;
pub(crate) type NodeId = usize;

#[derive(Debug)]
pub(crate) struct WireInformation {
    pub(crate) public: bool,
    pub(crate) ty: WireType,
    pub(crate) produced_by: NodeId,
}

pub(crate) struct Node<F: PrimeField> {
    op: Op<F>,
    input: Vec<Wire>,
    output: Vec<Wire>,
}

#[derive(Debug)]
pub enum Op<F: PrimeField> {
    Load,
    Store,
    Constant(F),
    Add,
    Mul,
}

#[derive(Debug)]
enum WireType {
    Input,
    Output,
    Intermediate,
    R1CS,
}

pub(crate) struct CircomAST<F: PrimeField> {
    pub(crate) wires: Vec<WireInformation>,
    pub(crate) nodes: Vec<Node<F>>,
}

impl WireInformation {
    pub(crate) fn r1cs_wire() -> Self {
        Self {
            public: true,
            ty: WireType::R1CS,
            produced_by: 0, // doesn't matter
        }
    }

    pub(crate) fn input_wire(public: bool) -> Self {
        Self {
            public,
            ty: WireType::Input,
            produced_by: 0, // doesn't matter
        }
    }

    pub(crate) fn output_wire() -> Self {
        Self {
            public: true,
            ty: WireType::Output,
            produced_by: 0, // doesn't matter
        }
    }
    pub(crate) fn new(public: bool, produced_by: NodeId) -> Self {
        Self {
            public,
            ty: WireType::Intermediate,
            produced_by,
        }
    }
}

impl<F: PrimeField> Node<F> {
    pub(crate) fn load(input: Wire, output: Wire) -> Self {
        Node {
            op: Op::Load,
            input: vec![input],
            output: vec![output],
        }
    }

    pub(crate) fn store(input: Wire) -> Self {
        Node {
            op: Op::Store,
            input: vec![input],
            output: vec![],
        }
    }

    pub(crate) fn bin_op(op: Op<F>, lhs: Wire, rhs: Wire, output: Wire) -> Self {
        Self {
            op,
            input: vec![lhs, rhs],
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

impl<F: PrimeField> std::fmt::Debug for CircomAST<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== Circom AST ===")?;
        for (idx, v) in self.wires.iter().enumerate() {
            writeln!(f, "{idx:0>4}: {v:?}")?;
        }

        for (idx, n) in self.nodes.iter().enumerate() {
            writeln!(f, "{idx:0>4}: {n:?}")?;
        }
        Ok(())
    }
}
