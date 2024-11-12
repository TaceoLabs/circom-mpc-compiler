pub(crate) type Wire = usize;
pub(crate) type NodeId = usize;

#[derive(Debug)]
pub(crate) struct WireInformation {
    pub(crate) public: bool,
    pub(crate) ty: WireType,
    pub(crate) produced_by: NodeId,
}

#[derive(Debug)]
pub(crate) struct Node {
    op: Op,
    input: Vec<Wire>,
    output: Vec<Wire>,
}

#[derive(Debug)]
pub enum Op {
    Load,
    Store,
    Mul,
}

#[derive(Debug)]
enum WireType {
    Input,
    Output,
    Intermediate,
    R1CS,
}

struct CircomIr {}

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

impl Node {
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

    pub(crate) fn bin_op(op: Op, lhs: Wire, rhs: Wire, output: Wire) -> Self {
        Self {
            op,
            input: vec![lhs, rhs],
            output: vec![output],
        }
    }
}
