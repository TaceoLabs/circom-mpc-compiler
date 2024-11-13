use core::panic;
use std::usize;

use ark_ff::PrimeField;

pub(crate) type Wire = usize;
pub(crate) type NodeId = usize;

#[derive(Debug, Clone)]
pub(crate) struct WireInformation {
    pub(crate) ty: WireType,
    pub(crate) produced_by: NodeId,
}

#[derive(Clone)]
pub(crate) struct Node<F: PrimeField> {
    op: Op<F>,
    input: Vec<Wire>,
    output: Vec<Wire>,
}

#[derive(Debug, Clone)]
pub enum Op<F: PrimeField> {
    LoadSubCmp(usize, usize),
    Load,
    StoreSubCmp(usize, usize),
    Store(usize),
    Constant(F),
    Add,
    Mul,
}

#[derive(Clone, Debug)]
enum WireType {
    Input,
    Output,
    Intermediate,
}

#[derive(Clone)]
pub(crate) struct NotInlinedCircomAST<F: PrimeField> {
    pub(crate) wires: Vec<WireInformation>,
    pub(crate) nodes: Vec<Node<F>>,
    pub(crate) sub_graphs: Vec<SubGraph<F>>,
}

pub(crate) struct SubCmpWireIndices {
    input: Wire,
    output: Wire,
}

impl SubCmpWireIndices {
    fn new(input: Wire, output: Wire) -> Self {
        Self { input, output }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SubGraph<F: PrimeField> {
    pub(crate) ast: NotInlinedCircomAST<F>,
    symbol: String,
    signal_offset: usize,
}

#[derive(Clone)]
pub(crate) struct CircomAST<F: PrimeField> {
    pub(crate) wires: Vec<WireInformation>,
    pub(crate) nodes: Vec<Node<F>>,
}

impl<F: PrimeField> SubGraph<F> {
    pub(crate) fn new(symbol: String, ast: NotInlinedCircomAST<F>, signal_offset: usize) -> Self {
        Self {
            ast,
            symbol,
            signal_offset,
        }
    }
}

impl WireInformation {
    pub(crate) fn is_output(&self) -> bool {
        matches!(self.ty, WireType::Output)
    }

    pub(crate) fn is_input(&self) -> bool {
        matches!(self.ty, WireType::Input)
    }

    pub(crate) fn input_wire() -> Self {
        Self {
            ty: WireType::Input,
            produced_by: 0, // doesn't matter
        }
    }

    pub(crate) fn output_wire() -> Self {
        Self {
            ty: WireType::Output,
            produced_by: 0, // doesn't matter
        }
    }
    pub(crate) fn new(produced_by: NodeId) -> Self {
        Self {
            ty: WireType::Intermediate,
            produced_by,
        }
    }
    pub(crate) fn inline(mut self, offset: usize) -> Self {
        match self.ty {
            WireType::Input => {
                // we are not assigned
                self.produced_by = usize::MAX; // mark it as unassigned
            }
            WireType::Output | WireType::Intermediate => {
                self.produced_by += offset;
            }
        }
        self.ty = WireType::Intermediate;
        self
    }
}

impl<F: PrimeField> Node<F> {
    pub(crate) fn inline(mut self, loc: usize, wires: usize) -> Self {
        if let Op::Store(_) = self.op {
            self.op = Op::Store(loc);
        }
        #[allow(unused_mut)]
        for mut input_wires in self.input.iter_mut() {
            *input_wires += wires;
        }

        #[allow(unused_mut)]
        for mut output_wires in self.output.iter_mut() {
            *output_wires += wires;
        }
        self
    }

    pub(crate) fn add_out_wire(&mut self, output: Wire) {
        self.output.push(output);
    }

    pub(crate) fn load(input: Wire, output: Wire) -> Self {
        Node {
            op: Op::Load,
            input: vec![input],
            output: vec![output],
        }
    }

    pub(crate) fn store(input: Wire, output: Wire) -> Self {
        Node {
            op: Op::Store(output),
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

    pub(crate) fn output_sub_cmp(sub_cmp: usize, sub_cmp_wire: Wire, output: Wire) -> Node<F> {
        Node {
            op: Op::LoadSubCmp(sub_cmp, sub_cmp_wire),
            input: vec![],
            output: vec![output],
        }
    }

    pub(crate) fn input_sub_cmp(sub_cmp: usize, sub_cmp_wire: Wire, input: Wire) -> Node<F> {
        Node {
            op: Op::StoreSubCmp(sub_cmp, sub_cmp_wire),
            input: vec![input],
            output: vec![],
        }
    }
}

impl<F: PrimeField> CircomAST<F> {
    pub(crate) fn from_main_component(mut ast: NotInlinedCircomAST<F>) -> Self {
        // my offset is one for wires and zero for nodes
        let wire_offset = 0;
        let node_offset = 0;
        for mut wire in ast.wires.iter_mut() {
            wire.produced_by += node_offset;
        }
        for mut node in ast.nodes.iter_mut() {
            for mut input in node.input.iter_mut() {
                *input += wire_offset;
            }
            //for mut output in node.output.iter_mut() {
            //    *output += wire_offset;
            //}
        }
        Self {
            wires: ast.wires,
            nodes: ast.nodes,
        }
    }

    fn inline() {}
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

impl<F: PrimeField> std::fmt::Debug for NotInlinedCircomAST<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== Circom AST ===")?;
        for (idx, v) in self.wires.iter().enumerate() {
            writeln!(f, "{idx:0>4}: {v:?}")?;
        }

        for (idx, n) in self.nodes.iter().enumerate() {
            writeln!(f, "{idx:0>4}: {n:?}")?;
        }
        if !self.sub_graphs.is_empty() {
            writeln!(f, "=== sub cmp ===")?;
            for sub_graph in self.sub_graphs.iter() {
                writeln!(f, " == {} ==", sub_graph.symbol)?;
                writeln!(f, "{sub_graph:?}")?;
                writeln!(f, "")?;
            }
        }
        Ok(())
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
