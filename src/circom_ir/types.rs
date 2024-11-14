use core::panic;
use std::usize;

use ark_ff::PrimeField;
use intmap::IntMap;

pub(crate) type Wire = usize;
pub(crate) type NodeId = usize;

macro_rules! to_u64 {
    ($x: expr) => {
        u64::try_from($x).expect("fits into u64")
    };
}

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
    Sub,
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
    num_input_outputs: usize,
    signal_offset: usize,
}

#[derive(Clone)]
pub(crate) struct CircomAST<F: PrimeField> {
    pub(crate) wires: Vec<WireInformation>,
    pub(crate) nodes: Vec<Node<F>>,
}

impl<F: PrimeField> SubGraph<F> {
    pub(crate) fn new(
        symbol: String,
        num_input_outputs: usize,
        ast: NotInlinedCircomAST<F>,
        signal_offset: usize,
    ) -> Self {
        Self {
            ast,
            num_input_outputs,
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
}

impl<F: PrimeField> Node<F> {
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
        tracing::debug!("{ast:?}");
        let mut i = 0;
        // append all nodes and wires
        let mut wires = std::mem::take(&mut ast.wires);
        let mut nodes = std::mem::take(&mut ast.nodes);

        let mut io_wires_map = Vec::with_capacity(ast.sub_graphs.len());
        for sub_graph in ast.sub_graphs {
            let (inlined_wires, inlined_nodes, io_wires) =
                CircomAST::inline(sub_graph, wires.len());
            wires.extend(inlined_wires);
            nodes.extend(inlined_nodes);
            io_wires_map.push(io_wires);
        }
        for i in 0..nodes.len() {
            // remove load
            // remove sub_cmp calls
            // remove dead nodes
            if let Op::StoreSubCmp(sub_cmp, sub_cmp_wire) = &nodes[i].op {
                let test = io_wires_map[*sub_cmp][*sub_cmp_wire];
                tracing::info!("{:?} now is {}", &nodes[i], test);
            }
        }
        Self { wires, nodes }
    }

    fn inline(
        mut sub_graph: SubGraph<F>,
        wire_offset: usize,
    ) -> (Vec<WireInformation>, Vec<Node<F>>, Vec<Wire>) {
        let wires = std::mem::take(&mut sub_graph.ast.wires);
        let mut nodes = std::mem::take(&mut sub_graph.ast.nodes);
        let mut io_wires = Vec::with_capacity(sub_graph.num_input_outputs);
        for i in 0..sub_graph.num_input_outputs {
            io_wires.push(i + wire_offset);
        }
        #[allow(unused_mut)]
        for mut node in nodes.iter_mut() {
            if let Op::Store(signal) = &mut node.op {
                *signal += sub_graph.signal_offset;
            }
            #[allow(unused_mut)]
            for mut input in node.input.iter_mut() {
                *input += wire_offset;
            }

            #[allow(unused_mut)]
            for mut output in node.output.iter_mut() {
                *output += wire_offset;
            }
        }

        (wires, nodes, io_wires)
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
