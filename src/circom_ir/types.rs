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

#[derive(Debug, Clone, Copy)]
pub(crate) struct WireInformation {
    pub(crate) ty: WireType,
    pub(crate) produced_by: NodeId,
}

#[derive(Clone)]
pub(crate) struct Node<F: PrimeField> {
    pub(crate) op: Op<F>,
    pub(crate) input: Vec<Wire>,
    pub(crate) output: Vec<Wire>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op<F: PrimeField> {
    LoadSubCmp(usize, usize),
    Input(usize),
    Load,
    StoreSubCmp(usize, usize),
    Output(usize),
    Constant(F),
    Add,
    Sub,
    Mul,
}

#[derive(Clone, Debug, Copy)]
pub enum WireType {
    Input,
    Output,
    Intermediate,
}

#[derive(Clone)]
pub(crate) struct NotInlinedCircomAST<F: PrimeField> {
    pub(crate) nodes: Vec<Node<F>>,
    pub(crate) sub_graphs: Vec<SubGraph<F>>,
    pub(crate) num_inputs: usize,
    pub(crate) num_outputs: usize,
    pub(crate) num_wires: usize,
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
    pub(crate) signal_offset: usize,
    symbol: String,
    num_input_outputs: usize,
}

#[derive(Clone)]
pub struct CircomAST<F: PrimeField> {
    pub(crate) nodes: Vec<Node<F>>,
    pub signal_to_witness: Vec<usize>,
    pub num_inputs: usize,
    pub num_outputs: usize,
    pub num_signals: usize,
    pub amount_wires: usize,
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
    pub(crate) fn inline(mut self, offset: NodeId) -> Self {
        self.produced_by += offset;
        self
    }

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

    pub(crate) fn load(input: Wire, output: Wire) -> Self {
        Node {
            op: Op::Load,
            input: vec![input],
            output: vec![output],
        }
    }

    pub(crate) fn store(signal: usize, input: Wire, output: Wire) -> Self {
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

    pub(crate) fn input_sub_cmp(
        sub_cmp: usize,
        sub_cmp_wire: Wire,
        input: Wire,
        output: Wire,
    ) -> Node<F> {
        Node {
            op: Op::StoreSubCmp(sub_cmp, sub_cmp_wire),
            input: vec![input],
            output: vec![output],
        }
    }
}

impl<F: PrimeField> CircomAST<F> {
    pub(crate) fn test_inline(
        nodes: &mut Vec<Node<F>>,
        wire_offset: usize,
        sub_graph: &SubGraph<F>,
        input_mapping: &IntMap<Wire>,
    ) -> (usize, IntMap<Wire>) {
        let my_wires = sub_graph.ast.num_wires;
        tracing::debug!(
            "inlining {} with wire offset {}",
            sub_graph.symbol,
            wire_offset
        );
        let signal_offset = sub_graph.signal_offset;
        let mut int_map = IntMap::new();

        for node in sub_graph.ast.nodes.iter() {
            match &node.op {
                Op::Input(input) => {
                    let mut node = node.clone();
                    node.op = Op::Output(*input);
                    let mut node = node.inline(signal_offset, wire_offset);
                    int_map.insert(
                        to_u64!(*input),
                        node.output[0] - sub_graph.num_input_outputs,
                    );
                    node.input
                        .push(*input_mapping.get(to_u64!(*input)).expect("must be there"));
                    nodes.push(node);
                }
                Op::Output(output) => {
                    let node = node.clone().inline(signal_offset, wire_offset);
                    int_map.insert(to_u64!(*output), node.output[0]);
                    nodes.push(node);
                }
                _ => {
                    let node = node.clone().inline(signal_offset, wire_offset);
                    nodes.push(node);
                }
            }
        }
        tracing::info!("{int_map:?}");
        (my_wires, int_map)
    }
    pub(crate) fn from_main_component(
        num_signals: usize,
        signal_to_witness: Vec<usize>,
        ast: NotInlinedCircomAST<F>,
    ) -> Self {
        tracing::debug!("inlining");
        // append all nodes and wires (maybe alloc the vec before hand)
        let mut nodes = Vec::with_capacity(1024);
        let sub_graphs = &ast.sub_graphs;
        let mut already_inlined = vec![];
        let mut amount_wires = 0;
        let mut outer_offset = 0;
        let mut sub_cmp_outputs = vec![];
        let mut sub_cmp_inputs = vec![];
        sub_cmp_outputs.resize(ast.sub_graphs.len(), IntMap::new());
        sub_cmp_inputs.resize(ast.sub_graphs.len(), IntMap::new());

        for node in ast.nodes.into_iter() {
            // remove sub cmp calls
            match node.op {
                Op::LoadSubCmp(sub_cmp, index) => {
                    // we want the output -> inline if not already inlined
                    if !already_inlined.contains(&sub_cmp) {
                        already_inlined.push(sub_cmp);

                        let (inner_offset, map) = Self::test_inline(
                            &mut nodes,
                            amount_wires,
                            &sub_graphs[sub_cmp],
                            &sub_cmp_inputs[sub_cmp],
                        );
                        outer_offset += inner_offset;
                        amount_wires += inner_offset;
                        sub_cmp_outputs[sub_cmp] = map;
                    }

                    amount_wires += node.output.len();
                    let mut node = node.inline(0, outer_offset);
                    node.op = Op::Load;
                    assert!(node.input.is_empty());
                    node.input.push(
                        *sub_cmp_outputs[sub_cmp]
                            .get(to_u64!(index))
                            .expect("is here"),
                    );
                    nodes.push(node);
                }
                Op::StoreSubCmp(sub_cmp, index) => {
                    let mappings = &mut sub_cmp_inputs[sub_cmp];
                    mappings.insert(to_u64!(index), node.output[0] + outer_offset);
                    amount_wires += node.output.len();
                    nodes.push(node.inline(0, outer_offset));
                }
                _ => {
                    amount_wires += node.output.len();
                    nodes.push(node.inline(0, outer_offset));
                }
            }
        }

        for (idx, n) in nodes.iter().enumerate() {
            tracing::debug!("{idx:0>4}: {n:?}")
        }
        tracing::debug!("==============");
        for node in nodes.iter_mut() {
            if let Op::StoreSubCmp(_, _) = node.op {
                node.op = Op::Load;
            }
        }

        for (idx, n) in nodes.iter().enumerate() {
            tracing::debug!("{idx:0>4}: {n:?}")
        }

        Self {
            num_signals,
            signal_to_witness,
            amount_wires,
            nodes,
            num_inputs: ast.num_inputs,
            num_outputs: ast.num_outputs,
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

impl<F: PrimeField> std::fmt::Debug for NotInlinedCircomAST<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== Circom AST ===")?;

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

        for (idx, n) in self.nodes.iter().enumerate() {
            writeln!(f, "{idx:0>4}: {n:?}")?;
        }
        Ok(())
    }
}
