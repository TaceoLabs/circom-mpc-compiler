//! The single value-graph IR shared by every stage of the compiler.
//!
//! A [`Graph`] is a flat, topologically ordered list of [`Node`]s. There is no separate "wire"
//! address space: a node's position in the graph *is* the identifier of the single value it
//! produces (its [`ValueId`]). This replaces the old model where every node additionally
//! allocated one or more `Wire` indices into a side-array, which required a whole family of
//! passes (`dead_code`, `load_elimination`, `reduce_wire_indices`) just to keep that side-array
//! dense and alias-free. See `docs/ARCHITECTURE.md` for the full rationale.

use ark_ff::PrimeField;

/// Identifies a node in a [`Graph`] and, equivalently, the single value it produces.
///
/// `ValueId(i)` always refers to `graph.nodes[i]`. There is no separate wire allocator: a value's
/// identity *is* its producer's position in the flat node list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ValueId(u32);

impl ValueId {
    pub(crate) fn new(index: usize) -> Self {
        Self(u32::try_from(index).expect("graph has more than u32::MAX nodes"))
    }

    pub(crate) fn index(self) -> usize {
        self.0 as usize
    }
}

/// A global circuit signal index (i.e. an index into circom's own flat signal numbering, after
/// any per-instance offset has already been resolved).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SignalIdx(pub(crate) u32);

impl SignalIdx {
    pub(crate) fn new(index: usize) -> Self {
        Self(u32::try_from(index).expect("signal index does not fit into u32"))
    }

    pub(crate) fn index(self) -> usize {
        self.0 as usize
    }
}

/// One operation of the value graph. Every variant produces exactly one value.
///
/// Deliberately narrow: only the linear/multiplicative core (`Add`/`Sub`/`Mul`) is a runtime op.
/// Everything else circom can express (`/`, `\`, `**`, shifts, bitwise ops, comparisons, ...) is
/// either rejected outright or, where all its operands are compile-time constants, folded away
/// before it ever reaches this enum (`frontend::fold`). See `docs/ARCHITECTURE.md` for why, and for
/// the MPC share-kind specialization this enum used to also carry (removed, see "Non-goals").
#[derive(Debug, Clone, PartialEq)]
pub enum Op<F: PrimeField> {
    /// Reads a circuit input signal.
    Input(SignalIdx),
    /// A field constant.
    Constant(F),
    Add,
    Sub,
    Mul,
}

impl<F: PrimeField> Op<F> {
    /// The number of operands this op reads from other values in the graph.
    pub(crate) fn arity(&self) -> usize {
        match self {
            Op::Input(_) | Op::Constant(_) => 0,
            Op::Add | Op::Sub | Op::Mul => 2,
        }
    }
}

/// A single node in the graph. `inputs` references other nodes by [`ValueId`]; every reference
/// must point strictly earlier in the graph (enforced by [`Graph::verify`]).
#[derive(Debug, Clone)]
pub struct Node<F: PrimeField> {
    pub op: Op<F>,
    pub inputs: Vec<ValueId>,
}

impl<F: PrimeField> Node<F> {
    pub(crate) fn new(op: Op<F>, inputs: Vec<ValueId>) -> Self {
        debug_assert_eq!(
            inputs.len(),
            op.arity(),
            "node input count does not match op arity"
        );
        Self { op, inputs }
    }
}

/// A list of circuit inputs: (name, witness offset, size).
pub type InputList = Vec<(String, usize, usize)>;

/// The compiled, flattened circuit: one value graph plus the metadata needed to feed it inputs
/// and read back a witness.
#[derive(Clone)]
pub struct Graph<F: PrimeField> {
    nodes: Vec<Node<F>>,
    /// Circuit-level sinks: which signal each output value is written to. Every subcomponent's
    /// input and output signal is also recorded here (not just main's declared outputs), because
    /// circom's witness vector addresses every signal in the circuit, not only main's I/O.
    outputs: Vec<(SignalIdx, ValueId)>,
    pub signal_to_witness: Vec<usize>,
    pub input_list: InputList,
    pub public_inputs: Vec<String>,
    pub num_inputs: usize,
    pub num_outputs: usize,
    pub num_signals: usize,
}

impl<F: PrimeField> Graph<F> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts(
        nodes: Vec<Node<F>>,
        outputs: Vec<(SignalIdx, ValueId)>,
        signal_to_witness: Vec<usize>,
        input_list: InputList,
        public_inputs: Vec<String>,
        num_inputs: usize,
        num_outputs: usize,
        num_signals: usize,
    ) -> Self {
        Self {
            nodes,
            outputs,
            signal_to_witness,
            input_list,
            public_inputs,
            num_inputs,
            num_outputs,
            num_signals,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.nodes.len()
    }

    // Only exercised by tests so far; kept as the standard single-node accessor for the passes
    // and codegen that land in later steps.
    #[allow(dead_code)]
    pub(crate) fn node(&self, id: ValueId) -> &Node<F> {
        &self.nodes[id.index()]
    }

    pub(crate) fn nodes(&self) -> &[Node<F>] {
        &self.nodes
    }

    pub(crate) fn outputs(&self) -> &[(SignalIdx, ValueId)] {
        &self.outputs
    }

    /// Marks every node reachable from `outputs`, drops the rest, and compacts `ValueId`s so the
    /// graph is dense again. Returns the old-to-new id mapping (`None` for dropped nodes).
    ///
    /// This one function replaces the old `dead_code_elimination` + `reduce_wire_indices` passes:
    /// those existed only to clean up after a sparse wire-index space, which the value-graph
    /// model does not have in the first place.
    pub(crate) fn gc(&mut self) -> Vec<Option<ValueId>> {
        let mut keep = vec![false; self.nodes.len()];
        for &(_, root) in &self.outputs {
            keep[root.index()] = true;
        }
        // single reverse sweep: since inputs only ever point strictly earlier, marking in
        // reverse order sees every use of a node before deciding whether to keep it.
        for i in (0..self.nodes.len()).rev() {
            if keep[i] {
                for input in &self.nodes[i].inputs {
                    keep[input.index()] = true;
                }
            }
        }

        let mut remap = vec![None; self.nodes.len()];
        let mut new_nodes = Vec::with_capacity(self.nodes.len());
        for (i, node) in self.nodes.iter().enumerate() {
            if keep[i] {
                remap[i] = Some(ValueId::new(new_nodes.len()));
                new_nodes.push(node.clone());
            }
        }
        for node in new_nodes.iter_mut() {
            for input in node.inputs.iter_mut() {
                *input = remap[input.index()].expect("gc kept a node whose input was dropped");
            }
        }
        for (_, value) in self.outputs.iter_mut() {
            *value = remap[value.index()].expect("gc dropped a node an output depends on");
        }

        tracing::debug!(
            "gc: {} nodes -> {} nodes ({} removed)",
            self.nodes.len(),
            new_nodes.len(),
            self.nodes.len() - new_nodes.len()
        );
        self.nodes = new_nodes;
        remap
    }

    /// Checks the graph's structural invariants:
    /// - every node's inputs reference strictly earlier nodes (topological order),
    /// - every node has exactly as many inputs as its op's arity,
    /// - every output references a node that exists.
    ///
    /// Called once after the frontend builds the graph and, in debug builds, between every pass.
    pub(crate) fn verify(&self) -> eyre::Result<()> {
        for (i, node) in self.nodes.iter().enumerate() {
            if node.inputs.len() != node.op.arity() {
                eyre::bail!(
                    "node {i} ({:?}) has {} inputs, expected {}",
                    node.op,
                    node.inputs.len(),
                    node.op.arity()
                );
            }
            for input in &node.inputs {
                if input.index() >= i {
                    eyre::bail!(
                        "node {i} ({:?}) references value {} which is not defined earlier",
                        node.op,
                        input.index()
                    );
                }
            }
        }
        for (signal, value) in &self.outputs {
            if value.index() >= self.nodes.len() {
                eyre::bail!(
                    "output signal {} references non-existent value {}",
                    signal.index(),
                    value.index()
                );
            }
        }
        Ok(())
    }
}

impl<F: PrimeField> std::fmt::Debug for Graph<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== graph ({} nodes) ===", self.nodes.len())?;
        for (idx, node) in self.nodes.iter().enumerate() {
            writeln!(f, "{idx:0>4}: {node:?}")?;
        }
        writeln!(f, "=== outputs ===")?;
        for (signal, value) in &self.outputs {
            writeln!(f, "signal {} <- value {}", signal.index(), value.index())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;

    // x0 = Input(0); x1 = Constant(2); x2 = Add(x0, x1); x3 = Mul(x0, x1) [dead: no output uses it]
    // output signal 0 <- x2
    fn sample_graph() -> Graph<Fr> {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(0)), vec![]),
            Node::new(Op::Constant(Fr::from(2u64)), vec![]),
            Node::new(Op::Add, vec![ValueId::new(0), ValueId::new(1)]),
            Node::new(Op::Mul, vec![ValueId::new(0), ValueId::new(1)]),
        ];
        let outputs = vec![(SignalIdx::new(0), ValueId::new(2))];
        Graph::from_parts(nodes, outputs, vec![0, 1], vec![], vec![], 1, 1, 2)
    }

    #[test]
    fn verify_accepts_well_formed_graph() {
        assert!(sample_graph().verify().is_ok());
    }

    #[test]
    fn verify_rejects_forward_reference() {
        let nodes = vec![
            Node::new(Op::Add, vec![ValueId::new(1), ValueId::new(0)]),
            Node::new(Op::Constant(Fr::from(1u64)), vec![]),
        ];
        let outputs = vec![(SignalIdx::new(0), ValueId::new(0))];
        let graph: Graph<Fr> = Graph::from_parts(nodes, outputs, vec![], vec![], vec![], 0, 1, 1);
        assert!(graph.verify().is_err());
    }

    #[test]
    fn verify_rejects_arity_mismatch() {
        let nodes = vec![Node::new(Op::Constant(Fr::from(1u64)), vec![])];
        // hand-build a node bypassing Node::new's debug_assert, to exercise the arity check
        let bad = Node {
            op: Op::Add,
            inputs: vec![ValueId::new(0)],
        };
        let mut nodes = nodes;
        nodes.push(bad);
        let outputs = vec![(SignalIdx::new(0), ValueId::new(1))];
        let graph: Graph<Fr> = Graph::from_parts(nodes, outputs, vec![], vec![], vec![], 0, 1, 1);
        assert!(graph.verify().is_err());
    }

    #[test]
    fn gc_drops_unreachable_nodes_and_compacts_ids() {
        let mut graph = sample_graph();
        assert_eq!(graph.len(), 4);
        let remap = graph.gc();
        // the Mul node (index 3) is unreachable from the single output and must be dropped
        assert_eq!(graph.len(), 3);
        assert_eq!(remap[3], None);
        assert!(remap[0].is_some());
        assert!(remap[1].is_some());
        assert!(remap[2].is_some());
        // the output must still resolve to a valid, in-range node after compaction
        let (_, out_value) = graph.outputs()[0];
        assert!(out_value.index() < graph.len());
        assert!(matches!(graph.node(out_value).op, Op::Add));
        assert!(graph.verify().is_ok());
    }
}
