//! Plaintext reference evaluator over [`ir::Graph`], used for debugging and as the oracle for the
//! plain-path KAT tests until the bytecode VM (a later step) takes over that role.
//!
//! `CoCircomCompiler::parse` always returns an MPC-lowered graph (see `docs/ARCHITECTURE.md`, "MPC
//! lowering") - there is no plaintext-only end state - so this also simulates the lowered ops
//! (`Op::MulLocal`/`Op::Round`/`Op::RoundResult`) in the clear. That makes every KAT that runs
//! through this interpreter a correctness test for the lowering, not just for the frontend.

use ark_ff::PrimeField;

use crate::ir::{self, Op, PrecomputeId, PrecomputeSite};

/// Supplies results for `Op::Precompute` sites during interpretation - the plaintext-evaluator
/// counterpart of the co-snarks VM's externally-supplied `ComponentAcceleratorOutput` traces (see
/// `docs/ARCHITECTURE.md`, "Precomputation"). `call` must return exactly
/// `site.num_outputs + site.num_intermediates` values, in slot order.
pub trait PrecomputeProvider<F: PrimeField> {
    fn call(&mut self, id: PrecomputeId, site: &PrecomputeSite, inputs: &[F]) -> eyre::Result<Vec<F>>;
}

/// The default provider: any graph with a precomputation site is a hard error, naming the first
/// site encountered, rather than silently running with zeros.
pub struct NoPrecomputation;

impl<F: PrimeField> PrecomputeProvider<F> for NoPrecomputation {
    fn call(&mut self, id: PrecomputeId, site: &PrecomputeSite, _inputs: &[F]) -> eyre::Result<Vec<F>> {
        eyre::bail!(
            "graph has precomputation site {} ({}) but no PrecomputeProvider was given",
            id.index(),
            site.name
        )
    }
}

pub struct Interpreter<F: PrimeField> {
    graph: ir::Graph<F>,
    signals: Vec<F>,
    values: Vec<F>,
}

impl<F: PrimeField> Interpreter<F> {
    pub fn new(graph: ir::Graph<F>, input_signals: Vec<F>) -> Self {
        let mut signals = vec![F::zero(); graph.num_signals];
        signals[0] = F::one();
        signals[1 + graph.num_outputs..1 + graph.num_outputs + graph.num_inputs]
            .clone_from_slice(&input_signals);
        let values = vec![F::zero(); graph.len()];
        Self {
            graph,
            signals,
            values,
        }
    }

    fn output_mapping(&self) -> Vec<F> {
        self.graph
            .signal_to_witness
            .iter()
            .map(|&idx| self.signals[idx])
            .collect()
    }

    /// Runs with the default [`NoPrecomputation`] provider - errors if the graph has any
    /// precomputation site. Most callers (the plain KAT tests) want this; use [`Self::run_with`]
    /// for graphs that have `TACEO_PRECOMPUTATION_*` sites.
    pub fn run(&mut self) -> Vec<F> {
        self.run_with(&mut NoPrecomputation)
            .expect("graph has no precomputation sites")
    }

    pub fn run_with(&mut self, provider: &mut impl PrecomputeProvider<F>) -> eyre::Result<Vec<F>> {
        // Cached per-site results, indexed by PrecomputeId, populated the first time any of a
        // site's PrecomputeResult nodes is evaluated (a Precompute node's own "value" is never
        // read directly - only via its result slots).
        let mut site_results: Vec<Option<Vec<F>>> = vec![None; self.graph.precompute_sites().len()];

        for (id, node) in self.graph.nodes().iter().enumerate() {
            tracing::trace!("node {id} = {node:?}");
            let value = match &node.op {
                Op::Input(signal) => self.signals[signal.index() + 1],
                Op::Constant(c) => *c,
                Op::Add => {
                    self.values[node.inputs[0].index()] + self.values[node.inputs[1].index()]
                }
                Op::Sub => {
                    self.values[node.inputs[0].index()] - self.values[node.inputs[1].index()]
                }
                Op::Mul => {
                    let lhs = self.values[node.inputs[0].index()];
                    let rhs = self.values[node.inputs[1].index()];
                    tracing::trace!("{lhs}*{rhs} = {}", lhs * rhs);
                    lhs * rhs
                }
                Op::MulLocal => {
                    self.values[node.inputs[0].index()] * self.values[node.inputs[1].index()]
                }
                // A Round's own value is never read (only RoundResult nodes reference it, and
                // they index its inputs directly) - park a placeholder, same as Precompute below.
                // There is no reshare to simulate in the clear: a Round's k-th input *is* its
                // k-th result, since a rep3 replicated share's local `a` component already sums
                // to the right value across three additive shares (see docs/ARCHITECTURE.md, "MPC
                // lowering") - nothing distinguishes "local" from "shared" in a single-party
                // plaintext evaluator.
                Op::Round(_) => F::zero(),
                Op::RoundResult(slot) => {
                    let round_node = &self.graph.nodes()[node.inputs[0].index()];
                    self.values[round_node.inputs[*slot as usize].index()]
                }
                // The Precompute node's own value is never read (only PrecomputeResult nodes
                // reference it, and they index site_results directly) - park a placeholder.
                Op::Precompute(_) => F::zero(),
                Op::PrecomputeResult(slot) => {
                    let Op::Precompute(site_id) = &self.graph.nodes()[node.inputs[0].index()].op
                    else {
                        unreachable!("verify() guarantees PrecomputeResult's input is Precompute");
                    };
                    if site_results[site_id.index()].is_none() {
                        let site = &self.graph.precompute_sites()[site_id.index()];
                        // The Precompute node's own inputs are the site's actual inputs - look
                        // them up via the Precompute node, not this PrecomputeResult node (whose
                        // sole input is the Precompute node itself).
                        let precompute_node = &self.graph.nodes()[node.inputs[0].index()];
                        let inputs: Vec<F> = precompute_node
                            .inputs
                            .iter()
                            .map(|v| self.values[v.index()])
                            .collect();
                        let results = provider.call(*site_id, site, &inputs)?;
                        eyre::ensure!(
                            results.len() == site.num_outputs + site.num_intermediates,
                            "precompute site {} ({}) returned {} results, expected {}",
                            site_id.index(),
                            site.name,
                            results.len(),
                            site.num_outputs + site.num_intermediates
                        );
                        site_results[site_id.index()] = Some(results);
                    }
                    site_results[site_id.index()].as_ref().unwrap()[*slot as usize]
                }
            };
            self.values[id] = value;
        }
        for &(signal, value) in self.graph.outputs() {
            self.signals[signal.index() + 1] = self.values[value.index()];
        }
        Ok(self.output_mapping())
    }
}
