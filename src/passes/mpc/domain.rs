//! Per-value MPC domain classification: `Public` (every party holds the cleartext), `Shared` (a
//! valid replicated share - any op may consume it), or `Local` (a valid additive-3 sharing only,
//! post-`Op::MulLocal`, pre-reshare). See `docs/ARCHITECTURE.md`, "MPC lowering", for why this
//! third domain is sound and what it buys: every linear op is free in all three, which is what
//! lets `mul_split` tell a genuine secret product (needs a round) apart from a free public one.
//!
//! Not a standalone [`super::super::Pass`] - `mul_split` is its only consumer, and it needs the
//! domain of each *new-space* value as it rewrites (a plain precomputed old-space array can't
//! answer that, since `EmitMany` shifts every later index - see `mul_split` for the full
//! reasoning), so this stays a small library of pure functions `mul_split` calls incrementally
//! rather than a separate pass with its own `PassContext` cache entry.

use ark_ff::PrimeField;

use crate::ir::{Graph, InputList, Op, PrecomputeKind, SignalIdx};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Domain {
    Public,
    Shared,
    Local,
}

/// Classifies every value in an already-built graph. Unlike `mul_split`'s incremental table, this
/// analysis only reads the graph, so it can be shared by codegen, batch planning, and diagnostics.
pub(crate) fn compute_domains<F: PrimeField>(graph: &Graph<F>) -> Vec<Domain> {
    let nodes = graph.nodes();
    let mut domains: Vec<Domain> = Vec::with_capacity(graph.len());
    for node in nodes {
        let domain = match &node.op {
            Op::Input(signal) => signal_domain(
                graph.num_outputs,
                &graph.input_list,
                &graph.public_inputs,
                &graph.mpc_public_inputs,
                *signal,
            ),
            Op::Constant(_) => Domain::Public,
            Op::Add | Op::Sub | Op::Mul => {
                domains[node.inputs[0].index()].join(domains[node.inputs[1].index()])
            }
            Op::MulLocal => Domain::Local,
            Op::Round(_) => Domain::Public,
            Op::RoundResult(_) => Domain::Shared,
            // A deterministic gadget is public exactly when all of its inputs are public. Keeping
            // this domain on the otherwise-unread service node lets each result inherit it.
            Op::Precompute(_) => node
                .inputs
                .iter()
                .fold(Domain::Public, |d, input| d.join(domains[input.index()])),
            // A `Reveal` site's result is unconditionally `Public` - that is its entire purpose,
            // regardless of whether its own input was `Shared` (see `PrecomputeKind::Reveal`).
            // Every other kind stays exactly what its site's domain already is.
            Op::PrecomputeResult(_) => {
                let precompute_idx = node.inputs[0].index();
                match &nodes[precompute_idx].op {
                    Op::Precompute(site_id)
                        if matches!(
                            graph.precompute_sites()[site_id.index()].kind,
                            PrecomputeKind::Reveal { .. }
                        ) =>
                    {
                        Domain::Public
                    }
                    _ => domains[precompute_idx],
                }
            }
        };
        domains.push(domain);
    }
    domains
}

impl Domain {
    /// The lattice join `Public < Shared < Local`: the domain a linear combination of both must be
    /// treated as.
    pub(crate) fn join(self, other: Self) -> Self {
        self.max(other)
    }
}

/// Whether `sig` is one of the circuit's declared public inputs, *or* one of its `mpc_public_inputs`
/// (an MPC-level declassification, distinct from and additional to circom's own SNARK-public list -
/// see `Graph::mpc_public_inputs`). `Op::Input`'s `SignalIdx` is main's own local signal numbering
/// (outputs first, then inputs - see `frontend/build.rs`), so an index below `num_outputs` is never
/// a genuine input read in a well-formed graph; conservatively classified `Shared` rather than
/// assumed impossible, since misclassifying a public value as secret only costs a missed
/// optimization, never a soundness bug (the reverse would be unsound - which is exactly why
/// `mpc_public_inputs` is a config knob populated only from `CompilerConfig`, never inferred).
///
/// Takes the graph's metadata by value/reference rather than `&Graph<F>` itself, so a caller
/// mid-`Graph::rewrite` (which already holds `&mut Graph<F>`) can call this from inside its rewrite
/// closure without a borrow conflict - see `mul_split`.
pub(crate) fn signal_domain(
    num_outputs: usize,
    input_list: &InputList,
    public_inputs: &[String],
    mpc_public_inputs: &[String],
    sig: SignalIdx,
) -> Domain {
    let idx = sig.index();
    if idx < num_outputs {
        return Domain::Shared;
    }
    let input_idx = idx - num_outputs;
    let is_public = input_list.iter().any(|(name, start, size)| {
        input_idx >= *start
            && input_idx < start + size
            && (public_inputs.iter().any(|p| p == name)
                || mpc_public_inputs.iter().any(|p| p == name))
    });
    if is_public {
        Domain::Public
    } else {
        Domain::Shared
    }
}
