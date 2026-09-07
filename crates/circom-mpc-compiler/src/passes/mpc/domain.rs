//! Per-value MPC domain classification: `Public` (every party holds the cleartext), `Shared` (a
//! valid replicated share - any op may consume it), or `Local` (a valid additive-3 sharing only,
//! post-`Op::MulLocal`, pre-reshare). Every linear op is free in all three domains, which is what
//! lets `mul_split` tell a genuine secret product (needs a round) apart from a free public one.
//! Shared by `mul_split`, `round_schedule`, batch planning, codegen, and diagnostics.

use crate::ir::{GadgetKind, Graph, Op, SignalIdx};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Domain {
    Public,
    Shared,
    Local,
}

/// Classifies every value in an already-built graph. Unlike `mul_split`'s incremental table, this
/// analysis only reads the graph, so it can be shared by codegen, batch planning, and diagnostics.
pub(crate) fn compute_domains(graph: &Graph) -> Vec<Domain> {
    let nodes = graph.nodes();
    let mut domains: Vec<Domain> = Vec::with_capacity(graph.len());
    for node in nodes {
        let domain = match &node.op {
            Op::Input(signal) => signal_domain(graph, *signal),
            // A round's own node is never read directly (only through its `RoundResult`s), so its
            // domain is a placeholder; `Constant` is genuinely always public.
            Op::Constant(_) | Op::Round(_) => Domain::Public,
            Op::Add | Op::Sub | Op::Mul => {
                domains[node.inputs[0].index()].join(domains[node.inputs[1].index()])
            }
            Op::MulLocal => Domain::Local,
            Op::RoundResult(_) => Domain::Shared,
            // A deterministic gadget is public exactly when all of its inputs are public. Keeping
            // this domain on the otherwise-unread service node lets each result inherit it.
            Op::Gadget(_) => node
                .inputs
                .iter()
                .fold(Domain::Public, |d, input| d.join(domains[input.index()])),
            // A `Reveal` site's result is unconditionally `Public` - that is its entire purpose,
            // regardless of whether its own input was `Shared` (see `GadgetKind::Reveal`).
            // Every other kind stays exactly what its site's domain already is.
            Op::GadgetResult(_) => {
                let gadget_idx = node.inputs[0].index();
                match &nodes[gadget_idx].op {
                    Op::Gadget(site_id)
                        if matches!(
                            graph.gadget_sites()[site_id.index()].kind,
                            GadgetKind::Reveal { .. }
                        ) =>
                    {
                        Domain::Public
                    }
                    _ => domains[gadget_idx],
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
/// (outputs first, then inputs), so an index below `num_outputs` is never a genuine input read in a
/// well-formed graph; conservatively classified `Shared` rather than assumed impossible, since
/// misclassifying a public value as secret only costs a missed optimization, never a soundness bug
/// (the reverse would be unsound - which is exactly why `mpc_public_inputs` is a config knob
/// populated only from `CompilerConfig`, never inferred).
pub(crate) fn signal_domain(graph: &Graph, sig: SignalIdx) -> Domain {
    let idx = sig.index();
    if idx < graph.num_outputs() {
        return Domain::Shared;
    }
    let input_idx = idx - graph.num_outputs();
    let is_public = graph.input_list().iter().any(|(name, start, size)| {
        input_idx >= *start
            && input_idx < start + size
            && (graph.public_inputs().iter().any(|p| p == name)
                || graph.mpc_public_inputs.iter().any(|p| p == name))
    });
    if is_public {
        Domain::Public
    } else {
        Domain::Shared
    }
}
