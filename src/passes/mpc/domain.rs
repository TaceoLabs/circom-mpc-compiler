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

use crate::ir::{InputList, SignalIdx};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Domain {
    Public,
    Shared,
    Local,
}

impl Domain {
    /// The lattice join `Public < Shared < Local`: the domain a linear combination of both must be
    /// treated as.
    pub(crate) fn join(self, other: Self) -> Self {
        self.max(other)
    }
}

/// Whether `sig` is one of the circuit's declared public inputs. `Op::Input`'s `SignalIdx` is
/// main's own local signal numbering (outputs first, then inputs - see `frontend/build.rs`), so an
/// index below `num_outputs` is never a genuine input read in a well-formed graph; conservatively
/// classified `Shared` rather than assumed impossible, since misclassifying a public value as
/// secret only costs a missed optimization, never a soundness bug (the reverse would be unsound).
///
/// Takes the graph's metadata by value/reference rather than `&Graph<F>` itself, so a caller
/// mid-`Graph::rewrite` (which already holds `&mut Graph<F>`) can call this from inside its rewrite
/// closure without a borrow conflict - see `mul_split`.
pub(crate) fn signal_domain(
    num_outputs: usize,
    input_list: &InputList,
    public_inputs: &[String],
    sig: SignalIdx,
) -> Domain {
    let idx = sig.index();
    if idx < num_outputs {
        return Domain::Shared;
    }
    let input_idx = idx - num_outputs;
    let is_public = input_list.iter().any(|(name, start, size)| {
        input_idx >= *start && input_idx < start + size && public_inputs.iter().any(|p| p == name)
    });
    if is_public {
        Domain::Public
    } else {
        Domain::Shared
    }
}
