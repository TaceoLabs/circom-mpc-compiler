//! Which gadget a compiler-side `GadgetSite` runs, and how many result slots
//! it produces. Lives in this crate (rather than `circom-mpc-compiler::ir`) because `Program`'s
//! own instruction/batch types and its on-disk format both need it, and this crate has no
//! dependency on the compiler.

/// Which gadget a `GadgetSite` runs. Resolved from the instantiated template's
/// name in the compiler's `frontend::build::handle_create_cmp_bucket`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GadgetKind {
    /// Poseidon2 permutation over a `t`-element state (`t` in `{2, 3, 4, 8, 12, 16}`).
    Poseidon2 {
        /// The state width.
        t: usize,
    },
    /// Bit decomposition of one field element into `n` bits.
    Num2Bits {
        /// The number of output bits.
        n: usize,
    },
    /// `1` iff the input is zero, plus the field-inversion helper trace.
    IsZero,
    /// Proves a 254-bit decomposition is a canonical (non-aliased) representative.
    AliasCheck,
    /// Declassifies `n` values: opens them to every MPC party in the clear if they were `Shared`,
    /// or is the identity if they were already `Public`. A genuine MPC event, not deterministic
    /// local work - see the compiler's `passes::mpc::level`'s re-keyed `GadgetResult` rule for
    /// how a `Reveal` site still charges a network level exactly when its own input was `Shared`,
    /// even though its result's *domain* is unconditionally `Public`.
    Reveal {
        /// The number of values revealed.
        n: usize,
    },
}

impl GadgetKind {
    /// How many result slots (`num_outputs + num_intermediates`) this gadget produces. Every kind
    /// has a closed form independent of its own implementation - the compiler's `Graph::verify`
    /// and `frontend/inline.rs` cross-check it against the circom-derived count from
    /// `frontend/mod.rs::compute_signal_spans`, so a trace-layout mistake is a compile-time error
    /// instead of a silently wrong witness.
    #[must_use]
    pub fn expected_results(self) -> usize {
        match self {
            // Mirrors the template structure of `circuits/libs/taceo/poseidon2.circom`:
            //   Poseidon2(t) = [out[t]][in[t]][state[(9+pr)][t]]
            //                  + ExternalMatMulT(t) + 8 x FullRound(t) + pr x PartialRound(t)
            // and result slots are every signal except the site's own `t` inputs. Kept here rather
            // than in `circom-mpc-vm::gadgets` so both crates that need it (this one, for the wire
            // format; the vm crate's gadgets, unit-tested against this for every supported width)
            // depend on it instead of on each other.
            GadgetKind::Poseidon2 { t } => {
                // `amount_partial_rounds` in poseidon2_constants.circom.
                let pr = if t <= 4 { 56 } else { 57 };
                // Acc(n) = [out][in[n]][sums[n]]
                let acc = |n: usize| 2 * n + 1;
                // ExternalMatMul2/3/4 - the fixed-width leaves.
                let emm_leaf = |t: usize| match t {
                    2 => 5,
                    3 => 7,
                    _ => 18,
                };
                // ExternalMatMulT(t) = [out[t]][in[t]] + subtree. For t >= 8 the subtree is
                // (t/4) x ExternalMatMul4 followed by 4 x Acc(t/4).
                let emmt = |t: usize| {
                    if let 2..=4 = t {
                        2 * t + emm_leaf(t)
                    } else {
                        let m = t / 4;
                        2 * t + m * 18 + 4 * acc(m)
                    }
                };
                // InternalMatMulT(t) = [out[t]][in[t]] + a nested InternalMatMul2/3 for those
                // widths, else the own `acc` intermediate plus an Acc(t) subtree.
                let immt = |t: usize| match t {
                    2 => 2 * t + 5,
                    3 => 2 * t + 7,
                    _ => (2 * t + 1) + acc(t),
                };
                // FullRound  = [out][in][RC][linear_layer][sbox] (5t) + ExternalMatMulT + Sbox(t),
                //              where Sbox(t) = [out[t]][in[t]] + t x Sbox_e(4) = 6t.
                let full = 5 * t + emmt(t) + 6 * t;
                // PartialRound = [out[t]][in[t]][RC][linear_layer][sbox] (2t+3)
                //                + Sbox_e(4) + InternalMatMulT.
                let partial = (2 * t + 3) + 4 + immt(t);
                let total = 2 * t + (9 + pr) * t + emmt(t) + 8 * full + pr * partial;
                total - t
            }
            // n output bits/values, no intermediates - both Num2Bits(n) and a `TACEO_REVEAL(n)`
            // site's own signal layout skip the site's own inputs.
            GadgetKind::Num2Bits { n } | GadgetKind::Reveal { n } => n,
            // 1 output (is_zero) + 1 intermediate (the masked-inverse helper).
            GadgetKind::IsZero => 2,
            // No outputs. AliasCheck's subtree is its CompConstant subcomponent: 254 input-signal
            // copies + 1 output = 255, + 127 `parts` + 1 `sout`, + CompConstant's child
            // Num2Bits(135) (1 input + 135 bits = 136). Cross-checked directly against
            // `circuits/libs/{aliascheck,compconstant}.circom`.
            GadgetKind::AliasCheck => 255 + 127 + 1 + 136,
        }
    }
}
