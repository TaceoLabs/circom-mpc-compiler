//! `VmDriver`: the pluggable backend `Machine::run` executes a `Program` against - either
//! `plain::PlainDriver` (single-party, the reference driver) or a real rep3 driver (three-party, behind
//! the `rep3` feature). See `docs/ARCHITECTURE.md`, "Bytecode and the slot machine".

pub mod plain;
#[cfg(feature = "rep3")]
pub mod rep3;

use ark_ff::PrimeField;

/// What actually executes a compiled `Program`. Linear ops (`add_ss`/`sub_sp`/...) are infallible
/// local computation - a plain field op for `PlainDriver`, a share-local op for a real MPC driver,
/// never a network round (see `docs/ARCHITECTURE.md`, "MPC lowering", for why every linear op is
/// free). `mul_local`/`reshare` are the two MPC-lowering primitives; the four `*_traces` methods
/// are the precomputation gadgets (see "Precomputation") batched circuit-wide by
/// `Machine::run`'s precompute phase.
pub trait VmDriver<F: PrimeField> {
    /// A valid share any linear op may consume - `F` in `PlainDriver`, `Rep3PrimeFieldShare<F>` in
    /// a real rep3 driver.
    type Share: Clone + Default;
    /// A post-`mul_local`, pre-`reshare` additive-3 sharing - `F` in every driver (even rep3: it's
    /// the `a` component of a replicated share, already a valid additive-3 sharing on its own).
    type Local: Clone + Default;

    /// Lifts a known-public value into `Share` representation - used when a `Public`-bank value
    /// ends up as a circuit output (the final witness is uniformly `Vec<Self::Share>`).
    fn promote(&mut self, value: F) -> Self::Share;

    fn add_ss(&mut self, a: &Self::Share, b: &Self::Share) -> Self::Share;
    fn sub_ss(&mut self, a: &Self::Share, b: &Self::Share) -> Self::Share;
    fn add_sp(&mut self, a: &Self::Share, b: F) -> Self::Share;
    fn sub_sp(&mut self, a: &Self::Share, b: F) -> Self::Share;
    fn sub_ps(&mut self, a: F, b: &Self::Share) -> Self::Share;
    fn mul_sp(&mut self, a: &Self::Share, b: F) -> Self::Share;

    /// The free local half of a secret x secret product (`a*b + mask`, rep3's `local_mul_vec`) -
    /// not a valid share on its own, only after `reshare`.
    fn mul_local(&mut self, a: &Self::Share, b: &Self::Share) -> Self::Local;
    /// Vector form used once per scheduled round. The default preserves compatibility for simple
    /// drivers; rep3 overrides it so mask allocation and Rayon dispatch happen once per round.
    fn mul_local_vec(&mut self, a: &[Self::Share], b: &[Self::Share]) -> Vec<Self::Local> {
        assert_eq!(a.len(), b.len(), "local product vectors must have equal length");
        a.iter()
            .zip(b)
            .map(|(a, b)| self.mul_local(a, b))
            .collect()
    }
    /// One batched network round: reshares every `Local` value together in a single message.
    fn reshare(&mut self, locals: &[Self::Local]) -> eyre::Result<Vec<Self::Share>>;

    /// Reveals `shares` to every party, in one batched round.
    ///
    /// Not used by `Machine::run` itself - witness extension never needs to reveal anything. It
    /// exists for the *proving* boundary: co-snarks' `SharedWitness` splits into a cleartext
    /// `public_inputs` prefix and a secret-shared remainder, so producing one from this VM's
    /// uniformly-shared witness means opening exactly that prefix (see `vm::witness`).
    ///
    /// The identity for `PlainDriver`, whose `Share` is already `F`.
    fn open(&mut self, shares: &[Self::Share]) -> eyre::Result<Vec<F>>;

    /// `states` is `sites * t` shares (one length-`t` state per site, concatenated, in site
    /// order); returns `sites * (t + intermediates)` shares (each site's permuted state then its
    /// trace), matching `ir::PrecomputeKind::Poseidon2`'s result layout.
    fn poseidon2_traces(&mut self, t: usize, states: &[Self::Share]) -> eyre::Result<Vec<Self::Share>>;
    /// The sparse twin of [`Self::poseidon2_traces`]: `result_requests`/`result_offsets` are
    /// `PrecomputeBatch::result_requests`/`result_offsets`' own CSR table (site-major, each row
    /// strictly ascending), and the return value is exactly that requested subset, in the same
    /// order - a caller that already has the CSR table on hand (`Machine::run_batch`) should prefer
    /// this over `poseidon2_traces` + filtering. The default implementation *is* that filtering, so
    /// a third-party `VmDriver` keeps compiling without implementing sparsity itself; the two
    /// built-in drivers override it with a genuinely sparse gadget
    /// (`vm::gadgets::poseidon2::{plain,rep3}_trace_requested`) that skips materializing the
    /// witness-dead majority of a real batch's trace, rather than computing it and throwing it away.
    fn poseidon2_requested_traces(
        &mut self,
        t: usize,
        states: &[Self::Share],
        result_requests: &[u32],
        result_offsets: &[u32],
    ) -> eyre::Result<Vec<Self::Share>> {
        let sites = result_offsets.len().saturating_sub(1);
        let full = self.poseidon2_traces(t, states)?;
        eyre::ensure!(
            sites > 0 && full.len().is_multiple_of(sites),
            "poseidon2_requested_traces: {} full-trace values is not an even multiple of {sites} sites",
            full.len()
        );
        let capacity = full.len() / sites;
        let mut selected = Vec::with_capacity(result_requests.len());
        for site in 0..sites {
            let site_full = &full[site * capacity..(site + 1) * capacity];
            let lo = result_offsets[site] as usize;
            let hi = result_offsets[site + 1] as usize;
            selected.extend(result_requests[lo..hi].iter().map(|&r| site_full[r as usize].clone()));
        }
        Ok(selected)
    }
    /// `inputs` is one share per site; returns `sites * n` shares (bit decompositions, in order).
    fn num2bits_traces(&mut self, n: usize, inputs: &[Self::Share]) -> eyre::Result<Vec<Self::Share>>;
    /// `inputs` is one share per site; returns `sites * 2` shares (`is_zero`, then the masked-
    /// inverse helper, per site).
    fn is_zero_traces(&mut self, inputs: &[Self::Share]) -> eyre::Result<Vec<Self::Share>>;
    /// The 1-round twin of [`Self::is_zero_traces`], for `ir::PrecomputeKind::IsZeroRevealed` sites
    /// - only ever chosen by `passes::mpc::declassify_zero_test`, and only when the site's `out` is
    /// revealed immediately after. Same result shape as `is_zero_traces`; see
    /// `vm::gadgets::iszero::rep3_trace_revealed` for the protocol and its leak argument.
    fn is_zero_revealed_traces(&mut self, inputs: &[Self::Share]) -> eyre::Result<Vec<Self::Share>>;
    /// `inputs` is `sites * 2` shares (`[in[0], in[1]]` per site); returns `sites * 4` - see
    /// `ir::PrecomputeKind::IsEqual`. Delegates to `is_zero_traces` on the differences, so batching
    /// stays uniform across kinds rather than being special-cased in `Machine::run`.
    fn is_equal_traces(&mut self, inputs: &[Self::Share]) -> eyre::Result<Vec<Self::Share>>;
    /// The [`Self::is_zero_revealed_traces`] twin, for `ir::PrecomputeKind::IsEqualRevealed`.
    fn is_equal_revealed_traces(&mut self, inputs: &[Self::Share]) -> eyre::Result<Vec<Self::Share>>;
    /// `inputs` is `sites * 254` shares; returns `sites * 519` shares - see
    /// `ir::PrecomputeKind::AliasCheck`'s doc for the exact layout.
    fn alias_check_traces(&mut self, inputs: &[Self::Share]) -> eyre::Result<Vec<Self::Share>>;
}
