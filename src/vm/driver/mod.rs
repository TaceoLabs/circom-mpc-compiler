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
/// `Machine::run`'s precompute services.
pub trait VmDriver<F: PrimeField> {
    /// A valid share any linear op may consume - `F` in `PlainDriver`, `Rep3PrimeFieldShare<F>` in
    /// a real rep3 driver.
    type Share: Clone + Default;
    /// A post-`mul_local`, pre-`reshare` additive-3 sharing - `F` in every driver (even rep3: it's
    /// the `a` component of a replicated share, already a valid additive-3 sharing on its own).
    type Local: Clone + Default;

    /// Marks the start of one [`crate::vm::Machine::run`] attempt. The default is a no-op so plain
    /// and third-party compatibility drivers remain reusable. Stateful drivers can make a prepared
    /// instance one-shot; `Machine` calls this before even validating the program or inputs, so an
    /// execution error still spends a successfully-started run.
    fn begin_run(&mut self) -> eyre::Result<()> {
        Ok(())
    }

    /// Finishes a run after success or error, and during stack unwinding after a panic. Stateful
    /// drivers should transition to their terminal state before performing fallible consistency
    /// checks. The default is a no-op.
    fn finish_run(&mut self) -> eyre::Result<()> {
        Ok(())
    }

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
        assert_eq!(
            a.len(),
            b.len(),
            "local product vectors must have equal length"
        );
        a.iter().zip(b).map(|(a, b)| self.mul_local(a, b)).collect()
    }
    /// One batched network round: reshares every `Local` value together in a single message.
    fn reshare(&mut self, locals: &[Self::Local]) -> eyre::Result<Vec<Self::Share>>;

    /// Reveals `shares` to every party, in one batched round.
    ///
    /// Used by an explicit `TACEO_REVEAL` service and at the *proving* boundary: co-snarks'
    /// `SharedWitness` splits into a cleartext `public_inputs` prefix and a secret-shared
    /// remainder, so producing one from this VM's uniformly-shared witness means opening exactly
    /// that prefix (see `vm::witness`).
    ///
    /// The identity for `PlainDriver`, whose `Share` is already `F`.
    fn open(&mut self, shares: &[Self::Share]) -> eyre::Result<Vec<F>>;

    /// `states` is `sites * t` shares (one length-`t` state per site, concatenated, in site
    /// order); returns `sites * (t + intermediates)` shares (each site's permuted state then its
    /// trace), matching `ir::PrecomputeKind::Poseidon2`'s result layout.
    fn poseidon2_traces(
        &mut self,
        t: usize,
        states: &[Self::Share],
    ) -> eyre::Result<Vec<Self::Share>>;
    /// Request-aware Poseidon2 twin. `result_offsets` is a CSR row pointer with one row per site;
    /// each row names the site's strictly ascending logical result slots. Results are returned in
    /// that same site-major CSR order.
    ///
    /// The default keeps third-party drivers source-compatible by filtering their full trace.
    /// Built-in drivers override it to avoid materializing witness-dead trace values.
    fn poseidon2_requested_traces(
        &mut self,
        t: usize,
        states: &[Self::Share],
        result_requests: &[u32],
        result_offsets: &[u32],
    ) -> eyre::Result<Vec<Self::Share>> {
        eyre::ensure!(
            t != 0 && !states.is_empty() && states.len().is_multiple_of(t),
            "Poseidon2 requested trace input must contain a non-zero whole number of sites"
        );
        let sites = states.len() / t;
        eyre::ensure!(
            result_offsets.len() == sites + 1,
            "Poseidon2 request offsets has length {}, expected {}",
            result_offsets.len(),
            sites + 1
        );
        eyre::ensure!(
            result_offsets[0] == 0 && result_offsets[sites] as usize == result_requests.len(),
            "Poseidon2 request offsets do not span the request table"
        );

        let full = self.poseidon2_traces(t, states)?;
        eyre::ensure!(
            full.len().is_multiple_of(sites),
            "Poseidon2 full trace has {} values for {sites} sites",
            full.len()
        );
        let capacity = full.len() / sites;
        let mut selected = Vec::with_capacity(result_requests.len());
        for site in 0..sites {
            let lo = result_offsets[site] as usize;
            let hi = result_offsets[site + 1] as usize;
            eyre::ensure!(
                lo <= hi && hi <= result_requests.len(),
                "Poseidon2 site {site} has invalid request range {lo}..{hi}"
            );
            let requests = &result_requests[lo..hi];
            for pair in requests.windows(2) {
                eyre::ensure!(
                    pair[0] < pair[1],
                    "Poseidon2 site {site} requests must be strictly ascending"
                );
            }
            let site_full = &full[site * capacity..(site + 1) * capacity];
            for &logical in requests {
                let logical = logical as usize;
                eyre::ensure!(
                    logical < capacity,
                    "Poseidon2 site {site} requested slot {logical}, capacity is {capacity}"
                );
                selected.push(site_full[logical].clone());
            }
        }
        Ok(selected)
    }
    /// `inputs` is one share per site; returns `sites * n` shares (bit decompositions, in order).
    fn num2bits_traces(
        &mut self,
        n: usize,
        inputs: &[Self::Share],
    ) -> eyre::Result<Vec<Self::Share>>;
    /// `inputs` is one share per site; returns `sites * 2` shares (`is_zero`, then the masked-
    /// inverse helper, per site).
    fn is_zero_traces(&mut self, inputs: &[Self::Share]) -> eyre::Result<Vec<Self::Share>>;
    /// Fused trace for an explicitly revealed IsZero result. Each site returns
    /// `(is_zero_share, inverse_share, revealed_is_zero)`. Rep3 implements this with one fresh
    /// arithmetic mask per site and one vector multiplication-open.
    fn is_zero_reveal_traces(
        &mut self,
        inputs: &[Self::Share],
    ) -> eyre::Result<Vec<(Self::Share, Self::Share, F)>> {
        let traces = self.is_zero_traces(inputs)?;
        eyre::ensure!(
            traces.len() == inputs.len() * 2,
            "is_zero_traces returned {} values for {} inputs",
            traces.len(),
            inputs.len()
        );
        let is_zero: Vec<_> = traces.chunks_exact(2).map(|site| site[0].clone()).collect();
        let revealed = self.open(&is_zero)?;
        eyre::ensure!(
            revealed.len() == inputs.len(),
            "open returned {} values for {} IsZero sites",
            revealed.len(),
            inputs.len()
        );
        Ok(traces
            .chunks_exact(2)
            .zip(revealed)
            .map(|(site, opened)| (site[0].clone(), site[1].clone(), opened))
            .collect())
    }
    /// `inputs` is `sites * 2` shares (`[in[0], in[1]]` per site); returns `sites * 4` - see
    /// `ir::PrecomputeKind::IsEqual`. Delegates to `is_zero_traces` on the differences, so batching
    /// stays uniform across kinds rather than being special-cased in `Machine::run`.
    fn is_equal_traces(&mut self, inputs: &[Self::Share]) -> eyre::Result<Vec<Self::Share>>;
    /// `inputs` is `sites * 254` shares; returns `sites * 519` shares - see
    /// `ir::PrecomputeKind::AliasCheck`'s doc for the exact layout.
    fn alias_check_traces(&mut self, inputs: &[Self::Share]) -> eyre::Result<Vec<Self::Share>>;
}
