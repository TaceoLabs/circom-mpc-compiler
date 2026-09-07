//! `VmDriver`: the pluggable backend `Vm::run` executes a `Program` against - either
//! `plain::PlainDriver` (single-party, the reference driver) or a real three-party rep3 driver.

pub mod plain;
pub mod rep3;

use ark_bn254::Fr;

/// One fused `IsZero` trace together with its explicitly revealed result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsZeroRevealTrace<S> {
    /// Secret-shared `1` when the input is zero, otherwise secret-shared `0`.
    pub is_zero: S,
    /// Secret-shared inverse helper used by the `IsZero` constraint.
    pub inverse: S,
    /// Publicly revealed value of `is_zero`.
    pub revealed: Fr,
}

/// What actually executes a compiled `Program`. Linear ops (`add_ss`/`sub_sp`/...) are infallible
/// local computation - a plain field op for `PlainDriver`, a share-local op for a real MPC driver,
/// never a network round. `mul_vec` executes one scheduled multiplication stage; the
/// `*_traces` methods are the precomputation gadgets batched circuit-wide by `Vm::run`'s
/// precompute services.
pub trait VmDriver {
    /// A valid share any linear op may consume - `Fr` in `PlainDriver`, `Rep3PrimeFieldShare<Fr>` in
    /// a real rep3 driver.
    type Share: Clone + Default;

    /// Runs once, on the success path, at the end of [`crate::Vm::run`] - a one-shot driver (e.g.
    /// rep3, whose Poseidon2 mask pool must never be reused) performs its fallible consistency
    /// checks here. The default is a no-op. Never called on an execution error or a panic: `Vm` is
    /// simply dropped, taking any one-shot state with it.
    ///
    /// # Errors
    ///
    /// Returns an error if the driver's post-run consistency checks fail.
    fn finish(&mut self) -> eyre::Result<()> {
        Ok(())
    }

    /// Lifts a known-public value into `Share` representation - used when a `Public`-bank value
    /// ends up as a circuit output (the final witness is uniformly `Vec<Self::Share>`).
    fn promote(&mut self, value: Fr) -> Self::Share;

    /// `a + b`, both `Shared`.
    fn add_ss(&mut self, a: &Self::Share, b: &Self::Share) -> Self::Share;
    /// `a - b`, both `Shared`.
    fn sub_ss(&mut self, a: &Self::Share, b: &Self::Share) -> Self::Share;
    /// `a + b`, `a` `Shared`, `b` `Public`.
    fn add_sp(&mut self, a: &Self::Share, b: Fr) -> Self::Share;
    /// `a - b`, `a` `Shared`, `b` `Public`.
    fn sub_sp(&mut self, a: &Self::Share, b: Fr) -> Self::Share;
    /// `a - b`, `a` `Public`, `b` `Shared`.
    fn sub_ps(&mut self, a: Fr, b: &Self::Share) -> Self::Share;
    /// `a * b`, `a` `Shared`, `b` `Public`.
    fn mul_sp(&mut self, a: &Self::Share, b: Fr) -> Self::Share;

    /// Executes one complete multiplication stage in a single vectorized network call.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying network round fails.
    fn mul_vec(&mut self, a: &[Self::Share], b: &[Self::Share]) -> eyre::Result<Vec<Self::Share>>;

    /// Reveals `shares` to every party, in one batched round.
    ///
    /// Used by an explicit `TACEO_REVEAL` service and, internally, by `Vm::run`'s own closing
    /// split of the witness into co-snarks' `SharedWitness` shape - a cleartext `public_inputs`
    /// prefix and a secret-shared remainder (see [`crate::Witness`]).
    ///
    /// The identity for `PlainDriver`, whose `Share` is already `Fr`.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying network round fails.
    fn open(&mut self, shares: &[Self::Share]) -> eyre::Result<Vec<Fr>>;

    /// Poseidon2 traces for a batch of sites. `states` is `sites * t` shares (one length-`t` state
    /// per site, concatenated). `result_offsets` is a CSR row pointer with one row per site; each
    /// row names the site's strictly ascending logical result slots (indices into
    /// `ir::GadgetKind::Poseidon2`'s result layout). Results are returned in that same
    /// site-major CSR order, so witness-dead trace values are never materialized.
    ///
    /// # Errors
    ///
    /// Returns an error if `t` is unsupported, the inputs are malformed, or the underlying
    /// computation/network round fails.
    fn poseidon2_requested_traces(
        &mut self,
        t: usize,
        states: &[Self::Share],
        result_requests: &[u32],
        result_offsets: &[u32],
    ) -> eyre::Result<Vec<Self::Share>>;
    /// `inputs` is one share per site; returns `sites * n` shares (bit decompositions, in order).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying computation/network round fails.
    fn num2bits_traces(
        &mut self,
        n: usize,
        inputs: &[Self::Share],
    ) -> eyre::Result<Vec<Self::Share>>;
    /// `inputs` is one share per site; returns `sites * 2` shares (`is_zero`, then the masked-
    /// inverse helper, per site).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying computation/network round fails.
    fn is_zero_traces(&mut self, inputs: &[Self::Share]) -> eyre::Result<Vec<Self::Share>>;
    /// Fused trace for an explicitly revealed `IsZero` result. Each site returns
    /// `(is_zero_share, inverse_share, revealed_is_zero)`. Rep3 implements this with one fresh
    /// arithmetic mask per site and one vector multiplication-open.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying computation/network round fails.
    fn is_zero_reveal_traces(
        &mut self,
        inputs: &[Self::Share],
    ) -> eyre::Result<Vec<IsZeroRevealTrace<Self::Share>>>;
    /// `inputs` is `sites * 254` shares; returns `sites * 519` shares - see
    /// `ir::GadgetKind::AliasCheck`'s doc for the exact layout.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying computation/network round fails.
    fn alias_check_traces(&mut self, inputs: &[Self::Share]) -> eyre::Result<Vec<Self::Share>>;
}
