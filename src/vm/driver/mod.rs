//! `VmDriver`: the pluggable backend `Machine::run` executes a `Program` against - either
//! `plain::PlainDriver` (single-party, the reference driver) or a real rep3 driver (three-party, behind
//! the `rep3` feature).

pub mod plain;
#[cfg(feature = "rep3")]
pub mod rep3;

use ark_bn254::Fr;

/// What actually executes a compiled `Program`. Linear ops (`add_ss`/`sub_sp`/...) are infallible
/// local computation - a plain field op for `PlainDriver`, a share-local op for a real MPC driver,
/// never a network round. `mul_vec` executes one scheduled multiplication stage; the
/// `*_traces` methods are the precomputation gadgets batched circuit-wide by `Machine::run`'s
/// precompute services.
pub trait VmDriver {
    /// A valid share any linear op may consume - `Fr` in `PlainDriver`, `Rep3PrimeFieldShare<Fr>` in
    /// a real rep3 driver.
    type Share: Clone + Default;

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
    fn promote(&mut self, value: Fr) -> Self::Share;

    fn add_ss(&mut self, a: &Self::Share, b: &Self::Share) -> Self::Share;
    fn sub_ss(&mut self, a: &Self::Share, b: &Self::Share) -> Self::Share;
    fn add_sp(&mut self, a: &Self::Share, b: Fr) -> Self::Share;
    fn sub_sp(&mut self, a: &Self::Share, b: Fr) -> Self::Share;
    fn sub_ps(&mut self, a: Fr, b: &Self::Share) -> Self::Share;
    fn mul_sp(&mut self, a: &Self::Share, b: Fr) -> Self::Share;

    /// Executes one complete multiplication stage in a single vectorized network call.
    fn mul_vec(&mut self, a: &[Self::Share], b: &[Self::Share]) -> eyre::Result<Vec<Self::Share>>;

    /// Reveals `shares` to every party, in one batched round.
    ///
    /// Used by an explicit `TACEO_REVEAL` service and at the *proving* boundary: co-snarks'
    /// `SharedWitness` splits into a cleartext `public_inputs` prefix and a secret-shared
    /// remainder, so producing one from this VM's uniformly-shared witness means opening exactly
    /// that prefix (see `vm::witness`).
    ///
    /// The identity for `PlainDriver`, whose `Share` is already `Fr`.
    fn open(&mut self, shares: &[Self::Share]) -> eyre::Result<Vec<Fr>>;

    /// Poseidon2 traces for a batch of sites. `states` is `sites * t` shares (one length-`t` state
    /// per site, concatenated). `result_offsets` is a CSR row pointer with one row per site; each
    /// row names the site's strictly ascending logical result slots (indices into
    /// `ir::PrecomputeKind::Poseidon2`'s result layout). Results are returned in that same
    /// site-major CSR order, so witness-dead trace values are never materialized.
    fn poseidon2_requested_traces(
        &mut self,
        t: usize,
        states: &[Self::Share],
        result_requests: &[u32],
        result_offsets: &[u32],
    ) -> eyre::Result<Vec<Self::Share>>;
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
    #[allow(clippy::type_complexity)]
    fn is_zero_reveal_traces(
        &mut self,
        inputs: &[Self::Share],
    ) -> eyre::Result<Vec<(Self::Share, Self::Share, Fr)>>;
    /// `inputs` is `sites * 254` shares; returns `sites * 519` shares - see
    /// `ir::PrecomputeKind::AliasCheck`'s doc for the exact layout.
    fn alias_check_traces(&mut self, inputs: &[Self::Share]) -> eyre::Result<Vec<Self::Share>>;
}
