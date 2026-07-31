//! Real three-party rep3 execution over `mpc_net`/`mpc_core`. `Share = Rep3PrimeFieldShare<F>`;
//! `Local = F` - the `a` component of a replicated share is already a valid additive-3 sharing on
//! its own (see `docs/ARCHITECTURE.md`, "MPC lowering"), so there's nothing to wrap. Behind the
//! `rep3` feature.

use ark_ff::PrimeField;
use mpc_core::MpcState;
use mpc_core::protocols::rep3::{self, Rep3PrimeFieldShare, Rep3State};
use mpc_net::Network;

use crate::vm::gadgets;
use crate::vm::gadgets::poseidon2::SboxPool;

use super::VmDriver;

/// Borrows the party's network connection and rep3 state rather than owning them, so a caller can
/// reuse the same connection/rep3 state across several `Machine::run` calls (e.g. one per merces
/// protocol operation) without re-running the PRF setup (`Rep3State::new`) each time. This does
/// *not* extend to the `SboxPool` behind [`Self::preprocess`]: it's sized for exactly one
/// `Machine::run` and its consumption cursor never rewinds, so a caller reusing this driver across
/// runs must call `preprocess` again before each one - see [`Self::preprocess`].
/// Generic over `F` (unlike every other MPC-only type in this crate) purely to hold the one piece
/// of per-run state that outlives a single `poseidon2_traces` call - see [`Self::preprocess`].
pub struct Rep3Driver<'a, F: PrimeField, N: Network> {
    pub net: &'a N,
    pub state: &'a mut Rep3State,
    /// Filled by [`Self::preprocess`]; `None` until then, and `poseidon2_traces` errors rather than
    /// panicking if a `Shared` Poseidon2 batch runs before it's called.
    sbox_pool: Option<SboxPool<F>>,
}

impl<'a, F: PrimeField, N: Network> Rep3Driver<'a, F, N> {
    pub fn new(net: &'a N, state: &'a mut Rep3State) -> Self {
        Self {
            net,
            state,
            sbox_pool: None,
        }
    }

    /// Spends one `Machine::run`'s entire Poseidon2 s-box correlated-randomness budget
    /// (`Program::sbox_randomness`) up front, in 3 network rounds - the offline half of the
    /// masked-open s-box trick (see `vm::gadgets::poseidon2::SboxPool`), hoisted out of
    /// `Machine::run`'s critical path entirely: call this before binding any circuit input, not
    /// merely before `Machine::run`. A no-op when `budget == 0` (no genuinely `Shared` Poseidon2
    /// site in this program) - no rounds spent, no pool allocated.
    ///
    /// The resulting pool is good for exactly one `Machine::run`: `SboxPool::consumed` never
    /// rewinds, so a caller reusing this driver across several runs must call `preprocess` again
    /// before each one, not just once up front.
    pub fn preprocess(&mut self, budget: u64) -> eyre::Result<()> {
        if budget == 0 {
            return Ok(());
        }
        self.sbox_pool = Some(SboxPool::prepare(budget as usize, self.net, self.state)?);
        Ok(())
    }
}

impl<N: Network, F: PrimeField> VmDriver<F> for Rep3Driver<'_, F, N> {
    type Share = Rep3PrimeFieldShare<F>;
    type Local = F;

    fn promote(&mut self, value: F) -> Self::Share {
        Rep3PrimeFieldShare::promote_from_trivial(&value, self.state.id())
    }

    fn open(&mut self, shares: &[Self::Share]) -> eyre::Result<Vec<F>> {
        Ok(rep3::arithmetic::open_vec(shares, self.net)?)
    }

    fn add_ss(&mut self, a: &Self::Share, b: &Self::Share) -> Self::Share {
        rep3::arithmetic::add(*a, *b)
    }

    fn sub_ss(&mut self, a: &Self::Share, b: &Self::Share) -> Self::Share {
        rep3::arithmetic::sub(*a, *b)
    }

    fn add_sp(&mut self, a: &Self::Share, b: F) -> Self::Share {
        rep3::arithmetic::add_public(*a, b, self.state.id())
    }

    fn sub_sp(&mut self, a: &Self::Share, b: F) -> Self::Share {
        rep3::arithmetic::sub_shared_by_public(*a, b, self.state.id())
    }

    fn sub_ps(&mut self, a: F, b: &Self::Share) -> Self::Share {
        rep3::arithmetic::sub_public_by_shared(a, *b, self.state.id())
    }

    fn mul_sp(&mut self, a: &Self::Share, b: F) -> Self::Share {
        rep3::arithmetic::mul_public(*a, b)
    }

    fn mul_local(&mut self, a: &Self::Share, b: &Self::Share) -> F {
        rep3::arithmetic::local_mul_vec(std::slice::from_ref(a), std::slice::from_ref(b), self.state)[0]
    }

    fn mul_local_vec(&mut self, a: &[Self::Share], b: &[Self::Share]) -> Vec<F> {
        rep3::arithmetic::local_mul_vec(a, b, self.state)
    }

    fn reshare(&mut self, locals: &[F]) -> eyre::Result<Vec<Self::Share>> {
        rep3::arithmetic::reshare_vec(locals.to_vec(), self.net)
    }

    fn poseidon2_traces(&mut self, t: usize, states: &[Self::Share]) -> eyre::Result<Vec<Self::Share>> {
        let pool = self.sbox_pool.as_mut().ok_or_else(|| {
            eyre::eyre!(
                "poseidon2_traces called on a Rep3Driver with no s-box randomness prepared - call \
                 Rep3Driver::preprocess(program.sbox_randomness) before Machine::run"
            )
        })?;
        gadgets::poseidon2::rep3_trace(t, states, self.net, self.state, pool)
    }

    fn poseidon2_requested_traces(
        &mut self,
        t: usize,
        states: &[Self::Share],
        result_requests: &[u32],
        result_offsets: &[u32],
    ) -> eyre::Result<Vec<Self::Share>> {
        let pool = self.sbox_pool.as_mut().ok_or_else(|| {
            eyre::eyre!(
                "poseidon2_requested_traces called on a Rep3Driver with no s-box randomness \
                 prepared - call Rep3Driver::preprocess(program.sbox_randomness) before Machine::run"
            )
        })?;
        gadgets::poseidon2::rep3_trace_requested(
            t,
            states,
            self.net,
            self.state,
            pool,
            result_requests,
            result_offsets,
        )
    }

    fn num2bits_traces(&mut self, n: usize, inputs: &[Self::Share]) -> eyre::Result<Vec<Self::Share>> {
        gadgets::num2bits::rep3_trace(n, inputs, self.net, self.state)
    }

    fn is_zero_traces(&mut self, inputs: &[Self::Share]) -> eyre::Result<Vec<Self::Share>> {
        gadgets::iszero::rep3_trace(inputs, self.net, self.state)
    }

    fn is_zero_revealed_traces(&mut self, inputs: &[Self::Share]) -> eyre::Result<Vec<Self::Share>> {
        gadgets::iszero::rep3_trace_revealed(inputs, self.net, self.state)
    }

    fn is_equal_traces(&mut self, inputs: &[Self::Share]) -> eyre::Result<Vec<Self::Share>> {
        gadgets::isequal::rep3_trace(inputs, self.net, self.state)
    }

    fn is_equal_revealed_traces(&mut self, inputs: &[Self::Share]) -> eyre::Result<Vec<Self::Share>> {
        gadgets::isequal::rep3_trace_revealed(inputs, self.net, self.state)
    }

    fn alias_check_traces(&mut self, inputs: &[Self::Share]) -> eyre::Result<Vec<Self::Share>> {
        gadgets::aliascheck::rep3_trace(inputs, self.net, self.state)
    }
}
