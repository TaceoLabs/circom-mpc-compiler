//! Real three-party rep3 execution over `mpc_net`/`mpc_core`. `Share = Rep3PrimeFieldShare<F>`;
//! `Local = F` - the `a` component of a replicated share is already a valid additive-3 sharing on
//! its own (see `docs/ARCHITECTURE.md`, "MPC lowering"), so there's nothing to wrap. Behind the
//! `rep3` feature.

use ark_ff::PrimeField;
use mpc_core::MpcState;
use mpc_core::protocols::rep3::{self, Rep3PrimeFieldShare, Rep3State};
use mpc_net::Network;

use crate::vm::gadgets;

use super::VmDriver;

/// Borrows the party's network connection and rep3 state rather than owning them, so a caller can
/// reuse the same connection/correlated randomness across several `Machine::run` calls (e.g. one
/// per merces protocol operation) without re-running the PRF setup (`Rep3State::new`) each time.
pub struct Rep3Driver<'a, N: Network> {
    pub net: &'a N,
    pub state: &'a mut Rep3State,
}

impl<'a, N: Network> Rep3Driver<'a, N> {
    pub fn new(net: &'a N, state: &'a mut Rep3State) -> Self {
        Self { net, state }
    }
}

impl<N: Network, F: PrimeField> VmDriver<F> for Rep3Driver<'_, N> {
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
        // local_mul_vec squeezes the round's fresh mask from the correlated RNG - a round's slot
        // count must equal its product count (see docs/ARCHITECTURE.md, "MPC lowering"), which is
        // exactly what calling it once per MulLocal, one slice element at a time, guarantees.
        rep3::arithmetic::local_mul_vec(std::slice::from_ref(a), std::slice::from_ref(b), self.state)[0]
    }

    fn reshare(&mut self, locals: &[F]) -> eyre::Result<Vec<Self::Share>> {
        rep3::arithmetic::reshare_vec(locals.to_vec(), self.net)
    }

    fn poseidon2_traces(&mut self, t: usize, states: &[Self::Share]) -> eyre::Result<Vec<Self::Share>> {
        gadgets::poseidon2::rep3_trace(t, states, self.net, self.state)
    }

    fn num2bits_traces(&mut self, n: usize, inputs: &[Self::Share]) -> eyre::Result<Vec<Self::Share>> {
        gadgets::num2bits::rep3_trace(n, inputs, self.net, self.state)
    }

    fn is_zero_traces(&mut self, inputs: &[Self::Share]) -> eyre::Result<Vec<Self::Share>> {
        gadgets::iszero::rep3_trace(inputs, self.net, self.state)
    }

    fn is_equal_traces(&mut self, inputs: &[Self::Share]) -> eyre::Result<Vec<Self::Share>> {
        gadgets::isequal::rep3_trace(inputs, self.net, self.state)
    }

    fn alias_check_traces(&mut self, inputs: &[Self::Share]) -> eyre::Result<Vec<Self::Share>> {
        gadgets::aliascheck::rep3_trace(inputs, self.net, self.state)
    }
}
