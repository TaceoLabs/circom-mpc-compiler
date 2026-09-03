//! Real three-party rep3 execution over `mpc_net`/`mpc_core`. `Share = Rep3PrimeFieldShare<Fr>`;
//! `Local = Fr` - the `a` component of a replicated share is already a valid additive-3 sharing on
//! its own, so there's nothing to wrap.

use ark_bn254::Fr;
use mpc_core::MpcState;
use mpc_core::protocols::rep3::{self, Rep3PrimeFieldShare, Rep3State};
use mpc_net::Network;

use circom_mpc_program::Program;

use crate::gadgets;

use super::VmDriver;

/// One freshly prepared rep3 VM execution. The network connection and [`Rep3State`] are borrowed so
/// callers can reuse those long-lived resources, but this driver and its Poseidon2 mask pool are
/// deliberately one-shot: construct a new [`Self::new_for_run`] for every [`crate::Machine::run`].
/// The lifecycle is `Ready -> Running -> Spent`; opening/splitting the resulting witness remains
/// allowed after `Spent` because it consumes no Poseidon masks.
pub struct Rep3Driver<'a, N: Network> {
    /// The network connection to the other two parties.
    pub net: &'a N,
    /// This party's rep3 protocol state.
    pub state: &'a mut Rep3State,
    poseidon2: gadgets::poseidon2::Rep3Poseidon2Preprocessing,
    lifecycle: Lifecycle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lifecycle {
    Ready,
    Running,
    Spent,
}

impl<'a, N: Network> Rep3Driver<'a, N> {
    /// Validates `program`, derives its checked mask budget from executable shared-Poseidon2
    /// instructions, and prepares the complete fresh pool in three rounds (or zero rounds when the
    /// budget is zero). The derived budget is runtime state and is not part of program serialization.
    ///
    /// # Errors
    ///
    /// Returns an error if `program` fails its own encoding checks, or preparing the Poseidon2
    /// mask pool fails.
    pub fn new_for_run(
        net: &'a N,
        state: &'a mut Rep3State,
        program: &Program,
    ) -> eyre::Result<Self> {
        // Never communicate for a malformed public Program value.
        program.validate_encoding()?;
        let mask_budget = gadgets::poseidon2::mask_budget(program)?;
        let poseidon2 = gadgets::poseidon2::preprocess_rep3(mask_budget, net, state)?;
        Ok(Self {
            net,
            state,
            poseidon2,
            lifecycle: Lifecycle::Ready,
        })
    }
}

impl<N: Network> VmDriver for Rep3Driver<'_, N> {
    type Share = Rep3PrimeFieldShare<Fr>;

    fn begin_run(&mut self) -> eyre::Result<()> {
        match self.lifecycle {
            Lifecycle::Ready => {
                self.lifecycle = Lifecycle::Running;
                Ok(())
            }
            Lifecycle::Running => eyre::bail!("Rep3Driver is already running"),
            Lifecycle::Spent => {
                eyre::bail!(
                    "Rep3Driver has already been spent; prepare a fresh driver for each run"
                )
            }
        }
    }

    fn finish_run(&mut self) -> eyre::Result<()> {
        let previous = std::mem::replace(&mut self.lifecycle, Lifecycle::Spent);
        eyre::ensure!(
            previous == Lifecycle::Running,
            "Rep3Driver finish_run called while {previous:?}"
        );
        self.poseidon2.ensure_consumed()
    }

    fn promote(&mut self, value: Fr) -> Self::Share {
        Rep3PrimeFieldShare::promote_from_trivial(&value, self.state.id())
    }

    fn open(&mut self, shares: &[Self::Share]) -> eyre::Result<Vec<Fr>> {
        rep3::arithmetic::open_vec(shares, self.net)
    }

    fn add_ss(&mut self, a: &Self::Share, b: &Self::Share) -> Self::Share {
        rep3::arithmetic::add(*a, *b)
    }

    fn sub_ss(&mut self, a: &Self::Share, b: &Self::Share) -> Self::Share {
        rep3::arithmetic::sub(*a, *b)
    }

    fn add_sp(&mut self, a: &Self::Share, b: Fr) -> Self::Share {
        rep3::arithmetic::add_public(*a, b, self.state.id())
    }

    fn sub_sp(&mut self, a: &Self::Share, b: Fr) -> Self::Share {
        rep3::arithmetic::sub_shared_by_public(*a, b, self.state.id())
    }

    fn sub_ps(&mut self, a: Fr, b: &Self::Share) -> Self::Share {
        rep3::arithmetic::sub_public_by_shared(a, *b, self.state.id())
    }

    fn mul_sp(&mut self, a: &Self::Share, b: Fr) -> Self::Share {
        rep3::arithmetic::mul_public(*a, b)
    }

    fn mul_vec(&mut self, a: &[Self::Share], b: &[Self::Share]) -> eyre::Result<Vec<Self::Share>> {
        let local = rep3::arithmetic::local_mul_vec(a, b, self.state);
        rep3::arithmetic::reshare_vec(local, self.net)
    }

    fn poseidon2_requested_traces(
        &mut self,
        t: usize,
        states: &[Self::Share],
        result_requests: &[u32],
        result_offsets: &[u32],
    ) -> eyre::Result<Vec<Self::Share>> {
        gadgets::poseidon2::rep3_trace_requested_preprocessed(
            t,
            states,
            self.net,
            self.state,
            &mut self.poseidon2,
            result_requests,
            result_offsets,
        )
    }

    fn num2bits_traces(
        &mut self,
        n: usize,
        inputs: &[Self::Share],
    ) -> eyre::Result<Vec<Self::Share>> {
        gadgets::num2bits::rep3_trace(n, inputs, self.net, self.state)
    }

    fn is_zero_traces(&mut self, inputs: &[Self::Share]) -> eyre::Result<Vec<Self::Share>> {
        gadgets::iszero::rep3_trace(inputs, self.net, self.state)
    }

    fn is_zero_reveal_traces(
        &mut self,
        inputs: &[Self::Share],
    ) -> eyre::Result<Vec<(Self::Share, Self::Share, Fr)>> {
        gadgets::iszero::rep3_masked_reveal_trace(inputs, self.net, self.state)
    }

    fn alias_check_traces(&mut self, inputs: &[Self::Share]) -> eyre::Result<Vec<Self::Share>> {
        gadgets::aliascheck::rep3_trace(inputs, self.net, self.state)
    }
}
