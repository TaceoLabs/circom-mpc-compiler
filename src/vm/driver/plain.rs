//! `PlainDriver`: single-party execution in the clear - the reference driver. `Share = Local = F`: there
//! is nothing to mask or reshare with only one party, so `reshare` is the identity and `mul_local`
//! is a plain product.

use ark_ff::PrimeField;

use crate::vm::gadgets::{aliascheck, iszero, num2bits, poseidon2};

use super::VmDriver;

#[derive(Debug, Default, Clone, Copy)]
pub struct PlainDriver;

impl<F: PrimeField> VmDriver<F> for PlainDriver {
    type Share = F;
    type Local = F;

    fn promote(&mut self, value: F) -> F {
        value
    }

    fn open(&mut self, shares: &[F]) -> eyre::Result<Vec<F>> {
        Ok(shares.to_vec())
    }

    fn add_ss(&mut self, a: &F, b: &F) -> F {
        *a + *b
    }

    fn sub_ss(&mut self, a: &F, b: &F) -> F {
        *a - *b
    }

    fn add_sp(&mut self, a: &F, b: F) -> F {
        *a + b
    }

    fn sub_sp(&mut self, a: &F, b: F) -> F {
        *a - b
    }

    fn sub_ps(&mut self, a: F, b: &F) -> F {
        a - *b
    }

    fn mul_sp(&mut self, a: &F, b: F) -> F {
        *a * b
    }

    fn mul_local_vec(&mut self, a: &[F], b: &[F]) -> Vec<F> {
        a.iter().zip(b).map(|(a, b)| *a * *b).collect()
    }

    fn reshare(&mut self, locals: &[F]) -> eyre::Result<Vec<F>> {
        // Nothing distinguishes "local" from "shared" for a single party - a round's k-th input
        // already *is* its k-th result.
        Ok(locals.to_vec())
    }

    fn poseidon2_requested_traces(
        &mut self,
        t: usize,
        states: &[F],
        result_requests: &[u32],
        result_offsets: &[u32],
    ) -> eyre::Result<Vec<F>> {
        poseidon2::plain_trace_requested(t, states, result_requests, result_offsets)
    }

    fn num2bits_traces(&mut self, n: usize, inputs: &[F]) -> eyre::Result<Vec<F>> {
        Ok(inputs
            .iter()
            .flat_map(|&x| num2bits::plain_trace(x, n))
            .collect())
    }

    fn is_zero_traces(&mut self, inputs: &[F]) -> eyre::Result<Vec<F>> {
        Ok(inputs
            .iter()
            .flat_map(|&x| iszero::plain_trace(x))
            .collect())
    }

    fn is_zero_reveal_traces(&mut self, inputs: &[F]) -> eyre::Result<Vec<(F, F, F)>> {
        Ok(inputs
            .iter()
            .map(|&x| {
                let [is_zero, inverse] = iszero::plain_trace(x);
                (is_zero, inverse, is_zero)
            })
            .collect())
    }

    fn alias_check_traces(&mut self, inputs: &[F]) -> eyre::Result<Vec<F>> {
        eyre::ensure!(
            inputs.len().is_multiple_of(254),
            "alias_check_traces: {} inputs is not a multiple of 254",
            inputs.len()
        );
        let mut results = Vec::new();
        for chunk in inputs.chunks_exact(254) {
            results.extend(aliascheck::plain_trace(chunk));
        }
        Ok(results)
    }
}
