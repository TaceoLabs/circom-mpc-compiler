//! `PlainDriver`: single-party execution in the clear - the reference driver. `Share = Local = Fr`: there
//! is nothing to mask or reshare with only one party, so `reshare` is the identity and `mul_local`
//! is a plain product.

use ark_bn254::Fr;

use crate::gadgets::{aliascheck, iszero, num2bits, poseidon2};

use super::VmDriver;

/// Single-party reference [`VmDriver`]: every share is the plain field element itself.
#[derive(Debug, Default, Clone, Copy)]
pub struct PlainDriver;

impl VmDriver for PlainDriver {
    type Share = Fr;

    fn promote(&mut self, value: Fr) -> Fr {
        value
    }

    fn open(&mut self, shares: &[Fr]) -> eyre::Result<Vec<Fr>> {
        Ok(shares.to_vec())
    }

    fn add_ss(&mut self, a: &Fr, b: &Fr) -> Fr {
        *a + *b
    }

    fn sub_ss(&mut self, a: &Fr, b: &Fr) -> Fr {
        *a - *b
    }

    fn add_sp(&mut self, a: &Fr, b: Fr) -> Fr {
        *a + b
    }

    fn sub_sp(&mut self, a: &Fr, b: Fr) -> Fr {
        *a - b
    }

    fn sub_ps(&mut self, a: Fr, b: &Fr) -> Fr {
        a - *b
    }

    fn mul_sp(&mut self, a: &Fr, b: Fr) -> Fr {
        *a * b
    }

    fn mul_vec(&mut self, a: &[Fr], b: &[Fr]) -> eyre::Result<Vec<Fr>> {
        Ok(a.iter().zip(b).map(|(a, b)| *a * *b).collect())
    }

    fn poseidon2_requested_traces(
        &mut self,
        t: usize,
        states: &[Fr],
        result_requests: &[u32],
        result_offsets: &[u32],
    ) -> eyre::Result<Vec<Fr>> {
        poseidon2::plain_trace_requested(t, states, result_requests, result_offsets)
    }

    fn num2bits_traces(&mut self, n: usize, inputs: &[Fr]) -> eyre::Result<Vec<Fr>> {
        Ok(inputs
            .iter()
            .flat_map(|&x| num2bits::plain_trace(x, n))
            .collect())
    }

    fn is_zero_traces(&mut self, inputs: &[Fr]) -> eyre::Result<Vec<Fr>> {
        Ok(inputs
            .iter()
            .flat_map(|&x| iszero::plain_trace(x))
            .collect())
    }

    fn is_zero_reveal_traces(&mut self, inputs: &[Fr]) -> eyre::Result<Vec<(Fr, Fr, Fr)>> {
        Ok(inputs
            .iter()
            .map(|&x| {
                let [is_zero, inverse] = iszero::plain_trace(x);
                (is_zero, inverse, is_zero)
            })
            .collect())
    }

    fn alias_check_traces(&mut self, inputs: &[Fr]) -> eyre::Result<Vec<Fr>> {
        eyre::ensure!(
            inputs.len().is_multiple_of(254),
            "alias_check_traces: {} inputs is not a multiple of 254",
            inputs.len()
        );
        let mut results = Vec::new();
        for chunk in inputs.as_chunks::<254>().0 {
            results.extend(aliascheck::plain_trace(chunk));
        }
        Ok(results)
    }
}
