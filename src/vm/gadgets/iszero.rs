//! `IsZero`: `out = 1` iff `in == 0`, plus `inv` (the helper `circuits/libs/comparators.circom`
//! needs to constrain it: `inv <-- in!=0 ? 1/in : 0`, `out <== -in*inv + 1`). See
//! `ir::PrecomputeKind::IsZero`.

use ark_ff::PrimeField;

/// `[out, inv]`.
pub fn plain_trace<F: PrimeField>(x: F) -> [F; 2] {
    if x.is_zero() {
        [F::one(), F::zero()]
    } else {
        [F::zero(), x.inverse().expect("x is non-zero, checked above")]
    }
}

/// The rep3 twin of [`plain_trace`], batched across every site in one `Machine::precompute` call
/// (the same technique the co-snarks accelerator uses, `circom-mpc-vm/src/accelerator.rs`'s
/// `register_iszero`, generalized from one value to a batch): `is_zero = eq(in, 0)`; masking
/// `in` by `is_zero` before inverting avoids ever inverting a genuine zero (which the plain
/// branch above can do directly, but a secret comparison can't branch on); `helper = inv -
/// is_zero` cancels the mask back out. `out = is_zero`, `inv = helper`.
#[cfg(feature = "rep3")]
pub fn rep3_trace<F: PrimeField, N: mpc_net::Network>(
    inputs: &[mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut mpc_core::protocols::rep3::Rep3State,
) -> eyre::Result<Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>> {
    use mpc_core::protocols::rep3::arithmetic;

    let zeros = vec![F::zero(); inputs.len()];
    let is_zero = arithmetic::eq_public_many(inputs, &zeros, net, state)?;
    let inv_input: Vec<_> = inputs
        .iter()
        .zip(&is_zero)
        .map(|(&x, &z)| arithmetic::add(x, z))
        .collect();
    let invs = arithmetic::inv_vec(&inv_input, net, state)?;

    let mut results = Vec::with_capacity(inputs.len() * 2);
    for (iz, inv) in is_zero.into_iter().zip(invs) {
        results.push(iz);
        results.push(arithmetic::sub(inv, iz));
    }
    Ok(results)
}

#[cfg(all(test, feature = "rep3"))]
mod tests {
    use ark_bn254::Fr;

    use super::*;
    use crate::vm::gadgets::test_support::run3;

    #[test]
    fn rep3_agrees_with_plain_on_zero_and_nonzero() {
        let values = [Fr::from(0u64), Fr::from(7u64)];
        let expected: Vec<Fr> = values.iter().flat_map(|&x| plain_trace(x)).collect();

        let got = run3(&values, |net, state, shares| rep3_trace(shares, net, state));
        assert_eq!(got, expected);
    }
}
