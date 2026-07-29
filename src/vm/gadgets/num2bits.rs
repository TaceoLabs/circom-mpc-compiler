//! `Num2Bits(n)`: bit-decomposes one field element into `n` bits, least-significant first -
//! `out[i] = (in >> i) & 1` (`circuits/libs/bitify.circom`). No intermediates: `n` outputs, and
//! nothing else - see `ir::PrecomputeKind::Num2Bits`.

use ark_ff::{BigInteger, PrimeField};

/// `x`'s canonical representative, as `n` bits, least-significant first.
pub fn plain_trace<F: PrimeField>(x: F, n: usize) -> Vec<F> {
    let bigint = x.into_bigint();
    (0..n)
        .map(|i| if bigint.get_bit(i) { F::one() } else { F::zero() })
        .collect()
}

/// The rep3 twin of [`plain_trace`], batched across every site in one `Machine::precompute` call:
/// one `a2y2b_many` across every site's input, then one `bit_inject_many` across every site's bits.
#[cfg(feature = "rep3")]
pub fn rep3_trace<F: PrimeField, N: mpc_net::Network>(
    n: usize,
    inputs: &[mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut mpc_core::protocols::rep3::Rep3State,
) -> eyre::Result<Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>> {
    use mpc_core::protocols::rep3::conversion;
    use num_bigint::BigUint;
    use num_traits::One;

    let a2b = conversion::a2y2b_many(inputs, net, state)?;
    let mut all_bits = Vec::with_capacity(inputs.len() * n);
    for a2b in &a2b {
        all_bits.extend((0..n).map(|i| (a2b >> i) & BigUint::one()));
    }
    conversion::bit_inject_many(&all_bits, net, state)
}

#[cfg(all(test, feature = "rep3"))]
mod tests {
    use ark_bn254::Fr;

    use super::*;
    use crate::vm::gadgets::test_support::run3;

    #[test]
    fn rep3_agrees_with_plain_across_two_sites() {
        let values = [Fr::from(0b1011010u64), Fr::from(0b0001111u64)];
        let n = 12;
        let expected: Vec<Fr> = values.iter().flat_map(|&x| plain_trace(x, n)).collect();

        let got = run3(&values, |net, state, shares| rep3_trace(n, shares, net, state));
        assert_eq!(got, expected);
    }

    /// Pins the round count: one `a2y2b_many` call across the whole batch, then one
    /// `bit_inject_many` - independent of site count. The exact number is `a2y2b_many`'s own
    /// (a garbled-circuit conversion, not pinned here), but it must not scale with the number of
    /// sites.
    #[cfg(feature = "round-counting")]
    #[test]
    fn rep3_cost_is_independent_of_site_count() {
        use crate::vm::gadgets::test_support::run3_counted;

        let n = 12;
        let one_site = [Fr::from(1u64)];
        let (_, rounds_one) = run3_counted(&one_site, |net, state, shares| rep3_trace(n, shares, net, state));

        let four_sites: Vec<Fr> = (1..=4).map(Fr::from).collect();
        let (_, rounds_four) = run3_counted(&four_sites, |net, state, shares| rep3_trace(n, shares, net, state));

        assert_eq!(rounds_one, rounds_four, "round count must not scale with site count");
    }
}
