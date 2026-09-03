//! `Num2Bits(n)`: bit-decomposes one field element into `n` bits, least-significant first -
//! `out[i] = (in >> i) & 1` (`circuits/node_modules/circomlib/circuits/bitify.circom`). No intermediates: `n` outputs, and
//! nothing else - see `ir::GadgetKind::Num2Bits`.

use ark_bn254::Fr;
use ark_ff::{BigInteger, One, PrimeField, Zero};

/// `x`'s canonical representative, as `n` bits, least-significant first.
#[must_use]
pub fn plain_trace(x: Fr, n: usize) -> Vec<Fr> {
    let bigint = x.into_bigint();
    (0..n)
        .map(|i| {
            if bigint.get_bit(i) {
                Fr::one()
            } else {
                Fr::zero()
            }
        })
        .collect()
}

/// The rep3 twin of [`plain_trace`], batched across every site in one `Machine::run_batch` call (dispatched at `Opcode::Gadget`):
/// one strategy-selected A2B conversion across every site's input, then one `bit_inject_many`
/// across every site's bits.
///
/// # Errors
///
/// Returns an error if any underlying computation/network round fails.
pub fn rep3_trace<N: mpc_net::Network>(
    n: usize,
    inputs: &[mpc_core::protocols::rep3::Rep3PrimeFieldShare<Fr>],
    net: &N,
    state: &mut mpc_core::protocols::rep3::Rep3State,
) -> eyre::Result<Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<Fr>>> {
    use mpc_core::{protocols::rep3::conversion, uint::FieldUint};

    let a2b = super::a2b_many_selector(inputs, net, state)?;
    let mut all_bits = Vec::with_capacity(inputs.len() * n);
    for a2b in &a2b {
        all_bits.extend((0..n).map(|i| (a2b >> i).and_mask(&<Fr as FieldUint>::Uint::from(1u64))));
    }
    conversion::bit_inject_many(&all_bits, net, state)
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use mpc_core::protocols::rep3::conversion::A2BType;

    use super::*;
    use crate::gadgets::test_support::run3_with_a2b;

    #[test]
    fn rep3_agrees_with_plain_across_two_sites() {
        let values = [Fr::from(0b101_1010u64), Fr::from(0b000_1111u64)];
        let n = 12;
        let expected: Vec<Fr> = values.iter().flat_map(|&x| plain_trace(x, n)).collect();

        for strategy in [A2BType::Yao, A2BType::Direct] {
            let got = run3_with_a2b(&values, strategy, |net, state, shares| {
                rep3_trace(n, shares, net, state)
            });
            assert_eq!(got, expected, "strategy={strategy:?}");
        }
    }

    /// Pins the round count: one strategy-selected A2B call across the whole batch, then one
    /// `bit_inject_many` - independent of site count.
    #[test]
    fn rep3_cost_is_independent_of_site_count() {
        use crate::gadgets::test_support::run3_counted_with_a2b;

        let n = 12;
        let one_site = [Fr::from(1u64)];
        let four_sites: Vec<Fr> = (1..=4).map(Fr::from).collect();

        let mut max_by_strategy = Vec::new();
        for strategy in [A2BType::Yao, A2BType::Direct] {
            let (_, rounds_one) =
                run3_counted_with_a2b(&one_site, strategy, |net, state, shares| {
                    rep3_trace(n, shares, net, state)
                });
            let (_, rounds_four) =
                run3_counted_with_a2b(&four_sites, strategy, |net, state, shares| {
                    rep3_trace(n, shares, net, state)
                });

            assert_eq!(
                rounds_one.by_party, rounds_four.by_party,
                "strategy={strategy:?}"
            );
            max_by_strategy.push(rounds_one.max());
        }
        assert!(
            max_by_strategy[0] < max_by_strategy[1],
            "Yao must remain the lower-round A2B strategy"
        );
    }
}
