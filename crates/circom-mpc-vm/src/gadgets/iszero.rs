//! `IsZero`: `out = 1` iff `in == 0`, plus `inv` (the helper `circuits/libs/comparators.circom`
//! needs to constrain it: `inv <-- in!=0 ? 1/in : 0`, `out <== -in*inv + 1`). See
//! `ir::AcceleratorKind::IsZero`.

use ark_bn254::Fr;
use ark_ff::{Field, One, Zero};

/// `[out, inv]`.
pub fn plain_trace(x: Fr) -> [Fr; 2] {
    if x.is_zero() {
        [Fr::one(), Fr::zero()]
    } else {
        [
            Fr::zero(),
            x.inverse().expect("x is non-zero, checked above"),
        ]
    }
}

/// The rep3 twin of [`plain_trace`], batched across every site in one `Machine::run_batch` call (dispatched at `Opcode::Accelerator`)
/// (the same technique the co-snarks accelerator uses, `circom-mpc-vm/src/accelerator.rs`'s
/// `register_iszero`, generalized from one value to a batch): convert every input to binary with
/// the strategy selected on `Rep3State`, test the binary shares for zero, and inject the result
/// back into arithmetic sharing. Masking `in` by `is_zero` before inverting avoids ever inverting
/// a genuine zero; `helper = inv - is_zero` cancels the mask back out. `out = is_zero`, `inv =
/// helper`.
pub fn rep3_trace<N: mpc_net::Network>(
    inputs: &[mpc_core::protocols::rep3::Rep3PrimeFieldShare<Fr>],
    net: &N,
    state: &mut mpc_core::protocols::rep3::Rep3State,
) -> eyre::Result<Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<Fr>>> {
    use mpc_core::protocols::rep3::{arithmetic, binary, conversion};

    let bits = super::a2b_many_selector(inputs, net, state)?;
    let is_zero_bits = binary::is_zero_many(bits, net, state)?;
    let is_zero = conversion::bit_inject_many(&is_zero_bits, net, state)?;
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

/// One-round masked IsZero plus explicit reveal, batched across every site. This is the optimized
/// primitive used only for the VM's conservative whole-batch `IsZero -> Reveal(1)` fusion.
///
/// Each input is multiplied by its own fresh secret arithmetic mask and the products are opened
/// together. A non-zero product gives `inv = mask / product = 1 / input`; a zero product gives the
/// public zero predicate. A uniformly random mask is itself zero with probability `1/|Fr|`, which
/// can falsely classify a non-zero input, so the statistical-soundness tradeoff is restricted to
/// BN254 here as well as in codegen and `Program::validate`.
#[allow(clippy::type_complexity)]
pub fn rep3_masked_reveal_trace<N: mpc_net::Network>(
    inputs: &[mpc_core::protocols::rep3::Rep3PrimeFieldShare<Fr>],
    net: &N,
    state: &mut mpc_core::protocols::rep3::Rep3State,
) -> eyre::Result<
    Vec<(
        mpc_core::protocols::rep3::Rep3PrimeFieldShare<Fr>,
        mpc_core::protocols::rep3::Rep3PrimeFieldShare<Fr>,
        Fr,
    )>,
> {
    use mpc_core::MpcState;
    use mpc_core::protocols::rep3::{Rep3PrimeFieldShare, arithmetic};

    eyre::ensure!(!inputs.is_empty(), "masked IsZero/Reveal batch is empty");

    let masks: Vec<_> = (0..inputs.len()).map(|_| arithmetic::rand(state)).collect();
    let opened = arithmetic::mul_open_vec(inputs, &masks, net, state)?;
    Ok(masks
        .into_iter()
        .zip(opened)
        .map(|(mask, product)| {
            if product.is_zero() {
                let is_zero = Fr::one();
                (
                    Rep3PrimeFieldShare::promote_from_trivial(&is_zero, state.id()),
                    Rep3PrimeFieldShare::default(),
                    is_zero,
                )
            } else {
                let inverse = product.inverse().expect("non-zero product checked above");
                (
                    Rep3PrimeFieldShare::default(),
                    arithmetic::mul_public(mask, inverse),
                    Fr::zero(),
                )
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use mpc_core::protocols::rep3::conversion::A2BType;

    use super::*;
    use crate::gadgets::test_support::run3_with_a2b;

    #[test]
    fn rep3_agrees_with_plain_on_zero_and_nonzero() {
        let values = [Fr::from(0u64), Fr::from(7u64)];
        let expected: Vec<Fr> = values.iter().flat_map(|&x| plain_trace(x)).collect();

        for strategy in [A2BType::Yao, A2BType::Direct] {
            let got = run3_with_a2b(&values, strategy, |net, state, shares| {
                rep3_trace(shares, net, state)
            });
            assert_eq!(got, expected, "strategy={strategy:?}");
        }
    }

    #[test]
    fn masked_reveal_batches_zero_and_nonzero_together() {
        let values = [Fr::from(0u64), Fr::from(7u64)];
        let expected: Vec<Fr> = values.iter().flat_map(|&x| plain_trace(x)).collect();
        let got = run3_with_a2b(&values, A2BType::default(), |net, state, shares| {
            let traces = rep3_masked_reveal_trace(shares, net, state)?;
            assert_eq!(
                traces.iter().map(|trace| trace.2).collect::<Vec<_>>(),
                [Fr::from(1u64), Fr::from(0u64)]
            );
            Ok(traces
                .into_iter()
                .flat_map(|(is_zero, inverse, _)| [is_zero, inverse])
                .collect())
        });
        assert_eq!(got, expected);
    }

    #[test]
    fn masked_reveal_two_lane_batch_costs_one_round_for_every_party() {
        use crate::gadgets::test_support::run3_counted_with_a2b;

        let values = [Fr::from(0u64), Fr::from(7u64)];
        let (_, rounds) =
            run3_counted_with_a2b(&values, A2BType::default(), |net, state, shares| {
                Ok(rep3_masked_reveal_trace(shares, net, state)?
                    .into_iter()
                    .flat_map(|(is_zero, inverse, _)| [is_zero, inverse])
                    .collect())
            });
        assert_eq!(rounds.by_party, [1, 1, 1]);
    }

    /// Pins both conversion strategies' all-party critical path, as well as the circuit-wide
    /// batching guarantee.
    #[test]
    fn rep3_cost_by_strategy_is_independent_of_site_count() {
        use crate::gadgets::test_support::run3_counted_with_a2b;

        let one_site = [Fr::from(0u64)];
        let four_sites = [
            Fr::from(0u64),
            Fr::from(7u64),
            Fr::from(0u64),
            Fr::from(3u64),
        ];

        for (strategy, expected_max) in [(A2BType::Yao, 11), (A2BType::Direct, 29)] {
            let (_, rounds_one) =
                run3_counted_with_a2b(&one_site, strategy, |net, state, shares| {
                    rep3_trace(shares, net, state)
                });
            let (_, rounds_four) =
                run3_counted_with_a2b(&four_sites, strategy, |net, state, shares| {
                    rep3_trace(shares, net, state)
                });

            assert_eq!(rounds_one.max(), expected_max, "strategy={strategy:?}");
            assert_eq!(rounds_four.max(), expected_max, "strategy={strategy:?}");
            assert_eq!(
                rounds_one.by_party, rounds_four.by_party,
                "round count must not scale with site count for {strategy:?}"
            );
        }
    }
}
