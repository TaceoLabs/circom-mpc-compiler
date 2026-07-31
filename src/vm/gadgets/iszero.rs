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
/// `register_iszero`, generalized from one value to a batch): `is_zero = eq(in, 0)`, computed via
/// `a2y2b_many` (Yao A2B) rather than mpc-core's own `eq_public_many` - that helper hardcodes the
/// vectorized *Direct* A2B (`arithmetic::eq_bit_many` calls `conversion::a2b_many`; only the
/// single-value `eq_bit` uses the state's own `a2b_selector`), which costs 29 rounds against Yao's
/// 11. `vm::gadgets` always picks Yao here rather than reading `Rep3State::a2b_type` - this
/// module's cost model (`docs/ARCHITECTURE.md`, "The cost model") ranks network rounds first, so
/// trading bytes for rounds is always the right call at this layer, independent of what a caller
/// configured the driver's own state to prefer. Masking `in` by `is_zero` before inverting avoids
/// ever inverting a genuine zero (which the plain branch above can do directly, but a secret
/// comparison can't branch on); `helper = inv - is_zero` cancels the mask back out. `out = is_zero`,
/// `inv = helper`.
#[cfg(feature = "rep3")]
pub fn rep3_trace<F: PrimeField, N: mpc_net::Network>(
    inputs: &[mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut mpc_core::protocols::rep3::Rep3State,
) -> eyre::Result<Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>> {
    use mpc_core::protocols::rep3::{arithmetic, binary, conversion};

    let bits = conversion::a2y2b_many(inputs, net, state)?;
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

/// The 1-round twin of [`rep3_trace`], for [`crate::ir::PrecomputeKind::IsZeroRevealed`] sites -
/// only ever selected by `passes::mpc::declassify_zero_test`, and only when it has confirmed this
/// site's `out` is revealed immediately after (`TACEO_REVEAL`). Computes both results from **one**
/// `mul_open_vec`: for uniform secret `r`, opening `z = x * r` reveals `x == 0` (`z == 0 <=> x == 0`)
/// and nothing more, since whenever `x != 0`, `z` is uniform over `F` independent of `x` - the single
/// bit learned is exactly `out`, which the caller's `Reveal` site publishes anyway. `inv` falls out
/// of the same open rather than needing a second one: `x^{-1} = r * z^{-1}` whenever `z != 0`.
///
/// The `r == 0` case (probability `1/|F|`) mislabels a nonzero `x` as zero - a wrong witness, not a
/// leak, and the identical failure mode mpc-core's own `inv_vec` already accepts (it bails on
/// `y == 0`).
#[cfg(feature = "rep3")]
pub fn rep3_trace_revealed<F: PrimeField, N: mpc_net::Network>(
    inputs: &[mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut mpc_core::protocols::rep3::Rep3State,
) -> eyre::Result<Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>> {
    use mpc_core::protocols::rep3::arithmetic;

    let r: Vec<_> = (0..inputs.len()).map(|_| arithmetic::rand(state)).collect();
    let z = arithmetic::mul_open_vec(inputs, &r, net, state)?;

    let mut results = Vec::with_capacity(inputs.len() * 2);
    for (&r, z) in r.iter().zip(z) {
        if z.is_zero() {
            results.push(arithmetic::promote_to_trivial_share(state.id, F::one()));
            results.push(arithmetic::promote_to_trivial_share(state.id, F::zero()));
        } else {
            let z_inv = z.inverse().expect("z is non-zero, checked above");
            results.push(arithmetic::promote_to_trivial_share(state.id, F::zero()));
            results.push(arithmetic::mul_public(r, z_inv));
        }
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

    /// Pins the round count `a2y2b_many` + `is_zero_many` + `bit_inject_many` + `inv_vec` actually
    /// cost - 11 rounds (the Yao A2B conversion's own count, inherited from mpc-core, not chosen
    /// here, plus the two single-round calls after it), independent of site count.
    #[cfg(feature = "round-counting")]
    #[test]
    fn rep3_cost_is_independent_of_site_count() {
        use crate::vm::gadgets::test_support::run3_counted;

        let one_site = [Fr::from(0u64)];
        let (_, rounds_one) = run3_counted(&one_site, |net, state, shares| rep3_trace(shares, net, state));
        assert_eq!(rounds_one, 11);

        let four_sites = [Fr::from(0u64), Fr::from(7u64), Fr::from(0u64), Fr::from(3u64)];
        let (_, rounds_four) = run3_counted(&four_sites, |net, state, shares| rep3_trace(shares, net, state));

        assert_eq!(rounds_one, rounds_four, "round count must not scale with site count");
    }

    #[test]
    fn rep3_revealed_agrees_with_plain_on_zero_and_nonzero() {
        let values = [Fr::from(0u64), Fr::from(7u64)];
        let expected: Vec<Fr> = values.iter().flat_map(|&x| plain_trace(x)).collect();

        let got = run3(&values, |net, state, shares| rep3_trace_revealed(shares, net, state));
        assert_eq!(got, expected);
    }

    /// The whole point of the revealed variant: one round, not ordinary `rep3_trace`'s 11.
    #[cfg(feature = "round-counting")]
    #[test]
    fn rep3_revealed_costs_exactly_one_round() {
        use crate::vm::gadgets::test_support::run3_counted;

        let values = [Fr::from(0u64), Fr::from(7u64)];
        let (_, rounds) = run3_counted(&values, |net, state, shares| rep3_trace_revealed(shares, net, state));
        assert_eq!(rounds, 1);
    }
}
