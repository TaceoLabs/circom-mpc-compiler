//! `IsEqual`: `out = 1` iff `in[0] == in[1]`. A thin wrapper over [`super::iszero`] rather than a
//! separate implementation, because circomlib's `IsEqual` literally is one:
//!
//! ```circom
//! template IsEqual() {
//!     signal input in[2];
//!     signal output out;
//!     component isz = IsZero();
//!     in[1] - in[0] ==> isz.in;
//!     isz.out ==> out;
//! }
//! ```
//!
//! Result layout is that template's own signal layout, minus the site's two inputs:
//! `[out, isz.out, isz.in, isz.inv]` - the template's own `out`, then the whole `IsZero` subtree
//! (`[out][in][inv]`). See `ir::PrecomputeKind::IsEqual`, whose `expected_results()` is 4.
//!
//! **The difference is `in[1] - in[0]`, not the reverse.** `out` is identical either way, but
//! `isz.in` is a real witness slot, so getting the sign backwards produces a witness that differs
//! from circom's in exactly one position per site.

use ark_ff::PrimeField;

/// Per-site result count - `[out, isz.out, isz.in, isz.inv]`.
const RESULTS_PER_SITE: usize = 4;

/// `inputs` is `sites * 2` values (`[in[0], in[1]]` per site); returns `sites * 4`.
pub fn plain_trace<F: PrimeField>(inputs: &[F]) -> eyre::Result<Vec<F>> {
    eyre::ensure!(
        inputs.len().is_multiple_of(2),
        "is_equal_traces: {} inputs is not a multiple of 2",
        inputs.len()
    );
    let mut results = Vec::with_capacity(inputs.len() / 2 * RESULTS_PER_SITE);
    for pair in inputs.chunks_exact(2) {
        let diff = pair[1] - pair[0];
        let [out, inv] = super::iszero::plain_trace(diff);
        results.extend_from_slice(&[out, out, diff, inv]);
    }
    Ok(results)
}

/// The rep3 twin of [`plain_trace`]. The subtraction is a free local op, so this costs exactly what
/// one `IsZero` batch of the same size costs - no extra network rounds.
#[cfg(feature = "rep3")]
pub fn rep3_trace<F: PrimeField, N: mpc_net::Network>(
    inputs: &[mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut mpc_core::protocols::rep3::Rep3State,
) -> eyre::Result<Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>> {
    use mpc_core::protocols::rep3::arithmetic;

    eyre::ensure!(
        inputs.len().is_multiple_of(2),
        "is_equal_traces: {} inputs is not a multiple of 2",
        inputs.len()
    );
    let diffs: Vec<_> = inputs
        .chunks_exact(2)
        .map(|pair| arithmetic::sub(pair[1], pair[0]))
        .collect();
    // One batched IsZero call for every site, matching the "one driver call per batch" contract.
    let iszero = super::iszero::rep3_trace(&diffs, net, state)?;

    let mut results = Vec::with_capacity(diffs.len() * RESULTS_PER_SITE);
    for (site, diff) in diffs.into_iter().enumerate() {
        let out = iszero[site * 2];
        let inv = iszero[site * 2 + 1];
        results.extend_from_slice(&[out, out, diff, inv]);
    }
    Ok(results)
}

#[cfg(all(test, feature = "rep3"))]
mod tests {
    use ark_bn254::Fr;

    use super::*;
    use crate::vm::gadgets::test_support::run3;

    #[test]
    fn rep3_agrees_with_plain_across_two_sites() {
        // Equal, unequal, and equal-at-zero.
        let values = [
            Fr::from(5u64),
            Fr::from(5u64),
            Fr::from(3u64),
            Fr::from(9u64),
            Fr::from(0u64),
            Fr::from(0u64),
        ];
        let expected = plain_trace(&values).unwrap();
        let got = run3(&values, |net, state, shares| rep3_trace(shares, net, state));
        assert_eq!(got, expected);
    }

    #[test]
    fn out_is_one_exactly_when_the_inputs_are_equal() {
        let trace = plain_trace(&[Fr::from(4u64), Fr::from(4u64)]).unwrap();
        assert_eq!(trace[0], Fr::from(1u64));
        // isz.in is in[1] - in[0]; the sign matters even though it is 0 here.
        assert_eq!(trace[2], Fr::from(0u64));

        let trace = plain_trace(&[Fr::from(10u64), Fr::from(4u64)]).unwrap();
        assert_eq!(trace[0], Fr::from(0u64));
        assert_eq!(trace[2], Fr::from(4u64) - Fr::from(10u64));
    }
}
