//! `AliasCheck`: proves a 254-bit decomposition is the canonical (non-aliased) representative,
//! i.e. `< p` (BN254's scalar field modulus) - `circuits/libs/aliascheck.circom` wraps
//! `CompConstant(-1)` (`circuits/libs/compconstant.circom`), which itself wraps `Num2Bits(135)`.
//!
//! See `ir::PrecomputeKind::AliasCheck` for why the 519-slot result layout below is derived
//! directly from the real circuit's own signal numbering, and how it differs by one from merces'
//! own `DEFAULT_ALIAS_TRACE` (~/repos/merces/crates/merces-core/src/circom_proof/cosnark.rs) -
//! that trace omits `Num2Bits`' own single input signal (`num2bits.in`), which this compiler's
//! signal-span accounting doesn't let it skip.
//!
//! Slot order (519 total, no outputs): `[0] compConstant.out` (`== bits[127]`, still a genuine
//! witness signal despite aliasing one of Num2Bits' own outputs), `[1..255] compConstant.in[0..254]`
//! (copies of AliasCheck's own 254 inputs, per circom's `==>` semantics), `[255..382] parts[0..127]`,
//! `[382] sout`, `[383..518] num2bits.out[0..135]`, `[518] num2bits.in` (a second copy of `sout`).

use ark_ff::PrimeField;

use super::num2bits;

/// `CompConstant`'s compile-time constant bits, for `ct = -1` (i.e. `p - 1`, BN254's scalar field
/// modulus minus one) - the same table `~/repos/merces` uses (`CT_BITS_MINUS_ONE`), since it's an
/// intrinsic property of the field, not merces-specific logic.
#[rustfmt::skip]
const CT_BITS_MINUS_ONE: [bool; 254] = [
    false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, true, true, true, true, true, true, false, false, true, false, false, true, true,
    false, true, false, true, true, true, true, true, false, false, false, false, true, true, true,
    true, true, false, false, false, false, true, false, true, false, false, false, true, false,
    false, true, false, false, false, false, true, true, true, false, true, false, false, true,
    true, true, false, true, true, false, false, true, true, true, true, false, false, false,
    false, true, false, false, true, false, false, false, false, true, false, true, true, true,
    true, true, false, false, true, true, false, false, false, false, false, true, false, true,
    false, false, true, false, true, true, true, false, true, false, false, false, false, true,
    true, false, true, false, true, false, false, false, false, false, false, true, true, false,
    false, false, false, false, false, true, false, true, true, false, true, true, false, true,
    true, false, true, false, false, false, true, false, false, false, false, false, true, false,
    true, false, false, false, false, true, true, true, false, true, true, false, false, true,
    false, true, false, false, false, false, false, false, false, true, false, true, true, false,
    false, false, true, true, false, false, true, false, false, false, false, true, true, true,
    false, true, false, false, true, true, true, false, false, true, true, true, false, false,
    true, false, false, false, true, false, false, true, true, false, false, false, false, false,
    true, true,
];

/// The 519-slot result trace for one `AliasCheck` site, given its 254 inputs (`in[0..254]`).
pub fn plain_trace<F: PrimeField>(input: &[F]) -> Vec<F> {
    assert_eq!(input.len(), 254, "AliasCheck input must be 254 field elements");
    let ct_bits = &CT_BITS_MINUS_ONE;

    let mut b = F::from(u128::MAX);
    let mut a = F::one();
    let mut e = F::one();
    let mut sum = F::zero();
    let mut parts = Vec::with_capacity(127);

    for i in 0..127 {
        let lo = i * 2;
        let hi = lo + 1;
        let (clsb, cmsb) = (ct_bits[lo], ct_bits[hi]);
        let (slsb, smsb) = (input[lo], input[hi]);
        let part = match (cmsb, clsb) {
            (false, false) => -b * smsb * slsb + b * smsb + b * slsb,
            (false, true) => a * smsb * slsb - a * slsb + b * smsb - a * smsb + a,
            (true, false) => b * smsb * slsb - a * smsb + a,
            (true, true) => -a * smsb * slsb + a,
        };
        sum += part;
        parts.push(part);
        b -= e;
        a += e;
        e += e;
    }

    let sout = sum;
    let bits = num2bits::plain_trace(sout, 135);
    let compconstant_out = bits[127];

    let mut trace = Vec::with_capacity(519);
    trace.push(compconstant_out);
    trace.extend_from_slice(input);
    trace.extend(parts);
    trace.push(sout);
    trace.extend(bits);
    trace.push(sout); // num2bits.in - a second copy of sout in circom's own signal numbering
    trace
}

/// The rep3 twin of [`plain_trace`], batched across every site in one `Machine::precompute` call.
/// Ported from `~/repos/merces`'s `alias_check_trace_helper_rep3`
/// (`crates/merces-core/src/circom_proof/cosnark.rs`), generalized from one site to a batch and
/// from merces' own (518-slot, zero-padded) trace convention to the real 519-slot layout above -
/// `compConstant.in[0..254]` and `compConstant.out` are genuine values here (already in hand as
/// this function's own input, and `bits[127]` respectively), not zero placeholders, at no extra
/// round cost.
///
/// The 127-way products (`mul_vec`) batch across every site in one round - genuinely circuit-wide.
/// The bit decomposition (`a2y2b_many` then `bit_inject_many`) is batched the same way.
#[cfg(feature = "rep3")]
pub fn rep3_trace<F: PrimeField, N: mpc_net::Network>(
    inputs: &[mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>],
    net: &N,
    state: &mut mpc_core::protocols::rep3::Rep3State,
) -> eyre::Result<Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>> {
    use mpc_core::protocols::rep3::{Rep3PrimeFieldShare, arithmetic, conversion};
    use num_bigint::BigUint;
    use num_traits::One;

    eyre::ensure!(
        !inputs.is_empty() && inputs.len() % 254 == 0,
        "AliasCheck rep3_trace: {} inputs is not a multiple of 254",
        inputs.len()
    );
    let sites = inputs.len() / 254;
    let my_id = state.id;
    let ct_bits = &CT_BITS_MINUS_ONE;

    // Every site's 127 pairwise products, batched into one round.
    let mut lhs = Vec::with_capacity(sites * 127);
    let mut rhs = Vec::with_capacity(sites * 127);
    for site in inputs.chunks_exact(254) {
        for i in 0..127 {
            lhs.push(site[i * 2]);
            rhs.push(site[i * 2 + 1]);
        }
    }
    let products = arithmetic::mul_vec(&lhs, &rhs, net, state)?;

    let mut sums = Vec::with_capacity(sites);
    let mut all_parts = Vec::with_capacity(sites);
    for (site, prod) in inputs.chunks_exact(254).zip(products.chunks_exact(127)) {
        let mut b = F::from(u128::MAX);
        let mut a = F::one();
        let mut e = F::one();
        let mut sum = Rep3PrimeFieldShare::zero_share();
        let mut parts = Vec::with_capacity(127);
        for i in 0..127 {
            let lo = i * 2;
            let hi = lo + 1;
            let (clsb, cmsb) = (ct_bits[lo], ct_bits[hi]);
            let (slsb, smsb) = (site[lo], site[hi]);
            let smsb_times_slsb = prod[i];
            let part = match (cmsb, clsb) {
                (false, false) => {
                    arithmetic::mul_public(smsb_times_slsb, -b)
                        + arithmetic::mul_public(smsb, b)
                        + arithmetic::mul_public(slsb, b)
                }
                (false, true) => arithmetic::add_public(
                    arithmetic::mul_public(smsb_times_slsb, a) - arithmetic::mul_public(slsb, a)
                        + arithmetic::mul_public(smsb, b)
                        - arithmetic::mul_public(smsb, a),
                    a,
                    my_id,
                ),
                (true, false) => arithmetic::add_public(
                    arithmetic::mul_public(smsb_times_slsb, b) - arithmetic::mul_public(smsb, a),
                    a,
                    my_id,
                ),
                (true, true) => {
                    arithmetic::add_public(arithmetic::mul_public(smsb_times_slsb, -a), a, my_id)
                }
            };
            sum += part;
            parts.push(part);
            b -= e;
            a += e;
            e += e;
        }
        sums.push(sum);
        all_parts.push(parts);
    }

    // One a2b across every site's sum, then one combined bit-injection.
    let a2b = conversion::a2y2b_many(&sums, net, state)?;
    let mut all_bit_shares = Vec::with_capacity(sites * 135);
    for a_bits in &a2b {
        all_bit_shares.extend((0..135).map(|i| (a_bits >> i) & BigUint::one()));
    }
    let all_bits_field = conversion::bit_inject_many(&all_bit_shares, net, state)?;

    let mut results = Vec::with_capacity(sites * 519);
    for site_idx in 0..sites {
        let input = &inputs[site_idx * 254..(site_idx + 1) * 254];
        let sum = sums[site_idx];
        let bits = &all_bits_field[site_idx * 135..(site_idx + 1) * 135];
        let compconstant_out = bits[127];

        results.push(compconstant_out);
        results.extend_from_slice(input);
        results.extend_from_slice(&all_parts[site_idx]);
        results.push(sum);
        results.extend_from_slice(bits);
        results.push(sum);
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
        // Genuine 254-bit decompositions of two small canonical values - exactly the shape
        // AliasCheck's own caller (Num2Bits_strict) feeds it in a real circuit.
        let mut input = super::num2bits::plain_trace(Fr::from(123_456_789u64), 254);
        input.extend(super::num2bits::plain_trace(Fr::from(42u64), 254));
        let mut expected = Vec::new();
        for site in input.chunks_exact(254) {
            expected.extend(plain_trace(site));
        }

        let got = run3(&input, |net, state, shares| rep3_trace(shares, net, state));
        assert_eq!(got, expected);
    }

    /// Pins the round count: one batched 127-way `mul_vec`, one `a2y2b_many` across the whole
    /// batch, then one `bit_inject_many` - independent of site count. The exact number inherits
    /// `a2y2b_many`'s own (a garbled-circuit conversion, not pinned here), but it must not scale
    /// with the number of sites.
    #[cfg(feature = "round-counting")]
    #[test]
    fn rep3_cost_is_independent_of_site_count() {
        use crate::vm::gadgets::test_support::run3_counted;

        let input_for = |sites: usize| -> Vec<Fr> {
            let mut input = Vec::new();
            for i in 0..sites {
                input.extend(super::num2bits::plain_trace(Fr::from(123_456_789u64 + i as u64), 254));
            }
            input
        };

        let (_, rounds_one) =
            run3_counted(&input_for(1), |net, state, shares| rep3_trace(shares, net, state));
        let (_, rounds_two) =
            run3_counted(&input_for(2), |net, state, shares| rep3_trace(shares, net, state));

        assert_eq!(rounds_one, rounds_two, "round count must not scale with site count");
    }
}
