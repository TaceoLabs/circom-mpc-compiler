//! Poseidon2 permutation traces for `circuits/libs/taceo/poseidon2.circom`, computed from **that
//! template's own signal layout**, for every width the circuit defines (`t ∈ {2,3,4,8,12,16}`).
//!
//! # The layout rule
//!
//! circom lays out each component as
//! `[outputs][inputs][own intermediates, in source-declaration order][subcomponent subtrees]`, and -
//! the part that is easy to get wrong - **subcomponent subtrees are ordered by circom's template
//! *instance id* (global first-instantiation order), not by source or creation order within the
//! template.** Three consequences, all of them observable in the golden witness:
//!
//! - `FullRound` emits its `ExternalMatMulT` subtree *before* its `Sbox` subtree, even though the
//!   source instantiates `Sbox` first, because `ExternalMatMulT` is first instantiated earlier (by
//!   `Poseidon2` itself, for `state[0]`).
//! - `Poseidon2` emits all 8 `FullRound` blocks contiguously and only then all `PartialRound` blocks
//!   - so **layout order is not execution order**, since rounds 5..(4+pr) run between them.
//! - Within one template, instances keep their own creation order: the 8 full rounds are the first
//!   group's 4 followed by the second group's 4.
//!
//! Verified against `kats/precomputation_poseidon2_test/` (t=3, 2045 witness entries) by
//! `tests/circom_ir.rs::precomputation_poseidon2_test`, which is the real oracle for all of this.
//!
//! # Structure
//!
//! Three separated concerns, so the layout exists in exactly one place (unlike `super::aliascheck`,
//! which duplicates its much smaller layout between the plain and rep3 paths):
//!
//! - [`Ops`] - the arithmetic backend, implemented once for plain field elements and once for rep3
//!   shares. Only [`Ops::sbox_layer`] ever communicates.
//! - [`walk`] - the permutation itself, **layer-major across every site in lock-step**, so all of a
//!   batch's s-boxes at one round go into a single `sbox_layer` call.
//! - [`emit_site`] - the layout emitter, the one place the ordering above is encoded.

use ark_ff::PrimeField;

use super::poseidon2_constants::{partial_rounds, RoundConstants};

/// The widths `circuits/libs/taceo/poseidon2.circom` defines constants for.
pub const SUPPORTED_WIDTHS: [usize; 6] = [2, 3, 4, 8, 12, 16];

// --- Signal counts, mirroring the circuit's own template structure ---

/// `Acc(n)`: `[out][in[n]][sums[n]]`.
const fn acc_signals(n: usize) -> usize {
    2 * n + 1
}

/// `ExternalMatMul2`/`3`/`4` - the fixed-width leaves of `ExternalMatMulT`.
const fn external_matmul_leaf_signals(t: usize) -> usize {
    match t {
        2 => 5,  // [out[2]][in[2]][sum]
        3 => 7,  // [out[3]][in[3]][sum]
        _ => 18, // [out[4]][in[4]][10 named intermediates]
    }
}

/// `ExternalMatMulT(t)`: `[out[t]][in[t]]` plus its subtree.
const fn external_matmul_signals(t: usize) -> usize {
    match t {
        2..=4 => 2 * t + external_matmul_leaf_signals(t),
        _ => {
            let m = t / 4;
            // m x ExternalMatMul4, then 4 x Acc(m) - in that order, per the instance-id rule.
            2 * t + m * 18 + 4 * acc_signals(m)
        }
    }
}

/// `InternalMatMulT(t)`: `[out[t]][in[t]]` (+ `acc` and an `Acc(t)` subtree for `t >= 4`).
const fn internal_matmul_signals(t: usize) -> usize {
    match t {
        2 => 2 * t + 5,
        3 => 2 * t + 7,
        _ => (2 * t + 1) + acc_signals(t),
    }
}

/// `Sbox_e`: `[out][in][square][pow_4]`.
const SBOX_E_SIGNALS: usize = 4;

/// `Sbox(t)`: `[out[t]][in[t]]` + `t` x `Sbox_e`.
const fn sbox_signals(t: usize) -> usize {
    2 * t + t * SBOX_E_SIGNALS
}

/// `FullRound(t)`: `[out[t]][in[t]][RC[t]][linear_layer[t]][sbox[t]]` + `ExternalMatMulT` + `Sbox`.
const fn full_round_signals(t: usize) -> usize {
    5 * t + external_matmul_signals(t) + sbox_signals(t)
}

/// `PartialRound(t)`: `[out[t]][in[t]][RC][linear_layer][sbox]` + `Sbox_e` + `InternalMatMulT`.
const fn partial_round_signals(t: usize) -> usize {
    (2 * t + 3) + SBOX_E_SIGNALS + internal_matmul_signals(t)
}

/// Every signal `Poseidon2(t)`'s own body and transitive subtree declare, **inputs included**.
pub(crate) const fn total_signals(t: usize) -> usize {
    let pr = partial_rounds(t);
    // [out[t]][in[t]][state[(9+pr)][t]] + ExternalMatMulT + 8 x FullRound + pr x PartialRound
    2 * t
        + (9 + pr) * t
        + external_matmul_signals(t)
        + 8 * full_round_signals(t)
        + pr * partial_round_signals(t)
}

/// How many result slots one site occupies - every signal except the site's own `t` inputs, which the
/// caller supplies rather than the gadget producing. Must equal
/// `ir::PrecomputeKind::Poseidon2 { t }.expected_results()`.
pub(crate) const fn result_slots(t: usize) -> usize {
    total_signals(t) - t
}

// --- The arithmetic backend ---

/// One `Sbox_e`'s three witness values, for `x^5`.
struct SboxTrace<V> {
    square: V,
    pow4: V,
    out: V,
}

/// The field operations the walker needs. Everything except [`Self::sbox_layer`] is local work, free
/// in every domain (see `docs/ARCHITECTURE.md`, "MPC lowering").
trait Ops<F: PrimeField> {
    type V: Clone;

    /// A known constant as a value. The circuit's `RC[..]` signals are real witness positions, so
    /// these must be representable in `V`, not just used as scalars.
    fn public(&mut self, c: F) -> Self::V;
    fn add(&mut self, a: &Self::V, b: &Self::V) -> Self::V;
    fn add_public(&mut self, a: &Self::V, c: F) -> Self::V;
    fn mul_public(&mut self, a: &Self::V, c: F) -> Self::V;
    /// Prepares any per-element correlated randomness [`Self::sbox_layer`] needs, for the whole
    /// permutation batch at once - `walk` calls this once, up front, with the exact total element
    /// count across every s-box layer (full and partial) and every site. A no-op unless a backend
    /// actually has batch-wide prep to do (only `Rep3Ops` does).
    fn prepare_sboxes(&mut self, _total_elements: usize) -> eyre::Result<()> {
        Ok(())
    }
    /// One s-box layer for a whole batch at once - the only step that communicates.
    fn sbox_layer(&mut self, xs: &[Self::V]) -> eyre::Result<Vec<SboxTrace<Self::V>>>;
}

struct PlainOps;

impl<F: PrimeField> Ops<F> for PlainOps {
    type V = F;

    fn public(&mut self, c: F) -> F {
        c
    }
    fn add(&mut self, a: &F, b: &F) -> F {
        *a + *b
    }
    fn add_public(&mut self, a: &F, c: F) -> F {
        *a + c
    }
    fn mul_public(&mut self, a: &F, c: F) -> F {
        *a * c
    }
    fn sbox_layer(&mut self, xs: &[F]) -> eyre::Result<Vec<SboxTrace<F>>> {
        Ok(xs
            .iter()
            .map(|&x| {
                let square = x * x;
                let pow4 = square * square;
                SboxTrace {
                    square,
                    pow4,
                    out: pow4 * x,
                }
            })
            .collect())
    }
}

// --- The permutation, layer-major over every site ---

/// One site's recorded blocks, each already in its own layout order.
struct SiteTrace<V> {
    /// `(9 + pr)` rows of `t`.
    states: Vec<Vec<V>>,
    /// The initial `ExternalMatMulT(t)` subtree.
    initial_matmul: Vec<V>,
    /// The 8 `FullRound` blocks, indexed `0..4` = first group, `4..8` = second group - which is
    /// their layout order, so no re-sorting happens in [`emit_site`].
    full: Vec<Vec<V>>,
    /// The `pr` `PartialRound` blocks, in round order.
    partial: Vec<Vec<V>>,
}

/// `Acc(n)` over `in`: returns `(out, block)` where `block` is `[out][in[n]][sums[n]]`.
fn acc<F: PrimeField, O: Ops<F>>(ops: &mut O, input: &[O::V]) -> (O::V, Vec<O::V>) {
    let mut sums = Vec::with_capacity(input.len());
    sums.push(input[0].clone());
    for x in &input[1..] {
        let prev = sums.last().expect("non-empty");
        sums.push(ops.add(prev, x));
    }
    let out = sums.last().expect("non-empty").clone();
    let mut block = vec![out.clone()];
    block.extend_from_slice(input);
    block.extend(sums);
    (out, block)
}

/// `ExternalMatMul2`/`3`/`4` over exactly 2, 3 or 4 elements.
fn external_matmul_leaf<F: PrimeField, O: Ops<F>>(
    ops: &mut O,
    input: &[O::V],
) -> (Vec<O::V>, Vec<O::V>) {
    let two = F::from(2u64);
    let four = F::from(4u64);
    match input.len() {
        2 | 3 => {
            // out[i] = in[i] + sum
            let mut sum = input[0].clone();
            for x in &input[1..] {
                sum = ops.add(&sum, x);
            }
            let out: Vec<O::V> = input.iter().map(|x| ops.add(x, &sum)).collect();
            let mut block = out.clone();
            block.extend_from_slice(input);
            block.push(sum);
            (out, block)
        }
        4 => {
            let double_in1 = ops.mul_public(&input[1], two);
            let double_in3 = ops.mul_public(&input[3], two);
            let t_0 = ops.add(&input[0], &input[1]);
            let t_1 = ops.add(&input[2], &input[3]);
            let quad_t_0 = ops.mul_public(&t_0, four);
            let quad_t_1 = ops.mul_public(&t_1, four);
            let t_2 = ops.add(&double_in1, &t_1);
            let t_3 = ops.add(&double_in3, &t_0);
            let t_4 = ops.add(&quad_t_1, &t_3);
            let t_5 = ops.add(&quad_t_0, &t_2);
            let out = vec![
                ops.add(&t_3, &t_5),
                t_5.clone(),
                ops.add(&t_2, &t_4),
                t_4.clone(),
            ];
            let mut block = out.clone();
            block.extend_from_slice(input);
            // Source-declaration order of the 10 named intermediates.
            block.extend([
                double_in1, double_in3, t_0, t_1, quad_t_0, quad_t_1, t_2, t_3, t_4, t_5,
            ]);
            (out, block)
        }
        n => unreachable!("external_matmul_leaf takes 2, 3 or 4 elements, got {n}"),
    }
}

/// `ExternalMatMulT(t)`: `[out[t]][in[t]][subtree]`.
fn external_matmul<F: PrimeField, O: Ops<F>>(
    ops: &mut O,
    input: &[O::V],
) -> (Vec<O::V>, Vec<O::V>) {
    let t = input.len();
    let (out, subtree) = if t <= 4 {
        external_matmul_leaf(ops, input)
    } else {
        let m = t / 4;
        // m x ExternalMatMul4 first, then 4 x Acc(m) - the instance-id order.
        let mut mds_out = Vec::with_capacity(m);
        let mut mds_blocks = Vec::new();
        for i in 0..m {
            let (o, b) = external_matmul_leaf(ops, &input[4 * i..4 * i + 4]);
            mds_out.push(o);
            mds_blocks.extend(b);
        }
        let mut acc_out = Vec::with_capacity(4);
        let mut acc_blocks = Vec::new();
        for l in 0..4 {
            let column: Vec<O::V> = mds_out.iter().map(|row| row[l].clone()).collect();
            let (o, b) = acc(ops, &column);
            acc_out.push(o);
            acc_blocks.extend(b);
        }
        let mut out = Vec::with_capacity(t);
        for row in &mds_out {
            for (j, value) in row.iter().enumerate() {
                out.push(ops.add(value, &acc_out[j]));
            }
        }
        mds_blocks.extend(acc_blocks);
        (out, mds_blocks)
    };
    let mut block = out.clone();
    block.extend_from_slice(input);
    block.extend(subtree);
    (out, block)
}

/// `InternalMatMul2`/`3` - a genuine nested subcomponent for those widths, hence its own block
/// (`[out[t]][in[t]][sum]`) rather than inlined arithmetic.
fn internal_matmul_leaf<F: PrimeField, O: Ops<F>>(
    ops: &mut O,
    input: &[O::V],
) -> (Vec<O::V>, Vec<O::V>) {
    let t = input.len();
    let two = F::from(2u64);
    let mut sum = input[0].clone();
    for x in &input[1..] {
        sum = ops.add(&sum, x);
    }
    // The last element is doubled; the rest pass through.
    let out: Vec<O::V> = input
        .iter()
        .enumerate()
        .map(|(i, x)| {
            let scaled = if i == t - 1 {
                ops.mul_public(x, two)
            } else {
                x.clone()
            };
            ops.add(&scaled, &sum)
        })
        .collect();
    let mut block = out.clone();
    block.extend_from_slice(input);
    block.push(sum);
    (out, block)
}

/// `InternalMatMulT(t)`: `[out[t]][in[t]]` plus either a nested `InternalMatMul2`/`3` subcomponent, or
/// (for `t >= 4`) the own intermediate `acc` followed by its `Acc(t)` subtree.
fn internal_matmul<F: PrimeField, O: Ops<F>>(
    ops: &mut O,
    input: &[O::V],
    diag: &[F],
) -> (Vec<O::V>, Vec<O::V>) {
    let t = input.len();
    let (out, tail) = match t {
        2..=3 => internal_matmul_leaf(ops, input),
        _ => {
            let (acc_value, acc_block) = acc(ops, input);
            let out: Vec<O::V> = input
                .iter()
                .zip(diag)
                .map(|(x, &d)| {
                    let scaled = ops.mul_public(x, d);
                    ops.add(&scaled, &acc_value)
                })
                .collect();
            // Own intermediate `acc` precedes the `Acc(t)` subtree.
            let mut tail = vec![acc_value];
            tail.extend(acc_block);
            (out, tail)
        }
    };
    let mut block = out.clone();
    block.extend_from_slice(input);
    block.extend(tail);
    (out, block)
}

/// `Sbox_e`'s block: `[out][in][square][pow_4]`.
fn sbox_e_block<V: Clone>(input: &V, trace: &SboxTrace<V>) -> Vec<V> {
    vec![
        trace.out.clone(),
        input.clone(),
        trace.square.clone(),
        trace.pow4.clone(),
    ]
}

/// Runs the permutation for every site in `states` (each `t` elements, concatenated) in lock-step,
/// so each round's s-boxes across the whole batch are one [`Ops::sbox_layer`] call.
fn walk<F: PrimeField, O: Ops<F>>(
    ops: &mut O,
    t: usize,
    states: &[O::V],
    rc: &RoundConstants<F>,
) -> eyre::Result<Vec<SiteTrace<O::V>>> {
    let sites = states.len() / t;
    let pr = partial_rounds(t);

    // 8 full-round layers of `sites * t` elements, plus `pr` partial-round layers of `sites`
    // elements - the exact total the three `sbox_layer` calls below make, combined.
    ops.prepare_sboxes(sites * (8 * t + pr))?;

    let mut traces: Vec<SiteTrace<O::V>> = Vec::with_capacity(sites);
    // Current state per site, and the running record.
    let mut current: Vec<Vec<O::V>> = Vec::with_capacity(sites);
    for site in 0..sites {
        let input = &states[site * t..(site + 1) * t];
        let (out, block) = external_matmul(ops, input);
        current.push(out.clone());
        traces.push(SiteTrace {
            states: vec![out],
            initial_matmul: block,
            full: Vec::with_capacity(8),
            partial: Vec::with_capacity(pr),
        });
    }

    // A full round, for every site at once: add RC, one s-box layer, external matrix.
    let full_round = |ops: &mut O,
                          current: &mut Vec<Vec<O::V>>,
                          traces: &mut Vec<SiteTrace<O::V>>,
                          round_rc: &[F]|
     -> eyre::Result<()> {
        let mut linear: Vec<Vec<O::V>> = Vec::with_capacity(sites);
        for state in current.iter() {
            linear.push(
                state
                    .iter()
                    .zip(round_rc)
                    .map(|(x, &c)| ops.add_public(x, c))
                    .collect(),
            );
        }
        let flat: Vec<O::V> = linear.iter().flatten().cloned().collect();
        let sboxes = ops.sbox_layer(&flat)?;

        for (site, state) in current.iter_mut().enumerate() {
            let sbox_traces = &sboxes[site * t..(site + 1) * t];
            let sbox_out: Vec<O::V> = sbox_traces.iter().map(|s| s.out.clone()).collect();
            let (out, emm_block) = external_matmul(ops, &sbox_out);

            // [out][in][RC][linear_layer][sbox] + ExternalMatMulT + Sbox
            let mut block = out.clone();
            block.extend_from_slice(state);
            block.extend(round_rc.iter().map(|&c| ops.public(c)));
            block.extend(linear[site].iter().cloned());
            block.extend(sbox_out.iter().cloned());
            block.extend(emm_block);
            // Sbox(t)'s own block: [out[t]][in[t]] + t x Sbox_e
            block.extend(sbox_out.iter().cloned());
            block.extend(linear[site].iter().cloned());
            for (k, s) in sbox_traces.iter().enumerate() {
                block.extend(sbox_e_block(&linear[site][k], s));
            }

            traces[site].full.push(block);
            traces[site].states.push(out.clone());
            *state = out;
        }
        Ok(())
    };

    for round in 0..4 {
        let round_rc = &rc.full1[round * t..(round + 1) * t];
        full_round(ops, &mut current, &mut traces, round_rc)?;
    }

    // Partial rounds: RC and s-box on element 0 only, then the internal matrix.
    for round in 0..pr {
        let c = rc.partial[round];
        let linear: Vec<O::V> = current
            .iter()
            .map(|state| ops.add_public(&state[0], c))
            .collect();
        let sboxes = ops.sbox_layer(&linear)?;

        for (site, state) in current.iter_mut().enumerate() {
            let sbox = &sboxes[site];
            let mut imm_input = vec![sbox.out.clone()];
            imm_input.extend_from_slice(&state[1..]);
            let (out, imm_block) = internal_matmul(ops, &imm_input, &rc.diag);

            // [out][in][RC][linear_layer][sbox] + Sbox_e + InternalMatMulT
            let mut block = out.clone();
            block.extend_from_slice(state);
            let rc_value = ops.public(c);
            block.extend([rc_value, linear[site].clone(), sbox.out.clone()]);
            block.extend(sbox_e_block(&linear[site], sbox));
            block.extend(imm_block);

            traces[site].partial.push(block);
            traces[site].states.push(out.clone());
            *state = out;
        }
    }

    for round in 0..4 {
        let round_rc = &rc.full2[round * t..(round + 1) * t];
        full_round(ops, &mut current, &mut traces, round_rc)?;
    }

    Ok(traces)
}

/// Flattens one site into its [`result_slots`] values, in circom's own signal order. **The one place
/// the layout rule from the module doc is encoded.**
fn emit_site<V: Clone>(t: usize, site: &SiteTrace<V>) -> Vec<V> {
    let mut out = Vec::with_capacity(result_slots(t));
    // [out[t]] - the final state. (The site's own [in[t]] is skipped: those are the caller's, not
    // results.)
    out.extend(site.states.last().expect("at least one state").iter().cloned());
    // [state[(9+pr)][t]], row-major.
    for row in &site.states {
        out.extend(row.iter().cloned());
    }
    // Subtrees, ordered by template-instance id: ExternalMatMulT, then every FullRound, then every
    // PartialRound.
    out.extend(site.initial_matmul.iter().cloned());
    for block in &site.full {
        out.extend(block.iter().cloned());
    }
    for block in &site.partial {
        out.extend(block.iter().cloned());
    }
    out
}

fn check_width(t: usize, states: usize) -> eyre::Result<usize> {
    eyre::ensure!(
        SUPPORTED_WIDTHS.contains(&t),
        "unsupported Poseidon2 width t={t} - circuits/libs/taceo/poseidon2.circom only defines \
         {SUPPORTED_WIDTHS:?}"
    );
    eyre::ensure!(
        states != 0 && states.is_multiple_of(t),
        "Poseidon2(t={t}): {states} state elements is not a non-zero multiple of t"
    );
    Ok(states / t)
}

/// Plain traces for a whole batch: `states` is `sites * t` values (one length-`t` state per site,
/// concatenated), and the result is `sites * result_slots(t)` values in `Machine::precompute`'s slot
/// order.
pub fn plain_trace<F: PrimeField>(t: usize, states: &[F]) -> eyre::Result<Vec<F>> {
    let sites = check_width(t, states.len())?;
    let rc = RoundConstants::load(t)?;
    let traces = walk(&mut PlainOps, t, states, &rc)?;
    let mut out = Vec::with_capacity(sites * result_slots(t));
    for site in &traces {
        let emitted = emit_site(t, site);
        debug_assert_eq!(emitted.len(), result_slots(t));
        out.extend(emitted);
    }
    eyre::ensure!(
        out.len() == sites * result_slots(t),
        "Poseidon2(t={t}) emitted {} values, expected {}",
        out.len(),
        sites * result_slots(t)
    );
    Ok(out)
}

// --- rep3 ---

/// The correlated randomness [`Rep3Ops::sbox_layer`] consumes: `r` and its powers `r²..r⁵`, one
/// entry per element across the *whole* permutation batch (every s-box layer, every site),
/// prepared once by [`Rep3Ops::prepare_sboxes`] and consumed a slice at a time as layers run.
#[cfg(feature = "rep3")]
struct SboxPool<F: PrimeField> {
    r: Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>,
    r2: Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>,
    r3: Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>,
    r4: Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>,
    r5: Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>,
    /// How many elements of the pool have already been handed to a `sbox_layer` call.
    consumed: usize,
}

/// rep3 backend. The s-box uses the masked-opening trick (see [`Rep3Ops::sbox_layer`]) so a whole
/// layer costs **one** network round instead of the three a naive `x^2, x^4, x^5` chain needs.
#[cfg(feature = "rep3")]
struct Rep3Ops<'a, F: PrimeField, N: mpc_net::Network> {
    net: &'a N,
    state: &'a mut mpc_core::protocols::rep3::Rep3State,
    /// Populated by `prepare_sboxes` before `walk`'s round loop runs; `None` only before that call.
    pool: Option<SboxPool<F>>,
}

#[cfg(feature = "rep3")]
impl<F: PrimeField, N: mpc_net::Network> Ops<F> for Rep3Ops<'_, F, N> {
    type V = mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>;

    fn public(&mut self, c: F) -> Self::V {
        mpc_core::protocols::rep3::arithmetic::promote_to_trivial_share(self.state.id, c)
    }
    fn add(&mut self, a: &Self::V, b: &Self::V) -> Self::V {
        mpc_core::protocols::rep3::arithmetic::add(*a, *b)
    }
    fn add_public(&mut self, a: &Self::V, c: F) -> Self::V {
        mpc_core::protocols::rep3::arithmetic::add_public(*a, c, self.state.id)
    }
    fn mul_public(&mut self, a: &Self::V, c: F) -> Self::V {
        mpc_core::protocols::rep3::arithmetic::mul_public(*a, c)
    }

    /// `r`, `r²`, `r³`, `r⁴`, `r⁵` for every element the whole permutation batch's s-box layers will
    /// need (see [`SboxPool`]), in 3 rounds total - independent of batch size, and done exactly
    /// once, before any layer runs. `r²..r⁵` depend only on `r`, not on any secret input, which is
    /// what makes hoisting this out of the per-layer [`Self::sbox_layer`] sound: a *disjoint* slice
    /// of this pool goes to each layer, so every (layer, element) still gets its own fresh `r` -
    /// reusing one `r` across two layers would leak `x₁ - x₂` from their two masked opens.
    fn prepare_sboxes(&mut self, total_elements: usize) -> eyre::Result<()> {
        use mpc_core::protocols::rep3::arithmetic;

        let n = total_elements;
        let r: Vec<Self::V> = (0..n).map(|_| arithmetic::rand(self.state)).collect();
        let r2 = arithmetic::mul_vec(&r, &r, self.net, self.state)?;
        let r4 = arithmetic::mul_vec(&r2, &r2, self.net, self.state)?;
        let (lhs, rhs): (Vec<_>, Vec<_>) = r
            .iter()
            .copied()
            .chain(r.iter().copied())
            .zip(r2.iter().copied().chain(r4.iter().copied()))
            .unzip();
        let r35 = arithmetic::mul_vec(&lhs, &rhs, self.net, self.state)?;
        let (r3, r5) = r35.split_at(n);

        self.pool = Some(SboxPool {
            r,
            r2,
            r3: r3.to_vec(),
            r4,
            r5: r5.to_vec(),
            consumed: 0,
        });
        Ok(())
    }

    /// `x^2`, `x^4` and `x^5` are genuinely sequential as multiplications - from `{x, x^2}` the
    /// second round can only reach degree 4 - so a naive layer is 3 rounds, i.e. `3 * (8 + pr)` for
    /// the whole permutation (192 at t=3).
    ///
    /// Instead, mask and open: with `r` (and `r^2..r^5`, prepared once for the entire batch by
    /// [`Self::prepare_sboxes`]), publish `y = x - r` in **one** round; then `x = y + r` makes all
    /// three intermediates local linear combinations by binomial expansion. `y` is public and `r`
    /// uniform and unknown, so nothing about `x` leaks. This is mpc-core's own `sbox_rep3_precomp`
    /// trick, extended to also emit `square` and `pow_4` - which is exactly why it composes with a
    /// *full* trace at no extra round cost (mpc-core only ever needed `x^5`).
    fn sbox_layer(&mut self, xs: &[Self::V]) -> eyre::Result<Vec<SboxTrace<Self::V>>> {
        use mpc_core::protocols::rep3::arithmetic;

        let n = xs.len();
        let pool = self
            .pool
            .as_mut()
            .ok_or_else(|| eyre::eyre!("sbox_layer called before prepare_sboxes"))?;
        eyre::ensure!(
            pool.consumed + n <= pool.r.len(),
            "sbox randomness pool exhausted: {} elements requested, {} remain",
            n,
            pool.r.len() - pool.consumed
        );
        let start = pool.consumed;
        let end = start + n;
        pool.consumed = end;
        let (r, r2, r3, r4, r5) = (
            &pool.r[start..end],
            &pool.r2[start..end],
            &pool.r3[start..end],
            &pool.r4[start..end],
            &pool.r5[start..end],
        );

        // The one round that scales with the layer.
        let masked: Vec<Self::V> = xs
            .iter()
            .zip(r)
            .map(|(x, r)| arithmetic::sub(*x, *r))
            .collect();
        let y = arithmetic::open_vec(&masked, self.net)?;

        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let (y, r, r2, r3, r4, r5) = (y[i], r[i], r2[i], r3[i], r4[i], r5[i]);
            let y2 = y * y;
            let y3 = y2 * y;
            let y4 = y3 * y;
            let y5 = y4 * y;

            // x^2 = y^2 + 2yr + r2
            let mut square = arithmetic::mul_public(r, y.double());
            square = arithmetic::add(square, r2);
            square = arithmetic::add_public(square, y2, self.state.id);

            // x^4 = y^4 + 4y^3 r + 6y^2 r2 + 4y r3 + r4
            let mut pow4 = arithmetic::mul_public(r, y3 * F::from(4u64));
            pow4 = arithmetic::add(pow4, arithmetic::mul_public(r2, y2 * F::from(6u64)));
            pow4 = arithmetic::add(pow4, arithmetic::mul_public(r3, y * F::from(4u64)));
            pow4 = arithmetic::add(pow4, r4);
            pow4 = arithmetic::add_public(pow4, y4, self.state.id);

            // x^5 = y^5 + 5y^4 r + 10y^3 r2 + 10y^2 r3 + 5y r4 + r5
            let mut fifth = arithmetic::mul_public(r, y4 * F::from(5u64));
            fifth = arithmetic::add(fifth, arithmetic::mul_public(r2, y3 * F::from(10u64)));
            fifth = arithmetic::add(fifth, arithmetic::mul_public(r3, y2 * F::from(10u64)));
            fifth = arithmetic::add(fifth, arithmetic::mul_public(r4, y * F::from(5u64)));
            fifth = arithmetic::add(fifth, r5);
            fifth = arithmetic::add_public(fifth, y5, self.state.id);

            out.push(SboxTrace {
                square,
                pow4,
                out: fifth,
            });
        }
        Ok(out)
    }
}

/// The rep3 twin of [`plain_trace`]: one call services an entire batch, and every site rides the same
/// network rounds - `3 + (8 + partial_rounds(t))` in total, independent of the number of sites.
#[cfg(feature = "rep3")]
pub fn rep3_trace<F: PrimeField, N: mpc_net::Network>(
    t: usize,
    states: &[mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>],
    net: &N,
    rep3_state: &mut mpc_core::protocols::rep3::Rep3State,
) -> eyre::Result<Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>> {
    let sites = check_width(t, states.len())?;
    let rc = RoundConstants::load(t)?;
    let mut ops = Rep3Ops {
        net,
        state: rep3_state,
        pool: None,
    };
    let traces = walk(&mut ops, t, states, &rc)?;
    let mut out = Vec::with_capacity(sites * result_slots(t));
    for site in &traces {
        out.extend(emit_site(t, site));
    }
    eyre::ensure!(
        out.len() == sites * result_slots(t),
        "Poseidon2(t={t}) emitted {} values, expected {}",
        out.len(),
        sites * result_slots(t)
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;

    use super::*;

    /// The emitted length must match what `ir::PrecomputeKind` promises, for every width - otherwise
    /// `frontend/inline.rs`'s cross-check against the circuit's real signal span would be comparing
    /// against a number this module doesn't honor.
    #[test]
    fn emitted_length_matches_the_declared_result_count() {
        for t in SUPPORTED_WIDTHS {
            let states = vec![Fr::from(1u64); t];
            let got = plain_trace(t, &states).unwrap();
            assert_eq!(
                got.len(),
                crate::ir::PrecomputeKind::Poseidon2 { t }
                    .expected_results()
                    .expect("Poseidon2 has a closed-form result count"),
                "t={t}"
            );
        }
        // The one width with a golden witness to anchor against.
        assert_eq!(total_signals(3), 2038);
        assert_eq!(result_slots(3), 2035);
    }

    #[test]
    fn batching_is_just_concatenation() {
        let t = 3;
        let a = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let b = [Fr::from(4u64), Fr::from(5u64), Fr::from(6u64)];
        let mut expected = plain_trace(t, &a).unwrap();
        expected.extend(plain_trace(t, &b).unwrap());

        let both: Vec<Fr> = a.iter().chain(&b).copied().collect();
        assert_eq!(plain_trace(t, &both).unwrap(), expected);
    }

    #[test]
    fn rejects_unsupported_width_and_ragged_input() {
        assert!(plain_trace(5, &[Fr::from(0u64); 5]).is_err());
        assert!(plain_trace::<Fr>(3, &[]).is_err());
        assert!(plain_trace(3, &[Fr::from(0u64); 4]).is_err());
    }

    /// Guards the vendored constant tables against drifting from the circuit they were copied from.
    #[test]
    fn tables_match_the_circom_source() {
        let src = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/circuits/libs/taceo/poseidon2_constants.circom"
        ))
        .expect("the vendored constants circuit must be readable");
        for t in SUPPORTED_WIDTHS {
            let rc = RoundConstants::<Fr>::load(t).unwrap();
            assert_eq!(rc.full1.len(), 4 * t, "t={t} rc_full1");
            assert_eq!(rc.full2.len(), 4 * t, "t={t} rc_full2");
            assert_eq!(rc.partial.len(), partial_rounds(t), "t={t} rc_partial");
            assert_eq!(
                rc.diag.len(),
                if t >= 4 { t } else { 0 },
                "t={t} diag (widths 2 and 3 have no diagonal)"
            );
            // Every constant this module holds must literally appear in the circuit file.
            for c in rc.full1.iter().chain(&rc.full2).chain(&rc.partial).chain(&rc.diag) {
                let hex = format!("{:064x}", Into::<num_bigint::BigUint>::into(*c));
                assert!(
                    src.contains(&hex),
                    "constant 0x{hex} (t={t}) is not present in poseidon2_constants.circom"
                );
            }
        }
    }

    #[cfg(feature = "rep3")]
    #[test]
    fn rep3_agrees_with_plain_across_widths_and_sites() {
        use crate::vm::gadgets::test_support::run3;

        // Two sites per width, so this covers batching as well as the arithmetic.
        for t in SUPPORTED_WIDTHS {
            let states: Vec<Fr> = (0..2 * t).map(|i| Fr::from(i as u64 + 1)).collect();
            let expected = plain_trace(t, &states).unwrap();
            let got = run3(&states, |net, state, shares| {
                rep3_trace(t, shares, net, state)
            });
            assert_eq!(got, expected, "t={t}");
        }
    }

    /// Pins the round claim in `rep3_trace`'s doc: `3 + 8 + partial_rounds(t)`, the same for every
    /// site count in a batch.
    #[cfg(all(feature = "rep3", feature = "round-counting"))]
    #[test]
    fn rep3_costs_three_plus_eight_plus_partial_rounds_independent_of_sites() {
        use crate::vm::gadgets::test_support::run3_counted;

        for t in SUPPORTED_WIDTHS {
            let expected_rounds = 3 + 8 + partial_rounds(t);
            for sites in [1, 3] {
                let states: Vec<Fr> = (0..sites * t).map(|i| Fr::from(i as u64 + 1)).collect();
                let (_, rounds) = run3_counted(&states, |net, state, shares| rep3_trace(t, shares, net, state));
                assert_eq!(rounds, expected_rounds, "t={t} sites={sites}");
            }
        }
    }
}
