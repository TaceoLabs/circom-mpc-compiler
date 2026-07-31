//! Poseidon2 permutation traces for `circuits/libs/taceo/poseidon2.circom`, computed from **that
//! template's own signal layout**, for every width the circuit defines
//! (`t ∈ {2, 3, 4, 8, 12, 16}`).
//!
//! # The layout rule
//!
//! circom lays out each component as
//! `[outputs][inputs][own intermediates, in source-declaration order][subcomponent subtrees]`, and -
//! the part that is easy to get wrong - **sibling subcomponent subtrees are ordered by the *callee
//! template's own definition order in the source file*, not by the order their creating statements
//! execute within the caller.** Four consequences, all confirmed against a passing proof:
//!
//! - `FullRound` emits its `ExternalMatMulT` subtree *before* its `Sbox` subtree, even though the
//!   source instantiates `Sbox` first: `ExternalMatMulT` is defined earlier in the file.
//! - `ExternalMatMulT`'s own `t >= 8` branch emits its 4 `Acc(t/4)` subtrees *before* its `t/4`
//!   `ExternalMatMul4` subtrees, even though the source creates `mds[]` (the `ExternalMatMul4`s)
//!   before `accs[]` (the `Acc`s): `template Acc(t)` is defined before `template ExternalMatMul4` in
//!   `poseidon2.circom`. Verified directly against circom's own R1CS for `t=16` - the only width
//!   that reaches this branch (`t/4 >= 2`) among the widths this repo exercises.
//! - `Poseidon2` emits all 8 `FullRound` blocks contiguously and only then all `PartialRound` blocks
//!   - so **layout order is not execution order**, since rounds 5..(4+pr) run between them.
//! - Within one template, *same-definition* sibling instances keep their own creation order: the 8
//!   full rounds are the first group's 4 followed by the second group's 4, and `accs[0..4]`/
//!   `mds[0..4]` are each in their own loop's `l`/`i` order.
//!
//! Verified for t=3 (2045 witness entries) by `tests/proving.rs`'s
//! `precomputation_poseidon2_test`, which is the real oracle for all of this.
//!
//! # Structure
//!
//! Three separated concerns, so the layout exists in exactly one place (unlike `super::aliascheck`,
//! which duplicates its much smaller layout between the plain and rep3 paths):
//!
//! - `Ops` - the arithmetic backend, implemented once for plain field elements and once for rep3
//!   shares. During the walk, only `Ops::sbox_layer` communicates; rep3 pool preprocessing happens
//!   separately, before online execution.
//! - `walk` - the permutation itself, **layer-major across every site in lock-step**, so all of a
//!   batch's s-boxes at one round go into a single `sbox_layer` call.
//! - `SiteOutput` - a sparse layout sink. It records a value only when its logical result slot was
//!   requested, while `walk` still computes every value needed to evolve the permutation state.

use ark_ff::PrimeField;

use super::poseidon2_constants::{partial_rounds, RoundConstants};

/// The widths `circuits/libs/taceo/poseidon2.circom` defines constants for:
/// `{2, 3, 4, 8, 12, 16}`.
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
            // 4 x Acc(m), then m x ExternalMatMul4 - in that order, per the instance-id rule (a sum,
            // so the two terms' order here doesn't matter; see `external_matmul` for where it does).
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

enum SiteSelection<'a> {
    All,
    Requested(&'a [u32]),
}

/// Index-addressed output for one site. The witness layout is not execution ordered: the second
/// full-round group executes after the partial rounds but precedes them in signal order. Directly
/// addressing requested logical slots preserves that layout without retaining whole round blocks.
struct SiteOutput<'a, V> {
    selection: SiteSelection<'a>,
    values: Vec<Option<V>>,
    capacity: usize,
}

impl<'a, V: Clone> SiteOutput<'a, V> {
    fn all(capacity: usize) -> Self {
        Self {
            selection: SiteSelection::All,
            values: vec![None; capacity],
            capacity,
        }
    }

    fn requested(capacity: usize, requests: &'a [u32]) -> Self {
        Self {
            selection: SiteSelection::Requested(requests),
            values: vec![None; requests.len()],
            capacity,
        }
    }

    fn destination(&self, logical: usize) -> Option<usize> {
        debug_assert!(logical < self.capacity);
        match self.selection {
            SiteSelection::All => Some(logical),
            SiteSelection::Requested(requests) => requests.binary_search(&(logical as u32)).ok(),
        }
    }

    fn wants(&self, logical: usize) -> bool {
        self.destination(logical).is_some()
    }

    fn record(&mut self, logical: usize, value: &V) {
        if let Some(destination) = self.destination(logical) {
            self.values[destination] = Some(value.clone());
        }
    }

    fn record_owned(&mut self, logical: usize, value: V) {
        if let Some(destination) = self.destination(logical) {
            self.values[destination] = Some(value);
        }
    }

    fn record_slice(&mut self, start: usize, values: &[V]) {
        for (offset, value) in values.iter().enumerate() {
            self.record(start + offset, value);
        }
    }

    fn finish(self, site: usize) -> eyre::Result<Vec<V>> {
        self.values
            .into_iter()
            .enumerate()
            .map(|(position, value)| {
                value.ok_or_else(|| {
                    eyre::eyre!(
                        "Poseidon2 site {site} did not emit requested result position {position}"
                    )
                })
            })
            .collect()
    }
}

/// Starts of the four sections in one site's logical result layout. The site's top-level inputs are
/// supplied by the caller and therefore omitted from the result slots.
struct Layout {
    states: usize,
    initial_matmul: usize,
    full: usize,
    partial: usize,
}

impl Layout {
    fn new(t: usize) -> Self {
        let pr = partial_rounds(t);
        let states = t;
        let initial_matmul = states + (9 + pr) * t;
        let full = initial_matmul + external_matmul_signals(t);
        let partial = full + 8 * full_round_signals(t);
        debug_assert_eq!(partial + pr * partial_round_signals(t), result_slots(t));
        Self {
            states,
            initial_matmul,
            full,
            partial,
        }
    }
}

/// `Acc(n)` over `input`. Records `[out][in[n]][sums[n]]` at `base`, while retaining only the
/// running sum needed by state evolution.
fn acc<F: PrimeField, O: Ops<F>>(
    ops: &mut O,
    input: &[O::V],
    trace: &mut SiteOutput<'_, O::V>,
    base: usize,
) -> O::V {
    let n = input.len();
    trace.record_slice(base + 1, input);
    let mut sum = input[0].clone();
    trace.record(base + 1 + n, &sum);
    for (i, x) in input[1..].iter().enumerate() {
        sum = ops.add(&sum, x);
        trace.record(base + 1 + n + i + 1, &sum);
    }
    trace.record(base, &sum);
    sum
}

/// `ExternalMatMul2`/`3`/`4` over exactly 2, 3 or 4 elements.
fn external_matmul_leaf<F: PrimeField, O: Ops<F>>(
    ops: &mut O,
    input: &[O::V],
    trace: &mut SiteOutput<'_, O::V>,
    base: usize,
) -> Vec<O::V> {
    let two = F::from(2u64);
    let four = F::from(4u64);
    let t = input.len();
    trace.record_slice(base + t, input);
    let out = match t {
        2 | 3 => {
            // out[i] = in[i] + sum
            let mut sum = input[0].clone();
            for x in &input[1..] {
                sum = ops.add(&sum, x);
            }
            let out: Vec<O::V> = input.iter().map(|x| ops.add(x, &sum)).collect();
            trace.record(base + 2 * t, &sum);
            out
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
            // Source-declaration order of the 10 named intermediates.
            for (i, value) in [
                &double_in1,
                &double_in3,
                &t_0,
                &t_1,
                &quad_t_0,
                &quad_t_1,
                &t_2,
                &t_3,
                &t_4,
                &t_5,
            ]
            .into_iter()
            .enumerate()
            {
                trace.record(base + 2 * t + i, value);
            }
            out
        }
        n => unreachable!("external_matmul_leaf takes 2, 3 or 4 elements, got {n}"),
    };
    trace.record_slice(base, &out);
    out
}

/// `ExternalMatMulT(t)`: `[out[t]][in[t]][subtree]`.
fn external_matmul<F: PrimeField, O: Ops<F>>(
    ops: &mut O,
    input: &[O::V],
    trace: &mut SiteOutput<'_, O::V>,
    base: usize,
) -> Vec<O::V> {
    let t = input.len();
    trace.record_slice(base + t, input);
    let out = if t <= 4 {
        external_matmul_leaf(ops, input, trace, base + 2 * t)
    } else {
        let m = t / 4;
        // `mds[]` is created textually before `accs[]` in `ExternalMatMulT`'s source, but circom
        // orders sibling subcomponents by *template definition order in the file*, not by
        // creation-statement order within the enclosing body - `template Acc(t)` is defined before
        // `template ExternalMatMul4` in `poseidon2.circom`, so every `accs[]` instance is numbered
        // before every `mds[]` instance. Cross-checked against a real circom witness
        // (`main.Poseidon2_..ExternalMatMulT_...accs[0].out` precedes `.mds[0].out[0]`).
        let mut mds_out = Vec::with_capacity(m);
        let accs_base = base + 2 * t;
        let mds_base = accs_base + 4 * acc_signals(m);
        for i in 0..m {
            let o = external_matmul_leaf(
                ops,
                &input[4 * i..4 * i + 4],
                trace,
                mds_base + i * external_matmul_leaf_signals(4),
            );
            mds_out.push(o);
        }
        let mut acc_out = Vec::with_capacity(4);
        for l in 0..4 {
            let column: Vec<O::V> = mds_out.iter().map(|row| row[l].clone()).collect();
            let o = acc(ops, &column, trace, accs_base + l * acc_signals(m));
            acc_out.push(o);
        }
        let mut out = Vec::with_capacity(t);
        for row in &mds_out {
            for (j, value) in row.iter().enumerate() {
                out.push(ops.add(value, &acc_out[j]));
            }
        }
        out
    };
    trace.record_slice(base, &out);
    out
}

/// `InternalMatMul2`/`3` - a genuine nested subcomponent for those widths, hence its own block
/// (`[out[t]][in[t]][sum]`) rather than inlined arithmetic.
fn internal_matmul_leaf<F: PrimeField, O: Ops<F>>(
    ops: &mut O,
    input: &[O::V],
    trace: &mut SiteOutput<'_, O::V>,
    base: usize,
) -> Vec<O::V> {
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
    trace.record_slice(base, &out);
    trace.record_slice(base + t, input);
    trace.record(base + 2 * t, &sum);
    out
}

/// `InternalMatMulT(t)`: `[out[t]][in[t]]` plus either a nested `InternalMatMul2`/`3` subcomponent, or
/// (for `t >= 4`) the own intermediate `acc` followed by its `Acc(t)` subtree.
fn internal_matmul<F: PrimeField, O: Ops<F>>(
    ops: &mut O,
    input: &[O::V],
    diag: &[F],
    trace: &mut SiteOutput<'_, O::V>,
    base: usize,
) -> Vec<O::V> {
    let t = input.len();
    trace.record_slice(base + t, input);
    let out = match t {
        2..=3 => internal_matmul_leaf(ops, input, trace, base + 2 * t),
        _ => {
            let acc_value = acc(ops, input, trace, base + 2 * t + 1);
            let out: Vec<O::V> = input
                .iter()
                .zip(diag)
                .map(|(x, &d)| {
                    let scaled = ops.mul_public(x, d);
                    ops.add(&scaled, &acc_value)
                })
                .collect();
            // Own intermediate `acc` precedes the `Acc(t)` subtree.
            trace.record(base + 2 * t, &acc_value);
            out
        }
    };
    trace.record_slice(base, &out);
    out
}

/// Records `Sbox_e`'s block: `[out][in][square][pow_4]`.
fn record_sbox_e<V: Clone>(
    output: &mut SiteOutput<'_, V>,
    base: usize,
    input: &V,
    trace: &SboxTrace<V>,
) {
    output.record(base, &trace.out);
    output.record(base + 1, input);
    output.record(base + 2, &trace.square);
    output.record(base + 3, &trace.pow4);
}

/// Runs the permutation for every site in `states` (each `t` elements, concatenated) in lock-step,
/// so each round's s-boxes across the whole batch are one [`Ops::sbox_layer`] call.
fn walk<F: PrimeField, O: Ops<F>>(
    ops: &mut O,
    t: usize,
    states: &[O::V],
    rc: &RoundConstants<F>,
    mut outputs: Vec<SiteOutput<'_, O::V>>,
) -> eyre::Result<Vec<O::V>> {
    let sites = states.len() / t;
    let pr = partial_rounds(t);
    let layout = Layout::new(t);
    debug_assert_eq!(outputs.len(), sites);

    // Current state per site. Witness values are recorded directly into `outputs`; no round or
    // subcomponent trace blocks are materialized.
    let mut current: Vec<Vec<O::V>> = Vec::with_capacity(sites);
    for site in 0..sites {
        let input = &states[site * t..(site + 1) * t];
        let out = external_matmul(ops, input, &mut outputs[site], layout.initial_matmul);
        outputs[site].record_slice(layout.states, &out);
        current.push(out);
    }

    // A full round, for every site at once: add RC, one s-box layer, external matrix.
    let full_round = |ops: &mut O,
                      current: &mut Vec<Vec<O::V>>,
                      outputs: &mut Vec<SiteOutput<'_, O::V>>,
                      round_rc: &[F],
                      layout_round: usize,
                      state_row: usize|
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
            let base = layout.full + layout_round * full_round_signals(t);
            let emm_base = base + 5 * t;
            let out = external_matmul(ops, &sbox_out, &mut outputs[site], emm_base);

            // [out][in][RC][linear_layer][sbox] + ExternalMatMulT + Sbox
            outputs[site].record_slice(base, &out);
            outputs[site].record_slice(base + t, state);
            for (i, &c) in round_rc.iter().enumerate() {
                let logical = base + 2 * t + i;
                if outputs[site].wants(logical) {
                    let value = ops.public(c);
                    outputs[site].record_owned(logical, value);
                }
            }
            outputs[site].record_slice(base + 3 * t, &linear[site]);
            outputs[site].record_slice(base + 4 * t, &sbox_out);
            // Sbox(t)'s own block: [out[t]][in[t]] + t x Sbox_e
            let sbox_base = emm_base + external_matmul_signals(t);
            outputs[site].record_slice(sbox_base, &sbox_out);
            outputs[site].record_slice(sbox_base + t, &linear[site]);
            for (k, s) in sbox_traces.iter().enumerate() {
                record_sbox_e(
                    &mut outputs[site],
                    sbox_base + 2 * t + k * SBOX_E_SIGNALS,
                    &linear[site][k],
                    s,
                );
            }

            outputs[site].record_slice(layout.states + state_row * t, &out);
            *state = out;
        }
        Ok(())
    };

    for round in 0..4 {
        let round_rc = &rc.full1[round * t..(round + 1) * t];
        full_round(ops, &mut current, &mut outputs, round_rc, round, round + 1)?;
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
            let base = layout.partial + round * partial_round_signals(t);
            let imm_base = base + 2 * t + 3 + SBOX_E_SIGNALS;
            let out = internal_matmul(ops, &imm_input, &rc.diag, &mut outputs[site], imm_base);

            // [out][in][RC][linear_layer][sbox] + Sbox_e + InternalMatMulT
            outputs[site].record_slice(base, &out);
            outputs[site].record_slice(base + t, state);
            let rc_slot = base + 2 * t;
            if outputs[site].wants(rc_slot) {
                let rc_value = ops.public(c);
                outputs[site].record_owned(rc_slot, rc_value);
            }
            outputs[site].record(base + 2 * t + 1, &linear[site]);
            outputs[site].record(base + 2 * t + 2, &sbox.out);
            record_sbox_e(&mut outputs[site], base + 2 * t + 3, &linear[site], sbox);

            outputs[site].record_slice(layout.states + (5 + round) * t, &out);
            *state = out;
        }
    }

    for round in 0..4 {
        let round_rc = &rc.full2[round * t..(round + 1) * t];
        full_round(
            ops,
            &mut current,
            &mut outputs,
            round_rc,
            4 + round,
            5 + pr + round,
        )?;
    }

    // Top-level `[out[t]]`, known only after the second full-round group.
    for (site, state) in current.iter().enumerate() {
        outputs[site].record_slice(0, state);
    }

    let expected = outputs.iter().map(|output| output.values.len()).sum();
    let mut result = Vec::with_capacity(expected);
    for (site, output) in outputs.into_iter().enumerate() {
        result.extend(output.finish(site)?);
    }
    Ok(result)
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

fn requested_outputs<'a, V: Clone>(
    sites: usize,
    capacity: usize,
    requests: &'a [u32],
    offsets: &[u32],
) -> eyre::Result<Vec<SiteOutput<'a, V>>> {
    eyre::ensure!(
        offsets.len() == sites + 1,
        "Poseidon2 request offsets has length {}, expected {} for {sites} sites",
        offsets.len(),
        sites + 1
    );
    eyre::ensure!(
        offsets[0] == 0,
        "Poseidon2 request offsets must start at zero"
    );
    eyre::ensure!(
        offsets[sites] as usize == requests.len(),
        "Poseidon2 final request offset is {}, but there are {} requests",
        offsets[sites],
        requests.len()
    );

    let mut outputs = Vec::with_capacity(sites);
    for site in 0..sites {
        let lo = offsets[site] as usize;
        let hi = offsets[site + 1] as usize;
        eyre::ensure!(
            lo <= hi && hi <= requests.len(),
            "Poseidon2 site {site} has invalid request range {lo}..{hi}"
        );
        let site_requests = &requests[lo..hi];
        for pair in site_requests.windows(2) {
            eyre::ensure!(
                pair[0] < pair[1],
                "Poseidon2 site {site} result requests must be strictly ascending"
            );
        }
        if let Some(&last) = site_requests.last() {
            eyre::ensure!(
                (last as usize) < capacity,
                "Poseidon2 site {site} requested result slot {last}, but capacity is {capacity}"
            );
        }
        outputs.push(SiteOutput::requested(capacity, site_requests));
    }
    Ok(outputs)
}

/// Plain traces for a whole batch: `states` is `sites * t` values (one length-`t` state per site,
/// concatenated), and the result is `sites * result_slots(t)` values in `Machine::precompute`'s slot
/// order.
pub fn plain_trace<F: PrimeField>(t: usize, states: &[F]) -> eyre::Result<Vec<F>> {
    let sites = check_width(t, states.len())?;
    let capacity = result_slots(t);
    let rc = RoundConstants::load(t)?;
    let outputs = (0..sites).map(|_| SiteOutput::all(capacity)).collect();
    let out = walk(&mut PlainOps, t, states, &rc, outputs)?;
    eyre::ensure!(
        out.len() == sites * capacity,
        "Poseidon2(t={t}) emitted {} values, expected {}",
        out.len(),
        sites * capacity
    );
    Ok(out)
}

/// Computes only the requested logical trace slots for each site. `result_offsets` is a CSR row
/// pointer of length `sites + 1`; each site's request row must be strictly ascending and contain
/// slots in `0..result_slots(t)`. The returned values are site-major in exactly that CSR order.
///
/// All permutation state and s-box layers are still evaluated, because they feed later rounds. The
/// optimization is that witness-dead state copies, round constants, and subcomponent intermediates
/// are never materialized in the returned trace.
pub fn plain_trace_requested<F: PrimeField>(
    t: usize,
    states: &[F],
    result_requests: &[u32],
    result_offsets: &[u32],
) -> eyre::Result<Vec<F>> {
    let sites = check_width(t, states.len())?;
    let capacity = result_slots(t);
    let outputs = requested_outputs(sites, capacity, result_requests, result_offsets)?;
    let rc = RoundConstants::load(t)?;
    walk(&mut PlainOps, t, states, &rc, outputs)
}

// --- rep3 ---

/// Number of fresh masks one Poseidon2 service consumes. There are eight full-round s-box layers
/// of `t` elements and `partial_rounds(t)` one-element partial layers for every site.
///
/// Kept separate from the trace entry points because [`crate::vm::Program`] derives one checked,
/// program-wide preprocessing budget from the *executable* shared-Poseidon instruction
/// occurrences before a run starts.
#[cfg(feature = "rep3")]
pub(crate) fn mask_elements(t: usize, sites: usize) -> eyre::Result<usize> {
    eyre::ensure!(
        SUPPORTED_WIDTHS.contains(&t),
        "unsupported Poseidon2 width t={t} - circuits/libs/taceo/poseidon2.circom only defines \
         {SUPPORTED_WIDTHS:?}"
    );
    let full = t
        .checked_mul(8)
        .ok_or_else(|| eyre::eyre!("Poseidon2(t={t}) full-round mask count overflows"))?;
    let per_site = full
        .checked_add(partial_rounds(t))
        .ok_or_else(|| eyre::eyre!("Poseidon2(t={t}) per-site mask count overflows"))?;
    sites
        .checked_mul(per_site)
        .ok_or_else(|| eyre::eyre!("Poseidon2(t={t}) mask budget overflows for {sites} sites"))
}

/// The correlated randomness [`Rep3Ops::sbox_layer`] consumes: `r` and its powers `r²..r⁵`, one
/// entry per s-box element across every shared Poseidon2 service in one program execution. The
/// pool is prepared once, then disjoint slices are consumed in instruction order.
#[cfg(feature = "rep3")]
pub(crate) struct Rep3Poseidon2Preprocessing<F: PrimeField> {
    r: Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>,
    r2: Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>,
    r3: Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>,
    r4: Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>,
    r5: Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>,
    /// How many elements of the pool have already been handed to a `sbox_layer` call.
    consumed: usize,
}

#[cfg(feature = "rep3")]
impl<F: PrimeField> Rep3Poseidon2Preprocessing<F> {
    fn ensure_available(&self, count: usize) -> eyre::Result<()> {
        let end = self
            .consumed
            .checked_add(count)
            .ok_or_else(|| eyre::eyre!("Poseidon2 mask-pool cursor overflows"))?;
        eyre::ensure!(
            end <= self.r.len(),
            "Poseidon2 mask pool exhausted: {count} elements requested, {} remain",
            self.r.len().saturating_sub(self.consumed)
        );
        Ok(())
    }

    /// Verifies the one-shot driver consumed exactly the executable program's derived budget.
    pub(crate) fn ensure_consumed(&self) -> eyre::Result<()> {
        eyre::ensure!(
            self.consumed == self.r.len(),
            "Poseidon2 mask pool consumption mismatch: consumed {}, prepared {}",
            self.consumed,
            self.r.len()
        );
        Ok(())
    }
}

/// Prepares `r, r², r³, r⁴, r⁵` for a complete program execution in exactly three rounds,
/// independent of `total_elements`. A zero budget is represented by empty vectors and performs no
/// network operation.
#[cfg(feature = "rep3")]
pub(crate) fn preprocess_rep3<F: PrimeField, N: mpc_net::Network>(
    total_elements: usize,
    net: &N,
    state: &mut mpc_core::protocols::rep3::Rep3State,
) -> eyre::Result<Rep3Poseidon2Preprocessing<F>> {
    use mpc_core::protocols::rep3::arithmetic;

    if total_elements == 0 {
        return Ok(Rep3Poseidon2Preprocessing {
            r: Vec::new(),
            r2: Vec::new(),
            r3: Vec::new(),
            r4: Vec::new(),
            r5: Vec::new(),
            consumed: 0,
        });
    }

    let n = total_elements;
    let combined = n
        .checked_mul(2)
        .ok_or_else(|| eyre::eyre!("Poseidon2 power-preprocessing vector length overflows"))?;
    let r: Vec<_> = (0..n).map(|_| arithmetic::rand(state)).collect();
    let r2 = arithmetic::mul_vec(&r, &r, net, state)?;
    let r4 = arithmetic::mul_vec(&r2, &r2, net, state)?;
    let mut lhs = Vec::with_capacity(combined);
    lhs.extend(r.iter().copied());
    lhs.extend(r.iter().copied());
    let mut rhs = Vec::with_capacity(combined);
    rhs.extend(r2.iter().copied());
    rhs.extend(r4.iter().copied());
    let mut r35 = arithmetic::mul_vec(&lhs, &rhs, net, state)?;
    drop(lhs);
    drop(rhs);
    let r5 = r35.split_off(n);
    let r3 = r35;

    Ok(Rep3Poseidon2Preprocessing {
        r,
        r2,
        r3,
        r4,
        r5,
        consumed: 0,
    })
}

/// rep3 backend. The s-box uses the masked-opening trick (see [`Rep3Ops::sbox_layer`]) so a whole
/// layer costs **one** network round instead of the three a naive `x^2, x^4, x^5` chain needs.
#[cfg(feature = "rep3")]
struct Rep3Ops<'a, F: PrimeField, N: mpc_net::Network> {
    net: &'a N,
    state: &'a mut mpc_core::protocols::rep3::Rep3State,
    pool: &'a mut Rep3Poseidon2Preprocessing<F>,
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

    /// `x^2`, `x^4` and `x^5` are genuinely sequential as multiplications - from `{x, x^2}` the
    /// second round can only reach degree 4 - so a naive layer is 3 rounds, i.e. `3 * (8 + pr)` for
    /// the whole permutation (192 at t=3).
    ///
    /// Instead, mask and open: with `r` (and `r^2..r^5`, prepared once for the entire run by
    /// [`preprocess_rep3`]), publish `y = x - r` in **one** round; then `x = y + r` makes all
    /// three intermediates local linear combinations by binomial expansion. `y` is public and `r`
    /// uniform and unknown, so nothing about `x` leaks. This is mpc-core's own `sbox_rep3_precomp`
    /// trick, extended to also emit `square` and `pow_4` - which is exactly why it composes with a
    /// *full* trace at no extra round cost (mpc-core only ever needed `x^5`).
    fn sbox_layer(&mut self, xs: &[Self::V]) -> eyre::Result<Vec<SboxTrace<Self::V>>> {
        use mpc_core::protocols::rep3::arithmetic;

        let n = xs.len();
        self.pool.ensure_available(n)?;
        let pool = &mut self.pool;
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

/// Internal full-trace path backed by a caller-owned, program-wide preprocessing pool. It spends
/// only the online `8 + partial_rounds(t)` rounds; preparation is deliberately outside this call.
#[cfg(feature = "rep3")]
pub(crate) fn rep3_trace_preprocessed<F: PrimeField, N: mpc_net::Network>(
    t: usize,
    states: &[mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>],
    net: &N,
    rep3_state: &mut mpc_core::protocols::rep3::Rep3State,
    preprocessing: &mut Rep3Poseidon2Preprocessing<F>,
) -> eyre::Result<Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>> {
    let sites = check_width(t, states.len())?;
    let required = mask_elements(t, sites)?;
    preprocessing.ensure_available(required)?;
    let consumed_before = preprocessing.consumed;
    let capacity = result_slots(t);
    let rc = RoundConstants::load(t)?;
    let mut ops = Rep3Ops {
        net,
        state: rep3_state,
        pool: preprocessing,
    };
    let outputs = (0..sites).map(|_| SiteOutput::all(capacity)).collect();
    let out = walk(&mut ops, t, states, &rc, outputs)?;
    eyre::ensure!(
        ops.pool.consumed - consumed_before == required,
        "Poseidon2(t={t}) consumed {} masks, expected {required}",
        ops.pool.consumed - consumed_before
    );
    eyre::ensure!(
        out.len() == sites * capacity,
        "Poseidon2(t={t}) emitted {} values, expected {}",
        out.len(),
        sites * capacity
    );
    Ok(out)
}

/// Internal sparse-trace twin of [`rep3_trace_preprocessed`]. Request sparsity changes only local
/// trace retention; it consumes the same pool slice and online rounds as the full path.
#[cfg(feature = "rep3")]
pub(crate) fn rep3_trace_requested_preprocessed<F: PrimeField, N: mpc_net::Network>(
    t: usize,
    states: &[mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>],
    net: &N,
    rep3_state: &mut mpc_core::protocols::rep3::Rep3State,
    preprocessing: &mut Rep3Poseidon2Preprocessing<F>,
    result_requests: &[u32],
    result_offsets: &[u32],
) -> eyre::Result<Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>> {
    let sites = check_width(t, states.len())?;
    let required = mask_elements(t, sites)?;
    preprocessing.ensure_available(required)?;
    let consumed_before = preprocessing.consumed;
    let capacity = result_slots(t);
    let outputs = requested_outputs(sites, capacity, result_requests, result_offsets)?;
    let rc = RoundConstants::load(t)?;
    let mut ops = Rep3Ops {
        net,
        state: rep3_state,
        pool: preprocessing,
    };
    let out = walk(&mut ops, t, states, &rc, outputs)?;
    eyre::ensure!(
        ops.pool.consumed - consumed_before == required,
        "Poseidon2(t={t}) consumed {} masks, expected {required}",
        ops.pool.consumed - consumed_before
    );
    Ok(out)
}

/// Compatibility full-trace entry point. Direct gadget callers retain the historical behavior:
/// one fresh three-round preprocessing followed by the online permutation. VM execution uses the
/// internal preprocessed twin so all Poseidon2 services in a run share one freshly prepared pool.
#[cfg(feature = "rep3")]
pub fn rep3_trace<F: PrimeField, N: mpc_net::Network>(
    t: usize,
    states: &[mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>],
    net: &N,
    rep3_state: &mut mpc_core::protocols::rep3::Rep3State,
) -> eyre::Result<Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>> {
    let sites = check_width(t, states.len())?;
    let mut preprocessing = preprocess_rep3(mask_elements(t, sites)?, net, rep3_state)?;
    let out = rep3_trace_preprocessed(t, states, net, rep3_state, &mut preprocessing)?;
    preprocessing.ensure_consumed()?;
    Ok(out)
}

/// Compatibility sparse-trace entry point; see [`rep3_trace`].
#[cfg(feature = "rep3")]
pub fn rep3_trace_requested<F: PrimeField, N: mpc_net::Network>(
    t: usize,
    states: &[mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>],
    net: &N,
    rep3_state: &mut mpc_core::protocols::rep3::Rep3State,
    result_requests: &[u32],
    result_offsets: &[u32],
) -> eyre::Result<Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>> {
    let sites = check_width(t, states.len())?;
    let mut preprocessing = preprocess_rep3(mask_elements(t, sites)?, net, rep3_state)?;
    let out = rep3_trace_requested_preprocessed(
        t,
        states,
        net,
        rep3_state,
        &mut preprocessing,
        result_requests,
        result_offsets,
    )?;
    preprocessing.ensure_consumed()?;
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
        // The one width verified against circom's own R1CS (see the module doc).
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
    fn requested_trace_matches_filtering_full_trace_for_every_width() {
        let sites = 3;
        for t in SUPPORTED_WIDTHS {
            let states: Vec<Fr> = (0..sites * t)
                .map(|i| Fr::from((17 * i + 3) as u64))
                .collect();
            let full = plain_trace(t, &states).unwrap();
            let capacity = result_slots(t);

            let mut requests = Vec::new();
            let mut offsets = vec![0u32];
            // Site 0 requests everything, which checks that every layout path can address every
            // logical slot. Site 1 is genuinely sparse and crosses all major section boundaries.
            requests.extend((0..capacity).map(|slot| slot as u32));
            offsets.push(requests.len() as u32);
            let layout = Layout::new(t);
            let mut sparse_site = vec![
                0,
                t - 1,
                t,
                layout.initial_matmul.saturating_sub(1),
                layout.initial_matmul,
                layout.full.saturating_sub(1),
                layout.full,
                layout.partial.saturating_sub(1),
                layout.partial,
                capacity - 1,
            ];
            sparse_site.extend((1..capacity).step_by(97));
            sparse_site.sort_unstable();
            sparse_site.dedup();
            requests.extend(sparse_site.iter().map(|&slot| slot as u32));
            offsets.push(requests.len() as u32);
            // Site 2 deliberately requests nothing; it must still ride the same permutation batch.
            offsets.push(requests.len() as u32);

            let got = plain_trace_requested(t, &states, &requests, &offsets).unwrap();
            let mut expected = full[..capacity].to_vec();
            expected.extend(sparse_site.iter().map(|&slot| full[capacity + slot]));
            assert_eq!(got, expected, "t={t}");
        }
    }

    #[test]
    fn requested_trace_validates_its_csr() {
        let t = 3;
        let states = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let capacity = result_slots(t) as u32;

        assert!(plain_trace_requested(t, &states, &[0], &[0]).is_err());
        assert!(plain_trace_requested(t, &states, &[0], &[1, 1]).is_err());
        assert!(plain_trace_requested(t, &states, &[0], &[0, 0]).is_err());
        assert!(plain_trace_requested(t, &states, &[1, 0], &[0, 2]).is_err());
        assert!(plain_trace_requested(t, &states, &[capacity], &[0, 1]).is_err());

        assert_eq!(
            plain_trace_requested(t, &states, &[], &[0, 0]).unwrap(),
            Vec::<Fr>::new()
        );
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
            for c in rc
                .full1
                .iter()
                .chain(&rc.full2)
                .chain(&rc.partial)
                .chain(&rc.diag)
            {
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

    #[cfg(feature = "rep3")]
    #[test]
    fn rep3_requested_trace_matches_plain_filter() {
        use crate::vm::gadgets::test_support::run3;

        let t = 4;
        let sites = 2;
        let states: Vec<Fr> = (0..sites * t).map(|i| Fr::from(i as u64 + 11)).collect();
        let capacity = result_slots(t);
        let requests: Vec<u32> = [0, 3, 4, capacity / 2, capacity - 1, 1, 97, capacity - 2]
            .into_iter()
            .map(|slot| slot as u32)
            .collect();
        let offsets = [0, 5, 8];
        let expected = plain_trace_requested(t, &states, &requests, &offsets).unwrap();
        let got = run3(&states, |net, state, shares| {
            rep3_trace_requested(t, shares, net, state, &requests, &offsets)
        });
        assert_eq!(got, expected);
    }

    /// Exercises both internal entry points against their plain twins for every supported width.
    /// The two calls deliberately share one exactly-sized pool: checking the cursor after each call
    /// and exact exhaustion at the end pins the disjoint, consecutive slice contract.
    #[cfg(feature = "rep3")]
    #[test]
    fn preprocessed_full_and_sparse_traces_share_disjoint_pool_slices_across_widths() {
        use crate::vm::gadgets::test_support::run3;

        let sites = 2;
        for t in SUPPORTED_WIDTHS {
            let states: Vec<Fr> = (0..sites * t)
                .map(|i| Fr::from((13 * i + 5) as u64))
                .collect();
            let capacity = result_slots(t);
            let requests: Vec<u32> = [0, t - 1, t, capacity / 2, capacity - 1, 1, 97, capacity - 2]
                .into_iter()
                .map(|slot| slot as u32)
                .collect();
            let offsets = [0, 5, 8];

            let mut expected = plain_trace(t, &states).unwrap();
            expected.extend(plain_trace_requested(t, &states, &requests, &offsets).unwrap());

            let per_call = mask_elements(t, sites).unwrap();
            let total = per_call.checked_mul(2).unwrap();
            let got = run3(&states, |net, state, shares| {
                let mut preprocessing = preprocess_rep3(total, net, state)?;
                eyre::ensure!(
                    preprocessing.consumed == 0,
                    "fresh preprocessing pool must start unused"
                );

                let mut result =
                    rep3_trace_preprocessed(t, shares, net, state, &mut preprocessing)?;
                eyre::ensure!(
                    preprocessing.consumed == per_call,
                    "first Poseidon2 call consumed {} masks, expected {per_call}",
                    preprocessing.consumed
                );

                result.extend(rep3_trace_requested_preprocessed(
                    t,
                    shares,
                    net,
                    state,
                    &mut preprocessing,
                    &requests,
                    &offsets,
                )?);
                eyre::ensure!(
                    preprocessing.consumed == total,
                    "second Poseidon2 call ended at mask {}, expected {total}",
                    preprocessing.consumed
                );
                preprocessing.ensure_consumed()?;
                Ok(result)
            });
            assert_eq!(got, expected, "t={t}");
        }
    }

    #[cfg(all(feature = "rep3", feature = "round-counting"))]
    #[test]
    fn preprocessing_costs_three_rounds_and_zero_budget_costs_none() {
        use mpc_core::protocols::rep3::conversion::A2BType;

        use crate::vm::gadgets::test_support::run3_counted_with_a2b;

        let values = [Fr::from(1u64)];
        let budget = mask_elements(16, 3).unwrap();
        let (_, rounds) =
            run3_counted_with_a2b(&values, A2BType::default(), |net, state, _shares| {
                let preprocessing = preprocess_rep3::<Fr, _>(budget, net, state)?;
                eyre::ensure!(preprocessing.r.len() == budget);
                eyre::ensure!(preprocessing.consumed == 0);
                Ok(Vec::new())
            });
        assert_eq!(rounds.by_party, [3, 3, 3]);

        let (_, zero_rounds) =
            run3_counted_with_a2b(&values, A2BType::default(), |net, state, _shares| {
                let preprocessing = preprocess_rep3::<Fr, _>(0, net, state)?;
                preprocessing.ensure_consumed()?;
                Ok(Vec::new())
            });
        assert_eq!(zero_rounds.by_party, [0, 0, 0]);
    }

    /// Preparation is reset out of the counter before each internal call. Full and sparse traces
    /// therefore pin the online cost alone: one opening for every full or partial s-box layer.
    #[cfg(all(feature = "rep3", feature = "round-counting"))]
    #[test]
    fn preprocessed_full_and_sparse_online_costs_eight_plus_partial_rounds() {
        use mpc_core::protocols::rep3::conversion::A2BType;

        use crate::vm::gadgets::test_support::run3_counted_with_a2b;

        for t in SUPPORTED_WIDTHS {
            let states: Vec<Fr> = (0..t).map(|i| Fr::from(i as u64 + 19)).collect();
            let budget = mask_elements(t, 1).unwrap();
            let expected_online = 8 + partial_rounds(t);
            let expected_full = plain_trace(t, &states).unwrap();

            let (full, full_rounds) =
                run3_counted_with_a2b(&states, A2BType::default(), |net, state, shares| {
                    let mut preprocessing = preprocess_rep3(budget, net, state)?;
                    net.reset();
                    let result =
                        rep3_trace_preprocessed(t, shares, net, state, &mut preprocessing)?;
                    preprocessing.ensure_consumed()?;
                    Ok(result)
                });
            assert_eq!(full, expected_full, "full t={t}");
            assert_eq!(full_rounds.by_party, [expected_online; 3], "full t={t}");

            let capacity = result_slots(t);
            let requests: Vec<u32> = [0, t - 1, t, capacity / 2, capacity - 1]
                .into_iter()
                .map(|slot| slot as u32)
                .collect();
            let offsets = [0, requests.len() as u32];
            let expected_sparse = plain_trace_requested(t, &states, &requests, &offsets).unwrap();
            let (sparse, sparse_rounds) =
                run3_counted_with_a2b(&states, A2BType::default(), |net, state, shares| {
                    let mut preprocessing = preprocess_rep3(budget, net, state)?;
                    net.reset();
                    let result = rep3_trace_requested_preprocessed(
                        t,
                        shares,
                        net,
                        state,
                        &mut preprocessing,
                        &requests,
                        &offsets,
                    )?;
                    preprocessing.ensure_consumed()?;
                    Ok(result)
                });
            assert_eq!(sparse, expected_sparse, "sparse t={t}");
            assert_eq!(sparse_rounds.by_party, [expected_online; 3], "sparse t={t}");
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
                let (_, rounds) = run3_counted(&states, |net, state, shares| {
                    rep3_trace(t, shares, net, state)
                });
                assert_eq!(rounds, expected_rounds, "t={t} sites={sites}");
            }
        }

        let t = 4;
        let sites = 3;
        let capacity = result_slots(t) as u32;
        let requests = [0, capacity - 1, 1, capacity - 2];
        let offsets = [0, 2, 2, 4];
        let states: Vec<Fr> = (0..sites * t).map(|i| Fr::from(i as u64 + 1)).collect();
        let (_, sparse_rounds) = run3_counted(&states, |net, state, shares| {
            rep3_trace_requested(t, shares, net, state, &requests, &offsets)
        });
        assert_eq!(sparse_rounds, 3 + 8 + partial_rounds(t));
    }
}
