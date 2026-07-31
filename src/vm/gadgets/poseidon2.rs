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
//!   shares. Only `Ops::sbox_layer` ever communicates.
//! - `walk` - the permutation itself, **layer-major across every site in lock-step**, so all of a
//!   batch's s-boxes at one round go into a single `sbox_layer` call.
//! - `emit_site` - the layout emitter, the one place the ordering above is encoded.

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

/// Which of one site's logical result positions (`0..result_slots(t)`) a caller actually wants.
enum SiteSelection<'a> {
    All,
    Requested(&'a [u32]),
}

/// Index-addressed output for one site, replacing the old block-assembling `SiteTrace`/`emit_site`
/// pair. The permutation still computes every value (a later round depends on all of them), but a
/// `Requested` sink retains only the witness-live subset instead of assembling and then filtering a
/// full [`result_slots`]-sized block - the majority of a Poseidon2 trace is witness-dead in a real
/// circuit (see `docs/ARCHITECTURE.md`, "Sites are typed, not opaque"). `record`'s `logical` argument
/// is always a position in the *full*, `All`-sized space - this is what lets `walk` be written once,
/// oblivious to which sink it was handed.
struct SiteOutput<'a, V> {
    selection: SiteSelection<'a>,
    values: Vec<Option<V>>,
    capacity: usize,
}

impl<'a, V: Clone> SiteOutput<'a, V> {
    fn all(capacity: usize) -> Self {
        Self { selection: SiteSelection::All, values: vec![None; capacity], capacity }
    }

    /// `requests` must already be validated (ascending, in `0..capacity`) by [`requested_outputs`].
    fn requested(capacity: usize, requests: &'a [u32]) -> Self {
        Self {
            selection: SiteSelection::Requested(requests),
            values: vec![None; requests.len()],
            capacity,
        }
    }

    fn destination(&self, logical: usize) -> Option<usize> {
        debug_assert!(logical < self.capacity, "logical position {logical} >= capacity {}", self.capacity);
        match self.selection {
            SiteSelection::All => Some(logical),
            SiteSelection::Requested(requests) => requests.binary_search(&(logical as u32)).ok(),
        }
    }

    fn record(&mut self, logical: usize, value: &V) {
        if let Some(destination) = self.destination(logical) {
            self.values[destination] = Some(value.clone());
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
                    eyre::eyre!("Poseidon2 site {site} did not emit requested result position {position}")
                })
            })
            .collect()
    }
}

/// Starts of the four top-level sections in one site's logical result layout (`0..result_slots(t)`,
/// i.e. every signal except the site's own `t` inputs): the final `out[t]`, the `state[(9+pr)][t]`
/// array, the initial `ExternalMatMulT` subtree, the 8 `FullRound` blocks, then the `pr`
/// `PartialRound` blocks.
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
        Self { states, initial_matmul, full, partial }
    }
}

/// `Acc(n)` over `input`: records `[out][in[n]][sums[n]]` at `base` and returns `out` (the running
/// sum's final value, which a caller may still need to keep computing with even when it isn't
/// itself a requested result).
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

/// `ExternalMatMul2`/`3`/`4` over exactly 2, 3 or 4 elements. Records `[out[t]][in[t]][t named
/// intermediates or one sum]` at `base` and returns `out`.
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
            let named = [double_in1, double_in3, t_0, t_1, quad_t_0, quad_t_1, t_2, t_3, t_4, t_5];
            trace.record_slice(base + 2 * t, &named);
            out
        }
        n => unreachable!("external_matmul_leaf takes 2, 3 or 4 elements, got {n}"),
    };
    trace.record_slice(base, &out);
    out
}

/// `ExternalMatMulT(t)`: records `[out[t]][in[t]][subtree]` at `base` and returns `out`.
fn external_matmul<F: PrimeField, O: Ops<F>>(
    ops: &mut O,
    input: &[O::V],
    trace: &mut SiteOutput<'_, O::V>,
    base: usize,
) -> Vec<O::V> {
    let t = input.len();
    let out = if t <= 4 {
        // The outer `[out[t]][in[t]]` wraps a genuine `ExternalMatMul{2,3,4}` subcomponent, which
        // gets its own `<==`-aliased copies of `out`/`in` - hence the leaf call at its own,
        // further-nested base rather than reusing this level's.
        external_matmul_leaf(ops, input, trace, base + 2 * t)
    } else {
        let m = t / 4;
        // `mds[]` is created textually before `accs[]` in `ExternalMatMulT`'s source, but circom
        // orders sibling subcomponents by *template definition order in the file*, not by
        // creation-statement order within the enclosing body - `template Acc(t)` is defined before
        // `template ExternalMatMul4` in `poseidon2.circom`, so every `accs[]` instance is numbered
        // before every `mds[]` instance. Cross-checked against a real circom witness
        // (`main.Poseidon2_..ExternalMatMulT_...accs[0].out` precedes `.mds[0].out[0]`). Layout
        // order (`accs` before `mds`) therefore differs from computation order (`mds` must be
        // computed first, since `accs` reads its columns) - `record`'s explicit `base` offsets make
        // that split free; nothing needs re-sorting after the fact.
        let acc_region = 4 * acc_signals(m);
        let mds_base = base + 2 * t + acc_region;
        let mut mds_out = Vec::with_capacity(m);
        for i in 0..m {
            let o = external_matmul_leaf(ops, &input[4 * i..4 * i + 4], trace, mds_base + i * 18);
            mds_out.push(o);
        }
        let mut acc_out = Vec::with_capacity(4);
        for l in 0..4 {
            let column: Vec<O::V> = mds_out.iter().map(|row| row[l].clone()).collect();
            let acc_base = base + 2 * t + l * acc_signals(m);
            acc_out.push(acc(ops, &column, trace, acc_base));
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
    trace.record_slice(base + t, input);
    out
}

/// `InternalMatMul2`/`3` - a genuine nested subcomponent for those widths. Records
/// `[out[t]][in[t]][sum]` at `base` and returns `out`.
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
            let scaled = if i == t - 1 { ops.mul_public(x, two) } else { x.clone() };
            ops.add(&scaled, &sum)
        })
        .collect();
    trace.record_slice(base, &out);
    trace.record_slice(base + t, input);
    trace.record(base + 2 * t, &sum);
    out
}

/// `InternalMatMulT(t)`: records `[out[t]][in[t]]` plus either a nested `InternalMatMul2`/`3`
/// subcomponent, or (for `t >= 4`) the own intermediate `acc` followed by its `Acc(t)` subtree, at
/// `base`. Returns `out`.
fn internal_matmul<F: PrimeField, O: Ops<F>>(
    ops: &mut O,
    input: &[O::V],
    diag: &[F],
    trace: &mut SiteOutput<'_, O::V>,
    base: usize,
) -> Vec<O::V> {
    let t = input.len();
    let out = match t {
        2..=3 => {
            // Same double-layering as `external_matmul`'s `t <= 4` case: a nested subcomponent gets
            // its own aliased `out`/`in` copies, one level further in.
            internal_matmul_leaf(ops, input, trace, base + 2 * t)
        }
        _ => {
            // Own intermediate `acc` precedes the `Acc(t)` subtree in layout order.
            let acc_value = acc(ops, input, trace, base + 2 * t + 1);
            trace.record(base + 2 * t, &acc_value);
            input
                .iter()
                .zip(diag)
                .map(|(x, &d)| {
                    let scaled = ops.mul_public(x, d);
                    ops.add(&scaled, &acc_value)
                })
                .collect()
        }
    };
    trace.record_slice(base, &out);
    trace.record_slice(base + t, input);
    out
}

/// `Sbox_e`'s block: `[out][in][square][pow_4]`, at `base`.
fn record_sbox_e<V: Clone>(trace: &mut SiteOutput<'_, V>, base: usize, input: &V, s: &SboxTrace<V>) {
    trace.record(base, &s.out);
    trace.record(base + 1, input);
    trace.record(base + 2, &s.square);
    trace.record(base + 3, &s.pow4);
}

/// A full round, for every site at once: add RC, one s-box layer, external matrix. `block_idx` is
/// this round's position among the 8 `FullRound` layout slots (`0..4` = first group, `4..8` =
/// second - the two groups are not adjacent in *execution* order, since the partial rounds run
/// between them, but they are in *layout* order, which `block_idx` addresses directly).
fn full_round<F: PrimeField, O: Ops<F>>(
    ops: &mut O,
    t: usize,
    current: &mut [Vec<O::V>],
    outputs: &mut [SiteOutput<'_, O::V>],
    round_rc: &[F],
    layout: &Layout,
    block_idx: usize,
) -> eyre::Result<()> {
    let sites = current.len();
    let mut linear: Vec<Vec<O::V>> = Vec::with_capacity(sites);
    for state in current.iter() {
        linear.push(state.iter().zip(round_rc).map(|(x, &c)| ops.add_public(x, c)).collect());
    }
    let flat: Vec<O::V> = linear.iter().flatten().cloned().collect();
    let sboxes = ops.sbox_layer(&flat)?;

    let base = layout.full + block_idx * full_round_signals(t);
    for site in 0..sites {
        let sbox_traces = &sboxes[site * t..(site + 1) * t];
        let sbox_out: Vec<O::V> = sbox_traces.iter().map(|s| s.out.clone()).collect();

        // [out][in][RC][linear_layer][sbox]
        outputs[site].record_slice(base + t, &current[site]);
        let rc_values: Vec<O::V> = round_rc.iter().map(|&c| ops.public(c)).collect();
        outputs[site].record_slice(base + 2 * t, &rc_values);
        outputs[site].record_slice(base + 3 * t, &linear[site]);
        outputs[site].record_slice(base + 4 * t, &sbox_out);
        // ExternalMatMulT subtree, over the sbox output.
        let out = external_matmul(ops, &sbox_out, &mut outputs[site], base + 5 * t);
        outputs[site].record_slice(base, &out);

        // Sbox(t)'s own block: [out[t]][in[t]] + t x Sbox_e - a further-aliased copy, same reason
        // as `external_matmul`'s leaf double-layering.
        let sbox_base = base + 5 * t + external_matmul_signals(t);
        outputs[site].record_slice(sbox_base, &sbox_out);
        outputs[site].record_slice(sbox_base + t, &linear[site]);
        for (k, s) in sbox_traces.iter().enumerate() {
            record_sbox_e(&mut outputs[site], sbox_base + 2 * t + k * 4, &linear[site][k], s);
        }

        current[site] = out;
    }
    Ok(())
}

/// A partial round, for every site at once: RC and s-box on element 0 only, then the internal
/// matrix. `block_idx` is this round's position among the `pr` `PartialRound` layout slots (partial
/// rounds have no group split - they're one contiguous run in both execution and layout order).
fn partial_round<F: PrimeField, O: Ops<F>>(
    ops: &mut O,
    t: usize,
    current: &mut [Vec<O::V>],
    outputs: &mut [SiteOutput<'_, O::V>],
    c: F,
    diag: &[F],
    layout: &Layout,
    block_idx: usize,
) -> eyre::Result<()> {
    let sites = current.len();
    let linear: Vec<O::V> = current.iter().map(|state| ops.add_public(&state[0], c)).collect();
    let sboxes = ops.sbox_layer(&linear)?;

    let base = layout.partial + block_idx * partial_round_signals(t);
    for site in 0..sites {
        let sbox = &sboxes[site];
        let mut imm_input = vec![sbox.out.clone()];
        imm_input.extend_from_slice(&current[site][1..]);

        // [out][in][RC][linear_layer][sbox]
        outputs[site].record_slice(base + t, &current[site]);
        let rc_value = ops.public(c);
        outputs[site].record(base + 2 * t, &rc_value);
        outputs[site].record(base + 2 * t + 1, &linear[site]);
        outputs[site].record(base + 2 * t + 2, &sbox.out);
        record_sbox_e(&mut outputs[site], base + 2 * t + 3, &linear[site], sbox);
        let out = internal_matmul(ops, &imm_input, diag, &mut outputs[site], base + 2 * t + 7);
        outputs[site].record_slice(base, &out);

        current[site] = out;
    }
    Ok(())
}

/// Runs the permutation for every site in `states` (each `t` elements, concatenated) in lock-step,
/// so each round's s-boxes across the whole batch are one [`Ops::sbox_layer`] call. `outputs` is one
/// sink per site, already sized/selected by the caller ([`SiteOutput::all`] for a full trace,
/// [`requested_outputs`] for a sparse one) - `walk` computes every value either way (a later round
/// depends on all of them), only retention differs.
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

    // 8 full-round layers of `sites * t` elements, plus `pr` partial-round layers of `sites`
    // elements - the exact total the three `sbox_layer` calls below make, combined.
    ops.prepare_sboxes(sites * (8 * t + pr))?;

    let mut current: Vec<Vec<O::V>> = Vec::with_capacity(sites);
    for site in 0..sites {
        let input = &states[site * t..(site + 1) * t];
        let out = external_matmul(ops, input, &mut outputs[site], layout.initial_matmul);
        outputs[site].record_slice(layout.states, &out);
        current.push(out);
    }

    for round in 0..4 {
        let round_rc = &rc.full1[round * t..(round + 1) * t];
        full_round(ops, t, &mut current, &mut outputs, round_rc, &layout, round)?;
        for (site, state) in current.iter().enumerate() {
            outputs[site].record_slice(layout.states + (round + 1) * t, state);
        }
    }

    // Partial rounds: RC and s-box on element 0 only, then the internal matrix.
    for round in 0..pr {
        partial_round(ops, t, &mut current, &mut outputs, rc.partial[round], &rc.diag, &layout, round)?;
        for (site, state) in current.iter().enumerate() {
            outputs[site].record_slice(layout.states + (5 + round) * t, state);
        }
    }

    for round in 0..4 {
        let round_rc = &rc.full2[round * t..(round + 1) * t];
        full_round(ops, t, &mut current, &mut outputs, round_rc, &layout, round + 4)?;
        for (site, state) in current.iter().enumerate() {
            outputs[site].record_slice(layout.states + (5 + pr + round) * t, state);
        }
    }

    // The final permutation output - a separate witness signal from the state array's last row,
    // even though the value is identical (circom's own `out[t]` vs. `state[8+pr][t]`).
    for (site, state) in current.iter().enumerate() {
        outputs[site].record_slice(0, state);
    }

    let mut out = Vec::with_capacity(sites);
    for (site, sink) in outputs.into_iter().enumerate() {
        out.push(sink.finish(site)?);
    }
    Ok(out.into_iter().flatten().collect())
}

/// Validates and builds one [`SiteOutput::requested`] sink per site from a
/// `PrecomputeBatch::result_requests`/`result_offsets`-shaped CSR table: `offsets` is a row pointer
/// of length `sites + 1`, and `requests[offsets[site]..offsets[site + 1]]` must be strictly
/// ascending and within `0..capacity`.
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
    eyre::ensure!(offsets[0] == 0, "Poseidon2 request offsets must start at zero");
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
        eyre::ensure!(lo <= hi && hi <= requests.len(), "Poseidon2 site {site} has invalid request range {lo}..{hi}");
        let site_requests = &requests[lo..hi];
        for pair in site_requests.windows(2) {
            eyre::ensure!(pair[0] < pair[1], "Poseidon2 site {site} result requests must be strictly ascending");
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

/// Computes only the requested logical trace slots for each site (see [`requested_outputs`]) - the
/// permutation still evaluates every value (a later round depends on all of them), but witness-dead
/// state copies, round constants, and subcomponent intermediates are never materialized in the
/// returned trace. Returned values are site-major, in exactly the CSR order `result_requests`/
/// `result_offsets` describe.
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

/// How many [`SboxPool`] elements a `Shared`-domain batch of `sites` sites at width `t` will
/// consume: `sites * (8 * t + partial_rounds(t))` - the exact total `walk` sizes its
/// `prepare_sboxes` call with today (`8` full-round layers of `t` elements each, plus one
/// partial-round layer per element). `vm::codegen` sums this across every genuinely `Shared`
/// Poseidon2 batch to size `Program::sbox_randomness`, the offline preprocessing budget
/// [`SboxPool::prepare`] spends once, before any input is bound - see `docs/ARCHITECTURE.md`,
/// "Precomputation". Not gated on `rep3` - codegen needs it regardless of which features this
/// build enables, and it's plain arithmetic, no rep3 types involved.
pub(crate) fn sbox_randomness_budget(t: usize, sites: usize) -> u64 {
    sites as u64 * (8 * t as u64 + partial_rounds(t) as u64)
}

/// The correlated randomness [`Rep3Ops::sbox_layer`] consumes: `r` and its powers `r²..r⁵`, one
/// entry per element across the *whole* permutation batch (every s-box layer, every site).
/// [`Self::prepare`] fills every field in 3 network rounds; a caller then hands out disjoint
/// slices a layer at a time as `sbox_layer` runs.
#[cfg(feature = "rep3")]
pub(crate) struct SboxPool<F: PrimeField> {
    r: Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>,
    r2: Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>,
    r3: Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>,
    r4: Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>,
    r5: Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>,
    /// How many elements of the pool have already been handed to a `sbox_layer` call.
    consumed: usize,
}

#[cfg(feature = "rep3")]
impl<F: PrimeField> SboxPool<F> {
    /// `r`, `r²`, `r³`, `r⁴`, `r⁵` for `total_elements` elements, in 3 rounds total - independent of
    /// how large `total_elements` is, and everywhere this crate calls it, done once and offline
    /// (`Rep3Driver::preprocess`, before any circuit input is bound - see
    /// `docs/ARCHITECTURE.md`, "Precomputation"). `r²..r⁵` depend only on `r`, not on any secret
    /// input, which is what makes computing them ahead of time sound: a caller hands out a
    /// *disjoint* slice per s-box layer, so every (layer, element) still gets its own fresh `r` -
    /// reusing one `r` across two layers would leak `x₁ - x₂` from their two masked opens.
    pub(crate) fn prepare<N: mpc_net::Network>(
        total_elements: usize,
        net: &N,
        state: &mut mpc_core::protocols::rep3::Rep3State,
    ) -> eyre::Result<Self> {
        use mpc_core::protocols::rep3::arithmetic;

        let n = total_elements;
        let r: Vec<_> = (0..n).map(|_| arithmetic::rand(state)).collect();
        let r2 = arithmetic::mul_vec(&r, &r, net, state)?;
        let r4 = arithmetic::mul_vec(&r2, &r2, net, state)?;
        let (lhs, rhs): (Vec<_>, Vec<_>) = r
            .iter()
            .copied()
            .chain(r.iter().copied())
            .zip(r2.iter().copied().chain(r4.iter().copied()))
            .unzip();
        let r35 = arithmetic::mul_vec(&lhs, &rhs, net, state)?;
        let (r3, r5) = r35.split_at(n);

        Ok(SboxPool {
            r,
            r2,
            r3: r3.to_vec(),
            r4,
            r5: r5.to_vec(),
            consumed: 0,
        })
    }
}

/// rep3 backend. The s-box uses the masked-opening trick (see [`Rep3Ops::sbox_layer`]) so a whole
/// layer costs **one** network round instead of the three a naive `x^2, x^4, x^5` chain needs.
#[cfg(feature = "rep3")]
struct Rep3Ops<'a, F: PrimeField, N: mpc_net::Network> {
    net: &'a N,
    state: &'a mut mpc_core::protocols::rep3::Rep3State,
    /// Prepared by the caller (`rep3_trace`) before `walk` runs - see [`SboxPool::prepare`].
    pool: &'a mut SboxPool<F>,
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

    // `pool` already holds every s-box layer's correlated randomness by the time `walk` runs
    // (`rep3_trace` fills it via `SboxPool::prepare` before constructing `Rep3Ops` at all) - this
    // stays the trait default no-op, matching `PlainOps`.

    /// `x^2`, `x^4` and `x^5` are genuinely sequential as multiplications - from `{x, x^2}` the
    /// second round can only reach degree 4 - so a naive layer is 3 rounds, i.e. `3 * (8 + pr)` for
    /// the whole permutation (192 at t=3).
    ///
    /// Instead, mask and open: with `r` (and `r^2..r^5`, already prepared for the entire batch -
    /// see [`SboxPool::prepare`]), publish `y = x - r` in **one** round; then `x = y + r` makes all
    /// three intermediates local linear combinations by binomial expansion. `y` is public and `r`
    /// uniform and unknown, so nothing about `x` leaks. This is mpc-core's own `sbox_rep3_precomp`
    /// trick, extended to also emit `square` and `pow_4` - which is exactly why it composes with a
    /// *full* trace at no extra round cost (mpc-core only ever needed `x^5`).
    fn sbox_layer(&mut self, xs: &[Self::V]) -> eyre::Result<Vec<SboxTrace<Self::V>>> {
        use mpc_core::protocols::rep3::arithmetic;

        let n = xs.len();
        let pool = &mut *self.pool;
        eyre::ensure!(
            pool.consumed + n <= pool.r.len(),
            "sbox randomness pool exhausted: {} elements requested, {} remain - the pool is sized \
             for one Machine::run and never rewinds; call Rep3Driver::preprocess again before each \
             run",
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
/// network rounds - `8 + partial_rounds(t)` in total, independent of the number of sites, given a
/// `pool` already sized to (at least) [`sbox_randomness_budget`]`(t, sites)` - see
/// `Rep3Driver::preprocess`, which spends that budget's 3 rounds once, offline, before any circuit
/// input is bound.
#[cfg(feature = "rep3")]
pub(crate) fn rep3_trace<F: PrimeField, N: mpc_net::Network>(
    t: usize,
    states: &[mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>],
    net: &N,
    rep3_state: &mut mpc_core::protocols::rep3::Rep3State,
    pool: &mut SboxPool<F>,
) -> eyre::Result<Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>> {
    let sites = check_width(t, states.len())?;
    let capacity = result_slots(t);
    let rc = RoundConstants::load(t)?;
    let mut ops = Rep3Ops { net, state: rep3_state, pool };
    let outputs = (0..sites).map(|_| SiteOutput::all(capacity)).collect();
    let out = walk(&mut ops, t, states, &rc, outputs)?;
    eyre::ensure!(
        out.len() == sites * capacity,
        "Poseidon2(t={t}) emitted {} values, expected {}",
        out.len(),
        sites * capacity
    );
    Ok(out)
}

/// Rep3 twin of [`plain_trace_requested`]. Request sparsity changes only local trace retention -
/// every s-box layer still runs, in the same network rounds as [`rep3_trace`], given a `pool`
/// already sized to (at least) [`sbox_randomness_budget`]`(t, sites)`.
#[cfg(feature = "rep3")]
pub(crate) fn rep3_trace_requested<F: PrimeField, N: mpc_net::Network>(
    t: usize,
    states: &[mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>],
    net: &N,
    rep3_state: &mut mpc_core::protocols::rep3::Rep3State,
    pool: &mut SboxPool<F>,
    result_requests: &[u32],
    result_offsets: &[u32],
) -> eyre::Result<Vec<mpc_core::protocols::rep3::Rep3PrimeFieldShare<F>>> {
    let sites = check_width(t, states.len())?;
    let capacity = result_slots(t);
    let outputs = requested_outputs(sites, capacity, result_requests, result_offsets)?;
    let rc = RoundConstants::load(t)?;
    let mut ops = Rep3Ops { net, state: rep3_state, pool };
    walk(&mut ops, t, states, &rc, outputs)
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
    fn rejects_unsupported_width_and_ragged_input() {
        assert!(plain_trace(5, &[Fr::from(0u64); 5]).is_err());
        assert!(plain_trace::<Fr>(3, &[]).is_err());
        assert!(plain_trace(3, &[Fr::from(0u64); 4]).is_err());
    }

    /// A sparse `plain_trace_requested` must equal filtering the full `plain_trace` down to the
    /// same requests - the whole point of the sparse sink, checked over every width and a
    /// non-trivial request pattern (including one site whose row is entirely empty).
    #[test]
    fn requested_trace_matches_filtering_full_trace_for_every_width() {
        for t in SUPPORTED_WIDTHS {
            let capacity = result_slots(t);
            let sites = 3;
            let states: Vec<Fr> = (0..sites * t).map(|i| Fr::from(i as u64 + 1)).collect();
            let full = plain_trace(t, &states).unwrap();

            // Site 0: every third slot. Site 1: just the final `out[t]`. Site 2: nothing at all.
            let site0: Vec<u32> = (0..capacity as u32).step_by(3).collect();
            let site1: Vec<u32> = (0..t as u32).collect();
            let site2: Vec<u32> = Vec::new();
            let mut requests = site0.clone();
            requests.extend(&site1);
            requests.extend(&site2);
            let offsets = vec![
                0,
                site0.len() as u32,
                (site0.len() + site1.len()) as u32,
                (site0.len() + site1.len() + site2.len()) as u32,
            ];

            let sparse = plain_trace_requested(t, &states, &requests, &offsets).unwrap();

            let mut expected = Vec::new();
            for (site, reqs) in [&site0, &site1, &site2].into_iter().enumerate() {
                let row = &full[site * capacity..(site + 1) * capacity];
                expected.extend(reqs.iter().map(|&r| row[r as usize]));
            }
            assert_eq!(sparse, expected, "t={t}");
        }
    }

    #[test]
    fn requested_trace_rejects_malformed_csr_tables() {
        let t = 2;
        let capacity = result_slots(t);
        let states = vec![Fr::from(1u64); t];

        // Wrong offsets length (not sites + 1).
        assert!(plain_trace_requested(t, &states, &[0], &[0]).is_err());
        // Offsets don't start at zero.
        assert!(plain_trace_requested(t, &states, &[0], &[1, 1]).is_err());
        // Final offset doesn't match the request count.
        assert!(plain_trace_requested(t, &states, &[0], &[0, 2]).is_err());
        // Requests not strictly ascending.
        assert!(plain_trace_requested(t, &states, &[1, 0], &[0, 2]).is_err());
        // A request beyond capacity.
        assert!(plain_trace_requested(t, &states, &[capacity as u32], &[0, 1]).is_err());
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
                let mut pool = SboxPool::prepare(sbox_randomness_budget(t, 2) as usize, net, state)?;
                rep3_trace(t, shares, net, state, &mut pool)
            });
            assert_eq!(got, expected, "t={t}");
        }
    }

    /// Pins the *combined* offline + online cost a caller pays if it prepares the pool immediately
    /// before every call, rather than once up front - `3 + 8 + partial_rounds(t)`, the same for
    /// every site count in a batch. `Rep3Driver::preprocess` is what actually amortizes the 3
    /// offline rounds across an entire `Machine::run` instead of paying them per Poseidon2 batch -
    /// see `rep3_online_cost_is_eight_plus_partial_rounds_once_preprocessed` below for that half.
    #[cfg(all(feature = "rep3", feature = "round-counting"))]
    #[test]
    fn rep3_costs_three_plus_eight_plus_partial_rounds_independent_of_sites() {
        use crate::vm::gadgets::test_support::run3_counted;

        for t in SUPPORTED_WIDTHS {
            let expected_rounds = 3 + 8 + partial_rounds(t);
            for sites in [1, 3] {
                let states: Vec<Fr> = (0..sites * t).map(|i| Fr::from(i as u64 + 1)).collect();
                let (_, rounds) = run3_counted(&states, |net, state, shares| {
                    let mut pool =
                        SboxPool::prepare(sbox_randomness_budget(t, sites) as usize, net, state)?;
                    rep3_trace(t, shares, net, state, &mut pool)
                });
                assert_eq!(rounds, expected_rounds, "t={t} sites={sites}");
            }
        }
    }

    /// The whole point of hoisting `SboxPool::prepare` out of the online path: once a pool is
    /// already filled (as `Rep3Driver::preprocess` does, before `Machine::run` binds any input),
    /// `rep3_trace` alone costs only `8 + partial_rounds(t)` - the offline 3 rounds are paid once,
    /// outside this measurement, however many Poseidon2 batches the run makes.
    #[cfg(all(feature = "rep3", feature = "round-counting"))]
    #[test]
    fn rep3_online_cost_is_eight_plus_partial_rounds_once_preprocessed() {
        use crate::vm::gadgets::test_support::run3_counted;

        for t in SUPPORTED_WIDTHS {
            let expected_rounds = 8 + partial_rounds(t);
            for sites in [1, 3] {
                let states: Vec<Fr> = (0..sites * t).map(|i| Fr::from(i as u64 + 1)).collect();
                let (_, rounds) = run3_counted(&states, |net, state, shares| {
                    let mut pool =
                        SboxPool::prepare(sbox_randomness_budget(t, sites) as usize, net, state)?;
                    net.reset(); // isolate the online-only cost from the offline prepare above.
                    rep3_trace(t, shares, net, state, &mut pool)
                });
                assert_eq!(rounds, expected_rounds, "t={t} sites={sites}");
            }
        }
    }
}
