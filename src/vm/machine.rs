//! Executes a `Program` against a `VmDriver` - the replacement for the deleted plaintext
//! `Interpreter`: the same bytecode runs against `PlainDriver` (the KAT oracle) or a real rep3
//! driver, the only difference being which `VmDriver` is passed in. See `docs/ARCHITECTURE.md`,
//! "Bytecode and the slot machine".

use ark_ff::PrimeField;

use crate::ir::PrecomputeKind;

use super::driver::VmDriver;
use super::program::{Bank, Opcode, PrecomputeBatch, Program};

/// One circuit input's value, in whichever representation its domain calls for -
/// `Program::input_domains` tells a caller which variant each input needs;
/// `Program::classify_inputs` builds this array from a flat `&[F]` automatically for callers that
/// don't want to track domains themselves (e.g. the plain KAT tests).
#[derive(Debug, Clone)]
pub enum InputValue<F, S> {
    Public(F),
    Secret(S),
}

impl<F: PrimeField> Program<F> {
    /// Builds `Machine::run`'s `inputs` array from a flat `&[F]` in circuit signal order (the same
    /// convention the deleted `Interpreter` took `input_signals` in), consulting
    /// `Program::input_domains` to wrap each value as `Public` or `Secret` automatically. `share`
    /// is only invoked for `Secret`-destined values - e.g. `|v| v` for a driver whose `Share = F`
    /// (`PlainDriver`), or an actual secret-sharing routine for a real MPC driver (see
    /// `tests/rep3_vm.rs`).
    pub fn classify_inputs<S>(
        &self,
        values: &[F],
        mut share: impl FnMut(F) -> S,
    ) -> Vec<InputValue<F, S>> {
        assert_eq!(
            values.len(),
            self.num_inputs,
            "expected one value per circuit input ({}), got {}",
            self.num_inputs,
            values.len()
        );
        self.input_domains
            .iter()
            .zip(values)
            .map(|(bank, &v)| match bank {
                Bank::Public => InputValue::Public(v),
                Bank::Shared => InputValue::Secret(share(v)),
                Bank::Local => unreachable!("an input's domain is never Local"),
            })
            .collect()
    }
}

pub struct Machine;

impl Machine {
    pub fn run<F: PrimeField, D: VmDriver<F>>(
        program: &Program<F>,
        driver: &mut D,
        inputs: &[InputValue<F, D::Share>],
    ) -> eyre::Result<Vec<D::Share>> {
        eyre::ensure!(
            inputs.len() == program.num_inputs,
            "expected {} inputs, got {}",
            program.num_inputs,
            inputs.len()
        );

        let mut public: Vec<F> = vec![F::zero(); program.slots.public as usize];
        let mut shared: Vec<D::Share> = vec![D::Share::default(); program.slots.shared as usize];
        let mut local: Vec<D::Local> = vec![D::Local::default(); program.slots.local as usize];

        for (i, c) in program.constants.iter().enumerate() {
            public[i] = *c;
        }

        for binding in &program.inputs {
            match (binding.bank, &inputs[binding.input_index as usize]) {
                (Bank::Public, InputValue::Public(v)) => public[binding.slot as usize] = *v,
                (Bank::Shared, InputValue::Secret(v)) => shared[binding.slot as usize] = v.clone(),
                (bank, _) => eyre::bail!(
                    "input {} is {bank:?}-domain but was supplied as the other InputValue variant",
                    binding.input_index
                ),
            }
        }

        for instr in &program.instructions {
            match instr.op {
                Opcode::AddPP => {
                    public[instr.dst as usize] = public[instr.a as usize] + public[instr.b as usize]
                }
                Opcode::SubPP => {
                    public[instr.dst as usize] = public[instr.a as usize] - public[instr.b as usize]
                }
                Opcode::MulPP => {
                    public[instr.dst as usize] = public[instr.a as usize] * public[instr.b as usize]
                }
                Opcode::AddSS => {
                    shared[instr.dst as usize] =
                        driver.add_ss(&shared[instr.a as usize], &shared[instr.b as usize])
                }
                Opcode::SubSS => {
                    shared[instr.dst as usize] =
                        driver.sub_ss(&shared[instr.a as usize], &shared[instr.b as usize])
                }
                Opcode::AddSP => {
                    shared[instr.dst as usize] =
                        driver.add_sp(&shared[instr.a as usize], public[instr.b as usize])
                }
                Opcode::SubSP => {
                    shared[instr.dst as usize] =
                        driver.sub_sp(&shared[instr.a as usize], public[instr.b as usize])
                }
                Opcode::SubPS => {
                    shared[instr.dst as usize] =
                        driver.sub_ps(public[instr.a as usize], &shared[instr.b as usize])
                }
                Opcode::MulSP => {
                    shared[instr.dst as usize] =
                        driver.mul_sp(&shared[instr.a as usize], public[instr.b as usize])
                }
                Opcode::MulLocal => {
                    local[instr.dst as usize] =
                        driver.mul_local(&shared[instr.a as usize], &shared[instr.b as usize])
                }
                Opcode::Reshare => {
                    let entry = program.rounds[instr.a as usize];
                    let start = entry.operand_start as usize;
                    let len = entry.len as usize;
                    let locals: Vec<D::Local> = program.round_operands[start..start + len]
                        .iter()
                        .map(|&slot| local[slot as usize].clone())
                        .collect();
                    let results = driver.reshare(&locals)?;
                    eyre::ensure!(
                        results.len() == len,
                        "reshare returned {} results, expected {len}",
                        results.len()
                    );
                    let rstart = entry.result_start as usize;
                    for (k, r) in results.into_iter().enumerate() {
                        let slot = program.round_results[rstart + k];
                        if slot != u32::MAX {
                            shared[slot as usize] = r;
                        }
                    }
                }
                Opcode::Precompute => Self::run_batch(
                    &program.precompute_batches[instr.a as usize],
                    driver,
                    &public,
                    &mut shared,
                )?,
            }
        }

        // Signal 0 is the reserved always-true constant; every genuine `SignalIdx` `s` lands at
        // `s + 1` (the same convention the deleted `Interpreter` used) - `Program::signal_to_witness`
        // already indexes into this same, offset-by-one array.
        let mut signals: Vec<D::Share> = vec![D::Share::default(); program.num_signals];
        signals[0] = driver.promote(F::one());
        for store in &program.stores {
            signals[store.signal as usize + 1] = match store.bank {
                Bank::Public => driver.promote(public[store.slot as usize]),
                Bank::Shared => shared[store.slot as usize].clone(),
                Bank::Local => unreachable!("codegen never stores a Local value directly"),
            };
        }
        // Main's own circuit inputs are never `graph.outputs()` entries (only a *nested*
        // subcomponent's input signal is - see `frontend/inline.rs::inline_template`'s
        // `TemplateOp::LocalSignal` arm), so they'd otherwise never reach `signals` at all - copy
        // each one in directly from the caller-supplied `inputs`, exactly like the deleted
        // `Interpreter` pre-filled its own `signals` array from `input_signals` up front. Uses the
        // original `inputs` argument (not a P/S-bank slot) so this covers an input whose
        // `Op::Input` node `gc` dropped as dead too - still a genuine witness entry.
        for (input_index, value) in inputs.iter().enumerate() {
            let signal = program.num_outputs + input_index;
            signals[signal + 1] = match value {
                InputValue::Public(v) => driver.promote(*v),
                InputValue::Secret(v) => v.clone(),
            };
        }

        Ok(program
            .signal_to_witness
            .iter()
            .map(|&idx| signals[idx].clone())
            .collect())
    }

    /// Services one batched precomputation site group - a single driver call for every site of one
    /// kind at one stage. Dispatched from [`Opcode::Precompute`] at the batch's own point in the
    /// instruction stream, *not* from an up-front phase: a site's inputs may be produced by earlier
    /// instructions (see `docs/ARCHITECTURE.md`, "Precomputation").
    ///
    /// A gadget's per-site result count may be *shorter* than the site's reserved capacity
    /// (`num_outputs + num_intermediates`, sized from the real circuit's own signal layout): the
    /// real co-snarks VM (`circom-mpc-vm/src/mpc_vm.rs`) writes only `result.intermediate.len()`
    /// signals starting at a site's intermediate region, not the region's full remaining span,
    /// leaving whatever's left at its default (zero) value - unconstrained, and harmless for any
    /// signal nothing downstream reads. Each site within one batch gets its own prefix - the
    /// gadget's per-site length divides evenly (every site of the same kind shares the same
    /// template, hence the same real length), so this is never a flat prefix of the whole batch,
    /// which would spill one site's results into the next site's region.
    fn run_batch<F: PrimeField, D: VmDriver<F>>(
        batch: &PrecomputeBatch,
        driver: &mut D,
        public: &[F],
        shared: &mut [D::Share],
    ) -> eyre::Result<()> {
        // A site input isn't always a share - a circuit may pass a literal, which codegen resolves
        // to a `Public`-bank slot (see `SiteInput`). Promote those; every gadget expects shares.
        let inputs: Vec<D::Share> = batch
            .input_slots
            .iter()
            .map(|input| match input.bank {
                Bank::Public => driver.promote(public[input.slot as usize]),
                Bank::Shared => shared[input.slot as usize].clone(),
                Bank::Local => unreachable!(
                    "Graph::verify and codegen both reject an un-reshared MulLocal feeding a site"
                ),
            })
            .collect();
        let results = match batch.kind {
            PrecomputeKind::Poseidon2 { t } => driver.poseidon2_traces(t, &inputs)?,
            PrecomputeKind::Num2Bits { n } => driver.num2bits_traces(n, &inputs)?,
            PrecomputeKind::IsZero => driver.is_zero_traces(&inputs)?,
            PrecomputeKind::IsEqual => driver.is_equal_traces(&inputs)?,
            PrecomputeKind::AliasCheck => driver.alias_check_traces(&inputs)?,
        };
        eyre::ensure!(batch.sites > 0, "precompute batch has no sites");
        eyre::ensure!(
            results.len() % batch.sites == 0,
            "precompute batch ({:?}, {} sites) returned {} results, not an even multiple of \
             the site count",
            batch.kind,
            batch.sites,
            results.len()
        );
        let per_site_actual = results.len() / batch.sites;
        let per_site_capacity = batch.result_slots.len() / batch.sites;
        eyre::ensure!(
            per_site_actual <= per_site_capacity,
            "precompute batch ({:?}) returned {per_site_actual} results per site, exceeding \
             the {per_site_capacity} the circuit's own signal layout reserves",
            batch.kind
        );
        for (site_idx, chunk) in results.chunks_exact(per_site_actual).enumerate() {
            let base = site_idx * per_site_capacity;
            for (k, value) in chunk.iter().enumerate() {
                let slot = batch.result_slots[base + k];
                if slot != u32::MAX {
                    shared[slot as usize] = value.clone();
                }
            }
        }
        Ok(())
    }
}
