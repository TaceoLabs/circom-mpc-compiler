//! Executes a `Program` against a `VmDriver`: the same bytecode runs against `PlainDriver` (the
//! reference driver) or a real rep3 driver, the only difference being which `VmDriver` is passed in. See
//! `docs/ARCHITECTURE.md`, "Bytecode and the slot machine".

use ark_ff::PrimeField;

use crate::ir::PrecomputeKind;

use super::driver::VmDriver;
use super::program::{Bank, Opcode, PrecomputeBatch, Program};

/// One circuit input's value, in whichever representation its domain calls for -
/// `Program::input_domains` tells a caller which variant each input needs;
/// `Program::classify_inputs` builds this array from a flat `&[F]` automatically for callers that
/// don't want to track domains themselves (e.g. the plain-driver tests).
#[derive(Debug, Clone)]
pub enum InputValue<F, S> {
    Public(F),
    Secret(S),
}

impl<F: PrimeField> Program<F> {
    /// Builds `Machine::run`'s `inputs` array from a flat `&[F]` in circuit signal order,
    /// consulting `Program::input_domains` to wrap each value as `Public` or `Secret`
    /// automatically. `share`
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

        let mut pending_mul_lhs: Vec<D::Share> = Vec::new();
        let mut pending_mul_rhs: Vec<D::Share> = Vec::new();
        let mut pending_mul_dst: Vec<u32> = Vec::new();
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
                    // Codegen may recycle these shared slots before the round boundary, so retain
                    // the values rather than only their indices. The expensive masked product is
                    // still delayed and vectorized across the complete round.
                    pending_mul_lhs.push(shared[instr.a as usize].clone());
                    pending_mul_rhs.push(shared[instr.b as usize].clone());
                    pending_mul_dst.push(instr.dst);
                }
                Opcode::Reshare => {
                    let entry = program.rounds[instr.a as usize];
                    let start = entry.operand_start as usize;
                    let len = entry.len as usize;
                    eyre::ensure!(
                        pending_mul_dst.as_slice()
                            == &program.round_operands[start..start + len],
                        "MulLocal instructions do not match the following round's operand table"
                    );
                    let products = driver.mul_local_vec(&pending_mul_lhs, &pending_mul_rhs);
                    eyre::ensure!(
                        products.len() == len,
                        "mul_local_vec returned {} products, expected {len}",
                        products.len()
                    );
                    for (&dst, product) in pending_mul_dst.iter().zip(products) {
                        local[dst as usize] = product;
                    }
                    pending_mul_lhs.clear();
                    pending_mul_rhs.clear();
                    pending_mul_dst.clear();
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
                    &mut public,
                    &mut shared,
                )?,
            }
        }
        eyre::ensure!(
            pending_mul_dst.is_empty(),
            "program ended with MulLocal instructions not followed by Reshare"
        );

        // Signal 0 is the reserved always-true constant; every genuine `SignalIdx` `s` lands at
        // `s + 1` - `Program::signal_to_witness` already indexes into this same, offset-by-one
        // array.
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
        // each one in directly from the caller-supplied `inputs`. Uses the original `inputs`
        // argument (not a P/S-bank slot) so this covers an input whose `Op::Input` node `gc`
        // dropped as dead too - still a genuine witness entry.
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

    /// Services one batched precomputation site group at its point in the instruction stream. A
    /// public batch uses the plain gadget path; a shared batch is one driver call. Interleaving is
    /// required because a site's inputs may be produced by earlier instructions (see
    /// `docs/ARCHITECTURE.md`, "Precomputation").
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
        public: &mut [F],
        shared: &mut [D::Share],
    ) -> eyre::Result<()> {
        // Whether this batch needs a genuine MPC call, rather than `batch.result_bank == Public`:
        // for every kind but `Reveal` the two coincide (a site's inputs are all-`Public` exactly
        // when its result stays `Public`), but `Reveal`'s `result_bank` is unconditionally `Public`
        // even when its own inputs are `Shared` - that is its entire purpose (see
        // `PrecomputeKind::Reveal`), and precisely that case still needs a real `driver.open` call.
        let needs_mpc = batch.input_slots.iter().any(|input| input.bank == Bank::Shared);

        if !needs_mpc {
            let inputs: Vec<F> = batch
                .input_slots
                .iter()
                .map(|input| {
                    eyre::ensure!(
                        input.bank == Bank::Public,
                        "public precompute batch has a non-public input"
                    );
                    Ok(public[input.slot as usize])
                })
                .collect::<eyre::Result<_>>()?;
            let results = Self::run_plain_batch(batch.kind, &inputs)?;
            eyre::ensure!(
                batch.result_bank == Bank::Public,
                "an all-public precompute batch's result bank must be Public"
            );
            let selected = Self::select_requests(&results, batch)?;
            return Self::store_batch_results(batch, &selected, public);
        }

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

        // `Reveal` is the one kind whose MPC path writes into the `Public` bank (a genuine open,
        // rather than a share-producing gadget) - every other kind writes into `Shared`.
        if let PrecomputeKind::Reveal { .. } = batch.kind {
            eyre::ensure!(
                batch.result_bank == Bank::Public,
                "a Reveal precompute batch's result bank must be Public"
            );
            let opened = driver.open(&inputs)?;
            let selected = Self::select_requests(&opened, batch)?;
            return Self::store_batch_results(batch, &selected, public);
        }
        eyre::ensure!(
            batch.result_bank == Bank::Shared,
            "precompute batch result bank cannot be Local"
        );
        let results = match batch.kind {
            PrecomputeKind::Poseidon2 { t } => driver.poseidon2_traces(t, &inputs)?,
            PrecomputeKind::Num2Bits { n } => driver.num2bits_traces(n, &inputs)?,
            PrecomputeKind::IsZero => driver.is_zero_traces(&inputs)?,
            PrecomputeKind::IsEqual => driver.is_equal_traces(&inputs)?,
            PrecomputeKind::AliasCheck => driver.alias_check_traces(&inputs)?,
            PrecomputeKind::Reveal { .. } => unreachable!("handled above"),
        };
        let selected = Self::select_requests(&results, batch)?;
        Self::store_batch_results(batch, &selected, shared)
    }

    fn run_plain_batch<F: PrimeField>(kind: PrecomputeKind, inputs: &[F]) -> eyre::Result<Vec<F>> {
        use super::gadgets::{aliascheck, isequal, iszero, num2bits, poseidon2};

        Ok(match kind {
            PrecomputeKind::Poseidon2 { t } => poseidon2::plain_trace(t, inputs)?,
            PrecomputeKind::Num2Bits { n } => inputs
                .iter()
                .flat_map(|&x| num2bits::plain_trace(x, n))
                .collect(),
            PrecomputeKind::IsZero => inputs
                .iter()
                .flat_map(|&x| iszero::plain_trace(x))
                .collect(),
            PrecomputeKind::IsEqual => isequal::plain_trace(inputs)?,
            PrecomputeKind::AliasCheck => {
                eyre::ensure!(
                    inputs.len().is_multiple_of(254),
                    "alias_check_traces: {} inputs is not a multiple of 254",
                    inputs.len()
                );
                inputs
                    .chunks_exact(254)
                    .flat_map(aliascheck::plain_trace)
                    .collect()
            }
            // An all-public reveal is the identity: every party already holds every input in the
            // clear, so "opening" it changes nothing.
            PrecomputeKind::Reveal { .. } => inputs.to_vec(),
        })
    }

    /// Selects each site's witness-live logical result slots out of a gadget's full per-site
    /// output, flattening site-major. A temporary bridge (see `docs/ARCHITECTURE.md`,
    /// "Precomputation"): every gadget still computes and returns its *full* per-site trace
    /// unconditionally (`num_outputs + num_intermediates` values), and this filters the
    /// `PrecomputeBatch::result_requests` subset out of it before storing - until a later step
    /// teaches each gadget to skip computing the witness-dead majority in the first place.
    fn select_requests<T: Clone>(full: &[T], batch: &PrecomputeBatch) -> eyre::Result<Vec<T>> {
        eyre::ensure!(batch.sites > 0, "precompute batch has no sites");
        eyre::ensure!(
            full.len().is_multiple_of(batch.sites),
            "precompute batch ({:?}, {} sites) returned {} results, not an even multiple of \
             the site count",
            batch.kind,
            batch.sites,
            full.len()
        );
        let capacity = full.len() / batch.sites;
        let mut selected = Vec::with_capacity(batch.result_requests.len());
        for site in 0..batch.sites {
            let site_full = &full[site * capacity..(site + 1) * capacity];
            let lo = batch.result_offsets[site] as usize;
            let hi = batch.result_offsets[site + 1] as usize;
            for &logical in &batch.result_requests[lo..hi] {
                let logical = logical as usize;
                eyre::ensure!(
                    logical < capacity,
                    "precompute batch ({:?}) requested slot {logical}, exceeding the {capacity} \
                     the circuit's own signal layout reserves",
                    batch.kind
                );
                selected.push(site_full[logical].clone());
            }
        }
        Ok(selected)
    }

    fn store_batch_results<T: Clone>(
        batch: &PrecomputeBatch,
        results: &[T],
        destination: &mut [T],
    ) -> eyre::Result<()> {
        eyre::ensure!(
            results.len() == batch.result_slots.len(),
            "precompute batch ({:?}) produced {} results, expected exactly {} (one per requested \
             slot)",
            batch.kind,
            results.len(),
            batch.result_slots.len()
        );
        for (&slot, value) in batch.result_slots.iter().zip(results) {
            if slot != u32::MAX {
                destination[slot as usize] = value.clone();
            }
        }
        Ok(())
    }
}
