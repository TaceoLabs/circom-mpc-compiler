//! Executes a `Program` against a `VmDriver`: the same bytecode runs against `PlainDriver` (the
//! reference driver) or a real rep3 driver, the only difference being which `VmDriver` is passed
//! in.

use ark_bn254::Fr;
use ark_ff::{One, Zero};

use circom_mpc_program::{
    GadgetBatch, GadgetKind, Bank, BatchKind, InputValue, InputValues, Instruction, Program,
    Slot, WitnessSource,
};

use crate::driver::VmDriver;

/// One physical bank (`public`/`shared`), indexed by [`Slot`] instead of a bare `usize` - the one
/// place a `Slot` is finally cast down to index a `Vec`.
struct SlotBank<T>(Vec<T>);

impl<T> std::ops::Index<Slot> for SlotBank<T> {
    type Output = T;

    fn index(&self, slot: Slot) -> &T {
        &self.0[slot.index()]
    }
}

impl<T> std::ops::IndexMut<Slot> for SlotBank<T> {
    fn index_mut(&mut self, slot: Slot) -> &mut T {
        &mut self.0[slot.index()]
    }
}

/// One site's precomputed trace, shaped like co-snarks' `ComponentGadgetOutput` -
/// `output`/`intermediate` are exactly `GadgetSite`'s own outputs and intermediates, so a
/// producer never has to reason about the VM's physical slot layout.
#[derive(Debug, Clone)]
pub struct SiteTrace<S> {
    /// The site's output shares/values.
    pub output: Vec<S>,
    /// The site's intermediate shares/values.
    pub intermediate: Vec<S>,
}

impl<S> SiteTrace<S> {
    /// Builds a trace from its output and intermediate values.
    #[must_use]
    pub fn new(output: Vec<S>, intermediate: Vec<S>) -> Self {
        Self {
            output,
            intermediate,
        }
    }
}

/// A FIFO queue of `BatchKind::PrecomputedPoseidon2` batch traces, one entry per batch in
/// [`Program::precomputed_batches`] order. `Machine::run_with_precomputation` consumes one entry each
/// time it reaches an precomputed batch in the instruction stream, and errors if anything is left
/// over once the run finishes - the same "supplied exactly what was consumed" contract
/// `Rep3Poseidon2Preprocessing::ensure_consumed` enforces for the driver-serviced Poseidon2 mask
/// pool.
#[derive(Debug, Clone)]
pub struct GadgetPrecomputation<S> {
    batches: std::collections::VecDeque<Vec<SiteTrace<S>>>,
}

impl<S> GadgetPrecomputation<S> {
    /// Builds an empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self {
            batches: std::collections::VecDeque::new(),
        }
    }

    /// Queues one batch's traces, one [`SiteTrace`] per site, in the same site order as the
    /// batch's `GadgetBatch`.
    pub fn push_batch(&mut self, sites: Vec<SiteTrace<S>>) {
        self.batches.push_back(sites);
    }

    fn pop(&mut self) -> Option<Vec<SiteTrace<S>>> {
        self.batches.pop_front()
    }

    fn is_empty(&self) -> bool {
        self.batches.is_empty()
    }

    fn len(&self) -> usize {
        self.batches.len()
    }
}

impl<S> Default for GadgetPrecomputation<S> {
    fn default() -> Self {
        Self::new()
    }
}

/// Namespace for the VM's entry points.
pub struct Machine;

/// Ensures `finish_run` executes while unwinding as well as on every ordinary return. The explicit
/// finish path propagates consistency errors; `Drop` deliberately ignores them because replacing an
/// in-flight panic would hide the original failure. Rep3 transitions to `Spent` before its check in
/// either path.
struct RunGuard<'a, D: VmDriver> {
    driver: &'a mut D,
    finished: bool,
}

impl<'a, D: VmDriver> RunGuard<'a, D> {
    fn new(driver: &'a mut D) -> Self {
        Self {
            driver,
            finished: false,
        }
    }

    fn driver(&mut self) -> &mut D {
        self.driver
    }

    fn finish(mut self) -> eyre::Result<()> {
        // Disarm Drop first: a fallible finish must never be attempted twice.
        self.finished = true;
        self.driver.finish_run()
    }
}

impl<D: VmDriver> Drop for RunGuard<'_, D> {
    fn drop(&mut self) {
        if !self.finished {
            drop(self.driver.finish_run());
        }
    }
}

impl Machine {
    /// Same as [`Machine::run_with_precomputation`] with an empty precomputation - errors if the program has
    /// any `BatchKind::PrecomputedPoseidon2` batch rather than silently producing a zero witness value for it.
    ///
    /// # Errors
    ///
    /// Returns an error under the same conditions as [`Machine::run_with_precomputation`].
    pub fn run<D: VmDriver, I: InputValues<D::Share> + ?Sized>(
        program: &Program,
        driver: &mut D,
        inputs: &I,
    ) -> eyre::Result<Vec<D::Share>> {
        Self::run_with_precomputation(program, driver, inputs, GadgetPrecomputation::new())
    }

    /// Like [`Machine::run`], but `precomputation` supplies the trace for every `TACEO_PRECOMPUTATION_Poseidon2`
    /// site instead of the driver computing it: one [`SiteTrace`] per site, queued batch-by-batch
    /// in [`Program::precomputed_batches`] order. Errors if `precomputation` is short, mismatched, or has
    /// anything left over once the run finishes.
    ///
    /// # Errors
    ///
    /// Returns an error if `inputs` doesn't match the program's declared inputs, `program` fails
    /// its own encoding checks, `precomputation` is short, mismatched, or has entries left over
    /// once the run finishes, or the driver itself fails.
    pub fn run_with_precomputation<D: VmDriver, I: InputValues<D::Share> + ?Sized>(
        program: &Program,
        driver: &mut D,
        inputs: &I,
        mut precomputation: GadgetPrecomputation<D::Share>,
    ) -> eyre::Result<Vec<D::Share>> {
        let inputs = inputs.as_inputs(program)?;
        // Begin at the absolute run boundary. Once this succeeds, an invalid program, bad input,
        // network error, or panic all spend a one-shot prepared driver.
        driver.begin_run()?;
        let mut guard = RunGuard::<D>::new(driver);
        let run = Self::run_inner(program, guard.driver(), &inputs, &mut precomputation);
        let finish = guard.finish();
        let witness = match (run, finish) {
            (Ok(witness), Ok(())) => Ok(witness),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(run_error), Err(finish_error)) => Err(eyre::eyre!(
                "{run_error:#}; driver finalization also failed: {finish_error:#}"
            )),
        }?;
        eyre::ensure!(
            precomputation.is_empty(),
            "GadgetPrecomputation has {} unconsumed batch(es) after the run",
            precomputation.len()
        );
        Ok(witness)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "a single forward walk executing every opcode in the instruction stream; splitting it would not improve clarity"
    )]
    fn run_inner<D: VmDriver>(
        program: &Program,
        driver: &mut D,
        inputs: &[InputValue<D::Share>],
        precomputation: &mut GadgetPrecomputation<D::Share>,
    ) -> eyre::Result<Vec<D::Share>> {
        eyre::ensure!(
            inputs.len() == program.num_inputs(),
            "expected {} inputs, got {}",
            program.num_inputs(),
            inputs.len()
        );

        let slots = program.slots();
        let mut public = SlotBank(vec![Fr::zero(); slots.public as usize]);
        let mut shared = SlotBank(vec![D::Share::default(); slots.shared as usize]);

        for (i, c) in program.constants().iter().enumerate() {
            public.0[i] = *c;
        }

        for binding in program.inputs() {
            match (binding.bank, &inputs[binding.input_index.index()]) {
                (Bank::Public, InputValue::Public(v)) => public[binding.slot] = *v,
                (Bank::Shared, InputValue::Secret(v)) => shared[binding.slot] = v.clone(),
                (bank, _) => eyre::bail!(
                    "input {} is {bank:?}-domain but was supplied as the other InputValue variant",
                    binding.input_index
                ),
            }
        }

        let rounds = program.rounds();
        let round_operands = program.round_operands();
        let round_results = program.round_results();
        let gadget_batches = program.gadget_batches();

        let mut pending_mul_lhs: Vec<D::Share> = Vec::new();
        let mut pending_mul_rhs: Vec<D::Share> = Vec::new();
        let mut pending_mul_dst: Vec<Slot> = Vec::new();
        for instr in program.instructions() {
            match *instr {
                Instruction::Arith {
                    op: circom_mpc_program::Opcode::AddPP,
                    dst,
                    a,
                    b,
                } => {
                    public[dst] = public[a] + public[b];
                }
                Instruction::Arith {
                    op: circom_mpc_program::Opcode::SubPP,
                    dst,
                    a,
                    b,
                } => {
                    public[dst] = public[a] - public[b];
                }
                Instruction::Arith {
                    op: circom_mpc_program::Opcode::MulPP,
                    dst,
                    a,
                    b,
                } => {
                    public[dst] = public[a] * public[b];
                }
                Instruction::Arith {
                    op: circom_mpc_program::Opcode::AddSS,
                    dst,
                    a,
                    b,
                } => {
                    shared[dst] = driver.add_ss(&shared[a], &shared[b]);
                }
                Instruction::Arith {
                    op: circom_mpc_program::Opcode::SubSS,
                    dst,
                    a,
                    b,
                } => {
                    shared[dst] = driver.sub_ss(&shared[a], &shared[b]);
                }
                Instruction::Arith {
                    op: circom_mpc_program::Opcode::AddSP,
                    dst,
                    a,
                    b,
                } => {
                    shared[dst] = driver.add_sp(&shared[a], public[b]);
                }
                Instruction::Arith {
                    op: circom_mpc_program::Opcode::SubSP,
                    dst,
                    a,
                    b,
                } => {
                    shared[dst] = driver.sub_sp(&shared[a], public[b]);
                }
                Instruction::Arith {
                    op: circom_mpc_program::Opcode::SubPS,
                    dst,
                    a,
                    b,
                } => {
                    shared[dst] = driver.sub_ps(public[a], &shared[b]);
                }
                Instruction::Arith {
                    op: circom_mpc_program::Opcode::MulSP,
                    dst,
                    a,
                    b,
                } => {
                    shared[dst] = driver.mul_sp(&shared[a], public[b]);
                }
                Instruction::Arith {
                    op: circom_mpc_program::Opcode::MulLocal,
                    dst,
                    a,
                    b,
                } => {
                    // Codegen may recycle these shared slots before the round boundary, so retain
                    // the values rather than only their indices. The expensive masked product is
                    // still delayed and vectorized across the complete round.
                    pending_mul_lhs.push(shared[a].clone());
                    pending_mul_rhs.push(shared[b].clone());
                    pending_mul_dst.push(dst);
                }
                Instruction::Arith {
                    op: circom_mpc_program::Opcode::Reshare | circom_mpc_program::Opcode::Gadget,
                    ..
                } => unreachable!("Reshare/Gadget never appear in an Arith instruction"),
                Instruction::Reshare(round_idx) => {
                    let entry = rounds[round_idx.index()];
                    let start = entry.operand_start as usize;
                    let len = entry.len as usize;
                    eyre::ensure!(
                        pending_mul_dst.as_slice() == &round_operands[start..start + len],
                        "MulLocal instructions do not match the following round's operand table"
                    );
                    let results = driver.mul_vec(&pending_mul_lhs, &pending_mul_rhs)?;
                    pending_mul_lhs.clear();
                    pending_mul_rhs.clear();
                    pending_mul_dst.clear();
                    eyre::ensure!(
                        results.len() == len,
                        "reshare returned {} results, expected {len}",
                        results.len()
                    );
                    let rstart = entry.result_start as usize;
                    for (k, r) in results.into_iter().enumerate() {
                        shared[round_results[rstart + k]] = r;
                    }
                }
                Instruction::Gadget(batch_idx) => Self::run_batch(
                    &gadget_batches[batch_idx.index()],
                    driver,
                    &mut public,
                    &mut shared,
                    precomputation,
                )?,
            }
        }
        eyre::ensure!(
            pending_mul_dst.is_empty(),
            "program ended with MulLocal instructions not followed by Reshare"
        );

        // Codegen has already projected circom's flat signal address space into witness order.
        // Build exactly the final witness: no `num_signals`-sized zero-fill and no second clone
        // pass over that temporary array.
        let witness_sources = program.witness_sources();
        let mut witness = Vec::with_capacity(witness_sources.len());
        for source in witness_sources {
            witness.push(match *source {
                WitnessSource::One => driver.promote(Fr::one()),
                WitnessSource::Zero => driver.promote(Fr::zero()),
                WitnessSource::Input(input_index) => match &inputs[input_index.index()] {
                    InputValue::Public(value) => driver.promote(*value),
                    InputValue::Secret(value) => value.clone(),
                },
                WitnessSource::Slot {
                    bank: Bank::Public,
                    slot,
                } => driver.promote(public[slot]),
                WitnessSource::Slot {
                    bank: Bank::Shared,
                    slot,
                } => shared[slot].clone(),
                WitnessSource::Slot {
                    bank: Bank::Local, ..
                } => unreachable!("codegen never emits a Local witness source"),
            });
        }
        Ok(witness)
    }

    /// Services one batched gadget site group at its point in the instruction stream. A
    /// public batch uses the plain gadget path; a shared batch is one driver call. Interleaving is
    /// required because a site's inputs may be produced by earlier instructions.
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
    fn run_batch<D: VmDriver>(
        batch: &GadgetBatch,
        driver: &mut D,
        public: &mut SlotBank<Fr>,
        shared: &mut SlotBank<D::Share>,
        precomputation: &mut GadgetPrecomputation<D::Share>,
    ) -> eyre::Result<()> {
        if batch.kind == BatchKind::IsZeroReveal {
            return Self::run_is_zero_reveal_batch(batch, driver, public, shared);
        }
        if let BatchKind::PrecomputedPoseidon2 { t } = batch.kind {
            return Self::run_precomputed_batch(t.get(), batch, precomputation, shared);
        }
        let BatchKind::Gadget(kind) = batch.kind else {
            unreachable!("fused and host-precomputed batches handled above")
        };
        // Whether this batch needs a genuine MPC call, rather than inferring it from result targets:
        // for every kind but `Reveal` the two coincide (a site's inputs are all-`Public` exactly
        // when its result stays `Public`), but `Reveal`'s result target is unconditionally `Public`
        // even when its own inputs are `Shared` - that is its entire purpose (see
        // `GadgetKind::Reveal`), and precisely that case still needs a real `driver.open` call.
        let needs_mpc = batch
            .input_slots
            .iter()
            .any(|input| input.bank == Bank::Shared);

        let result_requests: Vec<u32> = batch.result_requests.iter().map(|r| r.get()).collect();

        if !needs_mpc {
            let inputs: Vec<Fr> = batch
                .input_slots
                .iter()
                .map(|input| {
                    eyre::ensure!(
                        input.bank == Bank::Public,
                        "public gadget batch has a non-public input"
                    );
                    Ok(public[input.slot])
                })
                .collect::<eyre::Result<_>>()?;
            if let GadgetKind::Poseidon2 { t } = kind {
                let selected = crate::gadgets::poseidon2::plain_trace_requested(
                    t.get(),
                    &inputs,
                    &result_requests,
                    &batch.result_offsets,
                )?;
                return Self::store_batch_results(batch, selected, Bank::Public, public);
            }
            let results = Self::run_plain_batch(kind, &inputs)?;
            let selected = Self::select_requests(&results, batch)?;
            return Self::store_batch_results(batch, selected, Bank::Public, public);
        }

        // A site input isn't always a share - a circuit may pass a literal, which codegen resolves
        // to a `Public`-bank slot (see `SiteInput`). Promote those; every gadget expects shares.
        let inputs: Vec<D::Share> = batch
            .input_slots
            .iter()
            .map(|input| match input.bank {
                Bank::Public => driver.promote(public[input.slot]),
                Bank::Shared => shared[input.slot].clone(),
                Bank::Local => unreachable!(
                    "codegen rejects an un-reshared MulLocal feeding a site"
                ),
            })
            .collect();

        // `Reveal` is the one kind whose MPC path writes into the `Public` bank (a genuine open,
        // rather than a share-producing gadget) - every other kind writes into `Shared`.
        if let GadgetKind::Reveal { .. } = kind {
            let opened = driver.open(&inputs)?;
            let selected = Self::select_requests(&opened, batch)?;
            return Self::store_batch_results(batch, selected, Bank::Public, public);
        }
        if let GadgetKind::Poseidon2 { t } = kind {
            let selected = driver.poseidon2_requested_traces(
                t.get(),
                &inputs,
                &result_requests,
                &batch.result_offsets,
            )?;
            return Self::store_batch_results(batch, selected, Bank::Shared, shared);
        }
        let results = match kind {
            GadgetKind::Num2Bits { n } => driver.num2bits_traces(n, &inputs)?,
            GadgetKind::IsZero => driver.is_zero_traces(&inputs)?,
            GadgetKind::AliasCheck => driver.alias_check_traces(&inputs)?,
            GadgetKind::Poseidon2 { .. } | GadgetKind::Reveal { .. } => {
                unreachable!("handled above")
            }
        };
        let selected = Self::select_requests(&results, batch)?;
        Self::store_batch_results(batch, selected, Bank::Shared, shared)
    }

    fn run_is_zero_reveal_batch<D: VmDriver>(
        batch: &GadgetBatch,
        driver: &mut D,
        public: &mut SlotBank<Fr>,
        shared: &mut SlotBank<D::Share>,
    ) -> eyre::Result<()> {
        eyre::ensure!(batch.sites > 0, "fused IsZero/Reveal batch has no sites");
        eyre::ensure!(
            batch.input_slots.len() == batch.sites,
            "fused IsZero/Reveal batch has {} inputs for {} sites",
            batch.input_slots.len(),
            batch.sites
        );
        let inputs: Vec<_> = batch
            .input_slots
            .iter()
            .map(|input| {
                eyre::ensure!(
                    input.bank == Bank::Shared,
                    "fused IsZero/Reveal requires one Shared input per site"
                );
                Ok(shared[input.slot].clone())
            })
            .collect::<eyre::Result<_>>()?;
        let traces = driver.is_zero_reveal_traces(&inputs)?;
        eyre::ensure!(
            traces.len() == batch.sites,
            "fused IsZero/Reveal returned {} site traces, expected {}",
            traces.len(),
            batch.sites
        );
        eyre::ensure!(
            batch.result_offsets.len() == batch.sites + 1
                && batch.result_requests.len() == batch.result_targets.len(),
            "malformed fused IsZero/Reveal CSR result table"
        );
        for (site, (is_zero, inverse, revealed)) in traces.into_iter().enumerate() {
            let lo = batch.result_offsets[site] as usize;
            let hi = batch.result_offsets[site + 1] as usize;
            eyre::ensure!(
                lo <= hi && hi <= batch.result_requests.len(),
                "invalid fused CSR row"
            );
            for (&logical, target) in batch.result_requests[lo..hi]
                .iter()
                .zip(&batch.result_targets[lo..hi])
            {
                match logical.get() {
                    0 => {
                        eyre::ensure!(target.bank == Bank::Shared, "IsZero.out must target Shared");
                        shared[target.slot] = is_zero.clone();
                    }
                    1 => {
                        eyre::ensure!(target.bank == Bank::Shared, "IsZero.inv must target Shared");
                        shared[target.slot] = inverse.clone();
                    }
                    2 => {
                        eyre::ensure!(target.bank == Bank::Public, "Reveal.out must target Public");
                        public[target.slot] = revealed;
                    }
                    other => {
                        eyre::bail!("fused IsZero/Reveal requested invalid logical slot {other}")
                    }
                }
            }
        }
        Ok(())
    }

    /// Services a `BatchKind::PrecomputedPoseidon2` batch: instead of calling the driver, pops the
    /// next queued [`SiteTrace`] group off `precomputation` and writes it straight into the `Shared`
    /// bank through the batch's own CSR result table - the same request/target machinery every
    /// other batch kind uses. `Program::validate` already guarantees every result target here is
    /// `Bank::Shared`, so this never touches `public`.
    fn run_precomputed_batch<S: Clone>(
        t: usize,
        batch: &GadgetBatch,
        precomputation: &mut GadgetPrecomputation<S>,
        shared: &mut SlotBank<S>,
    ) -> eyre::Result<()> {
        let num_outputs = t;
        let sites = precomputation.pop().ok_or_else(|| {
            eyre::eyre!(
                "missing precomputed trace for a Poseidon2{{t={t}}} batch ({} sites) - \
                 GadgetPrecomputation was exhausted before the run reached it",
                batch.sites
            )
        })?;
        eyre::ensure!(
            sites.len() == batch.sites,
            "precomputed Poseidon2{{t={t}}} batch was supplied {} site trace(s), expected {}",
            sites.len(),
            batch.sites
        );
        eyre::ensure!(
            batch.result_offsets.len() == batch.sites + 1
                && batch.result_requests.len() == batch.result_targets.len(),
            "malformed precomputed batch CSR result table"
        );
        for (site, trace) in sites.iter().enumerate() {
            eyre::ensure!(
                trace.output.len() == num_outputs,
                "precomputed Poseidon2{{t={t}}} site {site} supplied {} outputs, expected \
                 {num_outputs}",
                trace.output.len()
            );
            let lo = batch.result_offsets[site] as usize;
            let hi = batch.result_offsets[site + 1] as usize;
            eyre::ensure!(
                lo <= hi && hi <= batch.result_requests.len(),
                "invalid precomputed batch CSR row"
            );
            for (&logical, target) in batch.result_requests[lo..hi]
                .iter()
                .zip(&batch.result_targets[lo..hi])
            {
                eyre::ensure!(
                    target.bank == Bank::Shared,
                    "precomputed Poseidon2{{t={t}}} result must target Shared"
                );
                let logical = logical.index();
                let value = if logical < num_outputs {
                    trace.output[logical].clone()
                } else {
                    let idx = logical - num_outputs;
                    trace.intermediate.get(idx).cloned().ok_or_else(|| {
                        eyre::eyre!(
                            "precomputed Poseidon2{{t={t}}} site {site} requested intermediate slot \
                             {idx}, but only {} were supplied",
                            trace.intermediate.len()
                        )
                    })?
                };
                shared[target.slot] = value;
            }
        }
        Ok(())
    }

    fn run_plain_batch(kind: GadgetKind, inputs: &[Fr]) -> eyre::Result<Vec<Fr>> {
        use crate::gadgets::{aliascheck, iszero, num2bits};

        Ok(match kind {
            GadgetKind::Poseidon2 { .. } => {
                unreachable!("public Poseidon2 takes the requested-trace path in run_batch")
            }
            GadgetKind::Num2Bits { n } => inputs
                .iter()
                .flat_map(|&x| num2bits::plain_trace(x, n))
                .collect(),
            GadgetKind::IsZero => inputs
                .iter()
                .flat_map(|&x| iszero::plain_trace(x))
                .collect(),
            GadgetKind::AliasCheck => {
                eyre::ensure!(
                    inputs.len().is_multiple_of(254),
                    "alias_check_traces: {} inputs is not a multiple of 254",
                    inputs.len()
                );
                inputs
                    .as_chunks::<254>()
                    .0
                    .iter()
                    .flat_map(|chunk| aliascheck::plain_trace(chunk))
                    .collect()
            }
            // An all-public reveal is the identity: every party already holds every input in the
            // clear, so "opening" it changes nothing.
            GadgetKind::Reveal { .. } => inputs.to_vec(),
        })
    }

    /// Selects each site's witness-live logical result slots out of a gadget's full per-site
    /// output, flattening site-major. A temporary bridge (,
    /// "Precomputation"): gadgets other than Poseidon2 still compute and return their *full*
    /// per-site trace (`num_outputs + num_intermediates` values), and this filters the
    /// `GadgetBatch::result_requests` subset before storing. Poseidon2 consumes this CSR table
    /// directly and bypasses this bridge.
    fn select_requests<T: Clone>(full: &[T], batch: &GadgetBatch) -> eyre::Result<Vec<T>> {
        eyre::ensure!(batch.sites > 0, "gadget batch has no sites");
        eyre::ensure!(
            full.len().is_multiple_of(batch.sites),
            "gadget batch ({:?}, {} sites) returned {} results, not an even multiple of \
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
                let logical = logical.index();
                eyre::ensure!(
                    logical < capacity,
                    "gadget batch ({:?}) requested slot {logical}, exceeding the {capacity} \
                     the circuit's own signal layout reserves",
                    batch.kind
                );
                selected.push(site_full[logical].clone());
            }
        }
        Ok(selected)
    }

    fn store_batch_results<T>(
        batch: &GadgetBatch,
        results: Vec<T>,
        expected_bank: Bank,
        destination: &mut SlotBank<T>,
    ) -> eyre::Result<()> {
        eyre::ensure!(
            results.len() == batch.result_targets.len(),
            "gadget batch ({:?}) produced {} results, expected exactly {} (one per requested \
             slot)",
            batch.kind,
            results.len(),
            batch.result_targets.len()
        );
        for (target, value) in batch.result_targets.iter().zip(results) {
            eyre::ensure!(
                target.bank == expected_bank,
                "gadget batch ({:?}) result targets mixed banks unexpectedly",
                batch.kind
            );
            destination[target.slot] = value;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;

    use super::*;
    use circom_mpc_program::{ProgramParts, SlotCounts};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum MockLifecycle {
        Ready,
        Running,
        Spent,
    }

    struct PanicDriver {
        lifecycle: MockLifecycle,
        finish_calls: usize,
    }

    impl PanicDriver {
        fn new() -> Self {
            Self {
                lifecycle: MockLifecycle::Ready,
                finish_calls: 0,
            }
        }
    }

    impl VmDriver for PanicDriver {
        type Share = Fr;

        fn begin_run(&mut self) -> eyre::Result<()> {
            match self.lifecycle {
                MockLifecycle::Ready => {
                    self.lifecycle = MockLifecycle::Running;
                    Ok(())
                }
                MockLifecycle::Running | MockLifecycle::Spent => {
                    eyre::bail!("mock driver is spent")
                }
            }
        }

        fn finish_run(&mut self) -> eyre::Result<()> {
            self.lifecycle = MockLifecycle::Spent;
            self.finish_calls += 1;
            Ok(())
        }

        fn promote(&mut self, _value: Fr) -> Fr {
            panic!("intentional execution panic")
        }

        fn add_ss(&mut self, _a: &Fr, _b: &Fr) -> Fr {
            unreachable!("minimal panic fixture has no instructions")
        }

        fn sub_ss(&mut self, _a: &Fr, _b: &Fr) -> Fr {
            unreachable!("minimal panic fixture has no instructions")
        }

        fn add_sp(&mut self, _a: &Fr, _b: Fr) -> Fr {
            unreachable!("minimal panic fixture has no instructions")
        }

        fn sub_sp(&mut self, _a: &Fr, _b: Fr) -> Fr {
            unreachable!("minimal panic fixture has no instructions")
        }

        fn sub_ps(&mut self, _a: Fr, _b: &Fr) -> Fr {
            unreachable!("minimal panic fixture has no instructions")
        }

        fn mul_sp(&mut self, _a: &Fr, _b: Fr) -> Fr {
            unreachable!("minimal panic fixture has no instructions")
        }

        fn mul_vec(&mut self, _a: &[Fr], _b: &[Fr]) -> eyre::Result<Vec<Fr>> {
            unreachable!("minimal panic fixture has no instructions")
        }

        fn open(&mut self, _shares: &[Fr]) -> eyre::Result<Vec<Fr>> {
            unreachable!("minimal panic fixture has no instructions")
        }

        fn poseidon2_requested_traces(
            &mut self,
            _t: usize,
            _states: &[Fr],
            _result_requests: &[u32],
            _result_offsets: &[u32],
        ) -> eyre::Result<Vec<Fr>> {
            unreachable!("minimal panic fixture has no instructions")
        }

        fn num2bits_traces(&mut self, _n: usize, _inputs: &[Fr]) -> eyre::Result<Vec<Fr>> {
            unreachable!("minimal panic fixture has no instructions")
        }

        fn is_zero_traces(&mut self, _inputs: &[Fr]) -> eyre::Result<Vec<Fr>> {
            unreachable!("minimal panic fixture has no instructions")
        }

        fn is_zero_reveal_traces(&mut self, _inputs: &[Fr]) -> eyre::Result<Vec<(Fr, Fr, Fr)>> {
            unreachable!("minimal panic fixture has no instructions")
        }

        fn alias_check_traces(&mut self, _inputs: &[Fr]) -> eyre::Result<Vec<Fr>> {
            unreachable!("minimal panic fixture has no instructions")
        }
    }

    #[test]
    fn panic_finishes_and_spends_the_driver() {
        let program = Program::new(ProgramParts {
            instructions: Vec::new(),
            constants: Vec::new(),
            input_domains: Vec::new(),
            inputs: Vec::new(),
            input_signals: Vec::new(),
            rounds: Vec::new(),
            round_operands: Vec::new(),
            round_results: Vec::new(),
            gadget_batches: Vec::new(),
            witness_sources: vec![WitnessSource::One],
            num_inputs: 0,
            slots: SlotCounts::default(),
        });
        let mut driver = PanicDriver::new();

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drop(Machine::run(&program, &mut driver, &[]));
        }));
        assert!(panic.is_err());
        assert_eq!(driver.lifecycle, MockLifecycle::Spent);
        assert_eq!(driver.finish_calls, 1);

        let reuse = Machine::run(&program, &mut driver, &[])
            .expect_err("a spent driver must refuse to run again");
        assert!(reuse.to_string().contains("spent"));
        assert_eq!(driver.finish_calls, 1, "failed begin must not call finish");
    }
}
