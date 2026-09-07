//! `Vm`: prepares a `circom_mpc_program::Program` against a pluggable `VmDriver` -
//! `driver::plain::PlainDriver` (single-party, the reference driver) or a real three-party rep3
//! driver - and runs it exactly once. `run` consumes the `Vm`, so a one-shot driver's lifecycle is
//! enforced by the type system rather than at runtime.

use ark_bn254::Fr;
use ark_ff::{One, Zero};
use circom_mpc_program::{
    Bank, BatchKind, GadgetBatch, GadgetKind, InputValue, InputValues, Instruction, Opcode,
    Program, Slot, WitnessSource,
};
use mpc_core::protocols::rep3::Rep3State;
use mpc_net::Network;

use crate::driver::{VmDriver, plain::PlainDriver, rep3::Rep3Driver};

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
/// [`Program::precomputed_batches`] order. `Vm::run` consumes one entry each time it reaches a
/// precomputed batch in the instruction stream, and errors if anything is left over once the run
/// finishes - the same "supplied exactly what was consumed" contract
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

/// A [`Vm::run`] witness split into co-snarks' `SharedWitness` shape at the split point
/// `Program::num_public_witness` names: a cleartext `public_inputs` prefix (position 0 is the
/// reserved constant `1`) and a secret-shared remainder. The split's one batched `open` happens
/// inside `run` itself, so there is no separate "pass the matching driver" step afterward.
#[derive(Debug, Clone)]
pub struct Witness<S> {
    /// The opened public prefix, including the reserved leading `1`.
    pub public_inputs: Vec<Fr>,
    /// The secret-shared remainder.
    pub witness: Vec<S>,
}

impl<S> Witness<S> {
    /// Splits this witness back into its two parts.
    #[must_use]
    pub fn into_parts(self) -> (Vec<Fr>, Vec<S>) {
        (self.public_inputs, self.witness)
    }

    /// Total witness length (`public_inputs.len() + witness.len()`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.public_inputs.len() + self.witness.len()
    }

    /// Always `false`: `public_inputs` holds at least the reserved constant `1`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Witness<Fr> {
    /// Recombines a plain witness into one flat vector, in original witness order - the common
    /// case for a `PlainDriver` run, which has nothing left to keep secret.
    #[must_use]
    pub fn into_full(mut self) -> Vec<Fr> {
        self.public_inputs.append(&mut self.witness);
        self.public_inputs
    }
}

/// Prepares a [`Program`] against one [`VmDriver`] and runs it exactly once. Construct with
/// [`Vm::plain`] or [`Vm::rep3`] (or [`Vm::new`] for a custom driver), optionally attach host
/// precomputation with [`Vm::with_precomputation`], then consume it with [`Vm::run`].
pub struct Vm<'p, D: VmDriver> {
    program: &'p Program,
    driver: D,
    precomputation: GadgetPrecomputation<D::Share>,
    // Execution state: empty until `run` allocates it, private so the pre-run state is
    // unobservable and `run` consuming `self` is the only way to fill it in.
    public: SlotBank<Fr>,
    shared: SlotBank<D::Share>,
    pending_mul_lhs: Vec<D::Share>,
    pending_mul_rhs: Vec<D::Share>,
    pending_mul_dst: Vec<Slot>,
}

impl<'p, D: VmDriver> Vm<'p, D> {
    /// Builds a `Vm` prepared to run `program` once against `driver`.
    #[must_use]
    pub fn new(program: &'p Program, driver: D) -> Self {
        Self {
            program,
            driver,
            precomputation: GadgetPrecomputation::new(),
            public: SlotBank(Vec::new()),
            shared: SlotBank(Vec::new()),
            pending_mul_lhs: Vec::new(),
            pending_mul_rhs: Vec::new(),
            pending_mul_dst: Vec::new(),
        }
    }

    /// Supplies the trace for every `TACEO_PRECOMPUTATION_Poseidon2` site instead of the driver
    /// computing it: one [`SiteTrace`] per site, queued batch-by-batch in
    /// [`Program::precomputed_batches`] order.
    #[must_use]
    pub fn with_precomputation(mut self, precomputation: GadgetPrecomputation<D::Share>) -> Self {
        self.precomputation = precomputation;
        self
    }

    /// Executes `program` against `inputs`, consuming this `Vm`.
    ///
    /// # Errors
    ///
    /// Returns an error if `inputs` doesn't match the program's declared inputs, the attached
    /// precomputation is short, mismatched, or has entries left over once the run finishes, the
    /// driver itself fails, or the program has an unattached `BatchKind::PrecomputedPoseidon2`
    /// batch.
    #[allow(
        clippy::too_many_lines,
        reason = "a single forward walk executing every opcode in the instruction stream; splitting it would not improve clarity"
    )]
    pub fn run<I: InputValues<D::Share> + ?Sized>(
        mut self,
        inputs: &I,
    ) -> eyre::Result<Witness<D::Share>> {
        // A plain reference copy, independent of `self` - lets every read below borrow `program`
        // directly instead of `self.program`, so it never conflicts with the `&mut self` calls
        // that follow.
        let program: &'p Program = self.program;
        let inputs = inputs.as_inputs(program)?;
        eyre::ensure!(
            inputs.len() == program.num_inputs(),
            "expected {} inputs, got {}",
            program.num_inputs(),
            inputs.len()
        );

        let slots = program.slots();
        self.public = SlotBank(vec![Fr::zero(); slots.public as usize]);
        self.shared = SlotBank(vec![D::Share::default(); slots.shared as usize]);

        for (i, c) in program.constants().iter().enumerate() {
            self.public.0[i] = *c;
        }

        for binding in program.inputs() {
            match (binding.bank, &inputs[binding.input_index.index()]) {
                (Bank::Public, InputValue::Public(v)) => self.public[binding.slot] = *v,
                (Bank::Shared, InputValue::Secret(v)) => self.shared[binding.slot] = v.clone(),
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

        for instr in program.instructions() {
            match *instr {
                Instruction::Arith {
                    op: Opcode::AddPP,
                    dst,
                    a,
                    b,
                } => {
                    self.public[dst] = self.public[a] + self.public[b];
                }
                Instruction::Arith {
                    op: Opcode::SubPP,
                    dst,
                    a,
                    b,
                } => {
                    self.public[dst] = self.public[a] - self.public[b];
                }
                Instruction::Arith {
                    op: Opcode::MulPP,
                    dst,
                    a,
                    b,
                } => {
                    self.public[dst] = self.public[a] * self.public[b];
                }
                Instruction::Arith {
                    op: Opcode::AddSS,
                    dst,
                    a,
                    b,
                } => {
                    self.shared[dst] = self.driver.add_ss(&self.shared[a], &self.shared[b]);
                }
                Instruction::Arith {
                    op: Opcode::SubSS,
                    dst,
                    a,
                    b,
                } => {
                    self.shared[dst] = self.driver.sub_ss(&self.shared[a], &self.shared[b]);
                }
                Instruction::Arith {
                    op: Opcode::AddSP,
                    dst,
                    a,
                    b,
                } => {
                    self.shared[dst] = self.driver.add_sp(&self.shared[a], self.public[b]);
                }
                Instruction::Arith {
                    op: Opcode::SubSP,
                    dst,
                    a,
                    b,
                } => {
                    self.shared[dst] = self.driver.sub_sp(&self.shared[a], self.public[b]);
                }
                Instruction::Arith {
                    op: Opcode::SubPS,
                    dst,
                    a,
                    b,
                } => {
                    self.shared[dst] = self.driver.sub_ps(self.public[a], &self.shared[b]);
                }
                Instruction::Arith {
                    op: Opcode::MulSP,
                    dst,
                    a,
                    b,
                } => {
                    self.shared[dst] = self.driver.mul_sp(&self.shared[a], self.public[b]);
                }
                Instruction::Arith {
                    op: Opcode::MulLocal,
                    dst,
                    a,
                    b,
                } => {
                    // Codegen may recycle these shared slots before the round boundary, so retain
                    // the values rather than only their indices. The expensive masked product is
                    // still delayed and vectorized across the complete round.
                    self.pending_mul_lhs.push(self.shared[a].clone());
                    self.pending_mul_rhs.push(self.shared[b].clone());
                    self.pending_mul_dst.push(dst);
                }
                Instruction::Arith {
                    op: Opcode::Reshare | Opcode::Gadget,
                    ..
                } => unreachable!("Reshare/Gadget never appear in an Arith instruction"),
                Instruction::Reshare(round_idx) => {
                    let entry = rounds[round_idx.index()];
                    let start = entry.operand_start as usize;
                    let len = entry.len as usize;
                    eyre::ensure!(
                        self.pending_mul_dst.as_slice() == &round_operands[start..start + len],
                        "MulLocal instructions do not match the following round's operand table"
                    );
                    let results = self
                        .driver
                        .mul_vec(&self.pending_mul_lhs, &self.pending_mul_rhs)?;
                    self.pending_mul_lhs.clear();
                    self.pending_mul_rhs.clear();
                    self.pending_mul_dst.clear();
                    eyre::ensure!(
                        results.len() == len,
                        "reshare returned {} results, expected {len}",
                        results.len()
                    );
                    let rstart = entry.result_start as usize;
                    for (k, r) in results.into_iter().enumerate() {
                        self.shared[round_results[rstart + k]] = r;
                    }
                }
                Instruction::Gadget(batch_idx) => {
                    self.run_batch(&gadget_batches[batch_idx.index()])?;
                }
            }
        }
        eyre::ensure!(
            self.pending_mul_dst.is_empty(),
            "program ended with MulLocal instructions not followed by Reshare"
        );

        // Codegen has already projected circom's flat signal address space into witness order.
        // Build exactly the final witness: no `num_signals`-sized zero-fill and no second clone
        // pass over that temporary array.
        let witness_sources = program.witness_sources();
        let mut witness = Vec::with_capacity(witness_sources.len());
        for source in witness_sources {
            witness.push(match *source {
                WitnessSource::One => self.driver.promote(Fr::one()),
                WitnessSource::Zero => self.driver.promote(Fr::zero()),
                WitnessSource::Input(input_index) => match &inputs[input_index.index()] {
                    InputValue::Public(value) => self.driver.promote(*value),
                    InputValue::Secret(value) => value.clone(),
                },
                WitnessSource::Slot {
                    bank: Bank::Public,
                    slot,
                } => self.driver.promote(self.public[slot]),
                WitnessSource::Slot {
                    bank: Bank::Shared,
                    slot,
                } => self.shared[slot].clone(),
                WitnessSource::Slot {
                    bank: Bank::Local, ..
                } => unreachable!("codegen never emits a Local witness source"),
            });
        }

        eyre::ensure!(
            self.precomputation.is_empty(),
            "GadgetPrecomputation has {} unconsumed batch(es) after the run",
            self.precomputation.len()
        );
        self.driver.finish()?;

        // Split at the program's own public-witness count and open the prefix - see the module
        // doc on `Witness`. `n_pub` comes from the circuit's declared public signals (via
        // `Program::num_public_witness`), never from the MPC domain analysis `input_domains`
        // reflects.
        let n_pub = program.num_public_witness() as usize;
        eyre::ensure!(
            n_pub <= witness.len(),
            "witness has {} entries but the program declares {n_pub} public witness entries",
            witness.len()
        );
        eyre::ensure!(
            n_pub > 0,
            "num_public_witness must count the reserved constant-1 witness entry, so it is never 0"
        );
        let secret = witness.split_off(n_pub);
        let public_inputs = self.driver.open(&witness)?;
        debug_assert_eq!(
            public_inputs.len(),
            n_pub,
            "open must return one value per opened share"
        );
        eyre::ensure!(
            public_inputs[0] == Fr::one(),
            "witness position 0 must be the reserved constant 1, got something else - either the \
             program is malformed or num_public_witness is misaligned"
        );

        Ok(Witness {
            public_inputs,
            witness: secret,
        })
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
    fn run_batch(&mut self, batch: &GadgetBatch) -> eyre::Result<()> {
        if batch.kind == BatchKind::IsZeroReveal {
            return self.run_is_zero_reveal_batch(batch);
        }
        if let BatchKind::PrecomputedPoseidon2 { t } = batch.kind {
            return self.run_precomputed_batch(t.get(), batch);
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
            let public = &self.public;
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
                return store_batch_results(batch, selected, Bank::Public, &mut self.public);
            }
            let results = run_plain_batch(kind, &inputs)?;
            let selected = select_requests(&results, batch)?;
            return store_batch_results(batch, selected, Bank::Public, &mut self.public);
        }

        // A site input isn't always a share - a circuit may pass a literal, which codegen resolves
        // to a `Public`-bank slot (see `SiteInput`). Promote those; every gadget expects shares.
        let driver = &mut self.driver;
        let public = &self.public;
        let shared = &self.shared;
        let inputs: Vec<D::Share> = batch
            .input_slots
            .iter()
            .map(|input| match input.bank {
                Bank::Public => driver.promote(public[input.slot]),
                Bank::Shared => shared[input.slot].clone(),
                Bank::Local => {
                    unreachable!("codegen rejects an un-reshared MulLocal feeding a site")
                }
            })
            .collect();

        // `Reveal` is the one kind whose MPC path writes into the `Public` bank (a genuine open,
        // rather than a share-producing gadget) - every other kind writes into `Shared`.
        if let GadgetKind::Reveal { .. } = kind {
            let opened = self.driver.open(&inputs)?;
            let selected = select_requests(&opened, batch)?;
            return store_batch_results(batch, selected, Bank::Public, &mut self.public);
        }
        if let GadgetKind::Poseidon2 { t } = kind {
            let selected = self.driver.poseidon2_requested_traces(
                t.get(),
                &inputs,
                &result_requests,
                &batch.result_offsets,
            )?;
            return store_batch_results(batch, selected, Bank::Shared, &mut self.shared);
        }
        let results = match kind {
            GadgetKind::Num2Bits { n } => self.driver.num2bits_traces(n, &inputs)?,
            GadgetKind::IsZero => self.driver.is_zero_traces(&inputs)?,
            GadgetKind::AliasCheck => self.driver.alias_check_traces(&inputs)?,
            GadgetKind::Poseidon2 { .. } | GadgetKind::Reveal { .. } => {
                unreachable!("handled above")
            }
        };
        let selected = select_requests(&results, batch)?;
        store_batch_results(batch, selected, Bank::Shared, &mut self.shared)
    }

    fn run_is_zero_reveal_batch(&mut self, batch: &GadgetBatch) -> eyre::Result<()> {
        eyre::ensure!(batch.sites > 0, "fused IsZero/Reveal batch has no sites");
        eyre::ensure!(
            batch.input_slots.len() == batch.sites,
            "fused IsZero/Reveal batch has {} inputs for {} sites",
            batch.input_slots.len(),
            batch.sites
        );
        let shared = &self.shared;
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
        let traces = self.driver.is_zero_reveal_traces(&inputs)?;
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
                        self.shared[target.slot] = is_zero.clone();
                    }
                    1 => {
                        eyre::ensure!(target.bank == Bank::Shared, "IsZero.inv must target Shared");
                        self.shared[target.slot] = inverse.clone();
                    }
                    2 => {
                        eyre::ensure!(target.bank == Bank::Public, "Reveal.out must target Public");
                        self.public[target.slot] = revealed;
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
    /// next queued [`SiteTrace`] group off `self.precomputation` and writes it straight into the
    /// `Shared` bank through the batch's own CSR result table - the same request/target machinery
    /// every other batch kind uses. `Program::validate_encoding` already guarantees every result
    /// target here is `Bank::Shared`, so this never touches `public`.
    fn run_precomputed_batch(&mut self, t: usize, batch: &GadgetBatch) -> eyre::Result<()> {
        let num_outputs = t;
        let sites = self.precomputation.pop().ok_or_else(|| {
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
                self.shared[target.slot] = value;
            }
        }
        Ok(())
    }
}

impl<'p> Vm<'p, PlainDriver> {
    /// A single-party reference [`Vm`] - see [`PlainDriver`].
    #[must_use]
    pub fn plain(program: &'p Program) -> Self {
        Self::new(program, PlainDriver)
    }
}

impl<'p, 'n, N: Network> Vm<'p, Rep3Driver<'n, N>> {
    /// Prepares a fresh rep3 [`Vm`] for one run - see [`Rep3Driver::new`].
    ///
    /// # Errors
    ///
    /// Returns an error if `program` fails its own encoding checks, or preparing the Poseidon2
    /// mask pool fails.
    pub fn rep3(program: &'p Program, net: &'n N, state: &'n mut Rep3State) -> eyre::Result<Self> {
        let driver = Rep3Driver::new(net, state, program)?;
        Ok(Self::new(program, driver))
    }
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
