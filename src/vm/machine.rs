//! Executes a `Program` against a `VmDriver`: the same bytecode runs against `PlainDriver` (the
//! reference driver) or a real rep3 driver, the only difference being which `VmDriver` is passed
//! in.

use ark_ff::PrimeField;

use crate::ir::PrecomputeKind;

use super::driver::VmDriver;
use super::program::{Bank, BatchKind, Opcode, PrecomputeBatch, Program, WitnessSource};

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

/// Ensures `finish_run` executes while unwinding as well as on every ordinary return. The explicit
/// finish path propagates consistency errors; `Drop` deliberately ignores them because replacing an
/// in-flight panic would hide the original failure. Rep3 transitions to `Spent` before its check in
/// either path.
struct RunGuard<'a, F: PrimeField, D: VmDriver<F>> {
    driver: &'a mut D,
    finished: bool,
    field: std::marker::PhantomData<F>,
}

impl<'a, F: PrimeField, D: VmDriver<F>> RunGuard<'a, F, D> {
    fn new(driver: &'a mut D) -> Self {
        Self {
            driver,
            finished: false,
            field: std::marker::PhantomData,
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

impl<F: PrimeField, D: VmDriver<F>> Drop for RunGuard<'_, F, D> {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.driver.finish_run();
        }
    }
}

impl Machine {
    pub fn run<F: PrimeField, D: VmDriver<F>>(
        program: &Program<F>,
        driver: &mut D,
        inputs: &[InputValue<F, D::Share>],
    ) -> eyre::Result<Vec<D::Share>> {
        // Begin at the absolute run boundary. Once this succeeds, an invalid program, bad input,
        // network error, or panic all spend a one-shot prepared driver.
        driver.begin_run()?;
        let mut guard = RunGuard::<F, D>::new(driver);
        let run = Self::run_inner(program, guard.driver(), inputs);
        let finish = guard.finish();
        match (run, finish) {
            (Ok(witness), Ok(())) => Ok(witness),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Err(run_error), Err(finish_error)) => Err(eyre::eyre!(
                "{run_error:#}; driver finalization also failed: {finish_error:#}"
            )),
        }
    }

    fn run_inner<F: PrimeField, D: VmDriver<F>>(
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
                        pending_mul_dst.as_slice() == &program.round_operands[start..start + len],
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
                        shared[program.round_results[rstart + k] as usize] = r;
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

        // Codegen has already projected circom's flat signal address space into witness order.
        // Build exactly the final witness: no `num_signals`-sized zero-fill and no second clone
        // pass over that temporary array.
        let mut witness = Vec::with_capacity(program.witness_sources.len());
        for source in &program.witness_sources {
            witness.push(match *source {
                WitnessSource::One => driver.promote(F::one()),
                WitnessSource::Zero => driver.promote(F::zero()),
                WitnessSource::Input(input_index) => match &inputs[input_index as usize] {
                    InputValue::Public(value) => driver.promote(*value),
                    InputValue::Secret(value) => value.clone(),
                },
                WitnessSource::Slot {
                    bank: Bank::Public,
                    slot,
                } => driver.promote(public[slot as usize]),
                WitnessSource::Slot {
                    bank: Bank::Shared,
                    slot,
                } => shared[slot as usize].clone(),
                WitnessSource::Slot {
                    bank: Bank::Local,
                    ..
                } => unreachable!("codegen never emits a Local witness source"),
            });
        }
        Ok(witness)
    }

    /// Services one batched precomputation site group at its point in the instruction stream. A
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
    fn run_batch<F: PrimeField, D: VmDriver<F>>(
        batch: &PrecomputeBatch,
        driver: &mut D,
        public: &mut [F],
        shared: &mut [D::Share],
    ) -> eyre::Result<()> {
        if batch.kind == BatchKind::IsZeroReveal {
            return Self::run_is_zero_reveal_batch(batch, driver, public, shared);
        }
        let BatchKind::Precompute(kind) = batch.kind else {
            unreachable!("fused batch handled above")
        };
        // Whether this batch needs a genuine MPC call, rather than inferring it from result targets:
        // for every kind but `Reveal` the two coincide (a site's inputs are all-`Public` exactly
        // when its result stays `Public`), but `Reveal`'s result target is unconditionally `Public`
        // even when its own inputs are `Shared` - that is its entire purpose (see
        // `PrecomputeKind::Reveal`), and precisely that case still needs a real `driver.open` call.
        let needs_mpc = batch
            .input_slots
            .iter()
            .any(|input| input.bank == Bank::Shared);

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
            if let PrecomputeKind::Poseidon2 { t } = kind {
                let selected = super::gadgets::poseidon2::plain_trace_requested(
                    t,
                    &inputs,
                    &batch.result_requests,
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
                Bank::Public => driver.promote(public[input.slot as usize]),
                Bank::Shared => shared[input.slot as usize].clone(),
                Bank::Local => unreachable!(
                    "Graph::verify and codegen both reject an un-reshared MulLocal feeding a site"
                ),
            })
            .collect();

        // `Reveal` is the one kind whose MPC path writes into the `Public` bank (a genuine open,
        // rather than a share-producing gadget) - every other kind writes into `Shared`.
        if let PrecomputeKind::Reveal { .. } = kind {
            let opened = driver.open(&inputs)?;
            let selected = Self::select_requests(&opened, batch)?;
            return Self::store_batch_results(batch, selected, Bank::Public, public);
        }
        if let PrecomputeKind::Poseidon2 { t } = kind {
            let selected = driver.poseidon2_requested_traces(
                t,
                &inputs,
                &batch.result_requests,
                &batch.result_offsets,
            )?;
            return Self::store_batch_results(batch, selected, Bank::Shared, shared);
        }
        let results = match kind {
            PrecomputeKind::Poseidon2 { .. } => unreachable!("handled above"),
            PrecomputeKind::Num2Bits { n } => driver.num2bits_traces(n, &inputs)?,
            PrecomputeKind::IsZero => driver.is_zero_traces(&inputs)?,
            PrecomputeKind::AliasCheck => driver.alias_check_traces(&inputs)?,
            PrecomputeKind::Reveal { .. } => unreachable!("handled above"),
        };
        let selected = Self::select_requests(&results, batch)?;
        Self::store_batch_results(batch, selected, Bank::Shared, shared)
    }

    fn run_is_zero_reveal_batch<F: PrimeField, D: VmDriver<F>>(
        batch: &PrecomputeBatch,
        driver: &mut D,
        public: &mut [F],
        shared: &mut [D::Share],
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
                Ok(shared[input.slot as usize].clone())
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
            eyre::ensure!(lo <= hi && hi <= batch.result_requests.len(), "invalid fused CSR row");
            for (&logical, target) in batch.result_requests[lo..hi]
                .iter()
                .zip(&batch.result_targets[lo..hi])
            {
                match logical {
                    0 => {
                        eyre::ensure!(target.bank == Bank::Shared, "IsZero.out must target Shared");
                        shared[target.slot as usize] = is_zero.clone();
                    }
                    1 => {
                        eyre::ensure!(target.bank == Bank::Shared, "IsZero.inv must target Shared");
                        shared[target.slot as usize] = inverse.clone();
                    }
                    2 => {
                        eyre::ensure!(target.bank == Bank::Public, "Reveal.out must target Public");
                        public[target.slot as usize] = revealed;
                    }
                    other => eyre::bail!("fused IsZero/Reveal requested invalid logical slot {other}"),
                }
            }
        }
        Ok(())
    }

    fn run_plain_batch<F: PrimeField>(kind: PrecomputeKind, inputs: &[F]) -> eyre::Result<Vec<F>> {
        use super::gadgets::{aliascheck, iszero, num2bits};

        Ok(match kind {
            PrecomputeKind::Poseidon2 { .. } => {
                unreachable!("public Poseidon2 takes the requested-trace path in run_batch")
            }
            PrecomputeKind::Num2Bits { n } => inputs
                .iter()
                .flat_map(|&x| num2bits::plain_trace(x, n))
                .collect(),
            PrecomputeKind::IsZero => inputs
                .iter()
                .flat_map(|&x| iszero::plain_trace(x))
                .collect(),
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
    /// output, flattening site-major. A temporary bridge (,
    /// "Precomputation"): gadgets other than Poseidon2 still compute and return their *full*
    /// per-site trace (`num_outputs + num_intermediates` values), and this filters the
    /// `PrecomputeBatch::result_requests` subset before storing. Poseidon2 consumes this CSR table
    /// directly and bypasses this bridge.
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

    fn store_batch_results<T>(
        batch: &PrecomputeBatch,
        results: Vec<T>,
        expected_bank: Bank,
        destination: &mut [T],
    ) -> eyre::Result<()> {
        eyre::ensure!(
            results.len() == batch.result_targets.len(),
            "precompute batch ({:?}) produced {} results, expected exactly {} (one per requested \
             slot)",
            batch.kind,
            results.len(),
            batch.result_targets.len()
        );
        for (target, value) in batch.result_targets.iter().zip(results) {
            eyre::ensure!(
                target.bank == expected_bank,
                "precompute batch ({:?}) result targets mixed banks unexpectedly",
                batch.kind
            );
            destination[target.slot as usize] = value;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;

    use super::*;
    use crate::vm::program::SlotCounts;

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

    impl VmDriver<Fr> for PanicDriver {
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

        fn num2bits_traces(
            &mut self,
            _n: usize,
            _inputs: &[Fr],
        ) -> eyre::Result<Vec<Fr>> {
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
        let program = Program {
            instructions: Vec::new(),
            constants: Vec::new(),
            input_domains: Vec::new(),
            inputs: Vec::new(),
            rounds: Vec::new(),
            round_operands: Vec::new(),
            round_results: Vec::new(),
            precompute_batches: Vec::new(),
            witness_sources: vec![WitnessSource::One],
            num_inputs: 0,
            slots: SlotCounts::default(),
        };
        let mut driver = PanicDriver::new();

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = Machine::run(&program, &mut driver, &[]);
        }));
        assert!(panic.is_err());
        assert_eq!(driver.lifecycle, MockLifecycle::Spent);
        assert_eq!(driver.finish_calls, 1);

        let reuse = Machine::run(&program, &mut driver, &[]).unwrap_err();
        assert!(reuse.to_string().contains("spent"));
        assert_eq!(driver.finish_calls, 1, "failed begin must not call finish");
    }
}
