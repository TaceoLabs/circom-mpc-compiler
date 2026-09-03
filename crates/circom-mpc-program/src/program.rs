//! The compiled bytecode program: a slot machine over three domain-typed banks (`Public`/
//! `Shared`/`Local` - the same lattice `passes::mpc::domain` classifies values into), plus the
//! side tables that carry everything that is program *structure* rather than a per-value
//! operation - constants, inputs, batched MPC rounds, gadget sites, and the final signal
//! witness sources.

use ark_bn254::Fr;

use crate::{BatchIdx, GadgetKind, InputIdx, ResultSlot, RoundIdx, Slot};

/// Poseidon2 widths every gadget and the VM's batch-shape validation support (`t` in the
/// permutation's state size).
pub const POSEIDON2_SUPPORTED_WIDTHS: [usize; 5] = [2, 3, 4, 8, 16];

/// Which physical slot bank a value lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bank {
    /// Every party holds the cleartext value directly as [`Fr`].
    Public,
    /// A valid share any op may consume - [`Fr`] in `circom_mpc_vm::driver::plain::PlainDriver`,
    /// `Rep3PrimeFieldShare<Fr>` in the rep3 driver.
    Shared,
    /// A post-`MulLocal`, pre-reshare additive-3 sharing. Only ever an operand of [`Opcode::Reshare`]
    /// - codegen rejects any graph where a `Local` value reaches anything else.
    Local,
}

/// One operation. Arithmetic opcodes are named `<Op><BankOfA><BankOfB>` (`P` public, `S` shared);
/// `MulLocal`/`Reshare` are the MPC-lowering ops.
/// There is no constant-load or round-result opcode: constants are preloaded at init
/// (`Program::constants`), and a round's results are written straight into their slots by
/// `Reshare` - see `Program::rounds`. `Add`/`Mul` are commutative, so codegen reorders operands to
/// match the single `..SP` opcode instead of also encoding a `..PS` variant; `Sub` is not, hence
/// both `SubSP` and `SubPS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    /// `dst = a + b`, all `Public`.
    AddPP,
    /// `dst = a - b`, all `Public`.
    SubPP,
    /// `dst = a * b`, all `Public`.
    MulPP,
    /// `dst = a + b`, all `Shared`.
    AddSS,
    /// `dst = a - b`, all `Shared`.
    SubSS,
    /// `dst = a + b`, `a`/`dst` `Shared`, `b` `Public`.
    AddSP,
    /// `dst = a - b`, `a`/`dst` `Shared`, `b` `Public`.
    SubSP,
    /// `dst = a - b`, `a` `Public`, `b`/`dst` `Shared`.
    SubPS,
    /// `dst = a * b`, `a`/`dst` `Shared`, `b` `Public`.
    MulSP,
    /// The free local half of a secret x secret product: `a`/`b` are `Shared`-bank slots, `dst`
    /// is a `Local`-bank slot.
    MulLocal,
    /// One batched network round: `a` is an index into [`Program::rounds`]; `dst`/`b` are unused
    /// - a round's operands and results are its own slot lists, not encoded per-instruction.
    Reshare,
    /// One batched gadget service: `a` is an index into [`Program::gadget_batches`];
    /// `dst`/`b` are unused - a batch's operands and results are its own slot lists, exactly as for
    /// [`Opcode::Reshare`].
    ///
    /// Being a real instruction rather than an out-of-band phase is what lets a site's inputs depend
    /// on earlier instructions - needed by circuits whose Poseidon2 sites chain through secret
    /// multiplications.
    Gadget,
}

/// One instruction. Every arithmetic opcode reads/writes bank-relative [`Slot`]s directly;
/// `Reshare`/`Gadget` instead carry a table index into [`Program::rounds`]/[`Program::gadget_batches`],
/// since a round's or batch's own operands and results are its own side-table lists, not encoded
/// per instruction. Splitting these into distinct variants (rather than a single `(op, dst, a, b)`
/// record where `a` means slot-or-round-id-or-batch-id depending on `op`) makes that distinction a
/// type rather than a convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Instruction {
    /// An arithmetic opcode. `dst`/`a`/`b` are slot indices *within whichever bank the opcode's
    /// operands live in* - fully determined by `op`, so the instruction itself carries no bank
    /// tag.
    Arith {
        /// The operation to execute.
        op: Opcode,
        /// Destination slot.
        dst: Slot,
        /// First operand slot.
        a: Slot,
        /// Second operand slot.
        b: Slot,
    },
    /// One batched network round: an index into [`Program::rounds`].
    Reshare(RoundIdx),
    /// One batched gadget service: an index into [`Program::gadget_batches`]. Being a real
    /// instruction rather than an out-of-band phase is what lets a site's inputs depend on
    /// earlier instructions - needed by circuits whose Poseidon2 sites chain through secret
    /// multiplications.
    Gadget(BatchIdx),
}

impl Instruction {
    /// The opcode this instruction executes - `Opcode::Reshare`/`Opcode::Gadget` for the
    /// table-index variants.
    #[must_use]
    pub fn op(&self) -> Opcode {
        match self {
            Instruction::Arith { op, .. } => *op,
            Instruction::Reshare(_) => Opcode::Reshare,
            Instruction::Gadget(_) => Opcode::Gadget,
        }
    }
}

/// One batched MPC round: `operand_start/len` index into `Program::round_operands` (`Local`-bank
/// slots to reshare together, one message) and `result_start/len` index into
/// `Program::round_results` (the `Shared`-bank slot each result lands in).
#[derive(Debug, Clone, Copy)]
pub struct RoundEntry {
    /// Start index into [`Program::round_operands`].
    pub operand_start: u32,
    /// Number of operands/results in this round.
    pub len: u32,
    /// Start index into [`Program::round_results`].
    pub result_start: u32,
}

/// One input value of one gadget site. Carries its bank because a site input is *not*
/// always a share: a circuit may pass a literal, as in
/// `Poseidon2(4)([value, 0, r, domainSeparator()])` - two of those four fold to
/// `Op::Constant`, i.e. `Bank::Public`. `Machine::run` promotes a `Public` slot into a share before
/// handing the batch to the driver. `Bank::Local` never appears - codegen rejects an un-reshared
/// `MulLocal` reaching a site.
///
/// Shaped like [`WitnessSource::Slot`], the other place a `(bank, slot)` pair crosses into a side
/// table rather than an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiteInput {
    /// Which bank `slot` lives in.
    pub bank: Bank,
    /// Slot index within `bank`.
    pub slot: Slot,
}

/// The service executed by a [`GadgetBatch`]. Most batches are a direct runtime realization
/// of one circuit [`GadgetKind`]. `IsZeroReveal` is deliberately VM-only: codegen may fuse the
/// conservative circuit shape `shared IsZero.out -> Reveal(1)` without changing the graph, R1CS,
/// witness layout, or proving artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchKind {
    /// A direct runtime realization of one circuit [`GadgetKind`].
    Gadget(GadgetKind),
    /// Computes a zero test's `[out, inv]` shares and the explicitly revealed `out` together.
    IsZeroReveal,
    /// A `TACEO_PRECOMPUTATION_Poseidon2` site: the host supplies this batch's trace instead of
    /// `circom_mpc_vm::gadgets` servicing it. Poseidon2 is the only gadget that can be
    /// host-precomputed, and its result bank is always `Shared` - see
    /// `Machine::run_with_precomputation`.
    PrecomputedPoseidon2 {
        /// The Poseidon2 state width.
        t: crate::Poseidon2Width,
    },
}

/// One requested batch result's physical destination. Per-result (not per-batch) because a fused
/// service writes both shared witness values and a public revealed value from one site-major CSR
/// request table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResultTarget {
    /// Which bank `slot` lives in.
    pub bank: Bank,
    /// Slot index within `bank`.
    pub slot: Slot,
}

/// Compatible gadget sites of one [`GadgetKind`], domain, and stage, batched
/// into a single service. Codegen first keys sites by `(kind, stage, domain)`, then splits a group
/// when an early consumer closes its anchor/deadline placement window.
///
/// Independent compatible sites normally collapse into one entry. A site may remain alone when its
/// kind, stage, or domain differs, or when combining it would cross an earlier result deadline.
#[derive(Debug, Clone)]
pub struct GadgetBatch {
    /// The service this batch runs.
    pub kind: BatchKind,
    /// Number of sites batched together.
    pub sites: usize,
    /// `sites * (this kind's per-site input count)` entries, one site's inputs contiguous, in site
    /// order.
    pub input_slots: Vec<SiteInput>,
    /// Which of each site's logical result slots (`0..num_outputs + num_intermediates`) are
    /// actually witness-live - `passes::dead_signals` prunes the rest before codegen ever sees this
    /// batch. Site-contiguous, ascending within a site; a range `result_offsets[site]` to
    /// `result_offsets[site + 1]` is that site's own sorted sublist. Two sites in one batch can
    /// have different live counts, which is why this isn't a flat `sites * capacity` shape
    /// recoverable by division.
    pub result_requests: Vec<ResultSlot>,
    /// `len == sites + 1`: CSR row pointers into
    /// [`Self::result_requests`]/[`Self::result_targets`].
    pub result_offsets: Vec<u32>,
    /// Parallel to [`Self::result_requests`]: the banked destination for each requested value.
    /// `Bank::Local` is never valid here.
    pub result_targets: Vec<ResultTarget>,
}

impl GadgetBatch {
    /// This site's row into [`Self::result_requests`]/[`Self::result_targets`] - the CSR range
    /// `result_offsets[site]..result_offsets[site + 1]`.
    #[must_use]
    pub fn site_results(&self, site: usize) -> std::ops::Range<usize> {
        self.result_offsets[site] as usize..self.result_offsets[site + 1] as usize
    }
}

/// One declared circuit input signal and the flat input range it occupies - lets a caller resolve
/// a name (e.g. from a circom-style `input.json`) into the positional range `Program::inputs`
/// addresses, without needing the compiler's `ir::Graph` around at run time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputSignal {
    /// The signal's declared name.
    pub name: String,
    /// First flat input index this signal occupies, 0-based over the circuit's inputs alone.
    pub offset: usize,
    /// Number of field elements this signal occupies (1 for a scalar, the product of the
    /// dimensions for an array).
    pub size: usize,
}

/// Binds one circuit input to the slot it's read from - `Machine::run` fills these in from the
/// caller-supplied input values before running anything else.
#[derive(Debug, Clone, Copy)]
pub struct InputBinding {
    /// Which bank `slot` lives in.
    pub bank: Bank,
    /// Slot index within `bank`.
    pub slot: Slot,
    /// The circuit's own flat input index (`0..num_inputs`) - not a per-bank ordinal, so a caller
    /// doesn't need to know how many of the circuit's inputs are public vs secret ahead of time.
    pub input_index: InputIdx,
}

/// Where one final witness entry comes from once the instruction stream has run. Codegen records
/// these directly in witness order, so `Machine::run` never needs to materialize circom's much
/// larger flat signal array merely to project a small subset out of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessSource {
    /// Circom witness position zero, the reserved constant `1`.
    One,
    /// A witness slot with no surviving producer. The old signal array was zero-initialized, so
    /// unconstrained/dead circom signals project to zero rather than making compilation fail.
    Zero,
    /// One of main's original circuit inputs. Inputs remain available to `Machine::run` even when
    /// their `Op::Input` was dead and removed from the executable graph.
    Input(InputIdx),
    /// A value retained in one of the VM's final slot banks.
    Slot {
        /// Which bank `slot` lives in.
        bank: Bank,
        /// Slot index within `bank`.
        slot: Slot,
    },
}

/// How many slots each bank needs, sized by codegen's liveness-driven allocator - this is what
/// makes VM memory track live width instead of total node count.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SlotCounts {
    /// Number of `Public`-bank slots.
    pub public: u32,
    /// Number of `Shared`-bank slots.
    pub shared: u32,
    /// Number of `Local`-bank slots.
    pub local: u32,
}

/// A compiled circuit: the instruction stream plus every side table `Machine::run` needs to
/// execute it against a `circom_mpc_vm::driver::VmDriver`. Produced by the compiler crate's
/// `codegen::compile`, serializable via [`Program::write`]/[`Program::read`].
#[derive(Debug, Clone)]
pub struct Program {
    pub(crate) instructions: Vec<Instruction>,
    /// Preloaded into `Public`-bank slots `0..constants.len()` at init - no const opcode.
    pub(crate) constants: Vec<Fr>,
    /// One entry per circuit input (`len == num_inputs`), in flat signal order - `Bank::Local`
    /// never appears. An input whose `Op::Input` node didn't survive `gc` (dead, never read) has
    /// no corresponding entry here; its domain still appears in this table so a caller can tell
    /// which representation to prepare without needing it to be live.
    pub(crate) input_domains: Vec<Bank>,
    pub(crate) inputs: Vec<InputBinding>,
    /// The circuit's declared input signals by name, in declaration order - lets a caller resolve
    /// a name-keyed input map without the compiler's `ir::Graph`. Empty for a program with no
    /// named inputs (e.g. a test fixture built directly from `ProgramParts`).
    pub(crate) input_signals: Vec<InputSignal>,
    pub(crate) rounds: Vec<RoundEntry>,
    pub(crate) round_operands: Vec<Slot>,
    pub(crate) round_results: Vec<Slot>,
    /// Indexed by [`Opcode::Gadget`]'s `a`. These are **not** run up front: each is serviced at
    /// its own point in the instruction stream, because a site's inputs may depend on earlier
    /// instructions.
    pub(crate) gadget_batches: Vec<GadgetBatch>,
    /// One source per final witness entry, already in circom witness order.
    pub(crate) witness_sources: Vec<WitnessSource>,
    pub(crate) num_inputs: usize,
    pub(crate) slots: SlotCounts,
}

/// [`Program`]'s fields, laid bare for construction (by the compiler crate's `codegen::compile`)
/// and for tests that need to build or mutate a program without going through codegen.
#[derive(Debug, Clone)]
pub struct ProgramParts {
    /// See [`Program::instructions`].
    pub instructions: Vec<Instruction>,
    /// See [`Program::constants`].
    pub constants: Vec<Fr>,
    /// See [`Program::input_domains`].
    pub input_domains: Vec<Bank>,
    /// See [`Program::inputs`].
    pub inputs: Vec<InputBinding>,
    /// See [`Program::input_signals`].
    pub input_signals: Vec<InputSignal>,
    /// See [`Program::rounds`].
    pub rounds: Vec<RoundEntry>,
    /// See [`Program::round_operands`].
    pub round_operands: Vec<Slot>,
    /// See [`Program::round_results`].
    pub round_results: Vec<Slot>,
    /// See [`Program::gadget_batches`].
    pub gadget_batches: Vec<GadgetBatch>,
    /// See [`Program::witness_sources`].
    pub witness_sources: Vec<WitnessSource>,
    /// See [`Program::num_inputs`].
    pub num_inputs: usize,
    /// See [`Program::slots`].
    pub slots: SlotCounts,
}

/// One `BatchKind::PrecomputedPoseidon2` batch's shape, as reported by [`Program::precomputed_batches`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrecomputedBatch {
    /// Always `GadgetKind::Poseidon2`.
    pub kind: GadgetKind,
    /// Number of sites in this batch.
    pub sites: usize,
}

/// Summary counters over a [`Program`], as reported by [`Program::statistics`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramStatistics {
    /// Number of instructions.
    pub instructions: usize,
    /// Number of circuit inputs.
    pub inputs: usize,
    /// Number of final witness entries.
    pub witness_values: usize,
    /// Number of `Public`-bank slots.
    pub public_slots: u32,
    /// Number of `Shared`-bank slots.
    pub shared_slots: u32,
    /// Number of `Local`-bank slots.
    pub local_slots: u32,
    /// Number of batched MPC rounds.
    pub multiplication_rounds: usize,
    /// Total operands reshared across all rounds - also the number of secret x secret
    /// multiplications, since each lowers to exactly one round slot.
    pub multiplication_elements: usize,
    /// Fewest operands in any single round, or `None` if there are no rounds.
    pub min_slots_per_round: Option<usize>,
    /// Most operands in any single round, or `None` if there are no rounds.
    pub max_slots_per_round: Option<usize>,
    /// Number of multiplications with at least one public operand, free of any network round.
    pub public_multiplications: usize,
    /// Number of gadget batches.
    pub gadget_batches: usize,
    /// Total gadget sites across all batches.
    pub gadget_sites: usize,
    /// Number of gadget batches with at least one `Shared` input.
    pub shared_gadget_batches: usize,
    /// Number of `BatchKind::IsZeroReveal` batches.
    pub fused_is_zero_reveal_batches: usize,
    /// Number of gadget results targeting the `Public` bank.
    pub public_gadget_results: usize,
    /// Batches whose trace the host supplies at run time (`BatchKind::PrecomputedPoseidon2`) rather than
    /// `vm::gadgets`.
    pub precomputed_batches: usize,
}

impl Program {
    /// Builds a `Program` from its raw parts - the constructor `codegen::compile` uses, and the
    /// escape hatch tests use to build or mutate a program without going through it.
    #[must_use]
    pub fn new(parts: ProgramParts) -> Self {
        Self {
            instructions: parts.instructions,
            constants: parts.constants,
            input_domains: parts.input_domains,
            inputs: parts.inputs,
            input_signals: parts.input_signals,
            rounds: parts.rounds,
            round_operands: parts.round_operands,
            round_results: parts.round_results,
            gadget_batches: parts.gadget_batches,
            witness_sources: parts.witness_sources,
            num_inputs: parts.num_inputs,
            slots: parts.slots,
        }
    }

    /// The inverse of [`Program::new`] - unwraps a program back into its mutable parts, e.g. to
    /// build a deliberately malformed program for a `validate_encoding` negative test.
    #[must_use]
    pub fn into_parts(self) -> ProgramParts {
        ProgramParts {
            instructions: self.instructions,
            constants: self.constants,
            input_domains: self.input_domains,
            inputs: self.inputs,
            input_signals: self.input_signals,
            rounds: self.rounds,
            round_operands: self.round_operands,
            round_results: self.round_results,
            gadget_batches: self.gadget_batches,
            witness_sources: self.witness_sources,
            num_inputs: self.num_inputs,
            slots: self.slots,
        }
    }

    /// The instruction stream.
    #[must_use]
    pub fn instructions(&self) -> &[Instruction] {
        &self.instructions
    }

    /// Constants preloaded into `Public`-bank slots at init.
    #[must_use]
    pub fn constants(&self) -> &[Fr] {
        &self.constants
    }

    /// Each circuit input's domain, in flat signal order.
    #[must_use]
    pub fn input_domains(&self) -> &[Bank] {
        &self.input_domains
    }

    /// Bindings from circuit inputs to the slots they're read from.
    #[must_use]
    pub fn inputs(&self) -> &[InputBinding] {
        &self.inputs
    }

    /// The circuit's declared input signals by name, in declaration order.
    #[must_use]
    pub fn input_signals(&self) -> &[InputSignal] {
        &self.input_signals
    }

    /// The batched MPC rounds.
    #[must_use]
    pub fn rounds(&self) -> &[RoundEntry] {
        &self.rounds
    }

    /// Flat operand table indexed into by [`RoundEntry`] ranges.
    #[must_use]
    pub fn round_operands(&self) -> &[Slot] {
        &self.round_operands
    }

    /// Flat result table indexed into by [`RoundEntry`] ranges.
    #[must_use]
    pub fn round_results(&self) -> &[Slot] {
        &self.round_results
    }

    /// The gadget batches, indexed by an [`Instruction::Gadget`]'s [`BatchIdx`].
    #[must_use]
    pub fn gadget_batches(&self) -> &[GadgetBatch] {
        &self.gadget_batches
    }

    /// One source per final witness entry, in circom witness order.
    #[must_use]
    pub fn witness_sources(&self) -> &[WitnessSource] {
        &self.witness_sources
    }

    /// The circuit's total input count.
    #[must_use]
    pub fn num_inputs(&self) -> usize {
        self.num_inputs
    }

    /// The slot counts each bank was sized to.
    #[must_use]
    pub fn slots(&self) -> SlotCounts {
        self.slots
    }

    /// Summary counters over this program.
    #[must_use]
    pub fn statistics(&self) -> ProgramStatistics {
        ProgramStatistics {
            instructions: self.instructions.len(),
            inputs: self.num_inputs,
            witness_values: self.witness_sources.len(),
            public_slots: self.slots.public,
            shared_slots: self.slots.shared,
            local_slots: self.slots.local,
            multiplication_rounds: self.rounds.len(),
            multiplication_elements: self.rounds.iter().map(|round| round.len as usize).sum(),
            min_slots_per_round: self.rounds.iter().map(|round| round.len as usize).min(),
            max_slots_per_round: self.rounds.iter().map(|round| round.len as usize).max(),
            public_multiplications: self
                .instructions
                .iter()
                .filter(|instr| {
                    matches!(
                        instr,
                        Instruction::Arith {
                            op: Opcode::MulPP | Opcode::MulSP,
                            ..
                        }
                    )
                })
                .count(),
            gadget_batches: self.gadget_batches.len(),
            gadget_sites: self
                .gadget_batches
                .iter()
                .map(|batch| batch.sites)
                .sum(),
            shared_gadget_batches: self
                .gadget_batches
                .iter()
                .filter(|batch| {
                    batch
                        .input_slots
                        .iter()
                        .any(|input| input.bank == Bank::Shared)
                })
                .count(),
            fused_is_zero_reveal_batches: self
                .gadget_batches
                .iter()
                .filter(|batch| batch.kind == BatchKind::IsZeroReveal)
                .count(),
            public_gadget_results: self
                .gadget_batches
                .iter()
                .flat_map(|batch| &batch.result_targets)
                .filter(|target| target.bank == Bank::Public)
                .count(),
            precomputed_batches: self
                .gadget_batches
                .iter()
                .filter(|batch| matches!(batch.kind, BatchKind::PrecomputedPoseidon2 { .. }))
                .count(),
        }
    }
    /// One `BatchKind::PrecomputedPoseidon2` batch's shape, in the order `Machine::run_with_precomputation`
    /// consumes it (`Program::precomputed_batches`).
    ///
    /// # Errors
    ///
    /// Returns an error if an instruction references a gadget batch index that doesn't exist.
    pub fn precomputed_batches(&self) -> eyre::Result<Vec<PrecomputedBatch>> {
        let mut batches = Vec::new();
        for (instruction_index, instruction) in self.instructions.iter().enumerate() {
            let Instruction::Gadget(batch_idx) = instruction else {
                continue;
            };
            let batch = self
                .gadget_batches
                .get(batch_idx.index())
                .ok_or_else(|| {
                    eyre::eyre!(
                        "instruction {instruction_index} references missing gadget batch {batch_idx}"
                    )
                })?;
            if let BatchKind::PrecomputedPoseidon2 { t } = batch.kind {
                batches.push(PrecomputedBatch {
                    kind: GadgetKind::Poseidon2 { t },
                    sites: batch.sites,
                });
            }
        }
        Ok(batches)
    }

    /// Checks every side-table and slot reference before execution. This is intentionally usable
    /// both after deserialization and by any caller that built a `Program` via [`Program::new`]
    /// without going through codegen.
    ///
    /// # Errors
    ///
    /// Returns an error describing the first inconsistency found - an out-of-range slot, a
    /// malformed side table, or a reference to a missing round/gadget batch.
    #[allow(
        clippy::too_many_lines,
        reason = "a single sequential validation pass over every side table; splitting it would not improve clarity"
    )]
    pub fn validate_encoding(&self) -> eyre::Result<()> {
        let check_slot = |bank: Bank, slot: Slot, what: &str| -> eyre::Result<()> {
            let limit = match bank {
                Bank::Public => self.slots.public,
                Bank::Shared => self.slots.shared,
                Bank::Local => self.slots.local,
            };
            eyre::ensure!(
                slot.get() < limit,
                "{what} references {bank:?} slot {slot}, but bank size is {limit}"
            );
            Ok(())
        };

        eyre::ensure!(
            self.constants.len() <= self.slots.public as usize,
            "{} constants do not fit in {} public slots",
            self.constants.len(),
            self.slots.public
        );
        eyre::ensure!(
            self.input_domains.len() == self.num_inputs,
            "input domain table has {} entries, expected {}",
            self.input_domains.len(),
            self.num_inputs
        );
        for (input, &bank) in self.input_domains.iter().enumerate() {
            eyre::ensure!(
                bank != Bank::Local,
                "input {input} has invalid Local domain"
            );
        }
        for binding in &self.inputs {
            let input = binding.input_index.index();
            eyre::ensure!(
                input < self.num_inputs,
                "input binding index {input} is out of range"
            );
            eyre::ensure!(
                binding.bank == self.input_domains[input],
                "input {input} binding bank {:?} disagrees with domain {:?}",
                binding.bank,
                self.input_domains[input]
            );
            check_slot(binding.bank, binding.slot, "input binding")?;
        }

        let signal_total: usize = self.input_signals.iter().map(|s| s.size).sum();
        eyre::ensure!(
            signal_total == self.num_inputs,
            "input signal sizes sum to {signal_total}, expected {}",
            self.num_inputs
        );
        let mut seen_signal_names = std::collections::HashSet::with_capacity(self.input_signals.len());
        for signal in &self.input_signals {
            eyre::ensure!(
                signal.offset + signal.size <= self.num_inputs,
                "input signal `{}` occupies {}..{}, out of range for {} inputs",
                signal.name,
                signal.offset,
                signal.offset + signal.size,
                self.num_inputs
            );
            eyre::ensure!(
                seen_signal_names.insert(signal.name.as_str()),
                "input signal name `{}` is declared more than once",
                signal.name
            );
        }

        for (index, instruction) in self.instructions.iter().enumerate() {
            match *instruction {
                Instruction::Arith {
                    op: Opcode::AddPP | Opcode::SubPP | Opcode::MulPP,
                    dst,
                    a,
                    b,
                } => {
                    check_slot(Bank::Public, dst, "instruction")?;
                    check_slot(Bank::Public, a, "instruction")?;
                    check_slot(Bank::Public, b, "instruction")?;
                }
                Instruction::Arith {
                    op: Opcode::AddSS | Opcode::SubSS,
                    dst,
                    a,
                    b,
                } => {
                    check_slot(Bank::Shared, dst, "instruction")?;
                    check_slot(Bank::Shared, a, "instruction")?;
                    check_slot(Bank::Shared, b, "instruction")?;
                }
                Instruction::Arith {
                    op: Opcode::AddSP | Opcode::SubSP | Opcode::MulSP,
                    dst,
                    a,
                    b,
                } => {
                    check_slot(Bank::Shared, dst, "instruction")?;
                    check_slot(Bank::Shared, a, "instruction")?;
                    check_slot(Bank::Public, b, "instruction")?;
                }
                Instruction::Arith {
                    op: Opcode::SubPS,
                    dst,
                    a,
                    b,
                } => {
                    check_slot(Bank::Shared, dst, "instruction")?;
                    check_slot(Bank::Public, a, "instruction")?;
                    check_slot(Bank::Shared, b, "instruction")?;
                }
                Instruction::Arith {
                    op: Opcode::MulLocal,
                    dst,
                    a,
                    b,
                } => {
                    check_slot(Bank::Local, dst, "instruction")?;
                    check_slot(Bank::Shared, a, "instruction")?;
                    check_slot(Bank::Shared, b, "instruction")?;
                }
                Instruction::Arith {
                    op: Opcode::Reshare | Opcode::Gadget,
                    ..
                } => eyre::bail!(
                    "instruction {index} carries Reshare/Gadget opcode in an Arith variant"
                ),
                Instruction::Reshare(round_idx) => eyre::ensure!(
                    round_idx.index() < self.rounds.len(),
                    "instruction {index} references missing round {round_idx}"
                ),
                Instruction::Gadget(batch_idx) => eyre::ensure!(
                    batch_idx.index() < self.gadget_batches.len(),
                    "instruction {index} references missing gadget batch {batch_idx}"
                ),
            }
        }

        for (index, round) in self.rounds.iter().enumerate() {
            eyre::ensure!(round.len > 0, "round {index} has no operands");
            let operand_start = round.operand_start as usize;
            let result_start = round.result_start as usize;
            let len = round.len as usize;
            let operand_end = operand_start
                .checked_add(len)
                .ok_or_else(|| eyre::eyre!("round {index} operand range overflows"))?;
            let result_end = result_start
                .checked_add(len)
                .ok_or_else(|| eyre::eyre!("round {index} result range overflows"))?;
            eyre::ensure!(
                operand_end <= self.round_operands.len(),
                "round {index} operand range is out of bounds"
            );
            eyre::ensure!(
                result_end <= self.round_results.len(),
                "round {index} result range is out of bounds"
            );
            for &slot in &self.round_operands[operand_start..operand_end] {
                check_slot(Bank::Local, slot, "round operand")?;
            }
            for &slot in &self.round_results[result_start..result_end] {
                check_slot(Bank::Shared, slot, "round result")?;
            }
        }

        for (index, batch) in self.gadget_batches.iter().enumerate() {
            eyre::ensure!(batch.sites > 0, "gadget batch {index} has no sites");
            let inputs_per_site = match batch.kind {
                // `t` is a `Poseidon2Width`, checked against `POSEIDON2_SUPPORTED_WIDTHS` at
                // construction - no need to re-check it here.
                BatchKind::Gadget(GadgetKind::Poseidon2 { t })
                | BatchKind::PrecomputedPoseidon2 { t } => t.get(),
                BatchKind::Gadget(GadgetKind::Num2Bits { .. } | GadgetKind::IsZero)
                | BatchKind::IsZeroReveal => 1,
                BatchKind::Gadget(GadgetKind::AliasCheck) => 254,
                BatchKind::Gadget(GadgetKind::Reveal { n }) => n,
            };
            let expected_inputs = batch
                .sites
                .checked_mul(inputs_per_site)
                .ok_or_else(|| eyre::eyre!("gadget batch {index} input count overflows"))?;
            eyre::ensure!(
                batch.input_slots.len() == expected_inputs,
                "gadget batch {index} has {} inputs, expected {expected_inputs}",
                batch.input_slots.len()
            );
            for input in &batch.input_slots {
                eyre::ensure!(
                    input.bank != Bank::Local,
                    "gadget batch {index} has a Local input"
                );
                check_slot(input.bank, input.slot, "gadget input")?;
            }
            if batch.kind == BatchKind::IsZeroReveal {
                eyre::ensure!(
                    batch
                        .input_slots
                        .iter()
                        .all(|input| input.bank == Bank::Shared),
                    "fused IsZeroReveal batch {index} must have only Shared inputs"
                );
            }
            if matches!(batch.kind, BatchKind::PrecomputedPoseidon2 { .. }) {
                // Mirrors `codegen::gadget_result_bank`'s `Domain::Shared` requirement: a
                // host-precomputed site may mix Public and Shared inputs (e.g. a public domain
                // separator alongside real shares), but at least one input must be Shared -
                // otherwise there is nothing for the host to precompute.
                eyre::ensure!(
                    batch
                        .input_slots
                        .iter()
                        .any(|input| input.bank == Bank::Shared),
                    "precomputed batch {index} must have at least one Shared input"
                );
            }

            let expected_offsets = batch
                .sites
                .checked_add(1)
                .ok_or_else(|| eyre::eyre!("gadget batch {index} site count overflows"))?;
            eyre::ensure!(
                batch.result_offsets.len() == expected_offsets,
                "gadget batch {index} result offsets have wrong length"
            );
            let request_count = u32::try_from(batch.result_requests.len()).map_err(|_| {
                eyre::eyre!("gadget batch {index} has too many result requests")
            })?;
            eyre::ensure!(
                batch.result_offsets.first() == Some(&0)
                    && batch.result_offsets.last().copied() == Some(request_count)
                    && batch
                        .result_offsets
                        .windows(2)
                        .all(|window| window[0] <= window[1]),
                "gadget batch {index} has invalid CSR offsets"
            );
            eyre::ensure!(
                batch.result_requests.len() == batch.result_targets.len(),
                "gadget batch {index} request/target lengths differ"
            );
            let capacity = match batch.kind {
                BatchKind::Gadget(kind) => kind.expected_results(),
                BatchKind::PrecomputedPoseidon2 { t } => {
                    GadgetKind::Poseidon2 { t }.expected_results()
                }
                BatchKind::IsZeroReveal => 3,
            };
            let normal_result_bank = match batch.kind {
                BatchKind::Gadget(GadgetKind::Reveal { .. }) => Some(Bank::Public),
                BatchKind::Gadget(_) => Some(
                    if batch
                        .input_slots
                        .iter()
                        .any(|input| input.bank == Bank::Shared)
                    {
                        Bank::Shared
                    } else {
                        Bank::Public
                    },
                ),
                // A host-precomputed site is always `Shared`-domain by construction (see
                // `gadget_result_bank`); a batch built any other way is rejected above.
                BatchKind::PrecomputedPoseidon2 { .. } => Some(Bank::Shared),
                BatchKind::IsZeroReveal => None,
            };
            for site in 0..batch.sites {
                let lo = batch.result_offsets[site] as usize;
                let hi = batch.result_offsets[site + 1] as usize;
                eyre::ensure!(
                    hi <= batch.result_requests.len(),
                    "gadget batch {index} CSR row is out of bounds"
                );
                let requests = &batch.result_requests[lo..hi];
                eyre::ensure!(
                    requests.windows(2).all(|window| window[0] < window[1]),
                    "gadget batch {index} site {site} requests are not strictly ascending"
                );
                for (request, target) in requests.iter().zip(&batch.result_targets[lo..hi]) {
                    eyre::ensure!(
                        request.index() < capacity,
                        "gadget batch {index} request {request} exceeds capacity {capacity}"
                    );
                    eyre::ensure!(
                        target.bank != Bank::Local,
                        "gadget batch {index} targets Local bank"
                    );
                    let expected_bank = normal_result_bank.unwrap_or({
                        if request.get() == 2 {
                            Bank::Public
                        } else {
                            Bank::Shared
                        }
                    });
                    eyre::ensure!(
                        target.bank == expected_bank,
                        "gadget batch {index} result {request} targets {:?}, expected {expected_bank:?}",
                        target.bank
                    );
                    check_slot(target.bank, target.slot, "gadget result")?;
                }
            }
        }

        eyre::ensure!(
            !self.witness_sources.is_empty(),
            "program has an empty witness"
        );
        eyre::ensure!(
            self.witness_sources.first() == Some(&WitnessSource::One),
            "witness position zero must be the reserved constant one"
        );
        eyre::ensure!(
            self.witness_sources
                .iter()
                .skip(1)
                .all(|source| *source != WitnessSource::One),
            "reserved constant-one source appears outside witness position zero"
        );
        for source in &self.witness_sources {
            match *source {
                WitnessSource::One | WitnessSource::Zero => {}
                WitnessSource::Input(input) => eyre::ensure!(
                    input.index() < self.num_inputs,
                    "witness source input {input} is out of range"
                ),
                WitnessSource::Slot { bank, slot } => {
                    eyre::ensure!(bank != Bank::Local, "witness source cannot use Local bank");
                    check_slot(bank, slot, "witness source")?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Poseidon2Width;

    /// A minimal program with one Poseidon2 gadget batch, for `validate_encoding` tests that
    /// don't need a real circuit.
    fn poseidon_budget_program(bank: Bank, sites: usize, executions: usize) -> Program {
        let t = Poseidon2Width::new(3).expect("3 is a supported width");
        let input_slots = (0..sites * t.get())
            .map(|_| SiteInput {
                bank,
                slot: Slot::new(0),
            })
            .collect();
        let batch = GadgetBatch {
            kind: BatchKind::Gadget(GadgetKind::Poseidon2 { t }),
            sites,
            input_slots,
            result_requests: Vec::new(),
            result_offsets: vec![0; sites + 1],
            result_targets: Vec::new(),
        };
        Program::new(ProgramParts {
            instructions: (0..executions)
                .map(|_| Instruction::Gadget(BatchIdx::new(0)))
                .collect(),
            constants: Vec::new(),
            input_domains: Vec::new(),
            inputs: Vec::new(),
            input_signals: Vec::new(),
            rounds: Vec::new(),
            round_operands: Vec::new(),
            round_results: Vec::new(),
            gadget_batches: vec![batch],
            witness_sources: vec![WitnessSource::One],
            num_inputs: 0,
            slots: SlotCounts {
                public: u32::from(bank == Bank::Public),
                shared: u32::from(bank == Bank::Shared),
                local: 0,
            },
        })
    }

    #[test]
    fn rejects_a_malformed_witness_source_table() {
        let mut parts = poseidon_budget_program(Bank::Public, 1, 1).into_parts();
        parts.witness_sources[0] = WitnessSource::Zero;
        assert!(Program::new(parts).validate_encoding().is_err());
    }
}
