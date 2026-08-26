//! The compiled bytecode program: a slot machine over three domain-typed banks (`Public`/
//! `Shared`/`Local` - the same lattice `passes::mpc::domain` classifies values into), plus the
//! side tables that carry everything that is program *structure* rather than a per-value
//! operation - constants, inputs, batched MPC rounds, precomputation sites, and the final signal
//! witness sources.

use ark_bn254::Fr;

use crate::ir::PrecomputeKind;

/// Which physical slot bank a value lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bank {
    /// Every party holds the cleartext value directly as [`Fr`].
    Public,
    /// A valid share any op may consume - [`Fr`] in [`crate::vm::driver::plain::PlainDriver`],
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
    AddPP,
    SubPP,
    MulPP,
    AddSS,
    SubSS,
    AddSP,
    SubSP,
    SubPS,
    MulSP,
    /// The free local half of a secret x secret product: `a`/`b` are `Shared`-bank slots, `dst`
    /// is a `Local`-bank slot.
    MulLocal,
    /// One batched network round: `a` is an index into [`Program::rounds`]; `dst`/`b` are unused
    /// - a round's operands and results are its own slot lists, not encoded per-instruction.
    Reshare,
    /// One batched precomputation service: `a` is an index into [`Program::precompute_batches`];
    /// `dst`/`b` are unused - a batch's operands and results are its own slot lists, exactly as for
    /// [`Opcode::Reshare`].
    ///
    /// Being a real instruction rather than an out-of-band phase is what lets a site's inputs depend
    /// on earlier instructions - which the merces circuits require, since their Poseidon2 sites chain
    /// through secret multiplications.
    Precompute,
}

/// One instruction: a fixed-width `(opcode, dst, a, b)` record. `a`/`b`/`dst` are slot indices
/// *within whichever bank the opcode's operands live in* - fully determined by `op`, so the
/// instruction itself carries no bank tag.
#[derive(Debug, Clone, Copy)]
pub struct Instruction {
    pub op: Opcode,
    pub dst: u32,
    pub a: u32,
    pub b: u32,
}

/// One batched MPC round: `operand_start/len` index into `Program::round_operands` (`Local`-bank
/// slots to reshare together, one message) and `result_start/len` index into
/// `Program::round_results` (the `Shared`-bank slot each result lands in).
#[derive(Debug, Clone, Copy)]
pub struct RoundEntry {
    pub operand_start: u32,
    pub len: u32,
    pub result_start: u32,
}

/// One input value of one precomputation site. Carries its bank because a site input is *not*
/// always a share: a circuit may pass a literal, as `circuits/merces/oblivious_vector/hash.circom`
/// does (`TACEO_PRECOMPUTATION_Poseidon2(4)([value, 0, r, commitDs()])` - two of those four fold to
/// `Op::Constant`, i.e. `Bank::Public`). `Machine::run` promotes a `Public` slot into a share before
/// handing the batch to the driver. `Bank::Local` never appears - both `Graph::verify` and codegen
/// reject an un-reshared `MulLocal` reaching a site.
///
/// Shaped like [`WitnessSource::Slot`], the other place a `(bank, slot)` pair crosses into a side
/// table rather than an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiteInput {
    pub bank: Bank,
    pub slot: u32,
}

/// The service executed by a [`PrecomputeBatch`]. Most batches are a direct runtime realization
/// of one circuit [`PrecomputeKind`]. `IsZeroReveal` is deliberately VM-only: codegen may fuse the
/// conservative circuit shape `shared IsZero.out -> Reveal(1)` without changing the graph, R1CS,
/// witness layout, or proving artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchKind {
    Precompute(PrecomputeKind),
    /// Computes a zero test's `[out, inv]` shares and the explicitly revealed `out` together.
    IsZeroReveal,
    /// A `TACEO_INJECTED_Poseidon2` site: the host supplies this batch's trace instead of
    /// `vm::gadgets` servicing it. Poseidon2 is the only injectable gadget, and its result bank
    /// is always `Shared` - see `Machine::run_with_injection`.
    InjectedPoseidon2 {
        t: usize,
    },
}

/// One requested batch result's physical destination. Per-result (not per-batch) because a fused
/// service writes both shared witness values and a public revealed value from one site-major CSR
/// request table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResultTarget {
    pub bank: Bank,
    pub slot: u32,
}

/// Compatible `TACEO_PRECOMPUTATION_*` sites of one [`PrecomputeKind`], domain, and stage, batched
/// into a single service. Codegen first keys sites by `(kind, stage, domain)`, then splits a group
/// when an early consumer closes its anchor/deadline placement window.
///
/// Independent compatible sites normally collapse into one entry. A site may remain alone when its
/// kind, stage, or domain differs, or when combining it would cross an earlier result deadline.
#[derive(Debug, Clone)]
pub struct PrecomputeBatch {
    pub kind: BatchKind,
    pub sites: usize,
    /// `sites * (this kind's per-site input count)` entries, one site's inputs contiguous, in site
    /// order.
    pub input_slots: Vec<SiteInput>,
    /// Which of each site's logical result slots (`0..num_outputs + num_intermediates`) are
    /// actually witness-live - `passes::dead_signals` prunes the rest before codegen ever sees this
    /// batch. Site-contiguous, ascending within a site; `result_offsets[site]..result_offsets[site
    /// + 1]` is that site's own sorted sublist. Two sites in one batch can have different live
    /// counts, which is why this isn't a flat `sites * capacity` shape recoverable by division.
    pub result_requests: Vec<u32>,
    /// `len == sites + 1`: CSR row pointers into
    /// [`Self::result_requests`]/[`Self::result_targets`].
    pub result_offsets: Vec<u32>,
    /// Parallel to [`Self::result_requests`]: the banked destination for each requested value.
    /// `Bank::Local` is never valid here.
    pub result_targets: Vec<ResultTarget>,
}

/// Binds one circuit input to the slot it's read from - `Machine::run` fills these in from the
/// caller-supplied input values before running anything else.
#[derive(Debug, Clone, Copy)]
pub struct InputBinding {
    pub bank: Bank,
    pub slot: u32,
    /// The circuit's own flat input index (`0..num_inputs`) - not a per-bank ordinal, so a caller
    /// doesn't need to know how many of the circuit's inputs are public vs secret ahead of time.
    pub input_index: u32,
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
    Input(u32),
    /// A value retained in one of the VM's final slot banks.
    Slot { bank: Bank, slot: u32 },
}

/// How many slots each bank needs, sized by codegen's liveness-driven allocator - this is what
/// makes VM memory track live width instead of total node count.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SlotCounts {
    pub public: u32,
    pub shared: u32,
    pub local: u32,
}

/// A compiled circuit: the instruction stream plus every side table `Machine::run` needs to
/// execute it against a [`crate::vm::driver::VmDriver`]. Produced by
/// [`crate::vm::codegen::compile`], serializable via [`Program::write`]/[`Program::read`].
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
    pub(crate) rounds: Vec<RoundEntry>,
    pub(crate) round_operands: Vec<u32>,
    pub(crate) round_results: Vec<u32>,
    /// Indexed by [`Opcode::Precompute`]'s `a`. These are **not** run up front: each is serviced at
    /// its own point in the instruction stream, because a site's inputs may depend on earlier
    /// instructions.
    pub(crate) precompute_batches: Vec<PrecomputeBatch>,
    /// One source per final witness entry, already in circom witness order.
    pub(crate) witness_sources: Vec<WitnessSource>,
    pub(crate) num_inputs: usize,
    pub(crate) slots: SlotCounts,
}

/// One `BatchKind::Injected` batch's shape, as reported by [`Program::injected_batches`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InjectedBatch {
    pub kind: PrecomputeKind,
    pub sites: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramStatistics {
    pub instructions: usize,
    pub inputs: usize,
    pub witness_values: usize,
    pub public_slots: u32,
    pub shared_slots: u32,
    pub local_slots: u32,
    pub multiplication_rounds: usize,
    pub multiplication_elements: usize,
    pub precompute_batches: usize,
    pub precompute_sites: usize,
    pub shared_precompute_batches: usize,
    pub fused_is_zero_reveal_batches: usize,
    pub public_precompute_results: usize,
    /// Batches whose trace the host supplies at run time (`BatchKind::Injected`) rather than
    /// `vm::gadgets`.
    pub injected_batches: usize,
}

impl Program {
    pub fn input_domains(&self) -> &[Bank] {
        &self.input_domains
    }

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
            precompute_batches: self.precompute_batches.len(),
            precompute_sites: self
                .precompute_batches
                .iter()
                .map(|batch| batch.sites)
                .sum(),
            shared_precompute_batches: self
                .precompute_batches
                .iter()
                .filter(|batch| {
                    batch
                        .input_slots
                        .iter()
                        .any(|input| input.bank == Bank::Shared)
                })
                .count(),
            fused_is_zero_reveal_batches: self
                .precompute_batches
                .iter()
                .filter(|batch| batch.kind == BatchKind::IsZeroReveal)
                .count(),
            public_precompute_results: self
                .precompute_batches
                .iter()
                .flat_map(|batch| &batch.result_targets)
                .filter(|target| target.bank == Bank::Public)
                .count(),
            injected_batches: self
                .precompute_batches
                .iter()
                .filter(|batch| matches!(batch.kind, BatchKind::InjectedPoseidon2 { .. }))
                .count(),
        }
    }
    /// Derives the number of fresh Poseidon2 masks one execution needs. The budget is intentionally
    /// not serialized: it is a checked function of executable precompute instructions and their
    /// version-one batch table. Walking instructions (rather than the side table alone) ignores
    /// unreachable entries and counts a deliberately repeated batch reference once per execution.
    #[cfg(feature = "rep3")]
    pub(crate) fn poseidon2_mask_budget(&self) -> eyre::Result<usize> {
        let mut total = 0usize;
        for (instruction_index, instruction) in self.instructions.iter().enumerate() {
            if instruction.op != Opcode::Precompute {
                continue;
            }
            let batch = self
                .precompute_batches
                .get(instruction.a as usize)
                .ok_or_else(|| {
                    eyre::eyre!(
                        "instruction {instruction_index} references missing precompute batch {}",
                        instruction.a
                    )
                })?;
            let BatchKind::Precompute(PrecomputeKind::Poseidon2 { t }) = batch.kind else {
                continue;
            };
            if !batch
                .input_slots
                .iter()
                .any(|input| input.bank == Bank::Shared)
            {
                continue;
            }
            let batch_masks = super::gadgets::poseidon2::mask_elements(t, batch.sites)?;
            total = total.checked_add(batch_masks).ok_or_else(|| {
                eyre::eyre!(
                    "program-wide Poseidon2 mask budget overflows at instruction {instruction_index}"
                )
            })?;
        }
        Ok(total)
    }

    /// One `BatchKind::Injected` batch's shape, in the order `Machine::run_with_injection`
    /// consumes it (`Program::injected_batches`).
    pub fn injected_batches(&self) -> eyre::Result<Vec<InjectedBatch>> {
        let mut batches = Vec::new();
        for (instruction_index, instruction) in self.instructions.iter().enumerate() {
            if instruction.op != Opcode::Precompute {
                continue;
            }
            let batch = self
                .precompute_batches
                .get(instruction.a as usize)
                .ok_or_else(|| {
                    eyre::eyre!(
                        "instruction {instruction_index} references missing precompute batch {}",
                        instruction.a
                    )
                })?;
            if let BatchKind::InjectedPoseidon2 { t } = batch.kind {
                batches.push(InjectedBatch {
                    kind: PrecomputeKind::Poseidon2 { t },
                    sites: batch.sites,
                });
            }
        }
        Ok(batches)
    }

    /// Checks every side-table and slot reference before execution. This is intentionally usable
    /// both after deserialization and at `Machine::run`'s public boundary: `Program` fields are
    /// public, so a caller can otherwise create a malformed value without going through codegen.
    pub(crate) fn validate_encoding(&self) -> eyre::Result<()> {
        let check_slot = |bank: Bank, slot: u32, what: &str| -> eyre::Result<()> {
            let limit = match bank {
                Bank::Public => self.slots.public,
                Bank::Shared => self.slots.shared,
                Bank::Local => self.slots.local,
            };
            eyre::ensure!(
                slot < limit,
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
            let input = binding.input_index as usize;
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

        for (index, instruction) in self.instructions.iter().enumerate() {
            match instruction.op {
                Opcode::AddPP | Opcode::SubPP | Opcode::MulPP => {
                    check_slot(Bank::Public, instruction.dst, "instruction")?;
                    check_slot(Bank::Public, instruction.a, "instruction")?;
                    check_slot(Bank::Public, instruction.b, "instruction")?;
                }
                Opcode::AddSS | Opcode::SubSS => {
                    check_slot(Bank::Shared, instruction.dst, "instruction")?;
                    check_slot(Bank::Shared, instruction.a, "instruction")?;
                    check_slot(Bank::Shared, instruction.b, "instruction")?;
                }
                Opcode::AddSP | Opcode::SubSP | Opcode::MulSP => {
                    check_slot(Bank::Shared, instruction.dst, "instruction")?;
                    check_slot(Bank::Shared, instruction.a, "instruction")?;
                    check_slot(Bank::Public, instruction.b, "instruction")?;
                }
                Opcode::SubPS => {
                    check_slot(Bank::Shared, instruction.dst, "instruction")?;
                    check_slot(Bank::Public, instruction.a, "instruction")?;
                    check_slot(Bank::Shared, instruction.b, "instruction")?;
                }
                Opcode::MulLocal => {
                    check_slot(Bank::Local, instruction.dst, "instruction")?;
                    check_slot(Bank::Shared, instruction.a, "instruction")?;
                    check_slot(Bank::Shared, instruction.b, "instruction")?;
                }
                Opcode::Reshare => eyre::ensure!(
                    (instruction.a as usize) < self.rounds.len(),
                    "instruction {index} references missing round {}",
                    instruction.a
                ),
                Opcode::Precompute => eyre::ensure!(
                    (instruction.a as usize) < self.precompute_batches.len(),
                    "instruction {index} references missing precompute batch {}",
                    instruction.a
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

        for (index, batch) in self.precompute_batches.iter().enumerate() {
            eyre::ensure!(batch.sites > 0, "precompute batch {index} has no sites");
            let inputs_per_site = match batch.kind {
                BatchKind::Precompute(PrecomputeKind::Poseidon2 { t }) => {
                    eyre::ensure!(
                        super::gadgets::poseidon2::SUPPORTED_WIDTHS.contains(&t),
                        "precompute batch {index} has unsupported Poseidon2 width {t}"
                    );
                    t
                }
                BatchKind::Precompute(PrecomputeKind::Num2Bits { .. })
                | BatchKind::Precompute(PrecomputeKind::IsZero) => 1,
                BatchKind::Precompute(PrecomputeKind::AliasCheck) => 254,
                BatchKind::Precompute(PrecomputeKind::Reveal { n }) => n,
                BatchKind::IsZeroReveal => 1,
                BatchKind::InjectedPoseidon2 { t } => {
                    eyre::ensure!(
                        super::gadgets::poseidon2::SUPPORTED_WIDTHS.contains(&t),
                        "precompute batch {index} has unsupported injected Poseidon2 width {t}"
                    );
                    t
                }
            };
            let expected_inputs = batch
                .sites
                .checked_mul(inputs_per_site)
                .ok_or_else(|| eyre::eyre!("precompute batch {index} input count overflows"))?;
            eyre::ensure!(
                batch.input_slots.len() == expected_inputs,
                "precompute batch {index} has {} inputs, expected {expected_inputs}",
                batch.input_slots.len()
            );
            for input in &batch.input_slots {
                eyre::ensure!(
                    input.bank != Bank::Local,
                    "precompute batch {index} has a Local input"
                );
                check_slot(input.bank, input.slot, "precompute input")?;
            }
            if batch.kind == BatchKind::IsZeroReveal
                || matches!(batch.kind, BatchKind::InjectedPoseidon2 { .. })
            {
                eyre::ensure!(
                    batch
                        .input_slots
                        .iter()
                        .all(|input| input.bank == Bank::Shared),
                    "fused IsZeroReveal / injected batch {index} must have only Shared inputs"
                );
            }

            let expected_offsets = batch
                .sites
                .checked_add(1)
                .ok_or_else(|| eyre::eyre!("precompute batch {index} site count overflows"))?;
            eyre::ensure!(
                batch.result_offsets.len() == expected_offsets,
                "precompute batch {index} result offsets have wrong length"
            );
            let request_count = u32::try_from(batch.result_requests.len()).map_err(|_| {
                eyre::eyre!("precompute batch {index} has too many result requests")
            })?;
            eyre::ensure!(
                batch.result_offsets.first() == Some(&0)
                    && batch.result_offsets.last().copied() == Some(request_count)
                    && batch
                        .result_offsets
                        .windows(2)
                        .all(|window| window[0] <= window[1]),
                "precompute batch {index} has invalid CSR offsets"
            );
            eyre::ensure!(
                batch.result_requests.len() == batch.result_targets.len(),
                "precompute batch {index} request/target lengths differ"
            );
            let capacity = match batch.kind {
                BatchKind::Precompute(kind) => kind.expected_results().ok_or_else(|| {
                    eyre::eyre!("precompute batch {index} has no declared result capacity")
                })?,
                BatchKind::InjectedPoseidon2 { t } => PrecomputeKind::Poseidon2 { t }
                    .expected_results()
                    .ok_or_else(|| {
                        eyre::eyre!("precompute batch {index} has no declared result capacity")
                    })?,
                BatchKind::IsZeroReveal => 3,
            };
            let normal_result_bank = match batch.kind {
                BatchKind::Precompute(PrecomputeKind::Reveal { .. }) => Some(Bank::Public),
                BatchKind::Precompute(_) => Some(
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
                // An injected site is always `Shared`-domain by construction (see
                // `precompute_result_bank`); a batch built any other way is rejected above.
                BatchKind::InjectedPoseidon2 { .. } => Some(Bank::Shared),
                BatchKind::IsZeroReveal => None,
            };
            for site in 0..batch.sites {
                let lo = batch.result_offsets[site] as usize;
                let hi = batch.result_offsets[site + 1] as usize;
                eyre::ensure!(
                    hi <= batch.result_requests.len(),
                    "precompute batch {index} CSR row is out of bounds"
                );
                let requests = &batch.result_requests[lo..hi];
                eyre::ensure!(
                    requests.windows(2).all(|window| window[0] < window[1]),
                    "precompute batch {index} site {site} requests are not strictly ascending"
                );
                for (request, target) in requests.iter().zip(&batch.result_targets[lo..hi]) {
                    eyre::ensure!(
                        (*request as usize) < capacity,
                        "precompute batch {index} request {request} exceeds capacity {capacity}"
                    );
                    eyre::ensure!(
                        target.bank != Bank::Local,
                        "precompute batch {index} targets Local bank"
                    );
                    let expected_bank = normal_result_bank.unwrap_or({
                        if *request == 2 {
                            Bank::Public
                        } else {
                            Bank::Shared
                        }
                    });
                    eyre::ensure!(
                        target.bank == expected_bank,
                        "precompute batch {index} result {request} targets {:?}, expected {expected_bank:?}",
                        target.bank
                    );
                    check_slot(target.bank, target.slot, "precompute result")?;
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
                    (input as usize) < self.num_inputs,
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
    use crate::{CoCircomCompiler, CompilerConfig};

    use super::*;

    fn program(circuit: &str) -> Program {
        let root = env!("CARGO_MANIFEST_DIR");
        let mut config = CompilerConfig::default();
        config
            .link_library
            .push(format!("{root}/circuits/libs/").into());
        CoCircomCompiler::compile(format!("{root}/circuits/{circuit}.circom"), config).unwrap()
    }

    #[test]
    fn accepts_a_freshly_compiled_program() {
        program("multiplier2").validate_encoding().unwrap();
        program("precomputation_iszero_test")
            .validate_encoding()
            .unwrap();
    }

    #[test]
    fn rejects_an_input_domain_count_mismatch() {
        let mut program = program("multiplier2");
        program.input_domains.pop();
        assert!(program.validate_encoding().is_err());
    }

    #[test]
    fn rejects_an_instruction_slot_out_of_bank_bounds() {
        let mut program = program("multiplier2");
        let instruction = program
            .instructions
            .iter_mut()
            .find(|instruction| instruction.op == Opcode::MulLocal)
            .expect("multiplier2's product is a genuine secret x secret multiplication");
        instruction.a = program.slots.shared;
        assert!(program.validate_encoding().is_err());
    }

    #[test]
    fn rejects_an_instruction_referencing_a_missing_round() {
        let mut program = program("multiplier2");
        let instruction = program
            .instructions
            .iter_mut()
            .find(|instruction| instruction.op == Opcode::Reshare)
            .expect("multiplier2's product needs one reshare round");
        instruction.a = program.rounds.len() as u32;
        assert!(program.validate_encoding().is_err());
    }

    #[test]
    fn rejects_a_precompute_batch_with_wrong_input_count() {
        let mut program = program("precomputation_iszero_test");
        program.precompute_batches[0].input_slots.pop();
        assert!(program.validate_encoding().is_err());
    }

    #[test]
    fn rejects_a_malformed_witness_source_table() {
        let mut program = program("multiplier2");
        program.witness_sources[0] = WitnessSource::Zero;
        assert!(program.validate_encoding().is_err());
    }

    #[cfg(feature = "rep3")]
    fn poseidon_budget_program(bank: Bank, sites: usize, executions: usize) -> Program {
        let t = 3;
        let input_slots = (0..sites * t)
            .map(|_| SiteInput { bank, slot: 0 })
            .collect();
        let batch = PrecomputeBatch {
            kind: BatchKind::Precompute(PrecomputeKind::Poseidon2 { t }),
            sites,
            input_slots,
            result_requests: Vec::new(),
            result_offsets: vec![0; sites + 1],
            result_targets: Vec::new(),
        };
        Program {
            instructions: (0..executions)
                .map(|_| Instruction {
                    op: Opcode::Precompute,
                    dst: 0,
                    a: 0,
                    b: 0,
                })
                .collect(),
            constants: Vec::new(),
            input_domains: Vec::new(),
            inputs: Vec::new(),
            rounds: Vec::new(),
            round_operands: Vec::new(),
            round_results: Vec::new(),
            precompute_batches: vec![batch],
            witness_sources: vec![WitnessSource::One],
            num_inputs: 0,
            slots: SlotCounts {
                public: u32::from(bank == Bank::Public),
                shared: u32::from(bank == Bank::Shared),
                local: 0,
            },
        }
    }

    #[cfg(feature = "rep3")]
    #[test]
    fn poseidon_mask_budget_tracks_executable_shared_batches() {
        let public = poseidon_budget_program(Bank::Public, 2, 1);
        assert_eq!(public.poseidon2_mask_budget().unwrap(), 0);

        // t=3 consumes 8*3 + 56 = 80 masks per site.
        let shared = poseidon_budget_program(Bank::Shared, 2, 1);
        assert_eq!(shared.poseidon2_mask_budget().unwrap(), 160);

        let repeated = poseidon_budget_program(Bank::Shared, 2, 2);
        assert_eq!(repeated.poseidon2_mask_budget().unwrap(), 320);

        let mut unreferenced = shared.clone();
        unreferenced.instructions.clear();
        assert_eq!(unreferenced.poseidon2_mask_budget().unwrap(), 0);
    }

    #[cfg(feature = "rep3")]
    #[test]
    fn poseidon_mask_budget_is_derived_after_serialization() {
        let original = poseidon_budget_program(Bank::Shared, 2, 2);
        original.validate_encoding().unwrap();
        let mut bytes = Vec::new();
        original.write(&mut bytes).unwrap();
        let decoded = Program::read(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded.poseidon2_mask_budget().unwrap(), 320);
    }

    #[cfg(feature = "rep3")]
    #[test]
    fn poseidon_mask_budget_rejects_checked_arithmetic_overflow() {
        let mut program = poseidon_budget_program(Bank::Shared, 1, 1);
        program.precompute_batches[0].sites = usize::MAX;
        assert!(program.poseidon2_mask_budget().is_err());
    }
}
