//! The compiled bytecode program: a slot machine over three domain-typed banks (`Public`/
//! `Shared`/`Local` - the same lattice `passes::mpc::domain` classifies values into), plus the
//! side tables that carry everything that is program *structure* rather than a per-value
//! operation - constants, inputs, batched MPC rounds, precomputation sites, and the final witness
//! sources. See `docs/ARCHITECTURE.md`, "Bytecode and the slot machine".

use ark_ff::PrimeField;

use crate::ir::PrecomputeKind;

/// Which physical slot bank a value lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bank {
    /// Every party holds the cleartext value directly - `F` in every driver.
    Public,
    /// A valid share any op may consume - `F` in [`crate::vm::driver::plain::PlainDriver`],
    /// `Rep3PrimeFieldShare<F>` in the rep3 driver.
    Shared,
    /// A post-`MulLocal`, pre-reshare additive-3 sharing. Only ever an operand of [`Opcode::Reshare`]
    /// - codegen rejects any graph where a `Local` value reaches anything else.
    Local,
}

/// One operation. Arithmetic opcodes are named `<Op><BankOfA><BankOfB>` (`P` public, `S` shared);
/// `MulLocal`/`Reshare` are the MPC-lowering ops (see `docs/ARCHITECTURE.md`, "MPC lowering").
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
    /// through secret multiplications (see `docs/ARCHITECTURE.md`, "Precomputation").
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

/// One batched MPC round (see `docs/ARCHITECTURE.md`, "MPC lowering"): `operand_start/len` index
/// into `Program::round_operands` (`Local`-bank slots to reshare together, one message) and
/// `result_start/len` index into `Program::round_results` (`Shared`-bank slots each result lands
/// in; `u32::MAX` = discard - structurally supported for a future pass that prunes an unread round
/// result without renumbering the round table, though nothing produces one today).
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

/// Compatible `TACEO_PRECOMPUTATION_*` sites of one [`PrecomputeKind`], domain, and stage, batched
/// into a single service. Codegen first keys sites by `(kind, stage, domain)`, then splits a group
/// when an early consumer closes its anchor/deadline placement window. See
/// `docs/ARCHITECTURE.md`, "Precomputation".
///
/// Independent compatible sites normally collapse into one entry. A site may remain alone when its
/// kind, stage, or domain differs, or when combining it would cross an earlier result deadline.
#[derive(Debug, Clone)]
pub struct PrecomputeBatch {
    pub kind: PrecomputeKind,
    pub sites: usize,
    /// Public batches execute the deterministic plain gadget and write clear values; shared
    /// batches execute the driver's MPC gadget. `Local` is never valid here.
    pub result_bank: Bank,
    /// `sites * (this kind's per-site input count)` entries, one site's inputs contiguous, in site
    /// order.
    pub input_slots: Vec<SiteInput>,
    /// Which of each site's logical result slots (`0..num_outputs + num_intermediates`) are
    /// actually witness-live - `passes::dead_signals` prunes the rest before codegen ever sees this
    /// batch. Site-contiguous, ascending within a site; `result_offsets[site]..result_offsets[site
    /// + 1]` is that site's own sorted sublist. Two sites in one batch can have different live
    /// counts, which is why this isn't a flat `sites * capacity` shape recoverable by division.
    pub result_requests: Vec<u32>,
    /// `len == sites + 1`: CSR row pointers into [`Self::result_requests`]/[`Self::result_slots`].
    pub result_offsets: Vec<u32>,
    /// Parallel to [`Self::result_requests`]: the destination slot in [`Self::result_bank`] for
    /// each requested value. `u32::MAX` = discard.
    pub result_slots: Vec<u32>,
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

/// Where one final witness entry's value comes from, once the instruction stream (and precompute
/// phase) have both run. Codegen records these directly in witness order (`Program::witness_sources`
/// is `len == ` the witness itself), so `Machine::run` builds exactly the witness-sized output with
/// no intermediate signal-indexed array to project out of afterward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessSource {
    /// Witness position zero, the reserved constant `1`.
    One,
    /// A witness position with no surviving producer - an unconstrained circom signal. The old
    /// signal-indexed array was zero-initialized, so this preserves that behavior explicitly rather
    /// than requiring every witness position to have a genuine producer.
    Zero,
    /// One of the circuit's own top-level inputs (`0..num_inputs`). Not read through any node - a
    /// circuit input `gc` dropped as dead is still a genuine witness entry (see
    /// `docs/ARCHITECTURE.md`, "Precomputation": only a *nested* subcomponent's own input signal is
    /// ever a `graph.outputs()` entry, never main's) - so this reads directly from `Machine::run`'s
    /// caller-supplied `inputs` instead.
    Input(u32),
    /// A value retained in one of the VM's own final slot banks. `Bank::Local` never appears here -
    /// codegen rejects an un-reshared `MulLocal` reaching a circuit output.
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
pub struct Program<F: PrimeField> {
    pub instructions: Vec<Instruction>,
    /// Preloaded into `Public`-bank slots `0..constants.len()` at init - no const opcode.
    pub constants: Vec<F>,
    /// One entry per circuit input (`len == num_inputs`), in flat signal order - `Bank::Local`
    /// never appears. An input whose `Op::Input` node didn't survive `gc` (dead, never read) has
    /// no corresponding entry here; its domain still appears in this table so a caller can tell
    /// which representation to prepare without needing it to be live.
    pub input_domains: Vec<Bank>,
    pub inputs: Vec<InputBinding>,
    pub rounds: Vec<RoundEntry>,
    pub round_operands: Vec<u32>,
    pub round_results: Vec<u32>,
    /// Indexed by [`Opcode::Precompute`]'s `a`. These are **not** run up front: each is serviced at
    /// its own point in the instruction stream, because a site's inputs may depend on earlier
    /// instructions (see `docs/ARCHITECTURE.md`, "Precomputation").
    pub precompute_batches: Vec<PrecomputeBatch>,
    /// This program's entire Poseidon2 s-box correlated-randomness budget, summed across every
    /// genuinely `Shared` `Poseidon2` batch (see `vm::gadgets::poseidon2::sbox_randomness_budget`)
    /// - `0` if none. Not consumed by `Machine::run` itself: a real rep3 caller spends it once,
    /// offline, via `Rep3Driver::preprocess`, before binding any circuit input - see
    /// `docs/ARCHITECTURE.md`, "Precomputation". `PlainDriver` never reads this field.
    pub sbox_randomness: u64,
    /// One source per final witness entry, already in circom witness order - see
    /// [`WitnessSource`]. Empty for a hand-built `Program` with no witness projection (codegen's own
    /// unit tests; mirrors `Graph::signal_to_witness`'s same empty-means-no-projection convention).
    pub witness_sources: Vec<WitnessSource>,
    pub num_inputs: usize,
    pub slots: SlotCounts,
}

impl<F: PrimeField> Program<F> {
    /// Checks every instruction and side-table reference, bank/slot bound, round range, batch
    /// arity and CSR shape, and witness source against `self.slots`/`self.num_inputs` - every
    /// `Program` field is `pub`, so a caller can otherwise hand `Machine::run` a malformed value
    /// that would reach unchecked indexing instead of a typed error. Only meaningful against an
    /// executable/serialized program: a hand-built codegen unit-test `Program` has an empty
    /// `witness_sources` (see its own doc), which this treats as "no witness to check", the same
    /// convention `passes::dead_signals` uses for an empty `Graph::signal_to_witness`.
    pub fn validate(&self) -> eyre::Result<()> {
        let check_slot = |bank: Bank, slot: u32, what: &str| -> eyre::Result<()> {
            let limit = match bank {
                Bank::Public => self.slots.public,
                Bank::Shared => self.slots.shared,
                Bank::Local => self.slots.local,
            };
            eyre::ensure!(slot < limit, "{what} references {bank:?} slot {slot}, but bank size is {limit}");
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
            eyre::ensure!(bank != Bank::Local, "input {input} has invalid Local domain");
        }
        for binding in &self.inputs {
            let input = binding.input_index as usize;
            eyre::ensure!(input < self.num_inputs, "input binding index {input} is out of range");
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
            eyre::ensure!(operand_end <= self.round_operands.len(), "round {index} operand range is out of bounds");
            eyre::ensure!(result_end <= self.round_results.len(), "round {index} result range is out of bounds");
            for &slot in &self.round_operands[operand_start..operand_end] {
                check_slot(Bank::Local, slot, "round operand")?;
            }
            for &slot in &self.round_results[result_start..result_end] {
                if slot != u32::MAX {
                    check_slot(Bank::Shared, slot, "round result")?;
                }
            }
        }

        for (index, batch) in self.precompute_batches.iter().enumerate() {
            eyre::ensure!(batch.sites > 0, "precompute batch {index} has no sites");
            eyre::ensure!(batch.result_bank != Bank::Local, "precompute batch {index} result bank cannot be Local");
            let inputs_per_site = match batch.kind {
                PrecomputeKind::Poseidon2 { t } => {
                    eyre::ensure!(
                        super::gadgets::poseidon2::SUPPORTED_WIDTHS.contains(&t),
                        "precompute batch {index} has unsupported Poseidon2 width {t}"
                    );
                    t
                }
                PrecomputeKind::Num2Bits { .. }
                | PrecomputeKind::IsZero
                | PrecomputeKind::IsZeroRevealed => 1,
                PrecomputeKind::IsEqual | PrecomputeKind::IsEqualRevealed => 2,
                PrecomputeKind::AliasCheck => 254,
                PrecomputeKind::Reveal { n } => n,
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
                eyre::ensure!(input.bank != Bank::Local, "precompute batch {index} has a Local input");
                check_slot(input.bank, input.slot, "precompute input")?;
            }

            let expected_offsets = batch
                .sites
                .checked_add(1)
                .ok_or_else(|| eyre::eyre!("precompute batch {index} site count overflows"))?;
            eyre::ensure!(
                batch.result_offsets.len() == expected_offsets,
                "precompute batch {index} result offsets have wrong length"
            );
            let request_count = u32::try_from(batch.result_requests.len())
                .map_err(|_| eyre::eyre!("precompute batch {index} has too many result requests"))?;
            eyre::ensure!(
                batch.result_offsets.first() == Some(&0)
                    && batch.result_offsets.last().copied() == Some(request_count)
                    && batch.result_offsets.windows(2).all(|window| window[0] <= window[1]),
                "precompute batch {index} has invalid CSR offsets"
            );
            eyre::ensure!(
                batch.result_requests.len() == batch.result_slots.len(),
                "precompute batch {index} request/slot lengths differ"
            );
            let capacity = batch
                .kind
                .expected_results()
                .ok_or_else(|| eyre::eyre!("precompute batch {index} has no declared result capacity"))?;
            for site in 0..batch.sites {
                let lo = batch.result_offsets[site] as usize;
                let hi = batch.result_offsets[site + 1] as usize;
                eyre::ensure!(hi <= batch.result_requests.len(), "precompute batch {index} CSR row is out of bounds");
                let requests = &batch.result_requests[lo..hi];
                eyre::ensure!(
                    requests.windows(2).all(|window| window[0] < window[1]),
                    "precompute batch {index} site {site} requests are not strictly ascending"
                );
                for (&request, &slot) in requests.iter().zip(&batch.result_slots[lo..hi]) {
                    eyre::ensure!(
                        (request as usize) < capacity,
                        "precompute batch {index} request {request} exceeds capacity {capacity}"
                    );
                    if slot != u32::MAX {
                        check_slot(batch.result_bank, slot, "precompute result")?;
                    }
                }
            }
        }

        if !self.witness_sources.is_empty() {
            eyre::ensure!(
                self.witness_sources.first() == Some(&WitnessSource::One),
                "witness position zero must be the reserved constant one"
            );
            eyre::ensure!(
                self.witness_sources.iter().skip(1).all(|source| *source != WitnessSource::One),
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
        }

        // `sbox_randomness` is this crate's own new field (see its doc) and the one a caller is
        // most likely to get wrong by hand: an undersized budget surfaces as a pool-exhausted
        // error deep inside a gadget mid-run, not at this boundary.
        let expected_sbox_randomness: u64 = self
            .precompute_batches
            .iter()
            .filter(|batch| batch.result_bank == Bank::Shared)
            .filter_map(|batch| match batch.kind {
                PrecomputeKind::Poseidon2 { t } => {
                    Some(super::gadgets::poseidon2::sbox_randomness_budget(t, batch.sites))
                }
                _ => None,
            })
            .sum();
        eyre::ensure!(
            self.sbox_randomness == expected_sbox_randomness,
            "sbox_randomness is {}, but the shared Poseidon2 batches need {expected_sbox_randomness}",
            self.sbox_randomness
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::{Bn254, Fr};

    use crate::{CoCircomCompiler, CompilerConfig};

    use super::*;

    fn program(circuit: &str) -> Program<Fr> {
        let root = env!("CARGO_MANIFEST_DIR");
        let mut config = CompilerConfig::default();
        config.link_library.push(format!("{root}/circuits/libs/").into());
        CoCircomCompiler::<Bn254>::compile(format!("{root}/circuits/{circuit}.circom"), config)
            .unwrap()
    }

    #[test]
    fn accepts_a_freshly_compiled_program() {
        program("multiplier2").validate().unwrap();
        program("precomputation_iszero_test").validate().unwrap();
    }

    #[test]
    fn rejects_an_input_domain_count_mismatch() {
        let mut p = program("multiplier2");
        p.input_domains.pop();
        assert!(p.validate().is_err());
    }

    #[test]
    fn rejects_an_instruction_slot_out_of_bank_bounds() {
        let mut p = program("multiplier2");
        let instr = p
            .instructions
            .iter_mut()
            .find(|i| i.op == Opcode::MulLocal)
            .expect("multiplier2's out <== a*b is a genuine secret x secret product");
        instr.a = p.slots.shared;
        assert!(p.validate().is_err());
    }

    #[test]
    fn rejects_an_instruction_referencing_a_missing_round() {
        let mut p = program("multiplier2");
        let instr = p
            .instructions
            .iter_mut()
            .find(|i| i.op == Opcode::Reshare)
            .expect("multiplier2's product needs exactly one reshare round");
        instr.a = p.rounds.len() as u32;
        assert!(p.validate().is_err());
    }

    #[test]
    fn rejects_a_precompute_batch_with_wrong_input_count() {
        let mut p = program("precomputation_iszero_test");
        p.precompute_batches[0].input_slots.pop();
        assert!(p.validate().is_err());
    }

    #[test]
    fn rejects_a_malformed_witness_source_table() {
        let mut p = program("multiplier2");
        p.witness_sources[0] = WitnessSource::Zero;
        assert!(p.validate().is_err());
    }

    #[test]
    fn rejects_a_wrong_sbox_randomness_budget() {
        let mut p = program("precomputation_iszero_test");
        p.sbox_randomness += 1;
        assert!(p.validate().is_err());
    }
}
