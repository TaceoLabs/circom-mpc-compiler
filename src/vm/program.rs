//! The compiled bytecode program: a slot machine over three domain-typed banks (`Public`/
//! `Shared`/`Local` - the same lattice `passes::mpc::domain` classifies values into), plus the
//! side tables that carry everything that is program *structure* rather than a per-value
//! operation - constants, inputs, batched MPC rounds, precomputation sites, and the final signal
//! stores. See `docs/ARCHITECTURE.md`, "Bytecode and the slot machine".

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
/// Shaped like [`StoreEntry`], which is the other place a `(bank, slot)` pair crosses into a side
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

/// Where one final circuit signal's value comes from, once the instruction stream has run.
#[derive(Debug, Clone, Copy)]
pub struct StoreEntry {
    pub bank: Bank,
    pub slot: u32,
    pub signal: u32,
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
    pub stores: Vec<StoreEntry>,
    pub signal_to_witness: Vec<usize>,
    pub num_inputs: usize,
    /// Circuit input `k` lives at signal index `num_outputs + k` (matching
    /// `passes::mpc::domain::signal_domain`'s own convention) - `Machine::run` needs this to copy
    /// each raw input value into the final signals array directly, rather than through a live
    /// `Op::Input` node (which may not exist: a circuit input `gc` dropped as dead is still a
    /// genuine witness entry, just one nothing in the graph reads).
    pub num_outputs: usize,
    pub num_signals: usize,
    pub slots: SlotCounts,
}
