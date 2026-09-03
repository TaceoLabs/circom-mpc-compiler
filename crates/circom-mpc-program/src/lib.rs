//! The compiled circuit representation: `Program` (a slot-machine bytecode program plus its side
//! tables), `GadgetKind` (which gadget a gadget site runs), and the on-disk format
//! (`Program::write`/`Program::read`). No dependency on the compiler or the VM - a downstream
//! crate that only needs to load and inspect a compiled program can depend on this crate alone.

mod gadget;
mod index;
mod inputs;
mod program;
mod serialize;

pub use gadget::{GadgetKind, Poseidon2Width};
pub use index::{BatchIdx, InputIdx, ResultSlot, RoundIdx, Slot};
pub use inputs::{InputValue, InputValues};
pub use program::{
    Bank, BatchKind, GadgetBatch, InputBinding, InputSignal, Instruction, Opcode,
    POSEIDON2_SUPPORTED_WIDTHS, PrecomputedBatch, Program, ProgramParts, ProgramStatistics,
    ResultTarget, RoundEntry, SiteInput, SlotCounts, WitnessSource,
};
pub use serialize::ProgramReadLimits;
