//! The compiled circuit representation: `Program` (a slot-machine bytecode program plus its side
//! tables), `AcceleratorKind` (which gadget an accelerator site runs), and the on-disk format
//! (`Program::write`/`Program::read`). No dependency on the compiler or the VM - a downstream
//! crate that only needs to load and inspect a compiled program can depend on this crate alone.

mod accelerator;
mod inputs;
mod program;
mod serialize;

pub use accelerator::AcceleratorKind;
pub use inputs::{InputValue, InputValues};
pub use program::{
    AcceleratorBatch, Bank, BatchKind, InputBinding, Instruction, Opcode,
    POSEIDON2_SUPPORTED_WIDTHS, PrecomputedBatch, Program, ProgramParts, ProgramStatistics,
    ResultTarget, RoundEntry, SiteInput, SlotCounts, WitnessSource,
};
pub use serialize::ProgramReadLimits;
