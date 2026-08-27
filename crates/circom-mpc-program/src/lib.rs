//! The compiled circuit representation: `Program` (a slot-machine bytecode program plus its side
//! tables), `PrecomputeKind` (which gadget a precomputation site runs), and the on-disk format
//! (`Program::write`/`Program::read`). No dependency on the compiler or the VM - a downstream
//! crate that only needs to load and inspect a compiled program can depend on this crate alone.

mod inputs;
mod precompute;
mod program;
mod serialize;

pub use inputs::{InputValue, InputValues};
pub use precompute::PrecomputeKind;
pub use program::{
    Bank, BatchKind, InjectedBatch, InputBinding, Instruction, Opcode, PrecomputeBatch, Program,
    ProgramParts, ProgramStatistics, ResultTarget, RoundEntry, SiteInput, SlotCounts,
    WitnessSource, POSEIDON2_SUPPORTED_WIDTHS,
};
pub use serialize::ProgramReadLimits;
