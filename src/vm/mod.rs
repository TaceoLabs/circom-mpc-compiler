//! The bytecode VM: `codegen::compile` lowers a fully-passed `ir::Graph` into a `Program`
//! (fixed-width instructions over three domain-typed slot banks), and `Machine::run` executes one
//! against a pluggable `VmDriver` - `driver::plain::PlainDriver` (single-party, the KAT oracle) or
//! a real rep3 driver (three-party, behind the `rep3` feature). See `docs/ARCHITECTURE.md`,
//! "Bytecode and the slot machine".

pub mod codegen;
#[cfg(feature = "round-counting")]
pub mod counting_net;
pub mod driver;
pub mod gadgets;
pub mod machine;
pub mod program;
mod serialize;
pub mod witness;

pub use machine::{InputValue, Machine};
pub use program::Program;
