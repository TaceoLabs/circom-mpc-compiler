//! The bytecode VM: `codegen::compile` lowers a fully-passed `ir::Graph` into a `Program`
//! (fixed-width instructions over three domain-typed slot banks), and `Machine::run` executes one
//! against a pluggable `VmDriver` - `driver::plain::PlainDriver` (single-party, the reference driver) or
//! a real rep3 driver (three-party, behind the `rep3` feature).

pub mod codegen;
#[cfg(feature = "round-counting")]
pub mod counting_net;
pub mod driver;
pub mod gadgets;
pub mod machine;
pub mod program;
mod serialize;
pub mod witness;

pub use machine::{GadgetInjection, InputValue, Machine, SiteTrace};
pub use program::Program;
pub use serialize::ProgramReadLimits;
