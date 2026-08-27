//! The bytecode VM: `Machine::run` executes a `circom_mpc_program::Program` (produced by the
//! compiler crate's `codegen::compile`) against a pluggable `VmDriver` -
//! `driver::plain::PlainDriver` (single-party, the reference driver) or a real three-party rep3
//! driver. No dependency on the compiler or on circom.

pub mod counting_net;
pub mod driver;
pub mod gadgets;
mod machine;
mod witness;

pub use circom_mpc_program::{
    self as program, InputValue, InputValues, Program, ProgramReadLimits,
};
pub use machine::{GadgetInjection, Machine, SiteTrace};
pub use mpc_net;
pub use witness::split_witness;
