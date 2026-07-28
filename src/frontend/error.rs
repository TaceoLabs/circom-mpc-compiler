//! Typed errors for circom constructs this compiler deliberately does not support, replacing the
//! `todo!()`/`panic!()`s that used to stand in for them. Every frontend function on the path from
//! `build_graph` down to these error sites already returns `eyre::Result`, and `eyre::Report`'s
//! blanket `From<E: std::error::Error>` threads these without any extra glue - see
//! `GraphCompiler`'s `err_*` helpers in `build.rs`, which build one of these and hand it back as
//! an `eyre::Report` via `From::from`.

use thiserror::Error;

/// A circom construct this compiler deliberately does not support (yet, or ever).
#[derive(Debug, Error)]
pub enum Unsupported {
    #[error("unsupported operator `{op}` in template `{template}` at line {line}")]
    Operator {
        op: String,
        template: String,
        line: usize,
    },
    #[error(
        "operator `{op}` is only supported on compile-time constants (template `{template}`, line {line})"
    )]
    NonConstantOperator {
        op: String,
        template: String,
        line: usize,
    },
    #[error(
        "address operator `{op}` in value position (template `{template}`, line {line}) - dynamic array indexing is not supported"
    )]
    AddressOperator {
        op: String,
        template: String,
        line: usize,
    },
    #[error("unsupported instruction `{kind}` in template `{template}` at line {line}")]
    Instruction {
        kind: String,
        template: String,
        line: usize,
    },
    #[error(
        "unsupported mapped location rule in template `{template}` at line {line} - bus/anonymous component access is not supported"
    )]
    MappedLocation { template: String, line: usize },
    #[error(
        "unrecognized TACEO_PRECOMPUTATION_* gadget `{gadget}` in template `{template}` at line {line} - only Poseidon2, Num2Bits, IsZero, and AliasCheck are supported"
    )]
    PrecomputeGadget {
        gadget: String,
        template: String,
        line: usize,
    },
}
