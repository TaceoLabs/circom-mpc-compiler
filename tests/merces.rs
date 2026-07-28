//! Compile-only checks for the real-world circuits vendored from `~/repos/merces/circom`
//! (`circuits/merces/`). These are **not** witness-compared - there is no golden `.wtns` oracle for
//! them, deliberately (see `docs/ARCHITECTURE.md`, "Real-world target circuits"). The only thing
//! asserted here is whether `CoCircomCompiler::parse` succeeds, and if it doesn't, that it fails
//! with a typed `Unsupported` error (a precise "this operator/instruction isn't supported yet")
//! rather than a panic.
//!
//! All three currently fail - the operator surface is deliberately limited to `Add`/`Sub`/`Mul`
//! (see `src/ir.rs`), and the circuits reach `Div` (field inversion inside `IsZero`) and
//! `ShiftR`/`BitAnd` (bit extraction inside `Num2Bits`) at runtime. That failure is the point: it's
//! the visible marker for what has to land before these circuits compile end-to-end.

use ark_bn254::Bn254;
use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig, SimplificationLevel};

fn manifest_dir() -> &'static str {
    env!("CARGO_MANIFEST_DIR")
}

fn merces_circuit_path(name: &str) -> String {
    format!("{}/circuits/merces/main/{name}.circom", manifest_dir())
}

fn merces_config() -> CompilerConfig {
    let mut config = CompilerConfig::default();
    // The vendored circuits are pragma circom 2.2.2 verbatim; the compiler's own default version
    // was raised to match (src/lib.rs::default_version) rather than pinned here, but set it
    // explicitly anyway so this test doesn't silently rely on that default staying in sync.
    config.version = "2.2.2".to_owned();
    config.simplification = SimplificationLevel::O2(usize::MAX);
    // Two link libraries, mirroring how merces itself compiles these circuits (`-l circom/
    // node_modules -l circom`): `circuits/libs/` resolves circomlib + the vendored `taceo/`
    // subtree, `circuits/merces/` resolves the `merces/`/`oblivious_vector/` cross-references.
    config
        .link_library
        .push(format!("{}/circuits/libs/", manifest_dir()).into());
    config
        .link_library
        .push(format!("{}/circuits/merces/", manifest_dir()).into());
    config
}

macro_rules! compile_only_test {
    ($name:ident) => {
        #[test]
        fn $name() {
            let path = merces_circuit_path(stringify!($name));
            match CoCircomCompiler::<Bn254>::parse(path, merces_config()) {
                Ok(_) => panic!(
                    "{} compiled successfully - if this is expected, replace this compile-only \
                     check with a real witness-comparison test",
                    stringify!($name)
                ),
                Err(e) => {
                    // Confirm this is a clean, typed "unsupported" error naming the exact gap,
                    // not an uncaught panic bubbling up as some other kind of failure.
                    let msg = e.to_string();
                    assert!(
                        msg.contains("unsupported operator")
                            || msg.contains("unsupported instruction")
                            || msg.contains("unsupported mapped location")
                            || msg.contains("is only supported on compile-time constants"),
                        "{} failed for an unexpected reason (not a typed Unsupported error): {msg}",
                        stringify!($name)
                    );
                }
            }
        }
    };
}

compile_only_test!(transfer_arity4_batch1);
compile_only_test!(transfer_arity4_batch8);
compile_only_test!(transfer_client_compressed);
