//! Writes a merces main's `input.json` to stdout, for feeding the reference circom witness
//! calculator - see `scripts/gen-merces-artifacts.sh`, which is the intended caller.
//!
//! Deliberately the *same* code path `tests/merces.rs` uses to build its own inputs
//! (`fixtures::merces_server_inputs`), so the golden witness and this compiler's witness can never be
//! computed from different values.

use ark_bn254::Fr;
use circom_mpc_compiler::fixtures::{merces_server_inputs, to_input_json};

/// Batch size per main, matching each one's `component main` instantiation.
fn batch_size(main: &str) -> eyre::Result<usize> {
    Ok(match main {
        "transfer_arity4_batch1" => 1,
        "transfer_arity4_batch8" => 8,
        other => eyre::bail!(
            "unknown merces main `{other}` - expected transfer_arity4_batch1 or \
             transfer_arity4_batch8 (transfer_client_compressed is not supported; see \
             docs/ARCHITECTURE.md, \"Real-world target circuits\")"
        ),
    })
}

/// Both vendored server mains use MAX_DEPTH = 13.
const MAX_DEPTH: usize = 13;

/// Fixed so a regenerated artifact set is byte-identical to the previous one.
const SEED: u64 = 42;

fn main() -> eyre::Result<()> {
    let main = std::env::args()
        .nth(1)
        .ok_or_else(|| eyre::eyre!("usage: gen-merces-input <main-name>"))?;
    let inputs = merces_server_inputs::<Fr>(batch_size(&main)?, MAX_DEPTH, SEED);
    println!("{}", serde_json::to_string_pretty(&to_input_json(&inputs))?);
    Ok(())
}
