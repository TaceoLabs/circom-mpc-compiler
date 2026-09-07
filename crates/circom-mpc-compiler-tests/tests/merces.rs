//! Independent known-answer tests for the large Merces circuits. These deliberately stop at the
//! complete witness: unlike the small circuits in `proving.rs`, Merces has no zkey workflow here.

use std::{collections::BTreeMap, path::PathBuf};

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use circom_mpc_compiler::{CompilerConfig, OptLevel};
use circom_mpc_compiler_tests::fixtures::{merces_mpc_public_inputs, rep3::run_witness};
use circom_mpc_program::{InputSignal, Program};
use circom_mpc_vm::{Machine, driver::plain::PlainDriver};
use sha2::{Digest, Sha256};

fn root() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

fn compile(batch: usize) -> Program {
    std::thread::Builder::new()
        .name(format!("compile-merces-batch{batch}"))
        .stack_size(64 << 20)
        .spawn(move || {
            let root = root();
            let config = CompilerConfig {
                opt_level: OptLevel::O2,
                link_library: vec![
                    root.join("circuits/node_modules"),
                    root.join("circuits/merces"),
                ],
                mpc_public_inputs: merces_mpc_public_inputs(),
                precomputed_gadgets: false,
                ..CompilerConfig::default()
            };
            circom_mpc_compiler::compile(
                root.join(format!(
                    "circuits/merces/main/transfer_arity4_batch{batch}.circom"
                )),
                &config,
            )
            .unwrap_or_else(|e| panic!("Merces batch {batch} must compile: {e}"))
        })
        .unwrap()
        .join()
        .unwrap()
}

fn flatten(value: &serde_json::Value, out: &mut Vec<Fr>) {
    if let Some(rows) = value.as_array() {
        for row in rows {
            flatten(row, out);
        }
    } else {
        let decimal = value
            .as_str()
            .map(str::to_owned)
            .or_else(|| value.as_u64().map(|v| v.to_string()))
            .unwrap_or_else(|| panic!("input leaf must be a decimal field element: {value}"));
        let bigint = num_bigint::BigUint::parse_bytes(decimal.as_bytes(), 10)
            .unwrap_or_else(|| panic!("invalid decimal field element: {decimal}"));
        out.push(Fr::from_le_bytes_mod_order(&bigint.to_bytes_le()));
    }
}

fn fixture_values(batch: usize, signals: &[InputSignal]) -> Vec<Fr> {
    let path = root().join(format!(
        "kats/merces/transfer_arity4_batch{batch}/valid.json"
    ));
    let json: BTreeMap<String, serde_json::Value> =
        serde_json::from_reader(std::fs::File::open(&path).unwrap()).unwrap();
    let mut values = vec![Fr::from(0u64); signals.iter().map(|s| s.size).sum()];
    for signal in signals {
        let mut flattened = Vec::new();
        flatten(
            json.get(&signal.name)
                .unwrap_or_else(|| panic!("{}: missing input {}", path.display(), signal.name)),
            &mut flattened,
        );
        assert_eq!(
            flattened.len(),
            signal.size,
            "{}: shape of {}",
            path.display(),
            signal.name
        );
        values[signal.offset..signal.offset + signal.size].copy_from_slice(&flattened);
    }
    values
}

fn canonical_witness_digest(witness: &[Fr]) -> String {
    let mut hash = Sha256::new();
    for value in witness {
        let mut bytes = value.into_bigint().to_bytes_le();
        bytes.resize(32, 0);
        hash.update(bytes);
    }
    hash.finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn witness_kat(batch: usize) {
    let program = compile(batch);
    let values = fixture_values(batch, program.input_signals());
    let inputs = program.classify_inputs(&values, |value| value);
    let plain = Machine::run(&program, &mut PlainDriver, &inputs).unwrap();
    assert_eq!(
        run_witness(&program, &values),
        plain,
        "Merces batch {batch}: Rep3 reconstruction"
    );

    let digest_path = root().join(format!(
        "kats/merces/transfer_arity4_batch{batch}/expected.sha256"
    ));
    let expected = std::fs::read_to_string(&digest_path).unwrap();
    assert_eq!(
        canonical_witness_digest(&plain),
        expected.trim(),
        "Merces batch {batch}: full canonical witness differs from pinned Circom; refresh only with scripts/refresh-merces-witness-kats.sh"
    );
}

#[test]
fn transfer_arity4_batch1_witness_kat() {
    witness_kat(1);
}

#[test]
fn transfer_arity4_batch4_witness_kat() {
    witness_kat(4);
}
