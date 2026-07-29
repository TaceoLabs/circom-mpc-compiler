//! Shared KAT (known-answer-test) fixture loading, used by `circom_ir.rs` and `rep3_vm.rs`.
//!
//! Lives under `tests/common/mod.rs` (not `tests/common.rs`) so cargo does not also compile it as
//! its own (empty) integration test binary — only files directly under `tests/` get that
//! treatment.

// Each integration test binary compiles this module separately, so any binary using only part of
// it (e.g. `frontend.rs`, which needs the path helpers but not the KAT loader) would otherwise
// warn on the rest.
#![allow(dead_code)]

use std::{fs::File, str::FromStr};

use circom_types::Witness;

pub fn manifest_dir() -> &'static str {
    env!("CARGO_MANIFEST_DIR")
}

pub fn circuit_path(name: &str) -> String {
    format!("{}/circuits/{name}.circom", manifest_dir())
}

pub fn libs_path() -> std::path::PathBuf {
    format!("{}/circuits/libs/", manifest_dir()).into()
}

#[derive(Debug)]
pub struct TestInputs {
    pub inputs: Vec<Vec<ark_bn254::Fr>>,
    pub witnesses: Vec<Witness<ark_bn254::Fr>>,
}

pub fn read_field_element(s: &str) -> ark_bn254::Fr {
    if let Some(striped) = s.strip_prefix('-') {
        -ark_bn254::Fr::from_str(striped).unwrap()
    } else {
        ark_bn254::Fr::from_str(s).unwrap()
    }
}

/// Every `kats/<fn_name>/input<i>.json`, in order, with no golden witness requirement - the input
/// half of `from_test_name`, usable by fixtures (like the prove+verify tests) that check the
/// witness against a zkey-derived proof rather than a `.wtns` byte comparison.
pub fn inputs_from_test_name(fn_name: &str) -> Vec<Vec<ark_bn254::Fr>> {
    let root = manifest_dir();
    let mut inputs: Vec<Vec<ark_bn254::Fr>> = Vec::new();
    let mut i = 0;
    loop {
        let Ok(input_file) = File::open(format!("{root}/kats/{fn_name}/input{i}.json")) else {
            break;
        };
        let json_str: serde_json::Value = serde_json::from_reader(input_file).unwrap();
        let input = json_str
            .get("in")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|s| read_field_element(s.as_str().unwrap()))
            .collect::<Vec<_>>();
        inputs.push(input);
        i += 1
    }
    if i == 0 {
        panic!("no input fixtures for {fn_name}");
    }
    inputs
}

pub fn from_test_name(fn_name: &str) -> TestInputs {
    let root = manifest_dir();
    let inputs = inputs_from_test_name(fn_name);
    let witnesses = (0..inputs.len())
        .map(|i| {
            let witness = File::open(format!("{root}/kats/{fn_name}/witness{i}.wtns")).unwrap();
            Witness::<ark_bn254::Fr>::from_reader(witness).unwrap()
        })
        .collect();
    TestInputs { inputs, witnesses }
}
