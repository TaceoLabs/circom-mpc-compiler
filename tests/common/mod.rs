//! Shared test fixture loading: circuit/library paths and the `kats/<name>/input<i>.json` loader
//! used by `circom_ir.rs` and `tests/proving.rs`.
//!
//! Lives under `tests/common/mod.rs` (not `tests/common.rs`) so cargo does not also compile it as
//! its own (empty) integration test binary — only files directly under `tests/` get that
//! treatment.

// Each integration test binary compiles this module separately, so any binary using only part of
// it (e.g. `frontend.rs`, which needs the path helpers but not the input loader) would otherwise
// warn on the rest.
#![allow(dead_code)]

use std::{fs::File, str::FromStr};

pub fn manifest_dir() -> &'static str {
    env!("CARGO_MANIFEST_DIR")
}

pub fn circuit_path(name: &str) -> String {
    format!("{}/circuits/{name}.circom", manifest_dir())
}

pub fn libs_path() -> std::path::PathBuf {
    format!("{}/circuits/libs/", manifest_dir()).into()
}

pub fn read_field_element(s: &str) -> ark_bn254::Fr {
    if let Some(striped) = s.strip_prefix('-') {
        -ark_bn254::Fr::from_str(striped).unwrap()
    } else {
        ark_bn254::Fr::from_str(s).unwrap()
    }
}

/// Every `kats/<fn_name>/input<i>.json`, in order.
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
