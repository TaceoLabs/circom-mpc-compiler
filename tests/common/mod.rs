//! Shared KAT (known-answer-test) fixture loading, used by both `circom_ir.rs` and `mpc_ir.rs`.
//! Was copy-pasted between the two files before; consolidated here as part of the IR rewrite.
//!
//! Lives under `tests/common/mod.rs` (not `tests/common.rs`) so cargo does not also compile it as
//! its own (empty) integration test binary — only files directly under `tests/` get that
//! treatment.

use std::{
    fs::{self, File},
    str::FromStr,
};

use crate::misc::Witness;

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

pub fn from_test_name(fn_name: &str) -> TestInputs {
    let root = manifest_dir();
    let mut witnesses: Vec<Witness<ark_bn254::Fr>> = Vec::new();
    let mut inputs: Vec<Vec<ark_bn254::Fr>> = Vec::new();
    let mut i = 0;
    loop {
        if fs::metadata(format!("{root}/kats/{fn_name}/witness{i}.wtns")).is_err() {
            break;
        }
        let witness = File::open(format!("{root}/kats/{fn_name}/witness{i}.wtns")).unwrap();
        let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
        witnesses.push(should_witness);
        let input_file = File::open(format!("{root}/kats/{fn_name}/input{i}.json")).unwrap();
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
        panic!("no test for {fn_name}");
    }
    TestInputs { inputs, witnesses }
}
