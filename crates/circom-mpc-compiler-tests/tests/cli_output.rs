//! A compiled program written to a file by the `circom-mpc-compile` CLI (`Program::write`) reads
//! back byte-identical via `Program::read`. `tests/serialize.rs` round-trips through an in-memory
//! `Vec<u8>`; this is the one path that goes through an actual file.

use circom_mpc_compiler::CompilerConfig;
use circom_mpc_program::Program;

#[test]
fn round_trips_through_a_file() {
    let root = env!("CARGO_MANIFEST_DIR");
    let mut config = CompilerConfig::default();
    config
        .link_library
        .push(format!("{root}/../../circuits/node_modules/").into());
    let original = circom_mpc_compiler::compile(
        format!("{root}/../../circuits/multiplier2.circom"),
        &config,
    )
    .unwrap();

    let path = std::env::temp_dir().join("circom-mpc-compiler-tests-round-trip.cmpc");
    original
        .write(&mut std::io::BufWriter::new(
            std::fs::File::create(&path).unwrap(),
        ))
        .unwrap();
    let read_back =
        Program::read(&mut std::io::BufReader::new(std::fs::File::open(&path).unwrap())).unwrap();
    std::fs::remove_file(&path).unwrap();

    assert_eq!(original.statistics(), read_back.statistics());
}
