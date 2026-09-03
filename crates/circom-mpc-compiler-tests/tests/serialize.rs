//! Round-trips `Program::write`/`Program::read` (the on-disk format, `circom-mpc-program`) against
//! real compiled circuits and checks the resulting witness is identical.

use ark_bn254::Fr;
use circom_mpc_compiler::CompilerConfig;
use circom_mpc_program::{
    Bank, BatchKind, Instruction, Poseidon2Width, Program, Slot, WitnessSource,
};
use circom_mpc_vm::{Machine, driver::plain::PlainDriver};

/// Compiles one fixture through the public path used by serialized programs.
fn program(circuit: &str) -> Program {
    let root = env!("CARGO_MANIFEST_DIR");
    let mut config = CompilerConfig::default();
    config
        .link_library
        .push(format!("{root}/../../circuits/node_modules/").into());
    circom_mpc_compiler::compile(format!("{root}/../../circuits/{circuit}.circom"), &config)
        .unwrap()
}

fn witness(program: &Program, inputs: &[Fr]) -> Vec<Fr> {
    let inputs = program.classify_inputs(inputs, |v| v).unwrap();
    let mut driver = PlainDriver;
    Machine::run(program, &mut driver, &inputs).unwrap()
}

#[test]
fn round_trips_a_program_with_a_round_byte_identically() {
    let original = program("multiplier2");
    assert_eq!(
        original.witness_sources().first(),
        Some(&WitnessSource::One)
    );
    assert!(
        original
            .witness_sources()
            .iter()
            .any(|source| matches!(source, WitnessSource::Input(_)))
    );
    assert!(
        original
            .witness_sources()
            .iter()
            .any(|source| matches!(source, WitnessSource::Slot { .. }))
    );
    let mut bytes = Vec::new();
    original.write(&mut bytes).unwrap();
    let read_back = Program::read(&mut bytes.as_slice()).unwrap();

    let inputs = [Fr::from(5u64), Fr::from(10u64)];
    assert_eq!(witness(&original, &inputs), witness(&read_back, &inputs));
}

#[test]
fn round_trips_input_signal_names() {
    use std::collections::BTreeMap;

    use circom_mpc_program::{InputValue, InputValues};

    let original = program("multiplier2");
    assert!(
        !original.input_signals().is_empty(),
        "fixture must declare named inputs for this test to cover anything"
    );
    let mut bytes = Vec::new();
    original.write(&mut bytes).unwrap();
    let read_back = Program::read(&mut bytes.as_slice()).unwrap();

    assert_eq!(read_back.input_signals(), original.input_signals());

    // A name-keyed map, resolved against the round-tripped program's own `input_signals`, must
    // scatter into the same positional order `classify_inputs` produces for the same values.
    let positional_values = [Fr::from(5u64), Fr::from(10u64)];
    let positional = read_back
        .classify_inputs(&positional_values, |v| v)
        .unwrap();

    let mut named: BTreeMap<String, Vec<InputValue<Fr>>> = BTreeMap::new();
    for signal in read_back.input_signals() {
        let values = (signal.offset..signal.offset + signal.size)
            .map(|i| positional[i].clone())
            .collect();
        named.insert(signal.name.clone(), values);
    }
    let via_map = named.as_inputs(&read_back).unwrap();

    fn unwrap(v: &InputValue<Fr>) -> Fr {
        match v {
            InputValue::Public(v) | InputValue::Secret(v) => *v,
        }
    }

    assert_eq!(via_map.len(), positional.len());
    for (m, p) in via_map.iter().zip(&positional) {
        assert_eq!(
            std::mem::discriminant(m),
            std::mem::discriminant(p),
            "named map must classify each input the same way as classify_inputs"
        );
        assert_eq!(unwrap(m), unwrap(p));
    }
}

#[test]
fn round_trips_a_program_with_a_precompute_site_byte_identically() {
    let original = program("gadget_iszero_test");
    let mut bytes = Vec::new();
    original.write(&mut bytes).unwrap();
    let read_back = Program::read(&mut bytes.as_slice()).unwrap();

    let inputs = [Fr::from(0u64)];
    assert_eq!(witness(&original, &inputs), witness(&read_back, &inputs));
}

#[test]
fn round_trips_an_unbound_zero_witness_source() {
    let original = program("loop_unrolling");
    assert!(original.witness_sources().contains(&WitnessSource::Zero));
    let mut bytes = Vec::new();
    original.write(&mut bytes).unwrap();
    let read_back = Program::read(&mut bytes.as_slice()).unwrap();
    assert!(read_back.witness_sources().contains(&WitnessSource::Zero));

    let inputs: Vec<_> = (1..=original.num_inputs())
        .map(|i| Fr::from(i as u64))
        .collect();
    assert_eq!(witness(&original, &inputs), witness(&read_back, &inputs));
}

#[test]
fn round_trips_a_fused_iszero_reveal_batch() {
    let original = program("gadget_iszero_reveal_test");
    assert_eq!(original.gadget_batches().len(), 1);
    assert_eq!(original.gadget_batches()[0].kind, BatchKind::IsZeroReveal);
    assert_eq!(original.gadget_batches()[0].sites, 2);
    let mut bytes = Vec::new();
    original.write(&mut bytes).unwrap();
    let read_back = Program::read(&mut bytes.as_slice()).unwrap();

    assert_eq!(read_back.gadget_batches()[0].kind, BatchKind::IsZeroReveal);
    assert_eq!(read_back.gadget_batches()[0].sites, 2);
    let inputs = [Fr::from(0u64), Fr::from(7u64)];
    assert_eq!(witness(&original, &inputs), witness(&read_back, &inputs));
}

#[test]
fn round_trips_a_fused_isequal_reveal_batch() {
    let original = program("gadget_isequal_reveal_test");
    assert_eq!(original.gadget_batches().len(), 1);
    assert_eq!(original.gadget_batches()[0].kind, BatchKind::IsZeroReveal);
    assert_eq!(original.gadget_batches()[0].sites, 3);
    let mut bytes = Vec::new();
    original.write(&mut bytes).unwrap();
    let read_back = Program::read(&mut bytes.as_slice()).unwrap();

    assert_eq!(read_back.gadget_batches()[0].kind, BatchKind::IsZeroReveal);
    assert_eq!(read_back.gadget_batches()[0].sites, 3);
    let inputs = [Fr::from(10u64), Fr::from(4u64), Fr::from(7u64)];
    assert_eq!(witness(&original, &inputs), witness(&read_back, &inputs));
}

#[test]
fn round_trips_a_public_precompute_batch() {
    let original = program("gadget_public_test");
    assert!(
        original
            .gadget_batches()
            .iter()
            .flat_map(|batch| &batch.result_targets)
            .all(|target| target.bank == Bank::Public)
    );
    let mut bytes = Vec::new();
    original.write(&mut bytes).unwrap();
    let read_back = Program::read(&mut bytes.as_slice()).unwrap();
    assert!(
        read_back
            .gadget_batches()
            .iter()
            .flat_map(|batch| &batch.result_targets)
            .all(|target| target.bank == Bank::Public)
    );
    let inputs = [Fr::from(0u64), Fr::from(9u64)];
    assert_eq!(witness(&original, &inputs), witness(&read_back, &inputs));
}

/// The two single-site programs above both have exactly one batch, so they can't catch a bug in
/// how *multiple* batches or their `Opcode::Gadget` instructions round-trip. This one is
/// genuinely staged: two same-kind sites at different stages, hence two batches interleaved into
/// the stream (see `circuits/gadget_staged_test.circom`).
#[test]
fn round_trips_a_staged_multi_batch_program() {
    let original = program("gadget_staged_test");
    assert_eq!(
        original.gadget_batches().len(),
        2,
        "fixture must be staged for this test to cover anything"
    );
    let mut bytes = Vec::new();
    original.write(&mut bytes).unwrap();
    let read_back = Program::read(&mut bytes.as_slice()).unwrap();

    assert_eq!(read_back.gadget_batches().len(), 2);
    assert_eq!(
        read_back
            .instructions()
            .iter()
            .filter(|i| matches!(i, Instruction::Gadget(_)))
            .count(),
        2
    );
    let inputs = [Fr::from(3u64), Fr::from(5u64)];
    assert_eq!(witness(&original, &inputs), witness(&read_back, &inputs));
}

#[test]
fn validation_rejects_out_of_range_witness_and_batch_targets() {
    let mut invalid_witness = program("multiplier2").into_parts();
    invalid_witness.witness_sources[1] = WitnessSource::Slot {
        bank: Bank::Shared,
        slot: Slot::new(invalid_witness.slots.shared),
    };
    let invalid_witness = Program::new(invalid_witness);
    assert!(invalid_witness.validate_encoding().is_err());
    assert!(invalid_witness.write(&mut Vec::new()).is_err());

    let mut invalid_batch = program("gadget_iszero_test").into_parts();
    invalid_batch.gadget_batches[0].result_targets[0].slot = Slot::new(invalid_batch.slots.shared);
    assert!(Program::new(invalid_batch).validate_encoding().is_err());

    // An unsupported Poseidon2 width is now rejected at construction, not at
    // `validate_encoding` time - `Poseidon2Width` can never hold one.
    assert!(Poseidon2Width::new(5).is_err());
}
