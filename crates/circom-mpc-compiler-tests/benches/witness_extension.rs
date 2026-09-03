//! `Machine::run` under `PlainDriver` versus real 3-party `Rep3Driver` over an in-process
//! `LocalNetwork`: the gap between the two series is what MPC actually costs for a given circuit,
//! and the `Program::statistics` line printed per circuit is what makes a number interpretable - a
//! circuit's floor is its round count, not its instruction count. In-process, so rep3 numbers
//! measure protocol work and round structure, not network latency. `rep3_total` is total cost:
//! every measured iteration includes `Rep3State` setup, fresh Poseidon2 preprocessing, and online
//! execution.

use ark_bn254::Fr;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use circom_mpc_compiler::CompilerConfig;
use circom_mpc_compiler_tests::fixtures::rep3::{run_witness_with_shares, share_inputs};
use circom_mpc_vm::driver::plain::PlainDriver;
use circom_mpc_vm::{Machine, Program};

fn manifest_dir() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../..")
}

/// One benched circuit: where it lives and how to build its inputs.
struct Case {
    /// Benchmark label, also the circuit's file stem under `circuits/`.
    name: &'static str,
}

fn cases() -> Vec<Case> {
    vec![
        // Known round shape (see tests/mpc_lowering.rs): a dependent chain, a balanced tree, and
        // four independent products - i.e. worst, middling and best cases for round batching.
        Case {
            name: "bench_chain",
        },
        Case { name: "bench_tree" },
        Case {
            name: "bench_widesum",
        },
    ]
}

fn config() -> CompilerConfig {
    let mut config = CompilerConfig::default();
    config
        .link_library
        .push(format!("{}/circuits/node_modules/", manifest_dir()).into());
    config
}

/// Compiles a case and builds its inputs, printing the round shape so a timing can be read against
/// it. Compilation is deliberately outside the measured closure.
fn prepare(case: &Case) -> (Program, Vec<Fr>) {
    let path = format!("{}/circuits/{}.circom", manifest_dir(), case.name);
    let program = circom_mpc_compiler::compile(path, &config())
        .unwrap_or_else(|e| panic!("{}: {e}", case.name));
    let stats = program.statistics();
    // Arbitrary but non-zero, so nothing degenerates into a trivial product.
    let values: Vec<Fr> = (0..stats.inputs).map(|i| Fr::from(i as u64 + 1)).collect();
    println!(
        "{:26} rounds={:3} reshare_elements={:6} max_slots={:5} sites={:4} batches={:3} instrs={:6}",
        case.name,
        stats.multiplication_rounds,
        stats.multiplication_elements,
        stats.max_slots_per_round.unwrap_or(0),
        stats.gadget_sites,
        stats.gadget_batches,
        stats.instructions,
    );
    (program, values)
}

fn run_plain(program: &Program, values: &[Fr]) -> Vec<Fr> {
    let inputs = program.classify_inputs(values, |v| v);
    let mut driver = PlainDriver;
    Machine::run(program, &mut driver, &inputs).expect("plain run")
}

fn bench(c: &mut Criterion) {
    println!("\n--- circuit shapes (round count is the floor MPC time cannot go below) ---");
    let prepared: Vec<(Case, Program, Vec<Fr>)> = cases()
        .into_iter()
        .map(|case| {
            let (program, values) = prepare(&case);
            (case, program, values)
        })
        .collect();
    println!();

    let mut group = c.benchmark_group("witness_extension");
    // Witness entries produced, so throughput is comparable across very different circuit sizes.
    for (case, program, values) in &prepared {
        group.throughput(Throughput::Elements(
            program.statistics().witness_values as u64,
        ));

        group.bench_with_input(BenchmarkId::new("plain", case.name), &(), |b, ()| {
            b.iter(|| run_plain(program, values));
        });

        let shares = share_inputs(program, values);
        // Each iteration is total cost: fresh network, `Rep3State` setup, program-wide Poseidon2
        // preprocessing, then online execution - what a fresh connection would pay.
        group.bench_with_input(BenchmarkId::new("rep3_total", case.name), &(), |b, ()| {
            b.iter(|| run_witness_with_shares(program, values, &shares));
        });
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
