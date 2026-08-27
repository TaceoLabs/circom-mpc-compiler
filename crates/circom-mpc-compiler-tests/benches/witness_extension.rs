//! `Machine::run` under `PlainDriver` versus real 3-party `Rep3Driver` over an in-process
//! `LocalNetwork`: the gap between the two series is what MPC actually costs for a given circuit,
//! and the `Graph::mpc_summary` line printed per circuit is what makes a number interpretable - a
//! circuit's floor is its round count, not its instruction count. In-process, so rep3 numbers
//! measure protocol work and round structure, not network latency. `rep3_total` is total cost:
//! every measured iteration includes `Rep3State` setup, fresh Poseidon2 preprocessing, and online
//! execution.

use ark_bn254::Fr;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use circom_mpc_compiler::codegen;
use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig};
use circom_mpc_compiler_tests::fixtures::{
    self, rep3::run_witness_with_shares, rep3::share_inputs,
};
use circom_mpc_vm::driver::plain::PlainDriver;
use circom_mpc_vm::{Machine, Program};

fn manifest_dir() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../..")
}

/// One benched circuit: where it lives and how to build its inputs.
struct Case {
    /// Benchmark label.
    name: &'static str,
    path: String,
    /// `Some(scenario)` for a merces server main, naming which real input set to use; `None` for a
    /// simple circuit whose inputs are just sequential values.
    merces_scenario: Option<&'static str>,
    /// Needs the merces link libraries.
    merces_config: bool,
}

fn simple(name: &'static str) -> Case {
    Case {
        name,
        path: format!("{}/circuits/{name}.circom", manifest_dir()),
        merces_scenario: None,
        merces_config: false,
    }
}

fn merces(name: &'static str, scenario: &'static str) -> Case {
    Case {
        name,
        path: format!("{}/circuits/merces/main/{name}.circom", manifest_dir()),
        merces_scenario: Some(scenario),
        merces_config: true,
    }
}

fn cases() -> Vec<Case> {
    vec![
        // Known round shape (see tests/mpc_lowering.rs): a dependent chain, a balanced tree, and
        // four independent products - i.e. worst, middling and best cases for round batching.
        simple("bench_chain"),
        simple("bench_tree"),
        simple("bench_widesum"),
        // `transfer`/`full_batch` are the scenarios with `isTransfer = 1` slots, the widest live
        // value spread of the four scenarios each main has.
        merces("transfer_arity4_batch1", "transfer"),
        merces("transfer_arity4_batch8", "full_batch"),
    ]
}

fn config(case: &Case) -> CompilerConfig {
    if case.merces_config {
        return fixtures::merces_config();
    }
    let mut config = CompilerConfig::default();
    config
        .link_library
        .push(format!("{}/circuits/libs/", manifest_dir()).into());
    config
}

/// Compiles a case and builds its inputs, printing the round shape so a timing can be read against
/// it. Compilation is deliberately outside the measured closure.
fn prepare(case: &Case) -> (Program, Vec<Fr>) {
    let graph = CoCircomCompiler::parse(case.path.clone(), config(case))
        .unwrap_or_else(|e| panic!("{}: {e}", case.name));
    let summary = graph.mpc_summary();
    let values = match case.merces_scenario {
        Some(scenario) => fixtures::scenario(case.name, scenario)
            .and_then(|s| s.values(&graph.input_list))
            .unwrap_or_else(|e| panic!("{}: {e}", case.name)),
        // Arbitrary but non-zero, so nothing degenerates into a trivial product.
        None => (0..graph.num_inputs)
            .map(|i| Fr::from(i as u64 + 1))
            .collect(),
    };
    let program = codegen::compile(&graph).unwrap_or_else(|e| panic!("{}: {e}", case.name));
    println!(
        "{:26} rounds={:3} reshare_elements={:6} max_slots={:5} sites={:4} batches={:3} instrs={:6}",
        case.name,
        summary.rounds,
        summary.reshare_elements,
        summary.max_slots_per_round.unwrap_or(0),
        summary.accelerator_sites,
        summary.accelerator_batches,
        program.statistics().instructions,
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
