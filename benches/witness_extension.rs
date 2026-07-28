//! `Machine::run` under `PlainDriver` versus real 3-party `Rep3Driver` over
//! `mpc_net::local::LocalNetwork`.
//!
//! The plain/rep3 pair is the headline comparison: plain is pure local field arithmetic, so the gap
//! between them is what MPC actually costs for a given circuit, and `Graph::mpc_summary` (printed
//! once per circuit before the benches run) is what makes a number interpretable - a circuit's floor
//! is its round count, not its instruction count.
//!
//! `transfer_arity4_batch1` versus `batch8` is the interesting pair: the same template at N=1 and
//! N=8, so it shows how round count and reshare width scale with batch size while precomputation
//! batching absorbs the extra sites.
//!
//! Note `LocalNetwork` is in-process, so rep3 numbers here measure protocol *work* and round
//! *structure*, not real network latency - which is exactly the quantity round batching reduces.

use ark_bn254::{Bn254, Fr};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use circom_mpc_compiler::fixtures::{flatten, merces_server_inputs};
use circom_mpc_compiler::vm::driver::plain::PlainDriver;
use circom_mpc_compiler::vm::driver::rep3::Rep3Driver;
use circom_mpc_compiler::vm::program::Bank;
use circom_mpc_compiler::vm::{codegen, Machine, Program};
use circom_mpc_compiler::{
    BareGadgetDetection, CoCircomCompiler, CompilerConfig, SimplificationLevel,
    UnknownPrecomputeGadget,
};
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::rep3::{share_field_element, Rep3PrimeFieldShare, Rep3State};
use mpc_net::local::LocalNetwork;
use rand::thread_rng;

const MAX_DEPTH: usize = 13;
const SEED: u64 = 42;

fn manifest_dir() -> &'static str {
    env!("CARGO_MANIFEST_DIR")
}

/// One benched circuit: where it lives and how to build its inputs.
struct Case {
    /// Benchmark label.
    name: &'static str,
    path: String,
    /// `Some(n)` for a merces server main with batch size `n`; `None` for a simple circuit whose
    /// inputs are just sequential values.
    merces_batch: Option<usize>,
    /// Needs the merces link libraries and leniency knobs.
    merces_config: bool,
}

fn simple(name: &'static str) -> Case {
    Case {
        name,
        path: format!("{}/circuits/{name}.circom", manifest_dir()),
        merces_batch: None,
        merces_config: false,
    }
}

fn merces(name: &'static str, n: usize) -> Case {
    Case {
        name,
        path: format!("{}/circuits/merces/main/{name}.circom", manifest_dir()),
        merces_batch: Some(n),
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
        merces("transfer_arity4_batch1", 1),
        merces("transfer_arity4_batch8", 8),
    ]
}

fn config(case: &Case) -> CompilerConfig {
    let mut config = CompilerConfig::default();
    config.simplification = SimplificationLevel::O2(usize::MAX);
    config
        .link_library
        .push(format!("{}/circuits/libs/", manifest_dir()).into());
    if case.merces_config {
        config.version = "2.2.2".to_owned();
        config
            .link_library
            .push(format!("{}/circuits/merces/", manifest_dir()).into());
        // See tests/merces.rs for why these two are needed.
        config.unknown_precompute_gadget = UnknownPrecomputeGadget::Warn;
        config.bare_gadget_detection = BareGadgetDetection::On;
    }
    config
}

/// Compiles a case and builds its inputs, printing the round shape so a timing can be read against
/// it. Compilation is deliberately outside the measured closure.
fn prepare(case: &Case) -> (Program<Fr>, Vec<Fr>) {
    let graph = CoCircomCompiler::<Bn254>::parse(case.path.clone(), config(case))
        .unwrap_or_else(|e| panic!("{}: {e}", case.name));
    let summary = graph.mpc_summary();
    let values = match case.merces_batch {
        Some(n) => {
            let named = merces_server_inputs::<Fr>(n, MAX_DEPTH, SEED);
            flatten(&named, &graph.input_list).unwrap_or_else(|e| panic!("{}: {e}", case.name))
        }
        // Arbitrary but non-zero, so nothing degenerates into a trivial product.
        None => (0..graph.num_inputs).map(|i| Fr::from(i as u64 + 1)).collect(),
    };
    let program = codegen::compile(&graph).unwrap_or_else(|e| panic!("{}: {e}", case.name));
    println!(
        "{:26} rounds={:3} reshare_elements={:6} max_slots={:5} sites={:4} batches={:3} instrs={:6}",
        case.name,
        summary.rounds,
        summary.reshare_elements,
        summary.max_slots_per_round.unwrap_or(0),
        summary.precompute_sites,
        summary.precompute_batches,
        program.instructions.len(),
    );
    (program, values)
}

fn run_plain(program: &Program<Fr>, values: &[Fr]) -> Vec<Fr> {
    let inputs = program.classify_inputs(values, |v| v);
    let mut driver = PlainDriver;
    Machine::run(program, &mut driver, &inputs).expect("plain run")
}

/// One full 3-party execution, including the per-run `Rep3State` setup a real deployment would also
/// pay once per connection.
fn run_rep3(program: &Program<Fr>, values: &[Fr], shares: &[[Rep3PrimeFieldShare<Fr>; 3]]) {
    let networks = LocalNetwork::new(3);
    std::thread::scope(|scope| {
        let handles: Vec<_> = networks
            .into_iter()
            .enumerate()
            .map(|(party, net)| {
                scope.spawn(move || {
                    let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                    let mut driver = Rep3Driver::new(&net, &mut state);
                    let mut next = 0;
                    let inputs = program.classify_inputs(values, |_v| {
                        let s = shares[next][party];
                        next += 1;
                        s
                    });
                    Machine::run(program, &mut driver, &inputs).unwrap()
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    });
}

fn bench(c: &mut Criterion) {
    println!("\n--- circuit shapes (round count is the floor MPC time cannot go below) ---");
    let prepared: Vec<(Case, Program<Fr>, Vec<Fr>)> = cases()
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
        group.throughput(Throughput::Elements(program.signal_to_witness.len() as u64));

        group.bench_with_input(BenchmarkId::new("plain", case.name), &(), |b, ()| {
            b.iter(|| run_plain(program, values));
        });

        let mut rng = thread_rng();
        let shares: Vec<[Rep3PrimeFieldShare<Fr>; 3]> = program
            .input_domains
            .iter()
            .zip(values)
            .filter(|(bank, _)| matches!(bank, Bank::Shared))
            .map(|(_, &v)| share_field_element(v, &mut rng))
            .collect();

        group.bench_with_input(BenchmarkId::new("rep3", case.name), &(), |b, ()| {
            b.iter(|| run_rep3(program, values, &shares));
        });
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
