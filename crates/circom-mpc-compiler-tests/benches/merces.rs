//! Merces witness extension, plain versus rep3, swept over the transaction batch size `N`.
//! Throughput is defined over `N` (transactions per run), so criterion's `thrpt` column reads as
//! transactions/second across batch sizes. Inputs are seeded-random field elements, not real
//! protocol values - this bench never proves, and rep3's cost is value-independent.
//!
//! Each party's `LocalNetwork` and `Rep3State` are built once per `N` and reused across timed
//! iterations (unlike `witness_extension.rs`, which models a fresh connection per run); each
//! iteration still prepares a fresh program-wide Poseidon2 pool before the online VM.

use ark_bn254::Fr;
use ark_ff::UniformRand;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::SeedableRng;
use rand::rngs::StdRng;

use circom_mpc_compiler::CoCircomCompiler;
use circom_mpc_compiler::codegen;
use circom_mpc_compiler_tests::fixtures::{merces_config, merces_main_path, rep3::share_inputs};
use circom_mpc_vm::driver::plain::PlainDriver;
use circom_mpc_vm::driver::rep3::Rep3Driver;
use circom_mpc_vm::{Machine, Program};
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::rep3::{Rep3PrimeFieldShare, Rep3State};
use mpc_net::local::LocalNetwork;

/// Transaction counts to sweep - matches `circuits/merces/main/transfer_arity4_batch{N}.circom` and
/// `src/bin/merces-net.rs`'s default `--batches`.
const BATCHES: [usize; 4] = [1, 8, 16, 32];

/// Fixed so every run (and every party, since all three derive the same values then keep only their
/// own share) sees the same inputs.
const SEED: u64 = 0;

/// Compiles `transfer_arity4_batch{n}.circom` and builds its seeded-random inputs, printing the
/// round shape so a timing can be read against it. Compilation is deliberately outside the measured
/// closure - parsing batch32 alone takes seconds.
fn prepare(n: usize) -> (Program, Vec<Fr>) {
    let path = merces_main_path(&format!("transfer_arity4_batch{n}"));
    let graph =
        CoCircomCompiler::parse(path, merces_config()).unwrap_or_else(|e| panic!("batch{n}: {e}"));
    let summary = graph.mpc_summary();
    let mut rng = StdRng::seed_from_u64(SEED);
    let values: Vec<Fr> = (0..graph.num_inputs).map(|_| Fr::rand(&mut rng)).collect();
    let program = codegen::compile(&graph).unwrap_or_else(|e| panic!("batch{n}: {e}"));
    println!(
        "batch{n:<3} rounds={:3} reshare_elements={:6} max_slots={:5} sites={:4} batches={:3} instrs={:6}",
        summary.rounds,
        summary.reshare_elements,
        summary.max_slots_per_round.unwrap_or(0),
        summary.gadget_sites,
        summary.gadget_batches,
        program.statistics().instructions,
    );
    (program, values)
}

fn run_plain(program: &Program, values: &[Fr]) -> Vec<Fr> {
    let inputs = program.classify_inputs(values, |v| v);
    let mut driver = PlainDriver;
    Machine::run(program, &mut driver, &inputs).expect("plain run")
}

/// Builds the three rep3 parties' network and correlated-randomness state once, for reuse across
/// every timed `run_rep3` call at this `N` - the handshake needs the parties concurrently, so it runs
/// in its own scope rather than the caller's.
fn rep3_setup() -> (Vec<LocalNetwork>, Vec<Rep3State>) {
    let networks = LocalNetwork::new(3);
    let states = std::thread::scope(|scope| {
        let handles: Vec<_> = networks
            .iter()
            .map(|net| scope.spawn(move || Rep3State::new(net, A2BType::default()).unwrap()))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    (networks, states)
}

/// One full 3-party total-cost execution over the long-lived `networks`/`states` `rep3_setup` built
/// for this `N`, including fresh program-wide Poseidon2 preprocessing on every run.
fn run_rep3(
    program: &Program,
    values: &[Fr],
    shares: &[[Rep3PrimeFieldShare<Fr>; 3]],
    networks: &[LocalNetwork],
    states: &mut [Rep3State],
) {
    std::thread::scope(|scope| {
        let handles: Vec<_> = networks
            .iter()
            .zip(states.iter_mut())
            .enumerate()
            .map(|(party, (net, state))| {
                scope.spawn(move || {
                    let mut driver = Rep3Driver::new_for_run(net, state, program).unwrap();
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
    println!("\n--- merces batch scaling (round count is the floor MPC time cannot go below) ---");

    let mut group = c.benchmark_group("merces_batch_scaling");
    // rep3 over three in-process threads gets far slower as N grows; the default 100 samples would
    // take too long at batch32 (same precedent as benches/compile.rs's slow `parse` group).
    group.sample_size(10);

    for n in BATCHES {
        let (program, values) = prepare(n);
        // N transactions per run, so throughput reads as transactions/second across the whole sweep.
        group.throughput(Throughput::Elements(n as u64));

        group.bench_with_input(BenchmarkId::new("plain", n), &(), |b, ()| {
            b.iter(|| run_plain(&program, &values));
        });

        let shares = share_inputs(&program, &values);

        let (networks, mut states) = rep3_setup();
        group.bench_with_input(BenchmarkId::new("rep3_total", n), &(), |b, ()| {
            b.iter(|| run_rep3(&program, &values, &shares, &networks, &mut states));
        });
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
