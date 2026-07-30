//! Merces witness extension, plain versus rep3, swept over the transaction batch size `N` of
//! `TransferBatchedCompressedArity4(N, ...)`. Throughput is defined over `N` (transactions per run,
//! not witness entries), so criterion's `thrpt` column reads directly as transactions/second and is
//! comparable across batch sizes - this is the question `benches/witness_extension.rs` cannot answer,
//! since it normalizes throughput by witness size and only compares batch1 against batch8.
//!
//! Inputs are seeded-random field elements (`StdRng::seed_from_u64`), not real protocol values, for
//! every `N` uniformly - this bench only measures witness-extension time and never proves or checks
//! a `===` constraint, and rep3's cost is value-independent (see `src/bin/merces-net.rs`, which makes
//! the same call). Real fixtures only exist for batch1/batch8 anyway (`src/fixtures.rs`); using them
//! for those two and dummy values for batch16/batch32 would mix two input provenances in one group
//! for no benefit here.
//!
//! Each party's `LocalNetwork` and `Rep3State` (the correlated-randomness handshake) are built once
//! per `N`, outside every timed iteration, and reused across all of them - deliberately unlike
//! `witness_extension.rs`, which pays that setup inside every timed run to model a fresh connection.
//! Here the setup cost is roughly constant in `N` and would compress the very scaling curve this bench
//! exists to measure.

use ark_bn254::{Bn254, Fr};
use ark_ff::UniformRand;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::rngs::StdRng;
use rand::{thread_rng, SeedableRng};

use circom_mpc_compiler::vm::driver::plain::PlainDriver;
use circom_mpc_compiler::vm::driver::rep3::Rep3Driver;
use circom_mpc_compiler::vm::program::Bank;
use circom_mpc_compiler::vm::{codegen, Machine, Program};
use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig};
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::rep3::{share_field_element, Rep3PrimeFieldShare, Rep3State};
use mpc_net::local::LocalNetwork;

/// Transaction counts to sweep - matches `circuits/merces/main/transfer_arity4_batch{N}.circom` and
/// `src/bin/merces-net.rs`'s default `--batches`.
const BATCHES: [usize; 4] = [1, 8, 16, 32];

/// Fixed so every run (and every party, since all three derive the same values then keep only their
/// own share) sees the same inputs.
const SEED: u64 = 0;

fn manifest_dir() -> &'static str {
    env!("CARGO_MANIFEST_DIR")
}

fn config() -> CompilerConfig {
    let mut config = CompilerConfig::default();
    config.version = "2.2.2".to_owned();
    config
        .link_library
        .push(format!("{}/circuits/libs/", manifest_dir()).into());
    config
        .link_library
        .push(format!("{}/circuits/merces/", manifest_dir()).into());
    config.mpc_public_inputs = circom_mpc_compiler::fixtures::merces_mpc_public_inputs();
    config
}

/// Compiles `transfer_arity4_batch{n}.circom` and builds its seeded-random inputs, printing the
/// round shape so a timing can be read against it. Compilation is deliberately outside the measured
/// closure - parsing batch32 alone takes seconds.
fn prepare(n: usize) -> (Program<Fr>, Vec<Fr>) {
    let path = format!(
        "{}/circuits/merces/main/transfer_arity4_batch{n}.circom",
        manifest_dir()
    );
    let graph =
        CoCircomCompiler::<Bn254>::parse(path, config()).unwrap_or_else(|e| panic!("batch{n}: {e}"));
    let summary = graph.mpc_summary();
    let mut rng = StdRng::seed_from_u64(SEED);
    let values: Vec<Fr> = (0..graph.num_inputs).map(|_| Fr::rand(&mut rng)).collect();
    let program = codegen::compile(&graph).unwrap_or_else(|e| panic!("batch{n}: {e}"));
    println!(
        "batch{n:<3} rounds={:3} reshare_elements={:6} max_slots={:5} sites={:4} batches={:3} instrs={:6}",
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

/// One full 3-party execution over the long-lived `networks`/`states` `rep3_setup` built for this
/// `N`, reused run to run.
fn run_rep3(
    program: &Program<Fr>,
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
                    let mut driver = Rep3Driver::new(net, state);
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

        let mut rng = thread_rng();
        let shares: Vec<[Rep3PrimeFieldShare<Fr>; 3]> = program
            .input_domains
            .iter()
            .zip(&values)
            .filter(|(bank, _)| matches!(bank, Bank::Shared))
            .map(|(_, &v)| share_field_element(v, &mut rng))
            .collect();

        let (networks, mut states) = rep3_setup();
        group.bench_with_input(BenchmarkId::new("rep3", n), &(), |b, ()| {
            b.iter(|| run_rep3(&program, &values, &shares, &networks, &mut states));
        });
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
