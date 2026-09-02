//! Merces precomputation and witness extension, plain versus rep3, swept over the transaction
//! batch size `N`. Two groups, mirroring the real merces node's `Engine::execute_batch` (see
//! `~/repos/merces`'s `crates/merces-node/src/engine.rs`): `merces_precompute` times the host-side
//! Poseidon2 commit-batch precomputation (`Commit1`/`Commit2` in
//! `circuits/merces/oblivious_vector/hash.circom`, wrapped `TACEO_PRECOMPUTATION_Poseidon2`), and
//! `merces_witness` times witness extension with those traces inlined via
//! `Machine::run_with_precomputation`. Throughput is defined over `N` (transactions per run), so
//! criterion's `thrpt` column reads as transactions/second across batch sizes.
//!
//! Inputs (both the circuit inputs and the commit-site precomputation states) are seeded-random
//! field elements, not real protocol values - this bench never proves, and rep3's cost is
//! value-independent. This bench does not measure proving; see `src/bin/merces-net.rs` for that.
//!
//! Each party's `LocalNetwork` and `Rep3State` are built once per `N` and reused across timed
//! iterations (unlike `witness_extension.rs`, which models a fresh connection per run).

use ark_bn254::Fr;
use ark_ff::UniformRand;
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::SeedableRng;
use rand::rngs::StdRng;

use circom_mpc_compiler::CoCircomCompiler;
use circom_mpc_compiler::codegen;
use circom_mpc_compiler_tests::fixtures::{
    merces_config, merces_main_path, precomputation, rep3::share_inputs,
};
use circom_mpc_vm::driver::plain::PlainDriver;
use circom_mpc_vm::driver::rep3::Rep3Driver;
use circom_mpc_vm::{GadgetPrecomputation, Machine, Program, SiteTrace};
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::rep3::{Rep3PrimeFieldShare, Rep3State, share_field_element};
use mpc_net::local::LocalNetwork;

/// Transaction counts to sweep - matches `circuits/merces/main/transfer_arity4_batch{N}.circom` and
/// `src/bin/merces-net.rs`'s default `--batches`.
const BATCHES: [usize; 4] = [1, 8, 16, 32];

/// Fixed so every run (and every party, since all three derive the same values then keep only their
/// own share) sees the same inputs.
const SEED: u64 = 0;

/// Everything reusable across one batch size's iterations: the compiled program, its seeded
/// circuit inputs, its host-precomputed batches' site counts (in consumption order - see
/// `Program::precomputed_batches`), and rep3 share triples for both the circuit inputs and the
/// commit-site precomputation states.
struct Prepared {
    program: Program,
    values: Vec<Fr>,
    site_counts: Vec<usize>,
    input_shares: Vec<[Rep3PrimeFieldShare<Fr>; 3]>,
    commit_triples: Vec<[Rep3PrimeFieldShare<Fr>; 3]>,
}

/// Compiles `transfer_arity4_batch{n}.circom` and builds its seeded-random inputs, printing the
/// round shape so a timing can be read against it. Compilation is deliberately outside the measured
/// closure - parsing batch32 alone takes seconds.
fn prepare(n: usize) -> Prepared {
    let path = merces_main_path(&format!("transfer_arity4_batch{n}"));
    let graph =
        CoCircomCompiler::parse(path, merces_config()).unwrap_or_else(|e| panic!("batch{n}: {e}"));
    let summary = graph.mpc_summary();
    let mut rng = StdRng::seed_from_u64(SEED);
    let values: Vec<Fr> = (0..graph.num_inputs()).map(|_| Fr::rand(&mut rng)).collect();
    let program = codegen::compile(&graph).unwrap_or_else(|e| panic!("batch{n}: {e}"));
    println!(
        "batch{n:<3} rounds={:3} reshare_elements={:6} max_slots={:5} sites={:4} batches={:3} instrs={:6} precomputed_batches={:3}",
        summary.rounds,
        summary.reshare_elements,
        summary.max_slots_per_round.unwrap_or(0),
        summary.gadget_sites,
        summary.gadget_batches,
        program.statistics().instructions,
        summary.precomputed_batches,
    );

    let input_shares = share_inputs(&program, &values);
    let site_counts = precomputation::site_counts(&program).unwrap_or_else(|e| panic!("batch{n}: {e}"));
    let total_sites: usize = site_counts.iter().sum();
    // Drawn from the same rng, right after the circuit inputs, so a rerun with the same SEED
    // reproduces the same commit states too - not load-bearing for correctness (rep3's cost is
    // value-independent), just for a stable, reviewable trace.
    let commit_triples: Vec<[Rep3PrimeFieldShare<Fr>; 3]> = (0..total_sites * 3)
        .map(|_| share_field_element(Fr::rand(&mut rng), &mut rng))
        .collect();

    Prepared {
        program,
        values,
        site_counts,
        input_shares,
        commit_triples,
    }
}

fn precompute_plain(p: &Prepared, rng: &mut StdRng) -> GadgetPrecomputation<Fr> {
    precomputation::plain(&p.program, rng).expect("plain precompute")
}

/// Builds the three rep3 parties' network and correlated-randomness state once, for reuse across
/// every timed call at this `N` - the handshake needs the parties concurrently, so it runs in its
/// own scope rather than the caller's.
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

/// One 3-party precomputation run: each party's own `Poseidon2Service` over its commit-site
/// shares, opening the commitments - mirrors `Engine::commit_batch`. Returns each party's traces,
/// flat and site-major, for `witext_rep3` to queue up.
fn precompute_rep3(
    p: &Prepared,
    networks: &[LocalNetwork],
    states: &mut [Rep3State],
) -> Vec<Vec<SiteTrace<Rep3PrimeFieldShare<Fr>>>> {
    let total_sites: usize = p.site_counts.iter().sum();
    std::thread::scope(|scope| {
        let handles: Vec<_> = networks
            .iter()
            .zip(states.iter_mut())
            .enumerate()
            .map(|(party, (net, state))| {
                let commit_states =
                    precomputation::commit_states_for_party(&p.commit_triples, party);
                scope.spawn(move || {
                    precomputation::rep3(total_sites, &commit_states, net, state)
                        .expect("rep3 precompute")
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    })
}

fn run_plain(program: &Program, values: &[Fr], queue: GadgetPrecomputation<Fr>) -> Vec<Fr> {
    let inputs = program.classify_inputs(values, |v| v);
    let mut driver = PlainDriver;
    Machine::run_with_precomputation(program, &mut driver, &inputs, queue).expect("plain run")
}

/// One full 3-party total-cost witness extension over the long-lived `networks`/`states`
/// `rep3_setup` built for this `N`, including fresh program-wide Poseidon2 preprocessing (now
/// near-zero: every commit site is precomputed) and the given per-party precomputation queues.
fn run_rep3(
    p: &Prepared,
    networks: &[LocalNetwork],
    states: &mut [Rep3State],
    queues: Vec<GadgetPrecomputation<Rep3PrimeFieldShare<Fr>>>,
) {
    std::thread::scope(|scope| {
        let handles: Vec<_> = networks
            .iter()
            .zip(states.iter_mut())
            .zip(queues)
            .enumerate()
            .map(|(party, ((net, state), queue))| {
                scope.spawn(move || {
                    let mut driver = Rep3Driver::new_for_run(net, state, &p.program).unwrap();
                    let mut next = 0;
                    let inputs = p.program.classify_inputs(&p.values, |_v| {
                        let s = p.input_shares[next][party];
                        next += 1;
                        s
                    });
                    Machine::run_with_precomputation(&p.program, &mut driver, &inputs, queue)
                        .unwrap()
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

    let mut precompute_group = c.benchmark_group("merces_precompute");
    // rep3 over three in-process threads gets far slower as N grows; the default 100 samples would
    // take too long at batch32 (same precedent as benches/compile.rs's slow `parse` group).
    precompute_group.sample_size(10);
    let mut prepared: Vec<Prepared> = BATCHES.into_iter().map(prepare).collect();

    for (i, n) in BATCHES.into_iter().enumerate() {
        let p = &prepared[i];
        precompute_group.throughput(Throughput::Elements(n as u64));

        let mut rng = StdRng::seed_from_u64(SEED ^ 0x506f7332);
        precompute_group.bench_with_input(BenchmarkId::new("plain", n), &(), |b, ()| {
            b.iter(|| precompute_plain(p, &mut rng));
        });

        let (networks, mut states) = rep3_setup();
        precompute_group.bench_with_input(BenchmarkId::new("rep3", n), &(), |b, ()| {
            b.iter(|| precompute_rep3(p, &networks, &mut states));
        });
    }
    precompute_group.finish();

    let mut witness_group = c.benchmark_group("merces_witness");
    witness_group.sample_size(10);

    for (i, n) in BATCHES.into_iter().enumerate() {
        let p = &mut prepared[i];
        witness_group.throughput(Throughput::Elements(n as u64));

        let mut plain_rng = StdRng::seed_from_u64(SEED ^ 0x506f7332);
        witness_group.bench_with_input(BenchmarkId::new("plain", n), &(), |b, ()| {
            b.iter_batched(
                || precompute_plain(p, &mut plain_rng),
                |queue| run_plain(&p.program, &p.values, queue),
                BatchSize::SmallInput,
            );
        });

        let (networks, mut states) = rep3_setup();
        let traces = precompute_rep3(p, &networks, &mut states);
        witness_group.bench_with_input(BenchmarkId::new("rep3_total", n), &(), |b, ()| {
            b.iter_batched(
                || {
                    traces
                        .iter()
                        .cloned()
                        .map(|t| precomputation::queue(&p.site_counts, t).expect("queue"))
                        .collect::<Vec<_>>()
                },
                |queues| run_rep3(p, &networks, &mut states, queues),
                BatchSize::SmallInput,
            );
        });
    }
    witness_group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
