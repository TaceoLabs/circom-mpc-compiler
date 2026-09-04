//! `Machine::run` under `PlainDriver` versus real 3-party `Rep3Driver` over an in-process
//! `LocalNetwork`: the gap between the two series is what MPC actually costs for a given circuit,
//! and the `Program::statistics` line printed per circuit is what makes a number interpretable - a
//! circuit's floor is its round count, not its instruction count. In-process, so rep3 numbers
//! measure protocol work and round structure, not network latency. `rep3_total` is total cost:
//! every measured iteration includes `Rep3State` setup, fresh Poseidon2 preprocessing (both the
//! driver's own and, for cases with `TACEO_PRECOMPUTATION_Poseidon2` sites, the host
//! precomputation), and online execution.
//!
//! Cases come from `circom_mpc_compiler_tests::cases` - see that module to add a benchmark.
//! `BENCH_CASES=<substr>` filters by case name (e.g. `BENCH_CASES=micro`, `BENCH_CASES=merces`); by
//! default every registered case runs except `merces/batch50` and `merces/batch100`, which are
//! minutes-scale in-process (an explicit `BENCH_CASES` filter naming them opts back in - see
//! `src/bin/witext-bench.rs` for a batch-100 sweep over a real network instead). A case that fails
//! to compile with today's compiler is skipped with a printed warning rather than failing the
//! bench - not every registered circuit is supported yet.

use ark_bn254::Fr;
use ark_ff::UniformRand;
use circom_mpc_compiler_tests::{
    cases::{self, Case},
    fixtures::{self, precomputation},
};
use circom_mpc_program::Program;
use circom_mpc_vm::{Machine, driver::plain::PlainDriver};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use mpc_core::protocols::rep3::{Rep3PrimeFieldShare, share_field_element};
use rand::{SeedableRng, rngs::StdRng};

/// Fixed so every run sees the same inputs; witness-extension cost is value-independent, so this
/// is purely for reproducible traces across runs, not correctness.
const SEED: u64 = 0;

/// A compiled case plus everything a bench iteration needs, built once outside every measured
/// closure: seeded-random circuit inputs, their rep3 shares, and (for cases with host-precomputed
/// Poseidon2 sites) shared commit-site precomputation states.
struct Prepared {
    program: Program,
    values: Vec<Fr>,
    input_shares: Vec<[Rep3PrimeFieldShare<Fr>; 3]>,
    commit_triples: Vec<[Rep3PrimeFieldShare<Fr>; 3]>,
}

/// Compiles a case and builds its inputs, printing the round shape so a timing can be read against
/// it. Compilation is deliberately outside the measured closure. Returns `None` (after printing
/// why) for a case today's compiler cannot handle.
fn prepare(case: &Case) -> Option<Prepared> {
    let program = match cases::compile(case) {
        Ok(program) => program,
        Err(e) => {
            println!("skipping {}: {e}", case.name);
            return None;
        }
    };
    let stats = program.statistics();
    let mut rng = StdRng::seed_from_u64(SEED);
    let values: Vec<Fr> = (0..stats.inputs).map(|_| Fr::rand(&mut rng)).collect();
    println!(
        "{:22} rounds={:3} reshare_elements={:6} max_slots={:5} sites={:4} batches={:3} \
         precomputed_batches={:3} instrs={:6}",
        case.name,
        stats.multiplication_rounds,
        stats.multiplication_elements,
        stats.max_slots_per_round.unwrap_or(0),
        stats.gadget_sites,
        stats.gadget_batches,
        stats.precomputed_batches,
        stats.instructions,
    );

    let input_shares = fixtures::rep3::share_inputs(&program, &values);
    let site_counts =
        precomputation::site_counts(&program).unwrap_or_else(|e| panic!("{}: {e}", case.name));
    let total_sites: usize = site_counts.iter().sum();
    // Drawn from the same rng, right after the circuit inputs, so a rerun with SEED reproduces the
    // same commit states too - not load-bearing (rep3's cost is value-independent), just stable.
    let commit_triples: Vec<[Rep3PrimeFieldShare<Fr>; 3]> = (0..total_sites * 3)
        .map(|_| share_field_element(Fr::rand(&mut rng), &mut rng))
        .collect();

    Some(Prepared {
        program,
        values,
        input_shares,
        commit_triples,
    })
}

fn run_plain(p: &Prepared) -> Vec<Fr> {
    let mut rng = StdRng::seed_from_u64(SEED);
    let precomputation = precomputation::plain(&p.program, &mut rng).expect("plain precompute");
    let inputs = p
        .program
        .classify_inputs(&p.values, |v| v)
        .expect("valid inputs");
    let mut driver = PlainDriver;
    Machine::run_with_precomputation(&p.program, &mut driver, &inputs, precomputation)
        .expect("plain run")
}

fn run_rep3(p: &Prepared) -> Vec<Fr> {
    fixtures::rep3::run_witness_with_precomputation(
        &p.program,
        &p.values,
        &p.input_shares,
        &p.commit_triples,
    )
}

fn bench(c: &mut Criterion) {
    println!("\n--- circuit shapes (round count is the floor MPC time cannot go below) ---");
    let filter = std::env::var("BENCH_CASES").ok();
    let prepared: Vec<(Case, Prepared)> = cases::select(filter.as_deref())
        .into_iter()
        // Batch 50/100 are minutes-scale in-process; skip them unless BENCH_CASES asked for them
        // by name.
        .filter(|case| {
            filter.is_some()
                || !(case.name.contains("merces/batch50") || case.name.contains("merces/batch100"))
        })
        .filter_map(|case| prepare(&case).map(|p| (case, p)))
        .collect();
    println!();

    let mut group = c.benchmark_group("witness_extension");
    for (case, prepared) in &prepared {
        // Witness entries produced, so throughput is comparable across very different circuit
        // sizes.
        group.throughput(Throughput::Elements(
            prepared.program.statistics().witness_values as u64,
        ));
        // `lib/sha256_512` is minutes-scale at the default sample size; 10 samples keeps it
        // tractable without losing the signal.
        group.sample_size(if case.name.contains("lib/sha256") {
            10
        } else {
            100
        });

        group.bench_with_input(BenchmarkId::new("plain", &case.name), &(), |b, ()| {
            b.iter(|| run_plain(prepared));
        });
        group.bench_with_input(BenchmarkId::new("rep3_total", &case.name), &(), |b, ()| {
            b.iter(|| run_rep3(prepared));
        });
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
