//! Witness-extension-only benchmark over a genuine TLS network - one process per party, started
//! separately (potentially on different machines). This is the binary `taceo-benchmarks` drives
//! (see `benchmarks/merces-wit-vm/config.yaml` there): its CLI is `--config <party toml>` plus
//! free-form flags, its output is a free-form stdout table, and its exit code is ignored - nothing
//! about its interface is parsed by the harness.
//!
//! Cases come from `circom_mpc_compiler_tests::cases`; add a benchmark there, not here. Each case
//! is compiled exactly once and then run `--runs` times - connection setup, the rep3
//! correlated-randomness handshake, and every case's compile happen once, entirely outside every
//! timed region below. Scope is witness extension only, no proving: `Machine::run` /
//! `run_with_precomputation` is what's measured, nothing past it.
//!
//! Inputs are seeded-random field elements, not real protocol values - witness extension's cost is
//! value-independent, and this binary never proves. Every party derives the same field elements
//! from the same `--seed`, then keeps only its own share - no share distribution round.
//!
//! ```text
//! # on each node (party N gets its own party config, e.g. configs/partyN.toml)
//! cargo run --release -p circom-mpc-compiler-tests --no-default-features --features tls \
//!     --bin witext-bench -- \
//!     --config configs/party0.toml --all-cases --batches 8,32,50,100 --opt 2 --runs 5
//! ```
//!
//! The party config TOML and the TLS material it points at are produced outside this repo - see
//! `scripts/run-witext-bench.sh` for the expected shape. `dns_name` in `[[network.parties]]`
//! doubles as the TLS server name, so a config that addresses parties by bare IP needs certs with a
//! matching IP SAN.

use std::{
    io::Read as _,
    path::PathBuf,
    time::{Duration, Instant},
};

use ark_bn254::Fr;
use ark_ff::UniformRand;
use circom_mpc_compiler_tests::{
    cases::{self, Case},
    fixtures::precomputation,
};
use circom_mpc_program::Program;
use circom_mpc_vm::{Machine, counting_net::CountingNet, driver::rep3::Rep3Driver};
use clap::Parser;
use mpc_core::protocols::rep3::{
    Rep3PrimeFieldShare, Rep3State, conversion::A2BType, share_field_element,
};
use mpc_net::{
    Network,
    bytes::Bytes,
    config::{NetworkConfig, NetworkConfigFile},
    tls::TlsNetwork,
};
use rand::{SeedableRng, rngs::StdRng};
use serde::Deserialize;

#[derive(Parser)]
#[command(about = "Real-network witness-extension benchmark over the case registry")]
struct Cli {
    /// Path to this party's network config TOML (its `my_id` says which party it is).
    #[arg(long)]
    config: PathBuf,
    /// Case-name substring filter into `circom_mpc_compiler_tests::cases`, e.g. `merces`, `micro`,
    /// `lib/sha256`. Matches every case containing the substring. Defaults to `merces` unless
    /// `--all-cases` is set.
    #[arg(long, conflicts_with = "all_cases")]
    cases: Option<String>,
    /// Run every registered case, including cases the current compiler may report as unsupported.
    #[arg(long)]
    all_cases: bool,
    /// Merces batch sizes to sweep - only affects `merces/batch<N>` cases; ignored otherwise.
    #[arg(long, value_delimiter = ',', default_values_t = vec![8usize, 32, 50, 100])]
    batches: Vec<usize>,
    /// Compiler optimization level: 0, 1, or 2.
    #[arg(long, default_value_t = 2)]
    opt: u8,
    /// Number of timed runs, per case.
    #[arg(long, default_value_t = 5)]
    runs: usize,
    /// RNG seed for generating inputs and splitting them into rep3 shares. Must match across all
    /// three parties - it is what makes every node derive the same share triples without
    /// exchanging them.
    #[arg(long, default_value_t = 0)]
    seed: u64,
}

fn install_tracing() {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(false).with_line_number(false))
        .init();
}

fn opt_level(n: u8) -> eyre::Result<circom_mpc_compiler::OptLevel> {
    match n {
        0 => Ok(circom_mpc_compiler::OptLevel::O0),
        1 => Ok(circom_mpc_compiler::OptLevel::O1),
        2 => Ok(circom_mpc_compiler::OptLevel::O2),
        _ => eyre::bail!("--opt must be 0, 1, or 2 (there is no O3)"),
    }
}

fn main() -> eyre::Result<()> {
    install_tracing();
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| eyre::eyre!("could not install default rustls crypto provider"))?;

    run(Cli::parse())
}

/// Sends and receives one byte to/from each peer, so no party proceeds ahead of the others -
/// `Network` has no barrier of its own.
fn barrier(net: &impl Network) -> eyre::Result<()> {
    let my_id = net.id();
    for id in 0..3 {
        if id != my_id {
            net.send(id, Bytes::from_static(&[0]))?;
        }
    }
    for id in 0..3 {
        if id != my_id {
            net.recv(id)?;
        }
    }
    net.flush()
}

/// Sends and receives `bytes` to/from each peer, to warm up TCP buffers before timing starts.
fn warmup(net: &impl Network, bytes: usize) -> eyre::Result<()> {
    let my_id = net.id();
    let payload = Bytes::from(vec![0u8; bytes]);
    for id in 0..3 {
        if id != my_id {
            net.send(id, payload.clone())?;
        }
    }
    for id in 0..3 {
        if id != my_id {
            net.recv(id)?;
        }
    }
    net.flush()
}

#[derive(Deserialize)]
struct FileConfig {
    network: NetworkConfigFile,
}

/// One run's timing + traffic.
#[derive(Clone, Copy, Default)]
struct RunStats {
    elapsed: Duration,
    rounds: usize,
    sent: usize,
    recv: usize,
}

/// Barriers, then snapshots round/byte counters right before timing starts - the barrier's own
/// round and bytes land before the snapshot, so they are excluded.
fn run_begin(
    net: &CountingNet<TlsNetwork>,
) -> eyre::Result<(Instant, mpc_net::ConnectionStats, usize)> {
    barrier(net)?;
    Ok((Instant::now(), net.get_connection_stats(), net.rounds()))
}

/// Stops the clock, flushes, and diffs the counters `run_begin` snapshotted.
fn run_end(
    net: &CountingNet<TlsNetwork>,
    start: Instant,
    stats_before: &mpc_net::ConnectionStats,
    rounds_before: usize,
) -> eyre::Result<RunStats> {
    let elapsed = start.elapsed();
    net.flush()?;
    let rounds = net.rounds() - rounds_before;
    let diff = net.get_connection_stats().get_diff_to(stats_before);
    let (sent, recv) = diff.values().fold((0, 0), |(s, r), &(a, b)| (s + a, r + b));
    Ok(RunStats {
        elapsed,
        rounds,
        sent,
        recv,
    })
}

/// One case's samples across its runs. `rounds`/`sent`/`recv` are the last run's - they don't vary
/// run to run, so summing would only inflate the summary table for no reason.
#[derive(Default)]
struct Samples {
    times: Vec<Duration>,
    rounds: usize,
    sent: usize,
    recv: usize,
}

impl Samples {
    fn push(&mut self, s: RunStats) {
        self.times.push(s.elapsed);
        self.rounds = s.rounds;
        self.sent = s.sent;
        self.recv = s.recv;
    }

    fn min_median_max(&self) -> (Duration, Duration, Duration) {
        let mut sorted = self.times.clone();
        sorted.sort_unstable();
        (
            sorted[0],
            sorted[sorted.len() / 2],
            sorted[sorted.len() - 1],
        )
    }
}

fn run(args: Cli) -> eyre::Result<()> {
    let mut toml_src = String::new();
    std::fs::File::open(&args.config)
        .map_err(|e| eyre::eyre!("opening {}: {e}", args.config.display()))?
        .read_to_string(&mut toml_src)?;
    let file: FileConfig = toml::from_str(&toml_src)
        .map_err(|e| eyre::eyre!("parsing {}: {e}", args.config.display()))?;
    let network_config = NetworkConfig::try_from(file.network)?;
    eyre::ensure!(
        network_config.tls.is_some(),
        "{} has no [network.tls] table; TlsNetwork needs `key` and `certs`",
        args.config.display(),
    );
    let my_id = network_config.my_id;
    let opt = opt_level(args.opt)?;

    // Network establishment and the rep3 correlated-randomness handshake happen once, up front,
    // shared across every case - entirely outside every timed region below.
    let t = Instant::now();
    let net = TlsNetwork::new(network_config)?;
    barrier(&net)?;
    warmup(&net, 1 << 20)?;
    let mut state = Rep3State::new(&net, A2BType::default())?;
    barrier(&net)?;
    println!(
        "party {my_id}: network established + warmed up in {:.2?}",
        t.elapsed()
    );
    let net = CountingNet::new(net);

    let filter = if args.all_cases {
        None
    } else {
        Some(args.cases.as_deref().unwrap_or("merces"))
    };
    let cases = cases::select(filter);
    eyre::ensure!(
        !cases.is_empty(),
        "no registered case name contains {:?}",
        filter
    );

    let mut results = Vec::with_capacity(cases.len());
    for case in &cases {
        // `--batches` only shapes merces cases; a case for a batch size not asked for is skipped.
        if case.name.starts_with("merces/batch") {
            let n: usize = case.name["merces/batch".len()..]
                .parse()
                .unwrap_or_else(|e| panic!("{}: malformed merces batch case name: {e}", case.name));
            if !args.batches.contains(&n) {
                continue;
            }
        }
        let mut case = case.clone();
        case.config.opt_level = opt;
        match bench_case(my_id, &net, &mut state, &case, args.runs, args.seed) {
            Ok(result) => results.push(result),
            Err(e) => println!("party {my_id}: skipping {}: {e}", case.name),
        }
    }

    println!("party {my_id}: summary (rounds/bytes from the last run of each case)");
    println!(
        "party {my_id}: {:<24}  {:>10}  {:>10}  {:>10}  {:>10}  {:>12}  {:>12}",
        "case", "min", "median", "max", "rounds", "sent", "recv"
    );
    for (name, samples) in &results {
        let (min, median, max) = samples.min_median_max();
        println!(
            "party {my_id}: {:<24}  {:>10.2?}  {:>10.2?}  {:>10.2?}  {:>10}  {:>12}  {:>12}",
            name, min, median, max, samples.rounds, samples.sent, samples.recv
        );
    }

    Ok(())
}

/// Compiles `case` once, then runs `runs` timed witness-extension rounds (host-precomputing any
/// `TACEO_PRECOMPUTATION_Poseidon2` sites first, inside the same timed run) against seeded-random
/// dummy inputs, returning the timing/traffic samples.
fn bench_case(
    my_id: usize,
    net: &CountingNet<TlsNetwork>,
    state: &mut Rep3State,
    case: &Case,
    runs: usize,
    seed: u64,
) -> eyre::Result<(String, Samples)> {
    eyre::ensure!(runs > 0, "--runs must be > 0");

    let t = Instant::now();
    let program: Program = cases::compile(case)?;
    println!(
        "party {my_id}: {}: compiled in {:.2?}  (instructions={} inputs={} witness_values={} \
         rounds={} gadget_sites={} precomputed_batches={})",
        case.name,
        t.elapsed(),
        program.statistics().instructions,
        program.statistics().inputs,
        program.statistics().witness_values,
        program.statistics().multiplication_rounds,
        program.statistics().gadget_sites,
        program.statistics().precomputed_batches,
    );

    // Dummy inputs, once per case: witness extension's cost is value-independent, so seeded-random
    // field elements stand in for real values. Every party derives the same share triples from the
    // same seed, then keeps only its own index - no share distribution round.
    let mut rng = StdRng::seed_from_u64(seed);
    let values: Vec<Fr> = (0..program.statistics().inputs)
        .map(|_| Fr::rand(&mut rng))
        .collect();
    let shares: Vec<[Rep3PrimeFieldShare<Fr>; 3]> = program
        .input_domains()
        .iter()
        .zip(&values)
        .filter(|(bank, _)| matches!(bank, circom_mpc_program::Bank::Shared))
        .map(|(_, &v)| share_field_element(v, &mut rng))
        .collect();
    let mut next = 0;
    let inputs = program.classify_inputs(&values, |_v| {
        let s = shares[next][my_id];
        next += 1;
        s
    })?;

    let site_counts = precomputation::site_counts(&program)?;
    let total_sites: usize = site_counts.iter().sum();
    // Drawn once per case, right after the circuit inputs, so a rerun with the same `--seed`
    // reproduces the same commit states too - not load-bearing for correctness (rep3's cost is
    // value-independent), just for a stable, reviewable trace.
    let commit_triples: Vec<[Rep3PrimeFieldShare<Fr>; 3]> = (0..total_sites * 3)
        .map(|_| share_field_element(Fr::rand(&mut rng), &mut rng))
        .collect();

    let mut samples = Samples::default();
    for i in 0..runs {
        let (begin, stats0, rounds0) = run_begin(net)?;

        let commit_states = precomputation::commit_states_for_party(&commit_triples, my_id);
        let traces = precomputation::rep3(total_sites, &commit_states, net, state)?;
        let precomputation = precomputation::queue(&site_counts, traces)?;

        let mut driver = Rep3Driver::new_for_run(net, state, &program)?;
        let witness =
            Machine::run_with_precomputation(&program, &mut driver, &inputs, precomputation)?;
        drop(witness);
        drop(driver);

        let stats = run_end(net, begin, &stats0, rounds0)?;
        println!(
            "party {my_id}: {}: run {i}: {:.2?} (rounds={})",
            case.name, stats.elapsed, stats.rounds
        );
        samples.push(stats);

        std::thread::sleep(Duration::from_millis(200));
    }

    println!("party {my_id}: {}: {runs} runs done", case.name);
    Ok((case.name.clone(), samples))
}
