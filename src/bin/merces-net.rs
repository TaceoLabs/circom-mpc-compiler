//! Runs rep3 witness extension over a genuine TLS network - one process per party, started
//! separately (potentially on different machines). Unlike `examples/merces.rs`, which runs all
//! three parties in one process over an in-process `LocalNetwork`, this binary is the tool for
//! measuring real network behavior: connection and correlated-randomness setup happen once and are
//! excluded from every timed run, while each reported total-cost run includes fresh program-wide
//! Poseidon2 preprocessing followed by online witness extension.
//!
//! Sweeps a set of batch sizes (`--batches`, default `1,8,16,32`) in one process, so the network
//! and rep3 randomness setup is paid once for the whole sweep rather than once per size. Inputs are
//! seeded-random field elements, not real merces protocol values - fine here, since this binary
//! only measures witness-extension time and never proves or checks a `===` constraint.
//!
//! ```text
//! # on each node (party N gets its own party config, e.g. configs/partyN.toml)
//! cargo run --release --features net --bin merces-net -- \
//!     --config configs/party0.toml --opt 1 --runs 5 --batches 1,8,16,32
//! ```
//!
//! The party config TOML and the TLS material it points at (a PKCS#8 private key and one
//! certificate per party, indexed by id) are produced outside this repo - see
//! `scripts/run-merces-net.sh` for the shape it expects. `dns_name` in `[[network.parties]]`
//! doubles as the TLS server name (`ServerName::try_from` in `mpc_net::tls`), so a config that
//! addresses parties by bare IP needs certs with a matching IP SAN. Example TOML:
//!
//! ```toml
//! [network]
//! my_id = 0
//! bind_addr = "0.0.0.0:10000"
//! timeout = "30min"
//! connect_timeout = "60s"
//!
//! [network.tls]
//! key = "./data/key0.der"
//! certs = ["./data/cert0.der", "./data/cert1.der", "./data/cert2.der"]
//!
//! [[network.parties]]
//! id = 0
//! dns_name = "127.0.0.1:10000"
//! # ... id = 1, id = 2
//! ```

use std::io::Read as _;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use ark_bn254::{Bn254, Fr};
use ark_ff::UniformRand;
use clap::Parser;
use circom_mpc_compiler::vm::counting_net::CountingNet;
use circom_mpc_compiler::vm::driver::rep3::Rep3Driver;
use circom_mpc_compiler::vm::program::Bank;
use circom_mpc_compiler::vm::{codegen, Machine};
use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig, OptLevel};
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::rep3::{share_field_element, Rep3PrimeFieldShare, Rep3State};
use mpc_net::bytes::Bytes;
use mpc_net::config::{NetworkConfig, NetworkConfigFile};
use mpc_net::tls::TlsNetwork;
use mpc_net::Network;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::Deserialize;

#[derive(Parser)]
#[command(about = "Real-network rep3 witness extension, one process per party")]
struct Cli {
    /// Path to this party's network config TOML (its `my_id` says which party it is).
    #[arg(long)]
    config: PathBuf,
    /// Batch sizes to sweep, e.g. `--batches 1,8,16,32`. Each `N` compiles
    /// `circuits/merces/main/transfer_arity4_batchN.circom`.
    #[arg(long, value_delimiter = ',', default_values_t = vec![1usize, 8, 16, 32])]
    batches: Vec<usize>,
    /// Compiler optimization level: 0, 1, or 2.
    #[arg(long, default_value_t = 1)]
    opt: u8,
    /// Number of timed total-cost witness-extension runs, per batch size.
    #[arg(long, default_value_t = 5)]
    runs: usize,
    /// RNG seed for generating inputs and splitting them into rep3 shares. Must match across all
    /// three parties - it is what makes every node derive the same share triples without
    /// exchanging them.
    #[arg(long, default_value_t = 0)]
    seed: u64,
}

fn install_tracing() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{fmt, EnvFilter};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(false).with_line_number(false))
        .init();
}

fn opt_level(n: u8) -> eyre::Result<OptLevel> {
    match n {
        0 => Ok(OptLevel::O0),
        1 => Ok(OptLevel::O1),
        2 => Ok(OptLevel::O2),
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

/// Timing summary for one batch size.
struct BatchResult {
    n: usize,
    min: Duration,
    median: Duration,
    max: Duration,
    rounds: usize,
    sent: usize,
    recv: usize,
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
    // shared across every batch size in the sweep - entirely outside every timed region below.
    let t = Instant::now();
    let net = TlsNetwork::new(network_config)?;
    barrier(&net)?;
    warmup(&net, 1 << 20)?;
    let mut state = Rep3State::new(&net, A2BType::default())?;
    barrier(&net)?;
    println!("party {my_id}: network established + warmed up in {:.2?}", t.elapsed());
    let net = CountingNet::new(net);

    let mut results = Vec::with_capacity(args.batches.len());
    for n in &args.batches {
        results.push(bench_batch(my_id, &net, &mut state, *n, opt, args.runs, args.seed)?);
    }

    println!("party {my_id}: summary");
    println!("party {my_id}: {:>6}  {:>10}  {:>10}  {:>10}  {:>10}  {:>12}  {:>12}", "N", "min", "median", "max", "total rnds", "total sent", "total recv");
    for r in &results {
        println!(
            "party {my_id}: {:>6}  {:>10.2?}  {:>10.2?}  {:>10.2?}  {:>10}  {:>12}  {:>12}",
            r.n, r.min, r.median, r.max, r.rounds, r.sent, r.recv
        );
    }

    Ok(())
}

/// Compiles `transfer_arity4_batch{n}.circom`, runs `runs` timed total-cost witness extensions
/// (fresh Poseidon2 preprocessing plus online execution) against seeded-random dummy inputs, and
/// returns the timing/traffic summary.
fn bench_batch(
    my_id: usize,
    net: &CountingNet<TlsNetwork>,
    state: &mut Rep3State,
    n: usize,
    opt: OptLevel,
    runs: usize,
    seed: u64,
) -> eyre::Result<BatchResult> {
    eyre::ensure!(runs > 0, "--runs must be > 0");

    let root = env!("CARGO_MANIFEST_DIR");
    let mut config = CompilerConfig::default();
    config.opt_level = opt;
    config.link_library.push(format!("{root}/circuits/libs/").into());
    config.link_library.push(format!("{root}/circuits/merces/").into());
    config.mpc_public_inputs = circom_mpc_compiler::fixtures::merces_mpc_public_inputs();
    let path = format!("{root}/circuits/merces/main/transfer_arity4_batch{n}.circom");

    println!("party {my_id}: batch {n}: circuit {path} (opt={opt:?})");
    let t = Instant::now();
    let graph = CoCircomCompiler::<Bn254>::parse(path, config)?;
    let summary = graph.mpc_summary();
    println!("party {my_id}: batch {n}: parse   {:.2?}", t.elapsed());
    println!(
        "party {my_id}: batch {n}:   signals={} inputs={} outputs={} rounds={} precompute: {} sites -> {} driver calls",
        graph.num_signals,
        graph.num_inputs,
        graph.num_outputs,
        summary.rounds,
        summary.precompute_sites,
        summary.precompute_batches,
    );

    let t = Instant::now();
    let program = codegen::compile(&graph)?;
    println!(
        "party {my_id}: batch {n}: codegen {:.2?}  ({} instructions, slots public={} shared={} local={})",
        t.elapsed(),
        program.instructions.len(),
        program.slots.public,
        program.slots.shared,
        program.slots.local,
    );

    // Dummy inputs: this binary only measures total per-run witness-extension cost (fresh
    // Poseidon2 preprocessing plus online execution), and rep3's cost is value-independent, so
    // seeded-random field elements stand in for real merces protocol values. Every party derives
    // the same share triples from the same seed, then keeps only its own index - no share
    // distribution, no extra network round.
    let mut rng = StdRng::seed_from_u64(seed);
    let values: Vec<Fr> = (0..program.num_inputs).map(|_| Fr::rand(&mut rng)).collect();
    let shares: Vec<[Rep3PrimeFieldShare<Fr>; 3]> = program
        .input_domains
        .iter()
        .zip(&values)
        .filter(|(bank, _)| matches!(bank, Bank::Shared))
        .map(|(_, &v)| share_field_element(v, &mut rng))
        .collect();
    let mut next = 0;
    let inputs = program.classify_inputs(&values, |_v| {
        let s = shares[next][my_id];
        next += 1;
        s
    });

    // A representative single run's rounds/bytes for the summary table - reported alongside every
    // run's own line below, and not summed across `runs` since they don't vary run to run.
    let mut last_rounds = 0;
    let mut last_sent = 0;
    let mut last_recv = 0;

    let mut wall_times = Vec::with_capacity(runs);
    for i in 0..runs {
        barrier(net)?;
        let stats_before = net.get_connection_stats();
        let rounds_before = net.rounds();
        let t = Instant::now();
        let mut driver = Rep3Driver::<Fr, _>::new_for_run(net, state, &program)?;
        Machine::run(&program, &mut driver, &inputs)?;
        let elapsed = t.elapsed();
        net.flush()?;
        let rounds = net.rounds() - rounds_before;
        let stats_after = net.get_connection_stats();
        let diff = stats_after.get_diff_to(&stats_before);
        let (sent, recv) = diff.values().fold((0, 0), |(s, r), &(a, b)| (s + a, r + b));
        println!(
            "party {my_id}: batch {n}: total-cost run {i}: {:.2?}  rounds={rounds} bytes sent={sent} recv={recv}",
            elapsed
        );
        wall_times.push(elapsed);
        last_rounds = rounds;
        last_sent = sent;
        last_recv = recv;
        std::thread::sleep(Duration::from_millis(200));
    }

    wall_times.sort();
    let min = wall_times[0];
    let max = wall_times[wall_times.len() - 1];
    let median = wall_times[wall_times.len() / 2];
    println!(
        "party {my_id}: batch {n}: total-cost witness extension over {} runs: min={min:.2?} median={median:.2?} max={max:.2?}",
        wall_times.len()
    );

    Ok(BatchResult {
        n,
        min,
        median,
        max,
        rounds: last_rounds,
        sent: last_sent,
        recv: last_recv,
    })
}
