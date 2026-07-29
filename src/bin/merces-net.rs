//! Runs rep3 witness extension over a genuine TLS network - one process per party, started
//! separately (potentially on different machines). Unlike `examples/merces.rs`, which runs all
//! three parties in one process over an in-process `LocalNetwork`, this binary is the tool for
//! measuring real network behavior: connection and correlated-randomness setup happen once and are
//! excluded from every timed run, so `--runs` reports witness-extension time alone.
//!
//! ```text
//! # on each node (party N gets its own party config, e.g. configs/partyN.toml)
//! cargo run --release --features net --bin merces-net -- \
//!     --config configs/party0.toml --opt 1 --runs 5 --check
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
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use clap::Parser;
use circom_mpc_compiler::vm::counting_net::CountingNet;
use circom_mpc_compiler::vm::driver::plain::PlainDriver;
use circom_mpc_compiler::vm::driver::rep3::Rep3Driver;
use circom_mpc_compiler::vm::program::Bank;
use circom_mpc_compiler::vm::{codegen, Machine, Program};
use circom_mpc_compiler::{fixtures, CoCircomCompiler, CompilerConfig, OptLevel};
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::rep3::{
    combine_field_elements, share_field_element, Rep3PrimeFieldShare, Rep3State,
};
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
    /// Merces server main to compile.
    #[arg(long, default_value = "transfer_arity4_batch8")]
    main: String,
    /// Scenario name (see `circom_mpc_compiler::fixtures::scenarios`).
    #[arg(long, default_value = "full_batch")]
    scenario: String,
    /// Compiler optimization level: 0, 1, or 2.
    #[arg(long, default_value_t = 1)]
    opt: u8,
    /// Number of timed witness-extension runs.
    #[arg(long, default_value_t = 5)]
    runs: usize,
    /// RNG seed for splitting inputs into rep3 shares. Must match across all three parties -
    /// it is what makes every node derive the same share triples without exchanging them.
    #[arg(long, default_value_t = 0)]
    seed: u64,
    /// After timing, reconstruct the witness across parties and compare against the plain driver.
    #[arg(long)]
    check: bool,
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

    let root = env!("CARGO_MANIFEST_DIR");
    let mut config = CompilerConfig::default();
    config.opt_level = opt_level(args.opt)?;
    config.link_library.push(format!("{root}/circuits/libs/").into());
    config.link_library.push(format!("{root}/circuits/merces/").into());
    let path = format!("{root}/circuits/merces/main/{}.circom", args.main);

    println!("party {my_id}: circuit {path} (opt={:?})", config.opt_level);
    let t = Instant::now();
    let graph = CoCircomCompiler::<Bn254>::parse(path, config)?;
    let summary = graph.mpc_summary();
    println!("party {my_id}: parse   {:.2?}", t.elapsed());
    println!(
        "party {my_id}:   signals={} inputs={} outputs={} rounds={} precompute: {} sites -> {} driver calls",
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
        "party {my_id}: codegen {:.2?}  ({} instructions, slots public={} shared={} local={})",
        t.elapsed(),
        program.instructions.len(),
        program.slots.public,
        program.slots.shared,
        program.slots.local,
    );

    let s = fixtures::scenario(&args.main, &args.scenario)?;
    let values = s.values::<Fr>(&graph.input_list)?;

    // Every party derives the same share triples from the same seed and the same plaintext
    // values, then keeps only its own index - no share distribution, no extra network round.
    let mut rng = StdRng::seed_from_u64(args.seed);
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

    // Network establishment, the rep3 correlated-randomness handshake, and a warmup round trip
    // all happen here, entirely outside the timed region below.
    let t = Instant::now();
    let net = TlsNetwork::new(network_config)?;
    barrier(&net)?;
    warmup(&net, 1 << 20)?;
    let mut state = Rep3State::new(&net, A2BType::default())?;
    barrier(&net)?;
    println!("party {my_id}: network established + warmed up in {:.2?}", t.elapsed());

    let net = CountingNet::new(net);
    let mut wall_times = Vec::with_capacity(args.runs);
    let mut last_witness = None;
    for i in 0..args.runs {
        barrier(&net)?;
        let stats_before = net.get_connection_stats();
        let rounds_before = net.rounds();
        let t = Instant::now();
        let mut driver = Rep3Driver::new(&net, &mut state);
        let witness = Machine::run(&program, &mut driver, &inputs)?;
        let elapsed = t.elapsed();
        net.flush()?;
        let rounds = net.rounds() - rounds_before;
        let stats_after = net.get_connection_stats();
        let diff = stats_after.get_diff_to(&stats_before);
        let (sent, recv) = diff.values().fold((0, 0), |(s, r), &(a, b)| (s + a, r + b));
        println!(
            "party {my_id}: run {i}: {:.2?}  rounds={rounds} bytes sent={sent} recv={recv}",
            elapsed
        );
        wall_times.push(elapsed);
        last_witness = Some(witness);
        std::thread::sleep(Duration::from_millis(200));
    }

    wall_times.sort();
    if !wall_times.is_empty() {
        let min = wall_times[0];
        let max = wall_times[wall_times.len() - 1];
        let median = wall_times[wall_times.len() / 2];
        println!(
            "party {my_id}: witness extension over {} runs: min={min:.2?} median={median:.2?} max={max:.2?}",
            wall_times.len()
        );
    }

    if args.check {
        check(my_id, &net, &program, &values, last_witness.expect("--runs must be > 0 to --check"))?;
    }

    Ok(())
}

/// Reconstructs the witness across all three parties and compares it against a local plain-driver
/// run - the correctness oracle for a wrong seeded split or a wrong `my_id`. Run only after all
/// timed runs, so its network traffic never pollutes a measurement.
fn check(
    my_id: usize,
    net: &CountingNet<TlsNetwork>,
    program: &Program<Fr>,
    values: &[Fr],
    witness: Vec<Rep3PrimeFieldShare<Fr>>,
) -> eyre::Result<()> {
    barrier(net)?;
    let shares = match my_id {
        0 => {
            let w1 = recv_witness(net, 1)?;
            let w2 = recv_witness(net, 2)?;
            Some((witness, w1, w2))
        }
        _ => {
            send_witness(net, 0, &witness)?;
            None
        }
    };

    if let Some((w0, w1, w2)) = shares {
        let reconstructed = combine_field_elements(&w0, &w1, &w2);
        let inputs = program.classify_inputs(values, |v| v);
        let mut plain = PlainDriver;
        let expected = Machine::run(program, &mut plain, &inputs)?;
        if reconstructed == expected {
            println!("party 0: --check passed: reconstructed witness matches the plain driver");
        } else {
            eyre::bail!("--check failed: rep3 and plain witnesses disagree");
        }
    }
    Ok(())
}

fn send_witness(net: &impl Network, to: usize, witness: &[Rep3PrimeFieldShare<Fr>]) -> eyre::Result<()> {
    let mut buf = Vec::new();
    witness.serialize_compressed(&mut buf)?;
    net.send(to, Bytes::from(buf))?;
    net.flush()
}

fn recv_witness(net: &impl Network, from: usize) -> eyre::Result<Vec<Rep3PrimeFieldShare<Fr>>> {
    let buf = net.recv(from)?;
    Ok(Vec::<Rep3PrimeFieldShare<Fr>>::deserialize_compressed(&buf[..])?)
}
