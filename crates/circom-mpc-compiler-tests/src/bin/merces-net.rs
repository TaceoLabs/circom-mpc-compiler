//! Runs the merces pipeline over a genuine TLS network - one process per party, started
//! separately (potentially on different machines): host-side Poseidon2 commit precomputation,
//! rep3 witness extension, then (for the first `--prove-runs` runs) a collaborative Groth16 proof
//! over the Shamir bridge - the same three phases, over the same network, as the real merces
//! node's `Engine::execute_batch` + `groth16::prove` (see `~/repos/merces`'s
//! `crates/merces-node/src/{engine.rs,services/mpc_worker.rs}`). Unlike `examples/merces.rs` (all
//! three parties in one process over `LocalNetwork`), this measures real network behavior:
//! connection and correlated-randomness setup happen once for the whole `--batches` sweep and are
//! excluded from every timed run.
//!
//! Inputs are seeded-random field elements, not real merces protocol values - rep3 witness
//! extension and Groth16 proving are both value-independent, so the resulting proof does not
//! verify, but the timings are representative. `tests/merces.rs` is what checks correctness
//! against real scenarios and a real proof.
//!
//! ```text
//! # on each node (party N gets its own party config, e.g. configs/partyN.toml)
//! cargo run --release -p circom-mpc-compiler-tests --no-default-features --features tls \
//!     --bin merces-net -- \
//!     --config configs/party0.toml --opt 1 --runs 5 --prove-runs 1 --batches 1,8,16,32
//! ```
//!
//! The party config TOML and the TLS material it points at are produced outside this repo - see
//! `scripts/run-merces-net.sh` for the expected shape. `dns_name` in `[[network.parties]]` doubles
//! as the TLS server name, so a config that addresses parties by bare IP needs certs with a
//! matching IP SAN. Proving a large batch size can take minutes and hold a multi-hundred-MB zkey
//! in memory - size `[network] timeout`/`flush_timeout` generously (minutes, not seconds), or a
//! party that finishes early will time out waiting for the others at the next barrier.

use std::io::Read as _;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use ark_bn254::Fr;
use ark_ff::UniformRand;
use circom_mpc_compiler::codegen;
use circom_mpc_compiler::{CoCircomCompiler, OptLevel};
use circom_mpc_compiler_tests::fixtures;
use circom_mpc_vm::counting_net::CountingNet;
use circom_mpc_vm::driver::rep3::Rep3Driver;
use circom_mpc_vm::program::Bank;
use circom_mpc_vm::{Machine, split_witness};
use clap::Parser;
use co_groth16::{CircomReduction, Rep3CoGroth16};
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::rep3::{Rep3PrimeFieldShare, Rep3State, share_field_element};
use mpc_net::Network;
use mpc_net::bytes::Bytes;
use mpc_net::config::{NetworkConfig, NetworkConfigFile};
use mpc_net::tls::TlsNetwork;
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde::Deserialize;

fn manifest_dir() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../..")
}

#[derive(Parser)]
#[command(about = "Real-network merces pipeline: precompute, witness extension, prove")]
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
    /// Number of timed precompute+witness-extension runs, per batch size.
    #[arg(long, default_value_t = 5)]
    runs: usize,
    /// Of those `--runs`, how many also produce a co-groth16 proof - proving is minutes-scale at
    /// large batch sizes, so this defaults far lower than `--runs`.
    #[arg(long, default_value_t = 1)]
    prove_runs: usize,
    /// Skip proving entirely, even if a zkey is present.
    #[arg(long)]
    no_prove: bool,
    /// Directory holding `transfer_arity4_batch<N>.arks.zkey` files. Defaults to `inputs/zkey`
    /// under the repo root.
    #[arg(long)]
    zkey_dir: Option<PathBuf>,
    /// RNG seed for generating inputs and splitting them into rep3 shares. Must match across all
    /// three parties - it is what makes every node derive the same share triples without
    /// exchanging them.
    #[arg(long, default_value_t = 0)]
    seed: u64,
}

fn install_tracing() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{EnvFilter, fmt};

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

/// AND-reduces a local boolean across the three parties in one round. Used to agree on whether a
/// batch's zkey is present on every party before entering the prove phase - otherwise a party
/// missing it would skip the phase while the others wait at the next barrier forever.
fn agree(net: &impl Network, mine: bool) -> eyre::Result<bool> {
    let my_id = net.id();
    for id in 0..3 {
        if id != my_id {
            net.send(id, Bytes::from_static(if mine { &[1] } else { &[0] }))?;
        }
    }
    let mut all = mine;
    for id in 0..3 {
        if id != my_id {
            all &= net.recv(id)?.first().copied() == Some(1);
        }
    }
    net.flush()?;
    Ok(all)
}

#[derive(Deserialize)]
struct FileConfig {
    network: NetworkConfigFile,
}

/// One phase's timing + traffic for one run.
#[derive(Clone, Copy, Default)]
struct PhaseStats {
    elapsed: Duration,
    rounds: usize,
    sent: usize,
    recv: usize,
}

/// Barriers, then snapshots round/byte counters right before a phase starts - the barrier's own
/// round and bytes land before the snapshot, so they are excluded from the phase.
fn phase_begin(net: &CountingNet<TlsNetwork>) -> eyre::Result<(Instant, mpc_net::ConnectionStats, usize)> {
    barrier(net)?;
    Ok((Instant::now(), net.get_connection_stats(), net.rounds()))
}

/// Stops the clock, flushes, and diffs the counters `phase_begin` snapshotted.
fn phase_end(
    net: &CountingNet<TlsNetwork>,
    start: Instant,
    stats_before: &mpc_net::ConnectionStats,
    rounds_before: usize,
) -> eyre::Result<PhaseStats> {
    let elapsed = start.elapsed();
    net.flush()?;
    let rounds = net.rounds() - rounds_before;
    let diff = net.get_connection_stats().get_diff_to(stats_before);
    let (sent, recv) = diff.values().fold((0, 0), |(s, r), &(a, b)| (s + a, r + b));
    Ok(PhaseStats {
        elapsed,
        rounds,
        sent,
        recv,
    })
}

/// One phase's samples across a batch's runs. `rounds`/`sent`/`recv` are the last run's - they
/// don't vary run to run, so summing would only inflate the summary table for no reason.
#[derive(Default)]
struct PhaseSamples {
    times: Vec<Duration>,
    rounds: usize,
    sent: usize,
    recv: usize,
}

impl PhaseSamples {
    fn push(&mut self, s: PhaseStats) {
        self.times.push(s.elapsed);
        self.rounds = s.rounds;
        self.sent = s.sent;
        self.recv = s.recv;
    }

    fn min_median_max(&self) -> (Duration, Duration, Duration) {
        let mut sorted = self.times.clone();
        sorted.sort();
        (sorted[0], sorted[sorted.len() / 2], sorted[sorted.len() - 1])
    }
}

/// Timing summary for one batch size: precomputation, witness extension, prove (if any zkey was
/// found), and their elementwise total.
struct BatchResult {
    n: usize,
    precompute: PhaseSamples,
    preparation: PhaseSamples,
    witness: PhaseSamples,
    prove: Option<PhaseSamples>,
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
    let zkey_dir = args
        .zkey_dir
        .unwrap_or_else(|| PathBuf::from(format!("{}/inputs/zkey", manifest_dir())));

    // Network establishment and the rep3 correlated-randomness handshake happen once, up front,
    // shared across every batch size in the sweep - entirely outside every timed region below.
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

    let mut results = Vec::with_capacity(args.batches.len());
    for n in &args.batches {
        results.push(bench_batch(
            my_id,
            &net,
            &mut state,
            *n,
            opt,
            args.runs,
            args.prove_runs,
            args.no_prove,
            args.seed,
            &zkey_dir,
        )?);
    }

    println!("party {my_id}: summary (rounds/bytes from the last run of each phase)");
    println!(
        "party {my_id}: {:>6}  {:>10}  {:>10}  {:>10}  {:>10}  {:>10}  {:>12}  {:>12}",
        "N", "phase", "min", "median", "max", "rounds", "sent", "recv"
    );
    for r in &results {
        let row = |name: &str, samples: &PhaseSamples| {
            let (min, median, max) = samples.min_median_max();
            println!(
                "party {my_id}: {:>6}  {:>10}  {:>10.2?}  {:>10.2?}  {:>10.2?}  {:>10}  {:>12}  {:>12}",
                r.n, name, min, median, max, samples.rounds, samples.sent, samples.recv
            );
        };
        row("precomp", &r.precompute);
        row("prep", &r.preparation);
        row("witext", &r.witness);
        if let Some(prove) = &r.prove {
            row("prove", prove);
        }
    }

    Ok(())
}

/// Compiles `transfer_arity4_batch{n}.circom`, runs `runs` timed precompute+witness-extension
/// rounds (the first `prove_runs` also proving) against seeded-random dummy inputs, and returns
/// the timing/traffic summary.
#[allow(clippy::too_many_arguments)]
fn bench_batch(
    my_id: usize,
    net: &CountingNet<TlsNetwork>,
    state: &mut Rep3State,
    n: usize,
    opt: OptLevel,
    runs: usize,
    prove_runs: usize,
    no_prove: bool,
    seed: u64,
    zkey_dir: &std::path::Path,
) -> eyre::Result<BatchResult> {
    eyre::ensure!(runs > 0, "--runs must be > 0");

    let mut config = fixtures::merces_config();
    config.opt_level = opt;
    let path = fixtures::merces_main_path(&format!("transfer_arity4_batch{n}"));

    println!("party {my_id}: batch {n}: circuit {path} (opt={opt:?})");
    let t = Instant::now();
    let graph = CoCircomCompiler::parse(path, config)?;
    let summary = graph.mpc_summary();
    println!("party {my_id}: batch {n}: parse   {:.2?}", t.elapsed());
    println!(
        "party {my_id}: batch {n}:   signals={} inputs={} outputs={} rounds={} precompute: {} sites -> {} driver calls ({} host-precomputed)",
        graph.num_signals(),
        graph.num_inputs(),
        graph.num_outputs(),
        summary.rounds,
        summary.gadget_sites,
        summary.gadget_batches,
        summary.precomputed_batches,
    );

    let t = Instant::now();
    let program = codegen::compile(&graph)?;
    println!(
        "party {my_id}: batch {n}: codegen {:.2?}  ({} instructions, slots public={} shared={} local={})",
        t.elapsed(),
        program.statistics().instructions,
        program.statistics().public_slots,
        program.statistics().shared_slots,
        program.statistics().local_slots,
    );

    // Dummy inputs: this binary only measures cost, and rep3's cost (like Groth16 proving) is
    // value-independent, so seeded-random field elements stand in for real merces protocol
    // values. Every party derives the same share triples from the same seed, then keeps only its
    // own index - no share distribution, no extra network round. The commit-site precomputation
    // states are drawn from the same rng, right after the circuit inputs, so all three parties'
    // draws stay in lockstep.
    let mut rng = StdRng::seed_from_u64(seed);
    let values: Vec<Fr> = (0..program.statistics().inputs)
        .map(|_| Fr::rand(&mut rng))
        .collect();
    let shares: Vec<[Rep3PrimeFieldShare<Fr>; 3]> = program
        .input_domains()
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

    let site_counts = fixtures::precomputation::site_counts(&program)?;
    let total_sites: usize = site_counts.iter().sum();
    let commit_triples: Vec<[Rep3PrimeFieldShare<Fr>; 3]> = (0..total_sites * 3)
        .map(|_| share_field_element(Fr::rand(&mut rng), &mut rng))
        .collect();

    // The same `net` is reused for the proof, exactly like the real merces node's `MpcWorker`
    // reuses its one session for both `Engine::execute_batch` and `groth16::prove` -
    // `prove_with_shamir_bridge` takes one `&N`, issues its traffic strictly after witness
    // extension has finished, and never forks the connection. So there is nothing to set up here
    // beyond deciding, together with the other parties, whether a zkey exists to prove with.
    let zkey_path = zkey_dir.join(format!("transfer_arity4_batch{n}.arks.zkey"));
    let want_prove = !no_prove && prove_runs > 0;
    let t = Instant::now();
    let have_zkey = want_prove && std::fs::metadata(&zkey_path).is_ok();
    let will_prove = agree(net, have_zkey)?;
    let zkey = if will_prove {
        let zkey = fixtures::zkey::read(&zkey_path.to_string_lossy())?;
        println!(
            "party {my_id}: batch {n}: zkey    {:.2?}  (read {})",
            t.elapsed(),
            zkey_path.display()
        );
        Some(zkey)
    } else {
        if want_prove {
            println!(
                "party {my_id}: batch {n}: no zkey at {} on every party - skipping prove",
                zkey_path.display()
            );
        }
        None
    };

    let mut precompute = PhaseSamples::default();
    let mut preparation = PhaseSamples::default();
    let mut witness = PhaseSamples::default();
    let mut prove = zkey.is_some().then(PhaseSamples::default);

    for i in 0..runs {
        // Precomputation: the host builds every commit site's trace up front and opens the
        // commitments, mirroring the real node's `Engine::commit_batch` - this is what lets the
        // circuit's `TACEO_PRECOMPUTATION_Poseidon2` sites skip both the driver's mask-pool
        // preprocessing and their own online rounds.
        let commit_states =
            fixtures::precomputation::commit_states_for_party(&commit_triples, my_id);
        let (begin, stats0, rounds0) = phase_begin(net)?;
        let traces = fixtures::precomputation::rep3(total_sites, &commit_states, net, state)?;
        let stats = phase_end(net, begin, &stats0, rounds0)?;
        precompute.push(stats);
        let queue = fixtures::precomputation::queue(&site_counts, traces)?;

        // Preparation: `Rep3Driver::new_for_run`'s program-wide Poseidon2 mask-pool preprocessing.
        // Once every commit site is precomputed, the driver has nothing shared left to prepare
        // for (`poseidon2::mask_budget` only counts driver-serviced batches) - `r=0` here is the
        // whole point of precomputing, not an oversight; a nonzero round count would mean some
        // shared Poseidon2 batch escaped precomputation.
        let (begin, stats0, rounds0) = phase_begin(net)?;
        let mut driver = Rep3Driver::new_for_run(net, state, &program)?;
        let prep_stats = phase_end(net, begin, &stats0, rounds0)?;
        preparation.push(prep_stats);

        // Witness extension: online execution, with the precomputed traces inlined.
        let (begin, stats0, rounds0) = phase_begin(net)?;
        let full_witness = Machine::run_with_precomputation(&program, &mut driver, &inputs, queue)?;
        let wit_stats = phase_end(net, begin, &stats0, rounds0)?;
        witness.push(wit_stats);

        // Prove: split the witness at the zkey's public/secret boundary and run the collaborative
        // Groth16 proof through the Shamir bridge, over the same `net` witness extension just
        // used - only for the first `prove_runs` runs, since proving is far slower than the other
        // two phases.
        if i < prove_runs {
            if let Some((matrices, pkey)) = &zkey {
                let n_pub = matrices.num_instance_variables;
                let (begin, stats0, rounds0) = phase_begin(net)?;
                let (public_inputs, secret) = split_witness(&mut driver, full_witness, n_pub)?;
                let shared = co_circom_types::SharedWitness {
                    public_inputs,
                    witness: secret,
                };
                let _proof = Rep3CoGroth16::prove_with_shamir_bridge::<_, CircomReduction>(
                    net, pkey, matrices, shared,
                )?;
                let stats = phase_end(net, begin, &stats0, rounds0)?;
                prove.as_mut().expect("prove is Some whenever zkey is Some").push(stats);
            }
        }
        drop(driver);

        println!(
            "party {my_id}: batch {n}: run {i}: precomp {:.2?} (r={}) | prep {:.2?} (r={}) | witext {:.2?} (r={}){} | total {:.2?}",
            precompute.times[i],
            precompute.rounds,
            preparation.times[i],
            preparation.rounds,
            witness.times[i],
            witness.rounds,
            prove.as_ref().and_then(|p| p.times.get(i)).map(|d| format!(" | prove {d:.2?}")).unwrap_or_default(),
            precompute.times[i] + preparation.times[i] + witness.times[i]
                + prove.as_ref().and_then(|p| p.times.get(i)).copied().unwrap_or_default(),
        );

        std::thread::sleep(Duration::from_millis(200));
    }

    println!(
        "party {my_id}: batch {n}: {runs} runs done{}",
        if prove.is_some() {
            format!(", {prove_runs} of them proved")
        } else {
            String::new()
        }
    );

    Ok(BatchResult {
        n,
        precompute,
        preparation,
        witness,
        prove,
    })
}
