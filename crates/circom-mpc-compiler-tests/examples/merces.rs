//! The whole pipeline on a real production circuit: parse a merces main, report its MPC shape,
//! generate bytecode, run it in the clear, then run the same bytecode across three genuine rep3
//! parties, check the reconstructed witness matches, and produce a co-groth16 proof that verifies.
//!
//! ```text
//! cargo run --release -p circom-mpc-compiler-tests --example merces
//! cargo run --release -p circom-mpc-compiler-tests --example merces -- transfer_arity4_batch8 full_batch
//! cargo run --release -p circom-mpc-compiler-tests --example merces -- circuits/multiplier3.circom kats/proving/multiplier3.zkey
//! cargo run --release -p circom-mpc-compiler-tests --example merces -- circuits/multiplier3.circom
//! ```

#![allow(clippy::type_complexity)] // the per-party (witness, metrics, proof) tuples

use std::time::{Duration, Instant};

use ark_bn254::{Bn254, Fr};
use ark_serialize::{CanonicalDeserialize, Compress, Validate};
use circom_mpc_compiler::CoCircomCompiler;
use circom_mpc_compiler::codegen;
use circom_mpc_compiler_tests::fixtures;
use circom_mpc_vm::counting_net::CountingNet;
use circom_mpc_vm::driver::plain::PlainDriver;
use circom_mpc_vm::driver::rep3::Rep3Driver;
use circom_mpc_vm::split_witness;
use circom_mpc_vm::{Machine, Program};
use circom_types::CheckElement;
use co_groth16::{CircomReduction, ConstraintMatrices, Groth16, ProvingKey, Rep3CoGroth16};
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::rep3::{Rep3PrimeFieldShare, Rep3State, combine_field_elements};
use mpc_net::Network;
use mpc_net::local::LocalNetwork;

fn install_tracing() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{EnvFilter, fmt};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(false).with_line_number(false))
        .init();
}

/// Default scenario per merces server main, or `None` for any other circuit.
fn default_scenario(main: &str) -> Option<&'static str> {
    match main {
        "transfer_arity4_batch1" => Some("deposit"),
        "transfer_arity4_batch8" => Some("full_batch"),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug)]
struct PartyMetrics {
    preprocessing_rounds: usize,
    online_rounds: usize,
    bytes_sent: usize,
    bytes_recv: usize,
    setup_time: Duration,
    preprocessing_time: Duration,
    witness_time: Duration,
    prove_time: Option<Duration>,
}

impl PartyMetrics {
    fn combined_rounds(self) -> usize {
        self.preprocessing_rounds + self.online_rounds
    }
}

/// Reads a zkey for proving, in whichever of the two formats this repo uses: `.arks.zkey` is the
/// merces ceremony key (ark-serialized, uncompressed - see `tests/merces.rs`'s `ceremony_zkey`),
/// anything else is a plain snarkjs zkey (`tests/proving.rs`'s format, e.g.
/// `kats/proving/multiplier3.zkey`).
fn read_zkey(path: &str) -> (ConstraintMatrices<Fr>, ProvingKey<Bn254>) {
    if path.ends_with(".arks.zkey") {
        let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
        // `Validate::No`: validating hundreds of MB of group elements costs far more than the proof
        // itself, and a bad zkey shows up immediately as a proof that fails to verify.
        circom_types::groth16::ArkZkey::<Bn254>::deserialize_with_mode(
            bytes.as_slice(),
            Compress::No,
            Validate::No,
        )
        .unwrap_or_else(|e| panic!("parsing {path}: {e}"))
        .into_inner()
    } else {
        let file = std::fs::File::open(path).unwrap_or_else(|e| panic!("opening {path}: {e}"));
        circom_types::groth16::Zkey::<Bn254>::from_reader(file, CheckElement::No)
            .unwrap_or_else(|e| panic!("parsing {path}: {e}"))
            .into()
    }
}

/// Where to look for a zkey when none was given on the command line: the merces ceremony key for a
/// server main, otherwise nothing - there is no default zkey for an arbitrary circuit.
fn default_zkey_path(root: &str, main: &str, is_merces_main: bool) -> Option<String> {
    is_merces_main.then(|| format!("{root}/inputs/zkey/{main}.arks.zkey"))
}

fn main() -> eyre::Result<()> {
    install_tracing();
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let mut args = std::env::args().skip(1);
    let arg = args
        .next()
        .unwrap_or_else(|| "transfer_arity4_batch1".to_owned());
    let is_merces_main = default_scenario(&arg).is_some();
    // A merces main takes a scenario name as its second arg (defaulting per `default_scenario`);
    // any other circuit has no scenario, so its second arg (if any) is the zkey path instead.
    let scenario_name = is_merces_main
        .then(|| {
            args.next()
                .or_else(|| default_scenario(&arg).map(str::to_owned))
        })
        .flatten();
    let zkey_arg = args.next();

    let mut config = fixtures::merces_config();
    if !is_merces_main {
        config.mpc_public_inputs.clear();
    }

    let path = if is_merces_main {
        format!("{root}/circuits/merces/main/{arg}.circom")
    } else {
        arg.clone()
    };

    println!("circuit: {path}");
    let t = Instant::now();
    let graph = CoCircomCompiler::parse(path, config)?;
    let summary = graph.mpc_summary();
    println!("parse:   {:.2?}", t.elapsed());
    println!(
        "  signals={} inputs={} outputs={}",
        graph.num_signals, graph.num_inputs, graph.num_outputs
    );
    println!(
        "  rounds={} reshare_elements={} widest_round={}",
        summary.rounds,
        summary.reshare_elements,
        summary.max_slots_per_round.unwrap_or(0),
    );
    // The batching claim, on a real circuit: hundreds of sites, a couple of dozen services.
    println!(
        "  precompute: {} sites -> {} batch services ({} local muls, {} free public muls)",
        summary.accelerator_sites,
        summary.accelerator_batches,
        summary.local_muls,
        summary.public_muls,
    );

    let values: Vec<Fr> = match &scenario_name {
        Some(name) => {
            let s = fixtures::scenario(&arg, name)?;
            println!("scenario: {name} ({})", s.note);
            s.values(&graph.input_list)?
        }
        None => (0..graph.num_inputs)
            .map(|i| Fr::from(i as u64 + 1))
            .collect(),
    };

    let t = Instant::now();
    let program = codegen::compile(&graph)?;
    println!("codegen: {:.2?}", t.elapsed());
    println!(
        "  {} instructions, slots public={} shared={} local={}",
        program.statistics().instructions,
        program.statistics().public_slots,
        program.statistics().shared_slots,
        program.statistics().local_slots,
    );

    let t = Instant::now();
    let plain = {
        let inputs = program.classify_inputs(&values, |v| v);
        let mut driver = PlainDriver;
        Machine::run(&program, &mut driver, &inputs)?
    };
    println!(
        "plain:   {:.2?}  ({} witness entries)",
        t.elapsed(),
        plain.len()
    );

    let zkey_path = zkey_arg.or_else(|| default_zkey_path(root, &arg, is_merces_main));
    let t = Instant::now();
    let zkey = zkey_path.as_deref().and_then(|p| {
        std::fs::metadata(p)
            .is_ok()
            .then(|| read_zkey(p))
            .or_else(|| {
                println!("note: no zkey at {p} - skipping prove+verify.");
                None
            })
    });
    if zkey.is_some() {
        println!(
            "zkey:    {:.2?}  (read {})",
            t.elapsed(),
            zkey_path.as_deref().unwrap()
        );
    }

    let t = Instant::now();
    let (rep3, party_metrics, proof) = run_rep3(&program, &values, zkey.as_ref());
    let preprocessing_rounds = party_metrics.map(|metrics| metrics.preprocessing_rounds);
    let online_rounds = party_metrics.map(|metrics| metrics.online_rounds);
    let combined_rounds = party_metrics.map(PartyMetrics::combined_rounds);
    let max_preprocessing_rounds = preprocessing_rounds.iter().copied().max().unwrap_or(0);
    let max_online_rounds = online_rounds.iter().copied().max().unwrap_or(0);
    let max_combined_rounds = combined_rounds.iter().copied().max().unwrap_or(0);
    let online_gadget_rounds = max_online_rounds.saturating_sub(summary.rounds);
    println!("  total:         {:.2?}", t.elapsed());
    for (party, metrics) in party_metrics.iter().enumerate() {
        match metrics.prove_time {
            Some(prove) => println!(
                "  party {party}: state setup {:.2?}, preprocessing {:.2?}, witness ext {:.2?}, prove {:.2?}",
                metrics.setup_time, metrics.preprocessing_time, metrics.witness_time, prove,
            ),
            None => println!(
                "  party {party}: state setup {:.2?}, preprocessing {:.2?}, witness ext {:.2?}",
                metrics.setup_time, metrics.preprocessing_time, metrics.witness_time,
            ),
        }
    }
    println!(
        "  preprocessing rounds={preprocessing_rounds:?} by party, max={max_preprocessing_rounds}"
    );
    println!(
        "  online rounds={online_rounds:?} by party, max={max_online_rounds}  ({} reshare + {online_gadget_rounds} gadget-internal)",
        summary.rounds,
    );
    println!("  combined rounds={combined_rounds:?} by party, max={max_combined_rounds}");
    for (party, metrics) in party_metrics.iter().enumerate() {
        println!(
            "  party {party}: combined bytes sent={} recv={}",
            metrics.bytes_sent, metrics.bytes_recv
        );
    }

    if rep3 != plain {
        eyre::bail!("rep3 and plain witnesses disagree - this is a bug, not a configuration issue");
    }
    println!(
        "\nwitnesses agree: the rep3 driver reconstructs exactly what the plain one computes."
    );

    if let Some((vk, proof, public)) = proof {
        let t = Instant::now();
        Groth16::<Bn254>::verify(&vk, &proof, &public[1..]).unwrap_or_else(|e| {
            panic!(
                "the proof did not verify: {e} - this points at this compiler's witness (layout \
                 or a gadget), not at the zkey or the inputs"
            )
        });
        println!(
            "verify:  {:.2?}  (proof verifies against {})",
            t.elapsed(),
            zkey_path.unwrap()
        );
    }
    Ok(())
}

/// Three real parties, each with its own connection and correlated randomness. Returns the
/// reconstructed witness, all parties' preprocessing/online round counts and combined
/// witness-extension byte totals (`Rep3State::new` setup excluded; each party's bytes are summed
/// across its two peer connections - see `vm::counting_net`), and, if a zkey was given, party 0's
/// verifying key/proof/public-inputs.
fn run_rep3(
    program: &Program,
    values: &[Fr],
    zkey: Option<&(ConstraintMatrices<Fr>, ProvingKey<Bn254>)>,
) -> (
    Vec<Fr>,
    [PartyMetrics; 3],
    Option<(
        co_groth16::VerifyingKey<Bn254>,
        co_groth16::Proof<Bn254>,
        Vec<Fr>,
    )>,
) {
    let t = Instant::now();
    let shares = fixtures::rep3::share_inputs(program, values);
    println!("rep3:    (3 parties over an in-process LocalNetwork)");
    println!("  share inputs:  {:.2?}", t.elapsed());

    // A second and third connection per party are only needed if we are actually proving.
    let extension_nets = LocalNetwork::new(3);
    let proving_nets0 = zkey.map(|_| LocalNetwork::new(3));
    let proving_nets1 = zkey.map(|_| LocalNetwork::new(3));

    let results: Vec<(
        Vec<Rep3PrimeFieldShare<Fr>>,
        PartyMetrics,
        Option<(co_groth16::Proof<Bn254>, Vec<Fr>)>,
    )> = std::thread::scope(|scope| {
        let mut proving0 = proving_nets0.map(|n| n.into_iter());
        let mut proving1 = proving_nets1.map(|n| n.into_iter());
        extension_nets
            .into_iter()
            .enumerate()
            .map(|(party, net)| {
                let shares = &shares;
                let p0 = proving0.as_mut().map(|it| it.next().unwrap());
                let p1 = proving1.as_mut().map(|it| it.next().unwrap());
                scope.spawn(move || {
                    let net = CountingNet::new(net);
                    let t = Instant::now();
                    let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                    let setup_time = t.elapsed();
                    let (setup_sent, setup_recv) = net
                        .get_connection_stats()
                        .iter()
                        .fold((0, 0), |(s, r), (_, (sent, recv))| (s + sent, r + recv));
                    net.reset();
                    let t = Instant::now();
                    let mut driver = Rep3Driver::new_for_run(&net, &mut state, program).unwrap();
                    let preprocessing_time = t.elapsed();
                    let preprocessing_rounds = net.rounds();
                    net.reset();
                    let mut next = 0;
                    let inputs = program.classify_inputs(values, |_v| {
                        let s = shares[next][party];
                        next += 1;
                        s
                    });
                    let t = Instant::now();
                    let witness = Machine::run(program, &mut driver, &inputs).unwrap();
                    let witness_time = t.elapsed();
                    let online_rounds = net.rounds();
                    let full_witness = witness.clone();
                    let (total_sent, total_recv) = net
                        .get_connection_stats()
                        .iter()
                        .fold((0, 0), |(s, r), (_, (sent, recv))| (s + sent, r + recv));
                    let bytes_sent = total_sent.saturating_sub(setup_sent);
                    let bytes_recv = total_recv.saturating_sub(setup_recv);

                    let t = Instant::now();
                    let proof = zkey.map(|(matrices, pkey)| {
                        let n_pub = matrices.num_instance_variables;
                        let (public_inputs, secret) =
                            split_witness(&mut driver, witness, n_pub).unwrap();
                        let shared = co_circom_types::SharedWitness {
                            public_inputs: public_inputs.clone(),
                            witness: secret,
                        };
                        let proof = Rep3CoGroth16::prove::<_, CircomReduction>(
                            p0.as_ref().unwrap(),
                            p1.as_ref().unwrap(),
                            pkey,
                            matrices,
                            shared,
                        )
                        .unwrap();
                        (proof, public_inputs)
                    });
                    let prove_time = proof.is_some().then(|| t.elapsed());

                    (
                        full_witness,
                        PartyMetrics {
                            preprocessing_rounds,
                            online_rounds,
                            bytes_sent,
                            bytes_recv,
                            setup_time,
                            preprocessing_time,
                            witness_time,
                            prove_time,
                        },
                        proof,
                    )
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect()
    });

    let [(w0, metrics0, proof0), (w1, metrics1, _), (w2, metrics2, _)]: [(
        Vec<Rep3PrimeFieldShare<Fr>>,
        PartyMetrics,
        Option<(co_groth16::Proof<Bn254>, Vec<Fr>)>,
    ); 3] = results.try_into().unwrap();

    let proof = zkey.map(|(_, pkey)| {
        let (proof, public) = proof0.expect("proving was requested, party 0 must have proved");
        (pkey.vk.clone(), proof, public)
    });

    let t = Instant::now();
    let witness = combine_field_elements(&w0, &w1, &w2);
    println!("  combine:       {:.2?}", t.elapsed());

    (witness, [metrics0, metrics1, metrics2], proof)
}
