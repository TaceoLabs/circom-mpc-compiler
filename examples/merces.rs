//! The whole pipeline on a real production circuit: parse a merces main, report its MPC shape,
//! generate bytecode, run it in the clear, then run the same bytecode across three genuine rep3
//! parties, check the reconstructed witness matches, and produce a co-groth16 proof that verifies.
//!
//! ```text
//! cargo run --release --example merces                              # transfer_arity4_batch1 deposit
//! cargo run --release --example merces -- transfer_arity4_batch8 full_batch
//! cargo run --release --example merces -- circuits/multiplier3.circom kats/proving/multiplier3.zkey
//! cargo run --release --example merces -- circuits/multiplier3.circom   # no zkey: skips proving
//! ```

use std::time::Instant;

use ark_bn254::{Bn254, Fr};
use ark_serialize::{CanonicalDeserialize, Compress, Validate};
use circom_mpc_compiler::fixtures;
use circom_mpc_compiler::vm::counting_net::CountingNet;
use circom_mpc_compiler::vm::driver::plain::PlainDriver;
use circom_mpc_compiler::vm::driver::rep3::Rep3Driver;
use circom_mpc_compiler::vm::program::Bank;
use circom_mpc_compiler::vm::witness::split_witness;
use circom_mpc_compiler::vm::{codegen, Machine, Program};
use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig};
use circom_types::CheckElement;
use co_groth16::{CircomReduction, ConstraintMatrices, Groth16, ProvingKey, Rep3CoGroth16};
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::rep3::{
    combine_field_elements, share_field_element, Rep3PrimeFieldShare, Rep3State,
};
use mpc_net::local::LocalNetwork;
use mpc_net::Network;
use rand::thread_rng;

fn install_tracing() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{fmt, EnvFilter};

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
    let root = env!("CARGO_MANIFEST_DIR");
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

    let mut config = CompilerConfig::default();
    config.version = "2.2.2".to_owned();
    config
        .link_library
        .push(format!("{root}/circuits/libs/").into());
    config
        .link_library
        .push(format!("{root}/circuits/merces/").into());
    if is_merces_main {
        config.mpc_public_inputs = fixtures::merces_mpc_public_inputs();
    }

    let path = if is_merces_main {
        format!("{root}/circuits/merces/main/{arg}.circom")
    } else {
        arg.clone()
    };

    println!("circuit: {path}");
    let t = Instant::now();
    let graph = CoCircomCompiler::<Bn254>::parse(path, config)?;
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
        summary.precompute_sites,
        summary.precompute_batches,
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
        program.instructions.len(),
        program.slots.public,
        program.slots.shared,
        program.slots.local,
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
    let zkey = zkey_path.as_deref().and_then(|p| {
        std::fs::metadata(p)
            .is_ok()
            .then(|| read_zkey(p))
            .or_else(|| {
                println!("note: no zkey at {p} - skipping prove+verify.");
                None
            })
    });

    let t = Instant::now();
    let (rep3, party_metrics, proof) = run_rep3(&program, &values, zkey.as_ref());
    let preprocessing_rounds = party_metrics.map(|metrics| metrics.preprocessing_rounds);
    let online_rounds = party_metrics.map(|metrics| metrics.online_rounds);
    let combined_rounds = party_metrics.map(PartyMetrics::combined_rounds);
    let max_preprocessing_rounds = preprocessing_rounds.iter().copied().max().unwrap_or(0);
    let max_online_rounds = online_rounds.iter().copied().max().unwrap_or(0);
    let max_combined_rounds = combined_rounds.iter().copied().max().unwrap_or(0);
    let online_gadget_rounds = max_online_rounds.saturating_sub(summary.rounds);
    println!(
        "rep3:    {:.2?}  (3 parties over an in-process LocalNetwork)",
        t.elapsed()
    );
    println!(
        "  preprocessing rounds={preprocessing_rounds:?} by party, max={max_preprocessing_rounds}"
    );
    println!(
        "  online rounds={online_rounds:?} by party, max={max_online_rounds}  ({} reshare + {online_gadget_rounds} gadget-internal)",
        summary.rounds,
    );
    println!(
        "  combined rounds={combined_rounds:?} by party, max={max_combined_rounds}"
    );
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
        Groth16::<Bn254>::verify(&vk, &proof, &public[1..]).unwrap_or_else(|e| {
            panic!(
                "the proof did not verify: {e} - this points at this compiler's witness (layout \
                 or a gadget), not at the zkey or the inputs"
            )
        });
        println!("proof verifies against {}", zkey_path.unwrap());
    }
    Ok(())
}

/// Three real parties, each with its own connection and correlated randomness. Returns the
/// reconstructed witness, all parties' preprocessing/online round counts and combined
/// witness-extension byte totals (`Rep3State::new` setup excluded; each party's bytes are summed
/// across its two peer connections - see `vm::counting_net`), and, if a zkey was given, party 0's
/// verifying key/proof/public-inputs.
fn run_rep3(
    program: &Program<Fr>,
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
    let mut rng = thread_rng();
    let shares: Vec<[Rep3PrimeFieldShare<Fr>; 3]> = program
        .input_domains
        .iter()
        .zip(values)
        .filter(|(bank, _)| matches!(bank, Bank::Shared))
        .map(|(_, &v)| share_field_element(v, &mut rng))
        .collect();

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
                let zkey = zkey;
                let p0 = proving0.as_mut().map(|it| it.next().unwrap());
                let p1 = proving1.as_mut().map(|it| it.next().unwrap());
                scope.spawn(move || {
                    let net = CountingNet::new(net);
                    let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                    let (setup_sent, setup_recv) = net
                        .get_connection_stats()
                        .iter()
                        .fold((0, 0), |(s, r), (_, (sent, recv))| (s + sent, r + recv));
                    net.reset();
                    let mut driver =
                        Rep3Driver::<Fr, _>::new_for_run(&net, &mut state, program).unwrap();
                    let preprocessing_rounds = net.rounds();
                    net.reset();
                    let mut next = 0;
                    let inputs = program.classify_inputs(values, |_v| {
                        let s = shares[next][party];
                        next += 1;
                        s
                    });
                    let witness = Machine::run(program, &mut driver, &inputs).unwrap();
                    let online_rounds = net.rounds();
                    let full_witness = witness.clone();
                    let (total_sent, total_recv) = net
                        .get_connection_stats()
                        .iter()
                        .fold((0, 0), |(s, r), (_, (sent, recv))| (s + sent, r + recv));
                    let bytes_sent = total_sent.saturating_sub(setup_sent);
                    let bytes_recv = total_recv.saturating_sub(setup_recv);

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

                    (
                        full_witness,
                        PartyMetrics {
                            preprocessing_rounds,
                            online_rounds,
                            bytes_sent,
                            bytes_recv,
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

    (
        combine_field_elements(&w0, &w1, &w2),
        [metrics0, metrics1, metrics2],
        proof,
    )
}
