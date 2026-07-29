//! The whole pipeline on a real production circuit: parse a merces main, report its MPC shape,
//! generate bytecode, run it in the clear, then run the same bytecode across three genuine rep3
//! parties and check the reconstructed witness matches.
//!
//! ```text
//! cargo run --release --example merces                              # transfer_arity4_batch1
//! cargo run --release --example merces -- transfer_arity4_batch8
//! cargo run --release --example merces -- circuits/multiplier2.circom   # any other circuit
//! ```

use std::time::Instant;

use ark_bn254::{Bn254, Fr};
use circom_mpc_compiler::fixtures::{flatten, merces_server_inputs};
use circom_mpc_compiler::vm::driver::plain::PlainDriver;
use circom_mpc_compiler::vm::driver::rep3::Rep3Driver;
use circom_mpc_compiler::vm::program::Bank;
use circom_mpc_compiler::vm::{codegen, Machine, Program};
use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig, SimplificationLevel};
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::rep3::{
    combine_field_elements, share_field_element, Rep3PrimeFieldShare, Rep3State,
};
use mpc_net::local::LocalNetwork;
use rand::thread_rng;

const MAX_DEPTH: usize = 13;
const SEED: u64 = 42;

fn install_tracing() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{fmt, EnvFilter};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(false).with_line_number(false))
        .init();
}

/// Batch size for a merces server main, or `None` for any other circuit.
fn merces_batch_size(name: &str) -> Option<usize> {
    match name {
        "transfer_arity4_batch1" => Some(1),
        "transfer_arity4_batch8" => Some(8),
        _ => None,
    }
}

fn main() -> eyre::Result<()> {
    install_tracing();
    let root = env!("CARGO_MANIFEST_DIR");
    let arg = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "transfer_arity4_batch1".to_owned());

    let mut config = CompilerConfig::default();
    config.version = "2.2.2".to_owned();
    config.simplification = SimplificationLevel::O2(usize::MAX);
    config.link_library.push(format!("{root}/circuits/libs/").into());
    config
        .link_library
        .push(format!("{root}/circuits/merces/").into());

    let batch = merces_batch_size(&arg);
    let path = if batch.is_some() {
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
    // The batching claim, on a real circuit: hundreds of sites, a couple of dozen driver calls.
    println!(
        "  precompute: {} sites -> {} driver calls ({} local muls, {} free public muls)",
        summary.precompute_sites,
        summary.precompute_batches,
        summary.local_muls,
        summary.public_muls,
    );

    let values: Vec<Fr> = match batch {
        Some(n) => flatten(&merces_server_inputs::<Fr>(n, MAX_DEPTH, SEED), &graph.input_list)?,
        None => (0..graph.num_inputs).map(|i| Fr::from(i as u64 + 1)).collect(),
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

    let t = Instant::now();
    let rep3 = run_rep3(&program, &values);
    println!("rep3:    {:.2?}  (3 parties over an in-process LocalNetwork)", t.elapsed());

    if rep3 == plain {
        println!("\nwitnesses agree: the rep3 driver reconstructs exactly what the plain one computes.");
    } else {
        eyre::bail!("rep3 and plain witnesses disagree - this is a bug, not a configuration issue");
    }
    if batch.is_some() {
        println!(
            "note: inputs are placeholders from fixtures::merces_server_inputs - arbitrary values \
             that still satisfy the circuit's === constraints. See that module's doc."
        );
    }
    Ok(())
}

/// Three real parties, each with its own connection and correlated randomness.
fn run_rep3(program: &Program<Fr>, values: &[Fr]) -> Vec<Fr> {
    let mut rng = thread_rng();
    let shares: Vec<[Rep3PrimeFieldShare<Fr>; 3]> = program
        .input_domains
        .iter()
        .zip(values)
        .filter(|(bank, _)| matches!(bank, Bank::Shared))
        .map(|(_, &v)| share_field_element(v, &mut rng))
        .collect();

    let networks = LocalNetwork::new(3);
    let witnesses: Vec<Vec<Rep3PrimeFieldShare<Fr>>> = std::thread::scope(|scope| {
        networks
            .into_iter()
            .enumerate()
            .map(|(party, net)| {
                let shares = &shares;
                scope.spawn(move || {
                    let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                    let mut driver = Rep3Driver::new(&net, &mut state);
                    let mut next = 0;
                    let inputs = program.classify_inputs(values, |_v| {
                        let s = shares[next][party];
                        next += 1;
                        s
                    });
                    Machine::run(program, &mut driver, &inputs).unwrap()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect()
    });

    let [w0, w1, w2]: [Vec<Rep3PrimeFieldShare<Fr>>; 3] = witnesses.try_into().unwrap();
    combine_field_elements(&w0, &w1, &w2)
}
