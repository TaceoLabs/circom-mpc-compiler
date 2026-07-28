//! Every test here needs a real rep3 driver, so the whole file is gated on the feature that provides
//! one - otherwise `cargo test --no-default-features` (the fast, plain-only build the architecture
//! doc describes) fails to compile this file rather than skipping it.
#![cfg(feature = "rep3")]

//! Proves `Rep3Driver` against real 3-party rep3 execution: secret-share an input, run the same
//! `Program` on three threads over `mpc_net::local::LocalNetwork`, reconstruct the witness, and
//! compare against the plain driver's - this is what proves the rep3 driver agrees with the plain
//! one on genuinely secret-shared data, not just in the clear. `tests/proving.rs`'s prove+verify
//! tests are the value oracle for both drivers. See `docs/ARCHITECTURE.md`, "Bytecode and the slot
//! machine".

use ark_bn254::{Bn254, Fr};
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::rep3::{Rep3PrimeFieldShare, Rep3State, combine_field_elements, share_field_element};
use mpc_net::local::LocalNetwork;
use rand::thread_rng;

use circom_mpc_compiler::vm::driver::rep3::Rep3Driver;
use circom_mpc_compiler::vm::program::Bank;
use circom_mpc_compiler::vm::Machine;
use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig};

mod common;

use common::{circuit_path, libs_path};

fn config() -> CompilerConfig {
    let mut config = CompilerConfig::default();
    config.link_library.push(libs_path());
    config
}

/// Runs one input through 3-party rep3 and returns the reconstructed witness.
fn run_rep3(program: &circom_mpc_compiler::vm::Program<Fr>, values: &[Fr]) -> Vec<Fr> {
    // One [share0, share1, share2] triple per Shared-domain input, in the same order
    // `Program::classify_inputs` visits them - each party gets its own entry below.
    let mut rng = thread_rng();
    let secret_shares: Vec<[Rep3PrimeFieldShare<Fr>; 3]> = program
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
                let secret_shares = &secret_shares;
                scope.spawn(move || {
                    let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                    let mut driver = Rep3Driver::new(&net, &mut state);
                    let mut next = 0;
                    let inputs = program.classify_inputs(values, |_v| {
                        let s = secret_shares[next][party];
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

/// Staged precomputation under a *real* network. This compares 3-party rep3 against the plain
/// driver, the same substitute the gadget unit tests already use.
///
/// **This is the test that proves interleaving actually works.** `PlainDriver` cannot detect a
/// mis-ordered batch - its `reshare` is the identity and every slot starts zeroed, so reading a
/// not-yet-written slot silently yields a plausible number. Against three real parties the same bug
/// either deadlocks or consumes uninitialized shares, and the reconstruction diverges.
#[test]
fn staged_precomputation_matches_the_plain_driver_under_rep3() {
    use circom_mpc_compiler::vm::driver::plain::PlainDriver;

    let program = CoCircomCompiler::<Bn254>::compile(
        circuit_path("precomputation_staged_test"),
        config(),
    )
    .unwrap();
    assert_eq!(
        program.precompute_batches.len(),
        2,
        "the fixture must actually be staged for this test to mean anything"
    );

    for values in [
        [Fr::from(0u64), Fr::from(7u64)],
        [Fr::from(3u64), Fr::from(5u64)],
        [Fr::from(11u64), Fr::from(0u64)],
    ] {
        let plain = {
            let inputs = program.classify_inputs(&values, |v| v);
            let mut driver = PlainDriver;
            Machine::run(&program, &mut driver, &inputs).unwrap()
        };
        assert_eq!(run_rep3(&program, &values), plain, "inputs {values:?}");
    }
}

#[test]
fn wide_round_vector_products_match_the_plain_driver() {
    use circom_mpc_compiler::vm::driver::plain::PlainDriver;

    let program =
        CoCircomCompiler::<Bn254>::compile(circuit_path("bench_widesum"), config()).unwrap();
    assert_eq!(program.rounds.len(), 1);
    assert_eq!(program.rounds[0].len, 4);
    let values: Vec<Fr> = (1..=8).map(Fr::from).collect();
    let plain = {
        let inputs = program.classify_inputs(&values, |v| v);
        Machine::run(&program, &mut PlainDriver, &inputs).unwrap()
    };
    assert_eq!(run_rep3(&program, &values), plain);
}

#[test]
fn all_public_precomputation_uses_the_plain_path_under_rep3() {
    use circom_mpc_compiler::OptLevel;
    use circom_mpc_compiler::vm::driver::plain::PlainDriver;

    let mut cfg = config();
    cfg.opt_level = OptLevel::O2;
    let program = CoCircomCompiler::<Bn254>::compile(
        circuit_path("precomputation_public_test"),
        cfg,
    )
    .unwrap();
    let values = [Fr::from(0u64), Fr::from(9u64)];
    let plain = {
        let inputs = program.classify_inputs(&values, |v| v);
        Machine::run(&program, &mut PlainDriver, &inputs).unwrap()
    };
    assert_eq!(run_rep3(&program, &values), plain);
}
