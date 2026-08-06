//! Proves `Rep3Driver` against real 3-party rep3 execution: secret-share an input, run the same
//! `Program` on three threads over `mpc_net::local::LocalNetwork`, reconstruct the witness, and
//! compare against the plain driver's - this is what proves the rep3 driver agrees with the plain
//! one on genuinely secret-shared data, not just in the clear. `tests/proving.rs`'s prove+verify
//! tests are the value oracle for both drivers.
#![cfg(feature = "rep3")]

use ark_bn254::Fr;
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::rep3::{combine_field_elements, Rep3PrimeFieldShare, Rep3State};
use mpc_net::local::LocalNetwork;

use circom_mpc_compiler::fixtures::rep3::{run_witness, share_inputs};
use circom_mpc_compiler::vm::driver::rep3::Rep3Driver;
use circom_mpc_compiler::vm::Machine;
use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig};

mod common;

use common::{circuit_path, libs_path};

fn config() -> CompilerConfig {
    let mut config = CompilerConfig::default();
    config.link_library.push(libs_path());
    config
}

/// Staged precomputation under a real network - the test that proves batch interleaving works.
/// `PlainDriver` cannot detect a mis-ordered batch (its `reshare` is the identity and slots start
/// zeroed); against three real parties the same bug deadlocks or diverges.
#[test]
fn staged_precomputation_matches_the_plain_driver_under_rep3() {
    use circom_mpc_compiler::vm::driver::plain::PlainDriver;

    let program =
        CoCircomCompiler::compile(circuit_path("precomputation_staged_test"), config()).unwrap();
    assert_eq!(
        program.statistics().precompute_batches,
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
        assert_eq!(run_witness(&program, &values), plain, "inputs {values:?}");
    }
}

#[test]
fn fused_iszero_reveal_matches_plain_for_zero_and_nonzero() {
    use circom_mpc_compiler::vm::driver::plain::PlainDriver;

    let program =
        CoCircomCompiler::compile(circuit_path("precomputation_iszero_reveal_test"), config())
            .unwrap();
    assert_eq!(program.statistics().precompute_batches, 1);
    assert_eq!(program.statistics().fused_is_zero_reveal_batches, 1);
    assert_eq!(program.statistics().precompute_sites, 2);

    let values = [Fr::from(0u64), Fr::from(7u64)];
    let plain = {
        let inputs = program.classify_inputs(&values, |v| v);
        Machine::run(&program, &mut PlainDriver, &inputs).unwrap()
    };
    assert_eq!(run_witness(&program, &values), plain, "inputs {values:?}");
}

#[test]
fn fused_isequal_reveal_matches_plain_for_shared_and_mixed_operands() {
    use circom_mpc_compiler::vm::driver::plain::PlainDriver;

    let program =
        CoCircomCompiler::compile(circuit_path("precomputation_isequal_reveal_test"), config())
            .unwrap();
    assert_eq!(program.statistics().precompute_batches, 1);
    assert_eq!(program.statistics().fused_is_zero_reveal_batches, 1);
    assert_eq!(program.statistics().precompute_sites, 3);

    for (values, expected) in [
        (
            [Fr::from(5u64), Fr::from(5u64), Fr::from(5u64)],
            [1u64, 1, 1],
        ),
        // Circom orders public inputs first: [clear, secret[0], secret[1]].
        (
            [Fr::from(4u64), Fr::from(10u64), Fr::from(4u64)],
            [0u64, 0, 1],
        ),
        (
            [Fr::from(4u64), Fr::from(4u64), Fr::from(10u64)],
            [0u64, 1, 0],
        ),
    ] {
        let plain = {
            let inputs = program.classify_inputs(&values, |v| v);
            Machine::run(&program, &mut PlainDriver, &inputs).unwrap()
        };
        assert_eq!(
            &plain[1..4],
            &expected.map(Fr::from),
            "main equality outputs for {values:?}"
        );
        assert_eq!(run_witness(&program, &values), plain, "inputs {values:?}");
    }
}

#[cfg(feature = "round-counting")]
#[test]
fn fused_iszero_reveal_costs_one_online_round() {
    use circom_mpc_compiler::fixtures::rep3::run_witness_counted;

    let program =
        CoCircomCompiler::compile(circuit_path("precomputation_iszero_reveal_test"), config())
            .unwrap();
    let (_, _, online) = run_witness_counted(&program, &[Fr::from(0u64), Fr::from(7u64)]);
    assert_eq!(online, [1, 1, 1]);
}

#[cfg(feature = "round-counting")]
#[test]
fn three_fused_isequal_reveal_sites_cost_one_online_round() {
    use circom_mpc_compiler::fixtures::rep3::run_witness_counted;

    let program =
        CoCircomCompiler::compile(circuit_path("precomputation_isequal_reveal_test"), config())
            .unwrap();
    let values = [Fr::from(4u64), Fr::from(10u64), Fr::from(4u64)];
    let (_, _, online) = run_witness_counted(&program, &values);
    assert_eq!(online, [1, 1, 1]);
}

#[test]
fn wide_round_vector_products_match_the_plain_driver() {
    use circom_mpc_compiler::vm::driver::plain::PlainDriver;

    let program = CoCircomCompiler::compile(circuit_path("bench_widesum"), config()).unwrap();
    assert_eq!(program.statistics().multiplication_rounds, 1);
    assert_eq!(program.statistics().multiplication_elements, 4);
    let values: Vec<Fr> = (1..=8).map(Fr::from).collect();
    let plain = {
        let inputs = program.classify_inputs(&values, |v| v);
        Machine::run(&program, &mut PlainDriver, &inputs).unwrap()
    };
    assert_eq!(run_witness(&program, &values), plain);
}

#[test]
fn all_public_precomputation_uses_the_plain_path_under_rep3() {
    use circom_mpc_compiler::vm::driver::plain::PlainDriver;
    use circom_mpc_compiler::OptLevel;

    let mut cfg = config();
    cfg.opt_level = OptLevel::O2;
    let program =
        CoCircomCompiler::compile(circuit_path("precomputation_public_test"), cfg).unwrap();
    let values = [Fr::from(0u64), Fr::from(9u64)];
    let plain = {
        let inputs = program.classify_inputs(&values, |v| v);
        Machine::run(&program, &mut PlainDriver, &inputs).unwrap()
    };
    assert_eq!(run_witness(&program, &values), plain);
}

#[cfg(feature = "round-counting")]
#[test]
fn prepared_driver_is_one_shot_and_fresh_driver_reuses_network_and_state() {
    use circom_mpc_compiler::vm::counting_net::CountingNet;
    use circom_mpc_compiler::vm::driver::plain::PlainDriver;

    struct PartyRun {
        first: Vec<Rep3PrimeFieldShare<Fr>>,
        fresh: Vec<Rep3PrimeFieldShare<Fr>>,
        preparation_rounds: usize,
        first_online_rounds: usize,
        reuse_rounds: usize,
        fresh_preparation_rounds: usize,
        fresh_online_rounds: usize,
        reuse_error: String,
    }

    // One ordinary shared multiplication round and no Poseidon2 service: preparing either driver
    // must be communication-free, while a successful execution costs exactly one round.
    let program = CoCircomCompiler::compile(circuit_path("bench_widesum"), config()).unwrap();
    assert_eq!(program.statistics().precompute_batches, 0);
    let values: Vec<Fr> = (1..=8).map(Fr::from).collect();
    let shares = share_inputs(&program, &values);
    let networks: Vec<_> = LocalNetwork::new(3)
        .into_iter()
        .map(CountingNet::new)
        .collect();

    let runs: Vec<PartyRun> = std::thread::scope(|scope| {
        networks
            .into_iter()
            .enumerate()
            .map(|(party, net)| {
                let program = &program;
                let shares = &shares;
                let values = &values;
                scope.spawn(move || {
                    let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                    net.reset();
                    let mut next = 0;
                    let inputs = program.classify_inputs(values, |_| {
                        let share = shares[next][party];
                        next += 1;
                        share
                    });

                    let mut driver = Rep3Driver::new_for_run(&net, &mut state, program).unwrap();
                    let preparation_rounds = net.rounds();
                    let first = Machine::run(program, &mut driver, &inputs).unwrap();
                    let first_online_rounds = net.rounds() - preparation_rounds;

                    let before_reuse = net.rounds();
                    let reuse_error = Machine::run(program, &mut driver, &inputs)
                        .unwrap_err()
                        .to_string();
                    let reuse_rounds = net.rounds() - before_reuse;
                    drop(driver);

                    let before_fresh_preparation = net.rounds();
                    let mut fresh_driver =
                        Rep3Driver::new_for_run(&net, &mut state, program).unwrap();
                    let fresh_preparation_rounds = net.rounds() - before_fresh_preparation;
                    let before_fresh_run = net.rounds();
                    let fresh = Machine::run(program, &mut fresh_driver, &inputs).unwrap();
                    let fresh_online_rounds = net.rounds() - before_fresh_run;

                    PartyRun {
                        first,
                        fresh,
                        preparation_rounds,
                        first_online_rounds,
                        reuse_rounds,
                        fresh_preparation_rounds,
                        fresh_online_rounds,
                        reuse_error,
                    }
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect()
    });

    for run in &runs {
        assert_eq!(run.preparation_rounds, 0);
        assert_eq!(run.first_online_rounds, 1);
        assert_eq!(run.reuse_rounds, 0, "reuse rejection must be local");
        assert_eq!(run.fresh_preparation_rounds, 0);
        assert_eq!(run.fresh_online_rounds, 1);
        assert!(run.reuse_error.contains("spent"), "{}", run.reuse_error);
    }

    let first = combine_field_elements(&runs[0].first, &runs[1].first, &runs[2].first);
    let fresh = combine_field_elements(&runs[0].fresh, &runs[1].fresh, &runs[2].fresh);
    let expected_inputs = program.classify_inputs(&values, |value| value);
    let expected = Machine::run(&program, &mut PlainDriver, &expected_inputs).unwrap();
    assert_eq!(first, expected);
    assert_eq!(fresh, expected);
}

#[cfg(feature = "round-counting")]
#[test]
fn execution_error_spends_prepared_driver_without_communication() {
    use circom_mpc_compiler::vm::counting_net::CountingNet;
    use circom_mpc_compiler::vm::driver::plain::PlainDriver;

    struct PartyRun {
        fresh: Vec<Rep3PrimeFieldShare<Fr>>,
        error_rounds: usize,
        reuse_rounds: usize,
        fresh_preparation_rounds: usize,
        fresh_online_rounds: usize,
        execution_error: String,
        reuse_error: String,
    }

    let program = CoCircomCompiler::compile(circuit_path("bench_widesum"), config()).unwrap();
    assert_eq!(program.statistics().precompute_batches, 0);
    let values: Vec<Fr> = (1..=8).map(Fr::from).collect();
    let shares = share_inputs(&program, &values);
    let networks: Vec<_> = LocalNetwork::new(3)
        .into_iter()
        .map(CountingNet::new)
        .collect();

    let runs: Vec<PartyRun> = std::thread::scope(|scope| {
        networks
            .into_iter()
            .enumerate()
            .map(|(party, net)| {
                let program = &program;
                let shares = &shares;
                let values = &values;
                scope.spawn(move || {
                    let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                    net.reset();
                    let mut next = 0;
                    let inputs = program.classify_inputs(values, |_| {
                        let share = shares[next][party];
                        next += 1;
                        share
                    });
                    let mut driver = Rep3Driver::new_for_run(&net, &mut state, program).unwrap();

                    let before_error = net.rounds();
                    let execution_error = Machine::run(program, &mut driver, &[])
                        .unwrap_err()
                        .to_string();
                    let error_rounds = net.rounds() - before_error;
                    let before_reuse = net.rounds();
                    let reuse_error = Machine::run(program, &mut driver, &inputs)
                        .unwrap_err()
                        .to_string();
                    let reuse_rounds = net.rounds() - before_reuse;
                    drop(driver);

                    let before_fresh_preparation = net.rounds();
                    let mut fresh_driver =
                        Rep3Driver::new_for_run(&net, &mut state, program).unwrap();
                    let fresh_preparation_rounds = net.rounds() - before_fresh_preparation;
                    let before_fresh_run = net.rounds();
                    let fresh = Machine::run(program, &mut fresh_driver, &inputs).unwrap();
                    let fresh_online_rounds = net.rounds() - before_fresh_run;

                    PartyRun {
                        fresh,
                        error_rounds,
                        reuse_rounds,
                        fresh_preparation_rounds,
                        fresh_online_rounds,
                        execution_error,
                        reuse_error,
                    }
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect()
    });

    for run in &runs {
        assert_eq!(run.error_rounds, 0);
        assert_eq!(run.reuse_rounds, 0);
        assert_eq!(run.fresh_preparation_rounds, 0);
        assert_eq!(run.fresh_online_rounds, 1);
        assert!(
            run.execution_error.contains("expected 8 inputs, got 0"),
            "{}",
            run.execution_error
        );
        assert!(run.reuse_error.contains("spent"), "{}", run.reuse_error);
    }

    let fresh = combine_field_elements(&runs[0].fresh, &runs[1].fresh, &runs[2].fresh);
    let expected_inputs = program.classify_inputs(&values, |value| value);
    let expected = Machine::run(&program, &mut PlainDriver, &expected_inputs).unwrap();
    assert_eq!(fresh, expected);
}
