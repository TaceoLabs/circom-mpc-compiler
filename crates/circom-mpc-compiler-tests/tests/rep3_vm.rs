//! Proves `Rep3Driver` against real 3-party rep3 execution: secret-share an input, run the same
//! `Program` on three threads over `mpc_net::local::LocalNetwork`, reconstruct the witness, and
//! compare against the plain driver's - this is what proves the rep3 driver agrees with the plain
//! one on genuinely secret-shared data, not just in the clear. `tests/proving.rs`'s prove+verify
//! tests are the value oracle for both drivers.
use ark_bn254::Fr;
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::rep3::{Rep3PrimeFieldShare, Rep3State, combine_field_elements};
use mpc_net::local::LocalNetwork;

use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig};
use circom_mpc_compiler_tests::fixtures::rep3::{run_witness, share_inputs};
use circom_mpc_vm::Machine;
use circom_mpc_vm::driver::rep3::Rep3Driver;

mod common;

use common::{circuit_path, libs_path};

fn config() -> CompilerConfig {
    let mut config = CompilerConfig::default();
    config.link_library.push(libs_path());
    config
}

/// Staged batching under a real network - the test that proves batch interleaving works.
/// `PlainDriver` cannot detect a mis-ordered batch (its `reshare` is the identity and slots start
/// zeroed); against three real parties the same bug deadlocks or diverges.
#[test]
fn staged_gadget_matches_the_plain_driver_under_rep3() {
    use circom_mpc_vm::driver::plain::PlainDriver;

    let program =
        CoCircomCompiler::compile(circuit_path("gadget_staged_test"), config()).unwrap();
    assert_eq!(
        program.statistics().gadget_batches,
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
    use circom_mpc_vm::driver::plain::PlainDriver;

    let program =
        CoCircomCompiler::compile(circuit_path("gadget_iszero_reveal_test"), config())
            .unwrap();
    assert_eq!(program.statistics().gadget_batches, 1);
    assert_eq!(program.statistics().fused_is_zero_reveal_batches, 1);
    assert_eq!(program.statistics().gadget_sites, 2);

    let values = [Fr::from(0u64), Fr::from(7u64)];
    let plain = {
        let inputs = program.classify_inputs(&values, |v| v);
        Machine::run(&program, &mut PlainDriver, &inputs).unwrap()
    };
    assert_eq!(run_witness(&program, &values), plain, "inputs {values:?}");
}

#[test]
fn fused_isequal_reveal_matches_plain_for_shared_and_mixed_operands() {
    use circom_mpc_vm::driver::plain::PlainDriver;

    let program =
        CoCircomCompiler::compile(circuit_path("gadget_isequal_reveal_test"), config())
            .unwrap();
    assert_eq!(program.statistics().gadget_batches, 1);
    assert_eq!(program.statistics().fused_is_zero_reveal_batches, 1);
    assert_eq!(program.statistics().gadget_sites, 3);

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

#[test]
fn fused_iszero_reveal_costs_one_online_round() {
    use circom_mpc_compiler_tests::fixtures::rep3::run_witness_counted;

    let program =
        CoCircomCompiler::compile(circuit_path("gadget_iszero_reveal_test"), config())
            .unwrap();
    let (_, _, online) = run_witness_counted(&program, &[Fr::from(0u64), Fr::from(7u64)]);
    assert_eq!(online, [1, 1, 1]);
}

#[test]
fn three_fused_isequal_reveal_sites_cost_one_online_round() {
    use circom_mpc_compiler_tests::fixtures::rep3::run_witness_counted;

    let program =
        CoCircomCompiler::compile(circuit_path("gadget_isequal_reveal_test"), config())
            .unwrap();
    let values = [Fr::from(4u64), Fr::from(10u64), Fr::from(4u64)];
    let (_, _, online) = run_witness_counted(&program, &values);
    assert_eq!(online, [1, 1, 1]);
}

#[test]
fn wide_round_vector_products_match_the_plain_driver() {
    use circom_mpc_vm::driver::plain::PlainDriver;

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
fn all_public_gadget_uses_the_plain_path_under_rep3() {
    use circom_mpc_compiler::OptLevel;
    use circom_mpc_vm::driver::plain::PlainDriver;

    let mut cfg = config();
    cfg.opt_level = OptLevel::O2;
    let program = CoCircomCompiler::compile(circuit_path("gadget_public_test"), cfg).unwrap();
    let values = [Fr::from(0u64), Fr::from(9u64)];
    let plain = {
        let inputs = program.classify_inputs(&values, |v| v);
        Machine::run(&program, &mut PlainDriver, &inputs).unwrap()
    };
    assert_eq!(run_witness(&program, &values), plain);
}

#[test]
fn prepared_driver_is_one_shot_and_fresh_driver_reuses_network_and_state() {
    use circom_mpc_vm::counting_net::CountingNet;
    use circom_mpc_vm::driver::plain::PlainDriver;

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
    assert_eq!(program.statistics().gadget_batches, 0);
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

#[test]
fn execution_error_spends_prepared_driver_without_communication() {
    use circom_mpc_vm::counting_net::CountingNet;
    use circom_mpc_vm::driver::plain::PlainDriver;

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
    assert_eq!(program.statistics().gadget_batches, 0);
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

/// Precomputing a Poseidon2 permutation with [`circom_mpc_vm::gadgets::poseidon2::Poseidon2Service`]
/// and handing the trace to the host removes that permutation's rounds from the proof run
/// entirely, which is the whole point of `TACEO_PRECOMPUTATION_Poseidon2`. The precompute phase
/// still pays for the permutation once (3 preprocessing + `8 + partial_rounds(t)` online), but the
/// proof run's own online round count for it drops to zero, and the reconstructed witness still
/// matches the ordinary driver-serviced `Poseidon2` circuit run under `PlainDriver`.
#[test]
fn precomputing_poseidon2_removes_its_rounds_from_the_proof_run() {
    use circom_mpc_vm::GadgetPrecomputation;
    use circom_mpc_vm::counting_net::CountingNet;
    use circom_mpc_vm::driver::plain::PlainDriver;
    use circom_mpc_vm::gadgets::poseidon2::Poseidon2Service;

    let program =
        CoCircomCompiler::compile(circuit_path("precomputation_poseidon2_test"), config()).unwrap();
    let values = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let expected = {
        let baseline =
            CoCircomCompiler::compile(circuit_path("gadget_poseidon2_test"), config())
                .unwrap();
        let inputs = baseline.classify_inputs(&values, |v| v);
        Machine::run(&baseline, &mut PlainDriver, &inputs).unwrap()
    };

    let shares = share_inputs(&program, &values);
    let networks: Vec<_> = LocalNetwork::new(3)
        .into_iter()
        .map(CountingNet::new)
        .collect();

    struct PartyRun {
        witness: Vec<Rep3PrimeFieldShare<Fr>>,
        precompute_rounds: usize,
        online_rounds: usize,
    }

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
                    let my_shares: Vec<Rep3PrimeFieldShare<Fr>> =
                        shares.iter().map(|s| s[party]).collect();

                    // Precompute phase: run the permutation once, up front, over its own network
                    // rounds - exactly what a host would do before the values it hashes even
                    // exist as circuit inputs (e.g. before revealing a new leaf commitment to
                    // build a Merkle path from).
                    net.reset();
                    let mut service = Poseidon2Service::new(3, 1, &net, &mut state).unwrap();
                    let states: Vec<_> = my_shares
                        .iter()
                        .copied()
                        .map(circom_mpc_vm::InputValue::Secret)
                        .collect();
                    let traces = service.trace(3, &states, &net, &mut state).unwrap();
                    service.finish().unwrap();
                    let precompute_rounds = net.rounds();

                    let mut precomputation = GadgetPrecomputation::new();
                    precomputation.push_batch(traces);

                    // The proof run: preparing `Rep3Driver` derives a zero Poseidon2 mask budget
                    // (its only Poseidon2 batch is host-precomputed, not driver-serviced), and
                    // running it makes no further network calls for that site at all.
                    net.reset();
                    let mut driver = Rep3Driver::new_for_run(&net, &mut state, program).unwrap();
                    let mut next = 0;
                    let inputs = program
                        .classify_inputs(values, |_v| {
                            let s = shares[next][party];
                            next += 1;
                            s
                        })
                        .unwrap();
                    let witness = Machine::run_with_precomputation(
                        program,
                        &mut driver,
                        &inputs,
                        precomputation,
                    )
                    .unwrap();
                    let online_rounds = net.rounds();

                    PartyRun {
                        witness,
                        precompute_rounds,
                        online_rounds,
                    }
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect()
    });

    for run in &runs {
        assert_eq!(
            run.precompute_rounds,
            3 + 8 + 56,
            "Poseidon2(t=3) has 56 partial rounds"
        );
        assert_eq!(
            run.online_rounds, 0,
            "no driver-serviced Poseidon2 batch should remain in the proof run"
        );
    }
    let got = combine_field_elements(&runs[0].witness, &runs[1].witness, &runs[2].witness);
    assert_eq!(got, expected);
}

/// The same setup as [`precomputing_poseidon2_removes_its_rounds_from_the_proof_run`], but the
/// precomputed site's own input mixes Public and Shared - `a` is a genuinely public value, so
/// [`Poseidon2Service::trace`] promotes it to a trivial share (no network cost) instead of the
/// host secret-sharing it.
#[test]
fn precomputed_poseidon2_promotes_a_public_input_to_a_trivial_share() {
    use circom_mpc_vm::GadgetPrecomputation;
    use circom_mpc_vm::InputValue;
    use circom_mpc_vm::driver::plain::PlainDriver;
    use circom_mpc_vm::gadgets::poseidon2::Poseidon2Service;

    let program = CoCircomCompiler::compile(circuit_path("precomputation_mixed_domain_test"), config())
        .unwrap();
    let values = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let expected = {
        let baseline =
            CoCircomCompiler::compile(circuit_path("gadget_poseidon2_mixed_domain_test"), config())
                .unwrap();
        let inputs = baseline.classify_inputs(&values, |v| v);
        Machine::run(&baseline, &mut PlainDriver, &inputs).unwrap()
    };

    // `share_inputs` only secret-shares `Bank::Shared` inputs - `a` is `Bank::Public`, so `shares`
    // covers just `b` and `c`, in that order.
    let shares = share_inputs(&program, &values);
    assert_eq!(shares.len(), 2, "only b and c are Shared");

    let runs: Vec<Vec<Rep3PrimeFieldShare<Fr>>> = std::thread::scope(|scope| {
        LocalNetwork::new(3)
            .into_iter()
            .enumerate()
            .map(|(party, net)| {
                let program = &program;
                let shares = &shares;
                let values = &values;
                scope.spawn(move || {
                    let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                    let my_shares: Vec<Rep3PrimeFieldShare<Fr>> =
                        shares.iter().map(|s| s[party]).collect();

                    let mut service = Poseidon2Service::new(3, 1, &net, &mut state).unwrap();
                    let states = [
                        InputValue::Public(values[0]),
                        InputValue::Secret(my_shares[0]),
                        InputValue::Secret(my_shares[1]),
                    ];
                    let traces = service.trace(3, &states, &net, &mut state).unwrap();
                    service.finish().unwrap();

                    let mut precomputation = GadgetPrecomputation::new();
                    precomputation.push_batch(traces);

                    let mut driver = Rep3Driver::new_for_run(&net, &mut state, program).unwrap();
                    let mut next = 0;
                    let inputs = program
                        .classify_inputs(values, |_v| {
                            let s = shares[next][party];
                            next += 1;
                            s
                        })
                        .unwrap();
                    Machine::run_with_precomputation(program, &mut driver, &inputs, precomputation)
                        .unwrap()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect()
    });

    let got = combine_field_elements(&runs[0], &runs[1], &runs[2]);
    assert_eq!(got, expected);
}
