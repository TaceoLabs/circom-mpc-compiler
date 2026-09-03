//! Shared test/bench harness for running a compiled `Program` under real 3-party rep3. Lives in
//! the library because tests and benches are separate compilation units that cannot share a
//! `tests/common` module.

/// The 3-party in-process rep3 harness shared by tests and benches: secret-share the inputs, run
/// the same `Program` on three threads over `mpc_net::local::LocalNetwork`, and reconstruct the
/// witness.
#[cfg(feature = "local")]
pub mod rep3 {
    use ark_bn254::Fr;
    use mpc_core::protocols::rep3::conversion::A2BType;
    use mpc_core::protocols::rep3::{
        combine_field_elements, share_field_element, Rep3PrimeFieldShare, Rep3State,
    };
    use mpc_net::local::LocalNetwork;

    use circom_mpc_program::{Bank, Program};
    use circom_mpc_vm::driver::rep3::Rep3Driver;
    use circom_mpc_vm::Machine;

    /// One `[share; 3]` triple per `Shared`-domain input, in the order `Program::classify_inputs`
    /// visits them - each party takes its own component.
    pub fn share_inputs(program: &Program, values: &[Fr]) -> Vec<[Rep3PrimeFieldShare<Fr>; 3]> {
        let mut rng = rand::thread_rng();
        program
            .input_domains()
            .iter()
            .zip(values)
            .filter(|(bank, _)| matches!(bank, Bank::Shared))
            .map(|(_, &v)| share_field_element(v, &mut rng))
            .collect()
    }

    /// Runs `values` through real 3-party rep3 and returns the reconstructed witness.
    pub fn run_witness(program: &Program, values: &[Fr]) -> Vec<Fr> {
        run_witness_with_shares(program, values, &share_inputs(program, values))
    }

    /// [`run_witness`] with caller-supplied input shares (benches share once across iterations).
    pub fn run_witness_with_shares(
        program: &Program,
        values: &[Fr],
        shares: &[[Rep3PrimeFieldShare<Fr>; 3]],
    ) -> Vec<Fr> {
        let networks = LocalNetwork::new(3);
        let witnesses: Vec<Vec<Rep3PrimeFieldShare<Fr>>> = std::thread::scope(|scope| {
            networks
                .into_iter()
                .enumerate()
                .map(|(party, net)| {
                    scope.spawn(move || {
                        let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                        let mut driver =
                            Rep3Driver::new_for_run(&net, &mut state, program).unwrap();
                        let mut next = 0;
                        let inputs = program
                            .classify_inputs(values, |_v| {
                                let s = shares[next][party];
                                next += 1;
                                s
                            })
                            .unwrap();
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

    /// [`run_witness`], additionally reporting each party's network rounds, split into
    /// (driver preparation, online execution).
    pub fn run_witness_counted(
        program: &Program,
        values: &[Fr],
    ) -> (Vec<Fr>, [usize; 3], [usize; 3]) {
        use circom_mpc_vm::counting_net::CountingNet;

        let shares = share_inputs(program, values);
        let networks: Vec<_> = LocalNetwork::new(3)
            .into_iter()
            .map(CountingNet::new)
            .collect();
        let results: Vec<(Vec<Rep3PrimeFieldShare<Fr>>, usize, usize)> =
            std::thread::scope(|scope| {
                networks
                    .into_iter()
                    .enumerate()
                    .map(|(party, net)| {
                        let shares = &shares;
                        scope.spawn(move || {
                            let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                            net.reset();
                            let mut driver =
                                Rep3Driver::new_for_run(&net, &mut state, program).unwrap();
                            let preparation = net.rounds();
                            net.reset();
                            let mut next = 0;
                            let inputs = program
                                .classify_inputs(values, |_v| {
                                    let s = shares[next][party];
                                    next += 1;
                                    s
                                })
                                .unwrap();
                            let witness = Machine::run(program, &mut driver, &inputs).unwrap();
                            (witness, preparation, net.rounds())
                        })
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .map(|h| h.join().unwrap())
                    .collect()
            });

        let [(w0, p0, o0), (w1, p1, o1), (w2, p2, o2)]: [_; 3] = results
            .try_into()
            .unwrap_or_else(|_| unreachable!("exactly three parties"));
        (
            combine_field_elements(&w0, &w1, &w2),
            [p0, p1, p2],
            [o0, o1, o2],
        )
    }
}
