//! Shared test harness for running a compiled `Program` under real 3-party rep3.

/// The 3-party in-process rep3 harness shared by the integration tests: secret-share the inputs, run
/// the same `Program` on three threads over `mpc_net::local::LocalNetwork`, and reconstruct the
/// witness.
#[cfg(feature = "local")]
pub mod rep3 {
    use ark_bn254::Fr;
    use circom_mpc_program::{Bank, Program};
    use circom_mpc_vm::Vm;
    use mpc_core::protocols::rep3::{
        Rep3PrimeFieldShare, Rep3State, combine_field_elements, conversion::A2BType,
        share_field_element,
    };
    use mpc_net::local::LocalNetwork;

    /// Stitches one party's opened `public_inputs` prefix (identical across parties) back together
    /// with the three parties' secret-shared remainders, reconstructing the full flat witness in
    /// original witness order.
    fn combine_witness(
        w0: circom_mpc_vm::Witness<Rep3PrimeFieldShare<Fr>>,
        w1: circom_mpc_vm::Witness<Rep3PrimeFieldShare<Fr>>,
        w2: circom_mpc_vm::Witness<Rep3PrimeFieldShare<Fr>>,
    ) -> Vec<Fr> {
        let mut full = w0.public_inputs;
        full.extend(combine_field_elements(
            &w0.witness,
            &w1.witness,
            &w2.witness,
        ));
        full
    }

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

    /// [`run_witness`] with caller-supplied input shares, for callers that reuse the same shares
    /// across repeated runs instead of resharing every time.
    pub fn run_witness_with_shares(
        program: &Program,
        values: &[Fr],
        shares: &[[Rep3PrimeFieldShare<Fr>; 3]],
    ) -> Vec<Fr> {
        let networks = LocalNetwork::new(3);
        let witnesses: Vec<_> = std::thread::scope(|scope| {
            networks
                .into_iter()
                .enumerate()
                .map(|(party, net)| {
                    scope.spawn(move || {
                        let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                        let vm = Vm::rep3(program, &net, &mut state).unwrap();
                        let mut next = 0;
                        let inputs = program
                            .classify_inputs(values, |_v| {
                                let s = shares[next][party];
                                next += 1;
                                s
                            })
                            .unwrap();
                        vm.run(&inputs).unwrap()
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect()
        });

        let [w0, w1, w2] = witnesses
            .try_into()
            .unwrap_or_else(|_| unreachable!("exactly three parties"));
        combine_witness(w0, w1, w2)
    }

    /// [`run_witness`], additionally reporting each party's network rounds, split into
    /// (driver preparation, online execution). Online now includes the closing `open` of the
    /// public-witness prefix that `Vm::run` performs internally.
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
        let results: Vec<_> = std::thread::scope(|scope| {
            networks
                .into_iter()
                .enumerate()
                .map(|(party, net)| {
                    let shares = &shares;
                    scope.spawn(move || {
                        let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                        net.reset();
                        let vm = Vm::rep3(program, &net, &mut state).unwrap();
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
                        let witness = vm.run(&inputs).unwrap();
                        (witness, preparation, net.rounds())
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect()
        });

        let [(w0, p0, o0), (w1, p1, o1), (w2, p2, o2)] = results
            .try_into()
            .unwrap_or_else(|_| unreachable!("exactly three parties"));
        (combine_witness(w0, w1, w2), [p0, p1, p2], [o0, o1, o2])
    }
}
