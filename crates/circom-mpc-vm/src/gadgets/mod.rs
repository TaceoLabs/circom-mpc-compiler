//! The five precomputation gadgets this compiler knows how to run, both plain and batched rep3 MPC.

pub(crate) mod aliascheck;
pub(crate) mod iszero;
pub(crate) mod num2bits;
pub mod poseidon2;
mod poseidon2_constants;

/// Batched arithmetic-to-binary conversion using the strategy selected on [`Rep3State`].
///
/// `mpc-core` exposes a selector for one value, but its vector conversion API does not. Keeping the
/// selection here lets every VM gadget preserve circuit-wide batching without silently forcing the
/// high-round Direct protocol when the driver requested Yao.
fn a2b_many_selector<N: mpc_net::Network>(
    inputs: &[mpc_core::protocols::rep3::Rep3PrimeFieldShare<ark_bn254::Fr>],
    net: &N,
    state: &mut mpc_core::protocols::rep3::Rep3State,
) -> eyre::Result<Vec<mpc_core::protocols::rep3::Rep3UintShare<ark_bn254::Fr>>> {
    use mpc_core::protocols::rep3::conversion::{self, A2BType};

    match state.a2b_type {
        A2BType::Direct => conversion::a2b_many(inputs, net, state),
        A2BType::Yao => conversion::a2y2b_many(inputs, net, state),
    }
}

/// Shared 3-party rep3 test harness for this module's own unit tests - each gadget's `rep3_trace`
/// is checked against its `plain_trace` twin on the same plaintext input, secret-shared and
/// reconstructed via real `LocalNetwork` execution. Not a value oracle (that lives in the
/// compiler-tests crate) - just proof the two implementations agree. [`run3_counted`] also reports
/// the round count each gadget's own tests pin.
#[cfg(test)]
pub(crate) mod test_support {
    use ark_bn254::Fr;
    use mpc_core::protocols::rep3::conversion::A2BType;
    use mpc_core::protocols::rep3::{
        combine_field_elements, share_field_element, Rep3PrimeFieldShare, Rep3State,
    };
    use mpc_net::local::LocalNetwork;
    use mpc_net::Network;
    use rand::thread_rng;

    use crate::counting_net::CountingNet;

    /// Secret-shares `values` and runs `f` on each of the 3 parties' own network/state/shares,
    /// reconstructing the returned shares back into plaintext. Generic over the network type so the
    /// same closure serves both this and [`run3_counted`].
    fn run_networked<N: Network>(
        networks: Vec<N>,
        values: &[Fr],
        a2b_type: A2BType,
        f: impl Fn(
                &N,
                &mut Rep3State,
                &[Rep3PrimeFieldShare<Fr>],
            ) -> eyre::Result<Vec<Rep3PrimeFieldShare<Fr>>>
            + Sync,
    ) -> (Vec<Fr>, Vec<N>) {
        let mut rng = thread_rng();
        let shares: Vec<[Rep3PrimeFieldShare<Fr>; 3]> = values
            .iter()
            .map(|&v| share_field_element(v, &mut rng))
            .collect();

        let (witnesses, networks): (Vec<Vec<Rep3PrimeFieldShare<Fr>>>, Vec<N>) =
            std::thread::scope(|scope| {
                let handles: Vec<_> = networks
                    .into_iter()
                    .enumerate()
                    .map(|(party, net)| {
                        let shares = &shares;
                        let f = &f;
                        scope.spawn(move || {
                            let mut state = Rep3State::new(&net, a2b_type)
                                .expect("constructing Rep3State from a fresh LocalNetwork does not fail");
                            let own_shares: Vec<_> = shares.iter().map(|s| s[party]).collect();
                            let witness = f(&net, &mut state, &own_shares)
                                .expect("the test closure must succeed on well-formed shares");
                            (witness, net)
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|h| h.join().expect("a test party thread must not panic"))
                    .unzip()
            });

        let [r0, r1, r2]: [Vec<Rep3PrimeFieldShare<Fr>>; 3] = witnesses
            .try_into()
            .unwrap_or_else(|w: Vec<Vec<Rep3PrimeFieldShare<Fr>>>| {
                panic!("expected exactly 3 parties, got {}", w.len())
            });
        (combine_field_elements(&r0, &r1, &r2), networks)
    }

    /// [`run_networked`] over a plain `LocalNetwork`, discarding round counts - the common case for
    /// tests that only check plain/rep3 agreement.
    pub(crate) fn run3(
        values: &[Fr],
        f: impl Fn(
                &LocalNetwork,
                &mut Rep3State,
                &[Rep3PrimeFieldShare<Fr>],
            ) -> eyre::Result<Vec<Rep3PrimeFieldShare<Fr>>>
            + Sync,
    ) -> Vec<Fr> {
        run3_with_a2b(values, A2BType::default(), f)
    }

    /// The explicit-conversion-strategy form of [`run3`].
    pub(crate) fn run3_with_a2b(
        values: &[Fr],
        a2b_type: A2BType,
        f: impl Fn(
                &LocalNetwork,
                &mut Rep3State,
                &[Rep3PrimeFieldShare<Fr>],
            ) -> eyre::Result<Vec<Rep3PrimeFieldShare<Fr>>>
            + Sync,
    ) -> Vec<Fr> {
        run_networked(LocalNetwork::new(3), values, a2b_type, f).0
    }

    /// Per-party round counts for a three-party local execution.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct RoundCounts {
        pub(crate) by_party: [usize; 3],
    }

    impl RoundCounts {
        pub(crate) fn max(self) -> usize {
            self.by_party.into_iter().max().unwrap_or(0)
        }
    }

    /// [`run_networked`] over a [`CountingNet`]-wrapped `LocalNetwork`, returning the maximum of all
    /// three parties' measured round counts for `f` alone. The counter is reset right after
    /// `Rep3State::new`'s one-time correlated-randomness setup (2 rounds, spent before `f` ever
    /// runs), so the count reflects the gadget, not the harness.
    pub(crate) fn run3_counted(
        values: &[Fr],
        f: impl Fn(
                &CountingNet<LocalNetwork>,
                &mut Rep3State,
                &[Rep3PrimeFieldShare<Fr>],
            ) -> eyre::Result<Vec<Rep3PrimeFieldShare<Fr>>>
            + Sync,
    ) -> (Vec<Fr>, usize) {
        let (result, rounds) = run3_counted_with_a2b(values, A2BType::default(), f);
        (result, rounds.max())
    }

    /// The explicit-conversion-strategy form of [`run3_counted`], retaining all three parties'
    /// counters so asymmetric protocols are judged by their actual critical path.
    pub(crate) fn run3_counted_with_a2b(
        values: &[Fr],
        a2b_type: A2BType,
        f: impl Fn(
                &CountingNet<LocalNetwork>,
                &mut Rep3State,
                &[Rep3PrimeFieldShare<Fr>],
            ) -> eyre::Result<Vec<Rep3PrimeFieldShare<Fr>>>
            + Sync,
    ) -> (Vec<Fr>, RoundCounts) {
        let networks: Vec<_> = LocalNetwork::new(3)
            .into_iter()
            .map(CountingNet::new)
            .collect();
        let (result, networks) = run_networked(networks, values, a2b_type, |net, state, shares| {
            net.reset();
            f(net, state, shares)
        });
        let by_party = networks
            .iter()
            .map(CountingNet::rounds)
            .collect::<Vec<_>>()
            .try_into()
            .expect("LocalNetwork always has exactly three parties");
        (result, RoundCounts { by_party })
    }
}
