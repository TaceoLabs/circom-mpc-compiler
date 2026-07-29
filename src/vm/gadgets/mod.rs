//! The five precomputation gadgets this compiler knows how to run, plain (used unconditionally) and
//! batched-MPC (`rep3`, behind the `rep3` feature). See `docs/ARCHITECTURE.md`, "Precomputation".

pub mod aliascheck;
pub mod isequal;
pub mod iszero;
pub mod num2bits;
pub mod poseidon2;
mod poseidon2_constants;

/// Shared 3-party rep3 test harness for this module's own unit tests - each gadget's `rep3_trace`
/// is checked against its `plain_trace` twin on the same plaintext input, secret-shared and
/// reconstructed via real `LocalNetwork` execution. Not a golden-witness oracle (that's
/// `tests/rep3_vm.rs`'s job, once the KATs in `docs/ARCHITECTURE.md`'s known gaps land) - just
/// proof the two implementations agree with each other. When `round-counting` is enabled,
/// [`run3_counted`] also reports the round count each gadget's own tests pin against
/// `docs/ARCHITECTURE.md`'s claims.
#[cfg(all(test, feature = "rep3"))]
pub(crate) mod test_support {
    use ark_bn254::Fr;
    use mpc_core::protocols::rep3::conversion::A2BType;
    use mpc_core::protocols::rep3::{Rep3PrimeFieldShare, Rep3State, combine_field_elements, share_field_element};
    use mpc_net::local::LocalNetwork;
    use mpc_net::Network;
    use rand::thread_rng;

    #[cfg(feature = "round-counting")]
    use crate::vm::counting_net::CountingNet;

    /// Secret-shares `values` and runs `f` on each of the 3 parties' own network/state/shares,
    /// reconstructing the returned shares back into plaintext. Generic over the network type so the
    /// same closure serves both this and [`run3_counted`].
    fn run_networked<N: Network>(
        networks: Vec<N>,
        values: &[Fr],
        f: impl Fn(&N, &mut Rep3State, &[Rep3PrimeFieldShare<Fr>]) -> eyre::Result<Vec<Rep3PrimeFieldShare<Fr>>>
            + Sync,
    ) -> (Vec<Fr>, Vec<N>) {
        let mut rng = thread_rng();
        let shares: Vec<[Rep3PrimeFieldShare<Fr>; 3]> =
            values.iter().map(|&v| share_field_element(v, &mut rng)).collect();

        let (witnesses, networks): (Vec<Vec<Rep3PrimeFieldShare<Fr>>>, Vec<N>) = std::thread::scope(|scope| {
            let handles: Vec<_> = networks
                .into_iter()
                .enumerate()
                .map(|(party, net)| {
                    let shares = &shares;
                    let f = &f;
                    scope.spawn(move || {
                        let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                        let own_shares: Vec<_> = shares.iter().map(|s| s[party]).collect();
                        let witness = f(&net, &mut state, &own_shares).unwrap();
                        (witness, net)
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).unzip()
        });

        let [r0, r1, r2]: [Vec<Rep3PrimeFieldShare<Fr>>; 3] = witnesses.try_into().unwrap();
        (combine_field_elements(&r0, &r1, &r2), networks)
    }

    /// [`run_networked`] over a plain `LocalNetwork`, discarding round counts - the common case for
    /// tests that only check plain/rep3 agreement.
    pub(crate) fn run3(
        values: &[Fr],
        f: impl Fn(&LocalNetwork, &mut Rep3State, &[Rep3PrimeFieldShare<Fr>]) -> eyre::Result<Vec<Rep3PrimeFieldShare<Fr>>>
            + Sync,
    ) -> Vec<Fr> {
        run_networked(LocalNetwork::new(3), values, f).0
    }

    /// [`run_networked`] over a [`CountingNet`]-wrapped `LocalNetwork`, additionally returning party
    /// 0's measured round count for `f` alone - what the per-gadget round-count tests assert
    /// against. The counter is reset right after `Rep3State::new`'s one-time correlated-randomness
    /// setup (2 rounds, spent before `f` ever runs), so the count reflects the gadget, not the
    /// harness.
    #[cfg(feature = "round-counting")]
    pub(crate) fn run3_counted(
        values: &[Fr],
        f: impl Fn(
                &CountingNet<LocalNetwork>,
                &mut Rep3State,
                &[Rep3PrimeFieldShare<Fr>],
            ) -> eyre::Result<Vec<Rep3PrimeFieldShare<Fr>>>
            + Sync,
    ) -> (Vec<Fr>, usize) {
        let networks: Vec<_> = LocalNetwork::new(3).into_iter().map(CountingNet::new).collect();
        let (result, networks) = run_networked(networks, values, |net, state, shares| {
            net.reset();
            f(net, state, shares)
        });
        (result, networks[0].rounds())
    }
}
