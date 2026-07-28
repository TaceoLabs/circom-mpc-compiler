//! The four `TACEO_PRECOMPUTATION_*` gadgets this compiler's precompute phase knows how to run,
//! plain (used unconditionally) and batched-MPC (`rep3`, behind the `rep3` feature). See
//! `docs/ARCHITECTURE.md`, "Precomputation".

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
/// proof the two implementations agree with each other.
#[cfg(all(test, feature = "rep3"))]
pub(crate) mod test_support {
    use ark_bn254::Fr;
    use mpc_core::protocols::rep3::conversion::A2BType;
    use mpc_core::protocols::rep3::{Rep3PrimeFieldShare, Rep3State, combine_field_elements, share_field_element};
    use mpc_net::local::LocalNetwork;
    use rand::thread_rng;

    /// Secret-shares `values` and runs `f` on each of the 3 parties' own network/state/shares,
    /// reconstructing the returned shares back into plaintext.
    pub(crate) fn run3(
        values: &[Fr],
        f: impl Fn(&LocalNetwork, &mut Rep3State, &[Rep3PrimeFieldShare<Fr>]) -> eyre::Result<Vec<Rep3PrimeFieldShare<Fr>>>
            + Sync,
    ) -> Vec<Fr> {
        let mut rng = thread_rng();
        let shares: Vec<[Rep3PrimeFieldShare<Fr>; 3]> =
            values.iter().map(|&v| share_field_element(v, &mut rng)).collect();

        let networks = LocalNetwork::new(3);
        let results: Vec<Vec<Rep3PrimeFieldShare<Fr>>> = std::thread::scope(|scope| {
            networks
                .into_iter()
                .enumerate()
                .map(|(party, net)| {
                    let shares = &shares;
                    let f = &f;
                    scope.spawn(move || {
                        let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                        let own_shares: Vec<_> = shares.iter().map(|s| s[party]).collect();
                        f(&net, &mut state, &own_shares).unwrap()
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect()
        });

        let [r0, r1, r2]: [Vec<Rep3PrimeFieldShare<Fr>>; 3] = results.try_into().unwrap();
        combine_field_elements(&r0, &r1, &r2)
    }
}
