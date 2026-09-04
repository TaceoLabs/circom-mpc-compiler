//! Shared test/bench harness for running a compiled `Program` under real 3-party rep3. Lives in
//! the library because tests and benches are separate compilation units that cannot share a
//! `tests/common` module.

/// `CompilerConfig::mpc_public_inputs` for the vendored merces server main: the signal names
/// merces' own MPC implementation passes as cleartext rather than secret-shared - `sender`,
/// `receiver`, their Merkle paths, `depth`, `isDeposit`, `isWithdraw` (see the `// Public input`
/// comments on `TransferBatchedCompressedArity4` in `merces/server.circom` and
/// `circom/README.md` in the merces repo). Deliberately excludes `amount`: merces passes it
/// cleartext for a pure deposit/withdraw but shared for a transfer, and one circuit serves all
/// three, so it cannot be declared public here without being wrong for transfers.
pub fn merces_mpc_public_inputs() -> Vec<String> {
    [
        "sender",
        "receiver",
        "senderPath",
        "receiverPath",
        "depth",
        "isDeposit",
        "isWithdraw",
    ]
    .map(String::from)
    .to_vec()
}

/// Host-precomputation for `TACEO_PRECOMPUTATION_Poseidon2` sites, e.g. the merces circuits'
/// commit sites (`circuits/merces/oblivious_vector/hash.circom`). A circuit with no such sites
/// gets an empty [`circom_mpc_vm::GadgetPrecomputation`], which `Machine::run_with_precomputation`
/// treats exactly like `Machine::run` - so one code path covers both merces and non-merces cases.
///
/// Not gated on `feature = "local"` (unlike the [`rep3`] module) so a `--no-default-features
/// --features tls` bench binary can use the `rep3` half over a real network too.
pub mod precomputation {
    use ark_bn254::Fr;
    use ark_ff::{PrimeField, UniformRand};
    use circom_mpc_program::{GadgetKind, InputValue, Program};
    use circom_mpc_vm::{GadgetPrecomputation, SiteTrace, gadgets::poseidon2};
    use mpc_core::protocols::rep3::Rep3PrimeFieldShare;
    use rand::Rng;

    /// The Poseidon2 width every merces commit site uses.
    pub const COMMIT_T: usize = 4;

    /// `commitDs()` from `circuits/merces/oblivious_vector/hash.circom`: the ASCII bytes
    /// `"TACEO-Merces-Commit"` read as a big-endian integer.
    pub fn commit_domain_separator() -> Fr {
        Fr::from_be_bytes_mod_order(b"TACEO-Merces-Commit")
    }

    /// Site counts per `BatchKind::PrecomputedPoseidon2` batch, in the order
    /// `Machine::run_with_precomputation` consumes them (`Program::precomputed_batches` walks the
    /// instruction stream). Errors if a batch isn't width-4 Poseidon2 - a width change must not be
    /// silently mis-sized.
    pub fn site_counts(program: &Program) -> eyre::Result<Vec<usize>> {
        program
            .precomputed_batches()?
            .into_iter()
            .map(|batch| match batch.kind {
                GadgetKind::Poseidon2 { t } if t.get() == COMMIT_T => Ok(batch.sites),
                other => eyre::bail!(
                    "expected every host-precomputed batch to be Poseidon2(t={COMMIT_T}), found {other:?}"
                ),
            })
            .collect()
    }

    /// `4 * sites` entries - `[Secret(value), Secret(index), Secret(r), Public(DS)]` per site,
    /// values drawn from `rng`. `share` turns a cleartext value into whatever this driver's share
    /// type is - `|v| v` for the plain path, "split with a shared seeded rng and keep my index"
    /// for rep3.
    pub fn commit_states<S>(
        sites: usize,
        rng: &mut impl Rng,
        mut share: impl FnMut(Fr) -> S,
    ) -> Vec<InputValue<S>> {
        let ds = commit_domain_separator();
        (0..sites)
            .flat_map(|_| {
                let value = Fr::rand(rng);
                let index = Fr::rand(rng);
                let r = Fr::rand(rng);
                [
                    InputValue::Secret(share(value)),
                    InputValue::Secret(share(index)),
                    InputValue::Secret(share(r)),
                    InputValue::Public(ds),
                ]
            })
            .collect()
    }

    /// One party's view of [`commit_states`]-shaped inputs built from pre-shared `[share; 3]`
    /// triples, three per site in `[value, index, r]` order.
    pub fn commit_states_for_party(
        triples: &[[Rep3PrimeFieldShare<Fr>; 3]],
        party: usize,
    ) -> Vec<InputValue<Rep3PrimeFieldShare<Fr>>> {
        let ds = commit_domain_separator();
        let (sites, _remainder) = triples.as_chunks::<3>();
        sites
            .iter()
            .flat_map(|site| {
                let [value, index, r] = std::array::from_fn(|j| InputValue::Secret(site[j][party]));
                [value, index, r, InputValue::Public(ds)]
            })
            .collect()
    }

    /// Chops one flat, site-major trace vector into per-batch `push_batch` calls, in
    /// `site_counts` order.
    pub fn queue<S>(
        counts: &[usize],
        traces: Vec<SiteTrace<S>>,
    ) -> eyre::Result<GadgetPrecomputation<S>> {
        eyre::ensure!(
            traces.len() == counts.iter().sum::<usize>(),
            "{} precomputed traces but the program's batches need {}",
            traces.len(),
            counts.iter().sum::<usize>()
        );
        let mut traces = traces.into_iter();
        let mut queue = GadgetPrecomputation::new();
        for &count in counts {
            queue.push_batch(traces.by_ref().take(count).collect());
        }
        Ok(queue)
    }

    /// Plain-driver precomputation: `poseidon2::plain_trace` over seeded-random commit states,
    /// queued in `program`'s batch order. Needed even for the plain baseline - once a circuit's
    /// commit sites are host-precomputed, `Machine::run` (without a precomputation queue) errors
    /// on them.
    pub fn plain(program: &Program, rng: &mut impl Rng) -> eyre::Result<GadgetPrecomputation<Fr>> {
        let counts = site_counts(program)?;
        let sites: usize = counts.iter().sum();
        // `plain_trace`/`Poseidon2Service` both reject a zero-element call outright (there is no
        // width to check it against) - a circuit with no host-precomputed sites just gets an
        // empty queue, which `run_with_precomputation` treats exactly like `Machine::run`.
        if sites == 0 {
            return Ok(GadgetPrecomputation::new());
        }
        let states = commit_states(sites, rng, |v| v);
        let traces = poseidon2::plain_trace(COMMIT_T, &states)?;
        queue(&counts, traces)
    }

    /// Rep3-driver precomputation: one [`poseidon2::Poseidon2Service`] over every commit site
    /// (3 preprocessing rounds regardless of site count), one `trace` call, then `open_vec` of
    /// each site's commitment - merces' `Engine::commit_batch` opens the commitments too, so that
    /// round belongs to this phase's cost. Returns the traces flat, site-major; chop them into a
    /// [`GadgetPrecomputation`] with [`queue`] once `counts` is known.
    pub fn rep3<N: mpc_net::Network>(
        sites: usize,
        states: &[InputValue<Rep3PrimeFieldShare<Fr>>],
        net: &N,
        rep3_state: &mut mpc_core::protocols::rep3::Rep3State,
    ) -> eyre::Result<Vec<SiteTrace<Rep3PrimeFieldShare<Fr>>>> {
        // See `plain`'s matching guard: a circuit with no host-precomputed sites must not call
        // into a zero-element Poseidon2 trace, which rejects that outright.
        if sites == 0 {
            return Ok(Vec::new());
        }
        let mut service = poseidon2::Poseidon2Service::new(COMMIT_T, sites, net, rep3_state)?;
        let traces = service.trace(COMMIT_T, states, net, rep3_state)?;
        service.finish()?;
        let outputs: Vec<_> = traces.iter().map(|trace| trace.output[0]).collect();
        // The engine opens the commitments as part of this phase - not needed by the witness
        // extension that follows (the circuit's own `TACEO_REVEAL` opens them again in-circuit),
        // but skipping it here would understate the phase's real network cost.
        let _commitments = mpc_core::protocols::rep3::arithmetic::open_vec(&outputs, net)?;
        Ok(traces)
    }
}

/// The 3-party in-process rep3 harness shared by tests and benches: secret-share the inputs, run
/// the same `Program` on three threads over `mpc_net::local::LocalNetwork`, and reconstruct the
/// witness.
#[cfg(feature = "local")]
pub mod rep3 {
    use ark_bn254::Fr;
    use circom_mpc_program::{Bank, Program};
    use circom_mpc_vm::{Machine, driver::rep3::Rep3Driver};
    use mpc_core::protocols::rep3::{
        Rep3PrimeFieldShare, Rep3State, combine_field_elements, conversion::A2BType,
        share_field_element,
    };
    use mpc_net::local::LocalNetwork;

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

    /// [`run_witness_with_shares`], for a program with host-precomputed `TACEO_PRECOMPUTATION_
    /// Poseidon2` sites (e.g. the merces circuits): each party also secret-shares
    /// `commit_triples`-worth of commit-site precomputation states, precomputes its own trace via
    /// [`crate::fixtures::precomputation::rep3`], then runs `Machine::run_with_precomputation`
    /// with the resulting queue.
    pub fn run_witness_with_precomputation(
        program: &Program,
        values: &[Fr],
        shares: &[[Rep3PrimeFieldShare<Fr>; 3]],
        commit_triples: &[[Rep3PrimeFieldShare<Fr>; 3]],
    ) -> Vec<Fr> {
        use crate::fixtures::precomputation;

        let site_counts = precomputation::site_counts(program).expect("valid precomputed batches");
        let total_sites: usize = site_counts.iter().sum();

        let networks = LocalNetwork::new(3);
        let witnesses: Vec<Vec<Rep3PrimeFieldShare<Fr>>> = std::thread::scope(|scope| {
            networks
                .into_iter()
                .enumerate()
                .map(|(party, net)| {
                    let site_counts = &site_counts;
                    scope.spawn(move || {
                        let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                        let commit_states =
                            precomputation::commit_states_for_party(commit_triples, party);
                        let traces =
                            precomputation::rep3(total_sites, &commit_states, &net, &mut state)
                                .unwrap();
                        let queue = precomputation::queue(site_counts, traces).unwrap();

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
                        Machine::run_with_precomputation(program, &mut driver, &inputs, queue)
                            .unwrap()
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
