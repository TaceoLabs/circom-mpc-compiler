//! Real protocol inputs for the vendored `circuits/merces/` circuits, shared by
//! `tests/merces.rs`, `benches/`, and `examples/merces.rs`. Lives in the library because tests,
//! benches and examples are separate compilation units that cannot share a `tests/common` module.
//!
//! `inputs/<main>_<scenario>.json` are real merces protocol values (not placeholders), copied
//! verbatim from merces' own `circom/main/inputs/` and baked in with `include_str!`. Real values
//! matter: witness extension runs on anything, but a *proof* additionally needs every `===` in the
//! circuit to hold (flag exclusivity, genuine index bits, and transfer root-linking, which needs a
//! real Merkle setup).

use std::collections::BTreeMap;

use ark_bn254::Fr;
use ark_ff::{PrimeField, Zero};
use num_bigint::BigUint;

use circom_mpc_compiler::{CompilerConfig, OptLevel};
use circom_mpc_program::InputSignal;

/// The compiler configuration for the vendored merces circuits, mirroring how merces itself
/// compiles them (`-l circom/node_modules -l circom`): `circuits/node_modules/` resolves circomlib plus
/// the vendored `taceo/` subtree, `circuits/merces/` the `merces/`/`oblivious_vector/`
/// cross-references. The circuits are `pragma circom 2.2.2` verbatim.
pub fn merces_config() -> CompilerConfig {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    CompilerConfig {
        version: "2.2.2".to_owned(),
        link_library: vec![
            format!("{root}/circuits/node_modules/").into(),
            format!("{root}/circuits/merces/").into(),
        ],
        opt_level: OptLevel::O2,
        mpc_public_inputs: merces_mpc_public_inputs(),
        ..CompilerConfig::default()
    }
}

/// `circuits/merces/main/<main>.circom`.
pub fn merces_main_path(main: &str) -> String {
    format!(
        "{}/circuits/merces/main/{main}.circom",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../..")
    )
}

/// Reads a zkey for proving, in whichever of the two formats this repo uses: `.arks.zkey` is the
/// merces ceremony key (ark-serialized, uncompressed - see `tests/merces.rs`'s `ceremony_zkey`),
/// anything else is a plain snarkjs zkey (`tests/proving.rs`'s format, e.g.
/// `kats/proving/multiplier3.zkey`). Shared by `examples/merces.rs` and `merces-net`.
#[cfg(feature = "prove")]
pub mod zkey {
    use std::io::BufReader;

    use ark_bn254::{Bn254, Fr};
    use ark_serialize::{CanonicalDeserialize, Compress, Validate};
    use co_groth16::{ConstraintMatrices, ProvingKey};

    /// Streams the file rather than `fs::read`-ing it first: a batch32 ceremony key is several
    /// hundred MB, and reading it into a `Vec` before deserializing would hold two copies at once.
    pub fn read(path: &str) -> eyre::Result<(ConstraintMatrices<Fr>, ProvingKey<Bn254>)> {
        let file = std::fs::File::open(path).map_err(|e| eyre::eyre!("opening {path}: {e}"))?;
        Ok(if path.ends_with(".arks.zkey") {
            // `Validate::No`: validating hundreds of MB of group elements costs far more than the
            // proof itself, and a bad zkey shows up immediately as a proof that fails to verify.
            circom_types::groth16::ArkZkey::<Bn254>::deserialize_with_mode(
                BufReader::new(file),
                Compress::No,
                Validate::No,
            )
            .map_err(|e| eyre::eyre!("parsing {path}: {e}"))?
            .into_inner()
        } else {
            circom_types::groth16::Zkey::<Bn254>::from_reader(file, circom_types::CheckElement::No)
                .map_err(|e| eyre::eyre!("parsing {path}: {e}"))?
                .into()
        })
    }
}

/// Host-side Poseidon2 commit precomputation for the merces circuits, mirroring merces' own
/// `Engine::commit_batch`: one width-4 site per `Commit1`/`Commit2` call
/// (`circuits/merces/oblivious_vector/hash.circom`), `[value, index, r, commitDs()]` with the
/// first three secret and the domain separator public. Not feature-gated - `merces-net` builds
/// `--no-default-features --features tls`, without `rep3` below.
pub mod precomputation {
    use ark_bn254::Fr;
    use ark_ff::{PrimeField, UniformRand};
    use mpc_core::protocols::rep3::Rep3PrimeFieldShare;
    use rand::Rng;

    use circom_mpc_program::{GadgetKind, InputValue, Program};
    use circom_mpc_vm::gadgets::poseidon2;
    use circom_mpc_vm::{GadgetPrecomputation, SiteTrace};

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
    /// for rep3 (see `merces-net.rs`'s own input-sharing trick).
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
        triples
            .chunks_exact(3)
            .flat_map(|site| {
                let [value, index, r] = std::array::from_fn(|j| InputValue::Secret(site[j][party]));
                [value, index, r, InputValue::Public(ds)]
            })
            .collect()
    }

    /// Chops one flat, site-major trace vector into per-batch `push_batch` calls, in
    /// `site_counts` order.
    pub fn queue<S>(counts: &[usize], traces: Vec<SiteTrace<S>>) -> eyre::Result<GadgetPrecomputation<S>> {
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
    ///
    /// Not gated on `feature = "local"` (unlike `fixtures::rep3`) so `merces-net`'s
    /// `--no-default-features --features tls` build can call it too.
    pub fn rep3<N: mpc_net::Network>(
        sites: usize,
        states: &[InputValue<mpc_core::protocols::rep3::Rep3PrimeFieldShare<Fr>>],
        net: &N,
        rep3_state: &mut mpc_core::protocols::rep3::Rep3State,
    ) -> eyre::Result<Vec<SiteTrace<mpc_core::protocols::rep3::Rep3PrimeFieldShare<Fr>>>> {
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

/// The 3-party in-process rep3 harness shared by tests, benches and examples: secret-share the
/// inputs, run the same `Program` on three threads over `mpc_net::local::LocalNetwork`, and
/// reconstruct the witness.
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

/// A circuit's inputs by name, each already flattened row-major the way circom numbers a
/// multi-dimensional input signal.
type NamedInputs = BTreeMap<String, Vec<Fr>>;

/// Parses one circom input leaf: a decimal string (optionally `-`-prefixed), a `0x`-prefixed hex
/// string, or a JSON integer. Reduced mod p, matching circom's own input semantics.
fn parse_field(v: &serde_json::Value) -> eyre::Result<Fr> {
    let s = match v {
        serde_json::Value::String(s) => s.as_str(),
        serde_json::Value::Number(n) => {
            return Ok(Fr::from(n.as_u64().ok_or_else(|| {
                eyre::eyre!("input number `{n}` is not a non-negative integer")
            })?))
        }
        other => eyre::bail!("expected a field element (string or integer), got {other}"),
    };
    let (negative, digits) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let magnitude = if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        BigUint::parse_bytes(hex.as_bytes(), 16)
    } else {
        BigUint::parse_bytes(digits.as_bytes(), 10)
    }
    .ok_or_else(|| eyre::eyre!("`{s}` is not a decimal or 0x-prefixed hex integer"))?;
    let value = Fr::from_le_bytes_mod_order(&magnitude.to_bytes_le());
    Ok(if negative { -value } else { value })
}

/// Flattens a circom-style input value row-major (last index fastest) into `out`. `path` names the
/// signal for error messages; nested arrays must be rectangular, since a ragged row would otherwise
/// silently shift every later element.
fn push_flat(path: &str, v: &serde_json::Value, out: &mut Vec<Fr>) -> eyre::Result<()> {
    match v {
        serde_json::Value::Array(rows) => {
            let mut row_len = None;
            for (i, row) in rows.iter().enumerate() {
                let before = out.len();
                push_flat(&format!("{path}[{i}]"), row, out)?;
                let this_len = out.len() - before;
                match row_len {
                    None => row_len = Some(this_len),
                    Some(expected) => eyre::ensure!(
                        this_len == expected,
                        "circuit input `{path}[{i}]` has {this_len} flattened element(s), but \
                         `{path}[0]` has {expected}; circom numbers multi-dimensional inputs \
                         row-major, so every row must be the same shape"
                    ),
                }
            }
            Ok(())
        }
        serde_json::Value::Bool(_) | serde_json::Value::Null | serde_json::Value::Object(_) => {
            eyre::bail!("circuit input `{path}` must be a field element or an array, got {v}")
        }
        leaf => {
            out.push(parse_field(leaf).map_err(|e| eyre::eyre!("circuit input `{path}`: {e}"))?);
            Ok(())
        }
    }
}

/// A circom-style `input.json` as [`NamedInputs`]: nested arrays flatten row-major, bare scalars
/// become one-element vectors.
fn from_input_json(json: &serde_json::Value) -> eyre::Result<NamedInputs> {
    let object = json
        .as_object()
        .ok_or_else(|| eyre::eyre!("input.json must be a JSON object of `name: value` pairs"))?;
    let mut inputs = NamedInputs::new();
    for (name, value) in object {
        let mut flat = Vec::new();
        push_flat(name, value, &mut flat)?;
        inputs.insert(name.clone(), flat);
    }
    Ok(inputs)
}

/// Orders `inputs` into the flat `&[Fr]` `Program::classify_inputs` expects, using the circuit's own
/// `Program::input_signals` rather than any assumed ordering.
///
/// Errors if a name the circuit declares is missing, its length disagrees with what the circuit
/// expects, or `inputs` carries a name the circuit does not declare at all (a stale key in a
/// hand-edited scenario file, otherwise a silent no-op).
fn flatten(inputs: &NamedInputs, input_signals: &[InputSignal]) -> eyre::Result<Vec<Fr>> {
    let total = input_signals.iter().map(|s| s.size).sum();
    let mut flat = vec![Fr::zero(); total];
    let mut claimed: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for signal in input_signals {
        claimed.insert(signal.name.as_str());
        let values = inputs.get(&signal.name).ok_or_else(|| {
            eyre::eyre!(
                "no value supplied for circuit input `{}` (the circuit declares {} \
                 element(s) at offset {}); supplied names: {:?}",
                signal.name,
                signal.size,
                signal.offset,
                inputs.keys().collect::<Vec<_>>()
            )
        })?;
        eyre::ensure!(
            values.len() == signal.size,
            "circuit input `{}` needs {} element(s), got {}",
            signal.name,
            signal.size,
            values.len()
        );
        flat[signal.offset..signal.offset + signal.size].copy_from_slice(values);
    }
    if let Some(stale) = inputs.keys().find(|name| !claimed.contains(name.as_str())) {
        eyre::bail!("supplied input `{stale}` is not declared by this circuit");
    }
    Ok(flat)
}

/// `CompilerConfig::mpc_public_inputs` for either merces server main: the signal names merces' own
/// MPC implementation passes as cleartext rather than secret-shared. Deliberately excludes
/// `amount`: merces passes it cleartext for a pure deposit/withdraw but shared for a transfer, and
/// one circuit serves all three, so it cannot be declared public here without being wrong for
/// transfers.
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

/// One real protocol input set for a vendored merces main, keyed by `(main, name)`.
pub struct Scenario {
    /// `circuits/merces/main/<main>.circom`.
    pub main: &'static str,
    /// The `_<name>` suffix of `inputs/<main>_<name>.json`.
    pub name: &'static str,
    /// `N` in `TransferBatchedCompressedArity4(N, ...)`, for reporting - the file itself is
    /// authoritative about shape.
    pub batch: usize,
    /// What this scenario exercises that the others do not.
    pub note: &'static str,
    json: &'static str,
}

/// All real protocol scenarios, baked in from `inputs/*.json`, four per server main.
pub const MERCES_SCENARIOS: &[Scenario] = &[
    Scenario {
        main: "transfer_arity4_batch1",
        name: "deposit",
        batch: 1,
        note: "isDeposit = 1 in its only slot",
        json: include_str!("../../../inputs/transfer_arity4_batch1_deposit.json"),
    },
    Scenario {
        main: "transfer_arity4_batch1",
        name: "withdraw",
        batch: 1,
        note: "isWithdraw = 1 in its only slot",
        json: include_str!("../../../inputs/transfer_arity4_batch1_withdraw.json"),
    },
    Scenario {
        main: "transfer_arity4_batch1",
        name: "invalid_withdraw",
        batch: 1,
        note: "a withdraw whose RangeCheckWithOutputFlag output is 0 - not an unsatisfied \
               constraint, an invalid *output*",
        json: include_str!("../../../inputs/transfer_arity4_batch1_invalid_withdraw.json"),
    },
    Scenario {
        main: "transfer_arity4_batch1",
        name: "transfer",
        batch: 1,
        note: "isDeposit = isWithdraw = 0, so isTransfer = 1 - the only family the old placeholder \
               generator could not satisfy, since it needs a real Merkle setup linking the withdraw \
               and deposit roots",
        json: include_str!("../../../inputs/transfer_arity4_batch1_transfer.json"),
    },
    Scenario {
        main: "transfer_arity4_batch8",
        name: "full_batch",
        batch: 8,
        note: "a mix of deposit, withdraw and transfer slots across all 8 transactions",
        json: include_str!("../../../inputs/transfer_arity4_batch8_full_batch.json"),
    },
    Scenario {
        main: "transfer_arity4_batch8",
        name: "partial_batch",
        batch: 8,
        note: "one deposit, one transfer, one withdraw, the rest idle zero-amount transfers",
        json: include_str!("../../../inputs/transfer_arity4_batch8_partial_batch.json"),
    },
    Scenario {
        main: "transfer_arity4_batch8",
        name: "multi_withdraw",
        batch: 8,
        note: "one deposit and three withdraw slots, the rest idle zero-amount transfers",
        json: include_str!("../../../inputs/transfer_arity4_batch8_multi_withdraw.json"),
    },
    Scenario {
        main: "transfer_arity4_batch8",
        name: "invalid_slot",
        batch: 8,
        note: "one slot's RangeCheckWithOutputFlag output is 0",
        json: include_str!("../../../inputs/transfer_arity4_batch8_invalid_slot.json"),
    },
];

impl Scenario {
    /// This scenario's inputs, parsed but not yet flattened against a circuit.
    fn named_inputs(&self) -> eyre::Result<NamedInputs> {
        let json: serde_json::Value = serde_json::from_str(self.json)
            .map_err(|e| eyre::eyre!("{}: {e}", self.file_name()))?;
        from_input_json(&json).map_err(|e| eyre::eyre!("{}: {e}", self.file_name()))
    }

    /// This scenario's inputs, flattened against a circuit's declared input signals.
    pub fn values(&self, input_signals: &[InputSignal]) -> eyre::Result<Vec<Fr>> {
        flatten(&self.named_inputs()?, input_signals)
    }

    /// `inputs/<main>_<name>.json`, matching the file this scenario was baked in from.
    pub fn file_name(&self) -> String {
        format!("{}_{}.json", self.main, self.name)
    }
}

/// Looks up one scenario by `(main, name)`.
pub fn scenario(main: &str, name: &str) -> eyre::Result<&'static Scenario> {
    MERCES_SCENARIOS
        .iter()
        .find(|s| s.main == main && s.name == name)
        .ok_or_else(|| {
            eyre::eyre!(
                "no scenario `{name}` for `{main}`; available: {:?}",
                scenarios(main).map(|s| s.name).collect::<Vec<_>>()
            )
        })
}

/// All scenarios for one main, in declaration order.
pub fn scenarios(main: &str) -> impl Iterator<Item = &'static Scenario> + use<'_> {
    MERCES_SCENARIOS.iter().filter(move |s| s.main == main)
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ff::{One, Zero};

    use super::*;

    #[test]
    fn every_scenario_parses() {
        for s in MERCES_SCENARIOS {
            s.named_inputs()
                .unwrap_or_else(|e| panic!("{}: {e}", s.file_name()));
        }
    }

    #[test]
    fn server_scenario_shapes_match_the_batch_size() {
        const MAX_DEPTH: usize = 13;
        for s in scenarios("transfer_arity4_batch1").chain(scenarios("transfer_arity4_batch8")) {
            let inputs = s.named_inputs().unwrap();
            for name in ["sender", "receiver"] {
                assert_eq!(
                    inputs[name].len(),
                    s.batch * 2 * MAX_DEPTH,
                    "{}: {name}",
                    s.file_name()
                );
            }
            for name in ["senderPath", "receiverPath"] {
                assert_eq!(
                    inputs[name].len(),
                    s.batch * 3 * MAX_DEPTH,
                    "{}: {name}",
                    s.file_name()
                );
            }
            for name in ["amount", "isDeposit", "isWithdraw"] {
                assert_eq!(inputs[name].len(), s.batch, "{}: {name}", s.file_name());
            }
            assert_eq!(inputs["depth"].len(), 1);
            assert_eq!(inputs["alpha"].len(), 1);
        }
    }

    #[test]
    fn index_bits_are_bits_and_zero_beyond_depth() {
        for s in scenarios("transfer_arity4_batch1").chain(scenarios("transfer_arity4_batch8")) {
            let inputs = s.named_inputs().unwrap();
            let depth = inputs["depth"][0];
            for name in ["sender", "receiver"] {
                for (slot, bits) in inputs[name].chunks(26).enumerate() {
                    for (level, pair) in bits.chunks(2).enumerate() {
                        for bit in pair {
                            assert!(
                                *bit == Fr::zero() || *bit == Fr::one(),
                                "{}: {name} slot {slot} must be a genuine bit",
                                s.file_name()
                            );
                        }
                        if Fr::from(level as u64) >= depth {
                            assert_eq!(
                                pair,
                                [Fr::zero(), Fr::zero()],
                                "{}: {name} slot {slot} level {level} is beyond depth {depth:?} and \
                                 must be zero (merkle_root_4.circom's shouldBeZeros)",
                                s.file_name()
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn flags_are_bits_and_never_both_set() {
        for s in scenarios("transfer_arity4_batch1").chain(scenarios("transfer_arity4_batch8")) {
            let inputs = s.named_inputs().unwrap();
            for (d, w) in inputs["isDeposit"].iter().zip(&inputs["isWithdraw"]) {
                for flag in [d, w] {
                    assert!(*flag == Fr::zero() || *flag == Fr::one());
                }
                assert_eq!(
                    *d * *w,
                    Fr::zero(),
                    "{}: isDeposit * isWithdraw",
                    s.file_name()
                );
            }
        }
    }

    #[test]
    fn parse_rejects_ragged_rows() {
        let json = serde_json::json!({"a": [["1", "2"], ["3"]]});
        let err = from_input_json(&json).unwrap_err().to_string();
        assert!(err.contains("row-major"), "{err}");
    }

    #[test]
    fn parse_rejects_non_integer_leaves() {
        let json = serde_json::json!({"a": "not a number"});
        assert!(from_input_json(&json).is_err());
        let json = serde_json::json!({"a": true});
        let err = from_input_json(&json).unwrap_err().to_string();
        assert!(err.contains("field element"), "{err}");
    }

    #[test]
    fn parse_accepts_hex_and_negative_and_json_integers() {
        let json = serde_json::json!({"a": "0x10", "b": "-1", "c": 5});
        let inputs = from_input_json(&json).unwrap();
        assert_eq!(inputs["a"], vec![Fr::from(16u64)]);
        assert_eq!(inputs["b"], vec![-Fr::one()]);
        assert_eq!(inputs["c"], vec![Fr::from(5u64)]);
    }

    #[test]
    fn flatten_reports_a_missing_or_misshaped_input_by_name() {
        let mut inputs: NamedInputs = BTreeMap::new();
        inputs.insert("depth".to_owned(), vec![Fr::from(3u64)]);

        let list = [InputSignal {
            name: "nope".to_owned(),
            offset: 0,
            size: 1,
        }];
        let err = flatten(&inputs, &list).unwrap_err().to_string();
        assert!(err.contains("nope"), "{err}");

        let list = [InputSignal {
            name: "depth".to_owned(),
            offset: 0,
            size: 4,
        }];
        let err = flatten(&inputs, &list).unwrap_err().to_string();
        assert!(err.contains("needs 4 element(s)"), "{err}");
    }

    #[test]
    fn flatten_rejects_an_unclaimed_input_name() {
        let mut inputs: NamedInputs = BTreeMap::new();
        inputs.insert("a".to_owned(), vec![Fr::from(1u64)]);
        inputs.insert("stale".to_owned(), vec![Fr::from(2u64)]);
        let list = [InputSignal {
            name: "a".to_owned(),
            offset: 0,
            size: 1,
        }];
        let err = flatten(&inputs, &list).unwrap_err().to_string();
        assert!(err.contains("stale"), "{err}");
    }

    #[test]
    fn flatten_places_values_at_the_declared_offsets() {
        let mut inputs: NamedInputs = BTreeMap::new();
        inputs.insert("a".to_owned(), vec![Fr::from(1u64), Fr::from(2u64)]);
        inputs.insert("b".to_owned(), vec![Fr::from(3u64)]);
        // Deliberately not in alphabetical order, to prove the offsets drive placement.
        let list = [
            InputSignal {
                name: "b".to_owned(),
                offset: 0,
                size: 1,
            },
            InputSignal {
                name: "a".to_owned(),
                offset: 1,
                size: 2,
            },
        ];
        assert_eq!(
            flatten(&inputs, &list).unwrap(),
            vec![Fr::from(3u64), Fr::from(1u64), Fr::from(2u64)]
        );
    }
}
