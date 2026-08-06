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

use crate::ir::InputList;
use crate::{CompilerConfig, OptLevel};

/// The compiler configuration for the vendored merces circuits, mirroring how merces itself
/// compiles them (`-l circom/node_modules -l circom`): `circuits/libs/` resolves circomlib plus
/// the vendored `taceo/` subtree, `circuits/merces/` the `merces/`/`oblivious_vector/`
/// cross-references. The circuits are `pragma circom 2.2.2` verbatim.
pub fn merces_config() -> CompilerConfig {
    let root = env!("CARGO_MANIFEST_DIR");
    CompilerConfig {
        version: "2.2.2".to_owned(),
        link_library: vec![
            format!("{root}/circuits/libs/").into(),
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
        env!("CARGO_MANIFEST_DIR")
    )
}

/// The 3-party in-process rep3 harness shared by tests, benches and examples: secret-share the
/// inputs, run the same `Program` on three threads over `mpc_net::local::LocalNetwork`, and
/// reconstruct the witness.
#[cfg(feature = "rep3")]
pub mod rep3 {
    use ark_bn254::Fr;
    use mpc_core::protocols::rep3::conversion::A2BType;
    use mpc_core::protocols::rep3::{
        combine_field_elements, share_field_element, Rep3PrimeFieldShare, Rep3State,
    };
    use mpc_net::local::LocalNetwork;

    use crate::vm::driver::rep3::Rep3Driver;
    use crate::vm::program::Bank;
    use crate::vm::{Machine, Program};

    /// One `[share; 3]` triple per `Shared`-domain input, in the order `Program::classify_inputs`
    /// visits them - each party takes its own component.
    pub fn share_inputs(program: &Program, values: &[Fr]) -> Vec<[Rep3PrimeFieldShare<Fr>; 3]> {
        let mut rng = rand::thread_rng();
        program
            .input_domains
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
    #[cfg(feature = "round-counting")]
    pub fn run_witness_counted(
        program: &Program,
        values: &[Fr],
    ) -> (Vec<Fr>, [usize; 3], [usize; 3]) {
        use crate::vm::counting_net::CountingNet;

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
/// `Graph::input_list` (`(name, start, size)` per input signal) rather than any assumed ordering.
///
/// Errors if a name the circuit declares is missing, its length disagrees with what the circuit
/// expects, or `inputs` carries a name the circuit does not declare at all (a stale key in a
/// hand-edited scenario file, otherwise a silent no-op).
fn flatten(inputs: &NamedInputs, input_list: &InputList) -> eyre::Result<Vec<Fr>> {
    let total = input_list.iter().map(|(_, _, size)| size).sum();
    let mut flat = vec![Fr::zero(); total];
    let mut claimed: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for (name, start, size) in input_list {
        claimed.insert(name.as_str());
        let values = inputs.get(name).ok_or_else(|| {
            eyre::eyre!(
                "no value supplied for circuit input `{name}` (the circuit declares {size} \
                 element(s) at offset {start}); supplied names: {:?}",
                inputs.keys().collect::<Vec<_>>()
            )
        })?;
        eyre::ensure!(
            values.len() == *size,
            "circuit input `{name}` needs {size} element(s), got {}",
            values.len()
        );
        flat[*start..start + size].copy_from_slice(values);
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

/// All real protocol scenarios, baked in from `inputs/*.json`. The two server mains get four
/// scenarios each; `transfer_client_compressed` gets one, for the day its main compiles (see
/// `tests/merces.rs::client_main_is_still_unsupported`).
pub const MERCES_SCENARIOS: &[Scenario] = &[
    Scenario {
        main: "transfer_arity4_batch1",
        name: "deposit",
        batch: 1,
        note: "isDeposit = 1 in its only slot",
        json: include_str!("../inputs/transfer_arity4_batch1_deposit.json"),
    },
    Scenario {
        main: "transfer_arity4_batch1",
        name: "withdraw",
        batch: 1,
        note: "isWithdraw = 1 in its only slot",
        json: include_str!("../inputs/transfer_arity4_batch1_withdraw.json"),
    },
    Scenario {
        main: "transfer_arity4_batch1",
        name: "invalid_withdraw",
        batch: 1,
        note: "a withdraw whose RangeCheckWithOutputFlag output is 0 - not an unsatisfied \
               constraint, an invalid *output*",
        json: include_str!("../inputs/transfer_arity4_batch1_invalid_withdraw.json"),
    },
    Scenario {
        main: "transfer_arity4_batch1",
        name: "transfer",
        batch: 1,
        note: "isDeposit = isWithdraw = 0, so isTransfer = 1 - the only family the old placeholder \
               generator could not satisfy, since it needs a real Merkle setup linking the withdraw \
               and deposit roots",
        json: include_str!("../inputs/transfer_arity4_batch1_transfer.json"),
    },
    Scenario {
        main: "transfer_arity4_batch8",
        name: "full_batch",
        batch: 8,
        note: "a mix of deposit, withdraw and transfer slots across all 8 transactions",
        json: include_str!("../inputs/transfer_arity4_batch8_full_batch.json"),
    },
    Scenario {
        main: "transfer_arity4_batch8",
        name: "partial_batch",
        batch: 8,
        note: "one deposit, one transfer, one withdraw, the rest idle zero-amount transfers",
        json: include_str!("../inputs/transfer_arity4_batch8_partial_batch.json"),
    },
    Scenario {
        main: "transfer_arity4_batch8",
        name: "multi_withdraw",
        batch: 8,
        note: "one deposit and three withdraw slots, the rest idle zero-amount transfers",
        json: include_str!("../inputs/transfer_arity4_batch8_multi_withdraw.json"),
    },
    Scenario {
        main: "transfer_arity4_batch8",
        name: "invalid_slot",
        batch: 8,
        note: "one slot's RangeCheckWithOutputFlag output is 0",
        json: include_str!("../inputs/transfer_arity4_batch8_invalid_slot.json"),
    },
    Scenario {
        main: "transfer_client_compressed",
        name: "default",
        batch: 1,
        note: "the client main - still unsupported, see client_main_is_still_unsupported",
        json: include_str!("../inputs/transfer_client_compressed.json"),
    },
];

impl Scenario {
    /// This scenario's inputs, parsed but not yet flattened against a circuit.
    fn named_inputs(&self) -> eyre::Result<NamedInputs> {
        let json: serde_json::Value = serde_json::from_str(self.json)
            .map_err(|e| eyre::eyre!("{}: {e}", self.file_name()))?;
        from_input_json(&json).map_err(|e| eyre::eyre!("{}: {e}", self.file_name()))
    }

    /// This scenario's inputs, flattened against a circuit's declared `input_list`.
    pub fn values(&self, input_list: &InputList) -> eyre::Result<Vec<Fr>> {
        flatten(&self.named_inputs()?, input_list)
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

        let list: InputList = vec![("nope".to_owned(), 0, 1)];
        let err = flatten(&inputs, &list).unwrap_err().to_string();
        assert!(err.contains("nope"), "{err}");

        let list: InputList = vec![("depth".to_owned(), 0, 4)];
        let err = flatten(&inputs, &list).unwrap_err().to_string();
        assert!(err.contains("needs 4 element(s)"), "{err}");
    }

    #[test]
    fn flatten_rejects_an_unclaimed_input_name() {
        let mut inputs: NamedInputs = BTreeMap::new();
        inputs.insert("a".to_owned(), vec![Fr::from(1u64)]);
        inputs.insert("stale".to_owned(), vec![Fr::from(2u64)]);
        let list: InputList = vec![("a".to_owned(), 0, 1)];
        let err = flatten(&inputs, &list).unwrap_err().to_string();
        assert!(err.contains("stale"), "{err}");
    }

    #[test]
    fn flatten_places_values_at_the_declared_offsets() {
        let mut inputs: NamedInputs = BTreeMap::new();
        inputs.insert("a".to_owned(), vec![Fr::from(1u64), Fr::from(2u64)]);
        inputs.insert("b".to_owned(), vec![Fr::from(3u64)]);
        // Deliberately not in alphabetical order, to prove the offsets drive placement.
        let list: InputList = vec![("b".to_owned(), 0, 1), ("a".to_owned(), 1, 2)];
        assert_eq!(
            flatten(&inputs, &list).unwrap(),
            vec![Fr::from(3u64), Fr::from(1u64), Fr::from(2u64)]
        );
    }
}
