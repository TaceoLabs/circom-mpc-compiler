//! Real protocol inputs for the vendored `circuits/merces/` circuits, shared by
//! `tests/merces.rs`, `benches/`, and `examples/merces.rs`.
//!
//! Lives in the library rather than under `tests/` because integration tests, benches and examples
//! are three separate compilation units that cannot share a `tests/common` module between them.
//!
//! # Where the inputs come from
//!
//! `inputs/<main>_<scenario>.json` are real merces protocol values (not placeholders), one file per
//! scenario, baked into the binary with `include_str!` so no test can silently skip because a file
//! moved. Copied verbatim from merces' own `circom/main/inputs/`; regenerate from there, not from
//! anything in this crate. [`MERCES_SCENARIOS`] is the index; [`Scenario::values`] turns one into the
//! flat `&[F]` `Program::classify_inputs` expects, via [`flatten`] against the circuit's own
//! `Graph::input_list`.
//!
//! # The `===` constraints these values satisfy
//!
//! Witness extension would happily run on any values; a *proof* additionally needs every `===` in
//! the circuit to hold, which real protocol values do and arbitrary ones would not. Four families
//! exist in the server closure:
//!
//! | Constraint | Where | How the real inputs satisfy it |
//! |---|---|---|
//! | `isDeposit * isWithdraw === 0` | `server.circom:110` | never both set, in any slot of any scenario |
//! | `isTransfer * (senderWithdraw.newRoot - receiverDeposit.oldRoot) === 0` | `server.circom:159` | `isTransfer = 1` in `transfer` and in several batch8 slots; holds because the sender's post-withdraw root genuinely equals the receiver's pre-deposit root under a real Merkle setup |
//! | `indexBits[k] * (indexBits[k] - 1) === 0` | `hash.circom:40` | genuine 0/1 index bits |
//! | `shouldBeZeros[i] * indexBits[..] === 0` | `merkle_root_4.circom:76` | `depth = 3 < MAX_DEPTH = 13`, and every index bit at position `2*depth..` is zero |
//!
//! Everything else is `<--`/`<==` assignment, satisfied by construction. The root-linking family is
//! not checkable by anything in this crate - it is confirmed externally by a passing prove+verify
//! test in `tests/merces.rs`, against circom's own R1CS (see `scripts/gen-merces-artifacts.sh`).

use std::{collections::BTreeMap, path::Path};

use ark_ff::PrimeField;
use num_bigint::BigUint;

use crate::ir::InputList;

/// A circuit's inputs by name, each already flattened row-major the way circom numbers a
/// multi-dimensional input signal.
pub type NamedInputs<F> = BTreeMap<String, Vec<F>>;

/// Parses one circom input leaf: a decimal string (optionally `-`-prefixed), a `0x`-prefixed hex
/// string, or a JSON integer. Reduced mod p, matching circom's own input semantics.
fn parse_field<F: PrimeField>(v: &serde_json::Value) -> eyre::Result<F> {
    let s = match v {
        serde_json::Value::String(s) => s.as_str(),
        serde_json::Value::Number(n) => {
            return Ok(F::from(
                n.as_u64()
                    .ok_or_else(|| eyre::eyre!("input number `{n}` is not a non-negative integer"))?,
            ))
        }
        other => eyre::bail!("expected a field element (string or integer), got {other}"),
    };
    let (negative, digits) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let magnitude = if let Some(hex) = digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")) {
        BigUint::parse_bytes(hex.as_bytes(), 16)
    } else {
        BigUint::parse_bytes(digits.as_bytes(), 10)
    }
    .ok_or_else(|| eyre::eyre!("`{s}` is not a decimal or 0x-prefixed hex integer"))?;
    let value = F::from_le_bytes_mod_order(&magnitude.to_bytes_le());
    Ok(if negative { -value } else { value })
}

/// Flattens a circom-style input value row-major (last index fastest) into `out`. `path` names the
/// signal for error messages; nested arrays must be rectangular, since a ragged row would otherwise
/// silently shift every later element.
fn push_flat<F: PrimeField>(path: &str, v: &serde_json::Value, out: &mut Vec<F>) -> eyre::Result<()> {
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
/// become one-element vectors. Composes directly with [`flatten`].
pub fn from_input_json<F: PrimeField>(json: &serde_json::Value) -> eyre::Result<NamedInputs<F>> {
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

/// [`from_input_json`] over a file, with the path in every error message.
pub fn read_input_json<F: PrimeField>(path: impl AsRef<Path>) -> eyre::Result<NamedInputs<F>> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path)
        .map_err(|e| eyre::eyre!("reading {}: {e}", path.display()))?;
    let json: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| eyre::eyre!("parsing {} as JSON: {e}", path.display()))?;
    from_input_json(&json).map_err(|e| eyre::eyre!("{}: {e}", path.display()))
}

/// Orders `inputs` into the flat `&[F]` `Program::classify_inputs` expects, using the circuit's own
/// `Graph::input_list` (`(name, start, size)` per input signal) rather than any assumed ordering.
///
/// Errors if a name the circuit declares is missing, its length disagrees with what the circuit
/// expects, or `inputs` carries a name the circuit does not declare at all (a stale key in a
/// hand-edited scenario file, otherwise a silent no-op).
pub fn flatten<F: PrimeField>(inputs: &NamedInputs<F>, input_list: &InputList) -> eyre::Result<Vec<F>> {
    let total = input_list.iter().map(|(_, _, size)| size).sum();
    let mut flat = vec![F::zero(); total];
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
    pub fn named_inputs<F: PrimeField>(&self) -> eyre::Result<NamedInputs<F>> {
        let json: serde_json::Value = serde_json::from_str(self.json)
            .map_err(|e| eyre::eyre!("{}: {e}", self.file_name()))?;
        from_input_json(&json).map_err(|e| eyre::eyre!("{}: {e}", self.file_name()))
    }

    /// This scenario's inputs, flattened against a circuit's declared `input_list`.
    pub fn values<F: PrimeField>(&self, input_list: &InputList) -> eyre::Result<Vec<F>> {
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
            s.named_inputs::<Fr>()
                .unwrap_or_else(|e| panic!("{}: {e}", s.file_name()));
        }
    }

    #[test]
    fn server_scenario_shapes_match_the_batch_size() {
        const MAX_DEPTH: usize = 13;
        for s in scenarios("transfer_arity4_batch1").chain(scenarios("transfer_arity4_batch8")) {
            let inputs = s.named_inputs::<Fr>().unwrap();
            for name in ["sender", "receiver"] {
                assert_eq!(inputs[name].len(), s.batch * 2 * MAX_DEPTH, "{}: {name}", s.file_name());
            }
            for name in ["senderPath", "receiverPath"] {
                assert_eq!(inputs[name].len(), s.batch * 3 * MAX_DEPTH, "{}: {name}", s.file_name());
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
            let inputs = s.named_inputs::<Fr>().unwrap();
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
            let inputs = s.named_inputs::<Fr>().unwrap();
            for (d, w) in inputs["isDeposit"].iter().zip(&inputs["isWithdraw"]) {
                for flag in [d, w] {
                    assert!(*flag == Fr::zero() || *flag == Fr::one());
                }
                assert_eq!(*d * *w, Fr::zero(), "{}: isDeposit * isWithdraw", s.file_name());
            }
        }
    }

    #[test]
    fn parse_rejects_ragged_rows() {
        let json: serde_json::Value = serde_json::json!({"a": [["1", "2"], ["3"]]});
        let err = from_input_json::<Fr>(&json).unwrap_err().to_string();
        assert!(err.contains("row-major"), "{err}");
    }

    #[test]
    fn parse_rejects_non_integer_leaves() {
        let json: serde_json::Value = serde_json::json!({"a": "not a number"});
        assert!(from_input_json::<Fr>(&json).is_err());
        let json: serde_json::Value = serde_json::json!({"a": true});
        let err = from_input_json::<Fr>(&json).unwrap_err().to_string();
        assert!(err.contains("field element"), "{err}");
    }

    #[test]
    fn parse_accepts_hex_and_negative_and_json_integers() {
        let json: serde_json::Value = serde_json::json!({"a": "0x10", "b": "-1", "c": 5});
        let inputs = from_input_json::<Fr>(&json).unwrap();
        assert_eq!(inputs["a"], vec![Fr::from(16u64)]);
        assert_eq!(inputs["b"], vec![-Fr::one()]);
        assert_eq!(inputs["c"], vec![Fr::from(5u64)]);
    }

    #[test]
    fn flatten_reports_a_missing_or_misshaped_input_by_name() {
        let mut inputs: NamedInputs<Fr> = BTreeMap::new();
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
        let mut inputs: NamedInputs<Fr> = BTreeMap::new();
        inputs.insert("a".to_owned(), vec![Fr::from(1u64)]);
        inputs.insert("stale".to_owned(), vec![Fr::from(2u64)]);
        let list: InputList = vec![("a".to_owned(), 0, 1)];
        let err = flatten(&inputs, &list).unwrap_err().to_string();
        assert!(err.contains("stale"), "{err}");
    }

    #[test]
    fn flatten_places_values_at_the_declared_offsets() {
        let mut inputs: NamedInputs<Fr> = BTreeMap::new();
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
