//! Deterministic input generation for the vendored `circuits/merces/` circuits, shared by
//! `tests/merces.rs`, `benches/`, and `examples/merces.rs`.
//!
//! Lives in the library rather than under `tests/` because integration tests, benches and examples
//! are three separate compilation units that cannot share a `tests/common` module between them.
//!
//! # These are placeholder values, not a protocol run
//!
//! The values are arbitrary. What is *not* arbitrary is that they satisfy the circuit's `===`
//! constraints, which a proof needs (witness extension itself would happily compute a witness from
//! anything; only the R1CS cares). Four families exist in the server closure, and
//! [`merces_server_inputs`] respects each:
//!
//! | Constraint | Where | How it is satisfied |
//! |---|---|---|
//! | `isDeposit * isWithdraw === 0` | `server.circom:110` | `isDeposit = 1`, `isWithdraw = 0` |
//! | `isTransfer * (withdraw.newRoot - deposit.oldRoot) === 0` | `server.circom:159` | `isTransfer = 1 - isDeposit - isWithdraw = 0`, so this holds without the roots having to agree - which they could not, without a real Merkle setup |
//! | `indexBits[k] * (indexBits[k] - 1) === 0` | `hash.circom:40` | `sender`/`receiver` are filled with genuine 0/1 bits |
//! | `shouldBeZeros[i] * indexBits[..] === 0` | `merkle_root_4.circom:76` | `depth = MAX_DEPTH`, which makes every `shouldBeZeros[i]` zero for `i < MAX_DEPTH` |
//!
//! Everything else in these circuits is `<--`/`<==` assignment, satisfied by construction once the
//! precomputation traces are right. In particular the balance range check is an *output flag*
//! (`RangeCheckWithOutputFlag`), not a constraint, so `oldBalance - amount` may underflow harmlessly;
//! and the server path commits to `amount` directly rather than through `CheckAmount`, so there is no
//! `amount < 2^BALANCE_BITSIZE` requirement either.
//!
//! Swap [`merces_server_inputs`] for real protocol values and nothing else has to change.

use std::collections::BTreeMap;

use ark_ff::PrimeField;

use crate::ir::InputList;

/// A circuit's inputs by name, each already flattened row-major the way circom numbers a
/// multi-dimensional input signal.
pub type NamedInputs<F> = BTreeMap<String, Vec<F>>;

/// A tiny deterministic generator, so a fixture is reproducible from its seed alone with no `rand`
/// dependency and no seed threading. xorshift64*; quality is irrelevant here, reproducibility is not.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // Any non-zero state; xorshift is degenerate at 0.
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn field<F: PrimeField>(&mut self) -> F {
        // Two limbs is plenty of entropy for a placeholder and keeps values well inside the field.
        F::from(self.next_u64()) * F::from(u64::MAX) + F::from(self.next_u64())
    }

    fn bit<F: PrimeField>(&mut self) -> F {
        if self.next_u64() & 1 == 0 {
            F::zero()
        } else {
            F::one()
        }
    }
}

/// Inputs for `TransferBatchedCompressedArity4(n, max_depth, _, _)` - i.e. the
/// `transfer_arity4_batch*` mains. `n` is the batch size, `max_depth` the arity-4 tree depth (13 for
/// both vendored mains).
///
/// See the module doc for which values are load-bearing and why.
pub fn merces_server_inputs<F: PrimeField>(n: usize, max_depth: usize, seed: u64) -> NamedInputs<F> {
    let mut rng = Rng::new(seed);
    let mut inputs: NamedInputs<F> = BTreeMap::new();

    // Index bits, one pair per tree level: must be genuine bits (`hash.circom:40`).
    for name in ["sender", "receiver"] {
        inputs.insert(
            name.to_owned(),
            (0..n * 2 * max_depth).map(|_| rng.bit()).collect(),
        );
    }
    // Sibling hashes: arbitrary, since no constraint ties them to a real tree.
    for name in ["senderPath", "receiverPath"] {
        let values = (0..n * 3 * max_depth).map(|_| rng.field()).collect();
        inputs.insert(name.to_owned(), values);
    }
    for name in [
        "senderOldBalance",
        "senderOldBalanceR",
        "senderNewBalanceR",
        "senderIndexR",
        "receiverOldBalance",
        "receiverOldBalanceR",
        "receiverNewBalanceR",
        "receiverIndexR",
        "amount",
        "amountR",
    ] {
        let values = (0..n).map(|_| rng.field()).collect();
        inputs.insert(name.to_owned(), values);
    }

    // `depth = max_depth` zeroes every `shouldBeZeros[i]`, so the index-range constraints in
    // `merkle_root_4.circom` hold for any index bits.
    inputs.insert("depth".to_owned(), vec![F::from(max_depth as u64)]);
    // A deposit: `isDeposit * isWithdraw == 0` and `isTransfer == 0`, so neither flag constraint
    // needs the withdraw and deposit roots to line up.
    inputs.insert("isDeposit".to_owned(), vec![F::one(); n]);
    inputs.insert("isWithdraw".to_owned(), vec![F::zero(); n]);
    // Public input to the compression sponge; unconstrained.
    inputs.insert("alpha".to_owned(), vec![rng.field()]);

    inputs
}

/// Orders `inputs` into the flat `&[F]` `Program::classify_inputs` expects, using the circuit's own
/// `Graph::input_list` (`(name, start, size)` per input signal) rather than any assumed ordering.
///
/// Errors if a name the circuit declares is missing, or its length disagrees with what the circuit
/// expects.
pub fn flatten<F: PrimeField>(inputs: &NamedInputs<F>, input_list: &InputList) -> eyre::Result<Vec<F>> {
    let total = input_list.iter().map(|(_, _, size)| size).sum();
    let mut flat = vec![F::zero(); total];
    for (name, start, size) in input_list {
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
    Ok(flat)
}

/// The same inputs as a circom `input.json`, for feeding the reference circom witness calculator (see
/// `scripts/gen-merces-artifacts.sh`). Decimal strings, which is what circom accepts for field
/// elements; single-element inputs are emitted as scalars rather than one-element arrays, matching
/// how circom's own tooling writes them.
pub fn to_input_json<F: PrimeField>(inputs: &NamedInputs<F>) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (name, values) in inputs {
        let decimals: Vec<serde_json::Value> = values
            .iter()
            .map(|v| serde_json::Value::String(v.into_bigint().to_string()))
            .collect();
        let entry = if decimals.len() == 1 {
            decimals.into_iter().next().expect("length checked")
        } else {
            serde_json::Value::Array(decimals)
        };
        map.insert(name.clone(), entry);
    }
    serde_json::Value::Object(map)
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ff::{One, Zero};

    use super::*;

    #[test]
    fn index_bits_are_bits_and_flags_satisfy_the_constraints() {
        let inputs = merces_server_inputs::<Fr>(8, 13, 42);
        for name in ["sender", "receiver"] {
            assert_eq!(inputs[name].len(), 8 * 2 * 13);
            for v in &inputs[name] {
                assert!(
                    *v == Fr::zero() || *v == Fr::one(),
                    "{name} must be genuine bits - hash.circom:40 constrains it"
                );
            }
        }
        // isDeposit * isWithdraw === 0, and isTransfer = 1 - 1 - 0 = 0.
        for (d, w) in inputs["isDeposit"].iter().zip(&inputs["isWithdraw"]) {
            assert_eq!(*d * *w, Fr::zero());
            assert_eq!(Fr::one() - *d - *w, Fr::zero());
        }
        assert_eq!(inputs["depth"], vec![Fr::from(13u64)]);
    }

    #[test]
    fn is_reproducible_from_the_seed() {
        assert_eq!(
            merces_server_inputs::<Fr>(1, 13, 7),
            merces_server_inputs::<Fr>(1, 13, 7)
        );
        assert_ne!(
            merces_server_inputs::<Fr>(1, 13, 7),
            merces_server_inputs::<Fr>(1, 13, 8)
        );
    }

    #[test]
    fn flatten_reports_a_missing_or_misshaped_input_by_name() {
        let inputs = merces_server_inputs::<Fr>(1, 13, 1);
        let list: InputList = vec![("nope".to_owned(), 0, 1)];
        let err = flatten(&inputs, &list).unwrap_err().to_string();
        assert!(err.contains("nope"), "{err}");

        let list: InputList = vec![("depth".to_owned(), 0, 4)];
        let err = flatten(&inputs, &list).unwrap_err().to_string();
        assert!(err.contains("needs 4 element(s)"), "{err}");
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
