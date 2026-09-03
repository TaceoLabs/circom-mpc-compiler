use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
};

use ark_bn254::Fr;

use crate::{Program, program::Bank};

/// One circuit input's value, in whichever representation its domain calls for -
/// `Program::input_domains` tells a caller which variant each input needs;
/// `Program::classify_inputs` builds this array from a flat `&[Fr]` automatically for callers that
/// don't want to track domains themselves (e.g. the plain-driver tests).
#[derive(Debug, Clone)]
pub enum InputValue<S> {
    /// A value visible to every party.
    Public(Fr),
    /// A value shared/secret to a single party's share representation `S`.
    Secret(S),
}

/// Converts a container of [`InputValue`]s into the slice form `Program::classify_inputs`
/// produces, so callers can pass a `Vec`, an array, a slice, a `Result` of one, or a name-keyed
/// map interchangeably.
pub trait InputValues<S: Clone> {
    /// Returns the values as a slice, in the circuit's flat input order.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying container itself represents a failure (e.g. the
    /// `eyre::Result<Vec<_>>` impl), or, for a name-keyed map, if it doesn't match
    /// `program.input_signals()` (a missing name, a name with the wrong element count, or a name
    /// the circuit doesn't declare).
    fn as_inputs(&self, program: &Program) -> eyre::Result<Cow<'_, [InputValue<S>]>>;
}

impl<S: Clone> InputValues<S> for [InputValue<S>] {
    fn as_inputs(&self, _program: &Program) -> eyre::Result<Cow<'_, [InputValue<S>]>> {
        Ok(Cow::Borrowed(self))
    }
}

impl<S: Clone> InputValues<S> for Vec<InputValue<S>> {
    fn as_inputs(&self, _program: &Program) -> eyre::Result<Cow<'_, [InputValue<S>]>> {
        Ok(Cow::Borrowed(self))
    }
}

impl<S: Clone, const N: usize> InputValues<S> for [InputValue<S>; N] {
    fn as_inputs(&self, _program: &Program) -> eyre::Result<Cow<'_, [InputValue<S>]>> {
        Ok(Cow::Borrowed(self))
    }
}

impl<S: Clone> InputValues<S> for eyre::Result<Vec<InputValue<S>>> {
    fn as_inputs(&self, _program: &Program) -> eyre::Result<Cow<'_, [InputValue<S>]>> {
        self.as_ref()
            .map(|values| Cow::Borrowed(values.as_slice()))
            .map_err(|error| eyre::eyre!(error.to_string()))
    }
}

/// Scatters a name-keyed map of whole-signal values into the circuit's flat input order, per
/// `program.input_signals()`. Shared by the `BTreeMap`/`HashMap` impls below, which differ only in
/// how they look up and iterate their keys.
///
/// # Errors
///
/// Returns an error if a declared signal's name is missing from `named`, a supplied value has the
/// wrong element count for its signal, or `named` has a name the circuit doesn't declare.
fn flatten_named<'a, S>(
    program: &Program,
    get: impl Fn(&str) -> Option<&'a Vec<InputValue<S>>>,
    names: impl Iterator<Item = &'a str>,
) -> eyre::Result<Vec<InputValue<S>>>
where
    S: Clone + 'a,
{
    let mut flat: Vec<Option<InputValue<S>>> = vec![None; program.num_inputs()];
    for signal in program.input_signals() {
        let values = get(&signal.name).ok_or_else(|| {
            eyre::eyre!(
                "no value supplied for circuit input `{}` ({} element(s) at offset {})",
                signal.name,
                signal.size,
                signal.offset
            )
        })?;
        eyre::ensure!(
            values.len() == signal.size,
            "circuit input `{}` needs {} element(s), got {}",
            signal.name,
            signal.size,
            values.len()
        );
        for (i, value) in values.iter().enumerate() {
            flat[signal.offset + i] = Some(value.clone());
        }
    }
    if let Some(stale) = names.into_iter().find(|name| {
        !program
            .input_signals()
            .iter()
            .any(|signal| signal.name == *name)
    }) {
        eyre::bail!("supplied input `{stale}` is not declared by this circuit");
    }
    Ok(flat
        .into_iter()
        .enumerate()
        .map(|(i, v)| v.unwrap_or_else(|| panic!("input {i} has no declared signal covering it")))
        .collect())
}

impl<S: Clone> InputValues<S> for BTreeMap<String, Vec<InputValue<S>>> {
    fn as_inputs(&self, program: &Program) -> eyre::Result<Cow<'_, [InputValue<S>]>> {
        let flat = flatten_named(
            program,
            |name| self.get(name),
            self.keys().map(String::as_str),
        )?;
        Ok(Cow::Owned(flat))
    }
}

impl<S: Clone, H: std::hash::BuildHasher> InputValues<S>
    for HashMap<String, Vec<InputValue<S>>, H>
{
    fn as_inputs(&self, program: &Program) -> eyre::Result<Cow<'_, [InputValue<S>]>> {
        let flat = flatten_named(
            program,
            |name| self.get(name),
            self.keys().map(String::as_str),
        )?;
        Ok(Cow::Owned(flat))
    }
}

impl Program {
    /// Builds `Machine::run`'s `inputs` array from a flat `&[Fr]` in circuit signal order,
    /// consulting `Program::input_domains` to wrap each value as `Public` or `Secret`
    /// automatically. `share`
    /// is only invoked for `Secret`-destined values - e.g. `|v| v` for a driver whose `Share = Fr`
    /// (`PlainDriver`), or an actual secret-sharing routine for a real MPC driver (see
    /// `tests/rep3_vm.rs`).
    ///
    /// # Errors
    ///
    /// Returns an error if `values.len()` doesn't match the program's input count, or if an
    /// input's domain is `Local` (inputs cannot be `Local`).
    pub fn classify_inputs<S>(
        &self,
        values: &[Fr],
        mut share: impl FnMut(Fr) -> S,
    ) -> eyre::Result<Vec<InputValue<S>>> {
        eyre::ensure!(
            values.len() == self.num_inputs(),
            "expected one value per circuit input ({}), got {}",
            self.num_inputs(),
            values.len()
        );
        self.input_domains()
            .iter()
            .zip(values)
            .map(|(bank, &v)| match bank {
                Bank::Public => Ok(InputValue::Public(v)),
                Bank::Shared => Ok(InputValue::Secret(share(v))),
                Bank::Local => eyre::bail!("an input's domain cannot be Local"),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProgramParts, SlotCounts, program::InputSignal};

    /// A program with three `Fr` inputs, `a` (1 element) and `b` (2 elements), all `Public` -
    /// enough for `InputValues`, which never touches instructions, rounds, or gadgets.
    fn program_with_signals() -> Program {
        Program::new(ProgramParts {
            instructions: Vec::new(),
            constants: Vec::new(),
            input_domains: vec![Bank::Public; 3],
            inputs: Vec::new(),
            input_signals: vec![
                InputSignal {
                    name: "a".to_owned(),
                    offset: 0,
                    size: 1,
                },
                InputSignal {
                    name: "b".to_owned(),
                    offset: 1,
                    size: 2,
                },
            ],
            rounds: Vec::new(),
            round_operands: Vec::new(),
            round_results: Vec::new(),
            gadget_batches: Vec::new(),
            witness_sources: Vec::new(),
            num_inputs: 3,
            slots: SlotCounts::default(),
        })
    }

    fn fr(values: [u64; 3]) -> Vec<Fr> {
        values.into_iter().map(Fr::from).collect()
    }

    #[test]
    fn named_map_and_positional_agree() {
        let program = program_with_signals();
        let positional = program
            .classify_inputs(&fr([1, 2, 3]), |v| v)
            .expect("classify_inputs");

        let mut named: BTreeMap<String, Vec<InputValue<Fr>>> = BTreeMap::new();
        named.insert("a".to_owned(), vec![InputValue::Public(Fr::from(1u64))]);
        named.insert(
            "b".to_owned(),
            vec![
                InputValue::Public(Fr::from(2u64)),
                InputValue::Public(Fr::from(3u64)),
            ],
        );
        let via_map = named.as_inputs(&program).expect("as_inputs");

        assert_eq!(via_map.len(), positional.len());
        for (m, p) in via_map.iter().zip(&positional) {
            match (m, p) {
                (InputValue::Public(a), InputValue::Public(b)) => assert_eq!(a, b),
                _ => panic!("expected both to be Public"),
            }
        }
    }

    #[test]
    fn named_map_rejects_a_missing_name() {
        let program = program_with_signals();
        let mut named: BTreeMap<String, Vec<InputValue<Fr>>> = BTreeMap::new();
        named.insert("a".to_owned(), vec![InputValue::Public(Fr::from(1u64))]);
        let err = named
            .as_inputs(&program)
            .expect_err("must fail")
            .to_string();
        assert!(err.contains('b'), "{err}");
    }

    #[test]
    fn named_map_rejects_the_wrong_element_count() {
        let program = program_with_signals();
        let mut named: BTreeMap<String, Vec<InputValue<Fr>>> = BTreeMap::new();
        named.insert("a".to_owned(), vec![InputValue::Public(Fr::from(1u64))]);
        named.insert("b".to_owned(), vec![InputValue::Public(Fr::from(2u64))]);
        let err = named
            .as_inputs(&program)
            .expect_err("must fail")
            .to_string();
        assert!(err.contains("needs 2 element(s)"), "{err}");
    }

    #[test]
    fn named_map_rejects_an_undeclared_name() {
        let program = program_with_signals();
        let mut named: BTreeMap<String, Vec<InputValue<Fr>>> = BTreeMap::new();
        named.insert("a".to_owned(), vec![InputValue::Public(Fr::from(1u64))]);
        named.insert(
            "b".to_owned(),
            vec![
                InputValue::Public(Fr::from(2u64)),
                InputValue::Public(Fr::from(3u64)),
            ],
        );
        named.insert("stale".to_owned(), vec![InputValue::Public(Fr::from(4u64))]);
        let err = named
            .as_inputs(&program)
            .expect_err("must fail")
            .to_string();
        assert!(err.contains("stale"), "{err}");
    }
}
