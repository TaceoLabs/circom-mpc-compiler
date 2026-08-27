use ark_bn254::Fr;

use crate::program::Bank;
use crate::Program;

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
/// produces, so callers can pass a `Vec`, an array, a slice, or a `Result` of one interchangeably.
pub trait InputValues<S> {
    /// Returns the values as a slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying container itself represents a failure (e.g. the
    /// `eyre::Result<Vec<_>>` impl).
    fn as_inputs(&self) -> eyre::Result<&[InputValue<S>]>;
}

impl<S> InputValues<S> for [InputValue<S>] {
    fn as_inputs(&self) -> eyre::Result<&[InputValue<S>]> {
        Ok(self)
    }
}

impl<S> InputValues<S> for Vec<InputValue<S>> {
    fn as_inputs(&self) -> eyre::Result<&[InputValue<S>]> {
        Ok(self)
    }
}

impl<S, const N: usize> InputValues<S> for [InputValue<S>; N] {
    fn as_inputs(&self) -> eyre::Result<&[InputValue<S>]> {
        Ok(self)
    }
}

impl<S> InputValues<S> for eyre::Result<Vec<InputValue<S>>> {
    fn as_inputs(&self) -> eyre::Result<&[InputValue<S>]> {
        self.as_ref()
            .map(Vec::as_slice)
            .map_err(|error| eyre::eyre!(error.to_string()))
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
