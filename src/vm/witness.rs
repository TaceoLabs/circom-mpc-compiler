//! Converting this VM's native witness into co-snarks' `SharedWitness`, so a `co-groth16` proof can
//! be produced from it, in the tests and examples that actually prove (`tests/proving.rs`,
//! `tests/merces.rs`, `examples/merces.rs`) - this module has no dependency on co-snarks' proving
//! crates.
//!
//! `Machine::run` returns `Vec<D::Share>` - **uniformly** shared, one entry per witness position in
//! circom's own order, with position 0 the reserved constant `1`. co-snarks'
//! `SharedWitness { public_inputs, witness }` instead splits that into a *cleartext* prefix and a
//! secret-shared remainder, so the conversion is one batched open of the prefix and a move of the
//! rest (`Rep3PrimeFieldShare<F>` is already exactly the element type it wants - both crates pin the
//! same `mpc-core` revision, so there is no version skew to bridge).
//!
//! **The split index comes from the zkey, not from this compiler.** `ConstraintMatrices::
//! num_instance_variables` is circom's own count of instance variables for the circuit being proved.
//! Re-deriving it here from `Program::input_domains` would only be an approximation, because
//! `passes::mpc::domain` falls back to `Shared` conservatively when it cannot prove a signal public -
//! harmless for lowering (it just costs an optimization) but wrong as a split point, where being off
//! by one silently produces a proof over the wrong statement.

use ark_ff::PrimeField;

use super::driver::VmDriver;

/// Splits a `Machine::run` witness into `(public_inputs, witness)` at `n_pub`, opening the prefix.
///
/// `n_pub` must be `ConstraintMatrices::num_instance_variables` for the same circuit - see the module
/// doc. It counts the leading `1`, so `public_inputs[0] == 1` and a verifier's public input list is
/// `public_inputs[1..]`.
pub fn split_witness<F: PrimeField, D: VmDriver<F>>(
    driver: &mut D,
    witness: Vec<D::Share>,
    n_pub: usize,
) -> eyre::Result<(Vec<F>, Vec<D::Share>)> {
    eyre::ensure!(
        n_pub <= witness.len(),
        "witness has {} entries but the zkey declares {n_pub} instance variables - the program and \
         the zkey were built from different circuits",
        witness.len()
    );
    eyre::ensure!(
        n_pub > 0,
        "n_pub must count the reserved constant-1 witness entry, so it is never 0"
    );
    let mut witness = witness;
    let secret = witness.split_off(n_pub);
    let public = driver.open(&witness)?;
    debug_assert_eq!(public.len(), n_pub);
    eyre::ensure!(
        public[0] == F::one(),
        "witness position 0 must be the reserved constant 1, got something else - either the program \
         is malformed or n_pub is misaligned"
    );
    Ok((public, secret))
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;

    use super::*;
    use crate::vm::driver::plain::PlainDriver;

    #[test]
    fn splits_at_n_pub_and_opens_the_prefix() {
        let witness = vec![Fr::from(1u64), Fr::from(7u64), Fr::from(9u64), Fr::from(4u64)];
        let (public, secret) = split_witness(&mut PlainDriver, witness, 3).unwrap();
        assert_eq!(public, vec![Fr::from(1u64), Fr::from(7u64), Fr::from(9u64)]);
        assert_eq!(secret, vec![Fr::from(4u64)]);
    }

    #[test]
    fn rejects_a_misaligned_split() {
        // n_pub longer than the witness: program and zkey disagree.
        let witness = vec![Fr::from(1u64), Fr::from(2u64)];
        assert!(split_witness(&mut PlainDriver, witness, 5).is_err());

        // Position 0 not the reserved 1: a malformed program, or n_pub off by one.
        let witness = vec![Fr::from(3u64), Fr::from(2u64)];
        assert!(split_witness(&mut PlainDriver, witness, 1).is_err());
    }
}
