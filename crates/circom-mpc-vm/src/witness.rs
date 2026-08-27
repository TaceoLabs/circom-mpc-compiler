//! Converts this VM's uniformly-shared witness into co-snarks' `SharedWitness` (a cleartext
//! `public_inputs` prefix plus a secret-shared remainder): one batched open of the prefix, then a
//! move of the rest.
//!
//! **The split index comes from the zkey, not from this compiler.** Re-deriving it from
//! `Program::input_domains` would only be an approximation (the domain analysis falls back to
//! `Shared` conservatively), and an off-by-one split silently proves the wrong statement.

use ark_bn254::Fr;
use ark_ff::One;

use super::driver::VmDriver;

/// Splits a `Machine::run` witness into `(public_inputs, witness)` at `n_pub`, opening the prefix.
///
/// `n_pub` must be `ConstraintMatrices::num_instance_variables` for the same circuit - see the module
/// doc. It counts the leading `1`, so `public_inputs[0] == 1` and a verifier's public input list is
/// `public_inputs[1..]`.
pub fn split_witness<D: VmDriver>(
    driver: &mut D,
    witness: Vec<D::Share>,
    n_pub: usize,
) -> eyre::Result<(Vec<Fr>, Vec<D::Share>)> {
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
        public[0] == Fr::one(),
        "witness position 0 must be the reserved constant 1, got something else - either the program \
         is malformed or n_pub is misaligned"
    );
    Ok((public, secret))
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;

    use super::*;
    use crate::driver::plain::PlainDriver;

    #[test]
    fn splits_at_n_pub_and_opens_the_prefix() {
        let witness = vec![
            Fr::from(1u64),
            Fr::from(7u64),
            Fr::from(9u64),
            Fr::from(4u64),
        ];
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
