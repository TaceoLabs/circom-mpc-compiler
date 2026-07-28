//! Canonical affine form used by `passes/normalize.rs`: `constant + sum(coeff * atom)`, over
//! *atoms* - values that are not themselves `Add`/`Sub`/mul-by-constant (an `Input`, a `Constant`,
//! a genuine secret*secret `Mul`, a `PrecomputeResult`, ...). `normalize` collapses every maximal
//! `Add`/`Sub`/mul-by-constant tree into one of these, which is what lets it cancel terms
//! (`(a+b)-a -> b`) and reassociate long chains circom happened to nest arbitrarily.
//!
//! Degree is deliberately capped at 1 (affine, not quadratic) - see `docs/ARCHITECTURE.md`, "MPC
//! lowering", for why a degree-2 extension (fusing multiple products behind one reshare slot) is
//! rejected rather than built speculatively here.

use ark_ff::PrimeField;

use crate::ir::ValueId;

#[derive(Debug, Clone)]
pub(crate) struct Affine<F: PrimeField> {
    pub(crate) constant: F,
    /// Sorted by `ValueId`, no zero coefficients.
    pub(crate) terms: Vec<(F, ValueId)>,
}

impl<F: PrimeField> Affine<F> {
    pub(crate) fn constant(c: F) -> Self {
        Self {
            constant: c,
            terms: Vec::new(),
        }
    }

    pub(crate) fn atom(v: ValueId) -> Self {
        Self {
            constant: F::zero(),
            terms: vec![(F::one(), v)],
        }
    }

    pub(crate) fn add(&self, other: &Self) -> Self {
        self.combine(other, F::one())
    }

    pub(crate) fn sub(&self, other: &Self) -> Self {
        self.combine(other, -F::one())
    }

    fn combine(&self, other: &Self, sign: F) -> Self {
        let mut terms = self.terms.clone();
        for &(c, v) in &other.terms {
            match terms.binary_search_by_key(&v, |&(_, tv)| tv) {
                Ok(pos) => terms[pos].0 += c * sign,
                Err(pos) => terms.insert(pos, (c * sign, v)),
            }
        }
        terms.retain(|&(c, _)| c != F::zero());
        Self {
            constant: self.constant + other.constant * sign,
            terms,
        }
    }

    pub(crate) fn scale(&self, k: F) -> Self {
        if k == F::zero() {
            return Self::constant(F::zero());
        }
        Self {
            constant: self.constant * k,
            terms: self.terms.iter().map(|&(c, v)| (c * k, v)).collect(),
        }
    }

    /// If this form is a bare constant (no terms), returns it.
    pub(crate) fn as_constant(&self) -> Option<F> {
        if self.terms.is_empty() {
            Some(self.constant)
        } else {
            None
        }
    }

    /// If this form is exactly one bare atom (coefficient 1, no constant), returns it.
    pub(crate) fn as_atom(&self) -> Option<ValueId> {
        if self.constant == F::zero() && self.terms.len() == 1 && self.terms[0].0 == F::one() {
            Some(self.terms[0].1)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;

    use crate::ir::ValueId;

    use super::*;

    #[test]
    fn cancels_matching_terms() {
        // (a+b) - a -> b
        let a = Affine::<Fr>::atom(ValueId::new(0));
        let b = Affine::<Fr>::atom(ValueId::new(1));
        let sum = a.add(&b);
        let result = sum.sub(&a);
        assert_eq!(result.as_atom(), Some(ValueId::new(1)));
    }

    #[test]
    fn scale_by_zero_collapses_to_zero_constant() {
        let a = Affine::<Fr>::atom(ValueId::new(0));
        let scaled = a.scale(Fr::from(0u64));
        assert_eq!(scaled.as_constant(), Some(Fr::from(0u64)));
    }

    #[test]
    fn combines_like_terms() {
        // a + a -> 2a
        let a = Affine::<Fr>::atom(ValueId::new(0));
        let sum = a.add(&a);
        assert_eq!(sum.terms, vec![(Fr::from(2u64), ValueId::new(0))]);
    }
}
