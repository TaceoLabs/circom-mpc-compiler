//! Canonical affine form used by `passes/normalize.rs`: `constant + sum(coeff * atom)`, over
//! *atoms* - values that are not themselves `Add`/`Sub`/mul-by-constant (an `Input`, a `Constant`,
//! a genuine secret*secret `Mul`, a `PrecomputeResult`, ...). `normalize` collapses every maximal
//! `Add`/`Sub`/mul-by-constant tree into one of these, which is what lets it cancel terms
//! (`(a+b)-a -> b`) and reassociate long chains circom happened to nest arbitrarily.
//!
//! Degree is deliberately capped at 1 (affine, not quadratic), for why a degree-2 extension (fusing multiple products behind one reshare slot) is
//! rejected rather than built speculatively here.

use std::collections::HashMap;

use ark_ff::PrimeField;

use crate::ir::ValueId;

#[derive(Debug, Clone)]
pub(crate) struct Affine<F: PrimeField> {
    pub(crate) constant: F,
    /// Coefficients before applying `term_scale`, with no zero entries. Keeping the common scale
    /// separate makes both scaling and a small-to-large merge constant-time in the size of the
    /// larger map (including when subtraction chooses its right-hand map as the destination).
    term_scale: F,
    terms: HashMap<ValueId, F>,
}

impl<F: PrimeField> Affine<F> {
    pub(crate) fn constant(c: F) -> Self {
        Self {
            constant: c,
            term_scale: F::one(),
            terms: HashMap::new(),
        }
    }

    pub(crate) fn atom(v: ValueId) -> Self {
        Self {
            constant: F::zero(),
            term_scale: F::one(),
            terms: HashMap::from([(v, F::one())]),
        }
    }

    pub(crate) fn add(self, other: Self) -> Self {
        self.combine(other, F::one())
    }

    pub(crate) fn sub(self, other: Self) -> Self {
        self.combine(other, -F::one())
    }

    fn combine(self, mut other: Self, sign: F) -> Self {
        let constant = self.constant + other.constant * sign;
        other.term_scale *= sign;

        // Insert the smaller map into the larger one. `term_scale` lets the destination keep its
        // representation unchanged: only coefficients crossing into it need conversion.
        let (mut base, small) = if self.terms.len() >= other.terms.len() {
            (self, other)
        } else {
            (other, self)
        };
        let ratio = if small.term_scale == base.term_scale {
            F::one()
        } else if small.term_scale == -base.term_scale {
            -F::one()
        } else {
            small.term_scale
                * base
                    .term_scale
                    .inverse()
                    .expect("an affine term scale is never zero")
        };
        for (atom, coefficient) in small.terms {
            let scaled = coefficient * ratio;
            match base.terms.entry(atom) {
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    *entry.get_mut() += scaled;
                    if *entry.get() == F::zero() {
                        entry.remove();
                    }
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(scaled);
                }
            }
        }
        base.constant = constant;
        base
    }

    pub(crate) fn scale(mut self, k: F) -> Self {
        if k == F::zero() {
            return Self::constant(F::zero());
        }
        self.constant *= k;
        self.term_scale *= k;
        self
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
        if self.constant == F::zero() && self.terms.len() == 1 {
            let (&atom, &coefficient) = self.terms.iter().next().unwrap();
            (coefficient * self.term_scale == F::one()).then_some(atom)
        } else {
            None
        }
    }

    /// Terms in deterministic `ValueId` order, with the lazy common scale applied. Sorting is
    /// deliberately deferred until a form is actually materialized: most intermediate forms are
    /// moved into a successor and never emitted on their own.
    pub(crate) fn sorted_terms(&self) -> Vec<(F, ValueId)> {
        let mut terms: Vec<_> = self
            .terms
            .iter()
            .map(|(&atom, &coefficient)| (coefficient * self.term_scale, atom))
            .collect();
        terms.sort_unstable_by_key(|&(_, atom)| atom);
        terms
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
        let sum = a.clone().add(b);
        let result = sum.sub(a);
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
        let sum = a.clone().add(a);
        assert_eq!(sum.sorted_terms(), vec![(Fr::from(2u64), ValueId::new(0))]);
    }

    #[test]
    fn subtraction_can_merge_into_the_larger_right_hand_map() {
        let a = Affine::<Fr>::atom(ValueId::new(0));
        let b = Affine::<Fr>::atom(ValueId::new(1));
        let c = Affine::<Fr>::atom(ValueId::new(2));
        let rhs = a.clone().add(b).add(c);

        let result = a.sub(rhs);
        assert_eq!(
            result.sorted_terms(),
            vec![
                (-Fr::from(1u64), ValueId::new(1)),
                (-Fr::from(1u64), ValueId::new(2)),
            ]
        );
    }
}
