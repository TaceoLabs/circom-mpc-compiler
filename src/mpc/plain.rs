use ark_ff::{One, PrimeField};
use eyre::eyre;
use num_bigint::BigUint;
use num_traits::ToPrimitive;

use super::traits::MpcExecutor;

/// Transforms a field element into an usize if possible.
macro_rules! to_usize {
    ($field: expr) => {{
        let a: BigUint = $field.into();
        usize::try_from(a.to_u64().ok_or(eyre!("Cannot convert var into u64"))?)?
    }};
}

macro_rules! bool_comp_op {
    ($driver: expr, $lhs: expr, $op: tt, $rhs: expr) => {{
        let lhs = $driver.val($lhs);
        let rhs = $driver.val($rhs);
       if (lhs $op rhs){
        tracing::trace!("{}{}{} -> 1", $lhs,stringify!($op), $rhs);
        F::one()
       } else {
        tracing::trace!("{}{}{} -> 0", $lhs,stringify!($op), $rhs);
        F::zero()
       }
    }};
}

macro_rules! to_u128 {
    ($field: expr) => {{
        let a: BigUint = $field.into();
        a.to_u128().ok_or(eyre!("Cannot convert var into u64"))?
    }};
}

macro_rules! to_bigint {
    ($field: expr) => {{
        let a: BigUint = $field.into();
        a
    }};
}

#[derive(Debug, Clone)]
pub struct PlainExecutor<F: PrimeField> {
    negative_one: F,
}

impl<F: PrimeField> Default for PlainExecutor<F> {
    fn default() -> Self {
        let modulus = to_bigint!(F::MODULUS);
        let one = BigUint::one();
        let two = BigUint::from(2u64);
        Self {
            negative_one: F::from(modulus / two + one),
        }
    }
}

impl<F: PrimeField> MpcExecutor<F> for PlainExecutor<F> {
    type ArithmeticShare = F;
    type BinaryShare = F;

    fn a2b(&mut self, a: Self::ArithmeticShare) -> eyre::Result<Self::BinaryShare> {
        Ok(a)
    }

    fn b2a(&mut self, a: Self::BinaryShare) -> eyre::Result<Self::ArithmeticShare> {
        Ok(a)
    }

    fn embed_public(a: F) -> Self::ArithmeticShare {
        a
    }

    fn get_public(a: Self::ArithmeticShare) -> F {
        a
    }

    fn open_arithmetic(&mut self, a: Self::ArithmeticShare) -> eyre::Result<F> {
        Ok(a)
    }

    fn open_binary(&mut self, a: &Self::BinaryShare) -> eyre::Result<F> {
        Ok(*a)
    }

    fn add(&mut self, a: F, b: F) -> F {
        a + b
    }

    fn add_secret_public(&mut self, a: Self::ArithmeticShare, b: F) -> Self::ArithmeticShare {
        a + b
    }

    fn add_secret_secret(
        &mut self,
        a: Self::ArithmeticShare,
        b: Self::ArithmeticShare,
    ) -> Self::ArithmeticShare {
        a + b
    }

    fn sub(&mut self, a: F, b: F) -> F {
        a - b
    }

    fn sub_public_secret(&mut self, a: F, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        a - b
    }

    fn sub_secret_public(&mut self, a: Self::ArithmeticShare, b: F) -> Self::ArithmeticShare {
        a - b
    }

    fn sub_secret_secret(
        &mut self,
        a: Self::ArithmeticShare,
        b: Self::ArithmeticShare,
    ) -> Self::ArithmeticShare {
        a - b
    }

    fn mul(&mut self, a: F, b: F) -> F {
        a * b
    }

    fn mul_secret_public(&mut self, a: Self::ArithmeticShare, b: F) -> Self::ArithmeticShare {
        a * b
    }

    fn mul_secret_secret(
        &mut self,
        a: Self::ArithmeticShare,
        b: Self::ArithmeticShare,
    ) -> eyre::Result<F> {
        Ok(a * b)
    }

    fn div(&mut self, a: F, b: F) -> F {
        a / b
    }

    fn div_public_secret(
        &mut self,
        a: F,
        b: Self::ArithmeticShare,
    ) -> eyre::Result<Self::ArithmeticShare> {
        Ok(a / b)
    }

    fn div_secret_public(
        &mut self,
        a: Self::ArithmeticShare,
        b: F,
    ) -> eyre::Result<Self::ArithmeticShare> {
        Ok(a / b)
    }

    fn div_secret_secret(
        &mut self,
        a: Self::ArithmeticShare,
        b: Self::ArithmeticShare,
    ) -> eyre::Result<Self::ArithmeticShare> {
        Ok(a / b)
    }

    fn int_div(&mut self, a: F, b: F) -> eyre::Result<F> {
        let lhs = to_u128!(a);
        let rhs = to_u128!(b);
        Ok(F::from(lhs / rhs))
    }

    fn pow(&mut self, a: F, b: F) -> F {
        a.pow(b.into_bigint())
    }

    fn pow_secret_public(
        &mut self,
        a: Self::ArithmeticShare,
        b: F,
    ) -> eyre::Result<Self::ArithmeticShare> {
        Ok(a.pow(b.into_bigint()))
    }

    fn rshift(&mut self, a: F, b: F) -> eyre::Result<F> {
        let val = to_bigint!(a);
        let shift = to_usize!(b);
        Ok(F::from(val >> shift))
    }

    fn rshift_secret_public(
        &mut self,
        a: Self::ArithmeticShare,
        b: F,
    ) -> eyre::Result<Self::ArithmeticShare> {
        let val = to_bigint!(a);
        let shift = to_usize!(b);
        Ok(F::from(val >> shift))
    }

    fn lshift(&mut self, a: F, b: F) -> eyre::Result<F> {
        let val = to_bigint!(a);
        let shift = to_usize!(b);
        Ok(F::from(val << shift))
    }

    fn lshift_secret_public(
        &mut self,
        a: Self::ArithmeticShare,
        b: F,
    ) -> eyre::Result<Self::ArithmeticShare> {
        let val = to_bigint!(a);
        let shift = to_usize!(b);
        Ok(F::from(val << shift))
    }

    fn bit_or(&mut self, a: F, b: F) -> F {
        let lhs = to_bigint!(a);
        let rhs = to_bigint!(b);
        F::from(lhs | rhs)
    }

    fn bit_or_secret_public(&mut self, a: &Self::BinaryShare, b: F) -> Self::BinaryShare {
        let lhs = to_bigint!(*a);
        let rhs = to_bigint!(b);
        F::from(lhs | rhs)
    }

    fn bit_or_secret_secret(
        &mut self,
        a: &Self::BinaryShare,
        b: &Self::BinaryShare,
    ) -> eyre::Result<Self::BinaryShare> {
        let lhs = to_bigint!(*a);
        let rhs = to_bigint!(*b);
        Ok(F::from(lhs | rhs))
    }

    fn bit_and(&mut self, a: F, b: F) -> F {
        let lhs = to_bigint!(a);
        let rhs = to_bigint!(b);
        F::from(lhs & rhs)
    }

    fn bit_and_secret_public(&mut self, a: &Self::BinaryShare, b: F) -> Self::BinaryShare {
        let lhs = to_bigint!(*a);
        let rhs = to_bigint!(b);
        F::from(lhs & rhs)
    }

    fn bit_and_secret_secret(
        &mut self,
        a: &Self::BinaryShare,
        b: &Self::BinaryShare,
    ) -> eyre::Result<Self::BinaryShare> {
        let lhs = to_bigint!(*a);
        let rhs = to_bigint!(*b);
        Ok(F::from(lhs & rhs))
    }

    fn bit_xor(&mut self, a: F, b: F) -> F {
        let lhs = to_bigint!(a);
        let rhs = to_bigint!(b);
        F::from(lhs ^ rhs)
    }

    fn bit_xor_secret_public(&mut self, a: &Self::BinaryShare, b: F) -> Self::BinaryShare {
        let lhs = to_bigint!(*a);
        let rhs = to_bigint!(b);
        F::from(lhs ^ rhs)
    }

    fn bit_xor_secret_secret(
        &mut self,
        a: &Self::BinaryShare,
        b: &Self::BinaryShare,
    ) -> Self::BinaryShare {
        let lhs = to_bigint!(*a);
        let rhs = to_bigint!(*b);
        F::from(lhs ^ rhs)
    }
}
