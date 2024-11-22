use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub trait MpcExecutor<F: PrimeField> {
    type ArithmeticShare: CanonicalSerialize
        + CanonicalDeserialize
        + Clone
        + Default
        + std::fmt::Debug;
    type BinaryShare: CanonicalSerialize + CanonicalDeserialize + Clone + Default + std::fmt::Debug;

    fn a2b(&mut self, a: Self::ArithmeticShare) -> eyre::Result<Self::BinaryShare>;
    fn b2a(&mut self, a: Self::BinaryShare) -> eyre::Result<Self::ArithmeticShare>;

    fn embed_public(a: F) -> Self::ArithmeticShare;
    fn get_public(a: Self::ArithmeticShare) -> F;

    fn open_arithmetic(&mut self, a: Self::ArithmeticShare) -> eyre::Result<F>;
    fn open_binary(&mut self, a: &Self::BinaryShare) -> eyre::Result<F>;

    fn add(&mut self, a: F, b: F) -> F;
    fn add_secret_public(&mut self, a: Self::ArithmeticShare, b: F) -> Self::ArithmeticShare;
    fn add_secret_secret(
        &mut self,
        a: Self::ArithmeticShare,
        b: Self::ArithmeticShare,
    ) -> Self::ArithmeticShare;

    fn sub(&mut self, a: F, b: F) -> F;
    fn sub_public_secret(&mut self, a: F, b: Self::ArithmeticShare) -> Self::ArithmeticShare;
    fn sub_secret_public(&mut self, a: Self::ArithmeticShare, b: F) -> Self::ArithmeticShare;
    fn sub_secret_secret(
        &mut self,
        a: Self::ArithmeticShare,
        b: Self::ArithmeticShare,
    ) -> Self::ArithmeticShare;

    fn mul(&mut self, a: F, b: F) -> F;
    fn mul_secret_public(&mut self, a: Self::ArithmeticShare, b: F) -> Self::ArithmeticShare;
    fn mul_secret_secret(
        &mut self,
        a: Self::ArithmeticShare,
        b: Self::ArithmeticShare,
    ) -> eyre::Result<Self::ArithmeticShare>;

    fn div(&mut self, a: F, b: F) -> F;
    fn div_public_secret(
        &mut self,
        a: F,
        b: Self::ArithmeticShare,
    ) -> eyre::Result<Self::ArithmeticShare>;
    fn div_secret_public(
        &mut self,
        a: Self::ArithmeticShare,
        b: F,
    ) -> eyre::Result<Self::ArithmeticShare>;
    fn div_secret_secret(
        &mut self,
        a: Self::ArithmeticShare,
        b: Self::ArithmeticShare,
    ) -> eyre::Result<Self::ArithmeticShare>;

    fn int_div(&mut self, a: F, b: F) -> eyre::Result<F>;

    fn pow(&mut self, a: F, b: F) -> F;
    fn pow_secret_public(
        &mut self,
        a: Self::ArithmeticShare,
        b: F,
    ) -> eyre::Result<Self::ArithmeticShare>;

    fn rshift(&mut self, a: F, b: F) -> eyre::Result<F>;
    fn rshift_secret_public(
        &mut self,
        a: Self::ArithmeticShare,
        b: F,
    ) -> eyre::Result<Self::ArithmeticShare>;

    fn lshift(&mut self, a: F, b: F) -> eyre::Result<F>;
    fn lshift_secret_public(
        &mut self,
        a: Self::ArithmeticShare,
        b: F,
    ) -> eyre::Result<Self::ArithmeticShare>;

    fn bit_or(&mut self, a: F, b: F) -> F;
    fn bit_or_secret_public(&mut self, a: &Self::BinaryShare, b: F) -> Self::BinaryShare;
    fn bit_or_secret_secret(
        &mut self,
        a: &Self::BinaryShare,
        b: &Self::BinaryShare,
    ) -> eyre::Result<Self::BinaryShare>;

    fn bit_and(&mut self, a: F, b: F) -> F;
    fn bit_and_secret_public(&mut self, a: &Self::BinaryShare, b: F) -> Self::BinaryShare;
    fn bit_and_secret_secret(
        &mut self,
        a: &Self::BinaryShare,
        b: &Self::BinaryShare,
    ) -> eyre::Result<Self::BinaryShare>;

    fn bit_xor(&mut self, a: F, b: F) -> F;
    fn bit_xor_secret_public(&mut self, a: &Self::BinaryShare, b: F) -> Self::BinaryShare;
    fn bit_xor_secret_secret(
        &mut self,
        a: &Self::BinaryShare,
        b: &Self::BinaryShare,
    ) -> Self::BinaryShare;
}
