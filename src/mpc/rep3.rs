use ark_ff::PrimeField;
use mpc_core::protocols::rep3::{
    arithmetic, binary, conversion,
    network::{IoContext, Rep3Network},
    Rep3BigUintShare, Rep3PrimeFieldShare,
};

use super::{plain::PlainExecutor, traits::MpcExecutor};

pub struct Rep3Executor<F: PrimeField, N: Rep3Network> {
    io_context: IoContext<N>,
    plain: PlainExecutor<F>,
}

impl<F: PrimeField, N: Rep3Network> Rep3Executor<F, N> {
    pub fn new(network: N) -> eyre::Result<Self> {
        let io_context = IoContext::init(network)?;
        Ok(Self {
            io_context,
            plain: PlainExecutor::default(),
        })
    }
}

impl<F: PrimeField, N: Rep3Network> MpcExecutor<F> for Rep3Executor<F, N> {
    type ArithmeticShare = Rep3PrimeFieldShare<F>;
    type BinaryShare = Rep3BigUintShare<F>;

    fn a2b(&mut self, a: Self::ArithmeticShare) -> eyre::Result<Self::BinaryShare> {
        Ok(conversion::a2b_selector(a, &mut self.io_context)?)
    }

    fn b2a(&mut self, a: Self::BinaryShare) -> eyre::Result<Self::ArithmeticShare> {
        Ok(conversion::b2a_selector(&a, &mut self.io_context)?)
    }

    fn embed_public(a: F) -> Self::ArithmeticShare {
        Rep3PrimeFieldShare::new(a, F::default())
    }

    fn get_public(a: Self::ArithmeticShare) -> F {
        a.a
    }

    fn open_arithmetic(&mut self, a: Self::ArithmeticShare) -> eyre::Result<F> {
        Ok(arithmetic::open(a, &mut self.io_context)?)
    }

    fn open_binary(&mut self, a: &Self::BinaryShare) -> eyre::Result<F> {
        Ok(binary::open(a, &mut self.io_context)?.into())
    }

    fn add(&mut self, a: F, b: F) -> F {
        self.plain.add(a, b)
    }

    fn add_secret_public(&mut self, a: Self::ArithmeticShare, b: F) -> Self::ArithmeticShare {
        arithmetic::add_public(a, b, self.io_context.id)
    }

    fn add_secret_secret(
        &mut self,
        a: Self::ArithmeticShare,
        b: Self::ArithmeticShare,
    ) -> Self::ArithmeticShare {
        arithmetic::add(a, b)
    }

    fn sub(&mut self, a: F, b: F) -> F {
        self.plain.sub(a, b)
    }

    fn sub_public_secret(&mut self, a: F, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        arithmetic::sub_public_by_shared(a, b, self.io_context.id)
    }

    fn sub_secret_public(&mut self, a: Self::ArithmeticShare, b: F) -> Self::ArithmeticShare {
        arithmetic::sub_shared_by_public(a, b, self.io_context.id)
    }

    fn sub_secret_secret(
        &mut self,
        a: Self::ArithmeticShare,
        b: Self::ArithmeticShare,
    ) -> Self::ArithmeticShare {
        arithmetic::sub(a, b)
    }

    fn mul(&mut self, a: F, b: F) -> F {
        self.plain.mul(a, b)
    }

    fn mul_secret_public(&mut self, a: Self::ArithmeticShare, b: F) -> Self::ArithmeticShare {
        arithmetic::mul_public(a, b)
    }

    fn mul_secret_secret(
        &mut self,
        a: Self::ArithmeticShare,
        b: Self::ArithmeticShare,
    ) -> eyre::Result<Self::ArithmeticShare> {
        let mul_local = arithmetic::local_mul_vec(&[a], &[b], &mut self.io_context.rngs);
        Ok(arithmetic::io_mul_vec(mul_local, &mut self.io_context)?
            .pop()
            .unwrap())
    }

    fn div(&mut self, a: F, b: F) -> F {
        self.plain.div(a, b)
    }

    fn div_public_secret(
        &mut self,
        a: F,
        b: Self::ArithmeticShare,
    ) -> eyre::Result<Self::ArithmeticShare> {
        Ok(arithmetic::div_public_by_shared(
            a,
            b,
            &mut self.io_context,
        )?)
    }

    fn div_secret_public(
        &mut self,
        a: Self::ArithmeticShare,
        b: F,
    ) -> eyre::Result<Self::ArithmeticShare> {
        arithmetic::div_shared_by_public(a, b)
    }

    fn div_secret_secret(
        &mut self,
        a: Self::ArithmeticShare,
        b: Self::ArithmeticShare,
    ) -> eyre::Result<Self::ArithmeticShare> {
        Ok(arithmetic::div(a, b, &mut self.io_context)?)
    }

    fn int_div(&mut self, a: F, b: F) -> eyre::Result<F> {
        self.plain.int_div(a, b)
    }

    fn pow(&mut self, a: F, b: F) -> F {
        self.plain.pow(a, b)
    }

    fn pow_secret_public(
        &mut self,
        a: Self::ArithmeticShare,
        b: F,
    ) -> eyre::Result<Self::ArithmeticShare> {
        Ok(arithmetic::pow_public(a, b, &mut self.io_context)?)
    }

    fn rshift(&mut self, a: F, b: F) -> eyre::Result<F> {
        self.plain.rshift(a, b)
    }

    fn rshift_secret_public(
        &mut self,
        a: Self::ArithmeticShare,
        b: F,
    ) -> eyre::Result<Self::ArithmeticShare> {
        todo!()
    }

    fn lshift(&mut self, a: F, b: F) -> eyre::Result<F> {
        self.plain.lshift(a, b)
    }

    fn lshift_secret_public(
        &mut self,
        a: Self::ArithmeticShare,
        b: F,
    ) -> eyre::Result<Self::ArithmeticShare> {
        todo!()
    }

    fn bit_or(&mut self, a: F, b: F) -> F {
        self.plain.bit_or(a, b)
    }

    fn bit_or_secret_public(&mut self, a: &Self::BinaryShare, b: F) -> Self::BinaryShare {
        binary::or_public(a, &b.into_bigint().into(), self.io_context.id)
    }

    fn bit_or_secret_secret(
        &mut self,
        a: &Self::BinaryShare,
        b: &Self::BinaryShare,
    ) -> eyre::Result<Self::BinaryShare> {
        Ok(binary::or(a, b, &mut self.io_context)?)
    }

    fn bit_and(&mut self, a: F, b: F) -> F {
        self.plain.bit_and(a, b)
    }

    fn bit_and_secret_public(&mut self, a: &Self::BinaryShare, b: F) -> Self::BinaryShare {
        binary::and_with_public(a, &b.into_bigint().into())
    }

    fn bit_and_secret_secret(
        &mut self,
        a: &Self::BinaryShare,
        b: &Self::BinaryShare,
    ) -> eyre::Result<Self::BinaryShare> {
        Ok(binary::and(a, b, &mut self.io_context)?)
    }

    fn bit_xor(&mut self, a: F, b: F) -> F {
        self.plain.bit_xor(a, b)
    }

    fn bit_xor_secret_public(&mut self, a: &Self::BinaryShare, b: F) -> Self::BinaryShare {
        binary::xor_public(a, &b.into_bigint().into(), self.io_context.id)
    }

    fn bit_xor_secret_secret(
        &mut self,
        a: &Self::BinaryShare,
        b: &Self::BinaryShare,
    ) -> Self::BinaryShare {
        binary::xor(a, b)
    }
}
