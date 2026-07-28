//! Compile-time folding for circom operators that `ir::Op` has no runtime variant for, plus
//! `Add`/`Sub`/`Mul` when they occur at the root of a static branch condition.
//!
//! `ir::Op` only carries `Add`/`Sub`/`Mul` as runtime ops (see `docs/ARCHITECTURE.md`). Circom
//! source can still use `/`, `\`, `**`, shifts, and bitwise ops, but only where every operand is a
//! compile-time constant - the moment one operand is a genuine circuit value, lowering it becomes
//! an `Unsupported::NonConstantOperator` error (`build.rs::handle_compute_bucket`) instead of
//! reaching this module.

use std::cmp::Ordering;

use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;
use num_traits::ToPrimitive;

use circom_compiler::intermediate_representation::ir_interface::OperatorType;

/// Field elements as an unsigned big integer, matching circom's own semantics for `\`, `<<`, `>>`,
/// `|`, `&`, `^` (which all operate on the canonical integer representative, not the field element
/// as such).
fn to_bigint<F: PrimeField>(f: F) -> BigUint {
    f.into()
}

fn to_u128<F: PrimeField>(f: F) -> u128 {
    to_bigint(f).to_u128().expect("does not fit into u128")
}

fn to_usize<F: PrimeField>(f: F) -> usize {
    to_bigint(f)
        .to_u64()
        .expect("does not fit into u64")
        .try_into()
        .expect("does not fit into usize")
}

/// Evaluates `op(lhs, rhs)` at compile time. Most callers use this for operators that have no
/// runtime `Op` variant; branch conditions additionally use it for `Add`/`Sub`/`Mul`, because the
/// root of `if (a + b)` must be evaluated before it can become an IR node.
///
/// Returns `None` if `op` has no compile-time-constant arithmetic semantics here (comparisons,
/// booleans, `Mod`, ...).
pub(super) fn fold_binary<F: PrimeField>(op: OperatorType, lhs: F, rhs: F) -> Option<F> {
    match op {
        OperatorType::Add => Some(lhs + rhs),
        OperatorType::Sub => Some(lhs - rhs),
        OperatorType::Mul => Some(lhs * rhs),
        OperatorType::Div => Some(lhs / rhs),
        OperatorType::IntDiv => {
            let lhs = to_u128(lhs);
            let rhs = to_u128(rhs);
            Some(F::from(lhs / rhs))
        }
        OperatorType::Pow => Some(lhs.pow(rhs.into_bigint())),
        OperatorType::ShiftL => {
            let val = to_bigint(lhs);
            let shift = to_usize(rhs);
            Some(F::from(val << shift))
        }
        OperatorType::ShiftR => {
            let val = to_bigint(lhs);
            let shift = to_usize(rhs);
            Some(F::from(val >> shift))
        }
        OperatorType::BitOr => Some(F::from(to_bigint(lhs) | to_bigint(rhs))),
        OperatorType::BitAnd => Some(F::from(to_bigint(lhs) & to_bigint(rhs))),
        OperatorType::BitXor => Some(F::from(to_bigint(lhs) ^ to_bigint(rhs))),
        _ => None,
    }
}

/// Orders canonical field representatives the way circom orders them: values from
/// `floor(p / 2) + 1` through `p - 1` represent negative integers and therefore precede the
/// non-negative half. Within either half, the canonical representatives retain their usual order.
fn circom_cmp<F: PrimeField>(lhs: F, rhs: F) -> Ordering {
    let lhs = to_bigint(lhs);
    let rhs = to_bigint(rhs);
    let modulus = BigUint::from_bytes_le(&F::MODULUS.to_bytes_le());
    let negative_threshold = (modulus >> 1usize) + BigUint::from(1u8);
    match (lhs >= negative_threshold, rhs >= negative_threshold) {
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        _ => lhs.cmp(&rhs),
    }
}

/// Evaluates a *comparison or boolean* `op(lhs, rhs)` at compile time, for use as an `if`/`else`
/// condition (`build.rs`'s `Instruction::Branch` arm).
///
/// Deliberately separate from [`fold_binary`], which returns a field element for arithmetic
/// operators. These return a `bool`, are never lowered to a node, and have no runtime counterpart
/// at all - a comparison on a genuine circuit value stays an `Unsupported` error regardless of
/// this function (there is no select/mux `Op` to arithmetize it into). This mirrors
/// how `unroll.rs::get_induction_iter` already evaluates a *loop* condition's comparison at compile
/// time; a branch condition is the same problem, so it gets the same treatment rather than a new one.
///
/// Ordering uses circom's signed field convention: canonical representatives at or above
/// `floor(p / 2) + 1` denote negative integers.
pub(super) fn fold_condition<F: PrimeField>(op: OperatorType, lhs: F, rhs: F) -> Option<bool> {
    match op {
        // `Eq(n)`'s payload is an array length: `n == 1` is the scalar comparison circom emits for
        // `a == b` on single signals/vars. A wider compare is a genuine element-wise array
        // comparison, which this returns `None` for rather than silently checking only element 0.
        OperatorType::Eq(1) => Some(lhs == rhs),
        OperatorType::NotEq => Some(lhs != rhs),
        OperatorType::Lesser => Some(circom_cmp(lhs, rhs).is_lt()),
        OperatorType::Greater => Some(circom_cmp(lhs, rhs).is_gt()),
        OperatorType::LesserEq => Some(circom_cmp(lhs, rhs).is_le()),
        OperatorType::GreaterEq => Some(circom_cmp(lhs, rhs).is_ge()),
        OperatorType::BoolAnd => Some(!lhs.is_zero() && !rhs.is_zero()),
        OperatorType::BoolOr => Some(!lhs.is_zero() || !rhs.is_zero()),
        _ => None,
    }
}

/// The unary counterpart of [`fold_condition`], for `if (!x)`.
pub(super) fn fold_unary_condition<F: PrimeField>(op: OperatorType, operand: F) -> Option<bool> {
    match op {
        OperatorType::BoolNot => Some(operand.is_zero()),
        _ => None,
    }
}
