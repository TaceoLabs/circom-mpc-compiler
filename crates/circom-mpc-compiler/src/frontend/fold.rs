//! Compile-time folding for circom operators that `ir::Op` has no runtime variant for, plus
//! `Add`/`Sub`/`Mul` when they occur at the root of a static branch condition.
//!
//! `ir::Op` only carries `Add`/`Sub`/`Mul` as runtime ops. Circom
//! source can still use `/`, `\`, `**`, shifts, and bitwise ops, but only where every operand is a
//! compile-time constant - the moment one operand is a genuine circuit value, lowering it becomes
//! an `non-constant-operator` error (`build.rs::handle_compute_bucket`) instead of
//! reaching this module.

use std::cmp::Ordering;

use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField};
use num_bigint::BigUint;
use num_traits::Zero as _;

use circom_compiler::intermediate_representation::ir_interface::{OperatorType, SizeOption};

/// Field elements as an unsigned big integer, matching circom's own semantics for `\`, `<<`, `>>`,
/// `|`, `&`, `^` (which all operate on the canonical integer representative, not the field element
/// as such).
fn to_bigint(f: Fr) -> BigUint {
    f.into()
}

/// Evaluates `op(lhs, rhs)` at compile time. Most callers use this for operators that have no
/// runtime `Op` variant; branch conditions additionally use it for `Add`/`Sub`/`Mul`, because the
/// root of `if (a + b)` must be evaluated before it can become an IR node.
///
/// Returns `None` if `op` has no compile-time-constant arithmetic semantics here (comparisons,
/// booleans, `Mod`, ...).
pub(super) fn fold_binary(op: &OperatorType, lhs: Fr, rhs: Fr) -> Option<Fr> {
    match op {
        OperatorType::Add => Some(lhs + rhs),
        OperatorType::Sub => Some(lhs - rhs),
        OperatorType::Mul => Some(lhs * rhs),
        OperatorType::Div => (!rhs.is_zero()).then(|| lhs / rhs),
        OperatorType::IntDiv => {
            let lhs = to_bigint(lhs);
            let rhs = to_bigint(rhs);
            (!rhs.is_zero()).then(|| Fr::from(lhs / rhs))
        }
        OperatorType::Pow => Some(lhs.pow(rhs.into_bigint())),
        OperatorType::ShiftL => {
            let val = to_bigint(lhs);
            let shift = to_bigint(rhs);
            let modulus = BigUint::from_bytes_le(&Fr::MODULUS.to_bytes_le());
            let factor = BigUint::from(2u8).modpow(&shift, &modulus);
            Some(Fr::from((val * factor) % modulus))
        }
        OperatorType::ShiftR => {
            let val = to_bigint(lhs);
            let shift = to_bigint(rhs);
            if shift.bits() > u64::from(usize::BITS) {
                Some(Fr::zero())
            } else {
                let bytes = shift.to_u64_digits();
                let shift = bytes.first().copied().unwrap_or(0);
                if shift >= val.bits() {
                    Some(Fr::zero())
                } else {
                    let shift = usize::try_from(shift)
                        .expect("shift.bits() <= usize::BITS was checked above");
                    Some(Fr::from(val >> shift))
                }
            }
        }
        OperatorType::BitOr => Some(Fr::from(to_bigint(lhs) | to_bigint(rhs))),
        OperatorType::BitAnd => Some(Fr::from(to_bigint(lhs) & to_bigint(rhs))),
        OperatorType::BitXor => Some(Fr::from(to_bigint(lhs) ^ to_bigint(rhs))),
        _ => None,
    }
}

/// Orders canonical field representatives the way circom orders them: values from
/// `floor(p / 2) + 1` through `p - 1` represent negative integers and therefore precede the
/// non-negative half. Within either half, the canonical representatives retain their usual order.
fn circom_cmp(lhs: Fr, rhs: Fr) -> Ordering {
    let lhs = to_bigint(lhs);
    let rhs = to_bigint(rhs);
    let modulus = BigUint::from_bytes_le(&Fr::MODULUS.to_bytes_le());
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
pub(super) fn fold_condition(op: &OperatorType, lhs: Fr, rhs: Fr) -> Option<bool> {
    match op {
        // `Eq(n)`'s payload is an array length: `n == Single(1)` is the scalar comparison circom
        // emits for `a == b` on single signals/vars. A wider compare is a genuine element-wise
        // array comparison, which this returns `None` for rather than silently checking only
        // element 0.
        OperatorType::Eq(SizeOption::Single(1)) => Some(lhs == rhs),
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
pub(super) fn fold_unary_condition(op: &OperatorType, operand: Fr) -> Option<bool> {
    match op {
        OperatorType::BoolNot => Some(operand.is_zero()),
        _ => None,
    }
}
