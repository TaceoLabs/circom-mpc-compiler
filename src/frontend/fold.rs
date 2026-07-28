//! Compile-time folding for the circom operators `ir::Op` no longer has a runtime variant for.
//!
//! `ir::Op` only carries `Add`/`Sub`/`Mul` as runtime ops (see `docs/ARCHITECTURE.md`). Circom
//! source can still use `/`, `\`, `**`, shifts, and bitwise ops, but only where every operand is a
//! compile-time constant - the moment one operand is a genuine circuit value, lowering it becomes
//! an `Unsupported::NonConstantOperator` error (`build.rs::handle_compute_bucket`) instead of
//! reaching this module.
//!
//! This is the same arithmetic `Interpreter::run` used to apply to these ops at runtime, before the
//! `Op` strip - lifted here verbatim (not reimplemented) so `constants_test`'s witness, which
//! depends on it exactly, doesn't silently change.

use ark_ff::PrimeField;
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

/// Evaluates `op(lhs, rhs)` at compile time, for the operators that no longer have a runtime `Op`
/// variant. Returns `None` if `op` has no compile-time-constant semantics at all (comparisons,
/// booleans, `Mod`, ...) - those are always errors, folded or not.
pub(super) fn fold_binary<F: PrimeField>(op: OperatorType, lhs: F, rhs: F) -> Option<F> {
    match op {
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

/// Evaluates a *comparison or boolean* `op(lhs, rhs)` at compile time, for use as an `if`/`else`
/// condition (`build.rs`'s `Instruction::Branch` arm).
///
/// Deliberately separate from [`fold_binary`], which returns a field element for the removed
/// *arithmetic* operators. These return a `bool`, are never lowered to a node, and have no runtime
/// counterpart at all - a comparison on a genuine circuit value stays an `Unsupported` error
/// regardless of this function (there is no select/mux `Op` to arithmetize it into). This mirrors
/// how `unroll.rs::get_induction_iter` already evaluates a *loop* condition's comparison at compile
/// time; a branch condition is the same problem, so it gets the same treatment rather than a new one.
///
/// Ordering uses circom's own semantics for these operators: the canonical unsigned integer
/// representative, not the field element as such - the same convention [`to_bigint`] exists for.
pub(super) fn fold_condition<F: PrimeField>(op: OperatorType, lhs: F, rhs: F) -> Option<bool> {
    match op {
        // `Eq(n)`'s payload is an array length: `n == 1` is the scalar comparison circom emits for
        // `a == b` on single signals/vars. A wider compare is a genuine element-wise array
        // comparison, which this returns `None` for rather than silently checking only element 0.
        OperatorType::Eq(1) => Some(lhs == rhs),
        OperatorType::NotEq => Some(lhs != rhs),
        OperatorType::Lesser => Some(to_bigint(lhs) < to_bigint(rhs)),
        OperatorType::Greater => Some(to_bigint(lhs) > to_bigint(rhs)),
        OperatorType::LesserEq => Some(to_bigint(lhs) <= to_bigint(rhs)),
        OperatorType::GreaterEq => Some(to_bigint(lhs) >= to_bigint(rhs)),
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
