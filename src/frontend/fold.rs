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
