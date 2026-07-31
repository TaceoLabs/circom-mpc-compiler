//! Loop unrolling: circom loops with a statically known trip count are fully unrolled during
//! per-template lowering.

use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use circom_compiler::intermediate_representation::ir_interface::{
    AddressType, Instruction, LocationRule, LoopBucket, OperatorType,
};
use eyre::Result;

use super::build::{to_u64, GraphCompiler};

#[derive(Debug)]
enum Step {
    Up(usize),
    Down(usize),
}

impl<'a, P: Pairing> GraphCompiler<'a, P> {
    fn get_step_size(&self, inst: &Instruction) -> (usize, Step) {
        // must be a top level store
        let (var_index, compute_inst) = if let Instruction::Store(store_bucket) = inst {
            if let LocationRule::Indexed {
                location,
                template_header: _,
            } = &store_bucket.dest
            {
                assert!(
                    matches!(store_bucket.dest_address_type, AddressType::Variable),
                    "must be a variable store for step size"
                );
                let index = self.get_constant_value(location);
                (index, store_bucket.src.as_ref())
            } else {
                panic!("must be an indexed store for induction variable")
            }
        } else {
            panic!("must be top level store bucket for step size");
        };
        match compute_inst {
            Instruction::Compute(compute_bucket) => {
                assert_eq!(compute_bucket.stack.len(), 2, "must be binary op");
                let lhs = &compute_bucket.stack[0];
                let rhs = &compute_bucket.stack[1];
                let step_size = if matches!(lhs.as_ref(), Instruction::Value(_)) {
                    self.get_constant_value(lhs)
                } else if matches!(rhs.as_ref(), Instruction::Value(_)) {
                    self.get_constant_value(rhs)
                } else {
                    panic!("non value inst for compute step size")
                };
                let step = match compute_bucket.op {
                    OperatorType::Add => Step::Up(step_size),
                    OperatorType::Sub => Step::Down(step_size),
                    x => panic!("unsupported induction step operator {}", x.to_string()),
                };
                (var_index, step)
            }
            inst @ Instruction::Value(_) => {
                // a constant round trip
                (var_index, Step::Up(self.get_constant_value(inst)))
            }
            x => panic!(
                "must be compute or value for step size but is {}",
                x.to_string()
            ),
        }
    }

    // we unroll the loop if it is public - if it is shared we panic for the moment
    pub(crate) fn handle_loop_bucket(&mut self, loop_bucket: &LoopBucket) -> Result<()> {
        // the last instruction of the loop body updates the induction variable
        let (var_index, step) = self.get_step_size(
            loop_bucket.body.last().expect("loop body must not be empty"),
        );

        let round_trips =
            if let Instruction::Compute(compute_bucket) = loop_bucket.continue_condition.as_ref() {
                debug_assert_eq!(
                    compute_bucket.stack.len(),
                    2,
                    "only allows binary ops in loop conditions"
                );
                let lhs = self.get_constant_value(&compute_bucket.stack[0]);
                let rhs = self.get_constant_value(&compute_bucket.stack[1]);
                induction_values(&compute_bucket.op, lhs, rhs, step)
            } else {
                panic!("condition not a compute for loop unrolling");
            };
        for induction_var in round_trips {
            for inst in loop_bucket.body[..loop_bucket.body.len() - 1].iter() {
                self.add_induction_variable_node(var_index, induction_var);
                self.handle_inst(inst)?;
            }
        }
        Ok(())
    }

    pub(crate) fn add_induction_variable_node(&mut self, var_index: usize, induction_var: usize) {
        let induction_var = <P::ScalarField as PrimeField>::BigInt::from(to_u64(induction_var));
        let constant = P::ScalarField::from(induction_var);
        let value = self.push_constant_value(constant);
        self.var_to_value.insert(var_index, value);
    }
}

/// The induction variable's values for a `for (i = lhs; i <op> rhs; i +=/-= step)` loop.
fn induction_values(op: &OperatorType, lhs: usize, rhs: usize, step: Step) -> Vec<usize> {
    match (op, step) {
        (OperatorType::Lesser, Step::Up(step)) => (lhs..rhs).step_by(step).collect(),
        (OperatorType::LesserEq, Step::Up(step)) => (lhs..=rhs).step_by(step).collect(),
        (OperatorType::Greater, Step::Down(step)) => (rhs + 1..=lhs).rev().step_by(step).collect(),
        (OperatorType::GreaterEq, Step::Down(step)) => (rhs..=lhs).rev().step_by(step).collect(),
        (op, step) => panic!(
            "unsupported loop shape in unrolling: condition {} with step {step:?}",
            op.to_string()
        ),
    }
}
