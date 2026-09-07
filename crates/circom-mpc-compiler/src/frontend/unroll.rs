//! Loop unrolling: circom loops with a statically known trip count are fully unrolled during
//! per-template lowering.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use circom_compiler::intermediate_representation::ir_interface::{
    AddressType, Instruction, LocationRule, LoopBucket, OperatorType,
};
use eyre::Result;

use super::build::{GraphCompiler, to_u64};

#[derive(Clone, Copy, Debug)]
enum Step {
    Up(usize),
    Down(usize),
}

impl GraphCompiler<'_> {
    fn get_step_size(&self, inst: &Instruction) -> Result<(usize, Step)> {
        // must be a top level store
        let (var_index, compute_inst) = if let Instruction::Store(store_bucket) = inst {
            if let LocationRule::Indexed {
                location,
                template_header: _,
            } = &store_bucket.dest
            {
                eyre::ensure!(
                    matches!(store_bucket.dest_address_type, AddressType::Variable),
                    "loop induction step must store a variable"
                );
                let index = self.get_constant_value(location);
                (index, store_bucket.src.as_ref())
            } else {
                eyre::bail!("loop induction step must use an indexed variable store")
            }
        } else {
            eyre::bail!("loop induction step must be a top-level store");
        };
        match compute_inst {
            Instruction::Compute(compute_bucket) => {
                eyre::ensure!(
                    compute_bucket.stack.len() == 2,
                    "loop induction step must be binary"
                );
                let lhs = &compute_bucket.stack[0];
                let rhs = &compute_bucket.stack[1];
                let step_size = if matches!(lhs.as_ref(), Instruction::Value(_)) {
                    self.get_constant_value(lhs)
                } else if matches!(rhs.as_ref(), Instruction::Value(_)) {
                    self.get_constant_value(rhs)
                } else {
                    eyre::bail!("loop induction step must contain a constant")
                };
                let step = match &compute_bucket.op {
                    OperatorType::Add => Step::Up(step_size),
                    OperatorType::Sub => Step::Down(step_size),
                    x => eyre::bail!("unsupported loop induction operator {}", x.to_string()),
                };
                eyre::ensure!(step_size != 0, "loop induction step must be nonzero");
                Ok((var_index, step))
            }
            inst @ Instruction::Value(_) => {
                // a constant round trip
                let step = self.get_constant_value(inst);
                eyre::ensure!(step != 0, "loop induction step must be nonzero");
                Ok((var_index, Step::Up(step)))
            }
            x => eyre::bail!("unsupported loop induction expression {}", x.to_string()),
        }
    }

    // we unroll the loop if it is public - if it is shared we panic for the moment
    pub(crate) fn handle_loop_bucket(&mut self, loop_bucket: &LoopBucket) -> Result<()> {
        // the last instruction of the loop body updates the induction variable
        let last = loop_bucket
            .body
            .last()
            .ok_or_else(|| eyre::eyre!("loop body must not be empty"))?;
        let (var_index, step) = self.get_step_size(last)?;

        let round_trips =
            if let Instruction::Compute(compute_bucket) = loop_bucket.continue_condition.as_ref() {
                eyre::ensure!(
                    compute_bucket.stack.len() == 2,
                    "loop condition must be binary"
                );
                let lhs = self.get_constant_value(&compute_bucket.stack[0]);
                let rhs = self.get_constant_value(&compute_bucket.stack[1]);
                induction_values(&compute_bucket.op, lhs, rhs, step)?
            } else {
                eyre::bail!("loop condition must be a comparison");
            };
        for &induction_var in &round_trips {
            self.add_induction_variable_node(var_index, induction_var);
            for inst in &loop_bucket.body[..loop_bucket.body.len() - 1] {
                if stores_variable(inst, var_index, self) {
                    eyre::bail!("loop body writes to induction variable");
                }
                self.handle_inst(inst)?;
            }
        }
        let terminal = match (round_trips.last().copied(), step) {
            (Some(value), Step::Up(step)) => value.checked_add(step),
            (Some(value), Step::Down(step)) => value.checked_sub(step),
            (None, _) => None,
        };
        if let Some(value) = terminal {
            self.add_induction_variable_node(var_index, value);
        } else if let (Some(value), Step::Down(step)) = (round_trips.last().copied(), step) {
            let value = Fr::from(to_u64(value)) - Fr::from(to_u64(step));
            let node = self.push_constant_value(value);
            self.var_to_value.insert(var_index, node);
        }
        Ok(())
    }

    pub(crate) fn add_induction_variable_node(&mut self, var_index: usize, induction_var: usize) {
        let induction_var = <Fr as PrimeField>::BigInt::from(to_u64(induction_var));
        let constant = Fr::from(induction_var);
        let value = self.push_constant_value(constant);
        self.var_to_value.insert(var_index, value);
    }
}

/// The induction variable's values for a `for (i = lhs; i <op> rhs; i +=/-= step)` loop.
fn induction_values(op: &OperatorType, lhs: usize, rhs: usize, step: Step) -> Result<Vec<usize>> {
    let condition = |value| match op {
        OperatorType::Lesser => value < rhs,
        OperatorType::LesserEq => value <= rhs,
        OperatorType::Greater => value > rhs,
        OperatorType::GreaterEq => value >= rhs,
        _ => false,
    };
    eyre::ensure!(
        matches!(
            (op, &step),
            (OperatorType::Lesser | OperatorType::LesserEq, Step::Up(_))
                | (
                    OperatorType::Greater | OperatorType::GreaterEq,
                    Step::Down(_)
                )
        ),
        "unsupported loop shape"
    );
    let mut values = Vec::new();
    let mut value = lhs;
    while condition(value) {
        values.push(value);
        let Some(next) = (match step {
            Step::Up(n) => value.checked_add(n),
            Step::Down(n) => value.checked_sub(n),
        }) else {
            break;
        };
        value = next;
    }
    Ok(values)
}

fn stores_variable(inst: &Instruction, var_index: usize, compiler: &GraphCompiler<'_>) -> bool {
    matches!(inst, Instruction::Store(store) if matches!(store.dest_address_type, AddressType::Variable)
        && matches!(&store.dest, LocationRule::Indexed { location, .. } if compiler.get_constant_value(location) == var_index))
}
