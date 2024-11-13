use core::panic;

use ark_ec::pairing::Pairing;
use circom_compiler::intermediate_representation::ir_interface::{
    Instruction, LoopBucket, OperatorType,
};
use eyre::Result;

use super::translate::GraphCompiler;

#[derive(Debug)]
enum StepType {
    Add(usize),
    Sub(usize),
    Mul(usize),
}

impl<'a, P: Pairing> GraphCompiler<'a, P> {
    fn get_step_size(&self, inst: &Instruction) -> StepType {
        // must be a top level store
        let compute_inst = if let Instruction::Store(store_bucket) = inst {
            store_bucket.src.as_ref()
        } else {
            panic!("must be top level store bucket for step size");
        };
        tracing::info!("{}", compute_inst.to_string());
        let compute_bucket = if let Instruction::Compute(compute_bucket) = compute_inst {
            compute_bucket
        } else {
            panic!("must be compute for step size");
        };
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
        tracing::trace!("step size is: {step_size}");
        match compute_bucket.op {
            OperatorType::Add => StepType::Add(step_size),
            OperatorType::Sub => StepType::Sub(step_size),
            OperatorType::Mul => StepType::Mul(step_size),
            x => todo!("not supported for step size {}", x.to_string()),
        }
    }

    // we unroll the loop if it is public - if it is shared we panic for the moment
    pub(crate) fn handle_loop_bucket(&mut self, loop_bucket: &LoopBucket) -> Result<()> {
        tracing::trace!("============================");
        tracing::trace!("{}", loop_bucket.continue_condition.to_string());
        tracing::trace!("body:");
        for inst in &loop_bucket.body {
            tracing::trace!("{}", inst.to_string());
        }
        // get last instruction of loop body - this is step size
        let step_size = if let Some(step_instruction) = loop_bucket.body.last().as_ref() {
            self.get_step_size(step_instruction)
        } else {
            panic!();
        };

        let round_trips =
            if let Instruction::Compute(compute_bucket) = loop_bucket.continue_condition.as_ref() {
                debug_assert_eq!(
                    compute_bucket.stack.len(),
                    2,
                    "only allows binary ops in loop conditions"
                );
                let lhs = self.get_constant_value(&compute_bucket.stack[0]);
                let mut rhs = self.get_constant_value(&compute_bucket.stack[1]);
                tracing::trace!("lhs {lhs}");
                tracing::trace!("rhs {rhs}");
                tracing::trace!("step size {:?}", step_size);
                match compute_bucket.op {
                    OperatorType::LesserEq => {
                        rhs += 1;
                        let diff = rhs - lhs.min(rhs);
                        match step_size {
                            StepType::Add(step) => diff.div_ceil(step),
                            StepType::Sub(step) => todo!(),
                            StepType::Mul(step) => todo!(),
                        }
                    }
                    OperatorType::GreaterEq => todo!(),
                    OperatorType::Lesser => {
                        let diff = rhs - lhs.min(rhs);
                        match step_size {
                            StepType::Add(step) => diff.div_ceil(step),
                            StepType::Sub(step) => todo!(),
                            StepType::Mul(step) => todo!(),
                        }
                    }
                    OperatorType::Greater => todo!(),
                    OperatorType::Eq(_) => todo!(),
                    OperatorType::NotEq => todo!(),
                    x => panic!("got type {} in loop unrolling compute", x.to_string()),
                }
            } else {
                todo!("condition not a compute for loop unrolling!");
            };
        tracing::info!("round trip: {}", round_trips);
        for _ in 0..round_trips {
            for inst in loop_bucket.body[..loop_bucket.body.len() - 1].iter() {
                self.handle_inst(inst)?
            }
        }

        Ok(())
    }
}
