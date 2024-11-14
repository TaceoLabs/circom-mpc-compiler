use core::panic;
use std::usize;

use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use circom_compiler::intermediate_representation::ir_interface::{
    AddressType, Instruction, LocationRule, LoopBucket, OperatorType,
};
use eyre::Result;
use serde::de::value;

use super::{
    translate::GraphCompiler,
    types::{Node, WireInformation},
};

macro_rules! to_u64 {
    ($x: expr) => {
        u64::try_from($x).expect("fits into u64")
    };
}

#[derive(Debug)]
enum StepType {
    Add(usize),
    Sub(usize),
    Mul(usize),
}

impl<'a, P: Pairing> GraphCompiler<'a, P> {
    fn get_step_size(&self, inst: &Instruction) -> (usize, StepType) {
        // must be a top level store
        let (var_index, compute_inst) = if let Instruction::Store(store_bucket) = inst {
            // we store a var here - we need to get the index and update it after every round
            // trip for the unrolling
            if let LocationRule::Indexed {
                location,
                template_header: _,
            } = &store_bucket.dest
            {
                assert!(
                    matches!(store_bucket.dest_address_type, AddressType::Variable),
                    "must be a variable store for step size"
                );
                let index = self.get_constant_value(&location);
                (index, store_bucket.src.as_ref())
            } else {
                panic!("must be an indexed store for induction variable")
            }
        } else {
            panic!("must be top level store bucket for step size");
        };
        tracing::info!("{}", compute_inst.to_string());
        // we can either have compute bucket or value bucket
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
                tracing::trace!("step size is: {step_size}");
                let step_type = match compute_bucket.op {
                    OperatorType::Add => StepType::Add(step_size),
                    OperatorType::Sub => StepType::Sub(step_size),
                    OperatorType::Mul => StepType::Mul(step_size),
                    x => todo!("not supported for step size {}", x.to_string()),
                };
                (var_index, step_type)
            }
            inst @ Instruction::Value(_) => {
                // we are a constant round trip
                tracing::trace!("this is a constant round trip");
                (var_index, StepType::Add(self.get_constant_value(inst)))
            }
            x => panic!(
                "must be compute or value for step size but is {}",
                x.to_string()
            ),
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
        let (var_index, step_size) =
            if let Some(step_instruction) = loop_bucket.body.last().as_ref() {
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
                let rhs = self.get_constant_value(&compute_bucket.stack[1]);
                tracing::trace!("lhs {lhs}");
                tracing::trace!("rhs {rhs}");
                tracing::trace!("step size {:?}", step_size);
                get_induction_iter(&compute_bucket.op, lhs, rhs, step_size)
            } else {
                todo!("condition not a compute for loop unrolling!");
            };
        for induction_var in round_trips {
            for inst in loop_bucket.body[..loop_bucket.body.len() - 1].iter() {
                self.add_induction_variable_node(var_index, induction_var);
                self.handle_inst(inst)?;
            }
        }
        Ok(())
    }

    pub fn add_induction_variable_node(&mut self, var_index: usize, induction_var: usize) {
        let induction_var = <P::ScalarField as PrimeField>::BigInt::from(to_u64!(induction_var));
        let next_wire = self.next_wire();
        let wire_information = WireInformation::new(self.next_node());
        self.wires.push(wire_information);
        self.nodes.push(Node::constant(
            P::ScalarField::from(induction_var),
            next_wire,
        ));
        self.var_to_wire.insert(to_u64!(var_index), next_wire);
    }
}

fn get_induction_iter(
    op: &OperatorType,
    lhs: usize,
    mut rhs: usize,
    step: StepType,
) -> Box<dyn Iterator<Item = usize>> {
    match op {
        OperatorType::LesserEq => {
            rhs += 1;
            match step {
                StepType::Add(step) => Box::new((lhs..rhs).step_by(step)),
                StepType::Sub(_) => todo!(),
                StepType::Mul(_) => todo!(),
            }
        }
        OperatorType::GreaterEq => match step {
            StepType::Add(_) => todo!(),
            StepType::Sub(step) => Box::new((rhs..=lhs).rev().step_by(step)),
            StepType::Mul(_) => todo!(),
        },
        OperatorType::Lesser => match step {
            StepType::Add(step) => Box::new((lhs..rhs).step_by(step)),
            StepType::Sub(_) => todo!(),
            StepType::Mul(_) => todo!(),
        },
        OperatorType::Greater => {
            rhs += 1;
            match step {
                StepType::Add(_) => todo!(),
                StepType::Sub(step) => Box::new((rhs..=lhs).rev().step_by(step)),
                StepType::Mul(_) => todo!(),
            }
        }
        OperatorType::Eq(_) => todo!(),
        OperatorType::NotEq => todo!(),
        x => panic!("got type {} in loop unrolling compute", x.to_string()),
    }
}
