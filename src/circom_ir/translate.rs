use std::collections::HashMap;
use std::marker::PhantomData;

use ark_ec::pairing::Pairing;
use circom_compiler::compiler_interface::{Circuit as CircomCircuit, CompilationFlags, VCP};
use circom_compiler::hir::very_concrete_program::Wire as CircomWire;
use circom_compiler::intermediate_representation::ir_interface::{
    ComputeBucket, Instruction, LoadBucket, OperatorType, SizeOption, StoreBucket,
};
use circom_compiler::intermediate_representation::ir_interface::{LocationRule, ValueType};
use circom_constraint_generation::BuildConfig;
use circom_program_structure::ast::SignalType;
use circom_program_structure::error_definition::Report;
use circom_program_structure::program_archive::ProgramArchive;
use circom_type_analysis::check_types;

use crate::{CompilerConfig, SimplificationLevel};
use ark_ff::{BigInteger, PrimeField};

use super::types::{self, Node, NodeId, Wire, WireInformation};

macro_rules! to_wire {
    ($v: expr) => {
        u64::try_from($v).expect("usize fits into u64")
    };
}

macro_rules! to_node_id {
    ($v: expr) => {
        u64::try_from($v).expect("usize fits into u64")
    };
}

struct CompilationCtx<P: Pairing> {
    wires: Vec<WireInformation>,
    next_wire: Wire,
    nodes: Vec<types::Node>,
    file: String, // must be a String because circom wants one instead of PathBuf
    config: CompilerConfig,
    offset_stack: Vec<Wire>,
    phandom_data: PhantomData<P>,
}

/// A list of inputs (Name, offset, size).
pub(crate) type InputList = Vec<(String, usize, usize)>;

/// A type that stores the name of an output signal and maps it to
/// the respective offset in the witness.
///
/// String -> (offset, size)
pub type OutputMapping = HashMap<String, (usize, usize)>;

fn get_size_from_size_option(size_option: &SizeOption) -> usize {
    match size_option {
        SizeOption::Single(v) => *v,
        SizeOption::Multiple(v) => v
            .iter()
            .map(|x| {
                // second value is the size
                x.1
            })
            .sum(),
    }
}

impl<P: Pairing> CompilationCtx<P> {
    fn new(file: String, config: CompilerConfig) -> Self {
        Self {
            wires: Vec::with_capacity(1024),
            next_wire: 1,
            nodes: Vec::with_capacity(1024),
            file,
            offset_stack: vec![],
            config,
            phandom_data: PhantomData,
        }
    }

    /*
     *   pub line: usize,
     *   pub message_id: usize,
     *   pub context: InstrContext,
     *   pub src_context: InstrContext,
     *   pub dest_is_output: bool,
     *   pub dest_address_type: AddressType,
     *   pub src_address_type: Option<InstructionPointer>,
     *   pub dest: LocationRule,
     *   pub src: InstructionPointer,
     */
    fn handle_store_bucket(&mut self, store_bucket: &StoreBucket) {
        tracing::trace!("lowering store bucket line: {}", store_bucket.line);
        self.handle_inst(&store_bucket.src);
        // TODO later we can store multiple - then we need to link more
        let last_wire = self.peek_next_wire() - 1;

        let my_offset = *self.offset_stack.last().expect("must be here");
        match &store_bucket.dest {
            LocationRule::Indexed {
                location,
                template_header: _,
            } => {
                // load the index - must be a value
                if let Instruction::Value(value_bucket) = location.as_ref() {
                    assert!(
                        matches!(value_bucket.parse_as, ValueType::U32),
                        "must be a u32"
                    );
                    self.add_store_node(last_wire, value_bucket.value + my_offset)
                } else {
                    unreachable!("must be value bucket");
                };
            }
            LocationRule::Mapped {
                signal_code,
                indexes,
            } => {
                //debug_assert!(*signal_code > 0);
                //indexes.iter().for_each(|at| self.handle_access_type(at));

                //(true, *signal_code)
            }
        };
        //match dest_addr {
        //    AddressType::Variable => (),
        //    AddressType::Signal => self
        //        .current_code_block
        //        .push(MpcOpCode::StoreSignals(context_size)),
        //    AddressType::SubcmpSignal {
        //        cmp_address,
        //        uniform_parallel_value: _,
        //        is_output,
        //        input_information: _,
        //    } => {
        //        //debug_assert!(!is_output);
        //        //self.handle_instruction(cmp_address);
        //        //self.emit_opcode(MpcOpCode::InputSubComp(mapped, signal_code, context_size));
        //    }
        //}
    }

    fn handle_compute_bucket(&mut self, compute_bucket: &ComputeBucket) {
        tracing::trace!("lowering compute bucket line: {}", compute_bucket.line);
        //tracing::trace!("{}", compute_bucket.to_string());

        compute_bucket.stack.iter().for_each(|inst| {
            self.handle_inst(inst);
        });

        match compute_bucket.op {
            OperatorType::Add => todo!(),
            OperatorType::Sub => todo!(),
            OperatorType::Mul => {
                debug_assert_eq!(compute_bucket.stack.len(), 2, "mul is a binary opcode");
                let peek_wire = self.peek_next_wire();
                self.add_bin_op_node(types::Op::Mul, peek_wire - 2, peek_wire - 1);
            }
            OperatorType::Div => todo!(),
            OperatorType::Pow => todo!(),
            OperatorType::IntDiv => todo!(),
            OperatorType::Mod => todo!(),
            OperatorType::ShiftL => todo!(),
            OperatorType::ShiftR => todo!(),
            OperatorType::LesserEq => todo!(),
            OperatorType::GreaterEq => todo!(),
            OperatorType::Lesser => todo!(),
            OperatorType::Greater => todo!(),
            OperatorType::Eq(size) => {
                assert_ne!(size, 0);
                todo!()
                //self.emit_opcode(MpcOpCode::Eq);
            }
            OperatorType::NotEq => todo!(),
            OperatorType::BoolOr => todo!(),
            OperatorType::BoolAnd => todo!(),
            OperatorType::BitOr => todo!(),
            OperatorType::BitAnd => todo!(),
            OperatorType::BitXor => todo!(),
            OperatorType::PrefixSub => todo!(),
            OperatorType::BoolNot => todo!(),
            OperatorType::Complement => todo!(),
            OperatorType::ToAddress => {
                todo!()
                //self.emit_opcode(MpcOpCode::ToIndex);
            }
            OperatorType::MulAddress => {
                todo!()
                //self.emit_opcode(MpcOpCode::MulIndex);
            }
            OperatorType::AddAddress => {
                todo!()
                //self.emit_opcode(MpcOpCode::AddIndex);
            }
        }
    }

    fn add_node(&mut self, node: Node) {
        self.nodes.push(node)
    }

    fn peek_next_wire(&self) -> Wire {
        self.next_wire
    }

    fn peek_next_node(&self) -> NodeId {
        self.nodes.len()
    }

    fn next_wire(&mut self) -> Wire {
        let wire = self.next_wire;
        self.next_wire += 1;
        wire
    }

    fn add_load_node(&mut self, input: Wire) {
        let next_wire = self.next_wire();
        let is_public = self.wires[input].public;
        let wire_information = WireInformation::new(is_public, self.peek_next_node());
        self.wires.push(wire_information);
        self.nodes.push(Node::load(input, next_wire));
    }

    fn add_store_node(&mut self, input: Wire, output: Wire) {
        // we produce not a new wire, but update the output wire
        self.wires[output].public = self.wires[input].public;
        self.wires[output].produced_by = self.peek_next_node();
        self.nodes.push(Node::store(input));
    }

    fn add_bin_op_node(&mut self, op: types::Op, lhs: Wire, rhs: Wire) {
        let next_wire = self.next_wire();
        let is_public = self.wires[lhs].public && self.wires[rhs].public;
        let wire_information = WireInformation::new(is_public, self.peek_next_node());
        self.wires.push(wire_information);
        self.nodes.push(Node::bin_op(op, lhs, rhs, next_wire))
    }

    fn handle_load_bucket(&mut self, load_bucket: &LoadBucket) {
        tracing::trace!("lowering load bucket line: {}", load_bucket.line);
        tracing::trace!("{}", load_bucket.to_string());
        // for load we have three cases.
        //     1.) we want to load a signal
        //     2.) we want to load a variable
        //     3.) we want to load from a subcmp.
        // all those should not have dedicated opcodes.
        // We just wire them to their, well, wires. Must be defined
        // because circom compiler was happy
        let context_size = get_size_from_size_option(&load_bucket.context.size);

        let my_offset = *self.offset_stack.last().expect("must be here");
        match &load_bucket.src {
            LocationRule::Indexed {
                location,
                template_header: _,
            } => {
                // load the index - must be a value
                if let Instruction::Value(value_bucket) = location.as_ref() {
                    assert!(
                        matches!(value_bucket.parse_as, ValueType::U32),
                        "must be a u32"
                    );
                    self.add_load_node(value_bucket.value + my_offset)
                } else {
                    unreachable!("must be value bucket");
                };
            }
            LocationRule::Mapped {
                signal_code,
                indexes,
            } => {
                //if indexes.is_empty() {
                //    // Just push 0 to signal that it is the first signal of the component
                //    // I am not sure if this is correct for all cases, so maybe investigate
                //    // this further
                //    self.emit_opcode(MpcOpCode::PushIndex(0));
                //} else {
                //    indexes.iter().for_each(|at| self.handle_access_type(at));
                //}
                //(true, *signal_code)
            }
        };
        //match &load_bucket.address_type {
        //    AddressType::Variable => todo!(),
        //    AddressType::Signal => self
        //        .current_code_block
        //        .push(MpcOpCode::LoadSignals(context_size)),
        //    AddressType::SubcmpSignal {
        //        cmp_address,
        //        uniform_parallel_value: _,
        //        is_output: _,
        //        input_information: _,
        //    } => {
        //        todo!("sub cmp signal")
        //    }
        //}
    }

    fn handle_inst(&mut self, inst: &Instruction) {
        match inst {
            Instruction::Value(_) => todo!(),
            Instruction::Load(load_bucket) => self.handle_load_bucket(load_bucket),
            Instruction::Store(store_bucket) => self.handle_store_bucket(store_bucket),
            Instruction::Compute(compute_bucket) => self.handle_compute_bucket(compute_bucket),
            Instruction::Call(_) => todo!(),
            Instruction::Branch(_) => todo!(),
            Instruction::Return(_) => todo!(),
            Instruction::Assert(_) => todo!(),
            Instruction::Log(_) => todo!(),
            Instruction::Loop(_) => todo!(),
            Instruction::CreateCmp(_) => todo!(),
        }
    }

    fn get_program_archive(&self) -> eyre::Result<ProgramArchive> {
        let field = P::ScalarField::MODULUS;
        let field_dig = circom_compiler::num_bigint::BigInt::from_bytes_be(
            circom_compiler::num_bigint::Sign::Plus,
            field.to_bytes_be().as_slice(),
        );
        match circom_parser::run_parser(
            self.file.clone(),
            &self.config.version,
            self.config.link_library.clone(),
            &field_dig,
        ) {
            Ok((mut program_archive, warnings)) => {
                Report::print_reports(&warnings, &program_archive.file_library);
                match check_types::check_types(&mut program_archive) {
                    Ok(warnings) => {
                        Report::print_reports(&warnings, &program_archive.file_library);
                        Ok(program_archive)
                    }
                    Err(errors) => {
                        Report::print_reports(&errors, &program_archive.file_library);
                        eyre::bail!("Error during type checking");
                    }
                }
            }
            Err((file_lib, errors)) => {
                Report::print_reports(&errors, &file_lib);
                eyre::bail!("Error during compilation");
            }
        }
    }

    fn build_circuit(
        &self,
        program_archive: ProgramArchive,
    ) -> eyre::Result<(CircomCircuit, OutputMapping)> {
        let build_config = BuildConfig {
            no_rounds: if let SimplificationLevel::O2(r) = self.config.simplification {
                r
            } else {
                0
            },
            flag_json_sub: false,
            json_substitutions: String::new(),
            flag_s: self.config.simplification == SimplificationLevel::O1,
            flag_f: self.config.simplification == SimplificationLevel::O0,
            flag_p: false,
            flag_verbose: self.config.verbose,
            flag_old_heuristics: false,
            inspect_constraints: self.config.inspect,
            prime: "bn128".to_owned(),
        };
        let (_, vcp) = circom_constraint_generation::build_circuit(program_archive, build_config)
            .map_err(|_| eyre::eyre!("cannot build vcp"))?;
        let output_mapping = self.get_output_mapping(&vcp);

        let flags = CompilationFlags {
            main_inputs_log: false,
            wat_flag: false,
        };
        Ok((
            CircomCircuit::build(vcp, flags, &self.config.version),
            output_mapping,
        ))
    }

    fn get_output_mapping(&self, vcp: &VCP) -> OutputMapping {
        let mut output_mappings = HashMap::new();
        let initial_node = vcp.get_main_id();
        let main = &vcp.templates[initial_node];
        for s in &main.wires {
            if let CircomWire::TSignal(s) = s {
                if s.xtype == SignalType::Output {
                    output_mappings.insert(s.name.clone(), (s.dag_local_id, s.size));
                }
            }
            // TODO: Can buses be outputs?
        }
        output_mappings
    }
    fn parse(mut self) -> eyre::Result<()> {
        let program_archive = self.get_program_archive()?;
        let public_inputs = program_archive.public_inputs.clone();
        let (circuit, output_mapping) = self.build_circuit(program_archive)?;
        let constant_table = circuit
            .c_producer
            .get_field_constant_list()
            .iter()
            .map(|s| s.parse::<P::ScalarField>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| eyre::eyre!("cannot parse string in constant list"))?;
        let string_table = circuit.c_producer.get_string_table().clone();

        let main_template = circuit
            .templates
            .iter()
            .find(|t| t.header == circuit.c_producer.main_header)
            .expect("main component must be here");

        let main_inputs = circuit.c_producer.number_of_main_inputs;
        let main_outputs = circuit.c_producer.number_of_main_outputs;
        let input_list = circuit
            .c_producer
            .main_input_list
            .into_iter()
            .map(|x| (x.name, x.start, x.size))
            .collect::<InputList>();

        self.wires.push(WireInformation::r1cs_wire());

        for _ in 0..main_outputs {
            self.wires.push(WireInformation::output_wire())
        }

        for (name, start, size) in input_list.iter() {
            for i in *start..start + size {
                self.next_wire = self.next_wire.max(i);
                self.wires
                    .push(WireInformation::input_wire(public_inputs.contains(name)));
            }
        }
        self.next_wire += 1;

        self.offset_stack.push(1); //offset for main component
        for templ in circuit.templates.iter() {
            tracing::debug!("parsing template: {}", templ.header);
            templ.body.iter().for_each(|inst| {
                self.handle_inst(inst);
            });
        }
        self.print_wires();
        self.print_nodes();
        Ok(())
    }

    fn print_wires(&self) {
        for (idx, v) in self.wires.iter().enumerate() {
            tracing::debug!("{idx:0>4}: {v:?}")
        }
    }

    fn print_nodes(&self) {
        for n in self.nodes.iter() {
            tracing::debug!("{n:?}")
        }
    }
}

pub(crate) fn build_circom_ir<P: Pairing>(
    file: String,
    config: CompilerConfig,
) -> eyre::Result<()> {
    CompilationCtx::<P>::new(file, config).parse()?;
    //for templ in circuit.templates.iter() {
    //    tracing::debug!("parsing template: {}", templ.header);
    //    templ.body.iter().for_each(|inst| {
    //        handle_inst(inst);
    //    });
    //let mut new_code_block = CodeBlock::default();
    //std::mem::swap(&mut new_code_block, &mut self.current_code_block);
    //new_code_block.push(MpcOpCode::Return);
    //tracing::debug!("template has {} opcodes", new_code_block.len());
    ////check if we need mapping for store bucket
    //let mappings = if let Some(mappings) = circuit.c_producer.io_map.get(&templ.id) {
    //    mappings.iter().map(|m| m.offset).collect_vec()
    //} else {
    //    vec![]
    //};
    //self.templ_decls.insert(
    //    templ.header.clone(),
    //    TemplateDecl::new(
    //        templ.header.clone(),
    //        templ.name.clone(),
    //        templ.number_of_inputs,
    //        templ.number_of_outputs,
    //        templ.number_of_components,
    //        templ.var_stack_depth,
    //        mappings,
    //        new_code_block,
    //    ),
    //);
    //}
    Ok(())
}

/*
#[derive(Default)]
pub struct TemplateCodeInfo {
    pub id: TemplateID,
    pub header: String,
    pub name: String,
    pub is_parallel: bool,
    pub is_parallel_component: bool,
    pub is_not_parallel_component: bool,
    pub has_parallel_sub_cmp: bool,
    pub number_of_inputs: usize,
    pub number_of_outputs: usize,
    pub number_of_intermediates: usize, // Not used now
    pub body: InstructionList,
    pub var_stack_depth: usize,
    pub expression_stack_depth: usize,
    pub signal_stack_depth: usize, // Not used now
    pub number_of_components: usize,
}
*/
