use core::panic;
use std::collections::HashMap;

use ark_ec::pairing::Pairing;
use circom_compiler::circuit_design::template::TemplateCode;
use circom_compiler::compiler_interface::{Circuit as CircomCircuit, CompilationFlags, VCP};
use circom_compiler::hir::very_concrete_program::Wire as CircomWire;
use circom_compiler::intermediate_representation::ir_interface::{
    AddressType, ComputeBucket, CreateCmpBucket, Instruction, LoadBucket, OperatorType, SizeOption,
    StoreBucket, ValueBucket,
};
use circom_compiler::intermediate_representation::ir_interface::{LocationRule, ValueType};
use circom_constraint_generation::BuildConfig;
use circom_program_structure::ast::SignalType;
use circom_program_structure::error_definition::Report;
use circom_program_structure::program_archive::ProgramArchive;
use circom_type_analysis::check_types;
use eyre::Result;
use intmap::IntMap;
use num_bigint::BigUint;

use crate::{CompilerConfig, SimplificationLevel};
use ark_ff::{BigInteger, PrimeField};

use super::types::{
    self, CircomAST, Node, NodeId, NotInlinedCircomAST, SubGraph, Wire, WireInformation,
};

macro_rules! to_u64 {
    ($x: expr) => {
        u64::try_from($x).expect("fits into u64")
    };
}

pub(crate) struct GraphCompiler<'a, P: Pairing> {
    pub(crate) wires: Vec<WireInformation>,
    pub(crate) nodes: Vec<types::Node<P::ScalarField>>,
    pub(crate) var_to_wire: IntMap<Wire>,
    sub_graphs: Vec<SubGraph<P::ScalarField>>,
    code: TemplateCode,
    num_inputs: usize,
    num_outputs: usize,
    offset: Wire,
    templates: &'a mut HashMap<String, TemplateCode>,
    compiled_graphs: &'a mut HashMap<String, NotInlinedCircomAST<P::ScalarField>>,
    constant_table: &'a [P::ScalarField],
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

impl<'a, P: Pairing> GraphCompiler<'a, P> {
    fn new(
        code: TemplateCode,
        num_inputs: usize,
        num_outputs: usize,
        templates: &'a mut HashMap<String, TemplateCode>,
        compiled_graphs: &'a mut HashMap<String, NotInlinedCircomAST<P::ScalarField>>,
        constant_table: &'a [P::ScalarField],
        input_wires: Vec<WireInformation>,
        offset_jump: Wire,
    ) -> Self {
        Self {
            // TODO maybe merge this
            sub_graphs: Vec::with_capacity(code.number_of_components),
            code,
            num_inputs,
            num_outputs,
            wires: input_wires,
            nodes: Vec::with_capacity(1024),
            offset: offset_jump,
            templates,
            compiled_graphs,
            constant_table,
            var_to_wire: IntMap::new(),
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
    fn handle_store_bucket(&mut self, store_bucket: &StoreBucket) -> Result<()> {
        self.handle_inst(&store_bucket.src)?;
        tracing::trace!("THIS WILL BE STORED: {}", store_bucket.src.to_string());
        // TODO later we can store multiple - then we need to link more
        let last_wire = self.next_wire() - 1;

        match &store_bucket.dest {
            LocationRule::Indexed {
                location,
                template_header: _,
            } => {
                tracing::trace!("indexed store at line {}", store_bucket.line);
                let index = self.get_constant_value(&location);
                match &store_bucket.dest_address_type {
                    AddressType::Variable => {
                        self.var_to_wire.insert(to_u64!(index), last_wire);
                    }
                    AddressType::Signal => self.add_store_node(last_wire, index),
                    AddressType::SubcmpSignal {
                        cmp_address,
                        uniform_parallel_value: _,
                        is_output,
                        input_information: _,
                    } => {
                        tracing::info!("LOOK AT MEEEEEEEEEE");
                        debug_assert!(!is_output);
                        tracing::info!("{}", cmp_address.to_string());
                        let cmp_index = self.get_constant_value(cmp_address);
                        tracing::info!("OK STOP IT {cmp_index}");
                        self.add_store_sub_cmp_node(last_wire, cmp_index, index);
                    }
                }
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
        Ok(())
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

    //   fn add_sub_cmp(
    //       &mut self,
    //       ast: CircomAST<P::ScalarField>,
    //       sub_cmp_wires: SubCmpWireIndices,
    //       signal_offset: usize,
    //   ) {
    //       let wire_offset = self.next_wire();
    //       self.sub_graphs.push(SubGraph {
    //           ast,
    //           sub_cmp_wires,
    //           signal_offset,
    //           wire_offset,
    //       });
    //   }

    fn handle_create_cmp_bucket(&mut self, create_cmp_bucket: &CreateCmpBucket) -> Result<()> {
        tracing::debug!(
            "we need to create {} {} times",
            create_cmp_bucket.symbol,
            create_cmp_bucket.number_of_cmp
        );
        let symbol = create_cmp_bucket.symbol.clone();
        if self.compiled_graphs.contains_key(&symbol) {
            todo!()
        } else {
            // we need to compile the graph
            let template_code = self.templates.remove(&symbol).expect("must be here");

            let mut cmp_wires = vec![];
            let num_outputs = template_code.number_of_outputs;
            let num_inputs = template_code.number_of_inputs;
            for _ in 0..num_outputs {
                // set to true for the moment - we change it as soon
                // as we provide the input
                cmp_wires.push(WireInformation::output_wire());
            }
            for _ in 0..num_inputs {
                // set to true for the moment - we change it as soon
                // as we provide the input
                cmp_wires.push(WireInformation::input_wire());
            }
            tracing::debug!("start compilation of {}", symbol);
            // create a new graph compiler
            let sub_cmp_compiler = GraphCompiler::<P>::new(
                template_code,
                num_inputs,
                num_outputs,
                self.templates,
                self.compiled_graphs,
                self.constant_table,
                cmp_wires,
                create_cmp_bucket.signal_offset, // offset
            );
            let sub_cmp = sub_cmp_compiler.parse()?;

            // now add it amount times
            let mut offset = self.offset + create_cmp_bucket.signal_offset;
            let offset_jump = create_cmp_bucket.signal_offset_jump;
            for _ in 0..create_cmp_bucket.number_of_cmp {
                let sub_graph = SubGraph::new(
                    symbol.clone(),
                    num_inputs + num_outputs,
                    sub_cmp.clone(),
                    offset,
                );
                self.sub_graphs.push(sub_graph);
                offset += offset_jump;
            }
            self.compiled_graphs.insert(symbol.clone(), sub_cmp);
        }
        Ok(())
    }

    // unwraps the value until if finds a constant value - if not possible panics
    pub(crate) fn get_constant_value(&self, inst: &Instruction) -> usize {
        match inst {
            Instruction::Value(value_bucket) => match value_bucket.parse_as {
                ValueType::U32 => value_bucket.value,
                ValueType::BigInt => {
                    let constant = self.constant_table[value_bucket.value];
                    let big_int: BigUint = constant.into_bigint().into();
                    let constant =
                        usize::try_from(big_int).expect("{big_int} not possible to fit into usize");
                    tracing::trace!("> got constant {constant}");
                    constant
                }
            },
            Instruction::Load(load_bucket) => {
                let index = if let LocationRule::Indexed {
                    location,
                    template_header: _,
                } = &load_bucket.src
                {
                    // we must have an index here, otherwise something is broken
                    let index = self.get_constant_value(&location);
                    tracing::trace!("> got index {index} to load for constant value");
                    index
                } else {
                    todo!("get_constant_load not indexed")
                };
                if let AddressType::Variable = &load_bucket.address_type {
                    let wire_mapping = self.var_to_wire.get(to_u64!(index)).expect("must be there");
                    let producing_node = self.wires[*wire_mapping].produced_by;
                    let constant = self.nodes[producing_node].get_constant();
                    let big_int: BigUint = constant.into_bigint().into();
                    let constant =
                        usize::try_from(big_int).expect("{big_int} not possible to fit into usize");
                    tracing::trace!("> loaded constant {constant}");
                    constant
                } else {
                    panic!("non variable loading in get constant value");
                }
            }
            Instruction::Compute(compute_bucket) => {
                // this must be a address computation - we evaluate this here and add a constant
                // node
                match compute_bucket.op {
                    OperatorType::MulAddress => {
                        assert_eq!(compute_bucket.stack.len(), 2, "mul is a bin op");
                        let lhs = self.get_constant_value(&compute_bucket.stack[0]);
                        let rhs = self.get_constant_value(&compute_bucket.stack[1]);
                        tracing::trace!("> mul address {lhs}*{rhs}={}", lhs * rhs);
                        lhs * rhs
                    }
                    OperatorType::AddAddress => {
                        assert_eq!(compute_bucket.stack.len(), 2, "add is a bin op");
                        let lhs = self.get_constant_value(&compute_bucket.stack[0]);
                        let rhs = self.get_constant_value(&compute_bucket.stack[1]);
                        tracing::trace!("> add address {lhs}+{rhs}={}", lhs + rhs);
                        lhs + rhs
                    }
                    OperatorType::ToAddress => {
                        assert_eq!(compute_bucket.stack.len(), 1, "to address is a unary op");
                        let constant = self.get_constant_value(&compute_bucket.stack[0]);
                        tracing::trace!("> to address {constant}");
                        constant
                    }
                    x => panic!(
                        "compute for constant must be add/mul address but is {}",
                        x.to_string()
                    ),
                }
            }
            x => panic!("cannot get constant of {}", x.to_string()),
        }
    }

    fn handle_compute_bucket(&mut self, compute_bucket: &ComputeBucket) -> Result<()> {
        for inst in compute_bucket.stack.iter() {
            self.handle_inst(inst)?;
        }

        match compute_bucket.op {
            OperatorType::Add => {
                tracing::trace!("lowering mul at line: {}", compute_bucket.line);
                debug_assert_eq!(compute_bucket.stack.len(), 2, "mul is a binary opcode");
                let peek_wire = self.next_wire();
                self.add_bin_op_node(types::Op::Add, peek_wire - 2, peek_wire - 1);
            }
            OperatorType::Sub => {
                tracing::trace!("lowering mul at line: {}", compute_bucket.line);
                debug_assert_eq!(compute_bucket.stack.len(), 2, "mul is a binary opcode");
                let peek_wire = self.next_wire();
                self.add_bin_op_node(types::Op::Add, peek_wire - 2, peek_wire - 1);
            }
            OperatorType::Mul => {
                tracing::trace!("lowering mul at line: {}", compute_bucket.line);
                debug_assert_eq!(compute_bucket.stack.len(), 2, "mul is a binary opcode");
                let peek_wire = self.next_wire();
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
        Ok(())
    }

    pub(crate) fn next_node(&self) -> NodeId {
        self.nodes.len()
    }

    pub(crate) fn next_wire(&mut self) -> Wire {
        self.wires.len()
    }

    fn add_load_signal_node(&mut self, input: Wire) {
        let next_wire = self.next_wire();
        let wire_information = WireInformation::new(self.next_node());
        self.wires.push(wire_information);
        self.nodes.push(Node::load(input, next_wire));
    }

    fn add_load_var_node(&mut self, input: Wire) {
        let wire_mapping = *self.var_to_wire.get(to_u64!(input)).expect("must be there");
        let next_wire = self.next_wire();
        let wire_information = WireInformation::new(self.next_node());
        self.wires.push(wire_information);
        self.nodes.push(Node::load(wire_mapping, next_wire));
    }

    fn add_load_sub_cmp_node(&mut self, sub_cmp: usize, sub_cmp_wire: Wire) {
        let output_wire = &self.sub_graphs[sub_cmp].ast.wires[sub_cmp_wire];
        assert!(output_wire.is_output(), "must be output to load sub cmp");
        let next_wire = self.next_wire();
        let wire_information = WireInformation::new(self.next_node());
        self.wires.push(wire_information);
        let input_cmp = Node::output_sub_cmp(sub_cmp, sub_cmp_wire, next_wire);
        self.nodes.push(input_cmp);
    }

    fn add_store_node(&mut self, input: Wire, output: Wire) {
        // we produce not a new wire, but update the output wire
        self.wires[output].produced_by = self.next_node();
        self.nodes.push(Node::store(input, output));
    }

    fn add_store_sub_cmp_node(&mut self, input: Wire, sub_cmp: usize, sub_cmp_wire: Wire) {
        let output_wire = &self.sub_graphs[sub_cmp].ast.wires[sub_cmp_wire];
        assert!(output_wire.is_input(), "must be input to store to sub cmp");
        let input_cmp = Node::input_sub_cmp(sub_cmp, sub_cmp_wire, input);
        self.nodes.push(input_cmp);
    }

    fn add_bin_op_node(&mut self, op: types::Op<P::ScalarField>, lhs: Wire, rhs: Wire) {
        let next_wire = self.next_wire();
        let wire_information = WireInformation::new(self.next_node());
        self.wires.push(wire_information);
        self.nodes.push(Node::bin_op(op, lhs, rhs, next_wire))
    }

    pub fn add_constant_node(&mut self, index: usize) {
        let next_wire = self.next_wire();
        let constant = self.constant_table[index];
        let wire_information = WireInformation::new(self.next_node());
        self.wires.push(wire_information);
        self.nodes.push(Node::constant(constant, next_wire))
    }

    fn handle_value_bucket(&mut self, value_bucket: &ValueBucket) -> Result<()> {
        let index = value_bucket.value;
        match value_bucket.parse_as {
            ValueType::BigInt => self.add_constant_node(index),
            ValueType::U32 => unreachable!("this should never happen!!!! (I guess )"),
        }
        Ok(())
    }

    fn handle_load_bucket(&mut self, load_bucket: &LoadBucket) -> Result<()> {
        // for load we have three cases.
        //     1.) we want to load a signal
        //     2.) we want to load a variable
        //     3.) we want to load from a subcmp.
        // all those should not have dedicated opcodes.
        // We just wire them to their, well, wires. Must be defined
        // because circom compiler was happy
        let context_size = get_size_from_size_option(&load_bucket.context.size);

        match &load_bucket.src {
            LocationRule::Indexed {
                location,
                template_header: _,
            } => {
                tracing::trace!("indexed load at line {}", load_bucket.line);
                let index = self.get_constant_value(&location);
                match &load_bucket.address_type {
                    AddressType::Variable => self.add_load_var_node(index),
                    AddressType::Signal => self.add_load_signal_node(index),
                    AddressType::SubcmpSignal {
                        cmp_address,
                        uniform_parallel_value,
                        is_output,
                        input_information,
                    } => {
                        debug_assert!(is_output);
                        let cmp_index = self.get_constant_value(cmp_address);
                        self.add_load_sub_cmp_node(cmp_index, index);
                    }
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
        Ok(())
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

    pub(crate) fn handle_inst(&mut self, inst: &Instruction) -> Result<()> {
        tracing::trace!("{}", inst.to_string());
        match inst {
            Instruction::Value(value_bucket) => self.handle_value_bucket(value_bucket),
            Instruction::Load(load_bucket) => self.handle_load_bucket(load_bucket),
            Instruction::Store(store_bucket) => self.handle_store_bucket(store_bucket),
            Instruction::Compute(compute_bucket) => self.handle_compute_bucket(compute_bucket),
            Instruction::Call(_) => todo!(),
            Instruction::Branch(_) => todo!(),
            Instruction::Return(_) => todo!(),
            Instruction::Assert(_) => todo!(),
            Instruction::Log(_) => todo!(),
            Instruction::Loop(loop_bucket) => self.handle_loop_bucket(loop_bucket),
            Instruction::CreateCmp(create_cmp_bucket) => {
                self.handle_create_cmp_bucket(create_cmp_bucket)
            }
        }
    }

    fn parse(mut self) -> Result<NotInlinedCircomAST<P::ScalarField>> {
        tracing::debug!("parsing {}", self.code.header);
        let body = std::mem::take(&mut self.code.body);
        for inst in body.iter() {
            self.handle_inst(inst)?;
        }
        self.print_ast();
        Ok(NotInlinedCircomAST::from(self))
    }

    pub(crate) fn print_ast(&self) {
        self.print_wires();
        self.print_nodes();
        self.print_var_mapping();
        self.print_sub_graphs();
    }

    fn print_sub_graphs(&self) {
        for sub_graph in self.sub_graphs.iter() {
            tracing::debug!("{sub_graph:?}");
        }
    }

    fn print_var_mapping(&self) {
        tracing::debug!("==== var mapping ====");
        for (k, v) in self.var_to_wire.iter() {
            tracing::debug!("{k:0>4}: {v:?}")
        }
    }

    fn print_wires(&self) {
        for (idx, v) in self.wires.iter().enumerate() {
            tracing::debug!("{idx:0>4}: {v:?}")
        }
    }

    fn print_nodes(&self) {
        for (idx, n) in self.nodes.iter().enumerate() {
            tracing::debug!("{idx:0>4}: {n:?}")
        }
    }
}

fn get_program_archive<F: PrimeField>(
    file: String,
    config: &CompilerConfig,
) -> Result<ProgramArchive> {
    let field = F::MODULUS;
    let field_dig = circom_compiler::num_bigint::BigInt::from_bytes_be(
        circom_compiler::num_bigint::Sign::Plus,
        field.to_bytes_be().as_slice(),
    );
    match circom_parser::run_parser(
        file,
        &config.version,
        config.link_library.clone(),
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
    program_archive: ProgramArchive,
    config: &CompilerConfig,
) -> Result<(CircomCircuit, OutputMapping)> {
    let build_config = BuildConfig {
        no_rounds: if let SimplificationLevel::O2(r) = config.simplification {
            r
        } else {
            0
        },
        flag_json_sub: false,
        json_substitutions: String::new(),
        flag_s: config.simplification == SimplificationLevel::O1,
        flag_f: config.simplification == SimplificationLevel::O0,
        flag_p: false,
        flag_verbose: config.verbose,
        flag_old_heuristics: false,
        inspect_constraints: config.inspect,
        prime: "bn128".to_owned(),
    };
    let (_, vcp) = circom_constraint_generation::build_circuit(program_archive, build_config)
        .map_err(|_| eyre::eyre!("cannot build vcp"))?;
    let output_mapping = get_output_mapping(&vcp);

    let flags = CompilationFlags {
        main_inputs_log: false,
        wat_flag: false,
    };
    Ok((
        CircomCircuit::build(vcp, flags, &config.version),
        output_mapping,
    ))
}

fn get_output_mapping(vcp: &VCP) -> OutputMapping {
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

pub(crate) fn build_circom_ir<P: Pairing>(
    file: String,
    config: CompilerConfig,
) -> Result<CircomAST<P::ScalarField>> {
    let program_archive = get_program_archive::<P::ScalarField>(file, &config)?;
    let public_inputs = program_archive.public_inputs.clone();
    let (mut circuit, output_mapping) = build_circuit(program_archive, &config)?;
    let constant_table = circuit
        .c_producer
        .get_field_constant_list()
        .iter()
        .map(|s| s.parse::<P::ScalarField>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| eyre::eyre!("cannot parse string in constant list"))?;
    let string_table = circuit.c_producer.get_string_table().clone();

    let mut templates = std::mem::take(&mut circuit.templates)
        .into_iter()
        .map(|t| (t.header.clone(), t))
        .collect::<HashMap<_, _>>();

    let main_template = templates
        .remove(&circuit.c_producer.main_header)
        .expect("main component must be here");

    let main_inputs = circuit.c_producer.number_of_main_inputs;
    let main_outputs = circuit.c_producer.number_of_main_outputs;
    let input_list = circuit
        .c_producer
        .main_input_list
        .into_iter()
        .map(|x| (x.name, x.start, x.size))
        .collect::<InputList>();
    let mut wires = Vec::with_capacity(1024);

    for _ in 0..main_outputs {
        wires.push(WireInformation::output_wire())
    }

    for (name, start, size) in input_list.iter() {
        for _ in *start..start + size {
            wires.push(WireInformation::input_wire());
        }
    }
    let mut compiled_graphs = HashMap::new();

    let main_graph = GraphCompiler::<P>::new(
        main_template,
        main_inputs,
        main_outputs,
        &mut templates,
        &mut compiled_graphs,
        &constant_table,
        wires,
        0, // offset for r1cs
    );
    let not_inlined_circom_ast = main_graph.parse()?;
    Ok(CircomAST::from_main_component(not_inlined_circom_ast))
}

impl<'a, P: Pairing> From<GraphCompiler<'a, P>> for NotInlinedCircomAST<P::ScalarField> {
    fn from(value: GraphCompiler<'a, P>) -> Self {
        Self {
            wires: value.wires,
            nodes: value.nodes,
            sub_graphs: value.sub_graphs,
            num_inputs: value.num_inputs,
            num_outputs: value.num_outputs,
        }
    }
}

impl<'a, P: Pairing> From<GraphCompiler<'a, P>> for CircomAST<P::ScalarField> {
    fn from(value: GraphCompiler<'a, P>) -> Self {
        Self {
            wires: value.wires,
            nodes: value.nodes,
            num_inputs: value.num_inputs,
            num_outputs: value.num_outputs,
        }
    }
}
