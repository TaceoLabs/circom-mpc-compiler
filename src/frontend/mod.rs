//! Circom -> value-graph frontend. Replaces the old `circom_ir` module.
//!
//! Pipeline: parse circom source into a `ProgramArchive`, run circom's own constraint generation
//! and simplification to get a bucket-code `Circuit`, lower each template's bucket instructions
//! into a [`build::TemplateGraph`] (recursing into subcomponents lazily, unrolling loops eagerly
//! — see `unroll.rs`), then flatten the whole template tree into one [`crate::ir::Graph`] via
//! [`inline::inline_template`].

mod build;
mod error;
mod fold;
mod inline;
mod unroll;

use std::collections::HashMap;

use ark_ec::pairing::Pairing;
use ark_ff::{BigInteger, PrimeField};
use circom_compiler::compiler_interface::{Circuit as CircomCircuit, CompilationFlags, VCP};
use circom_compiler::hir::very_concrete_program::Wire as CircomWire;
use circom_constraint_generation::BuildConfig;
use circom_program_structure::ast::SignalType;
use circom_program_structure::error_definition::Report;
use circom_program_structure::program_archive::ProgramArchive;
use circom_type_analysis::check_types;
use eyre::Result;
use rustc_hash::FxHashMap;

use crate::ir;
use crate::{CompilerConfig, SimplificationLevel};

use build::GraphCompiler;

/// A list of circuit inputs: (name, witness offset, size).
pub(crate) type InputList = ir::InputList;

/// Maps an output signal's name to (offset, size) in the witness.
pub type OutputMapping = HashMap<String, (usize, usize)>;

/// Every source template named with this prefix is treated as a first-class precomputation
/// wrapper (`TACEO_PRECOMPUTATION_Poseidon2`, `TACEO_PRECOMPUTATION_Num2Bits`, ...): its wrapped
/// (inner) component is never compiled or run - `build::GraphCompiler::handle_create_cmp_bucket`
/// turns it into an `ir::Op::Precompute` site instead. See `docs/ARCHITECTURE.md`,
/// "Precomputation".
pub(crate) const PRECOMPUTATION_PREFIX: &str = "TACEO_PRECOMPUTATION_";

/// A template header's total flat signal count: its own declared signals (inputs + outputs +
/// intermediates) plus every signal belonging to every subcomponent it transitively instantiates -
/// i.e. exactly the contiguous span circom's own runtime layout reserves for one instance of that
/// template. Needed to size a precomputation site's result-slot range (`num_intermediates` in
/// `ir::PrecomputeSite`).
///
/// circom itself computes this same quantity (`constraint_generation::execution_data::
/// executed_program::produce_dags_stats`), but only over its internal `DAG`, which
/// `circom_constraint_generation::build_circuit`'s public API does not expose (it returns a
/// `Box<dyn ConstraintExporter>` - a file-writer trait object with `r1cs`/`sym`/`json` methods
/// only, no structural accessors). This recomputes it from `VCP::templates`, which *is* public:
/// each `TemplateInstance` already carries its own direct signal counts and a `triggers` list
/// naming every subcomponent it instantiates by `template_id` (an index into this same `templates`
/// list - the convention `get_output_mapping` above also relies on), so the same recursive sum
/// falls out directly, just sourced from a different (but equivalent) part of circom's output.
fn compute_signal_spans(vcp: &VCP) -> FxHashMap<String, usize> {
    fn span(vcp: &VCP, id: usize, memo: &mut [Option<usize>]) -> usize {
        if let Some(cached) = memo[id] {
            return cached;
        }
        let template = &vcp.templates[id];
        let mut total =
            template.number_of_inputs + template.number_of_outputs + template.number_of_intermediates;
        for trigger in &template.triggers {
            total += span(vcp, trigger.template_id, memo);
        }
        memo[id] = Some(total);
        total
    }

    let mut memo = vec![None; vcp.templates.len()];
    vcp.templates
        .iter()
        .enumerate()
        .map(|(id, template)| (template.template_header.clone(), span(vcp, id, &mut memo)))
        .collect()
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
) -> Result<(CircomCircuit, OutputMapping, FxHashMap<String, usize>)> {
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
    let signal_spans = compute_signal_spans(&vcp);

    let flags = CompilationFlags {
        main_inputs_log: false,
        wat_flag: false,
    };
    Ok((
        CircomCircuit::build(vcp, flags, &config.version),
        output_mapping,
        signal_spans,
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

/// Parses `file` all the way down to a flat, verified (but not yet garbage-collected)
/// [`ir::Graph`]. The caller (`CoCircomCompiler::parse`) runs `gc`/`verify` on the result.
pub(crate) fn build_graph<P: Pairing>(
    file: String,
    config: CompilerConfig,
) -> Result<ir::Graph<P::ScalarField>> {
    let program_archive = get_program_archive::<P::ScalarField>(file, &config)?;
    let public_inputs = program_archive.public_inputs.clone();
    let (mut circuit, _output_mapping, signal_spans) = build_circuit(program_archive, &config)?;
    let constant_table = circuit
        .c_producer
        .get_field_constant_list()
        .iter()
        .map(|s| s.parse::<P::ScalarField>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| eyre::eyre!("cannot parse string in constant list"))?;

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

    let mut compiled_graphs = FxHashMap::default();
    let main_graph_compiler = GraphCompiler::<P>::new(
        main_template,
        &mut templates,
        &mut compiled_graphs,
        &constant_table,
        config.precomputation,
        &signal_spans,
    );
    let main_template_graph = main_graph_compiler.parse()?;

    let mut nodes = Vec::with_capacity(main_template_graph.nodes.len());
    let mut outputs = Vec::new();
    let mut precompute_sites = Vec::new();
    inline::inline_template(
        &mut nodes,
        &mut outputs,
        &mut precompute_sites,
        main_template_graph,
        0,
        &FxHashMap::default(),
    );

    Ok(ir::Graph::from_parts(
        nodes,
        outputs,
        precompute_sites,
        circuit.c_producer.witness_to_signal_list,
        input_list,
        public_inputs,
        main_inputs,
        main_outputs,
        circuit.c_producer.total_number_of_signals,
    ))
}
