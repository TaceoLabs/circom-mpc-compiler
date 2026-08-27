//! Circom -> value-graph frontend.
//!
//! Pipeline: parse circom source into a `ProgramArchive`, run circom's own constraint generation
//! and simplification to get a bucket-code `Circuit`, lower each template's bucket instructions
//! into a [`build::TemplateGraph`] (recursing into subcomponents lazily, unrolling loops eagerly
//! — see `unroll.rs`), then flatten the whole template tree into one [`crate::ir::Graph`] via
//! [`inline::inline_template`].

mod build;
mod fold;
mod inline;
mod unroll;

use std::collections::HashMap;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use circom_compiler::compiler_interface::{Circuit as CircomCircuit, CompilationFlags, VCP};
use circom_constraint_generation::BuildConfig;
use circom_program_structure::error_definition::Report;
use circom_program_structure::program_archive::ProgramArchive;
use circom_type_analysis::check_types;
use eyre::Result;
use rustc_hash::FxHashMap;

use crate::CompilerConfig;
use crate::ir;

use build::GraphCompiler;

use crate::ir::InputList;

/// A template header's total flat signal count: its own declared signals plus every signal of
/// every subcomponent it transitively instantiates - the contiguous span circom's runtime layout
/// reserves for one instance. Sizes a gadget site's result-slot range. Recomputed from
/// `VCP::templates` because circom computes it only on its internal `DAG`, which
/// `build_circuit`'s public API does not expose.
fn compute_signal_spans(vcp: &VCP) -> FxHashMap<String, usize> {
    fn span(vcp: &VCP, id: usize, memo: &mut [Option<usize>]) -> usize {
        if let Some(cached) = memo[id] {
            return cached;
        }
        let template = &vcp.templates[id];
        let mut total = template.number_of_inputs
            + template.number_of_outputs
            + template.number_of_intermediates;
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

fn get_program_archive(file: String, config: &CompilerConfig) -> Result<ProgramArchive> {
    let field = Fr::MODULUS;
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
) -> Result<(CircomCircuit, FxHashMap<String, usize>)> {
    let build_config = BuildConfig {
        // Full constraint simplification, unbounded round count - circom's `--O2`; no other level
        // is supported.
        no_rounds: usize::MAX,
        flag_json_sub: false,
        json_substitutions: String::new(),
        flag_s: false,
        flag_f: false,
        flag_p: false,
        flag_verbose: config.verbose,
        flag_old_heuristics: false,
        inspect_constraints: config.inspect,
        prime: "bn128".to_owned(),
    };
    let (_, vcp) = circom_constraint_generation::build_circuit(program_archive, build_config)
        .map_err(|_| eyre::eyre!("cannot build vcp"))?;
    let signal_spans = compute_signal_spans(&vcp);

    let flags = CompilationFlags {
        main_inputs_log: false,
        wat_flag: false,
    };
    Ok((
        CircomCircuit::build(vcp, flags, &config.version),
        signal_spans,
    ))
}

/// Parses `file` all the way down to a flat, verified (but not yet garbage-collected)
/// [`ir::Graph`]. The caller (`CoCircomCompiler::parse`) runs `gc`/`verify` on the result.
pub(crate) fn build_graph(file: String, config: CompilerConfig) -> Result<ir::Graph> {
    let program_archive = get_program_archive(file, &config)?;
    let public_inputs = program_archive.public_inputs.clone();
    let mpc_public_inputs = config.mpc_public_inputs.clone();
    let (mut circuit, signal_spans) = build_circuit(program_archive, &config)?;
    let constant_table = circuit
        .c_producer
        .get_field_constant_list()
        .iter()
        .map(|s| s.parse::<Fr>())
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
    // circom reports each input's `start` in *witness* numbering: position 0 is the reserved constant
    // `1`, then main's outputs, then its inputs - so the first input starts at `1 + main_outputs`.
    // Rebase to 0-based over the inputs alone, which is the numbering every consumer in this crate
    // actually uses (`passes::mpc::domain::signal_domain` derives its index as `signal - num_outputs`,
    // and `fixtures::flatten` indexes a `num_inputs`-long vector).
    //
    // Rebasing here rather than at each consumer is what keeps them consistent: comparing the two
    // numberings directly (witness offset vs 0-based input index) would misclassify a public input
    // as `Shared` with one main output, or a secret input as public with more than one - which
    // `Machine::run` then rejects outright.
    let input_base = 1 + main_outputs;
    let input_list = circuit
        .c_producer
        .main_input_list
        .into_iter()
        .map(|x| {
            let start = x.start.checked_sub(input_base).unwrap_or_else(|| {
                panic!(
                    "circom reported input `{}` at witness offset {}, before the first input slot \
                     ({input_base} = 1 reserved constant + {main_outputs} main outputs) - the \
                     witness layout assumption in frontend/mod.rs no longer holds",
                    x.name, x.start
                )
            });
            (x.name, start, x.size)
        })
        .collect::<InputList>();
    debug_assert_eq!(
        input_list.iter().map(|(_, _, size)| size).sum::<usize>(),
        main_inputs,
        "input_list sizes must cover exactly the declared inputs"
    );

    let mut compiled_graphs = FxHashMap::default();
    let main_graph_compiler = GraphCompiler::new(
        main_template,
        &mut templates,
        &mut compiled_graphs,
        &constant_table,
        &signal_spans,
    );
    let main_template_graph = main_graph_compiler.parse()?;

    let mut nodes = Vec::with_capacity(main_template_graph.nodes.len());
    let mut outputs = Vec::new();
    let mut gadget_sites = Vec::new();
    inline::inline_template(
        &mut nodes,
        &mut outputs,
        &mut gadget_sites,
        main_template_graph,
        0,
        true,
        &FxHashMap::default(),
    );

    let mut graph = ir::Graph::from_parts(
        nodes,
        outputs,
        gadget_sites,
        circuit.c_producer.witness_to_signal_list,
        input_list,
        public_inputs,
        main_inputs,
        main_outputs,
        circuit.c_producer.total_number_of_signals,
    );
    graph.mpc_public_inputs = mpc_public_inputs;
    Ok(graph)
}
