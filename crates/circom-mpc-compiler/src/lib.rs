//! Compiles a circom circuit into a `circom_mpc_program::Program`: [`compile`] builds the
//! frontend's graph, runs the optimization/MPC-lowering passes pipeline over it, and hands the
//! result to codegen.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

mod codegen;
mod frontend;
mod ir;
mod passes;

pub use passes::OptLevel;

/// The mpc-compiler configuration
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct CompilerConfig {
    /// The circom version
    #[serde(default = "default_version")]
    pub version: String,
    /// The path to Circom library files
    #[serde(default)]
    pub link_library: Vec<PathBuf>,
    /// Shows logs during compilation
    #[serde(default)]
    pub verbose: bool,
    /// Does an additional check over the constraints produced
    #[serde(default)]
    pub inspect: bool,
    /// Which of this crate's IR passes run after the frontend builds the graph. Distinct from
    /// upstream circom's own constraint simplification, which always runs at full `--O2`.
    #[serde(default)]
    pub opt_level: OptLevel,
    /// Input names every MPC party holds in cleartext, even though they are not declared
    /// SNARK-public. A genuine declassification: the domain analysis treats these as
    /// `Domain::Public`, which is only sound if every party already holds the value in the clear
    /// outside the proof. Misclassifying a value here leaks it to every MPC party. Independent of
    /// the SNARK statement split, which the zkey's `num_instance_variables` decides.
    #[serde(default)]
    pub mpc_public_inputs: Vec<String>,
    /// Whether a `TACEO_PRECOMPUTATION_Poseidon2` wrapper is honored as a host-precomputed site.
    /// `false` compiles it as an ordinary driver-serviced `Poseidon2` site instead - the two are
    /// R1CS-identical, so a zkey built from one still matches the other. Set this to `false` to
    /// prove against inputs whose commitment hashes were never computed by the host.
    #[serde(default = "default_precomputed_gadgets")]
    pub precomputed_gadgets: bool,
}

fn default_version() -> String {
    "2.2.2".to_owned()
}

fn default_precomputed_gadgets() -> bool {
    true
}

impl Default for CompilerConfig {
    fn default() -> Self {
        Self {
            version: default_version(),
            link_library: vec![],
            verbose: false,
            inspect: false,
            opt_level: OptLevel::default(),
            mpc_public_inputs: vec![],
            precomputed_gadgets: default_precomputed_gadgets(),
        }
    }
}

/// Parses and type-checks `file`, then runs the optimization/MPC-lowering passes over the
/// resulting graph.
fn build<Pth>(file: Pth, config: &CompilerConfig) -> eyre::Result<ir::Graph>
where
    PathBuf: From<Pth>,
    Pth: std::fmt::Debug,
{
    tracing::debug!("compiler starts parsing..");
    let opt_level = config.opt_level;
    let mut graph = frontend::build_graph(PathBuf::from(file).display().to_string(), config)?;
    graph.verify()?;
    tracing::debug!("graph before passes:\n{:?}", graph);
    passes::PassManager::for_opt_level(opt_level).run(&mut graph)?;
    Ok(graph)
}

/// Parses, type-checks and lowers `file` into a `circom_mpc_program::Program`, runnable via
/// `circom_mpc_vm::Machine::run` against the plain or rep3 driver.
///
/// # Errors
///
/// Returns an error if `file` fails to parse, type-check, or build into a graph, or if a pass or
/// codegen fails.
pub fn compile<Pth>(file: Pth, config: &CompilerConfig) -> eyre::Result<circom_mpc_program::Program>
where
    PathBuf: From<Pth>,
    Pth: std::fmt::Debug,
{
    let graph = build(file, config)?;
    let program = codegen::compile(&graph)?;
    tracing::debug!("compiled: {:?}", program.statistics());
    Ok(program)
}

/// Assertions on graph shape that have no `ProgramStatistics` equivalent - `ir::GadgetSite` and
/// `Graph::num_signals` are private, so these can't live in `circom-mpc-compiler-tests`.
#[cfg(test)]
mod tests {
    use ir::GadgetKind;

    use super::*;

    fn manifest_dir() -> &'static str {
        concat!(env!("CARGO_MANIFEST_DIR"), "/../..")
    }

    fn circuit_path(name: &str) -> String {
        format!("{}/circuits/{name}.circom", manifest_dir())
    }

    fn config() -> CompilerConfig {
        let mut config = CompilerConfig::default();
        config
            .link_library
            .push(format!("{}/circuits/node_modules/", manifest_dir()).into());
        config
    }

    struct Wrapper {
        circuit: &'static str,
        inner_name: &'static str,
        kind: GadgetKind,
        num_inputs: usize,
        num_outputs: usize,
    }

    fn wrappers() -> Vec<Wrapper> {
        vec![
            Wrapper {
                circuit: "gadget_poseidon2_test",
                inner_name: "Poseidon2",
                kind: GadgetKind::Poseidon2 {
                    t: circom_mpc_program::Poseidon2Width::new(3).expect("3 is a supported width"),
                },
                num_inputs: 3,
                num_outputs: 3,
            },
            Wrapper {
                circuit: "gadget_num2bits_test",
                inner_name: "Num2Bits",
                kind: GadgetKind::Num2Bits { n: 8 },
                num_inputs: 1,
                num_outputs: 8,
            },
            Wrapper {
                circuit: "gadget_iszero_test",
                inner_name: "IsZero",
                kind: GadgetKind::IsZero,
                num_inputs: 1,
                num_outputs: 1,
            },
            Wrapper {
                circuit: "gadget_aliascheck_test",
                inner_name: "AliasCheck",
                kind: GadgetKind::AliasCheck,
                num_inputs: 254,
                num_outputs: 0,
            },
        ]
    }

    #[test]
    fn extract_yields_one_site_per_wrapper() {
        for w in &wrappers() {
            let graph = build(circuit_path(w.circuit), &config())
                .unwrap_or_else(|e| panic!("{}: {e}", w.circuit));
            let sites = graph.gadget_sites();
            assert_eq!(
                sites.len(),
                1,
                "{}: expected exactly one gadget site",
                w.circuit
            );
            let site = &sites[0];
            assert!(
                site.header.starts_with(w.inner_name),
                "{}: expected header starting with `{}`, got `{}`",
                w.circuit,
                w.inner_name,
                site.header
            );
            assert_eq!(site.kind, w.kind, "{}", w.circuit);
            assert_eq!(site.num_inputs, w.num_inputs, "{}", w.circuit);
            assert_eq!(site.num_outputs, w.num_outputs, "{}", w.circuit);
        }
    }

    #[test]
    fn signal_span_matches_independent_total() {
        for w in &wrappers() {
            let graph = build(circuit_path(w.circuit), &config())
                .unwrap_or_else(|e| panic!("{}: {e}", w.circuit));
            let site = &graph.gadget_sites()[0];
            // main *is* the wrapper for each of these circuits, so the whole circuit's signal
            // count (minus the reserved constant-1 slot) must equal the wrapper's own I/O plus
            // the site's full result span.
            let expected = graph.num_inputs()
                + graph.num_outputs()
                + site.num_inputs
                + site.num_outputs
                + site.num_intermediates;
            assert_eq!(graph.num_signals() - 1, expected, "{}", w.circuit);
        }
    }
}
