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
    tracing::debug!("graph before passes:\n{:?}", graph);
    passes::PassManager::for_opt_level(opt_level).run(&mut graph);
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
