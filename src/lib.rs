use std::{marker::PhantomData, path::PathBuf};

use ark_ec::pairing::Pairing;

use serde::{Deserialize, Serialize};

pub mod fixtures;
mod frontend;
pub mod ir;
pub mod passes;
pub mod vm;

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
}

fn default_version() -> String {
    "2.2.2".to_owned()
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
        }
    }
}

/// Namespace for the two entry points, parameterized by the curve.
pub struct CoCircomCompiler<P: Pairing> {
    phantom_data: PhantomData<P>,
}

impl<P: Pairing> CoCircomCompiler<P> {
    pub fn parse<Pth>(file: Pth, config: CompilerConfig) -> eyre::Result<ir::Graph<P::ScalarField>>
    where
        PathBuf: From<Pth>,
        Pth: std::fmt::Debug,
    {
        tracing::debug!("compiler starts parsing..");
        let opt_level = config.opt_level;
        let mut graph =
            frontend::build_graph::<P>(PathBuf::from(file).display().to_string(), config)?;
        graph.verify()?;
        tracing::debug!("graph before passes:\n{:?}", graph);
        passes::PassManager::for_opt_level(opt_level).run(&mut graph)?;
        tracing::debug!("success!");
        Ok(graph)
    }

    /// `parse`, then lowers the resulting graph into a `vm::Program`, runnable via
    /// `vm::Machine::run` against the plain or rep3 driver.
    pub fn compile<Pth>(file: Pth, config: CompilerConfig) -> eyre::Result<vm::Program<P::ScalarField>>
    where
        PathBuf: From<Pth>,
        Pth: std::fmt::Debug,
    {
        let graph = Self::parse(file, config)?;
        vm::codegen::compile(&graph)
    }
}
