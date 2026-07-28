use std::{marker::PhantomData, path::PathBuf};

use ark_ec::pairing::Pairing;

use serde::{Deserialize, Serialize};

mod frontend;
pub mod interpreter;
pub mod ir;

/// The simplification level applied during constraint generation
#[derive(
    Debug, Default, Copy, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash,
)]
pub enum SimplificationLevel {
    /// No simplification
    O0,
    /// Only applies signal to signal and signal to constant simplification
    /// The default value since circom 2.2.0
    #[default]
    O1,
    /// Full constraint simplification (applied for n rounds)
    O2(usize),
}

/// The mpc-compiler configuration
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct CompilerConfig {
    /// The circom version
    #[serde(default = "default_version")]
    pub version: String,
    /// Allow leaking of secret values in loops (not used atm)
    #[serde(default)]
    pub allow_leaky_loops: bool,
    /// The path to Circom library files
    #[serde(default)]
    pub link_library: Vec<PathBuf>,
    /// The optimization flag passed to the compiler
    #[serde(default)]
    pub simplification: SimplificationLevel,
    /// Shows logs during compilation
    #[serde(default)]
    pub verbose: bool,
    /// Does an additional check over the constraints produced
    #[serde(default)]
    pub inspect: bool,
}

fn default_version() -> String {
    "2.2.2".to_owned()
}

impl Default for CompilerConfig {
    fn default() -> Self {
        Self {
            version: default_version(),
            link_library: vec![],
            allow_leaky_loops: false,
            simplification: SimplificationLevel::default(),
            verbose: false,
            inspect: false,
        }
    }
}

impl CompilerConfig {
    /// Creates a new instance of the compiler config with
    /// values set to default
    pub fn new() -> Self {
        Self::default()
    }
}

pub struct CoCircomCompiler<P: Pairing> {
    phantom_data: PhantomData<P>,
}

impl<P: Pairing> CoCircomCompiler<P> {
    // only internally to hold the state
    fn new<Pth>(file: Pth, config: CompilerConfig) -> Self
    where
        PathBuf: From<Pth>,
        Pth: std::fmt::Debug,
    {
        tracing::debug!("creating compiler for circuit {file:?} with config: {config:?}");
        Self {
            phantom_data: PhantomData,
        }
    }

    pub fn parse<Pth>(file: Pth, config: CompilerConfig) -> eyre::Result<ir::Graph<P::ScalarField>>
    where
        PathBuf: From<Pth>,
        Pth: std::fmt::Debug,
    {
        tracing::debug!("compiler starts parsing..");
        let mut graph =
            frontend::build_graph::<P>(PathBuf::from(file).display().to_string(), config)?;
        graph.verify()?;
        tracing::debug!("graph before gc:\n{:?}", graph);
        graph.gc();
        graph.verify()?;
        tracing::debug!("success!");
        Ok(graph)
    }
}
