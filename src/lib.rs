use std::{marker::PhantomData, path::PathBuf};

use ark_ec::pairing::Pairing;

use serde::{Deserialize, Serialize};

mod frontend;
pub mod interpreter;
pub mod ir;
pub mod passes;

pub use passes::OptLevel;

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

/// How `TACEO_PRECOMPUTATION_*`-wrapped components are handled. See `docs/ARCHITECTURE.md`,
/// "Precomputation".
#[derive(
    Debug, Default, Copy, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash,
)]
pub enum PrecomputationMode {
    /// Extract each wrapped component into an `ir::Op::Precompute` site instead of compiling its
    /// body - the wrapper's own inputs/outputs are wired up as usual, but the runtime must supply
    /// a trace for every site (see [`crate::interpreter::PrecomputeProvider`]).
    #[default]
    Extract,
    /// Compile the wrapped component's body like any other template. Useful for plaintext
    /// comparison against a circuit with no precomputation accelerator; expected to fail with the
    /// same typed `Unsupported` errors the wrapped gadgets would hit unwrapped (field inversion,
    /// bit extraction, ...).
    Inline,
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
    /// Which IR passes `CoCircomCompiler::parse` runs after the frontend builds the graph.
    /// Distinct from `simplification`, which configures upstream circom constraint
    /// simplification, not this crate's own passes (see `src/passes/`).
    #[serde(default)]
    pub opt_level: OptLevel,
    /// How `TACEO_PRECOMPUTATION_*`-wrapped components are handled.
    #[serde(default)]
    pub precomputation: PrecomputationMode,
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
            opt_level: OptLevel::default(),
            precomputation: PrecomputationMode::default(),
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
        let opt_level = config.opt_level;
        let mut graph =
            frontend::build_graph::<P>(PathBuf::from(file).display().to_string(), config)?;
        graph.verify()?;
        tracing::debug!("graph before passes:\n{:?}", graph);
        passes::PassManager::for_opt_level(opt_level).run(&mut graph)?;
        tracing::debug!("success!");
        Ok(graph)
    }
}
