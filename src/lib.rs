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
    /// Allow leaking of secret values in loops. Not currently consulted by the compiler.
    #[serde(default)]
    pub allow_leaky_loops: bool,
    /// The path to Circom library files
    #[serde(default)]
    pub link_library: Vec<PathBuf>,
    /// Shows logs during compilation
    #[serde(default)]
    pub verbose: bool,
    /// Does an additional check over the constraints produced
    #[serde(default)]
    pub inspect: bool,
    /// Which IR passes `CoCircomCompiler::parse` runs after the frontend builds the graph. Distinct
    /// from upstream circom's own constraint simplification (always run at full `--O2`, see
    /// `src/frontend/mod.rs`) - this configures this crate's own passes (see `src/passes/`).
    #[serde(default)]
    pub opt_level: OptLevel,
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
            verbose: false,
            inspect: false,
            opt_level: OptLevel::default(),
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

/// Namespace for the two entry points, parameterized by the curve. Never instantiated - there is no
/// compiler *state* to hold, so both entry points are associated functions.
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

    /// `parse`, then lowers the resulting graph into a `vm::Program` - the final compiler output,
    /// runnable via `vm::Machine::run` against either `vm::driver::plain::PlainDriver` or a real
    /// rep3 driver. See `docs/ARCHITECTURE.md`, "Bytecode and the slot machine".
    pub fn compile<Pth>(file: Pth, config: CompilerConfig) -> eyre::Result<vm::Program<P::ScalarField>>
    where
        PathBuf: From<Pth>,
        Pth: std::fmt::Debug,
    {
        let graph = Self::parse(file, config)?;
        vm::codegen::compile(&graph)
    }
}
