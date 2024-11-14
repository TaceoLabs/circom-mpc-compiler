use std::{collections::HashMap, marker::PhantomData, path::PathBuf};

use ark_ec::pairing::Pairing;
use ark_ff::{BigInteger, PrimeField};

use circom_compiler::{
    compiler_interface::{Circuit as CircomCircuit, CompilationFlags, VCP},
    hir::very_concrete_program::Wire,
};
use circom_constraint_generation::BuildConfig;
use circom_ir::types::CircomAST;
use circom_program_structure::{
    ast::SignalType, error_definition::Report, program_archive::ProgramArchive,
};
use circom_type_analysis::check_types;
use serde::{Deserialize, Serialize};

mod circom_ir;
pub mod interpreter;

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
    "2.2.0".to_owned()
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
    file: PathBuf,
    phantom_data: PhantomData<P>,
    config: CompilerConfig,
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
            file: PathBuf::from(file),
            config,
            phantom_data: PhantomData,
        }
    }
    pub fn parse<Pth>(file: Pth, config: CompilerConfig) -> eyre::Result<CircomAST<P::ScalarField>>
    where
        PathBuf: From<Pth>,
        Pth: std::fmt::Debug,
    {
        tracing::debug!("compiler starts parsing..");
        let circom_ir = circom_ir::translate::build_circom_ir::<P>(
            PathBuf::from(file).display().to_string(),
            config,
        )?;
        tracing::debug!("AST:\n{:?}", circom_ir);
        tracing::debug!("success!");
        Ok(circom_ir)
    }

    fn parse_inner(&mut self) -> eyre::Result<()> {
        Ok(())
    }
}
