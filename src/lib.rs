use std::{marker::PhantomData, path::PathBuf};

use ark_ec::pairing::Pairing;

use serde::{Deserialize, Serialize};

pub mod fixtures;
mod frontend;
pub mod ir;
pub mod passes;
pub mod vm;

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
    /// body - the wrapper's own inputs/outputs are wired up as usual, and `vm::Machine::run`
    /// computes every site's trace itself, batched by gadget kind (see
    /// [`crate::vm::driver::VmDriver`]).
    #[default]
    Extract,
    /// Compile the wrapped component's body like any other template. Useful for plaintext
    /// comparison against a circuit with no precomputation accelerator; expected to fail with the
    /// same typed `Unsupported` errors the wrapped gadgets would hit unwrapped (field inversion,
    /// bit extraction, ...).
    Inline,
}

/// What to do when a `TACEO_PRECOMPUTATION_*` wrapper names a gadget this compiler has no
/// out-of-band implementation for.
///
/// A wrapper marks an *opportunity* to accelerate, not a requirement: a compiler with no gadget for
/// it can still produce a correct circuit by compiling the wrapped body, losing only speed. That is
/// what [`Self::Warn`] does. It is what lets `circuits/merces/` compile unmodified - the vendored
/// `merkle_root_4.circom` wraps an `Arity4CMux` this compiler doesn't recognize, whose body is pure
/// `Add`/`Sub`/`Mul` and so compiles fine (and whose multiplications `passes::mpc::round_schedule`
/// then batches automatically, which is *better* than a hand-wrapped site).
///
/// See `docs/ARCHITECTURE.md`, "Precomputation".
#[derive(
    Debug, Default, Copy, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash,
)]
pub enum UnknownPrecomputeGadget {
    /// Fail with `Unsupported::PrecomputeGadget`, naming the gadget. The default, so no existing
    /// build silently changes meaning: a wrapper the author expected to be accelerated staying
    /// unaccelerated is a real (if non-fatal) surprise.
    #[default]
    Error,
    /// Emit a `tracing::warn!` naming the gadget, wrapper and line, then compile the wrapped body
    /// like any ordinary template.
    Warn,
}

/// Whether a gadget this compiler *does* have an out-of-band implementation for is cut into a
/// precomputation site even when it is instantiated **without** a `TACEO_PRECOMPUTATION_*` wrapper.
///
/// The mirror of [`UnknownPrecomputeGadget`]: that one handles a wrapper with no gadget, this one a
/// gadget with no wrapper. Needed by `circuits/merces/`, whose vendored `merkle_root_4.circom` calls
/// `IsEqual()` bare - and `IsEqual` reduces to `IsZero`, which needs field inversion, `!=`, and a
/// branch on a secret condition, none of which this compiler's `Add`/`Sub`/`Mul`-only `ir::Op` can
/// express.
///
/// See `docs/ARCHITECTURE.md`, "Precomputation".
#[derive(
    Debug, Default, Copy, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash,
)]
pub enum BareGadgetDetection {
    /// Compile an unwrapped gadget like any other template. The default: it keeps the
    /// `TACEO_PRECOMPUTATION_*` contract explicit-opt-in, so a gadget the circuit author
    /// deliberately wanted constrained in-circuit stays that way.
    #[default]
    Off,
    /// Cut a recognized gadget into a precomputation site whether or not it is wrapped.
    ///
    /// This is a *semantic* change, not merely a performance one - the gadget's body is no longer
    /// compiled, and its values are supplied out-of-band - which is why it is off by default and set
    /// per compile rather than inferred.
    On,
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
    /// What to do when a `TACEO_PRECOMPUTATION_*` wrapper names an unrecognized gadget.
    #[serde(default)]
    pub unknown_precompute_gadget: UnknownPrecomputeGadget,
    /// Whether recognized gadgets are cut into sites even when instantiated without a wrapper.
    #[serde(default)]
    pub bare_gadget_detection: BareGadgetDetection,
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
            unknown_precompute_gadget: UnknownPrecomputeGadget::default(),
            bare_gadget_detection: BareGadgetDetection::default(),
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
