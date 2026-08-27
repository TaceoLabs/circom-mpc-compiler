//! Compiles a circom circuit to a `circom-mpc-program::Program` and writes it to disk.
//!
//! ```text
//! cargo run --release -p circom-mpc-compiler --features cli -- \
//!     circuits/merces/main/transfer_arity4_batch1.circom \
//!     -l circuits/libs/ -l circuits/merces/ --opt 2 -o transfer_arity4_batch1.cmpc
//! ```

use std::fs::File;
use std::io::BufWriter;
use std::path::PathBuf;

use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig, OptLevel};
use clap::Parser;

#[derive(Parser)]
#[command(about = "Compiles a circom circuit into a circom-mpc-program::Program file")]
struct Cli {
    /// Path to the circom main file to compile.
    circuit: PathBuf,
    /// Where to write the compiled program. Defaults to the circuit's file stem with a `.cmpc`
    /// extension, in the current directory.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// TOML file deserialized into `CompilerConfig`. CLI flags below are applied on top of it.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Directory to resolve circom's `include`s against. Repeatable.
    #[arg(short = 'l', long = "link-library")]
    link_library: Vec<PathBuf>,
    /// Input name every MPC party holds in cleartext, even though it is not SNARK-public.
    /// Repeatable. See `CompilerConfig::mpc_public_inputs`.
    #[arg(long = "mpc-public-input")]
    mpc_public_input: Vec<String>,
    /// This crate's IR optimization level: 0, 1, or 2. Distinct from circom's own constraint
    /// simplification, which always runs at full `--O2`.
    #[arg(long)]
    opt: Option<u8>,
    /// The circom pragma version to compile against.
    #[arg(long)]
    circom_version: Option<String>,
    /// Runs an additional check over the produced constraints.
    #[arg(long)]
    inspect: bool,
    /// Shows logs during compilation.
    #[arg(long)]
    verbose: bool,
}

fn install_tracing() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{EnvFilter, fmt};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(false).with_line_number(false))
        .init();
}

fn opt_level(n: u8) -> eyre::Result<OptLevel> {
    match n {
        0 => Ok(OptLevel::O0),
        1 => Ok(OptLevel::O1),
        2 => Ok(OptLevel::O2),
        _ => eyre::bail!("--opt must be 0, 1, or 2 (there is no O3)"),
    }
}

fn build_config(cli: &Cli) -> eyre::Result<CompilerConfig> {
    let mut config = match &cli.config {
        Some(path) => {
            let src = std::fs::read_to_string(path)
                .map_err(|e| eyre::eyre!("reading {}: {e}", path.display()))?;
            toml::from_str(&src).map_err(|e| eyre::eyre!("parsing {}: {e}", path.display()))?
        }
        None => CompilerConfig::default(),
    };

    config.link_library.extend(cli.link_library.iter().cloned());
    config
        .mpc_public_inputs
        .extend(cli.mpc_public_input.iter().cloned());
    if let Some(opt) = cli.opt {
        config.opt_level = opt_level(opt)?;
    }
    if let Some(version) = &cli.circom_version {
        config.version = version.clone();
    }
    if cli.inspect {
        config.inspect = true;
    }
    if cli.verbose {
        config.verbose = true;
    }
    Ok(config)
}

fn output_path(cli: &Cli) -> PathBuf {
    cli.output.clone().unwrap_or_else(|| {
        let stem = cli
            .circuit
            .file_stem()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("out"));
        stem.with_extension("cmpc")
    })
}

fn main() -> eyre::Result<()> {
    install_tracing();
    let cli = Cli::parse();
    let config = build_config(&cli)?;
    let out = output_path(&cli);

    let program = CoCircomCompiler::compile(&cli.circuit, config)?;

    let stats = program.statistics();
    eprintln!("compiled: {}", cli.circuit.display());
    eprintln!(
        "  {} instructions, {} inputs, {} witness values",
        stats.instructions, stats.inputs, stats.witness_values
    );
    eprintln!(
        "  slots public={} shared={} local={}",
        stats.public_slots, stats.shared_slots, stats.local_slots
    );
    eprintln!(
        "  multiplication rounds={} elements={}",
        stats.multiplication_rounds, stats.multiplication_elements
    );
    eprintln!(
        "  accelerator: {} sites -> {} batches ({} host-precomputed)",
        stats.accelerator_sites, stats.accelerator_batches, stats.precomputed_batches
    );

    program.write(&mut BufWriter::new(
        File::create(&out).map_err(|e| eyre::eyre!("creating {}: {e}", out.display()))?,
    ))?;
    eprintln!("wrote:    {}", out.display());

    Ok(())
}
