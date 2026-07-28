use ark_bn254::Bn254;
use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig, SimplificationLevel};

fn install_tracing() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{fmt, EnvFilter};

    let fmt_layer = fmt::layer().with_target(false).with_line_number(false);
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();
}

fn main() -> eyre::Result<()> {
    install_tracing();
    let root = std::env!("CARGO_MANIFEST_DIR");
    // poseidon_hasher1.circom (the old default) calls a helper function, which this compiler
    // doesn't support yet (see docs/ARCHITECTURE.md, "Known gaps") - default to something that
    // actually compiles so `cargo run` demonstrates a working path out of the box.
    let circuit = std::env::args()
        .nth(1)
        .unwrap_or_else(|| format!("{root}/circuits/multiplier2.circom"));

    let mut config = CompilerConfig::new();
    config.simplification = SimplificationLevel::O2(usize::MAX);
    config
        .link_library
        .push(format!("{root}/circuits/libs/").into());

    let graph = CoCircomCompiler::<Bn254>::parse(circuit, config)?;
    tracing::info!("graph:\n{graph:?}");
    tracing::info!("mpc summary: {:?}", graph.mpc_summary());

    Ok(())
}
