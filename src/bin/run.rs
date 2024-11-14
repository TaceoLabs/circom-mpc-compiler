use ark_bn254::Bn254;
use circom_mpc_compiler::{
    interpreter::Interpreter, CoCircomCompiler, CompilerConfig, SimplificationLevel,
};

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
    let mut config = CompilerConfig::new();
    config.simplification = SimplificationLevel::O2(usize::MAX);
    let ast =
        CoCircomCompiler::<Bn254>::parse(format!("{root}/circuits/loop_unrolling.circom"), config)?;
    let signals = vec![
        ark_bn254::Fr::from(1),
        ark_bn254::Fr::from(0),
        ark_bn254::Fr::from(0),
        ark_bn254::Fr::from(0),
        ark_bn254::Fr::from(0),
        ark_bn254::Fr::from(2),
        ark_bn254::Fr::from(3),
        ark_bn254::Fr::from(4),
        ark_bn254::Fr::from(5),
    ];

    tracing::info!("signals before = {signals:?}");
    let mut interpreter = Interpreter::new(ast, signals);
    let signals = interpreter.run();

    tracing::info!("signals after = {signals:?}");

    Ok(())
}
