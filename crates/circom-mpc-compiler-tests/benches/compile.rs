//! Compile-time bench: `circom_mpc_compiler::compile` end to end (circom frontend, this crate's
//! passes, and codegen), and what each optimization level costs.
//!
//! Plain by nature - compilation never touches a driver or a network.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use circom_mpc_compiler::{CompilerConfig, OptLevel};

fn manifest_dir() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../..")
}

struct Case {
    name: &'static str,
    path: String,
}

fn cases() -> Vec<Case> {
    let simple = |name: &'static str| Case {
        name,
        path: format!("{}/circuits/{name}.circom", manifest_dir()),
    };
    vec![simple("multiplier16"), simple("bench_tree")]
}

fn config() -> CompilerConfig {
    let mut config = CompilerConfig::default();
    config
        .link_library
        .push(format!("{}/circuits/node_modules/", manifest_dir()).into());
    config
}

fn bench(c: &mut Criterion) {
    let cases = cases();

    let mut group = c.benchmark_group("compile");
    for case in &cases {
        group.bench_with_input(BenchmarkId::from_parameter(case.name), &(), |b, ()| {
            b.iter(|| {
                circom_mpc_compiler::compile(case.path.clone(), &config()).unwrap();
            });
        });
    }
    group.finish();

    // What each optimization level costs, on a circuit small enough for the difference to be legible.
    let mut group = c.benchmark_group("opt_level");
    let case = Case {
        name: "multiplier16",
        path: format!("{}/circuits/multiplier16.circom", manifest_dir()),
    };
    for opt in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{opt:?}")),
            &(),
            |b, ()| {
                b.iter(|| {
                    let mut cfg = config();
                    cfg.opt_level = opt;
                    circom_mpc_compiler::compile(case.path.clone(), &cfg).unwrap();
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
