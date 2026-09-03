//! Compile-time benches: `circom_mpc_compiler::parse` (circom frontend + this crate's lowering and
//! passes) and `vm::codegen::compile` (IR -> bytecode), timed **separately** so a regression lands on
//! whichever one caused it.
//!
//! Plain by nature - compilation never touches a driver or a network.
//!
//! `parse` dominates by orders of magnitude on real circuits, most of it upstream circom work this
//! crate does not control, which is precisely why the two are split: a pass-infrastructure regression
//! would be invisible inside a single combined number.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use circom_mpc_compiler::codegen;
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

    // `parse` = frontend + inlining + the whole PassManager pipeline.
    let mut group = c.benchmark_group("parse");
    for case in &cases {
        group.bench_with_input(BenchmarkId::from_parameter(case.name), &(), |b, ()| {
            b.iter(|| {
                circom_mpc_compiler::parse(case.path.clone(), &config()).unwrap();
            });
        });
    }
    group.finish();

    // `codegen` alone, on an already-parsed graph - the part this crate fully owns.
    let mut group = c.benchmark_group("codegen");
    for case in &cases {
        let graph = circom_mpc_compiler::parse(case.path.clone(), &config())
            .unwrap_or_else(|e| panic!("{}: {e}", case.name));
        group.bench_with_input(BenchmarkId::from_parameter(case.name), &(), |b, ()| {
            b.iter(|| codegen::compile(&graph).unwrap());
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
                    circom_mpc_compiler::parse(case.path.clone(), &cfg).unwrap();
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
