//! Compile-time benches: `CoCircomCompiler::parse` (circom frontend + this crate's lowering and
//! passes) and `vm::codegen::compile` (IR -> bytecode), timed **separately** so a regression lands on
//! whichever one caused it.
//!
//! Plain by nature - compilation never touches a driver or a network.
//!
//! `parse` dominates by orders of magnitude on real circuits, most of it upstream circom work this
//! crate does not control, which is precisely why the two are split: a pass-infrastructure regression
//! would be invisible inside a single combined number.

use ark_bn254::Bn254;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use circom_mpc_compiler::vm::codegen;
use circom_mpc_compiler::{CoCircomCompiler, CompilerConfig, OptLevel, SimplificationLevel};

fn manifest_dir() -> &'static str {
    env!("CARGO_MANIFEST_DIR")
}

struct Case {
    name: &'static str,
    path: String,
    merces: bool,
}

fn cases() -> Vec<Case> {
    let simple = |name: &'static str| Case {
        name,
        path: format!("{}/circuits/{name}.circom", manifest_dir()),
        merces: false,
    };
    let merces = |name: &'static str| Case {
        name,
        path: format!("{}/circuits/merces/main/{name}.circom", manifest_dir()),
        merces: true,
    };
    vec![
        simple("multiplier16"),
        simple("bench_tree"),
        // The one precompute-heavy small circuit: 119 sites at N=1 versus 950 at N=8, which is what
        // stresses the batch grouping and slot reservation.
        merces("transfer_arity4_batch1"),
        merces("transfer_arity4_batch8"),
    ]
}

fn config(case: &Case) -> CompilerConfig {
    let mut config = CompilerConfig::default();
    config.simplification = SimplificationLevel::O2(usize::MAX);
    config
        .link_library
        .push(format!("{}/circuits/libs/", manifest_dir()).into());
    if case.merces {
        config.version = "2.2.2".to_owned();
        config
            .link_library
            .push(format!("{}/circuits/merces/", manifest_dir()).into());
    }
    config
}

fn bench(c: &mut Criterion) {
    let cases = cases();

    // `parse` = frontend + inlining + the whole PassManager pipeline.
    let mut group = c.benchmark_group("parse");
    // These take seconds each on the merces mains; the default 100 samples would take an hour.
    group.sample_size(10);
    for case in &cases {
        group.bench_with_input(BenchmarkId::from_parameter(case.name), &(), |b, ()| {
            b.iter(|| {
                CoCircomCompiler::<Bn254>::parse(case.path.clone(), config(case)).unwrap();
            });
        });
    }
    group.finish();

    // `codegen` alone, on an already-parsed graph - the part this crate fully owns.
    let mut group = c.benchmark_group("codegen");
    for case in &cases {
        let graph = CoCircomCompiler::<Bn254>::parse(case.path.clone(), config(case))
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
        merces: false,
    };
    for opt in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{opt:?}")),
            &(),
            |b, ()| {
                b.iter(|| {
                    let mut cfg = config(&case);
                    cfg.opt_level = opt;
                    CoCircomCompiler::<Bn254>::parse(case.path.clone(), cfg).unwrap();
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
