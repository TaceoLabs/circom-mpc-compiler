//! Compile-time bench: `circom_mpc_compiler::compile` end to end (circom frontend, this crate's
//! passes, and codegen), across every case in `circom_mpc_compiler_tests::cases`, plus what each
//! optimization level costs on a small circuit.
//!
//! Plain by nature - compilation never touches a driver or a network. `BENCH_CASES=<substr>`
//! filters cases, same as `witness_extension.rs`. `merces/batch32` is omitted by default because
//! repeated compilation is too slow; an explicit matching filter opts it back in. A case that
//! fails to compile is skipped with a printed warning.

use circom_mpc_compiler::OptLevel;
use circom_mpc_compiler_tests::cases;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

fn bench(c: &mut Criterion) {
    let filter = std::env::var("BENCH_CASES").ok();
    let cases: Vec<_> = cases::select(filter.as_deref())
        .into_iter()
        .filter(|case| filter.is_some() || case.name != "merces/batch32")
        .filter(|case| match cases::compile(case) {
            Ok(_) => true,
            Err(e) => {
                println!("skipping {}: {e}", case.name);
                false
            }
        })
        .collect();

    let mut group = c.benchmark_group("compile");
    for case in &cases {
        group.bench_with_input(BenchmarkId::from_parameter(&case.name), &(), |b, ()| {
            b.iter(|| {
                cases::compile(case).unwrap();
            });
        });
    }
    group.finish();

    // What each optimization level costs, on a circuit small enough for the difference to be
    // legible.
    let mut group = c.benchmark_group("opt_level");
    let case = &cases::select(Some("micro/multiplier16"))
        .into_iter()
        .next()
        .expect("micro/multiplier16 is registered");
    for opt in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{opt:?}")),
            &(),
            |b, ()| {
                b.iter(|| {
                    let mut config = case.config.clone();
                    config.opt_level = opt;
                    circom_mpc_compiler::compile(case.path.clone(), &config).unwrap();
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
