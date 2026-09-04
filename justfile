[private]
default:
    @just --justfile {{ justfile() }} --list --list-heading $'Project commands:\n'

[group('build')]
circuits:
    pnpm -C circuits install

[group('build')]
gen-proving-artifacts *args:
    @bash scripts/gen-proving-artifacts.sh {{ args }}

[group('test')]
rust-tests: circuits
    cargo test --release --workspace --all-features

[group('bench')]
bench *args: circuits
    cargo bench -p circom-mpc-compiler-tests --bench witness_extension {{args}}

[group('bench')]
bench-net *args:
    @bash scripts/run-witext-bench.sh {{args}}

[group('ci')]
fmt:
    cargo +nightly fmt

[group('ci')]
lint:
    cargo +nightly fmt --all -- --check
    cargo clippy --workspace --tests --examples --benches --bins -q -- -D warnings
    cargo clippy --workspace --tests --examples --benches --bins -q --all-features -- -D warnings
    RUSTDOCFLAGS='-D warnings' cargo doc --workspace -q --no-deps --document-private-items

[group('ci')]
cargo-deny:
    cargo deny check

[group('ci')]
check-pr: lint cargo-deny rust-tests
