# circom-mpc-compiler

[![CI](https://github.com/TaceoLabs/circom-mpc-compiler/actions/workflows/ci.yml/badge.svg)](https://github.com/TaceoLabs/circom-mpc-compiler/actions/workflows/ci.yml)
[![Audit Dependencies](https://github.com/TaceoLabs/circom-mpc-compiler/actions/workflows/audit.yml/badge.svg)](https://github.com/TaceoLabs/circom-mpc-compiler/actions/workflows/audit.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0%20%7C%20GPL--3.0-blue)](#license)
[![rustc](https://img.shields.io/badge/rustc-1.90%2B-blue)](Cargo.toml)

Compiles [circom](https://github.com/iden3/circom) circuits into a witness-extension procedure, then
runs that procedure for real: a plain (in-the-clear) reference interpreter, and a 3-party rep3 MPC
driver that produces a co-groth16 proof over the shared witness. It is not a proving-system compiler
itself — it does not generate R1CS or a proving key, only the witness those need.

Pipeline: circom source → circom's own parser/type-checker/constraint-generation (always at full
`--O2`) → per-template lowering with lazy sub-component inlining and eager loop unrolling → one flat
value-graph IR → MPC lowering and codegen → the plain interpreter or the rep3 driver.

The runtime operator surface is deliberately narrow — only `Add`/`Sub`/`Mul` are supported; every
other circom operator is a typed `unsupported operator: ...` error.

## Crates

A Cargo workspace of four crates:

- `circom-mpc-program` — the compiled program representation (`Program`, `GadgetKind`) and its
  binary format (`Program::write`/`Program::read`). No dependency on the compiler or the VM.
- `circom-mpc-vm` — the bytecode VM (`Vm::run`), its plain and rep3 drivers, and
  `CountingNet`. Rep3 is always available; `mpc-net` backends are selected independently through
  the `local`, `quic`, `tcp`, `tcp-session`, `tcp-session-blocking`, and `tls` features.
- `circom-mpc-compiler` — parses circom source into the IR, lowers it through the MPC passes, and
  compiles it to a `circom-mpc-program::Program` (`circom_mpc_compiler::compile`). It does not
  depend on the VM or a network backend.
- `circom-mpc-compiler-tests` — non-published integration tests and fixtures. Its
  default `local` feature keeps the complete in-process MPC suite in plain `cargo test`; other
  network backends remain opt-in.

## CLI

`circom-mpc-compiler` builds a `circom-mpc-compile` binary, gated behind the `cli` feature, that
compiles a circom file to a `circom-mpc-program::Program` file.

### Install

From a checkout:

```sh
cargo install --path crates/circom-mpc-compiler --features cli
```

Directly from GitHub:

```sh
cargo install --git https://github.com/TaceoLabs/circom-mpc-compiler --features cli taceo-circom-mpc-compiler
```

Or run it in place without installing:

```sh
cargo run --release -p taceo-circom-mpc-compiler --features cli -- <args...>
```

### Usage

```sh
circom-mpc-compile circuits/multiplier3.circom -l circuits/node_modules/ --opt 2 -o multiplier3.cmpc
```

| Flag | Description |
| --- | --- |
| `<CIRCUIT>` | Path to the circom main file to compile. |
| `-o, --output <FILE>` | Where to write the compiled program. Defaults to the circuit's file stem with a `.cmpc` extension, in the current directory. |
| `--config <TOML>` | TOML file deserialized into `CompilerConfig` (see `crates/circom-mpc-compiler/src/lib.rs`); the flags below are applied on top of it. |
| `-l, --link-library <DIR>` | Directory to resolve circom's `include`s against. Repeatable. |
| `--mpc-public-input <NAME>` | Input name every MPC party holds in cleartext, even though it is not SNARK-public. Repeatable. |
| `--opt <0\|1\|2>` | This crate's IR optimization level. Distinct from circom's own constraint simplification, which always runs at full `--O2`. |
| `--circom-version <VERSION>` | The circom pragma version to compile against. |
| `--inspect` | Runs an additional check over the produced constraints. |
| `--verbose` | Shows logs during compilation. |

Run with `--help` for the flags as parsed by the installed binary. Compilation logs (instruction,
input, witness, slot, round, and gadget statistics) go through `tracing`; set `RUST_LOG` to control
verbosity.

## Development

`circuits/` pulls its circom dependencies (`@taceo/circom-lib`, `circomlib`) via pnpm into a
gitignored `node_modules`; run `just circuits` (or `pnpm -C circuits install`) once before
`cargo test`.

```sh
just gen-proving-artifacts
just rust-tests
```

The small-circuit integration tests require their generated Groth16 keys and run complete
prove/verify checks; a missing key fails with the generation command above.
`scripts/gen-proving-artifacts.sh` needs a `circom` built from this repo's pinned upstream
revision (see `circom-compiler` in `Cargo.toml`) — point `CIRCOM` at it if it's not the one on
`PATH` — and `snarkjs` on `PATH`. It downloads and verifies the phase-2-ready power-14 Perpetual
Powers of Tau file into a unique temporary directory, then deletes it on every exit.

`just` alone lists all available recipes. The ones used in CI:

- `just lint` — `cargo +nightly fmt --all -- --check`, clippy (default and `--all-features`), and
  `cargo doc` with warnings denied. Requires a nightly toolchain for `fmt`.
- `just cargo-deny` — `cargo deny check`.
- `just rust-tests` — `cargo test --release --workspace --all-features` (runs `just circuits`
  first).
- `just check-pr` — all of the above, in order; run this before opening a PR.

## Security boundary and deferred hardening

The current deployment treats the circuit source, compiled VM program, and zkey as trusted,
authentic, mutually matching artifacts. MPC public inputs and every `TACEO_REVEAL` site are
likewise reviewed as part of that artifact set.

Future hardening should authenticate and bind the program, circuit, and zkey; encode an auditable
reveal manifest; and perform semantic bytecode validation (including initialization, unique input
bindings, and schedule consumption). Cleartext
checking of `assert(...)`, `===`, and Num2Bits range constraints is also deferred: MPC execution
cannot check secret predicates without changing the protocol or revealing information.

## License

This repository uses split licensing:

- `taceo-circom-mpc-compiler` and `circom-mpc-compiler-tests` are licensed under
  [GPL-3.0-only](LICENSE-GPL-3.0). The compiler links directly to Circom's GPL-licensed Rust
  packages, so the compiler library and `circom-mpc-compile` CLI must be distributed under
  GPL-compatible terms.
- `taceo-circom-mpc-program` and `taceo-circom-mpc-vm` are licensed under
  [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option. They do not link to Circom.
- Other repository-authored files are licensed under MIT or Apache-2.0 unless a file or directory
  states otherwise.

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for dependencies and adapted third-party
material. Merely using GPL-licensed build tools such as Circom or snarkjs does not by itself apply
their license to generated output; output that incorporates third-party source remains subject to
that source's license.
