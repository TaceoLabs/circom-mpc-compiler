# circom-mpc-compiler

[![CI](https://github.com/TaceoLabs/circom-mpc-compiler/actions/workflows/ci.yml/badge.svg)](https://github.com/TaceoLabs/circom-mpc-compiler/actions/workflows/ci.yml)
[![Audit Dependencies](https://github.com/TaceoLabs/circom-mpc-compiler/actions/workflows/audit.yml/badge.svg)](https://github.com/TaceoLabs/circom-mpc-compiler/actions/workflows/audit.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0%20%7C%20GPL--3.0-blue)](#license)
[![rustc](https://img.shields.io/badge/rustc-1.90%2B-blue)](Cargo.toml)

Compiles [circom](https://github.com/iden3/circom) circuits into a witness-extension program, then
runs it either in the clear (plain reference interpreter) or under a 3-party rep3 MPC driver that
produces a co-groth16 proof over the shared witness. It generates the witness only, not R1CS or a
proving key.

```text
circom source → circom parser/type-checker/constraints (always --O2)
              → per-template lowering (lazy sub-component inlining, eager loop unrolling)
              → flat value-graph IR → MPC lowering + codegen
              → plain interpreter | rep3 driver
```

Only `Add`, `Sub` and `Mul` are supported at runtime. Any other circom operator fails with an
`unsupported operator: ...` error.

## Crates

| Crate | Path | Purpose |
| --- | --- | --- |
| `taceo-circom-mpc-program` | `crates/circom-mpc-program` | Compiled program representation (`Program`, `GadgetKind`) and its binary format. No dependency on the compiler or VM. |
| `taceo-circom-mpc-vm` | `crates/circom-mpc-vm` | Bytecode VM (`Vm::run`), plain and rep3 drivers, `CountingNet`. Rep3 is always available; `mpc-net` backends are opt-in via the `local`, `quic`, `tcp`, `tcp-session`, `tcp-session-blocking` and `tls` features. |
| `taceo-circom-mpc-compiler` | `crates/circom-mpc-compiler` | Circom source to `Program` (`circom_mpc_compiler::compile`). No dependency on the VM or a network backend. |
| `circom-mpc-compiler-tests` | `crates/circom-mpc-compiler-tests` | Unpublished integration tests and fixtures. The default `local` feature runs the full in-process MPC suite under plain `cargo test`. |

## CLI

The `cli` feature of `taceo-circom-mpc-compiler` builds `circom-mpc-compile`, which compiles a circom
file into a `Program` file.

```sh
# install from a checkout
cargo install --path crates/circom-mpc-compiler --features cli
# or from GitHub
cargo install --git https://github.com/TaceoLabs/circom-mpc-compiler --features cli taceo-circom-mpc-compiler
# or run in place
cargo run --release -p taceo-circom-mpc-compiler --features cli -- <args...>
```

```sh
circom-mpc-compile circuits/multiplier3.circom -l circuits/node_modules/ --opt 2 -o multiplier3.cmpc
```

| Flag | Description |
| --- | --- |
| `<CIRCUIT>` | Circom main file to compile. |
| `-o, --output <FILE>` | Output path. Defaults to `<circuit stem>.cmpc` in the current directory. |
| `--config <TOML>` | TOML file deserialized into `CompilerConfig` (`crates/circom-mpc-compiler/src/lib.rs`). Other flags override it. |
| `-l, --link-library <DIR>` | Directory to resolve circom `include`s against. Repeatable. |
| `--mpc-public-input <NAME>` | Input every MPC party holds in cleartext though it is not SNARK-public. Repeatable. |
| `--opt <0\|1\|2>` | IR optimization level. Separate from circom's constraint simplification, which always runs at `--O2`. |
| `--circom-version <VERSION>` | Circom pragma version to compile against. |
| `--inspect` | Run an additional check over the produced constraints. |
| `--verbose` | Show logs during compilation. |

Compilation statistics (instructions, inputs, witness, slots, rounds, gadgets) are logged via
`tracing`; set `RUST_LOG` to control verbosity. See `--help` for the authoritative flag list.

## Development

1. `just circuits` (or `pnpm -C circuits install`): fetches circom dependencies (`@taceo/circom-lib`,
   `circomlib`) into the gitignored `circuits/node_modules`.
2. `just gen-proving-artifacts`: generates the Groth16 keys the small-circuit integration tests
   need. A missing key fails the test with this command.
3. `just rust-tests`

`gen-proving-artifacts` requires:

- `circom` built from this repo's pinned upstream revision (see `circom-compiler` in `Cargo.toml`).
  Set `CIRCOM` if it is not the one on `PATH`.
- `snarkjs` on `PATH`.

It downloads and verifies the power-14 Perpetual Powers of Tau file into a temporary directory and
deletes it on exit.

Run `just` to list all recipes. Those used in CI:

| Recipe | Runs |
| --- | --- |
| `just lint` | `cargo +nightly fmt --all -- --check`, clippy (default and `--all-features`), `cargo doc` with warnings denied. Needs a nightly toolchain. |
| `just cargo-deny` | `cargo deny check` |
| `just rust-tests` | `cargo test --release --workspace --all-features` (after `just circuits`) |
| `just check-pr` | All of the above. Run before opening a PR. |

## Security model

**Trusted inputs.** The circuit source, compiled VM program and zkey are assumed authentic and
mutually matching. MPC public inputs and every `TACEO_REVEAL` site are reviewed as part of that set.

**Not yet implemented.**

- Authenticating and binding the program, circuit and zkey.
- An auditable reveal manifest.
- Semantic bytecode validation (initialization, unique input bindings, schedule consumption).
- Cleartext checking of `assert(...)`, `===` and Num2Bits range constraints. MPC execution cannot
  check secret predicates without changing the protocol or revealing information.

## License

Split licensing:

- `taceo-circom-mpc-compiler` and `circom-mpc-compiler-tests`: [GPL-3.0-only](LICENSE-GPL-3.0). The
  compiler links Circom's GPL-licensed Rust packages, so the library and CLI must be distributed
  under GPL-compatible terms.
- `taceo-circom-mpc-program` and `taceo-circom-mpc-vm`: [MIT](LICENSE-MIT) or
  [Apache-2.0](LICENSE-APACHE), at your option. They do not link to Circom.
- Other repository-authored files: MIT or Apache-2.0 unless a file or directory says otherwise.

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for dependencies and adapted third-party
material. Using GPL build tools such as Circom or snarkjs does not by itself apply their license to
generated output; output that incorporates third-party source stays under that source's license.
