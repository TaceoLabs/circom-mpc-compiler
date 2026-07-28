# circom-mpc-compiler

Compiles [circom](https://github.com/iden3/circom) circuits into a witness-extension procedure. It
is not a proving-system compiler — it does not produce R1CS or a proof, only the witness (public and
secret) the proving system needs. This crate is the compiler plus a plain (in-the-clear) reference
interpreter; there is no MPC execution here (see `docs/ARCHITECTURE.md`, "Non-goals").

Pipeline: circom source → circom's own parser/type-checker/constraint-generation →
per-template lowering with lazy sub-component inlining and eager loop unrolling → one flat
value-graph IR → the plain interpreter.

The runtime operator surface is deliberately narrow — only `Add`/`Sub`/`Mul` are supported; every
other circom operator is a typed `unsupported operator: ...` error. `docs/ARCHITECTURE.md`'s "Known
gaps" section is the up-to-date list of what that means for which circuits, including a set of
real-world circuits vendored under `circuits/merces/` as a compile-checked (not witness-tested)
target for this compiler to grow into.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design: the IR's data model and
invariants, why it's shaped the way it is, known gaps, and the planned path to a configurable pass
pipeline and a bytecode VM.

## Development

```
cargo test                              # KAT-based correctness tests (compares against circom's own witnesses)
cargo run --bin run -- <circuit.circom> # compile a circuit and dump its graph
```
