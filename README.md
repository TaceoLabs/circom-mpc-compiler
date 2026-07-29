# circom-mpc-compiler

Compiles [circom](https://github.com/iden3/circom) circuits into a witness-extension procedure, then
runs that procedure for real: a plain (in-the-clear) reference interpreter, and a 3-party rep3 MPC
driver that produces a co-groth16 proof over the shared witness. It is not a proving-system compiler
itself — it does not generate R1CS or a proving key, only the witness those need.

Pipeline: circom source → circom's own parser/type-checker/constraint-generation (always at full
`--O2`) → per-template lowering with lazy sub-component inlining and eager loop unrolling → one flat
value-graph IR → MPC lowering and codegen → the plain interpreter or the rep3 driver.

The runtime operator surface is deliberately narrow — only `Add`/`Sub`/`Mul` are supported; every
other circom operator is a typed `unsupported operator: ...` error. `docs/ARCHITECTURE.md`'s "Known
gaps" section is the up-to-date list of what that means for which circuits, including a set of
real-world circuits vendored under `circuits/merces/` — the two server mains compile, run under real
3-party rep3, and their witness matches circom's own byte for byte against real protocol inputs
(`inputs/`), with a co-groth16 proof that verifies (see "Real-world target circuits" in the
architecture doc). `cargo run --release --example merces` runs this end to end, including the proof.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design: the IR's data model and
invariants, why it's shaped the way it is, known gaps, and the planned path to a configurable pass
pipeline and a bytecode VM.

## Development

```
cargo test                              # KAT + prove/verify correctness tests (checked against circom itself)
cargo run --bin run -- <circuit.circom> # compile a circuit and dump its graph
cargo run --release --example merces    # full pipeline on a real production circuit, proof included
```
