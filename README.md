# circom-mpc-compiler

A Cargo workspace of four crates:

- `circom-mpc-program` — the compiled program representation (`Program`, `PrecomputeKind`) and its
  binary format (`Program::write`/`Program::read`). No dependency on the compiler or the VM.
- `circom-mpc-vm` — the bytecode VM (`Machine::run`), its plain and rep3 drivers, and
  `CountingNet`. Rep3 is always available; `mpc-net` backends are selected independently through
  the `local`, `quic`, `tcp`, `tcp-session`, `tcp-session-blocking`, and `tls` features.
- `circom-mpc-compiler` — parses circom source into the IR, lowers it through the MPC passes, and
  compiles it to a `circom-mpc-program::Program` (`CoCircomCompiler::compile`). It does not depend
  on the VM or a network backend.
- `circom-mpc-compiler-tests` — non-published integration tests, fixtures, benchmarks, and runnable
  Merces tools. Its default `local` feature keeps the complete in-process MPC suite in plain
  `cargo test`; other network backends remain opt-in.

## Security boundary and deferred hardening

The current deployment is focused on Merces and treats the circuit source, compiled VM program,
and zkey as trusted, authentic, mutually matching artifacts. MPC public inputs and every
`TACEO_REVEAL` site are likewise reviewed as part of that artifact set.

Future hardening should authenticate and bind the program, circuit, and zkey; store and check the
exact public-witness count; encode an auditable reveal manifest; and perform semantic bytecode
validation (including initialization, unique input bindings, and schedule consumption). Cleartext
checking of `assert(...)`, `===`, and Num2Bits range constraints is also deferred: MPC execution
cannot check secret predicates without changing the protocol or revealing information.

Compiles [circom](https://github.com/iden3/circom) circuits into a witness-extension procedure, then
runs that procedure for real: a plain (in-the-clear) reference interpreter, and a 3-party rep3 MPC
driver that produces a co-groth16 proof over the shared witness. It is not a proving-system compiler
itself — it does not generate R1CS or a proving key, only the witness those need.

Pipeline: circom source → circom's own parser/type-checker/constraint-generation (always at full
`--O2`) → per-template lowering with lazy sub-component inlining and eager loop unrolling → one flat
value-graph IR → MPC lowering and codegen → the plain interpreter or the rep3 driver.

The runtime operator surface is deliberately narrow — only `Add`/`Sub`/`Mul` are supported; every
other circom operator is a typed `unsupported operator: ...` error. The main target is the set of
merces circuits vendored under `circuits/merces/`: the two server mains compile, run under real
3-party rep3, and produce a co-groth16 proof against circom's own R1CS that verifies, against real
protocol inputs (`inputs/`).
`cargo run --release -p circom-mpc-compiler-tests --example merces` runs this end to end, including
the proof.

## Development

```
cargo test                              # prove/verify correctness tests (checked against circom itself)
cargo run --release -p circom-mpc-compiler-tests --example merces
                                        # full pipeline on a real production circuit, proof included
scripts/run-merces-net.sh --runs 5      # rep3 witness extension over a genuine 3-process TLS network
                                         # (needs configs/ + data/ supplied - see the script)
```
