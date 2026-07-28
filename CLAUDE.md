# Instructions for AI agents working in this repo

**Read `docs/ARCHITECTURE.md` before making any change to `src/ir.rs`, `src/frontend/`,
`src/passes/`, `src/mpc_ir/`, `src/interpreter.rs`, or `src/mpc_interpreter.rs`.** It records the
IR's invariants, why the recursive inliner is structured the way it is, which parts are known-gaps
rather than bugs, and where the compiler is headed (pass infrastructure, bytecode VM, rep3-specific
optimizations). Re-derive as little of that as possible — it's already written down.

When you land a change that matches one of the "Where this is headed" steps in that file, update
the step's status there too. When you find a new known gap or fix one, update the "Known gaps"
section. Treat that file as a decision record that should always reflect the current state of the
codebase, not a one-time writeup.

## Ground truth for correctness

`tests/circom_ir.rs` and `tests/mpc_ir.rs` compare this compiler's output against circom's own
golden witnesses (`kats/*/witness*.wtns`, generated independently of this repo). Any change to the
IR, frontend, or passes must keep every currently-enabled test in those files passing. When adding
support for a previously-unsupported circuit, prefer re-enabling one of the commented-out
`witness_extension_test_plain!(...)` lines in `tests/circom_ir.rs` over writing a new ad hoc test —
the KAT fixture is very likely already there in `kats/`.
