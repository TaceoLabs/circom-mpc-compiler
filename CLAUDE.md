# Instructions for AI agents working in this repo

**Read `docs/ARCHITECTURE.md` before making any change to `src/ir.rs`, `src/frontend/`,
`src/passes/`, or `src/vm/`.** It records the IR's invariants, why the recursive inliner is structured
the way it is, which parts are known-gaps rather than bugs, and where the compiler is headed.
Re-derive as little of that as possible — it's already written down. In particular, several things
that look like obvious cleanups are load-bearing decisions with the reasoning recorded there
(precomputation staging, the single network-event axis, why share kind is an analysis and not a set of
`Op` variants).

When you land a change that matches one of the "Where this is headed" steps in that file, update
the step's status there too. When you find a new known gap or fix one, update the "Known gaps"
section. Treat that file as a decision record that should always reflect the current state of the
codebase, not a one-time writeup.

## Ground truth for correctness

`tests/circom_ir.rs` (plain) and `tests/rep3_vm.rs` (real 3-party rep3) compare this compiler's output
against circom's own golden witnesses (`kats/*/witness*.wtns`, generated independently of this repo).
Any change to the IR, frontend, passes, or VM must keep every test in those files passing — they are the
oracle, and they catch layout and scheduling mistakes that no unit test can.

`cargo test` is expected to be **fully green**. When adding support for a previously-unsupported
circuit, prefer wiring up one more `witness_extension_test_plain!(...)` line in `tests/circom_ir.rs`
over writing a new ad hoc test — the KAT fixture is very likely already sitting in `kats/`, since
`circuits/` and `kats/` still hold fixtures for everything not yet supported. `docs/ARCHITECTURE.md`'s
"Known gaps" is the worklist of what's missing, not the test suite's failure list.

Also check both feature configurations, since each drops real code paths:
`cargo test --no-default-features` (plain-only, no `mpc-core`) and `cargo test --features proving`.
