# Architecture

This is a decision record, not a tutorial. It exists so a future contributor (human or model)
can reload the reasoning behind the current shape of the compiler without re-deriving it. Update
this file whenever a decision recorded here changes, or a new step from the plan below lands.

## What this compiler does

Compiles a circom circuit down to a witness-extension procedure that can run either in the clear
or under the rep3 replicated-secret-sharing MPC protocol. It does **not** produce R1CS or a proof;
that stays in circom / co-snarks. This repo is specifically the "witness extension" compiler:
circom source in, a procedure that computes the full witness (public and secret) out.

## Pipeline

```
circom source
  -> circom's own parser + type checker + constraint generation + simplification   (frontend/mod.rs, upstream circom crates)
  -> per-template lowering to TemplateGraph, recursing into subcomponents lazily    (frontend/build.rs)
     (unless TACEO_PRECOMPUTATION_*-wrapped - see "Precomputation"), unrolling
     loops eagerly, folding removed operators at compile time                      (frontend/unroll.rs, frontend/fold.rs)
  -> recursive inlining: flatten the TemplateGraph tree into one ir::Graph          (frontend/inline.rs)
  -> ir::Graph::verify(), then PassManager::for_opt_level(config.opt_level).run()   (ir.rs, passes/, called from lib.rs)
  -> interpreter (debug/reference, the only execution path in this crate)          (interpreter.rs)
```

`CoCircomCompiler::<P>::parse(file, config)` in `lib.rs` runs everything up to and including the
`PassManager`, and returns the `ir::Graph`. The plain `Interpreter` is the only consumer in this
crate - MPC execution (rep3, the plaintext stand-in `PlainExecutor`, the `mpc_ir` share-kind
translation pass) was deleted; see "Non-goals" below for why and where to find it again.

## The IR (`src/ir.rs`)

### The core idea: a node's index is its value

```rust
pub struct ValueId(u32);          // ValueId(i) == graph.nodes[i]
pub struct Node<F> { pub op: Op<F>, pub inputs: Vec<ValueId> }
pub struct Graph<F> {
    nodes: Vec<Node<F>>,
    outputs: Vec<(SignalIdx, ValueId)>,
    // + signal_to_witness, input_list, public_inputs, num_inputs, num_outputs, num_signals
}
```

There is **no separate wire/address space**. Every node produces exactly one value, and that
value's identity is the node's position in `nodes`. This replaced a model where every node
additionally allocated one or more `Wire = usize` indices into a side array (bump-allocated,
independent of node position), which required three passes just to keep that side array dense and
alias-free after rewrites (`dead_code`, `load_elimination`, `reduce_wire_indices` — all deleted, see
"What this replaced" below).

### Invariants (checked by `Graph::verify`)

- **Topological order.** `node.inputs[i].index() < node`'s own index, always. No node may
  reference a value defined later. This is what makes `gc` a single reverse sweep instead of a
  fixpoint, and what will make a future depth/liveness analysis a single forward/backward pass.
- **Arity matches the op.** `Op::arity()` is the single source of truth for how many inputs each
  op takes; `Node::new` asserts it in debug builds, `Graph::verify` checks it always.
- **Single result per node.** No multi-output ops. If MPC codegen (later) needs multiple related
  outputs from one physical operation, model it as multiple nodes sharing a common predecessor.

### `Op<F>` is deliberately narrow: only `Add`/`Sub`/`Mul` are runtime ops

`Op` has exactly five variants: `Input`, `Constant`, `Add`, `Sub`, `Mul`. Everything else circom can
express at the signal level - `Div`, `IntDiv`, `Pow`, `ShiftL`/`ShiftR`, `BitOr`/`BitAnd`/`BitXor`,
comparisons, booleans, `Mod` - is rejected with a typed `Unsupported` error
(`frontend/error.rs`) naming the exact operator, template, and line, rather than modeled as an IR
op. `frontend/build.rs::handle_compute_bucket` is the single dispatch point: `Add`/`Sub`/`Mul` push
a node directly; the eight operators above try `frontend/fold.rs::fold_binary` first (see "Where
compile-time folding lives" below) and only error if that fails; everything else is an immediate
`Unsupported::Operator`.

This exists to keep the compiler's runtime core - and the pass infrastructure and bytecode codegen
being built on top of it - small enough to reason about exhaustively before growing back out. It
also happens to retire the MPC-specific reason this enum used to be kept generic (share-kind
specialization deferred to a later analysis pass, so every IR-level pass wasn't written 9× per
binary op) - that reasoning no longer applies since there is no MPC path in this crate at all (see
"Non-goals"). If/when the operator surface grows back, keep specializing at bytecode codegen time
rather than in this enum, for the same "write every pass once" reason.

### Where compile-time folding lives

Losing `ShiftR`/`BitAnd` etc. as runtime ops would have silently regressed `constants_test` (which
only reaches them via a fully compile-time-constant table lookup, not a genuine circuit input) if
nothing replaced them. `frontend/fold.rs::fold_binary` evaluates the eight removed operators when
both operands are already `Op::Constant`, using the exact same arithmetic the old interpreter used
to apply at runtime (lifted verbatim, not reimplemented, so `constants_test`'s witness doesn't
silently change). This is deliberately narrow - it does not fold `Add`/`Sub`/`Mul` (that's a
separate, larger, semantics-preserving optimization that belongs under `passes/` once that
infrastructure exists, not bundled into this correctness fix) and it only fires inside
`handle_compute_bucket`, before a node is ever pushed - it is not a graph-rewrite pass.

A second, narrower compile-time evaluator exists for a different purpose:
`GraphCompiler::eval_constant_node` (`frontend/build.rs`) recursively folds `Add`/`Sub`/`Mul` chains
of already-resolved `Op::Constant` values, but *only* when resolving an array/signal/component
*address* (inside `get_constant_value`). This is what lets circom's own address-computation
idioms - reverse indexing (`arr[N-1-i]`), modular indexing (`arr[i % n]`), and an internal
loop-shadow-counter pattern circom sometimes emits alongside the canonical induction variable (see
"Known gaps" for how that was found) - resolve as the compile-time constants they actually are,
without turning into a general constant-folding pass over the graph.

### `Op::Load`, `Op::LoadSubCmp`, `Op::StoreSubCmp` do not exist

In the old model these were real ops: `Load` was an identity copy (a variable read that allocated
a fresh wire pointing at an existing one), and `LoadSubCmp`/`StoreSubCmp` were placeholders for a
subcomponent's input/output ports, resolved by a later pass that chased through the placeholder
chain and deleted them (`load_elimination`).

In the value-graph model these are pure aliasing and don't need a node at all:
- **Variable reads** are a `HashMap` lookup (`var_to_value` in `frontend/build.rs`) — the read
  returns the `ValueId` that was last stored, no new node.
- **Subcomponent ports** are resolved once, at inlining time, by `frontend/inline.rs` (see below) —
  no placeholder is ever materialized, so there is nothing to chase or delete afterward.

## Frontend (`src/frontend/`)

`build.rs` walks one template's circom bucket instructions (`Instruction::{Value,Load,Store,
Compute,...}`) and produces a `TemplateGraph` — a **not-yet-inlined** per-template graph. The
biggest structural change from the old `GraphCompiler`: `handle_inst` and its callees **return**
the `ValueId` an instruction produces, instead of pushing a node and having the caller peek at
"whatever was pushed most recently" (the old code's `peek_wire()` convention). Returning values
directly is what let `Op::Load` disappear — a variable read just returns the stored `ValueId`,
no node needed.

A `TemplateGraph` node's op is `TemplateOp`, a superset of `ir::Op` with four placeholder variants
that only make sense before inlining:

- `LocalSignal(usize)` / `LocalSignalWrite(usize)` — this template's own input or output signal, by
  local (pre-offset) index. Whether a read becomes a genuine external input (main) or an alias for
  a caller-provided value (nested) is decided during inlining.
- `SubCmpInput { sub_cmp, port }` / `SubCmpOutput { sub_cmp, port }` — a port of a *local*
  subcomponent instance, addressed by that instance's index within this template.

`unroll.rs` fully unrolls circom loops with a statically known trip count, during this same
per-template pass (not a separate graph-level pass — see "Non-goals" below for why).

### Inlining (`frontend/inline.rs`)

`inline_template` recursively flattens the `TemplateGraph` tree (main, plus every subcomponent it
instantiates, transitively) into one `ir::Graph`. It replaces `CircomAST::inline_subgraph` from the
old `circom_ir/types.rs`.

The old version shifted raw `Wire` numbers by a running `outer_offset` as subgraphs were spliced
into a shared flat array, with a placeholder `Op::Load` node standing in for every cross-template
reference until `load_elimination` chased through it later. That two-phase approach (materialize a
placeholder now, resolve it in a separate pass later) is unnecessary once there's no placeholder
op to materialize in the first place: this version resolves every cross-template reference
*at inlining time*, via a handful of maps that carry already-resolved `ValueId`s across the
recursion:

- `sub_cmp_inputs[instance][port]` — the value stored into a subcomponent instance's input port,
  filled in as `SubCmpInput` nodes are processed at the *caller's* level.
- the returned `port_outputs` map — which value a subcomponent's output port resolves to, handed
  back to the caller so a `SubCmpOutput` reference can resolve it.
- `local_writes[signal]` — this template's own signal writes, so a template can read back a signal
  it just wrote (its own output, or any intermediate signal) without re-deriving anything.
- `local_remap[local_node_index]` — the resolved outer `ValueId` for each of this template's own
  nodes, so `Real` ops can translate their locally-indexed inputs into globally-valid ones.

**A correctness improvement found during the port:** the old code only resolved "read my own
already-written signal" correctly for `main`, because its flat node list happened to interleave
writes before reads at runtime by construction. A *nested* subcomponent reading back its own output
signal would panic in the old code (`input_mapping` only ever held entries for input ports, not a
subcomponent's own output writes). This version checks `local_writes` first, uniformly, regardless
of nesting level, so both cases work the same way. This was verified by re-enabling `mux1_1`,
`binsum_test`, `binsub_test`, `lessthan`, `sum_test`, and `constants_test` in `tests/circom_ir.rs`
— all exercise real sub-component nesting and were never runnable before (they were commented out).

**A second correctness gap found and fixed while adding precomputation support:** a subcomponent
whose outputs are never read via `SubCmpOutput` was never inlined at all — nothing in
`inline_template` visited it unless some `SubCmpOutput` reference forced it, so none of its signals
ever reached `outputs`, silently leaving them `0` in the witness. This blocks any subcomponent that
declares no outputs (`TACEO_PRECOMPUTATION_AliasCheck` is exactly this shape) but is otherwise
latent for any pure-constraint subcomponent. Fixed by a trailing pass at the end of
`inline_template`: after the main node loop, every `sub_graphs` entry still `Some` (i.e. never
claimed by the `SubCmpOutput` arm) is inlined anyway. This is topologically sound because every such
subcomponent's inputs were necessarily already resolved earlier in the same loop (by the
`SubCmpInput` arm) - nothing about *reading* its outputs was required to *write* its inputs.

## Pass infrastructure (`src/passes/`)

A `Pass` trait (`fn run(&mut self, graph: &mut Graph<F>, ctx: &mut PassContext) -> Result<Changed>`)
plus a `PassManager` that runs a fixed pass list to a fixpoint (bounded by `max_iterations`),
re-verifying the graph after every pass in debug builds. `OptLevel` (`CompilerConfig::opt_level`)
selects the pass list - `O0` is dead code elimination only, `O1` (default) adds constant folding,
`O2` is reserved for CSE/GVN and the rep3-specific passes from the roadmap below. This is
deliberately a separate knob from `SimplificationLevel`, which configures upstream circom
constraint simplification, not this crate's own IR passes.

The piece that makes a `Pass` cheap to write correctly is `Graph::rewrite` (`src/ir.rs`): it walks
the old node list in original order, handing each pass's callback the node with its inputs already
remapped to new-space `ValueId`s, plus every node already emitted so far (so a pass can inspect an
input's *producer* - e.g. "is this a constant?" - by indexing into it). The callback returns
`Keep`, `ReplaceWith(other_value)` (alias, no node emitted), or `Emit(different_node)`; `rewrite`
owns the old-to-new remap and fixes up `outputs`, so a pass can never accidentally produce a forward
reference - the exact bug class that would otherwise be easy to introduce in this IR, since a
node's `ValueId` doubles as its position and deleting or replacing any node shifts every later
reference. `Graph::gc` (dead code elimination) predates `rewrite` and keeps its own hand-written
reverse-liveness sweep instead - it's a liveness walk, not a node-for-node rewrite, so the same
abstraction doesn't fit it - but its remap type is shared.

`passes/dead_code.rs` is a thin `Pass` wrapper over `Graph::gc`. `passes/const_fold.rs` is the first
real `Graph::rewrite` consumer: it folds `Add`/`Sub`/`Mul` when both operands are already
`Op::Constant`, plus the identity/annihilator cases (`x+0`/`x-0`/`x*1` alias to `x`; `x*0` folds to
`0`). This is a different, broader fold from the two pre-existing ones and doesn't replace either:
`frontend/fold.rs::fold_binary` folds the *removed* operators (`Div`, `ShiftR`, ...) at lowering
time, before a node ever exists, and `GraphCompiler::eval_constant_node` only folds in
array/signal/component *address* position. Both predate the pass infrastructure and still exist for
the reasons documented under "Where compile-time folding lives" above; `const_fold` is the first
pass that folds `Add`/`Sub`/`Mul` themselves, anywhere in the graph.

`Op::is_pure` (`false` only for `Op::Precompute`/`Op::PrecomputeResult`) is added alongside the
precomputation ops it protects, not consulted by anything yet - it's the signal a future CSE/GVN
pass needs to avoid merging two precomputation sites, since that would change how many traces the
runtime has to supply.

## Precomputation (`TACEO_PRECOMPUTATION_*`)

Circuits can wrap a gadget in a template named `TACEO_PRECOMPUTATION_<Name>` (see
`circuits/libs/taceo/precomputations.circom` for the four merces uses: `Poseidon2`, `Num2Bits`,
`IsZero`, `AliasCheck`) to mark it as a site the *runtime* computes out-of-band and injects, rather
than something this compiler has to execute. The co-snarks MPC witness-extension VM already
special-cases this convention (`circom-mpc-vm/src/mpc_vm.rs`: once a component whose name starts
with `TACEO_PRECOMPUTATION` has all its inputs bound, its wrapped component's body is never run -
an externally-supplied `ComponentAcceleratorOutput` trace is written into the signal array
instead), and merces computes those traces up front in one batched MPC pass specifically so witness
extension doesn't pay a network round per Poseidon2 call. Making this a first-class IR primitive
here does more than mirror that: it cuts a subtree this compiler cannot compile at all -
`poseidon2_constants.circom`'s round-constant-table functions (`Instruction::Call`), `IsZero`'s
field inversion (`Div`), and `Num2Bits`' bit extraction (`ShiftR`/`BitAnd`) are all *inside* wrapped
components, so cutting the subtree makes them irrelevant rather than blocking, without implementing
function calls or re-adding removed operators.

### The contract, kept byte-compatible with the co-snarks VM

The site is the wrapped *inner* component (e.g. `Poseidon2`), not the wrapper
(`TACEO_PRECOMPUTATION_Poseidon2`) - matching exactly what the VM cuts. For an inner instance at
signal offset `o` with `num_inputs`/`num_outputs`/`num_intermediates` (its own local signals plus
every signal in everything it in turn instantiates - see below), circom's layout is `[outputs at
o][inputs at o+num_outputs][intermediates + subtree at o+num_outputs+num_inputs]`, and a runtime
trace's result slots map onto it as:

- inputs are bound normally by the wrapper, like any subcomponent's;
- slots `0..num_outputs` → signals `o..o+num_outputs`;
- slots `num_outputs..` → signals `o+num_outputs+num_inputs..`, i.e. every remaining signal in the
  inner component's subtree, in flat order.

Sites are numbered in the order encountered during inlining (deterministic single-threaded
traversal) - that order *is* the trace order the runtime must supply results in.

### IR shape (`src/ir.rs`)

`Op::Precompute(PrecomputeId)` takes the site's input values as its node inputs (arity equals the
site's `num_inputs` - the one case `Op::arity()` can't answer without the site table, hence
`Arity::{Fixed, SiteInputs}` and why `Graph::verify`, not `Node::new`, checks it). One
`Op::PrecomputeResult(slot)` node per result slot hangs off the `Precompute` node as its sole input,
matching this IR's "single result per node" invariant the same way `docs/ARCHITECTURE.md`
prescribes for any future multi-output op. `Graph::precompute_sites: Vec<PrecomputeSite>` is the
side table `PrecomputeId` indexes into. `Graph::gc` treats every `Op::Precompute` node as an
unconditional root: every result slot is already bound to a witness signal (so it's normally kept
anyway), but this is deliberate defense in depth - the runtime supplies traces positionally, so
silently dropping a "dead" site would desynchronize every later site's trace.

### Frontend (`frontend/build.rs`, `frontend/inline.rs`)

The prefix marks the *wrapper* template, not the component a `CreateCmpBucket` instantiates - each
wrapper's body is exactly one line (`out <== Gadget(...)(in);`), so `GraphCompiler::
handle_create_cmp_bucket` checks `self.code.name` (the template currently being compiled) against
the prefix, not the newly-instantiated symbol's name. When it matches (and
`CompilerConfig::precomputation` is `Extract`, the default), the wrapped component's body is never
compiled: its `TemplateCodeInfo` is only *peeked* (never removed from the shared `templates` map,
unlike a normally-compiled template - a precomputed template is never inserted into
`compiled_graphs` either, precisely so every repeated instantiation keeps going through this same
peek instead of the removed-on-first-compile path) for its `name`/`header`/`number_of_inputs`/
`number_of_outputs`, and a `SubGraphInstance::Precomputed` is pushed instead of a compiled one.
`frontend/inline.rs::inline_precomputed` then does the three things "IR shape" above describes.
`PrecomputationMode::Inline` (config knob, default `Extract`) disables all of this, compiling the
wrapped body like any other template - useful for plaintext comparison, and expected to fail with
the same typed errors the gadget would hit unwrapped.

One indexing subtlety worth recording: `TemplateOp::SubCmpInput`/`SubCmpOutput`'s `port` is the
wrapped component's own *local signal index*, which - like every template - numbers outputs first,
then inputs (matching `TemplateOp::LocalSignal`/`LocalSignalWrite`). So input `k` of the site lives
at local signal `num_outputs + k`, not at `k` directly; only the output side is directly `0..
num_outputs`. This is easy to get backwards (it was, once, while landing this) since the two look
symmetric until you check where the actual bucket-level indices land.

### The signal-span problem (`frontend/mod.rs::compute_signal_spans`)

`num_intermediates` (the wrapped component's own locally-declared signals *plus* every signal
belonging to everything it transitively instantiates) is the one quantity not sitting in a
directly-usable field anywhere reachable from this crate. circom itself computes exactly this
(`constraint_generation::execution_data::executed_program::produce_dags_stats`, over its internal
`DAG`), but `circom_constraint_generation::build_circuit`'s public return type only exposes a
`Box<dyn ConstraintExporter>` (an `r1cs`/`sym`/`json` file-writer trait object, no structural
accessors) - the DAG itself never crosses the public API. `compute_signal_spans` recomputes the
same recursive sum from `VCP::templates` instead (public, and already relied on by
`get_output_mapping` above): each `TemplateInstance` already carries its own direct signal counts
and a `triggers` list naming every subcomponent it instantiates by `template_id` (an index into
that same `templates` list), so `span(id) = own(inputs+outputs+intermediates) + Σ span(child)`
falls out directly, just sourced from a different (but equivalent) part of circom's output. Keyed
by `template_header`, which is identical to the bucket-level `TemplateCodeInfo::header` the
`templates` map itself is keyed by (both trace back to the same `TemplateInstance.template_header`
- confirmed by reading `circuit_design::build.rs`, not assumed). Cross-checked in
`tests/precomputation.rs::signal_span_matches_independent_total` against
`circuit.c_producer.total_number_of_signals` (an independent computation, from a different part of
the circom crate) for all four vendored precomputation-wrapper circuits.

## Known gaps

- **Only `Add`/`Sub`/`Mul` are supported at runtime.** Every other circom operator is a typed
  `Unsupported::Operator`/`NonConstantOperator` error (see "`Op<F>` is deliberately narrow" above).
  This is a large, deliberate step back in coverage, made to keep the runtime core small while pass
  infrastructure and bytecode codegen are built. Of the 12 tests that were passing before this cut,
  7 survive (`multiplier2`, `multiplier3`, `multiplier16`, `loop_unrolling`, `dead_code`,
  `multiplier2_public`, `constants_test`); `mux1_1`, `binsum_test`, `binsub_test`, `lessthan`,
  `sum_test` regress, because they all reach `Num2Bits`/`BinSum`/`BinSub`'s
  `(in >> i) & 1`-style bit extraction on a genuine circuit input, which no amount of compile-time
  folding can save. All are still wired up in `tests/circom_ir.rs`, deliberately red, alongside every
  previously-commented-out fixture (69 total) - the failure list is the visible worklist. Re-adding
  `Div`/`IntDiv`/`Pow`/`ShiftL`/`ShiftR`/`BitOr`/`BitAnd`/`BitXor` as real ops is the most-requested
  next step for this KAT worklist; see "Real-world target circuits" below for why the merces
  circuits themselves no longer block on this (`CompilerConfig::precomputation` routes around it
  for every wrapped gadget call).
- **The two-level-subcomponent-nesting wrong-witness gap is currently masked, not fixed.**
  `greaterthan`, `greatereqthan`, `lesseqthan`, `mux2_1`, `mux3_1`, `mux4_1` used to compile and run
  to a wrong witness (nesting a subcomponent inside another nested subcomponent, e.g.
  `GreaterThan -> LessThan -> Num2Bits`); they now fail earlier, on `Num2Bits`'s `BITAND`, before
  ever reaching whatever produced the wrong witness. **This is very likely the same underlying bug
  as the whole-array-copy bug fixed below** (both are about multi-signal data crossing a
  subcomponent boundary) - re-test these six once shift/bitand return, before assuming the nesting
  bug is still open.
- **Two frontend bugs found and fixed while porting real-world circuits (see below):**
  - `handle_store_bucket`/`handle_load_bucket` used to ignore `StoreBucket`/`LoadBucket`'s
    `context.size` entirely and always transfer exactly one scalar. A whole-array copy into a
    subcomponent's input port (`inner.in <== a;`, or any anonymous-component call with an array
    argument - circom desugars both the same way) silently wrote only the first element, surfacing
    later as `inline.rs`'s "subcomponent input signal read before it was provided" panic. Fixed:
    `handle_store_bucket` now branches on `context.size` and does `size` element-wise
    reads/writes at consecutive addresses (`GraphCompiler::{read,write}_value_at`,
    `handle_bulk_store_bucket`) when it's greater than one. `SizeOption::Multiple` (a bulk copy
    spanning more than one component instance) is deliberately still an error, not silently
    mishandled - not needed by any circuit exercised so far.
  - `get_constant_value` (used for array/signal/component address computation, not signal values)
    only recognized the dedicated `MulAddress`/`AddAddress`/`ToAddress` operators plus a directly-
    resolved `Op::Constant`. Two related gaps surfaced through real circuits: (a) circom sometimes
    routes address arithmetic through the *plain* `Add`/`Sub`/`Mod` operators instead of the
    dedicated `*Address` ones - e.g. reverse indexing (`arr[N-1-i]`) and modular round-table
    indexing (`arr[i % n]`) - now handled by dedicated arms alongside the `*Address` ones; (b) a
    variable holding a value built via `var = var + 1` (observed as a circom-internal loop-shadow
    counter kept in lockstep with, but stored separately from, the loop's own induction variable -
    the latter is canonicalized to a fresh `Op::Constant` every iteration by
    `unroll.rs::add_induction_variable_node`, the former isn't) resolved to a genuine `Op::Add` node
    rather than a constant, and correctly *is* one at every iteration - `get_constant_value` just
    never tried to evaluate it. Fixed by `GraphCompiler::eval_constant_node` (see "Where
    compile-time folding lives" above). Confirmed by direct probing: this unblocked
    `ExternalMatMulT`/`Sbox`/`FullRound`/`PartialRound` (from `@taceo/circom-lib`'s Poseidon2) and
    both merces server-side mains, which now fail only on the function-call gap below.
- `Instruction::Call`/`Branch`/`Return` (unconstrained functions, `if`/`else` on a non-constant
  condition) remain entirely unimplemented - each is a clean `Unsupported::Instruction` error naming
  the call/branch and line, not a panic. This is why `poseidon_hasher1.circom` (calls a helper
  function) doesn't compile, and - now that `CompilerConfig::precomputation` (see "Precomputation"
  above) cuts every wrapped Poseidon2 call before it reaches `poseidon2_constants.circom`'s
  constant-table functions - why `IsEqual`'s bare, unwrapped `IsZero` call blocks all three merces
  circuits on `Instruction::Branch` instead; see "Real-world target circuits" below.

## Real-world target circuits

`circuits/merces/` vendors three production circuits from `~/repos/merces/circom`
(`transfer_arity4_batch1`, `transfer_arity4_batch8`, `transfer_client_compressed` - a Poseidon2/
BabyJubJub-based private-transfer system) plus the six `@taceo/circom-lib` files and ten circomlib
files they transitively need (`circuits/libs/taceo/`, `circuits/libs/`). They exist purely as a
compile-checked target for this compiler to grow into - `tests/merces.rs` asserts each one is
either a typed `Unsupported` error or a genuine pass, never a panic. **There is no witness oracle
for them** (unlike `kats/`, which holds circom's own golden witnesses); do not add witness
comparison here without also adding real golden witnesses.

As of this writing all three fail with `unsupported instruction: branch (if/else on a non-constant
condition)` inside `IsZero` (`circuits/libs/comparators.circom`, the `Instruction::Branch` gap
above) - reached through `IsEqual`'s bare, unwrapped use of it inside
`merces/dependencies/merkle_root_4.circom`'s depth-selection logic (`IsEqual()([depth, i])`, used to
pick which Merkle level's root is the real one). This is a different, and much later, blocker than
before `CompilerConfig::precomputation` (default `Extract`, see "Precomputation" above) existed:
every `TACEO_PRECOMPUTATION_*`-wrapped call - which is most of what these circuits do, since Poseidon2
hashing runs early and pervasively (every commitment goes through it) - is cut into a precomputation
site instead of compiled, so `poseidon2_constants.circom`'s constant-table functions (the
`Instruction::Call` gap) are never reached at all. What's left is `IsZero` used *unwrapped* - not
every use of a gadget in these circuits goes through its `TACEO_PRECOMPUTATION_*` wrapper, only the
ones the circuit author routed through one.

All three project-level circuits use only `Add`/`Sub`/`Mul` on signals - confirmed by direct
inspection, zero occurrences of any other signal-level operator anywhere in `merces/`,
`oblivious_vector/`, `main/`. The two circomlib gadgets that reach a runtime-non-linear operator -
`circuits/libs/comparators.circom`'s `1/in` (field inversion, `Div`) inside `IsZero`, and
`circuits/libs/bitify.circom`'s `(in >> i) & 1` (`ShiftR`, `BitAnd`) inside `Num2Bits` - are both
reached exclusively through their `TACEO_PRECOMPUTATION_*` wrapper *except* for `IsEqual`'s bare
`IsZero` call above, confirmed by direct inspection of every remaining `IsZero`/`Num2Bits` call site
in the transitive closure. So re-adding those two operators is no longer what's needed to get past
this blocker - either wrapping this specific `IsEqual` call too (a circuit-side change, outside this
repo), or implementing `Instruction::Branch` (this repo's own gap) would.

## Why `rustc-hash` instead of `intmap`/`std::collections::HashMap`

`FxHashMap`/`FxHashSet` (from the `rustc-hash` crate) replaced both `intmap::IntMap` and
`std::collections::HashMap` everywhere in the compiler. Two reasons:
1. Speed — `rustc-hash`'s FxHash is a fast non-cryptographic hash designed for exactly this kind of
   compiler-internal small-key map.
2. **Determinism.** `std::HashMap` is randomly seeded per-process; iterating it produces a
   different order on every run. `FxHashMap` is seedless, so a given input circuit always produces
   byte-identical compiler output. This matters more than usual here because iteration order over
   these maps was, in the old code, occasionally used to build the final node sequence.

Dense, small-integer-keyed tables (share kinds by `ValueId`, future slot assignments) should stay
plain `Vec`s — a direct index beats hashing, and a map isn't buying anything there.

## Deliberate non-goals (and why)

- **Loops stay unrolled in the frontend, not modeled as graph nodes.** Making unrolling a pass over
  the IR would require loop/region nodes, which breaks the flat topological-order invariant that
  makes `gc`, `verify`, and every future analysis a single linear pass instead of a fixpoint over a
  CFG. Revisit only if secret-dependent control flow (`CompilerConfig::allow_leaky_loops`, not
  currently wired up) is actually needed — note that's precisely the feature co-snarks' existing
  stack-machine VM (`circom-mpc-vm`, see below) pays a real runtime cost for.
- **No workspace split.** Single crate, restructured modules. Split into crates only once module
  boundaries have stopped moving.
- **The plain interpreter (`interpreter.rs`) is a debugging tool, not the product.** It exists to
  check the IR's semantics and to be the correctness oracle until a bytecode VM exists. Don't
  over-invest in it; extend it only as far as needed to validate a change.
- **No MPC execution in this crate.** `MpcInterpreter`, `mpc_ir::Op` (a 37-variant share-specialized
  mirror of `ir::Op`), `passes/mpc_ir_translation.rs` (the pass that monomorphized one into the
  other), and the rep3/plain executor abstractions underneath (`mpc/`) were all deleted. They were a
  node-traverser, not a step toward the bytecode VM this compiler is actually building toward (see
  "Where this is headed" below) - keeping them meant every IR change had to be mirrored into a
  37-variant enum and a 9-way share-kind match that the eventual VM will never use. Find them again
  at commit `5cdc695` if the design needs re-deriving; the reasoning that shaped them (share kind as
  an IR-external analysis property, not a set of specialized opcodes) still applies to the VM this
  crate is headed toward, it just isn't implemented anywhere right now.

## Where this is headed (not yet built)

The interpreter above is a placeholder. The actual target is bytecode for a **flat slot machine**,
which is a deliberate contrast with the stack machine co-snarks already ships
(`circom-mpc-vm`, in the `co-snarks` dependency at
`~/.cargo/git/checkouts/co-snarks-*/*/co-circom/circom-mpc-vm/src/op_codes.rs` — worth reading
before touching codegen): that VM has a field stack, an index stack, per-template `CodeBlock`s,
runtime `CreateCmp`/`InputSubComp`/`OutputSubComp` context switches, and runtime branches/jumps,
because *it* doesn't inline components or unroll loops ahead of time. This compiler does both of
those things statically (see "Non-goals" above), so its VM doesn't need any of that: no stack, no
components, no jumps, no address arithmetic. Fixed-width instructions, three slot banks (public /
arithmetic-share / binary-share), a `u8` opcode that *is* specialized per share kind (the right home
for the variant explosion that's deliberately absent from the IR, see above).

Planned steps, in order (see the original design conversation / PR history for the full writeup if
this section goes stale):

1. **(done)** Value-graph IR, recursive inliner, `gc`/`verify` replacing the three old cleanup
   passes.
2. **(done)** Pass infrastructure: a `Pass` trait, a `PassManager`, an opt-level config
   (`OptLevel`, `src/passes/mod.rs`) distinct from the existing `SimplificationLevel` (which
   configures upstream circom constraint simplification, a different knob). See "Pass
   infrastructure" below.
3. Design constraint for the future MPC/VM work (not a refactor of code that exists anymore - the
   code this step used to describe collapsing was deleted, see "Non-goals"): share-kind
   specialization belongs in a share-kind analysis pass over this one IR plus a generic
   `insert_conversions` pass, consulted only at bytecode codegen time - never as extra `ir::Op`
   variants. Whatever MPC crate eventually does this owes it to itself to re-derive the
   `amount_public_inputs`/wire-bank sizing bugs the old `mpc_interpreter.rs` had (hardcoded
   `amount_public_inputs = 0`, three full-length wire banks) rather than reintroduce them.
4. Bytecode + the flat-slot-machine VM described above, with linear-scan slot allocation over
   liveness so VM memory tracks live width, not total node count.
5. General optimization passes: constant folding **(done - `passes/const_fold.rs`)**, CSE/GVN (the
   value-graph model makes this a single hash-cons pass), algebraic simplification. The narrow,
   address-position-only fold that predates this (`frontend/fold.rs`, `GraphCompiler::
   eval_constant_node` - see "Where compile-time folding lives" above) still exists alongside it;
   see "Pass infrastructure" below for why both stay.
6. Rep3-specific passes, the actual point of all of the above: linear fusion (free ops never cost a
   round), conversion minimization (cancel `B2A(A2B(x))`, sink conversions past free linear ops),
   round scheduling (depth analysis, batch independent muls/opens into shared rounds), open
   sinking.
7. Re-add the operator surface removed in this cut (`Div`, `IntDiv`, `Pow`, `ShiftL`/`ShiftR`,
   `BitOr`/`BitAnd`/`BitXor`) as real `ir::Op` variants, and implement `Instruction::Call`/`Branch`/
   `Return`. This is now only needed for gadgets used *unwrapped* - every
   `TACEO_PRECOMPUTATION_*`-wrapped use of `IsZero`/`Num2Bits`/`Poseidon2`/`AliasCheck` sidesteps
   these gaps entirely (see "Precomputation" below), which is what got `circuits/merces/` past the
   `poseidon2_constants.circom` function-call gap. What's left blocking them is `IsZero` used
   *unwrapped* (`merkle_root_4.circom`'s `IsEqual`) - see "Real-world target circuits" below.
