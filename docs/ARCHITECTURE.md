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
  -> ir::Graph::verify(), then PassManager::for_opt_level(config.opt_level).run():
       classical passes to a fixpoint, then MPC lowering, unconditionally          (ir.rs, passes/, called from lib.rs)
  -> interpreter (debug/reference, the only execution path in this crate) -        (interpreter.rs)
     simulates the lowered ops in the clear, so it's also the oracle for lowering
```

`CoCircomCompiler::<P>::parse(file, config)` in `lib.rs` runs everything up to and including the
`PassManager`, and returns the `ir::Graph` - **always MPC-lowered** (see "MPC lowering" below); there
is no plaintext-only end state. The plain `Interpreter` is the only consumer in this crate, and
simulates the lowered ops too. An earlier version of this crate had a real MPC execution path (rep3,
a plaintext stand-in `PlainExecutor`, an `mpc_ir` share-kind-specialized mirror IR) that was deleted
before the lowering described below existed - see "Deliberate non-goals" for why that shape was wrong
and where to find it again if the reasoning ever needs re-deriving.

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
plus a `PassManager` with **two stages**: `optimize` (a fixed classical-pass list run to a fixpoint,
bounded by `max_iterations`) then `lower` (the MPC pipeline, `passes/mpc/`, run once, unconditionally
- see "MPC lowering" below for why this is a separate stage rather than more fixpoint passes).
Re-verifies the graph after every pass in debug builds. `OptLevel` (`CompilerConfig::opt_level`)
selects the *classical* pass list only - `O0` is dead code elimination, `O1` (default) adds constant
folding, `O2` adds CSE/GVN, commutative-operand canonicalization, and affine normalization. This is
deliberately a separate knob from `SimplificationLevel`, which configures upstream circom constraint
simplification, not this crate's own IR passes, and independent of MPC lowering, which runs at every
opt level.

The piece that makes a `Pass` cheap to write correctly is `Graph::rewrite` (`src/ir.rs`): it walks
the old node list in original order, handing each pass's callback the node with its inputs already
remapped to new-space `ValueId`s, plus every node already emitted so far (so a pass can inspect an
input's *producer* - e.g. "is this a constant?" - by indexing into it). The callback returns `Keep`,
`ReplaceWith(other_value)` (alias, no node emitted), `Emit(different_node)`, or
`EmitMany(Vec<Node<F>>)` (one original node expands into several - `passes::mpc::mul_split` is the
first consumer, splitting a secret `Mul` into its local part, a singleton round, and that round's
result); `rewrite` owns the old-to-new remap and fixes up `outputs`, so a pass can never accidentally
produce a forward reference - the exact bug class that would otherwise be easy to introduce in this
IR, since a node's `ValueId` doubles as its position and deleting or replacing any node shifts every
later reference. `Graph::gc` (dead code elimination) predates `rewrite` and keeps its own
hand-written reverse-liveness sweep instead - it's a liveness walk, not a node-for-node rewrite, so
the same abstraction doesn't fit it - but its remap type is shared. Two later passes hit the same
"doesn't fit `rewrite`" wall for a different reason (merging several existing nodes into one, or
eliding a node whose need isn't known until later, both change *which* original ids get a new
counterpart at all, not just what each one looks like) and follow `gc`'s precedent instead of
`rewrite`'s: see `passes::mpc::round_schedule` and `passes::normalize`. `Graph::rebuild_nodes`
generalizes `gc`'s "replace the whole node list, remap outputs" shape for these.

`passes/dead_code.rs` is a thin `Pass` wrapper over `Graph::gc`. `passes/const_fold.rs` is the first
real `Graph::rewrite` consumer: it folds `Add`/`Sub`/`Mul` when both operands are already
`Op::Constant`, plus the identity/annihilator cases (`x+0`/`x-0`/`x*1` alias to `x`; `x*0` folds to
`0`). This is a different, broader fold from the two pre-existing ones and doesn't replace either:
`frontend/fold.rs::fold_binary` folds the *removed* operators (`Div`, `ShiftR`, ...) at lowering
time, before a node ever exists, and `GraphCompiler::eval_constant_node` only folds in
array/signal/component *address* position. Both predate the pass infrastructure and still exist for
the reasons documented under "Where compile-time folding lives" above; `const_fold` is the first
pass that folds `Add`/`Sub`/`Mul` themselves, anywhere in the graph.

Three more classical passes round out `O2`, all in the family of "what a flat, control-flow-free
dataflow DAG over a field actually admits" - LICM, SROA, CFG passes, and vectorization don't apply
here at all (loops are unrolled in the frontend, there's no memory, no branches, and round batching
already subsumes vectorization's win - see "Deliberate non-goals"):

- **`passes/cse.rs`** - GVN by hash-consing every `Op::is_pure` node (`(op, inputs)` as the key,
  commutative inputs sorted first). This is `is_pure`'s first real consumer: it was added alongside
  the precomputation ops it protects, before anything checked it, specifically so a future pass
  wouldn't have to remember to add the guard - `cse` (and now the MPC round ops, `is_pure() == false`
  for the same "merging changes what the runtime must supply" reason) is that pass.
- **`passes/algebraic.rs`** - canonical operand order for commutative `Add`/`Mul` (constant right,
  else by `ValueId`), purely so `cse` sees `a+b` and `b+a` as the same key. Everything else one might
  expect here (`x-x -> 0`, `Add(x,x) -> Mul(2,x)`, cross-chain cancellation) turned out to already
  fall out of `normalize`'s affine algebra for free - see below - so this pass stays narrowly scoped
  to the one identity that doesn't.
- **`passes/normalize.rs`** (with `passes/poly.rs`, the affine engine it's built on) - collapses each
  maximal `Add`/`Sub`/mul-by-constant tree into one canonical `Affine` (`constant + Σ cᵢ·atomᵢ`) and
  rebuilds only what's actually needed. Subsumes cross-chain constant folding, cancellation
  (`(a+b)-a -> b`, left behind by circom's own simplifier), and reassociation of arbitrarily-nested
  chains, since all three are the same operation (combine into one `Affine`) applied transitively.
  Not a `Graph::rewrite` consumer - see the note above; a node whose need is only established by a
  *later* node (a real product's non-constant operand, or an output) can't be decided at its own,
  earlier turn, which `rewrite`'s per-node auto-remap requires. Deliberately capped at degree 1
  (affine, not quadratic): a degree-2 extension would fuse multiple products behind one reshare slot,
  which only helps MPC bandwidth (tier 2 of the cost model in "MPC lowering" below), never round
  count (tier 1, `round_schedule`'s job) - and its payoff is bounded by the same "materialized nodes
  can't be un-materialized" constraint documented there, currently unmeasurable since no circuit
  large enough to matter compiles yet. Rejected rather than spec'd out further; revisit once a real
  circuit's `mpc_summary` shows the bandwidth to save.

## MPC lowering (`src/passes/mpc/`)

`CoCircomCompiler::parse` always returns an MPC-lowered graph - this is not gated by any config
knob, and there is no plaintext-only end state. This section is the design record for why the
lowering looks the way it does; see "Non-goals" (below) for why an earlier, deleted version of MPC
support in this crate had the wrong shape, and why this one doesn't repeat that mistake.

### The domain lattice

A rep3 replicated share `(a_i, b_i)` of `x` satisfies `Σ_i a_i = x`, so its `a` component alone is
already a valid *additive*-3 sharing of `x`. That gives a third value domain below "replicated
share", not just "public" and "secret":

| Domain | Meaning | Free ops | Needs |
|---|---|---|---|
| `Public` | every party holds the cleartext | everything | - |
| `Shared` | valid replicated share; any op may consume it | add/sub, mul-by-public | - |
| `Local` | additive-3 sharing only (post-local-product, pre-reshare) | add/sub, mul-by-public | a reshare before any non-linear use |

`Public < Shared < Local`: `Shared -> Local` is free (take the `a` component), `Local -> Shared`
costs one reshare message. **Every linear op is free in all three domains** - this is the whole
reason round batching works: every independent product at the same multiplicative depth can share
one message, because nothing about combining `Local` values linearly needs a round first. One
security nuance worth stating explicitly: the fresh mask a local product carries comes from
`local_mul`, so a round's slot count must equal its product count - a round with zero slots would
have nothing to reshare, which is why `Graph::verify` rejects one (see below).

### The cost model

Lexicographic, and it settles every design choice below:

1. **rounds** - a network round-trip, latency-bound. Minimize first, always.
2. **reshare elements** - bandwidth. One field element per slot per round.
3. **local muls** - cheap field work, but not free.
4. **nodes** - VM memory/slot pressure (roadmap step 4, not yet built).

This is why `round_schedule` (batches by depth, tier 1) exists and a degree-2 fusion pass (tier 2
only) doesn't yet - see `passes/normalize.rs`'s doc above.

### Three new `Op` variants, following the `Precompute`/`PrecomputeResult` precedent

A batched round is inherently multi-output, which this IR forbids (single result per node - see
"Invariants" above). `Op::Precompute`/`Op::PrecomputeResult` already solved exactly this; rounds
reuse the shape rather than inventing a new one:

- `Op::MulLocal` (arity 2) - the free local half of a secret x secret product: `a*b + mask`,
  rep3's `local_mul_vec`. Domain `Local`.
- `Op::Round(RoundId)` (arity = the referenced `RoundDesc::len`, `Arity::RoundLen` alongside the
  existing `Arity::SiteInputs` for the same "only `Graph::verify` can check this" reason) - one
  network round; its inputs are the `MulLocal` values reshared together in one message. Its own
  value is never read directly, only through the `RoundResult`s that reference it - same convention
  as `Precompute`.
- `Op::RoundResult(slot)` (arity 1, the `Round` node) - domain `Shared`.

`Graph::rounds: Vec<RoundDesc>` is the side table `RoundId` indexes into (`kind: RoundKind` -
currently always `Reshare`; `len`; `depth`, diagnostic), mirroring `Graph::precompute_sites`.
`Graph::stage: Stage { Plain, MpcLowered }` is `pub(crate)`, not a config surface - it exists only so
`Graph::verify` knows which invariants apply mid-pipeline, and so pass unit tests can build a `Plain`
graph by hand without running the whole lowering pipeline first. `PassManager::run` sets it once,
right before running the lowering passes (not after - the first of them already introduces MPC ops,
so `verify`'s Stage::Plain check would otherwise misfire on the graph mid-lowering).

Deliberately absent: share-kind-specialized op variants (`MulSecretPublic`, `AddSecretSecret`, ...).
Which one applies falls out of the domain analysis below; baking it into `ir::Op` is exactly the
mirror-enum trap the deleted 37-variant `mpc_ir::Op` fell into (see "Non-goals").

### The pipeline (`src/passes/mpc/`)

Unlike the classical passes, this is a lowering *sequence*, not a fixpoint - `PassManager` runs it
once, after the classical passes converge, unconditionally at every `OptLevel`:

1. **`domain.rs`** - not a registered `Pass` (see below), a small library `mul_split` calls
   incrementally: `signal_domain` classifies an `Op::Input` as `Public` iff its signal falls in a
   `public_inputs`-named range of `input_list` (both already on `Graph`), else `Shared`; everything
   else is a simple lattice join over an op's inputs. Not cached in `PassContext`, and not its own
   `Pass`, because the domain of a *new-space* value is what `mul_split` needs while it rewrites, and
   `Graph::rewrite` remaps every node's inputs to new-space ids before the callback ever sees them -
   an old-space array computed by a separate prior pass can't be indexed by the ids the callback
   actually receives once an earlier `EmitMany` has shifted everything after it. Recomputing
   alongside the rewrite's own `new_nodes` keeps the two in lockstep for free instead.
2. **`mul_split.rs`** - every `Mul` with two `Shared` operands becomes `MulLocal` + a **singleton**
   `Round` + `RoundResult(0)`, via `EmitMany`. A `Mul` with any `Public` operand is untouched (already
   free). Emitting a singleton round (rather than a bare `MulLocal`) keeps every intermediate graph
   state valid and is exactly `rep3::arithmetic::mul` called once per product - so this pass alone,
   before `round_schedule` runs, is already a correct (if naive) lowering, independently testable.
3. **`round_schedule.rs`** - the headline transform. Computes MPC depth per value (`0` for
   `Public`/`Input`/`Constant`/precomputation ops, `max` of inputs for linear ops and `MulLocal`,
   `depth(Round) + 1` for `RoundResult`), then merges every singleton round at the same depth into
   one. ASAP scheduling, so the round count equals the circuit's multiplicative depth - the minimum -
   and **message count drops from one-per-secret-mul to one-per-depth-level**. Not a
   `Graph::rewrite` consumer (see the note under "Pass infrastructure"): a product's final round is
   only fully known once every *other* product at its depth has been seen, which can be later in the
   original node order - a forward reference a single forward pass can't express. Instead: a direct
   two-phase reconstruction (compute depths, then rebuild depth-bucket by depth-bucket, ordinary
   nodes first then that depth's merged round) that produces a valid topological order by
   construction - each bucket's ordinary nodes preserve their original relative order (still
   topological, since depth is non-decreasing along every edge), and a depth's round is only emitted
   once every node at that depth has been. `Graph::rebuild_nodes` installs the result.
4. **`Graph::mpc_summary`** - not a pass; a diagnostic method reporting rounds, total reshare
   elements, min/max slots per round, local muls, free public muls, and precomputation sites. Exists
   so every claim above is falsifiable rather than asserted - see `tests/mpc_lowering.rs`, which
   checks it against three synthetic circuits with known multiplicative-depth shape
   (`circuits/bench_{chain,tree,widesum}.circom`): a chain of 3 dependent products needs 3 rounds of
   width 1, a balanced tree of 8 inputs needs 3 rounds of width 4/2/1, and 4 independent products
   needs exactly 1 round of width 4. These are synthetic because the circuits that currently compile
   at all are small (see "Known gaps") - there is no large real circuit yet to measure batching
   against, and that limit is worth stating rather than hiding.

**Deliberately deferred, reason recorded instead of stubbed:** open sinking and `B2A(A2B(x))`
cancellation/conversion minimization need `Div`, comparisons, or bitwise ops to exist - none do (see
"Known gaps"). A conversion-minimization pass with nothing to convert is dead infrastructure.
`RoundKind::Open` and a future `Binary` domain are the extension points, added with a doc comment
rather than a stub variant, since `RoundKind` isn't public API and there's nothing to keep
source-compatible by pre-declaring it.

**One assumption worth being explicit about:** `PrecomputeResult` is depth 0 (round-free) in
`round_schedule`'s formula, because the runtime computes every `TACEO_PRECOMPUTATION_*` trace up
front, in one batched pass, before witness extension starts (see "Precomputation" below). A site
whose inputs depended on witness-extension results would violate that - a circuit-side property this
compiler can't fix, but shouldn't silently mismodel either.

### Executing a lowered graph

`interpreter.rs` simulates the three new ops in the clear: `MulLocal` is a plain product (there's
nothing to mask or reshare in a single-party evaluator), `Round`'s own value is never read (same
convention as `Precompute`), and `RoundResult(k)` reads input `k` of its `Round` node directly - a
round's k-th input *is* its k-th result, since nothing distinguishes "local" from "shared" once
there's only one party. Since `CoCircomCompiler::parse` always lowers, this makes every existing
golden-witness KAT (`tests/circom_ir.rs`) a correctness test for the lowering, not just the frontend
and classical passes - at zero added dependency cost, since this crate still doesn't depend on
`co-snarks`/rep3 at all.

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
- **Share kind is an external analysis, never a set of per-op variants - the lesson from the deleted
  `mpc_ir::Op`, still honored by the ops added in "MPC lowering" above.** An earlier version of this
  crate had `MpcInterpreter`, `mpc_ir::Op` (a 37-variant share-specialized *mirror* of `ir::Op` -
  every binary op repeated once per combination of public/arithmetic-share/binary-share operands),
  `passes/mpc_ir_translation.rs` (the pass that monomorphized one into the other), and the rep3/plain
  executor abstractions underneath (`mpc/`); all deleted (find them again at commit `5cdc695` if the
  design needs re-deriving). They were a node-traverser, not a step toward the bytecode VM this
  compiler is building toward, and kept every IR change synchronized against a 37-variant enum and a
  9-way share-kind match the eventual VM would never use. **This is not the same shape as
  `Op::MulLocal`/`Op::Round`/`Op::RoundResult`** (see "MPC lowering" above): those three model round
  *structure* - a batched network round is inherently multi-output, which this IR forbids regardless
  of MPC, the same reason `Op::Precompute`/`Op::PrecomputeResult` exist - not share kind. Domain
  (`Public`/`Shared`/`Local`) stays exactly what the deleted design got right and this one keeps: an
  external analysis (`passes/mpc/domain.rs`) consulted by a lowering pass, never baked into which `Op`
  variant a node uses. Reintroducing a `MulSecretPublic`/`AddSecretSecret`-style variant explosion
  would be repeating the mistake; adding a new *structural* op for a genuinely new multi-output shape
  (as `Precompute` already established the precedent for) is not.

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
3. **(done)** Share-kind specialization as an external analysis over this one IR
   (`passes/mpc/domain.rs`'s `Domain` lattice), consulted by lowering passes rather than baked into
   extra `ir::Op` variants - see "MPC lowering" above, and "Non-goals" for why the three ops that
   *were* added (`MulLocal`/`Round`/`RoundResult`) aren't a reversal of this. A generic
   `insert_conversions` pass (for `B2A`/`A2B`) is still future work - see "MPC lowering", "Rep3-
   specific passes" below - since there's no `Binary` domain or conversion op yet to insert.
   Whatever eventually needs bytecode-codegen-time share-kind dispatch owes it to itself to re-derive
   the `amount_public_inputs`/wire-bank sizing bugs the old `mpc_interpreter.rs` had (hardcoded
   `amount_public_inputs = 0`, three full-length wire banks) rather than reintroduce them.
4. Bytecode + the flat-slot-machine VM described above, with linear-scan slot allocation over
   liveness so VM memory tracks live width, not total node count.
5. **(done)** General optimization passes: constant folding (`passes/const_fold.rs`), CSE/GVN
   (`passes/cse.rs`, a single hash-cons pass as expected), algebraic simplification
   (`passes/algebraic.rs`, `passes/normalize.rs` + `passes/poly.rs`) - see "Pass infrastructure"
   above for what each one covers and why a degree-2 extension to `normalize` was rejected rather
   than built. The narrow, address-position-only fold that predates this (`frontend/fold.rs`,
   `GraphCompiler::eval_constant_node` - see "Where compile-time folding lives" above) still exists
   alongside it; see "Pass infrastructure" for why both stay.
6. Rep3-specific passes, the actual point of all of the above:
   - **(done)** Round scheduling - `passes/mpc/round_schedule.rs`, batching independent secret
     multiplications at the same depth into one round. See "MPC lowering" above.
   - **(done, trivial)** Linear fusion (free ops never cost a round) - not a separate pass; it falls
     directly out of the domain lattice (`Local`/`Shared` both support free linear ops), so nothing
     beyond `mul_split`'s domain check was needed to get it.
   - **Not yet built:** conversion minimization (cancel `B2A(A2B(x))`, sink conversions past free
     linear ops) and open sinking. Both need `Div`, comparisons, or bitwise ops to exist first - none
     do (see "Known gaps") - so there's nothing to convert or sink yet; `RoundKind::Open` and a
     future `Binary` domain are the extension points, deliberately not stubbed out ahead of a real
     producer. See "MPC lowering" above.
7. Re-add the operator surface removed in this cut (`Div`, `IntDiv`, `Pow`, `ShiftL`/`ShiftR`,
   `BitOr`/`BitAnd`/`BitXor`) as real `ir::Op` variants, and implement `Instruction::Call`/`Branch`/
   `Return`. This is now only needed for gadgets used *unwrapped* - every
   `TACEO_PRECOMPUTATION_*`-wrapped use of `IsZero`/`Num2Bits`/`Poseidon2`/`AliasCheck` sidesteps
   these gaps entirely (see "Precomputation" below), which is what got `circuits/merces/` past the
   `poseidon2_constants.circom` function-call gap. What's left blocking them is `IsZero` used
   *unwrapped* (`merkle_root_4.circom`'s `IsEqual`) - see "Real-world target circuits" below.
