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
     (unless it instantiates a recognized precomputation gadget - see
     "Precomputation"), unrolling loops eagerly, folding removed operators at
     compile time                                                                  (frontend/unroll.rs, frontend/fold.rs)
  -> recursive inlining: flatten the TemplateGraph tree into one ir::Graph          (frontend/inline.rs)
  -> ir::Graph::verify(), then PassManager::for_opt_level(config.opt_level).run():
       classical passes to a fixpoint, then MPC lowering, unconditionally          (ir.rs, passes/, called from lib.rs)
  -> codegen: Graph -> vm::Program, a fixed-width bytecode over three slot banks   (vm/codegen.rs)
  -> vm::Machine::run(program, driver, inputs) executes it against either          (vm/machine.rs, vm/driver/)
     vm::driver::plain::PlainDriver (single-party, the KAT oracle) or a real
     three-party vm::driver::rep3::Rep3Driver (behind the `rep3` feature)
```

`CoCircomCompiler::<P>::parse(file, config)` in `lib.rs` runs everything up to and including the
`PassManager`, and returns the `ir::Graph` - **always MPC-lowered** (see "MPC lowering" below); there
is no plaintext-only end state. `CoCircomCompiler::<P>::compile` runs `parse` and then
`vm::codegen::compile`, returning the final `vm::Program`. See "Deliberate non-goals" for why share
kind is an external analysis rather than a set of `ir::Op` variants, and "Bytecode and the slot
machine" for why MPC execution is a bytecode VM rather than a tree-walking interpreter.

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
value's identity is the node's position in `nodes`. Nothing needs a pass to keep some parallel
address space dense and alias-free after a rewrite, because there is no such space to begin with.

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
built on top of it - small enough to reason about exhaustively. Share-kind specialization
(public/shared/local) happens at bytecode codegen time (`vm::codegen`, see "Bytecode and the slot
machine"), never in this enum - see "Non-goals" for why. If/when the operator surface grows back,
keep specializing at bytecode codegen time rather than in this enum, for the same "write every pass
once" reason.

### Where compile-time folding lives

`constants_test` reaches `ShiftR`/`BitAnd`/etc. only via a fully compile-time-constant table lookup,
never a genuine circuit input, so those operators still need to fold to a concrete value even though
they have no runtime `Op` variant. `frontend/fold.rs::fold_binary` evaluates the eight removed
operators when both operands are already `Op::Constant`. This is deliberately narrow - it does not
fold `Add`/`Sub`/`Mul` (that's a
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

A variable read or a subcomponent port reference is pure aliasing and doesn't need a node at all:
- **Variable reads** are a `HashMap` lookup (`var_to_value` in `frontend/build.rs`) — the read
  returns the `ValueId` that was last stored, no new node.
- **Subcomponent ports** are resolved once, at inlining time, by `frontend/inline.rs` (see below) —
  no placeholder is ever materialized, so there is nothing to chase or delete afterward.

## Frontend (`src/frontend/`)

`build.rs` walks one template's circom bucket instructions (`Instruction::{Value,Load,Store,
Compute,...}`) and produces a `TemplateGraph` — a **not-yet-inlined** per-template graph.
`handle_inst` and its callees **return** the `ValueId` an instruction produces, rather than pushing
a node and having the caller peek at "whatever was pushed most recently" - a variable read just
returns the stored `ValueId` directly, so `Op::Load` never needs to exist.

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
instantiates, transitively) into one `ir::Graph`, resolving every cross-template reference *at
inlining time*, via a handful of maps that carry already-resolved `ValueId`s across the recursion:

- `sub_cmp_inputs[instance][port]` — the value stored into a subcomponent instance's input port,
  filled in as `SubCmpInput` nodes are processed at the *caller's* level.
- the returned `port_outputs` map — which value a subcomponent's output port resolves to, handed
  back to the caller so a `SubCmpOutput` reference can resolve it.
- `local_writes[signal]` — this template's own signal writes, so a template can read back a signal
  it just wrote (its own output, or any intermediate signal) without re-deriving anything.
- `local_remap[local_node_index]` — the resolved outer `ValueId` for each of this template's own
  nodes, so `Real` ops can translate their locally-indexed inputs into globally-valid ones.

A template's own signal reads resolve through `local_writes` first, uniformly regardless of nesting
level - so a *nested* subcomponent reading back its own already-written output signal (not just
`main`) resolves the same way.

A subcomponent whose outputs are never read via `SubCmpOutput` still needs inlining - nothing else
in `inline_template` would visit it, and its signals would otherwise never reach `outputs`, silently
leaving them `0` in the witness. This matters for any subcomponent declaring no outputs at all
(`AliasCheck` is exactly this shape) as well as any pure-constraint subcomponent nothing reads from.
A trailing pass at the end of `inline_template` inlines every `sub_graphs` entry still `Some` after
the main node loop (i.e. never claimed by the `SubCmpOutput` arm). This is topologically sound
because every such subcomponent's inputs were necessarily already resolved earlier in the same loop
(by the `SubCmpInput` arm) - nothing about *reading* its outputs was required to *write* its inputs.

**Signal offsets accumulate additively across nesting depth - `inline_sub_graph_instance` adds the
enclosing template's own absolute offset to the instance's stored one before recursing.** A
`SubGraphInstance`'s `signal_offset` field is *father-relative*: it comes straight from circom's own
`CreateCmpBucket::signal_offset`, which that struct's own doc comment in the pinned fork describes as
"signal offset with respect to the start of the father's signals" - i.e. relative to whichever
template's own body created the instance, not globally absolute. A regular (`Compiled`) template gets
compiled once and its `TemplateGraph` reused, unmodified, at every instantiation site (parameterized
only by the caller-supplied absolute offset) - which is exactly why the nested instances *inside* that
reused body cannot have baked in a correct absolute offset at compile time: the same body is inlined
at a different absolute base every time it's instantiated. `inline_template`'s own `signal_offset`
parameter is that instantiation's absolute base, so `inline_sub_graph_instance(..., parent_offset,
...)` adds `parent_offset` to each nested instance's own (still father-relative) `signal_offset` before
placing its signals or recursing into it - one addition per nesting level, so it composes correctly to
arbitrary depth. This is invisible at depth 2 (main instantiates a leaf directly: the father is main,
whose absolute offset is 0, so father-relative and globally-absolute coincide), which is why the
missing addition went unnoticed until a genuinely deep circuit exercised it - see "Known gaps".

## Pass infrastructure (`src/passes/`)

A `Pass` trait (`fn run(&mut self, graph: &mut Graph<F>, ctx: &mut PassContext) -> Result<Changed>`)
plus a `PassManager` with **two stages**: `optimize` (a fixed classical-pass list run to a fixpoint,
bounded by `max_iterations`) then `lower` (the MPC pipeline, `passes/mpc/`, run once, unconditionally
- see "MPC lowering" below for why this is a separate stage rather than more fixpoint passes).
Re-verifies the graph after every pass in debug builds. `OptLevel` (`CompilerConfig::opt_level`)
selects the *classical* pass list only - `O0` is dead code elimination, `O1` (default) adds constant
folding, `O2` adds CSE/GVN, commutative-operand canonicalization, and affine normalization. This is
deliberately a separate knob from upstream circom's own constraint simplification, which always runs
at full `--O2` (`no_rounds: usize::MAX` in `src/frontend/mod.rs`'s `BuildConfig` - see "Known gaps"
for why no other level is supported) and has no bearing on this crate's own IR passes. Independent of
MPC lowering, which runs at every opt level.

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
later reference. `Graph::gc` (dead code elimination) keeps its own hand-written reverse-liveness
sweep rather than going through `rewrite` - it's a liveness walk, not a node-for-node rewrite, so
the same abstraction doesn't fit it - but its remap type is shared. Two other passes hit the same
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
array/signal/component *address* position. Both exist for the reasons documented under "Where
compile-time folding lives" above; `const_fold` is the first pass that folds `Add`/`Sub`/`Mul`
themselves, anywhere in the graph.

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
lowering looks the way it does; see "Non-goals" (below) for why share kind is modeled as an
external analysis rather than baked into `ir::Op`.

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
3. **`round_schedule.rs`** - the headline transform. Buckets every value by `passes::mpc::level`'s
   network-event level (see "The event axis" below - `Precompute`/`PrecomputeResult` charge a level
   like everything else, they are not a `0` special case), then merges every singleton round at the
   same level into one. ASAP scheduling, so the round count equals the circuit's multiplicative depth
   plus any levels a precomputation site adds - the minimum for that DAG -
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
   needs exactly 1 round of width 4. `mpc_summary` reports **IR reshare rounds only** - it has no
   visibility into a precomputation batch's own internal round cost, which is a property of
   `vm::gadgets`, not of the graph. `examples/merces.rs` (`round-counting` feature,
   `vm::counting_net::CountingNet`) reports the *measured* total against a real 3-party run on the
   merces circuits and attributes the difference to gadget-internal rounds (see "Real-world target
   circuits" below).

**Deliberately deferred, reason recorded instead of stubbed:** open sinking and `B2A(A2B(x))`
cancellation/conversion minimization need `Div`, comparisons, or bitwise ops to exist - none do (see
"Known gaps"). A conversion-minimization pass with nothing to convert is dead infrastructure.
`RoundKind::Open` and a future `Binary` domain are the extension points, added with a doc comment
rather than a stub variant, since `RoundKind` isn't public API and there's nothing to keep
source-compatible by pre-declaring it.

### The event axis: `passes/mpc/level.rs`

`passes::mpc::level::network_levels` computes a value's **level**: *how many network events must
complete before it exists*, an event being either a reshare round or one precomputation batch
service. A site's inputs may depend on values produced only partway through witness extension -
this is what the merces circuits' chained Poseidon2 sites do as their main case - so a site's
results must sit strictly above its inputs' level, never at the same level:

| Op | Level |
|---|---|
| `Input`, `Constant` | 0 |
| `Add`/`Sub`/`Mul`/`MulLocal`, `Round`, `Precompute` | `max(inputs)` |
| `RoundResult`, `PrecomputeResult` | `level(input) + 1` |

Charging for a site is simply truthful - every rep3 `VmDriver::*_traces` gadget takes a `&Network`
and genuinely communicates, so a site's results are *not* available at the same instant as its inputs.

**One axis, not two.** Rounds and batch services share a counter rather than getting a `(depth, stage)`
pair, for two reasons that matter more than the one thing it costs:

- Two sites at the same level are *provably* mutually independent, since any dependency forces `+1` -
  exactly the property that folding N sites into one driver call requires. This cannot be recovered
  from multiplicative depth: `server.circom` chains `Num2Bits(254)` → `AliasCheck` → `IsZero` with
  **zero multiplications between them**, so all three sit at identical multiplicative depth despite
  being sequentially dependent. Any depth-keyed scheme batches dependent sites together and is wrong.
- With `PrecomputeResult` at `+1`, no node at level `d` can read a level-`d` site's result, so each
  level schedules as `[ordinary nodes] [this level's batches] [this level's round]` - the existing
  two-phase shape plus one event slot, needing no intra-level sub-order.

Accepted cost, recorded rather than hedged with a knob: for "site `S`, an unrelated product `A` at
`S`'s input level, and a product `B` reading `S`'s result", this emits round `{A}`, batch, round `{B}`
where a 2D scheme could emit batch, round `{A,B}` - one extra reshare message. A 2D scheme loses more
by splitting batches harder (key `(kind, depth, stage)`), and a batch service costs strictly more than
one reshare. `RoundDesc::level` is named for this axis, not for multiplicative depth.

Not a registered `Pass` - it mutates nothing, and has three consumers (`round_schedule`'s bucketing,
`vm::codegen`'s batch grouping, `Graph::mpc_summary`'s diagnostics). It follows `domain.rs`'s precedent:
pure functions, not cached in `PassContext`, because an old-space array is invalidated by the very
rewrite that consumes it.

**Deliberately deferred:** ASAP is not batch-optimal. Delaying an early site to join a later same-kind
batch (ALAP, or a real list scheduler over both event types) is a genuine win precisely because batch
services are the expensive events, and would also recover the `{A,B}` merge above. It needs a cost model
over batch services, which does not exist. That is also the one change that would require a site's stage
to be *recorded* in the IR rather than recomputed - see "Precomputation" for why it currently is not.

### Executing a lowered graph

`vm::codegen::compile` (see "Bytecode and the slot machine" below) turns the three new ops into real
instructions: `MulLocal` becomes one `Opcode::MulLocal`, and a `Round` plus its `RoundResult`s become
one `Opcode::Reshare` that writes straight into the result slots - there is no `RoundResult` opcode,
matching how `Op::PrecomputeResult` also vanishes from the instruction stream (see "Precomputation").
`vm::Machine::run` executes those against whichever `VmDriver` it's given -
`vm::driver::plain::PlainDriver` (`Local`/`Share` both `F`; `reshare` is the identity, since nothing
distinguishes "local" from "shared" once there's only one party) or a real
`vm::driver::rep3::Rep3Driver` (behind the `rep3` feature: `Share =
Rep3PrimeFieldShare<F>`, `Local = F`, `reshare` a genuine `rep3::arithmetic::reshare_vec` network
round). Since `CoCircomCompiler::compile` always lowers, this makes every existing golden-witness KAT
(`tests/circom_ir.rs`) a correctness test for the lowering and codegen both, not just the frontend and
classical passes - and `tests/rep3_vm.rs` re-runs the same KATs through real 3-party `LocalNetwork`
execution, proving the rep3 driver agrees with the plain one on genuinely secret-shared data, not
just in the clear.

## Bytecode and the slot machine (`src/vm/`)

Roadmap step 4 (see "Where this is headed"). `vm::codegen::compile` (not a `Pass` - it changes
representation, not the IR; called by `CoCircomCompiler::compile` after `PassManager` finishes) lowers
a fully-passed `ir::Graph` into a `vm::Program`: a fixed-width instruction stream over three
domain-typed slot banks, plus the side tables `vm::Machine::run` needs to execute it. This is a
deliberate contrast with the stack machine co-snarks already ships (`circom-mpc-vm`, in the
`co-snarks` dependency at `~/.cargo/git/checkouts/co-snarks-*/*/co-circom/circom-mpc-vm/src/
op_codes.rs` - worth reading before touching codegen): that VM has a field stack, an index stack,
per-template `CodeBlock`s, runtime `CreateCmp`/`InputSubComp`/`OutputSubComp` context switches, and
runtime branches/jumps, because *it* doesn't inline components or unroll loops ahead of time. This
compiler does both of those things statically (see "Non-goals"), so its VM doesn't need any of that:
no stack, no components, no jumps, no address arithmetic.

This is also the point where this crate first gains a real dependency on `mpc-core`/`mpc-net`
(`co-snarks`'s own crates, pinned at the same `rev` as the `co-snarks` checkout above) - gated behind
a default-on `rep3` Cargo feature (`vm::driver::rep3`, `vm::gadgets`' rep3-side functions). Disabling
it (`--no-default-features`) drops `mpc-core`/`mpc-net` (and the `swanky`/`fancy-garbling` dependency
tree they pull in for OT-related gadgets this crate never uses) entirely, leaving a fast-building,
plain-only compiler in which **all five precompute gadgets work** - every plain path is this crate's
own field arithmetic, with no dependency on `mpc_core::gadgets` at all. `tests/rep3_vm.rs` and
`tests/proving.rs` are `#![cfg(feature = "rep3")]`-gated so the plain-only configuration builds its
whole test suite too, not just the library.

`co-circom-types` and `co-groth16` (the co-snarks proving stack `vm::witness` and the prove+verify
tests build on - see "Proving" below) are dev-dependencies only, not a Cargo feature: the library
itself never proves, only splits a witness at the public/secret boundary, so nothing about proving
is gated behind a feature flag at all.

### Three banks: `Public`, `Shared`, `Local`

| Bank | Domain | `PlainDriver` | `Rep3Driver` |
|---|---|---|---|
| `Public` | `Public` | `F` | `F` |
| `Shared` | `Shared` | `F` | `Rep3PrimeFieldShare<F>` |
| `Local` | `Local` | `F` | `F` (the `a` component of a replicated share, already valid on its own) |

These are exactly `passes::mpc::domain::Domain`'s three values (that module is `pub(crate)` beyond
`passes::mpc` specifically so `vm::codegen` can reuse it rather than re-deriving domain from scratch).
There is no `Binary` bank yet, matching the IR: no conversion op exists to produce one (see "Known
gaps"). Codegen recomputes domain in one old-space forward pass over the already-lowered graph -
simpler than `mul_split`'s own new-space incremental version, since codegen only reads the graph, it
doesn't rewrite it.

### Instructions and opcodes (`vm/program.rs`)

`Instruction { op: Opcode, dst: u32, a: u32, b: u32 }` (16 bytes) - `dst`/`a`/`b` are slot indices
*within whichever bank the opcode's operands live in*, fully determined by `op`, so the instruction
itself carries no bank tag. Opcodes are named `<Op><BankOfA><BankOfB>`: `AddPP`/`SubPP`/`MulPP`
(public), `AddSS`/`SubSS` (both shared), `AddSP`/`SubSP`/`SubPS`/`MulSP` (mixed - `Add`/`Mul` are
commutative, so codegen reorders operands to match the one `..SP` opcode instead of also encoding a
`..PS` variant; `Sub` isn't, hence both). `MulLocal` (two `Shared` operands, one `Local` result) and
`Reshare` (`a` is an index into `Program::rounds`; operands/results are that round's own slot lists,
not per-instruction) are the two MPC-lowering ops. No constant-load or round-result opcode:
`Program::constants` are preloaded into `Public`-bank slots `0..constants.len()` at init, and a
round's results are written directly into their slots by `Reshare` - see `Op::RoundResult`'s own
removal, above.

`Opcode::Precompute` (`a` is an index into `Program::precompute_batches`) services one batch. It is a
real instruction rather than an out-of-band phase specifically so a site's inputs may be produced by
earlier instructions - see "Precomputation". `Reshare` was the precedent and the reason this cost one
enum variant, one match arm and one serialize tag: both are "a network event whose operands and results
are a side-table-owned slot list, not per-instruction operands". The alternative considered - an ordered
`Vec<(position_in_stream, batch)>` the machine interleaves - was rejected for putting control flow in a
side table (the run loop would test "is a batch due?" on every one of millions of iterations),
duplicating the ordering fact (explicit position *and* vector order, so `read` must validate
monotonicity), and forcing position fixups on every future stream transformation. With an opcode,
positions *are* the stream.

**Codegen asserts the `Local`-escape invariant instead of assuming it.** `mul_split` only ever
produces a bare `MulLocal` immediately wrapped by a `Round`, so a `Local` value should never reach an
`Add`/`Sub`/`Mul` operand or a circuit output directly - codegen checks this at every site (`select_
opcode`, the output-store loop) and returns a compile error naming the violation rather than silently
mis-encoding it. `vm::codegen::tests::local_value_reaching_anything_but_reshare_is_rejected` exercises
this on a hand-built graph, the same way pass unit tests build one.

### Liveness-driven slot allocation

A `BankAlloc` (bump counter + free list) per bank. Liveness is one pass, computed once up front: a
value's last-use index is the last node (in graph order) that reads it, with **two** exceptions. A value
`graph.outputs()` references gets `last_use = nodes.len()` (never freed), since its slot must still hold
the right value when `stores` reads it after the instruction stream finishes. And a value read by a
precomputation site is extended to its *batch's anchor*, because the batch runs later than the
`Op::Precompute` node that reads it - without that, the allocator could recycle a site's input slot in
between and a later instruction would clobber the gadget's input.

That second one is currently **masked** on frontend-produced graphs: `inline_precomputed` pushes every
site input into `graph.outputs()`, so the first exception already pins them. It is implemented anyway,
because hand-built codegen test graphs don't bind site inputs to outputs, and any future
witness-compaction pass that stops binding intermediate signals would silently reintroduce a clobbered
input that no golden KAT could localize
(`vm::codegen::tests::site_input_slot_survives_until_its_batch_runs`).

At each node, codegen allocates the result's slot, then frees any operand whose last use was this node -
this is what makes VM memory track live width, not total node count (`vm::codegen::tests::
slot_reuse_keeps_peak_width_below_node_count`).

Three regions are deliberately **not** recycled, for simplicity over maximal reuse: `Public`-bank
constants (`0..constants.len()`), `Shared`-bank precompute results (one contiguous range per site, in
site order - reserved before the main allocation loop runs, since a precompute batch's results must
already exist wherever the main instruction stream, or another site, might read them), and
`Shared`/`Public`-bank circuit inputs. A future optimization (not built): a precompute result read
only by `stores` could write directly into the final witness buffer, skipping its slot entirely.

`Op::Round`/`Op::RoundResult` need one adjacency assumption codegen relies on rather than re-derives:
`round_schedule` always places a `Round` node immediately followed by its `len` `RoundResult(0..len)`
nodes, in slot order (the same invariant `round_schedule`'s own construction documents). Codegen
processes a `Round` and its results in one step and advances past them, rather than visiting each
`RoundResult` independently - this is also *why* `Op::RoundResult` needs no opcode: its slot is
already known the moment the `Round` is processed. `Op::PrecomputeResult` doesn't need this adjacency
(its slot is a direct `site_result_base[site] + result_slot` lookup, tolerant of any surviving-node
gaps `gc` may have left between a `Precompute` node and its results).

**Batch placement is anchor/deadline, and the check is what makes the analysis safe.**
`plan_precompute_batches` groups sites by `(kind, level)` (see "The event axis"), then for each batch
computes `anchor` = the last node defining any of its sites, and `deadline` = the first node reading any
of its results. `anchor < deadline` is an `ensure!`, and `Opcode::Precompute` is emitted right after the
anchor node.

The tempting alternative - flush a batch once the walk's level advances past its stage - assumes graph
order is level-sorted. `round_schedule` does produce such an order, but it **early-returns without
reordering anything when the circuit has no secret multiplications at all**, which is exactly the
`Num2Bits` → `AliasCheck` → `IsZero` shape in `server.circom` (three stages, zero rounds). An anchor is
correct on any topological order, so that early return stays safe and needed no change. Levels only
*propose* the grouping; the check disposes of a bad one with a real error - the same posture as the
`Local`-escape assertion above. Analysis proposes, check disposes.

A value feeding an `Op::Precompute` may be any node the graph's level structure places before the
batch's anchor - not only a bare `Op::Input`/`Op::Constant` - so a site's inputs can themselves be
computed. The anchor check can only fire on a graph whose node order contradicts its own level
structure, i.e. a compiler bug or a hand-built graph. Two narrower errors remain: a site reading a
`Local` (un-reshared `MulLocal`) value, which `Graph::verify` also rejects structurally; and nothing
else - a `Public`-bank site input is legal (see "Precomputation").

### `Machine::run` (`vm/machine.rs`)

`Program::classify_inputs(values: &[F], share: impl FnMut(F) -> S)` builds the `Vec<InputValue<F,
S>>` `Machine::run` takes, consulting `Program::input_domains` to wrap each value as `Public(F)` or
`Secret(S)` automatically - `share` is only called for `Secret`-destined values (identity for
`PlainDriver`, real secret-sharing for `Rep3Driver` - see `tests/rep3_vm.rs`). `Machine::run`: binds
inputs into their banks, executes the instruction stream (a plain `match` over `Opcode`, dispatching
linear ops straight to the driver, `Reshare` to `program.rounds[instr.a]`'s operand/result slot ranges,
and `Precompute` to `run_batch` for `program.precompute_batches[instr.a]` - **interleaved**, at each
batch's own point in the stream rather than in an up-front phase), then builds the final signal array
(index 0 = the reserved constant-`1` signal; every genuine `SignalIdx` `s` lands at `s + 1`) from
`stores` plus - since a circuit's own top-level inputs are
never `graph.outputs()` entries (see "Precomputation" for why: only a *nested* subcomponent's own
input signal is) - directly from the caller-supplied `inputs`, and returns
`signal_to_witness.iter().map(|&i| signals[i])`.

### Proving (`vm/witness.rs`)

This is the default test oracle (`tests/proving.rs`), not a side path: compute the witness, prove it
against a real zkey, verify the proof. A verifying proof checks the witness values *and* the R1CS
layout against circom simultaneously - strictly more than a golden `.wtns` byte comparison
(`tests/circom_ir.rs`) can, and the only oracle available for a circuit with no golden witness at all
(the `precomputation_*_test` gadgets - see "Generating and cross-checking the golden KATs" below).

`Rep3Driver`'s output is `Vec<Rep3PrimeFieldShare<F>>` - this crate's *native* witness format:
**uniformly** shared, one entry per witness position in circom's order, position 0 the reserved constant
`1`. co-snarks' `SharedWitness { public_inputs, witness }` instead splits that into a cleartext prefix and
a secret-shared remainder, so the conversion is one batched open of the prefix and a move of the rest.
Opening is a real network operation, which is why `VmDriver` has an `open` method (identity for
`PlainDriver`, `rep3::arithmetic::open_vec` for
`Rep3Driver`). It is the only `VmDriver` method `Machine::run` never calls - witness extension has nothing
to reveal. `vm::witness::split_witness` does the split and the `public_inputs[0] == 1` sanity check;
it is the library's entire proving surface - assembling co-snarks' own `SharedWitness` from its output
is one caller-side struct literal, done in the tests and examples that actually prove rather than in
the library (see "Cargo features" above).

**The split index comes from the zkey, not from this compiler.**
`ConstraintMatrices::num_instance_variables` is circom's own count for the circuit being proved.
Re-deriving it from `Program::input_domains` would only be an approximation, because
`passes::mpc::domain` falls back to `Shared` whenever it cannot prove a signal public - harmless for
lowering (a missed optimization) but wrong as a split point, where being off by one silently proves a
different statement.

The recipe, end to end (`tests/proving.rs`):

```rust
let zkey = circom_types::groth16::Zkey::<Bn254>::from_reader(file, CheckElement::No)?;
let (matrices, pkey) = zkey.into();          // a standard snarkjs zkey - no convert-zkey-to-ark
let (public_inputs, witness) = split_witness(&mut driver, witness, matrices.num_instance_variables)?;
let shared = co_circom_types::SharedWitness { public_inputs, witness };
let proof = Rep3CoGroth16::prove::<_, CircomReduction>(&net0, &net1, &pkey, &matrices, shared)?;
Groth16::verify(&pkey.vk, &proof, &public_inputs[1..])?;
```

`co-groth16`'s `verify` is behind *its* non-default `verifier` feature, which is easy to miss.
`tests/proving.rs` wires up a `prove_and_verify_test!(...)` per circuit this compiler can compile,
each against its own checked-in zkey (`kats/proving/<name>.zkey`, from a locally-generated toy
powers-of-tau - fine for exercising plumbing, never for anything real; regenerate with
`scripts/gen-proving-artifacts.sh`). A test whose zkey is missing skips with a printed note rather
than failing, so `cargo test` stays green on a fresh clone before that script has run.

`tests/merces.rs` exercises the same recipe with a real zkey - too large to commit, and in a different
format: `inputs/zkey/<main>.arks.zkey` is `circom_types::groth16::ArkZkey<Bn254>`, ark-serialized
*uncompressed* (`ArkZkey::deserialize_with_mode(bytes, Compress::No, Validate::No)`, matching how
merces' own tooling produces it via `convert-zkey-to-ark --uncompressed`), not the snarkjs zkey format
`Zkey::from_reader` reads above - `ArkZkey::into_inner()` yields the same
`(ConstraintMatrices, ProvingKey)` pair either way, so everything below the read is identical.
`Validate::No` is deliberate: validating hundreds of MB of group elements costs far more than the proof
itself, and a genuinely bad zkey shows up immediately as a proof that fails to verify. The zkey is
gitignored (13-178 MB), so the test skips with a message rather than failing when it's absent - but
with it present, this is a real ceremony key over real protocol inputs, and the proof verifies.
`examples/merces.rs` runs this same recipe against the ceremony zkey (or an explicit zkey path, e.g.
`kats/proving/multiplier2.zkey` for a non-merces circuit), so the example demonstrates proving too,
not just witness agreement.

### Serialization (`vm/serialize.rs`)

`Program::write`/`read`: an 8-byte magic + `u32` version, `ark_serialize` for the one field-element
table (`constants`), and hand-rolled little-endian `byteorder` encoding for everything else (`Opcode`/
`Bank` are plain fieldless enums with no derive support to lean on) - the instruction stream is one
fixed 16-byte record per instruction (`u8` opcode + 3 bytes padding + three `u32`s). Round-tripped in
`vm::serialize::tests` against a program with a genuine MPC round, one with a precomputation site, and
one genuinely *staged* (two same-kind batches at different levels, so the format change below is covered
by more than a single-batch program).

`VERSION` is **2**. A version-1 program carries a batch table but no `Opcode::Precompute`
instruction - it assumes a machine that services every batch up front, which the current
`Machine::run` does not do. Reading a version-1 program under today's interleaved semantics would
silently service zero batches and return a plausible-looking wrong witness, so the version check in
`read` is the only thing between an old artifact and a bad answer. Site inputs
are also now encoded `(bank, slot)` like `stores`, since a site input may be a `Public` slot.

## Precomputation

`frontend/build.rs::handle_create_cmp_bucket` recognizes five gadget templates by name -
`Poseidon2`, `Num2Bits`, `IsZero`, `IsEqual`, `AliasCheck` - wherever one is instantiated, and cuts
it into a site the *runtime* computes out-of-band and injects, rather than compiling its body. This
is unconditional: it fires on the instantiated template's name regardless of what wraps it, and an
unrecognized name simply compiles as an ordinary template. `circuits/libs/taceo/precomputations.circom`
defines `TACEO_PRECOMPUTATION_<Name>` wrapper templates purely as a circom-side naming convention for
callers who want one - the compiler itself has no notion of a "wrapper"; a wrapper's body
(`out <== Gadget(...)(in);`) instantiates the gadget just like a bare call would, and recognition
fires the same way either time.

Recognizing these five gadgets cuts a subtree this compiler cannot compile at all -
`poseidon2_constants.circom`'s round-constant-table functions (`Instruction::Call`), `IsZero`'s
field inversion (`Div`), and `Num2Bits`' bit extraction (`ShiftR`/`BitAnd`) are all *inside* these
components, so cutting the subtree makes them irrelevant rather than blocking, without implementing
function calls or re-adding removed operators. **No vendored circuit is patched** -
`circuits/merces/` and `circuits/libs/` are byte-identical to upstream, which is what keeps them a
meaningful compile target rather than a fork that drifts.

The co-snarks MPC witness-extension VM has its own version of this convention
(`circom-mpc-vm/src/mpc_vm.rs`: once a component whose name starts with `TACEO_PRECOMPUTATION` has
all its inputs bound, its wrapped component's body is never run - a caller-supplied
`ComponentAcceleratorOutput` trace is written into the signal array instead, in positional order),
and merces (`~/repos/merces`, `crates/merces-core/src/circom_proof/cosnark.rs`) computes those traces
by hand, one MPC protocol operation at a time, specifically so witness extension doesn't pay a network
round per Poseidon2 call. **This crate's own VM does not keep that contract** - see "Sites are typed,
not opaque" below for what it does instead and why.

### Sites are typed, not opaque

`ir::PrecomputeKind` (`Poseidon2 { t }`, `Num2Bits { n }`, `IsZero`, `IsEqual`, `AliasCheck`) tells the
runtime what a site actually computes. `frontend/build.rs::handle_create_cmp_bucket` resolves the kind
once, from the instantiated template's name and arity, at the same point it already peeks `templates`
for `name`/`header`/`number_of_inputs`/`number_of_outputs`.

`IsEqual` is a thin wrapper over the `IsZero` gadget rather than a separate implementation, because
circomlib's `IsEqual` literally is one (`in[1] - in[0] ==> isz.in`). The subtraction is a free local op,
so it costs exactly what an `IsZero` batch of the same size costs. One detail worth stating because it is
easy to get backwards and produces a witness differing in exactly one position per site: the difference
is `in[1] - in[0]`, **not** the reverse - `out` is identical either way, but `isz.in` is a real witness
slot.

**No site has a `stage` field, and `Graph` has no stage table.** A stage is a derivation, not a runtime
name - unlike `RoundId`, which `Opcode::Reshare` carries and so must survive into the `Program`. A batch
index is minted by codegen itself, so nothing needs a stable IR-level name for it; codegen already
recomputes `Domain` rather than trusting a cached copy, for the same reason (a recomputed value cannot go
stale, a recorded one silently mis-schedules if a later pass touches node order); and `PrecomputeSite` is
frontend-derived circuit *shape*, not a scheduling decision. Practically, it also keeps hand-built codegen
tests from having to populate a table only a pass ever writes. `Graph::precompute_stages` is the extension
point for if/when the deferred non-ASAP scheduler makes stage a decision rather than a derivation.

`PrecomputeKind::expected_results()` cross-checks a site's real signal layout
(`num_outputs + num_intermediates`, from `compute_signal_spans` - see "The signal-span problem"
below) against a closed-form count, for every kind except `Poseidon2`: `Num2Bits { n }` is exactly
`n` (no intermediates - it has no subcomponents), `IsZero` is exactly `2` (`out`, then `inv`), and
`AliasCheck` is exactly `519` (derived directly from `circuits/libs/{aliascheck,compconstant}.circom`'s
own structure: `CompConstant`'s own 254 input signals + 1 output signal = 255, + 127 `parts` + 1
`sout`, then its child `Num2Bits(135)`'s own 1 input + 135 outputs = 136; `255 + 127 + 1 + 136 =
519`). This is **one more than merces' own `DEFAULT_ALIAS_TRACE`** (518) - that trace omits
`Num2Bits`' own input signal (`num2bits.in <== sout`, a second copy of `sout` circom still allocates
a real witness position for), which this compiler's independent signal-span accounting (cross-checked
against `circuit.c_producer.total_number_of_signals` in `tests/precomputation.rs::
signal_span_matches_independent_total`) doesn't let it skip. `IsEqual` is exactly `4`
(`[out, isz.out, isz.in, isz.inv]` - its own output plus the whole `IsZero` subtree, skipping the site's
two inputs).

`Poseidon2` also has a closed form, derived from `circuits/libs/taceo/poseidon2.circom`'s own signal
layout - see "Poseidon2 traces" below. `frontend/inline.rs`'s cross-check turns a mis-derived width
into a compile-time panic naming both numbers, instead of a silently wrong witness.

### Result slots: a compile-time-resolved destination, not a positional list

The recognized gadget component (e.g. `Poseidon2`, whether or not something wraps it) is the site, at
signal offset `o` with `num_inputs`/`num_outputs`/`num_intermediates`, and circom's own layout is
`[outputs at o][inputs at o+num_outputs][intermediates + subtree at o+num_outputs+num_inputs]` -
inputs are bound normally by whatever calls the gadget, slots `0..num_outputs` map to signals
`o..o+num_outputs`, slots `num_outputs..` to signals `o+num_outputs+num_inputs..`. Contrast with
co-snarks' VM, which takes a `Vec<ComponentAcceleratorOutput>` the caller supplies **in site
order**, one entry per site, and writes `result.intermediate.len()` values starting at each site's
intermediate region (not necessarily the region's full remaining span - see "Known gaps" for what
this leniency turned out to matter for). This compiler's codegen instead resolves every site's
destination once, at compile time (`site_result_base[site] + slot`, a fixed, non-recycled
`Shared`-bank slot range - see "Bytecode and the slot machine") - there is no positional list for a
caller to get out of order, and no injection point a caller supplies a provider through: codegen
groups sites into `PrecomputeBatch`es and `Machine::run_batch` calls the *driver's* matching gadget
method
(`VmDriver::poseidon2_traces`/`num2bits_traces`/`is_zero_traces`/`is_equal_traces`/`alias_check_traces`,
`vm/driver/mod.rs`) once per batch. This is exactly the batching merces performs by hand per protocol
operation (`Poseidon2::precompute_rep3(num_poseidon, ...)`), now derived by the compiler for the whole
circuit instead.

**Batches are keyed `(kind, stage)`, not `kind` alone** - the sites in a batch must be mutually
independent to be serviceable by one call, which is what a shared stage guarantees (see "The event axis").
Batching still does the work it exists to do: on `transfer_arity4_batch8`, **950 sites collapse into 24
driver calls**. `Graph::mpc_summary` reports `precompute_sites` and `precompute_batches` side by side so
that claim is falsifiable rather than asserted, and `tests/merces.rs` asserts the ratio on the real
circuits rather than an exact count, so the test tracks the claim and not today's scheduling arithmetic.

A site input may live in the `Public` bank, not only `Shared`: a circuit can pass a literal to a gadget, as
`circuits/merces/oblivious_vector/hash.circom` does
(`TACEO_PRECOMPUTATION_Poseidon2(4)([value, 0, r, commitDs()])` - two of those four fold to
`Op::Constant`). `PrecomputeBatch::input_slots` therefore carries `SiteInput { bank, slot }` and
`run_batch` promotes a `Public` slot before handing the batch to the driver.

`vm::gadgets` (plain unconditionally, rep3 behind the `rep3` feature) implements all five kinds, all of
them this compiler's own field arithmetic: `aliascheck` generalizes merces'
`alias_check_trace_helper_rep3` from one site to a batch and computes the real values in the 255 slots
merces zero-pads (see "Sites are typed, not opaque" above); `isequal` delegates to `iszero`; and
`poseidon2` derives its trace from the vendored circuit - see below.

A batch's per-site result count may be **shorter** than the site's reserved capacity - `Machine::
precompute` writes only a prefix of each site's slots (per site, not a flat prefix of the whole
batch, which would spill one site's results into the next site's region) and leaves the rest at
their zero default, mirroring the real co-snarks VM's own behavior.

Sites are numbered in the order encountered during inlining (deterministic single-threaded
traversal); this ordering has no runtime significance beyond being a stable, arbitrary key for
grouping into batches.

### Poseidon2 traces: derived from the circuit, not from an index table

`vm::gadgets::poseidon2` computes the signals `circuits/libs/taceo/poseidon2.circom` actually declares,
for every width the circuit defines (`t ∈ {2,3,4,8,12,16}`), with no dependency on any vendored index
table. `precomputation_poseidon2_test` passes in both `tests/circom_ir.rs` and `tests/rep3_vm.rs`.

**The layout rule, which is the load-bearing discovery.** circom lays out each component as
`[outputs][inputs][own intermediates, in source-declaration order][subcomponent subtrees]`, and
**sibling subcomponent subtrees are ordered by the *callee template's own definition order in the
source file*, not by the order their creating statements execute within the caller.** ("Instance id"
happened to track creation order for the first two cases below, which is why an earlier revision of
this doc described the rule that way - the third case shows definition order is the real rule, and
creation order is only a special case of it when the templates in question also happen to be defined
in that order.) Four consequences, all visible in a golden witness, and no other rule tried (source
order, first-use, alphabetical) fits all four:

- `FullRound` emits its `ExternalMatMulT` subtree *before* its `Sbox` subtree, despite instantiating
  `Sbox` first in source, because `ExternalMatMulT` is defined earlier in the file.
- `ExternalMatMulT`'s `t >= 8` branch emits its 4 `Acc(t/4)` subtrees *before* its `t/4`
  `ExternalMatMul4` subtrees, despite creating `mds[]` (the `ExternalMatMul4`s) before `accs[]` (the
  `Acc`s) in source: `template Acc(t)` is defined before `template ExternalMatMul4` in
  `poseidon2.circom`. This one was gotten backwards in an earlier revision of the gadget (see "Known
  gaps" history) - it silently produced a wrong witness for every `t >= 8` site (`t=16` only, among
  the widths this repo exercises) until the real merces circuits' golden-witness comparison caught it.
- `Poseidon2` emits all 8 `FullRound` blocks contiguously and only then all `PartialRound` blocks, so
  **layout order is not execution order** (the partial rounds run *between* the two full-round groups).
- Within one template, *same-definition* sibling instances keep their own creation order: the 8 full
  rounds are the first group's 4 then the second group's 4, and `accs[0..4]`/`mds[0..4]` are each in
  their own loop's index order.

Per-site result counts follow from the template structure, giving `expected_results()` its closed form:
`t=2 → 1509`, `t=3 → 2035`, `t=4 → 2698`, `t=8 → 5137`, `t=12 → 7431`, `t=16 → 9725`. For `t=3` that is
`2038` subtree signals minus the site's 3 inputs, and `1 + 6 + 2038 = 2045` is exactly the golden
witness's length.

The module is three separated concerns, so the 2035-slot layout exists in exactly one place (unlike
`gadgets/aliascheck`, which duplicates its much smaller layout between plain and rep3): an `Ops` trait
(the arithmetic backend, implemented for plain field elements and for rep3 shares), a **layer-major**
walker running every site in lock-step so a batch's s-boxes at one round are one call, and a single
`emit_site` emitter holding the ordering above.

**rep3: one round per s-box layer, not three.** `x²`, `x⁴`, `x⁵` are genuinely sequential as
multiplications - from `{x, x²}` a second round only reaches degree 4 - so a naive layer costs 3 rounds,
i.e. `3 · (8 + pr)` = 192 for `t=3`. Instead, with a fresh random `r` (and `r²..r⁵` prepared once per
batch in 3 rounds, independent of batch size), publish `y = x - r` in **one** round; `x = y + r` then makes
all three intermediates local linear combinations by binomial expansion. `y` is public and `r` uniform and
unknown, so nothing about `x` leaks. This is mpc-core's own `sbox_rep3_precomp` trick extended to also emit
`square` and `pow_4` - which is precisely why it composes with a *full* trace at no extra round cost, since
mpc-core only ever needed `x⁵`. Total per batch: `3 + (8 + partial_rounds(t))` rounds - 67 for
`t ∈ {2,3,4}`, 68 for `t ∈ {8,12,16}` - **independent of the number of sites**. The `r²..r⁵` prep
happens exactly once per batch, in `Rep3Ops::prepare_sboxes`, *not* inside `sbox_layer` itself - each
layer only slices a disjoint range out of that one pool. Measured, not just asserted, by
`vm::gadgets::poseidon2::tests::rep3_costs_three_plus_eight_plus_partial_rounds_independent_of_sites`
(needs the `round-counting` feature) via `vm::counting_net::CountingNet`.

The 22 constant tables in `vm/gadgets/poseidon2_constants.rs` are transcribed verbatim from
`poseidon2_constants.circom`, and a unit test re-extracts the hex from that circuit file at test time and
asserts equality - so they cannot silently drift from the circuit they describe.

**Verified, for every width merces exercises.** `t=3`'s ordering is witness-verified via
`precomputation_poseidon2_test`. `t=4` and `t=16` are witness-verified via `tests/merces.rs`: every
scenario's `PlainDriver` witness matches circom's own (`--O2`, the pinned fork) byte for byte, for both
server mains - and, since `transfer_arity4_batch1`'s co-groth16 proof also verifies, that is independent
confirmation the R1CS is satisfied, not just that a witness comparison happened to line up. `t=8`/`t=12`
remain order-*unverified*: their counts are order-independent and so trustworthy, and plain-vs-rep3
agreement is checked for all six widths, but nothing exercises their ordering against a real circom
witness. Generating `precomputation_poseidon2_t{8,12}_test` fixtures (or finding a real target circuit
that uses them) would close that.

### IR shape (`src/ir.rs`)

`Op::Precompute(PrecomputeId)` takes the site's input values as its node inputs (arity equals the
site's `num_inputs` - the one case `Op::arity()` can't answer without the site table, hence
`Arity::{Fixed, SiteInputs}` and why `Graph::verify`, not `Node::new`, checks it). One
`Op::PrecomputeResult(slot)` node per result slot hangs off the `Precompute` node as its sole input,
matching this IR's "single result per node" invariant the same way `docs/ARCHITECTURE.md`
prescribes for any future multi-output op. `Graph::precompute_sites: Vec<PrecomputeSite>` is the
side table `PrecomputeId` indexes into - each entry now also carries a `kind: PrecomputeKind` (see
"Sites are typed, not opaque" above). `Graph::gc` treats every `Op::Precompute` node as an
unconditional root: every result slot is already bound to a witness signal (so it's normally kept
anyway), but this is deliberate defense in depth - codegen groups sites into batches by kind, and
silently dropping a "dead" site would desynchronize every later same-kind site's slot range.

### Frontend (`frontend/build.rs`, `frontend/inline.rs`)

`GraphCompiler::handle_create_cmp_bucket` checks the *instantiated* template's name - the symbol a
`CreateCmpBucket` creates, never the enclosing template - against the five recognized gadget names.
When it matches, the component's body is never compiled: its `TemplateCodeInfo` is only *peeked*
(never removed from the shared `templates` map, unlike a normally-compiled template - a recognized
gadget's template is never inserted into `compiled_graphs` either, precisely so every repeated
instantiation keeps going through this same peek instead of the removed-on-first-compile path) for
its `name`/`header`/`number_of_inputs`/`number_of_outputs`. `name` is resolved to a `PrecomputeKind`
right here (`Poseidon2 { t: num_inputs }`, `Num2Bits { n: num_outputs }`, `IsZero`, `IsEqual`,
`AliasCheck`, or `None` for anything else, which falls through to the normal compile path), and a
`SubGraphInstance::Precomputed` carrying it is pushed instead of a compiled one.
`frontend/inline.rs::inline_precomputed` then does the three things "IR shape" above describes, plus
one more: it cross-checks `kind.expected_results()` against the real `num_outputs +
num_intermediates` for every kind with a closed form (a mismatch is a compile-time panic, not a
silently wrong witness).

One indexing subtlety worth recording: `TemplateOp::SubCmpInput`/`SubCmpOutput`'s `port` is the
gadget component's own *local signal index*, which - like every template - numbers outputs first,
then inputs (matching `TemplateOp::LocalSignal`/`LocalSignalWrite`). So input `k` of the site lives
at local signal `num_outputs + k`, not at `k` directly; only the output side is directly `0..
num_outputs`. This is easy to get backwards since the two look symmetric until you check where the
actual bucket-level indices land.

### The signal-span problem (`frontend/mod.rs::compute_signal_spans`)

`num_intermediates` (a recognized gadget component's own locally-declared signals *plus* every
signal belonging to everything it transitively instantiates) is the one quantity not sitting in a
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

### Generating and cross-checking the golden KATs and zkeys

`kats/*/witness*.wtns` were generated the same way for every fixture (real circom + a real witness
calculator), but with one non-obvious requirement: **the circom binary used must be built from this
crate's own pinned fork revision** (`circom-compiler`'s git dependency, `rev 1cc17fb`), not whatever
`circom` happens to be on `PATH`. Confirmed the hard way: a locally-installed `circom 2.2.2` and this
exact pinned revision (both built standalone, `cargo build --release --bin circom` in
`~/.cargo/git/checkouts/circom-*/1cc17fb/`) produce **different variable counts for the same circuit
and the same `--O` flag** (`244` vs `2045` for `precomputation_poseidon2_test` at what should be
equivalent settings) - the two forks' constraint-simplification-driven witness compaction disagrees,
even though this crate's own `total_number_of_signals`/`compute_signal_spans` accounting (sourced
from the *pinned* fork's crates) does not. The pinned fork's CLI also self-reports as `circom 2.2.0`
(`circom/src/main.rs`'s `VERSION` const, `env!("CARGO_PKG_VERSION")`) and rejects this repo's
`pragma circom 2.2.2;` circuits outright - patching that one const to `"2.2.2"` before rebuilding is
enough to unblock it, since `CompilerConfig::version` already tells the Rust API the same thing
(this doesn't ship anywhere; it's a one-line local patch to a vendored dependency purely to build a
matching CLI for fixture generation). `scripts/gen-proving-artifacts.sh` (the zkeys in
`kats/proving/`) and `scripts/gen-merces-artifacts.sh` (the `.wtns` fixtures and merces' own R1CS)
both carry this same requirement in their own prerequisite comments.

`kats/precomputation_{poseidon2,num2bits,iszero,aliascheck}_test/` keep their `input*.json` but have
no `witness*.wtns`: `tests/proving.rs`'s prove+verify tests are their oracle instead, per the
project-wide default (see "Proving" above) - a verifying proof checks the witness against the R1CS
itself, which subsumes a witness-length comparison and then some. (`prove_and_verify`'s own
`program.signal_to_witness.len() == num_instance_variables + num_witness_variables` assertion does
still confirm the lengths agree at full `--O2` for all four, for what it's worth - there was no
compaction mismatch left to route around by the time this repo dropped every simplification level
but `--O2`.)

## Known gaps

- **Batches that are provably independent still run as sequential driver calls, and so does a
  same-level reshare round alongside them.** Two `(kind, stage)` batches at the same stage but
  different kinds (a Poseidon2 `t=4` batch and a `t=16` batch, say) are exactly the case "The event
  axis" proves mutually independent, and a same-level reshare round is independent of both by the
  same argument - yet `Machine::run` issues each as its own `VmDriver` call, one after another,
  paying the sum of their round counts where the max would do. `VmDriver` is fully synchronous
  (`vm::driver::mod`), so there is no way to overlap them today. Fixing it means a split-phase
  (issue/collect) or async `VmDriver`; the ALAP/window scheduling already deferred in
  `passes::mpc::level` (see "Deliberately deferred" under "The event axis") is the other half of the
  same story - both would need a cost model over batch services that does not exist yet.

- **Only `Add`/`Sub`/`Mul` are supported at runtime.** Every other circom operator is a typed
  `Unsupported::Operator`/`NonConstantOperator` error (see "`Op<F>` is deliberately narrow" above).
  This is a large, deliberate step back in coverage, made to keep the runtime core small while pass
  infrastructure and bytecode codegen are built. The circuits that reach `Num2Bits`/`BinSum`/
  `BinSub`'s `(in >> i) & 1`-style bit extraction on a genuine circuit input (`mux1_1`,
  `binsum_test`, `binsub_test`, `lessthan`, `sum_test`, and most of `circuits/`) cannot be saved by
  any amount of compile-time folding.

  **`tests/circom_ir.rs` wires up only the circuits that actually pass.** The fixtures themselves
  all remain in `circuits/` and `kats/` - re-enabling one is a single macro line once its blocker is
  gone - and *this* section is the worklist. Re-adding
  `Div`/`IntDiv`/`Pow`/`ShiftL`/`ShiftR`/`BitOr`/`BitAnd`/`BitXor` as real ops is the most-requested
  next step; see "Real-world target circuits" below for why the merces circuits themselves no longer
  block on it (precomputation recognition routes around it for every recognized gadget call).
- ~~**The two-level-subcomponent-nesting wrong-witness gap is currently masked, not fixed.**~~
  **Found and fixed** (`frontend/inline.rs::inline_sub_graph_instance`): a `SubGraphInstance`'s own
  `signal_offset` is *father-relative* (circom's own doc comment on `CreateCmpBucket::signal_offset`:
  "with respect to the start of the father's signals"), so placing a subcomponent's signals requires
  adding the *enclosing* template's own absolute offset - which inlining never did. That's invisible
  at depth 2 (main instantiates a leaf directly: the father is main, whose own absolute offset is 0,
  so father-relative and globally-absolute coincide by construction) and silently wrong at depth 3+
  (main instantiates a mid template that itself instantiates a leaf): the leaf's signals land at
  whatever unrelated position the unadjusted low offset happens to name elsewhere in the flat witness.
  `merces`'s server mains are 4+ templates deep (`TransferBatchedCompressedArity4 ->
  TransferBatchedArity4 -> DepositWithdrawTransferArity4 -> MerkleRootArity4/Commit1/Commit2 -> ...`)
  and were producing an almost-entirely-wrong witness before this fix (rep3-vs-plain still agreed,
  since that only checks internal cross-consistency - it took a real circom golden witness to catch
  it). `greaterthan`, `greatereqthan`, `lesseqthan`, `mux2_1`, `mux3_1`, `mux4_1` (nesting a
  subcomponent inside another nested subcomponent, e.g. `GreaterThan -> LessThan -> Num2Bits`) are the
  same shape and were very likely hitting the same bug, masked by `Num2Bits`'s `BITAND` blocking
  first - **re-test these six once shift/bitand return**, since this fix was verified against merces
  and the offset-probe circuits, not against these specific ones.
- **`SizeOption::Multiple`** (a bulk array copy spanning more than one component instance) is a
  typed `Unsupported::Instruction` error, not silently mishandled - not needed by any circuit
  exercised so far. `handle_store_bucket`/`handle_load_bucket` do handle a single-instance bulk copy
  (`inner.in <== a;`, or any anonymous-component call with an array argument), branching on
  `context.size` to do `size` element-wise reads/writes at consecutive addresses
  (`GraphCompiler::{read,write}_value_at`, `handle_bulk_store_bucket`).
- `get_constant_value` (used for array/signal/component address computation, not signal values)
  resolves the dedicated `MulAddress`/`AddAddress`/`ToAddress` operators, a directly-resolved
  `Op::Constant`, plain `Add`/`Sub`/`Mod` chains (circom sometimes routes address arithmetic through
  these instead of the dedicated `*Address` ones - reverse indexing `arr[N-1-i]`, modular
  round-table indexing `arr[i % n]`), and a variable built via `var = var + 1` (a circom-internal
  loop-shadow counter kept in lockstep with, but stored separately from, the loop's own induction
  variable -
    the latter is canonicalized to a fresh `Op::Constant` every iteration by
    `unroll.rs::add_induction_variable_node`, the former isn't) resolves to a genuine `Op::Add` node
    that is nonetheless a compile-time constant at every iteration. `GraphCompiler::eval_constant_node`
    (see "Where compile-time folding lives" above) evaluates it. This is what lets
    `ExternalMatMulT`/`Sbox`/`FullRound`/`PartialRound` (from `@taceo/circom-lib`'s Poseidon2) and
    both merces server-side mains compile at all - they fail only on the function-call gap below.
- **`Instruction::Branch` is supported only for compile-time-constant conditions.**
  `frontend/build.rs::handle_branch_bucket` folds the condition and lowers just the taken arm, so the
  untaken arm's contents are irrelevant. Real circom needs this constantly: `merkle_root_4.circom`'s
  `if (i == 0)` inside an unrolled loop, and `compression.circom`'s `if (remaining > T - 1)` where
  `remaining = N - absorbed` - both compile-time. It reuses `eval_constant_node`, the same recursive
  `Add`/`Sub`/`Mul` folder address computation uses, because this build pass deliberately doesn't fold
  arithmetic (that is `passes::const_fold`'s job, much later), so a `var` computed from constants is a
  real `Op::Sub` node here even though its value is fixed. `fold.rs::fold_condition` handles the
  comparison and boolean operators, which `fold_binary` does not - those return a `bool`, are never
  lowered to a node, and have no runtime counterpart at all.

  A **non**-constant condition remains a clean `Unsupported::Instruction` error, and structurally has
  to: `ir::Op` is only `Add`/`Sub`/`Mul`, so there is no select/mux op to arithmetize a secret-dependent
  branch into. Supporting it means re-adding the operator surface, not extending that function. This is
  what `IsZero`'s `inv <-- in!=0 ? 1/in : 0` hits, and why unconditional gadget recognition (see
  "Precomputation") rather than branch support is what lets merces' bare `IsEqual` compile.
  `tests/frontend.rs::non_constant_branch_condition_is_a_typed_error` pins the error path;
  `control_flow` in `tests/circom_ir.rs` pins the folded path against a golden witness.
- `Instruction::Call`/`Return` (unconstrained functions) remain entirely unimplemented - a clean
  `Unsupported::Instruction` error naming the call and line, not a panic. This is why
  `poseidon_hasher1.circom` (calls a helper function) doesn't compile.
- ~~`SimplificationLevel::O1` panics on this crate's pinned circom fork~~ **Resolved by removing every
  level but full `--O2`.** Upstream circom's own constraint simplification is no longer configurable
  at all: `src/frontend/mod.rs`'s `BuildConfig` hardcodes `no_rounds: usize::MAX, flag_s: false,
  flag_f: false`, circom's `--O2round` with an unbounded round count. `O1` was already unusable
  (`constraint_list::constraint_simplification` hit `attempt to subtract with overflow` on every
  circuit tried, including trivial ones) and `O0` existed only for four precomputation-gadget
  circuits whose golden `.wtns` happened to need it (see "Generating and cross-checking the golden
  KATs" above) - those fixtures are gone, replaced by `tests/proving.rs`'s prove+verify tests, which
  turn out to pass at full `--O2` for all four with no compaction mismatch to route around.
- ~~Only Poseidon2 `t=3`'s trace *ordering* is verified against a real circom witness~~ **`t=4` and
  `t=16` are now also witness-verified**, via the real merces circuits rather than a synthetic KAT -
  see "Poseidon2 traces". This is what caught the `Acc`-vs-`ExternalMatMul4` ordering bug in the same
  section. `t=8`/`t=12` remain order-unverified (their counts and plain-vs-rep3 agreement are checked,
  same as always, but nothing exercises their real circom ordering) - see "Where this is headed".
- ~~The merces end-to-end proof has not been run against a real zkey.~~ **It has, with real protocol
  inputs.** `inputs/` holds real merces protocol values (not placeholders) for both server mains, 4
  scenarios each; `inputs/zkey/<main>.arks.zkey` holds the merces ceremony proving keys. Every
  scenario's witness matches circom's own (`--O2`) byte for byte, and every scenario's co-groth16
  proof verifies, for both mains - `transfer_arity4_batch1_all_scenarios_prove_and_verify` runs by
  default (skipping cleanly if the gitignored zkey is absent), the `batch8` equivalent is `#[ignore]`d
  for its cost. This closed both this gap and the Poseidon2 `t=4`/`t=16` ordering gap above at once,
  since a verifying proof needs both the witness *and* the R1CS to agree with circom's.

## Real-world target circuits

`circuits/merces/` vendors three production circuits from `~/repos/merces/circom`
(`transfer_arity4_batch1`, `transfer_arity4_batch8`, `transfer_client_compressed` - a Poseidon2/
BabyJubJub-based private-transfer system) plus the six `@taceo/circom-lib` files and ten circomlib
files they transitively need (`circuits/libs/taceo/`, `circuits/libs/`).

**The two server mains compile and run, with no vendored circuit patched, against real protocol
inputs.** `transfer_arity4_batch1` and `transfer_arity4_batch8` go all the way through parse -> lowering
-> codegen -> witness extension, under both `PlainDriver` and real 3-party rep3, with the two witnesses
agreeing, matching circom's own witness (`--O2`, the pinned fork) byte for byte, and - with the ceremony
zkey present - producing a co-groth16 proof that verifies (`tests/merces.rs`). Shape, for scale:

| | rounds | reshare elements | widest round | sites | driver calls | instructions | witness |
|---|---|---|---|---|---|---|---|
| `transfer_arity4_batch1` | 26 | 642 | 280 | 119 | 19 | 1 943 | 17 545 |
| `transfer_arity4_batch8` | 96 | 5 136 | 2 240 | 950 | 24 | 15 363 | 139 229 |

Two things worth reading off that table. Precomputation batching is doing real work - 950 sites into 24
driver calls. And `batch8` is 8x the transactions of `batch1` for only ~3.7x the rounds, which is round
batching: independent products across the 8 slots merge instead of serializing. `benches/witness_extension.rs`
measures both against `PlainDriver`, where rep3 throughput *improves* from batch1 to batch8 for the same
reason.

Features these circuits are load-bearing for:

1. The event axis (`passes/mpc/level.rs`), because these circuits' Poseidon2 sites chain through
   secret multiplications - see "Precomputation".
2. `Bank::Public` site inputs, for `hash.circom`'s literal gadget arguments.
3. Constant-condition `Instruction::Branch` - see "Known gaps".
4. Unconditional precomputation recognition, for `merkle_root_4.circom`'s unwrapped `IsEqual` call
   (`Arity4CMux`, unrecognized, compiles as an ordinary template and gets round-batched instead).

### Real protocol inputs (`inputs/`)

Inputs come from `inputs/<main>_<scenario>.json` - real merces protocol values, not placeholders: 4
scenarios per server main (`deposit`/`withdraw`/`invalid_withdraw`/`transfer` for `batch1`;
`full_batch`/`partial_batch`/`multi_withdraw`/`invalid_slot` for `batch8`), baked into the binary via
`include_str!` in `src/fixtures.rs` (`MERCES_SCENARIOS`). Circom-style named JSON, decimal strings,
nested arrays flattened row-major (circom's own multi-dimensional signal numbering) by
`fixtures::from_input_json`. See that module's doc for the `===` constraint families these values
satisfy - including the root-linking constraint (`server.circom:159`) that only a `transfer`/mixed-batch
scenario with a genuine Merkle setup can satisfy, which no placeholder generator ever could.

`scripts/gen-merces-artifacts.sh` compiles each main once (`--O2`, the pinned fork) and, for every
scenario file, generates circom's own witness and cross-checks it against the R1CS
(`snarkjs wtns check`) - the external oracle for that root-linking constraint, since nothing in this
crate can check it. The proving key is separate again: `inputs/zkey/<main>.arks.zkey`, the merces
ceremony proving key (ark-serialized, uncompressed, `circom_types::groth16::ArkZkey`) - too large to
commit (13-178 MB) or regenerate here, so it's gitignored and the proving tests skip cleanly without
it.

### `transfer_client_compressed` is still out of reach

Unlike the server mains, the client main's blockers are the *deliberately removed operator surface*,
which precomputation recognition cannot route around:

- a bare `IsZero` at `circuits/libs/escalarmulany.circom:143`, reached via `encryption.circom`'s
  `BabyJubJubScalarMulBits` -> `EscalarMulAny(251)`;
- bare `Num2Bits` at `taceo/babyjubjub.circom:210` (`BabyJubJubIsInFr`) and `compconstant.circom:69`;
- genuine non-constant field `Div` in `circuits/libs/montgomery.circom` (five sites), reached through
  `EscalarMulAny`/`EscalarMulFix`.

Unconditional recognition does cut the two `Num2Bits` sites, so the gap is narrower than the operator
list above suggests, but `montgomery.circom`'s divisions still need `Op::Div` to exist.
`tests/merces.rs::client_main_is_still_unsupported`
holds the line: it must fail with a *typed* error, never a panic, and it panics loudly if the circuit ever
starts compiling so that the test gets promoted rather than quietly rotting.

## Why `rustc-hash` instead of `intmap`/`std::collections::HashMap`

`FxHashMap`/`FxHashSet` (from the `rustc-hash` crate) replaced both `intmap::IntMap` and
`std::collections::HashMap` everywhere in the compiler. Two reasons:
1. Speed — `rustc-hash`'s FxHash is a fast non-cryptographic hash designed for exactly this kind of
   compiler-internal small-key map.
2. **Determinism.** `std::HashMap` is randomly seeded per-process; iterating it produces a
   different order on every run. `FxHashMap` is seedless, so a given input circuit always produces
   byte-identical compiler output - important here because nothing in this compiler may let a map's
   iteration order leak into the final node sequence undetected.

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
- **`vm::driver::plain::PlainDriver` (paired with `vm::Machine`) is the KAT oracle, not a product.**
  Don't over-invest in it beyond being correct and validating changes; it is not a second product
  alongside the rep3 driver.
- **Share kind is an external analysis, never a set of per-op variants.** A 37-variant
  share-specialized mirror of `ir::Op` (one variant per binary op × per combination of
  public/arithmetic-share/binary-share operands) is a real trap: it is a node-traverser, not a step
  toward a bytecode VM, and it keeps every IR change synchronized against both the variant count and
  a share-kind match the VM never uses. Domain (`Public`/`Shared`/`Local`) is instead an external
  analysis (`passes/mpc/domain.rs`) consulted by a lowering pass, never baked into which `Op` variant
  a node uses. **This is not the same shape as `Op::MulLocal`/`Op::Round`/`Op::RoundResult`** (see
  "MPC lowering" above): those three model round *structure* - a batched network round is inherently
  multi-output, which this IR forbids regardless of MPC, the same reason `Op::Precompute`/
  `Op::PrecomputeResult` exist - not share kind. Reintroducing a
  `MulSecretPublic`/`AddSecretSecret`-style variant explosion would repeat the mirror-enum mistake;
  adding a new *structural* op for a genuinely new multi-output shape (as `Precompute` already
  established the precedent for) would not. (An earlier revision of this crate built exactly this
  mirror-enum shape - `mpc_ir::Op`, `MpcInterpreter`, `passes/mpc_ir_translation.rs` - find it at
  commit `5cdc695` if this reasoning ever needs re-deriving from the code itself.)

## Where this is headed (not yet built)

1. Re-add the operator surface removed in this cut (`Div`, `IntDiv`, `Pow`, `ShiftL`/`ShiftR`,
   `BitOr`/`BitAnd`/`BitXor`) as real `ir::Op` variants, and implement `Instruction::Call`/`Return`
   plus non-constant `Branch`. This is not what blocks the merces server mains - they compile without
   it, via unconditional precomputation recognition (see "Precomputation"). It is what blocks
   `transfer_client_compressed` (`montgomery.circom`'s non-constant `Div`) and most of the `circuits/`
   KAT fixtures. Non-constant `Branch` additionally needs a select/mux op to arithmetize into, which
   does not exist and is a design decision in its own right.
2. Conversion minimization (cancel `B2A(A2B(x))`, sink conversions past free linear ops) and open
   sinking. Both need `Div`, comparisons, or bitwise ops to exist first - none do (see "Known
   gaps") - so there's nothing to convert or sink yet; `RoundKind::Open` and a future `Binary` domain
   are the extension points, deliberately not stubbed out ahead of a real producer. See "MPC
   lowering" above.
3. ~~Generate `precomputation_poseidon2_t{4,16}_test` golden KATs with the pinned circom fork, to
   close the last unverified assumption in the Poseidon2 layout.~~ **Closed, by other means**: the real
   merces circuits' golden-witness comparison and passing proof (`tests/merces.rs`) verify `t=4` and
   `t=16` directly, on a larger and more representative circuit than a synthetic KAT would have been -
   see "Known gaps" and "Poseidon2 traces". `t=8`/`t=12` remain unverified in the same sense; a
   `precomputation_poseidon2_t{8,12}_test` KAT (or a real target circuit using those widths) would
   close that.
