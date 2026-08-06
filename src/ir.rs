//! The single value-graph IR shared by every stage of the compiler.
//!
//! A [`Graph`] is a flat, topologically ordered list of [`Node`]s. There is no separate "wire"
//! address space: a node's position in the graph *is* the identifier of the single value it
//! produces (its [`ValueId`]).

use ark_bn254::Fr;

/// Identifies a node in a [`Graph`] and, equivalently, the single value it produces.
///
/// `ValueId(i)` always refers to `graph.nodes[i]`. There is no separate wire allocator: a value's
/// identity *is* its producer's position in the flat node list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ValueId(u32);

impl ValueId {
    pub(crate) fn new(index: usize) -> Self {
        Self(u32::try_from(index).expect("graph has more than u32::MAX nodes"))
    }

    pub(crate) fn index(self) -> usize {
        self.0 as usize
    }
}

/// A global circuit signal index (i.e. an index into circom's own flat signal numbering, after
/// any per-instance offset has already been resolved).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SignalIdx(pub(crate) u32);

impl SignalIdx {
    pub(crate) fn new(index: usize) -> Self {
        Self(u32::try_from(index).expect("signal index does not fit into u32"))
    }

    pub(crate) fn index(self) -> usize {
        self.0 as usize
    }
}

/// Identifies one entry in [`Graph::precompute_sites`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PrecomputeId(u32);

impl PrecomputeId {
    pub(crate) fn new(index: usize) -> Self {
        Self(u32::try_from(index).expect("more precompute sites than fit into u32"))
    }

    pub(crate) fn index(self) -> usize {
        self.0 as usize
    }
}

/// Identifies one batched rep3 network round (currently always a reshare).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RoundId(u32);

impl RoundId {
    pub(crate) fn new(index: usize) -> Self {
        Self(u32::try_from(index).expect("more rounds than fit into u32"))
    }

    pub(crate) fn index(self) -> usize {
        self.0 as usize
    }
}

/// One batched MPC network round (a reshare): every [`Op::MulLocal`] value that feeds this round's
/// [`Op::Round`] node reshares in the same message (`len` slots, one [`Op::RoundResult`] each).
#[derive(Debug, Clone)]
pub(crate) struct RoundDesc {
    pub(crate) len: usize,
    /// This round's position in the circuit's **network-event** order - reshare rounds and
    /// precomputation batch services interleaved on one axis (see `passes::mpc::level`). Not the
    /// same as multiplicative depth. Diagnostic only, not consulted structurally.
    #[allow(dead_code)]
    pub(crate) level: usize,
}

/// The effect of MPC lowering, as reported by [`Graph::mpc_summary`]. Diagnostic - logged under
/// `tracing` and asserted in `tests/mpc_lowering.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MpcSummary {
    pub rounds: usize,
    pub reshare_elements: usize,
    pub min_slots_per_round: Option<usize>,
    pub max_slots_per_round: Option<usize>,
    pub local_muls: usize,
    pub public_muls: usize,
    pub precompute_sites: usize,
    /// How many batch services those sites actually cost - normally one per
    /// `(kind, stage, domain)` group, with an additional split when an early consumer closes a
    /// batch's placement window. Public services run locally; shared services call the MPC driver.
    /// `precompute_batches < precompute_sites` makes the batching claim falsifiable rather than
    /// asserted.
    pub precompute_batches: usize,
    /// Batch services that require an MPC driver call rather than local public evaluation.
    pub shared_precompute_batches: usize,
}

/// Which precomputation gadget a [`PrecomputeSite`] runs. Resolved from the instantiated
/// template's name in `frontend/build.rs::handle_create_cmp_bucket`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrecomputeKind {
    /// Poseidon2 permutation over a `t`-element state (`t` in `{2, 3, 4, 8, 12, 16}`).
    Poseidon2 { t: usize },
    /// Bit decomposition of one field element into `n` bits.
    Num2Bits { n: usize },
    /// `1` iff the input is zero, plus the field-inversion helper trace.
    IsZero,
    /// Proves a 254-bit decomposition is a canonical (non-aliased) representative.
    AliasCheck,
    /// Declassifies `n` values: opens them to every MPC party in the clear if they were `Shared`,
    /// or is the identity if they were already `Public`. A genuine MPC event, not deterministic
    /// local work - see `passes::mpc::level`'s re-keyed `PrecomputeResult` rule for how a `Reveal`
    /// site still charges a network level exactly when its own input was `Shared`, even though its
    /// result's *domain* is unconditionally `Public`.
    Reveal { n: usize },
}

impl PrecomputeKind {
    /// How many result slots (`num_outputs + num_intermediates`) this gadget produces. Every kind
    /// has a closed form independent of its own implementation - `Graph::verify` and
    /// `frontend/inline.rs` cross-check it against the circom-derived count from
    /// `frontend/mod.rs::compute_signal_spans`, so a trace-layout mistake is a compile-time error
    /// instead of a silently wrong witness.
    pub fn expected_results(self) -> Option<usize> {
        match self {
            // Mirrors the template structure of `circuits/libs/taceo/poseidon2.circom`:
            //   Poseidon2(t) = [out[t]][in[t]][state[(9+pr)][t]]
            //                  + ExternalMatMulT(t) + 8 x FullRound(t) + pr x PartialRound(t)
            // and result slots are every signal except the site's own `t` inputs. Kept here rather
            // than in `vm::gadgets` so the dependency direction stays `vm -> ir`; that module's
            // `result_slots` is unit-tested against this for every supported width.
            PrecomputeKind::Poseidon2 { t } => {
                // `amount_partial_rounds` in poseidon2_constants.circom.
                let pr = if t <= 4 { 56 } else { 57 };
                // Acc(n) = [out][in[n]][sums[n]]
                let acc = |n: usize| 2 * n + 1;
                // ExternalMatMul2/3/4 - the fixed-width leaves.
                let emm_leaf = |t: usize| match t {
                    2 => 5,
                    3 => 7,
                    _ => 18,
                };
                // ExternalMatMulT(t) = [out[t]][in[t]] + subtree. For t >= 8 the subtree is
                // (t/4) x ExternalMatMul4 followed by 4 x Acc(t/4).
                let emmt = |t: usize| match t {
                    2..=4 => 2 * t + emm_leaf(t),
                    _ => {
                        let m = t / 4;
                        2 * t + m * 18 + 4 * acc(m)
                    }
                };
                // InternalMatMulT(t) = [out[t]][in[t]] + a nested InternalMatMul2/3 for those
                // widths, else the own `acc` intermediate plus an Acc(t) subtree.
                let immt = |t: usize| match t {
                    2 => 2 * t + 5,
                    3 => 2 * t + 7,
                    _ => (2 * t + 1) + acc(t),
                };
                // FullRound  = [out][in][RC][linear_layer][sbox] (5t) + ExternalMatMulT + Sbox(t),
                //              where Sbox(t) = [out[t]][in[t]] + t x Sbox_e(4) = 6t.
                let full = 5 * t + emmt(t) + 6 * t;
                // PartialRound = [out[t]][in[t]][RC][linear_layer][sbox] (2t+3)
                //                + Sbox_e(4) + InternalMatMulT.
                let partial = (2 * t + 3) + 4 + immt(t);
                let total = 2 * t + (9 + pr) * t + emmt(t) + 8 * full + pr * partial;
                Some(total - t)
            }
            // n output bits, no intermediates.
            PrecomputeKind::Num2Bits { n } => Some(n),
            // 1 output (is_zero) + 1 intermediate (the masked-inverse helper).
            PrecomputeKind::IsZero => Some(2),
            // No outputs. AliasCheck's subtree is its CompConstant subcomponent: 254 input-signal
            // copies + 1 output = 255, + 127 `parts` + 1 `sout`, + CompConstant's child
            // Num2Bits(135) (1 input + 135 bits = 136). Cross-checked directly against
            // `circuits/libs/{aliascheck,compconstant}.circom`.
            PrecomputeKind::AliasCheck => Some(255 + 127 + 1 + 136),
            // n outputs, no intermediates - a `TACEO_REVEAL(n)` site's own signal layout is exactly
            // `[in[n]][out[n]]`, and result slots skip the site's own inputs.
            PrecomputeKind::Reveal { n } => Some(n),
        }
    }
}

/// One recognized-gadget component instance: the shape the runtime must supply a trace for.
#[derive(Debug, Clone)]
pub struct PrecomputeSite {
    /// Which gadget this site runs, and (for the parameterized ones) its width.
    pub kind: PrecomputeKind,
    /// The gadget template's concrete header (parameterized name), e.g. `"Poseidon2_3"` -
    /// diagnostics only.
    pub header: String,
    pub num_inputs: usize,
    pub num_outputs: usize,
    pub num_intermediates: usize,
}

/// One operation of the value graph. Every variant produces exactly one value.
///
/// Deliberately narrow: only the linear/multiplicative core (`Add`/`Sub`/`Mul`) is a runtime op.
/// Everything else circom can express (`/`, `\`, `**`, shifts, bitwise ops, comparisons, ...) is
/// either rejected outright or, where all its operands are compile-time constants, folded away
/// before it ever reaches this enum (`frontend::fold`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Op {
    /// Reads a circuit input signal.
    Input(SignalIdx),
    /// A field constant.
    Constant(Fr),
    Add,
    Sub,
    Mul,
    /// Invokes an externally-supplied precomputation site (see [`PrecomputeSite`]), used for
    /// `TACEO_PRECOMPUTATION_*`-wrapped components. Arity equals the referenced site's
    /// `num_inputs`, which is validated when the graph invariants are checked.
    /// This node's own value is never read directly, only through [`Op::PrecomputeResult`] nodes
    /// that reference it.
    Precompute(PrecomputeId),
    /// Reads one result slot of the [`Op::Precompute`] node that is this node's sole input. Slot
    /// `0..num_outputs` are the wrapped component's outputs; `num_outputs..` are its subtree's
    /// intermediate signals, in flat circuit order.
    PrecomputeResult(u32),
    /// The free, local half of a secret x secret multiplication: `a*b + mask`, computed without a
    /// message (rep3's `local_mul_vec`). Not a valid share on its own - only a rep3 additive-3
    /// sharing (still sound to add and scale) until reshared via the [`Op::Round`] it feeds.
    MulLocal,
    /// One batched network round: arity equals the round's recorded length, which is validated when
    /// the graph invariants are checked, with one input per [`Op::MulLocal`] value being reshared
    /// together. This node's own value is never read directly, only through the
    /// [`Op::RoundResult`] nodes that reference it.
    Round(RoundId),
    /// Reads one slot of the [`Op::Round`] node that is this node's sole input - the reshared
    /// (`Shared`-domain) result of that slot's local product.
    RoundResult(u32),
}

impl Op {
    /// The number of operands this op reads, where that is context-free. `None` for
    /// [`Op::Precompute`] (arity is its site's `num_inputs`) and [`Op::Round`] (its round's `len`);
    /// only [`Graph::verify`] can check those, since it alone has the tables.
    pub(crate) fn fixed_arity(&self) -> Option<usize> {
        match self {
            Op::Input(_) | Op::Constant(_) => Some(0),
            Op::Add | Op::Sub | Op::Mul | Op::MulLocal => Some(2),
            Op::PrecomputeResult(_) | Op::RoundResult(_) => Some(1),
            Op::Precompute(_) | Op::Round(_) => None,
        }
    }

    /// Whether this op is free of side effects a rewrite pass must preserve exactly once each -
    /// `false` for the precomputation ops, since merging or duplicating a site would change how
    /// many traces the runtime has to supply, and
    /// `false` for the MPC round ops for the same reason: `Op::MulLocal` consumes a fresh mask per
    /// evaluation, so merging two occurrences would desync a round's slot count from what the
    /// runtime's `local_mul_vec`/`reshare_vec` calls actually produce. Everything else is pure
    /// arithmetic or a plain read, safe to deduplicate or reorder freely.
    pub(crate) fn is_pure(&self) -> bool {
        !matches!(
            self,
            Op::Precompute(_)
                | Op::PrecomputeResult(_)
                | Op::MulLocal
                | Op::Round(_)
                | Op::RoundResult(_)
        )
    }
}

/// A single node in the graph. `inputs` references other nodes by [`ValueId`]; every reference
/// must point strictly earlier in the graph, as enforced by graph verification.
#[derive(Debug, Clone)]
pub struct Node {
    pub op: Op,
    pub inputs: Vec<ValueId>,
}

impl Node {
    pub(crate) fn new(op: Op, inputs: Vec<ValueId>) -> Self {
        if let Some(arity) = op.fixed_arity() {
            debug_assert_eq!(
                inputs.len(),
                arity,
                "node input count does not match op arity"
            );
        }
        Self { op, inputs }
    }
}

/// What a [`Graph::rewrite`] callback decides to do with one original node, in original graph
/// order.
pub(crate) enum RewriteAction {
    /// Emit the node unchanged (its `inputs`, as seen by the callback, are already remapped to
    /// their new ids).
    Keep,
    /// This value is an alias for an already-emitted value; no node is pushed for it. `target`
    /// must be a value already emitted earlier in this rewrite (i.e. a "new-space" [`ValueId`] -
    /// the same space the callback's `inputs` and `already_emitted` are in).
    ReplaceWith(ValueId),
    /// Emit a different node in its place. `node.inputs` must reference only already-emitted
    /// (new-space) values.
    Emit(Node),
    /// Emit several nodes in its place; the *last* one is this original node's value (what later
    /// references to it resolve to). Each node's `inputs` may reference any already-emitted value,
    /// including the earlier nodes in this same `Vec` (they are pushed in order, so they are
    /// "already emitted" from the next one's point of view). Used by passes that expand one node
    /// into a small fixed-shape group - e.g. `passes::mpc::mul_split` splitting a secret `Mul` into
    /// its local part, a singleton round, and that round's result.
    EmitMany(Vec<Node>),
}

/// A list of circuit inputs: (name, witness offset, size).
pub type InputList = Vec<(String, usize, usize)>;

/// The compiled, flattened circuit: one value graph plus the metadata needed to feed it inputs
/// and read back a witness.
#[derive(Clone)]
pub struct Graph {
    nodes: Vec<Node>,
    /// Circuit-level sinks: which signal each output value is written to. Every subcomponent's
    /// input and output signal is also recorded here (not just main's declared outputs), because
    /// circom's witness vector addresses every signal in the circuit, not only main's I/O.
    outputs: Vec<(SignalIdx, ValueId)>,
    /// Every `TACEO_PRECOMPUTATION_*`-wrapped component encountered while inlining, in the order
    /// encountered - that order *is* the trace order the runtime must supply results in.
    precompute_sites: Vec<PrecomputeSite>,
    /// Every batched MPC network round, indexed by [`RoundId`]. Empty until `passes::mpc` lowers
    /// the graph.
    rounds: Vec<RoundDesc>,
    /// Whether MPC lowering has run. [`Graph::verify`] rejects MPC ops in a not-yet-lowered graph;
    /// pass unit tests build plain graphs by hand without running the whole pipeline.
    lowered: bool,
    pub signal_to_witness: Vec<usize>,
    pub input_list: InputList,
    pub public_inputs: Vec<String>,
    /// Input names every MPC party holds in cleartext, even though they are not SNARK-public. A
    /// genuine declassification, supplied by `CompilerConfig::mpc_public_inputs` - never inferred.
    /// Kept separate from `public_inputs`, which remains the correct source for the SNARK
    /// statement split (see `vm::witness`).
    pub mpc_public_inputs: Vec<String>,
    pub num_inputs: usize,
    pub num_outputs: usize,
    pub num_signals: usize,
}

impl Graph {
    /// Builds a fresh, not-yet-lowered ([`Stage::Plain`], no rounds) graph - the frontend's output,
    /// and what pass-level unit tests build by hand to exercise a single pass in isolation.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts(
        nodes: Vec<Node>,
        outputs: Vec<(SignalIdx, ValueId)>,
        precompute_sites: Vec<PrecomputeSite>,
        signal_to_witness: Vec<usize>,
        input_list: InputList,
        public_inputs: Vec<String>,
        num_inputs: usize,
        num_outputs: usize,
        num_signals: usize,
    ) -> Self {
        Self {
            nodes,
            outputs,
            precompute_sites,
            rounds: Vec::new(),
            lowered: false,
            signal_to_witness,
            input_list,
            public_inputs,
            mpc_public_inputs: Vec::new(),
            num_inputs,
            num_outputs,
            num_signals,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.nodes.len()
    }

    // Only exercised by tests so far; kept as the standard single-node accessor for the passes
    // and codegen that land in later steps.
    #[allow(dead_code)]
    pub(crate) fn node(&self, id: ValueId) -> &Node {
        &self.nodes[id.index()]
    }

    pub(crate) fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// Every `TACEO_PRECOMPUTATION_*`-wrapped component in this graph, in inlining order - the
    /// order the runtime must supply traces in.
    pub fn precompute_sites(&self) -> &[PrecomputeSite] {
        &self.precompute_sites
    }

    pub(crate) fn outputs(&self) -> &[(SignalIdx, ValueId)] {
        &self.outputs
    }

    /// Drops every `outputs` entry `keep` rejects, preserving the relative order of the rest -
    /// several entries can name the same signal and the witness projection is last-write-wins, so
    /// reordering could change which value ends up in a shared signal slot. Returns whether
    /// anything was dropped.
    pub(crate) fn retain_outputs(
        &mut self,
        mut keep: impl FnMut(SignalIdx, ValueId) -> bool,
    ) -> bool {
        let before = self.outputs.len();
        self.outputs.retain(|&(signal, value)| keep(signal, value));
        self.outputs.len() != before
    }

    /// Every batched MPC network round, indexed by [`RoundId`]. Empty before `passes::mpc` runs.
    // Only exercised by pass unit tests so far (`Graph::mpc_summary` reads the private field
    // directly) - same situation as `Graph::node` above.
    #[allow(dead_code)]
    pub(crate) fn rounds(&self) -> &[RoundDesc] {
        &self.rounds
    }

    /// Installs a fresh round table, replacing whatever was there (`mul_split` installs the
    /// one-round-per-product table, `round_schedule` replaces it with the batched one).
    pub(crate) fn set_rounds(&mut self, rounds: Vec<RoundDesc>) {
        self.rounds = rounds;
    }

    /// Marks the graph as MPC-lowered. Called once by the `PassManager`, right before its
    /// lowering-stage passes run.
    pub(crate) fn mark_lowered(&mut self) {
        self.lowered = true;
    }

    /// Replaces the whole node list at once, remapping `outputs` through `remap` (`None` for a
    /// node an output still depends on is a caller bug, and panics loudly). For passes whose
    /// transformation isn't a node-for-node substitution and so cannot use [`Graph::rewrite`]
    /// (`round_schedule` merges nodes, which changes arity).
    pub(crate) fn rebuild_nodes(&mut self, nodes: Vec<Node>, remap: &[Option<ValueId>]) {
        self.nodes = nodes;
        for (_, value) in self.outputs.iter_mut() {
            *value =
                remap[value.index()].expect("rebuild_nodes dropped a node an output depends on");
        }
    }

    /// Reports the effect of MPC lowering: rounds, total reshare elements (one field element per
    /// round slot), min/mean/max slots per round, free local multiplications, free public
    /// multiplications, and precomputation sites. Not a rewrite - this is what makes the round
    /// batching claims falsifiable instead of asserted; see `tests/mpc_lowering.rs`.
    pub fn mpc_summary(&self) -> MpcSummary {
        let slot_counts: Vec<usize> = self.rounds.iter().map(|r| r.len).collect();
        let reshare_elements: usize = slot_counts.iter().sum();
        let local_muls = self
            .nodes
            .iter()
            .filter(|n| matches!(n.op, Op::MulLocal))
            .count();
        let public_muls = self
            .nodes
            .iter()
            .filter(|n| matches!(n.op, Op::Mul))
            .count();
        let domains = crate::passes::mpc::domain::compute_domains(self);
        let batches =
            crate::passes::mpc::precompute_schedule::plan_precompute_batches(self, &domains);
        let precompute_batches = batches.len();
        let shared_precompute_batches = batches
            .iter()
            .filter(|batch| batch.domain == crate::passes::mpc::domain::Domain::Shared)
            .count();
        MpcSummary {
            rounds: self.rounds.len(),
            reshare_elements,
            min_slots_per_round: slot_counts.iter().copied().min(),
            max_slots_per_round: slot_counts.iter().copied().max(),
            local_muls,
            public_muls,
            precompute_sites: self.precompute_sites.len(),
            precompute_batches,
            shared_precompute_batches,
        }
    }

    /// Marks every node reachable from `outputs`, drops the rest, and compacts `ValueId`s so the
    /// graph is dense again. Returns the old-to-new id mapping (`None` for dropped nodes).
    pub(crate) fn gc(&mut self) -> Vec<Option<ValueId>> {
        let mut keep = vec![false; self.nodes.len()];
        for &(_, root) in &self.outputs {
            keep[root.index()] = true;
        }
        // Every precomputation site must survive gc even if none of its results end up read (a
        // site whose results are all witness-dead has zero references at this point). Codegen
        // resolves each site's destination slots from the fixed, in-order `precompute_sites`
        // table, so silently dropping a "dead" site would desynchronize every later same-kind
        // site's slot range - and `Graph::verify` requires exactly one `Op::Precompute` node per
        // site regardless.
        for (i, node) in self.nodes.iter().enumerate() {
            if matches!(node.op, Op::Precompute(_)) {
                keep[i] = true;
            }
        }
        // single reverse sweep: since inputs only ever point strictly earlier, marking in
        // reverse order sees every use of a node before deciding whether to keep it.
        for i in (0..self.nodes.len()).rev() {
            if keep[i] {
                for input in &self.nodes[i].inputs {
                    keep[input.index()] = true;
                }
            }
        }

        let mut remap = vec![None; self.nodes.len()];
        let mut new_nodes = Vec::with_capacity(self.nodes.len());
        for (i, node) in self.nodes.iter().enumerate() {
            if keep[i] {
                remap[i] = Some(ValueId::new(new_nodes.len()));
                new_nodes.push(node.clone());
            }
        }
        for node in new_nodes.iter_mut() {
            for input in node.inputs.iter_mut() {
                *input = remap[input.index()].expect("gc kept a node whose input was dropped");
            }
        }
        for (_, value) in self.outputs.iter_mut() {
            *value = remap[value.index()].expect("gc dropped a node an output depends on");
        }

        tracing::debug!(
            "gc: {} nodes -> {} nodes ({} removed)",
            self.nodes.len(),
            new_nodes.len(),
            self.nodes.len() - new_nodes.len()
        );
        self.nodes = new_nodes;
        remap
    }

    /// Checks the graph's structural invariants:
    /// - every node's inputs reference strictly earlier nodes (topological order),
    /// - every node has exactly as many inputs as its op's arity,
    /// - every `PrecomputeResult`/`RoundResult` references a real slot of a real producer,
    /// - every precomputation site has exactly one [`Op::Precompute`] node,
    /// - no [`Op::Precompute`] reads an un-reshared [`Op::MulLocal`] value,
    /// - MPC-lowering ops appear only once the graph is lowered,
    /// - every output references a node that exists.
    ///
    /// Called once after the frontend builds the graph and, in debug builds, between every pass.
    pub(crate) fn verify(&self) -> eyre::Result<()> {
        for (i, node) in self.nodes.iter().enumerate() {
            match &node.op {
                Op::Precompute(site_id) => {
                    let site = self.precompute_sites.get(site_id.index()).ok_or_else(|| {
                        eyre::eyre!(
                            "node {i} references precompute site {} which does not exist",
                            site_id.index()
                        )
                    })?;
                    if node.inputs.len() != site.num_inputs {
                        eyre::bail!(
                            "node {i} (Precompute({})) has {} inputs, expected {} (site num_inputs)",
                            site_id.index(),
                            node.inputs.len(),
                            site.num_inputs
                        );
                    }
                }
                Op::Round(round_id) => {
                    let round = self.rounds.get(round_id.index()).ok_or_else(|| {
                        eyre::eyre!(
                            "node {i} references round {} which does not exist",
                            round_id.index()
                        )
                    })?;
                    if node.inputs.len() != round.len {
                        eyre::bail!(
                            "node {i} (Round({})) has {} inputs, expected {} (round len)",
                            round_id.index(),
                            node.inputs.len(),
                            round.len
                        );
                    }
                    // Every slot's mask comes from the local product that feeds it - a round with
                    // no slots would have nothing to reshare.
                    if round.len == 0 {
                        eyre::bail!("round {} has no slots", round_id.index());
                    }
                }
                op => {
                    let arity = op.fixed_arity().expect("non-table ops have a fixed arity");
                    if node.inputs.len() != arity {
                        eyre::bail!(
                            "node {i} ({:?}) has {} inputs, expected {arity}",
                            node.op,
                            node.inputs.len(),
                        );
                    }
                }
            }
            if let Op::PrecomputeResult(slot) = &node.op {
                let referenced = &self.nodes[node.inputs[0].index()];
                let Op::Precompute(site_id) = &referenced.op else {
                    eyre::bail!("node {i} (PrecomputeResult) does not reference a Precompute node");
                };
                let site = &self.precompute_sites[site_id.index()];
                let total_results = site.num_outputs + site.num_intermediates;
                if *slot as usize >= total_results {
                    eyre::bail!(
                        "node {i} (PrecomputeResult({slot})) references out-of-range slot \
                         (site has {total_results} results)"
                    );
                }
            }
            // A precomputation gadget needs a genuine share. `Op::MulLocal` is the only producer of
            // a `Local` (un-reshared additive-3) value, so this is a purely syntactic check - no
            // domain analysis needed - and it is the structural counterpart of the same rejection
            // `vm::codegen` makes when resolving a site's operand banks.
            if let Op::Precompute(site_id) = &node.op {
                for input in &node.inputs {
                    if matches!(self.nodes[input.index()].op, Op::MulLocal) {
                        eyre::bail!(
                            "node {i} (Precompute({})) reads value {} which is an un-reshared \
                             MulLocal - a precomputation gadget needs a genuine share",
                            site_id.index(),
                            input.index()
                        );
                    }
                }
            }
            if let Op::RoundResult(slot) = &node.op {
                let referenced = &self.nodes[node.inputs[0].index()];
                let Op::Round(round_id) = &referenced.op else {
                    eyre::bail!("node {i} (RoundResult) does not reference a Round node");
                };
                let round = &self.rounds[round_id.index()];
                if *slot as usize >= round.len {
                    eyre::bail!(
                        "node {i} (RoundResult({slot})) references out-of-range slot \
                         (round has {} slots)",
                        round.len
                    );
                }
            }
            if !self.lowered && matches!(node.op, Op::MulLocal | Op::Round(_) | Op::RoundResult(_))
            {
                eyre::bail!(
                    "node {i} ({:?}) is an MPC-lowering op but the graph is not lowered",
                    node.op
                );
            }
            for input in &node.inputs {
                if input.index() >= i {
                    eyre::bail!(
                        "node {i} ({:?}) references value {} which is not defined earlier",
                        node.op,
                        input.index()
                    );
                }
            }
        }
        // Exactly one `Op::Precompute` node per site. Several things already assume this without
        // checking it: `vm::codegen` groups sites into batches and reserves one contiguous result
        // range per site, and `gc` roots every `Precompute` node so a "dead" site can't shift a
        // later same-kind site's slot range. Two nodes for one site would silently service it twice
        // and desynchronize both.
        let mut nodes_per_site = vec![0usize; self.precompute_sites.len()];
        for node in &self.nodes {
            if let Op::Precompute(site_id) = &node.op {
                nodes_per_site[site_id.index()] += 1;
            }
        }
        for (site, count) in nodes_per_site.iter().enumerate() {
            if *count != 1 {
                eyre::bail!(
                    "precompute site {site} is referenced by {count} Op::Precompute nodes, \
                     expected exactly 1"
                );
            }
        }
        for (signal, value) in &self.outputs {
            if value.index() >= self.nodes.len() {
                eyre::bail!(
                    "output signal {} references non-existent value {}",
                    signal.index(),
                    value.index()
                );
            }
        }
        Ok(())
    }

    /// Rewrites the graph node-by-node, in original order, driving each pass's transformation
    /// without it having to hand-roll `ValueId` remapping (easy to get wrong: `ValueId` doubles as
    /// a node's position, so deleting or replacing any node shifts every later reference).
    ///
    /// `f` is called once per original node, in order, with: the node's original id, the node
    /// itself with `inputs` already translated to their *new* ids, and every node already emitted
    /// so far (also in new-id space, so `f` can inspect an input's producer - e.g. "is this input
    /// a constant?" - by indexing `already_emitted` with an entry from `inputs`). It returns what
    /// to emit; see [`RewriteAction`]. A `ReplaceWith`/`Emit` referencing anything other than an
    /// already-emitted value is a bug in the pass, not in this function - topological order makes
    /// that the only value space `f` ever has to work with.
    ///
    /// Returns whether the graph actually changed (a node was aliased or replaced, or the node
    /// count changed because some input became dead) - passes use this as their `Pass::run`
    /// return value.
    pub(crate) fn rewrite(
        &mut self,
        mut f: impl FnMut(ValueId, &Node, &[Node]) -> RewriteAction,
    ) -> bool {
        let old_len = self.nodes.len();
        let mut remap: Vec<Option<ValueId>> = vec![None; old_len];
        let mut new_nodes = Vec::with_capacity(old_len);
        let mut changed = false;

        for (i, node) in std::mem::take(&mut self.nodes).into_iter().enumerate() {
            let remapped_inputs = node
                .inputs
                .iter()
                .map(|input| remap[input.index()].expect("rewrite visited a node before its input"))
                .collect();
            let remapped_node = Node {
                op: node.op,
                inputs: remapped_inputs,
            };
            match f(ValueId::new(i), &remapped_node, &new_nodes) {
                RewriteAction::Keep => {
                    remap[i] = Some(ValueId::new(new_nodes.len()));
                    new_nodes.push(remapped_node);
                }
                RewriteAction::ReplaceWith(target) => {
                    changed = true;
                    remap[i] = Some(target);
                }
                RewriteAction::Emit(new_node) => {
                    changed = true;
                    remap[i] = Some(ValueId::new(new_nodes.len()));
                    new_nodes.push(new_node);
                }
                RewriteAction::EmitMany(group) => {
                    changed = true;
                    assert!(!group.is_empty(), "EmitMany must emit at least one node");
                    for node in group {
                        new_nodes.push(node);
                    }
                    remap[i] = Some(ValueId::new(new_nodes.len() - 1));
                }
            }
        }
        changed |= new_nodes.len() != old_len;

        for (_, value) in self.outputs.iter_mut() {
            *value = remap[value.index()].expect("rewrite dropped a node an output depends on");
        }
        self.nodes = new_nodes;
        changed
    }
}

impl std::fmt::Debug for Graph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== graph ({} nodes) ===", self.nodes.len())?;
        for (idx, node) in self.nodes.iter().enumerate() {
            writeln!(f, "{idx:0>4}: {node:?}")?;
        }
        writeln!(f, "=== outputs ===")?;
        for (signal, value) in &self.outputs {
            writeln!(f, "signal {} <- value {}", signal.index(), value.index())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;

    // x0 = Input(0); x1 = Constant(2); x2 = Add(x0, x1); x3 = Mul(x0, x1) [dead: no output uses it]
    // output signal 0 <- x2
    fn sample_graph() -> Graph {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(0)), vec![]),
            Node::new(Op::Constant(Fr::from(2u64)), vec![]),
            Node::new(Op::Add, vec![ValueId::new(0), ValueId::new(1)]),
            Node::new(Op::Mul, vec![ValueId::new(0), ValueId::new(1)]),
        ];
        let outputs = vec![(SignalIdx::new(0), ValueId::new(2))];
        Graph::from_parts(nodes, outputs, vec![], vec![0, 1], vec![], vec![], 1, 1, 2)
    }

    #[test]
    fn verify_accepts_well_formed_graph() {
        assert!(sample_graph().verify().is_ok());
    }

    fn iszero_site() -> PrecomputeSite {
        PrecomputeSite {
            kind: PrecomputeKind::IsZero,
            header: "IsZero_0".to_owned(),
            num_inputs: 1,
            num_outputs: 1,
            num_intermediates: 1,
        }
    }

    /// Two `Op::Precompute` nodes for one site would service it twice and desynchronize every later
    /// same-kind site's reserved result range in `vm::codegen`.
    #[test]
    fn verify_rejects_duplicate_precompute_nodes_for_one_site() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]),
            Node::new(Op::Precompute(PrecomputeId::new(0)), vec![ValueId::new(0)]),
            Node::new(Op::Precompute(PrecomputeId::new(0)), vec![ValueId::new(0)]),
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(1)]),
        ];
        let outputs = vec![(SignalIdx::new(0), ValueId::new(3))];
        let graph = Graph::from_parts(
            nodes,
            outputs,
            vec![iszero_site()],
            vec![],
            vec![],
            vec![],
            1,
            1,
            2,
        );
        let err = graph.verify().unwrap_err().to_string();
        assert!(
            err.contains("referenced by 2 Op::Precompute nodes"),
            "unexpected error: {err}"
        );
    }

    /// A site with no `Op::Precompute` node at all is equally broken - `level::site_stages` and
    /// codegen's grouping both index by `PrecomputeId` and would have nothing to place.
    #[test]
    fn verify_rejects_a_site_with_no_precompute_node() {
        let nodes = vec![Node::new(Op::Input(SignalIdx::new(1)), vec![])];
        let outputs = vec![(SignalIdx::new(0), ValueId::new(0))];
        let graph = Graph::from_parts(
            nodes,
            outputs,
            vec![iszero_site()],
            vec![],
            vec![],
            vec![],
            1,
            1,
            2,
        );
        let err = graph.verify().unwrap_err().to_string();
        assert!(
            err.contains("referenced by 0 Op::Precompute nodes"),
            "unexpected error: {err}"
        );
    }

    /// A gadget needs a genuine share, not an un-reshared local product.
    #[test]
    fn verify_rejects_a_precompute_reading_an_unreshared_mul_local() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]),
            Node::new(Op::Input(SignalIdx::new(2)), vec![]),
            Node::new(Op::MulLocal, vec![ValueId::new(0), ValueId::new(1)]),
            Node::new(Op::Precompute(PrecomputeId::new(0)), vec![ValueId::new(2)]),
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(3)]),
        ];
        let outputs = vec![(SignalIdx::new(0), ValueId::new(4))];
        let mut graph = Graph::from_parts(
            nodes,
            outputs,
            vec![iszero_site()],
            vec![],
            vec![],
            vec![],
            2,
            1,
            3,
        );
        // MulLocal is only legal once lowering has started.
        graph.mark_lowered();
        let err = graph.verify().unwrap_err().to_string();
        assert!(
            err.contains("un-reshared MulLocal"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn verify_rejects_forward_reference() {
        let nodes = vec![
            Node::new(Op::Add, vec![ValueId::new(1), ValueId::new(0)]),
            Node::new(Op::Constant(Fr::from(1u64)), vec![]),
        ];
        let outputs = vec![(SignalIdx::new(0), ValueId::new(0))];
        let graph = Graph::from_parts(nodes, outputs, vec![], vec![], vec![], vec![], 0, 1, 1);
        assert!(graph.verify().is_err());
    }

    #[test]
    fn verify_rejects_arity_mismatch() {
        let nodes = vec![Node::new(Op::Constant(Fr::from(1u64)), vec![])];
        // hand-build a node bypassing Node::new's debug_assert, to exercise the arity check
        let bad = Node {
            op: Op::Add,
            inputs: vec![ValueId::new(0)],
        };
        let mut nodes = nodes;
        nodes.push(bad);
        let outputs = vec![(SignalIdx::new(0), ValueId::new(1))];
        let graph = Graph::from_parts(nodes, outputs, vec![], vec![], vec![], vec![], 0, 1, 1);
        assert!(graph.verify().is_err());
    }

    #[test]
    fn gc_drops_unreachable_nodes_and_compacts_ids() {
        let mut graph = sample_graph();
        assert_eq!(graph.len(), 4);
        let remap = graph.gc();
        // the Mul node (index 3) is unreachable from the single output and must be dropped
        assert_eq!(graph.len(), 3);
        assert_eq!(remap[3], None);
        assert!(remap[0].is_some());
        assert!(remap[1].is_some());
        assert!(remap[2].is_some());
        // the output must still resolve to a valid, in-range node after compaction
        let (_, out_value) = graph.outputs()[0];
        assert!(out_value.index() < graph.len());
        assert!(matches!(graph.node(out_value).op, Op::Add));
        assert!(graph.verify().is_ok());
    }
}
