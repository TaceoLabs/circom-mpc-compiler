//! `Graph<F>` -> `Program<F>`: not a `Pass` (it changes representation, not the IR), called by
//! `CoCircomCompiler::compile` once `PassManager` has finished lowering. A single forward walk
//! over `graph.nodes()` (already topologically ordered - `Graph::verify`) doing three things at
//! once: classifying each value's `Domain` (reusing `passes::mpc::domain`, the same analysis
//! `mul_split` used while lowering), linear-scan slot allocation over liveness, and instruction
//! emission. See `docs/ARCHITECTURE.md`, "Bytecode and the slot machine".

use ark_ff::{BigInteger, PrimeField};

use crate::ir::{Graph, Op, PrecomputeKind, ValueId};
use crate::passes::mpc::domain::{compute_domains, signal_domain, Domain};
use crate::passes::mpc::precompute_schedule::{BatchPlan, plan_precompute_batches};

use super::program::{
    Bank, BatchKind, InputBinding, Instruction, Opcode, PrecomputeBatch, Program, ResultTarget,
    RoundEntry, SiteInput, SlotCounts, WitnessSource,
};

/// A bump allocator with a free list: `alloc` reuses the most recently freed slot before minting a
/// new one, `free` returns a slot to the pool. This is the whole allocator - liveness (computed
/// once, up front) drives when `free` is called, not anything in here.
struct BankAlloc {
    free: Vec<u32>,
    next: u32,
}

impl BankAlloc {
    fn starting_at(next: u32) -> Self {
        Self {
            free: Vec::new(),
            next,
        }
    }

    fn alloc(&mut self) -> u32 {
        self.free.pop().unwrap_or_else(|| {
            let slot = self.next;
            self.next += 1;
            slot
        })
    }

    /// No-op for a slot in a reserved (non-recycled) region - callers only free slots they
    /// allocated from `self` in the first place, but a reserved-region slot never went through
    /// `alloc`, so this only guards against a caller accidentally passing one in.
    fn free(&mut self, slot: u32, reserved_below: u32) {
        if slot >= reserved_below {
            self.free.push(slot);
        }
    }
}

/// Where one node's value currently lives.
#[derive(Clone, Copy)]
struct Slot {
    bank: Bank,
    index: u32,
}

/// The recyclable slot arena for Phase B: one `BankAlloc` per bank, the reserved-region bounds
/// they must never recycle into, and the liveness table that drives when a slot is released.
struct Arena {
    p: BankAlloc,
    s: BankAlloc,
    l: BankAlloc,
    p_reserved_end: u32,
    s_reserved_end: u32,
    last_use: Vec<usize>,
}

impl Arena {
    fn alloc(&mut self, bank: Bank) -> u32 {
        match bank {
            Bank::Public => self.p.alloc(),
            Bank::Shared => self.s.alloc(),
            Bank::Local => self.l.alloc(),
        }
    }

    /// Releases `value`'s slot if `current` is its last use. Taking the mapping makes release
    /// idempotent when one consumer mentions the same SSA value more than once (`x*x`, or the same
    /// value in several positions of one gadget batch).
    fn free_if_dead(&mut self, value: ValueId, current: usize, slot: &mut [Option<Slot>]) {
        if self.last_use[value.index()] != current {
            return;
        }
        let Some(s) = slot[value.index()].take() else {
            return;
        };
        match s.bank {
            Bank::Public => self.p.free(s.index, self.p_reserved_end),
            Bank::Shared => self.s.free(s.index, self.s_reserved_end),
            Bank::Local => {} // freed directly at the Round arm, not through this helper
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ZeroTestRevealPair {
    zero_test_site: usize,
    zero_test_node: usize,
    reveal_site: usize,
}

#[derive(Debug)]
struct ZeroTestRevealPlan {
    source_plan: usize,
    reveal_plan: usize,
    anchor: usize,
    pairs: Vec<ZeroTestRevealPair>,
}

#[derive(Debug, Clone, Copy)]
enum RuntimePlan {
    Normal(usize),
    IsZeroReveal(usize),
}

/// Finds whole scheduler batches that can be replaced by the circuit-preserving Rep3 shortcut.
/// Staying at whole-batch granularity is intentionally conservative: a mixed Reveal batch or an
/// IsZero batch with even one non-revealed result continues through the ordinary gadget paths.
fn plan_zero_test_reveal_fusions<F: PrimeField>(
    graph: &Graph<F>,
    domains: &[Domain],
    plans: &[BatchPlan],
) -> Vec<ZeroTestRevealPlan> {
    // The fused protocol is reviewed and tested for the project's BN254 deployment. Keep generic
    // compilation untouched for any other field rather than silently opting it into a
    // probabilistic zero test.
    if F::MODULUS.to_bytes_le() != ark_bn254::Fr::MODULUS.to_bytes_le() {
        return Vec::new();
    }

    let nodes = graph.nodes();
    let sites = graph.precompute_sites();
    let mut consumers = vec![0usize; nodes.len()];
    for node in nodes {
        for input in &node.inputs {
            consumers[input.index()] += 1;
        }
    }
    let mut site_plan = vec![usize::MAX; sites.len()];
    for (plan_idx, plan) in plans.iter().enumerate() {
        for &(site_id, _) in &plan.sites {
            site_plan[site_id] = plan_idx;
        }
    }

    let mut claimed_source = vec![false; plans.len()];
    let mut fusions = Vec::new();
    for (reveal_plan_idx, reveal_plan) in plans.iter().enumerate() {
        if reveal_plan.domain != Domain::Shared
            || reveal_plan.kind != (PrecomputeKind::Reveal { n: 1 })
        {
            continue;
        }

        let mut pairs = Vec::with_capacity(reveal_plan.sites.len());
        let mut source_plan_idx = None;
        let mut valid = !reveal_plan.sites.is_empty();
        for &(reveal_site, reveal_node) in &reveal_plan.sites {
            let Some(&zero_test_result) = nodes[reveal_node].inputs.first() else {
                valid = false;
                break;
            };
            if nodes[reveal_node].inputs.len() != 1
                || !matches!(nodes[zero_test_result.index()].op, Op::PrecomputeResult(0))
                || consumers[zero_test_result.index()] != 1
            {
                valid = false;
                break;
            }
            let zero_test_node = nodes[zero_test_result.index()].inputs[0].index();
            let Op::Precompute(zero_test_site_id) = nodes[zero_test_node].op else {
                valid = false;
                break;
            };
            let zero_test_site = zero_test_site_id.index();
            if sites[zero_test_site].kind != PrecomputeKind::IsZero {
                valid = false;
                break;
            }
            // The fused service runs at the Reveal batch's anchor instead of the original
            // zero-test anchor. Slot 0 is safe to bypass because its sole computational reader is
            // this Reveal; the `inv` helper result must be witness-only, otherwise an earlier
            // reader could observe its slot before the fused service fills it.
            let other_result_has_reader = nodes.iter().enumerate().any(|(result_idx, result)| {
                matches!(result.op, Op::PrecomputeResult(slot) if slot != 0)
                    && result
                        .inputs
                        .first()
                        .is_some_and(|input| input.index() == zero_test_node)
                    && consumers[result_idx] != 0
            });
            if domains[zero_test_node] != Domain::Shared
                || nodes[zero_test_node].inputs.len() != 1
                || other_result_has_reader
            {
                valid = false;
                break;
            }
            let this_source_plan = site_plan[zero_test_site];
            if this_source_plan == usize::MAX
                || source_plan_idx.is_some_and(|idx| idx != this_source_plan)
            {
                valid = false;
                break;
            }
            source_plan_idx = Some(this_source_plan);
            pairs.push(ZeroTestRevealPair {
                zero_test_site,
                zero_test_node,
                reveal_site,
            });
        }
        let Some(source_plan_idx) = source_plan_idx else {
            continue;
        };
        let source_plan = &plans[source_plan_idx];
        if !valid
            || claimed_source[source_plan_idx]
            || source_plan.domain != Domain::Shared
            || source_plan.kind != PrecomputeKind::IsZero
            || source_plan.sites.len() != pairs.len()
            || !source_plan.sites.iter().all(|&(site_id, _)| {
                pairs
                    .iter()
                    .filter(|pair| pair.zero_test_site == site_id)
                    .count()
                    == 1
            })
        {
            continue;
        }
        claimed_source[source_plan_idx] = true;
        fusions.push(ZeroTestRevealPlan {
            source_plan: source_plan_idx,
            reveal_plan: reveal_plan_idx,
            anchor: reveal_plan.anchor,
            pairs,
        });
    }
    fusions
}

/// Last node index (in graph order) that reads each value - a value with no reader at all keeps
/// its own index (dead by construction only if `gc` missed it, which it shouldn't - see
/// `Graph::gc`). A value referenced by `graph.outputs()` gets `nodes.len()` (never freed): its
/// slot must still hold the right value after the instruction stream finishes, when the direct
/// witness-source projection reads it - freeing it mid-stream would let a later instruction
/// clobber it.
fn compute_last_use<F: PrimeField>(graph: &Graph<F>) -> Vec<usize> {
    let nodes = graph.nodes();
    let mut last_use: Vec<usize> = (0..nodes.len()).collect();
    for (i, node) in nodes.iter().enumerate() {
        for input in &node.inputs {
            last_use[input.index()] = i;
        }
    }
    for &(_, value) in graph.outputs() {
        last_use[value.index()] = nodes.len();
    }
    last_use
}

/// Picks the opcode, result bank, and whether to swap `(a, b)` so they match the opcode's fixed
/// operand order - `Add`/`Mul` are commutative (codegen reorders rather than doubling the opcode
/// count), `Sub` is not (hence both `SubSP` and `SubPS`). `Local` never reaches here: `mul_split`
/// only ever produces a bare `MulLocal` immediately wrapped by a `Round`, so an `Add`/`Sub`/`Mul`
/// operand is always `Public` or `Shared` in a well-formed lowered graph - a `Local` operand means
/// an earlier pass broke that invariant, which is exactly the case
/// `Unsupported`-style errors elsewhere in this compiler exist to catch instead of silently
/// mis-encoding.
fn select_opcode(
    op: &Op<impl PrimeField>,
    da: Domain,
    db: Domain,
) -> eyre::Result<(Opcode, Bank, bool)> {
    if da == Domain::Local || db == Domain::Local {
        eyre::bail!(
            "codegen: a Local-domain value reached {op:?} directly - it must only ever feed a \
             Round (rep3's reshare); this is a lowering invariant violation, not a supported circuit \
             shape"
        );
    }
    use Domain::{Public, Shared};
    Ok(match (op, da, db) {
        (Op::Add, Public, Public) => (Opcode::AddPP, Bank::Public, false),
        (Op::Add, Shared, Shared) => (Opcode::AddSS, Bank::Shared, false),
        (Op::Add, Shared, Public) => (Opcode::AddSP, Bank::Shared, false),
        (Op::Add, Public, Shared) => (Opcode::AddSP, Bank::Shared, true),
        (Op::Sub, Public, Public) => (Opcode::SubPP, Bank::Public, false),
        (Op::Sub, Shared, Shared) => (Opcode::SubSS, Bank::Shared, false),
        (Op::Sub, Shared, Public) => (Opcode::SubSP, Bank::Shared, false),
        (Op::Sub, Public, Shared) => (Opcode::SubPS, Bank::Shared, false),
        (Op::Mul, Public, Public) => (Opcode::MulPP, Bank::Public, false),
        (Op::Mul, Shared, Public) => (Opcode::MulSP, Bank::Shared, false),
        (Op::Mul, Public, Shared) => (Opcode::MulSP, Bank::Shared, true),
        (Op::Mul, Shared, Shared) => eyre::bail!(
            "codegen: a secret x secret Mul survived MPC lowering - mul_split should have split \
             every one of these into MulLocal + Round before codegen ever runs"
        ),
        _ => unreachable!("select_opcode only ever called for Op::Add/Sub/Mul"),
    })
}

/// Which bank a precomputation site's results live in. Every kind but [`PrecomputeKind::Reveal`]
/// keeps the site's own domain (deterministic public work stays `Public`, a real share stays
/// `Shared`) - `Reveal`'s entire purpose is to leave the `Public` domain regardless of whether its
/// own input was `Shared`, since that is exactly what a genuine MPC open does. See
/// `docs/ARCHITECTURE.md`, "Precomputation".
fn precompute_result_bank(kind: PrecomputeKind, domain: Domain) -> eyre::Result<Bank> {
    if domain == Domain::Local {
        eyre::bail!(
            "codegen: a precomputation site reads a Local (un-reshared MulLocal) value - it must \
             be reshared first; this is a lowering invariant violation"
        );
    }
    if matches!(kind, PrecomputeKind::Reveal { .. }) {
        return Ok(Bank::Public);
    }
    Ok(match domain {
        Domain::Public => Bank::Public,
        Domain::Shared => Bank::Shared,
        Domain::Local => unreachable!("checked above"),
    })
}

/// Compiles a fully lowered graph (`PassManager::run` has already run - see
/// `CoCircomCompiler::compile`) into a `Program`.
pub fn compile<F: PrimeField>(graph: &Graph<F>) -> eyre::Result<Program<F>> {
    let nodes = graph.nodes();
    let domain = compute_domains(graph);
    let mut last_use = compute_last_use(graph);
    let plans = plan_precompute_batches(graph, &domain);
    let fusion_plans = plan_zero_test_reveal_fusions(graph, &domain, &plans);
    let mut source_fusion = vec![None; plans.len()];
    let mut reveal_fusion = vec![None; plans.len()];
    for (fusion_idx, fusion) in fusion_plans.iter().enumerate() {
        source_fusion[fusion.source_plan] = Some(fusion_idx);
        reveal_fusion[fusion.reveal_plan] = Some(fusion_idx);
    }
    let mut runtime_plans = Vec::with_capacity(plans.len());
    for plan_idx in 0..plans.len() {
        if source_fusion[plan_idx].is_some() {
            continue;
        }
        if let Some(fusion_idx) = reveal_fusion[plan_idx] {
            runtime_plans.push(RuntimePlan::IsZeroReveal(fusion_idx));
        } else {
            runtime_plans.push(RuntimePlan::Normal(plan_idx));
        }
    }

    // A site's inputs must still hold their values when its *batch* runs, which is later than the
    // `Op::Precompute` node that reads them - so extend their lifetimes to the batch's anchor.
    //
    // Load-bearing, not just defense in depth, now that `passes::dead_signals` prunes witness-dead
    // outputs before this runs: `inline_precomputed` pushes every site input into `graph.outputs()`,
    // but circom's own constraint simplification frequently drops a gadget's own input signal from
    // the witness, so `dead_signals` removes that binding and `compute_last_use` no longer pins the
    // input to `nodes.len()`. This extension is what stops the allocator from recycling a site
    // input's slot between the `Op::Precompute` node and the batch's actual service point. Hand-built
    // codegen test graphs never bound site inputs to outputs in the first place, which is why this
    // was already exercised (`site_input_slot_survives_until_its_batch_runs`, below) before it
    // became load-bearing on real circuits too.
    for runtime in &runtime_plans {
        match *runtime {
            RuntimePlan::Normal(plan_idx) => {
                let plan = &plans[plan_idx];
                for &(_, site_node) in &plan.sites {
                    for input in &nodes[site_node].inputs {
                        last_use[input.index()] = last_use[input.index()].max(plan.anchor);
                    }
                }
            }
            RuntimePlan::IsZeroReveal(fusion_idx) => {
                let fusion = &fusion_plans[fusion_idx];
                for pair in &fusion.pairs {
                    for input in &nodes[pair.zero_test_node].inputs {
                        last_use[input.index()] = last_use[input.index()].max(fusion.anchor);
                    }
                }
            }
        }
    }
    // Batch indices anchored at each node, emitted right after that node is processed.
    let mut batches_at: Vec<Vec<usize>> = vec![Vec::new(); nodes.len()];
    for (batch_idx, runtime) in runtime_plans.iter().enumerate() {
        let anchor = match *runtime {
            RuntimePlan::Normal(plan_idx) => plans[plan_idx].anchor,
            RuntimePlan::IsZeroReveal(fusion_idx) => fusion_plans[fusion_idx].anchor,
        };
        batches_at[anchor].push(batch_idx);
    }

    // --- Phase A: reserved (non-recycled) regions ---
    // Public bank: constants, public precompute results, then Public-domain kept Op::Input.
    // Shared bank: shared precompute results, then Shared-domain kept Op::Input.
    let mut slot: Vec<Option<Slot>> = vec![None; nodes.len()];
    let mut constants: Vec<F> = Vec::new();
    let mut p_next: u32 = 0;
    let mut s_next: u32 = 0;

    for (i, node) in nodes.iter().enumerate() {
        if let Op::Constant(c) = &node.op {
            slot[i] = Some(Slot {
                bank: Bank::Public,
                index: p_next,
            });
            constants.push(*c);
            p_next += 1;
        }
    }

    let mut site_domains = vec![Domain::Public; graph.precompute_sites().len()];
    for (i, node) in nodes.iter().enumerate() {
        if let Op::Precompute(site_id) = &node.op {
            site_domains[site_id.index()] = domain[i];
        }
    }

    // Every site's *surviving* result slots: `passes::dead_signals` (run before `gc`) has already
    // dropped the `outputs` binding for every witness-dead result, and `gc` then deleted the
    // now-unreferenced `Op::PrecomputeResult` nodes - so a site's reserved region only needs to be
    // as wide as what's left, not its full `num_outputs + num_intermediates` capacity. Real scale:
    // at merces' `transfer_arity4_batch8`, this is the difference between ~2700 Poseidon2 result
    // slots per site and the ~140 actually read.
    //
    // `live_nodes[site]` is parallel to `live_slots[site]`: the node index of each surviving
    // `PrecomputeResult`, resolved to a physical slot below once `site_result_base` is known.
    let mut live_slots: Vec<Vec<u32>> = vec![Vec::new(); graph.precompute_sites().len()];
    let mut live_nodes: Vec<Vec<usize>> = vec![Vec::new(); graph.precompute_sites().len()];
    for (i, node) in nodes.iter().enumerate() {
        if let Op::PrecomputeResult(k) = &node.op {
            let Op::Precompute(site_id) = &nodes[node.inputs[0].index()].op else {
                unreachable!("Graph::verify guarantees PrecomputeResult's input is Precompute");
            };
            live_slots[site_id.index()].push(*k);
            live_nodes[site_id.index()].push(i);
        }
    }
    debug_assert!(
        live_slots.iter().all(|s| s.windows(2).all(|w| w[0] < w[1])),
        "a site's surviving PrecomputeResult nodes must stay in ascending slot order - gc and \
         dead_signals never reorder nodes, only drop them - since the flat, site-contiguous \
         request list below depends on it"
    );

    // Node-indexed physical slot for every surviving `PrecomputeResult`.
    let mut result_phys: Vec<Option<u32>> = vec![None; nodes.len()];
    let mut site_result_base: Vec<Slot> = Vec::with_capacity(graph.precompute_sites().len());
    for (site_id, site) in graph.precompute_sites().iter().enumerate() {
        let bank = precompute_result_bank(site.kind, site_domains[site_id])?;
        let base = match bank {
            Bank::Public => p_next,
            Bank::Shared => s_next,
            Bank::Local => unreachable!("precompute_result_bank never returns Local"),
        };
        site_result_base.push(Slot { bank, index: base });

        let mut physical_count = 0u32;
        for &node_idx in &live_nodes[site_id] {
            result_phys[node_idx] = Some(base + physical_count);
            physical_count += 1;
        }
        match bank {
            Bank::Public => p_next += physical_count,
            Bank::Shared => s_next += physical_count,
            Bank::Local => unreachable!("precompute_result_bank never returns Local"),
        }
    }

    let mut input_domains: Vec<Bank> = Vec::with_capacity(graph.num_inputs);
    let mut input_bindings: Vec<InputBinding> = Vec::new();
    for input_index in 0..graph.num_inputs {
        let sig = crate::ir::SignalIdx::new(graph.num_outputs + input_index);
        let d = signal_domain(graph, sig);
        input_domains.push(match d {
            Domain::Public => Bank::Public,
            Domain::Shared => Bank::Shared,
            Domain::Local => unreachable!("signal_domain never returns Local"),
        });
    }
    for (i, node) in nodes.iter().enumerate() {
        if let Op::Input(sig) = &node.op {
            let input_index = sig.index() - graph.num_outputs;
            let bank = input_domains[input_index];
            let s = match bank {
                Bank::Public => {
                    let idx = p_next;
                    p_next += 1;
                    Slot {
                        bank: Bank::Public,
                        index: idx,
                    }
                }
                Bank::Shared => {
                    let idx = s_next;
                    s_next += 1;
                    Slot {
                        bank: Bank::Shared,
                        index: idx,
                    }
                }
                Bank::Local => unreachable!("an input's domain is never Local"),
            };
            slot[i] = Some(s);
            input_bindings.push(InputBinding {
                bank,
                slot: s.index,
                input_index: u32::try_from(input_index).expect("input index does not fit into u32"),
            });
        }
    }

    // --- Phase B: the recyclable arena + instruction emission ---
    let mut arena = Arena {
        p: BankAlloc::starting_at(p_next),
        s: BankAlloc::starting_at(s_next),
        l: BankAlloc::starting_at(0),
        p_reserved_end: p_next,
        s_reserved_end: s_next,
        last_use,
    };

    let mut instructions: Vec<Instruction> = Vec::new();
    let mut rounds: Vec<RoundEntry> = vec![
        RoundEntry {
            operand_start: 0,
            len: 0,
            result_start: 0
        };
        graph.rounds().len()
    ];
    let mut round_operands: Vec<u32> = Vec::new();
    let mut round_results: Vec<u32> = Vec::new();

    // One entry per PrecomputeId, filled as each Op::Precompute node is walked.
    let mut site_inputs: Vec<Vec<SiteInput>> = vec![Vec::new(); graph.precompute_sites().len()];
    // The fused service consumes one Shared zero-test input per site - the IsZero site's original
    // input.
    let mut fusion_inputs: Vec<Vec<SiteInput>> = fusion_plans
        .iter()
        .map(|fusion| Vec::with_capacity(fusion.pairs.len()))
        .collect();

    let mut i = 0usize;
    while i < nodes.len() {
        let node = &nodes[i];
        match &node.op {
            Op::Constant(_) | Op::Input(_) => {
                // Slot already assigned in Phase A.
            }
            Op::Add | Op::Sub | Op::Mul => {
                let da = domain[node.inputs[0].index()];
                let db = domain[node.inputs[1].index()];
                let (opcode, dst_bank, swap) = select_opcode(&node.op, da, db)?;
                let sa = slot[node.inputs[0].index()].expect("operand not yet resolved");
                let sb = slot[node.inputs[1].index()].expect("operand not yet resolved");
                let (a, b) = if swap {
                    (sb.index, sa.index)
                } else {
                    (sa.index, sb.index)
                };
                let dst = arena.alloc(dst_bank);
                instructions.push(Instruction {
                    op: opcode,
                    dst,
                    a,
                    b,
                });
                slot[i] = Some(Slot {
                    bank: dst_bank,
                    index: dst,
                });
                arena.free_if_dead(node.inputs[0], i, &mut slot);
                arena.free_if_dead(node.inputs[1], i, &mut slot);
            }
            Op::MulLocal => {
                let sa = slot[node.inputs[0].index()].expect("operand not yet resolved");
                let sb = slot[node.inputs[1].index()].expect("operand not yet resolved");
                if domain[node.inputs[0].index()] != Domain::Shared
                    || domain[node.inputs[1].index()] != Domain::Shared
                {
                    eyre::bail!(
                        "codegen: MulLocal's operands must both be Shared (rep3's local_mul_vec \
                         needs two genuine shares) - got {:?}/{:?}",
                        domain[node.inputs[0].index()],
                        domain[node.inputs[1].index()]
                    );
                }
                let dst = arena.alloc(Bank::Local);
                instructions.push(Instruction {
                    op: Opcode::MulLocal,
                    dst,
                    a: sa.index,
                    b: sb.index,
                });
                slot[i] = Some(Slot {
                    bank: Bank::Local,
                    index: dst,
                });
                arena.free_if_dead(node.inputs[0], i, &mut slot);
                arena.free_if_dead(node.inputs[1], i, &mut slot);
            }
            Op::Round(round_id) => {
                let operand_start =
                    u32::try_from(round_operands.len()).expect("too many round operands");
                for &input in &node.inputs {
                    let s = slot[input.index()].expect("round operand not yet resolved");
                    if s.bank != Bank::Local {
                        eyre::bail!(
                            "codegen: a Round's operand must be a Local (MulLocal) value, got {:?}",
                            s.bank
                        );
                    }
                    round_operands.push(s.index);
                    arena.l.free(s.index, 0);
                }
                let len = u32::try_from(node.inputs.len())
                    .expect("round has more slots than fit into u32");

                // round_schedule guarantees a Round node is immediately followed by exactly `len`
                // RoundResult(0..len) nodes, in slot order - see its own module doc, and
                // docs/ARCHITECTURE.md, "MPC lowering". Codegen relies on the same guarantee its
                // own producer already asserts, rather than re-deriving the mapping some other way.
                let result_start =
                    u32::try_from(round_results.len()).expect("too many round results");
                for k in 0..node.inputs.len() {
                    let result_idx = i + 1 + k;
                    let expected_k = u32::try_from(k).unwrap();
                    match nodes.get(result_idx).map(|n| &n.op) {
                        Some(Op::RoundResult(slot_k)) if *slot_k == expected_k => {}
                        other => eyre::bail!(
                            "codegen: Round {} expected RoundResult({expected_k}) at node {result_idx}, \
                             found {other:?} - round_schedule's adjacency invariant was violated",
                            round_id.index()
                        ),
                    }
                    let dst = arena.alloc(Bank::Shared);
                    round_results.push(dst);
                    slot[result_idx] = Some(Slot {
                        bank: Bank::Shared,
                        index: dst,
                    });
                }
                rounds[round_id.index()] = RoundEntry {
                    operand_start,
                    len,
                    result_start,
                };
                instructions.push(Instruction {
                    op: Opcode::Reshare,
                    dst: 0,
                    a: u32::try_from(round_id.index()).expect("round id does not fit into u32"),
                    b: 0,
                });
                // Free every RoundResult(k) input that died the instant it was produced (rare -
                // an unread result would already have been dropped by an earlier gc in practice,
                // but the allocator handles it correctly regardless).
                for k in 0..node.inputs.len() {
                    let result_idx = i + 1 + k;
                    arena.free_if_dead(ValueId::new(result_idx), result_idx, &mut slot);
                }
                i += node.inputs.len(); // skip the RoundResult nodes just handled
            }
            Op::RoundResult(_) => {
                unreachable!(
                    "every RoundResult is consumed by its Round's own arm above - codegen never \
                     visits one on its own"
                );
            }
            Op::Precompute(site_id) => {
                // A site's inputs are ordinary operands, resolved like any other. They are *not*
                // required to be bare `Op::Input`/`Op::Constant`: batches are serviced at their own
                // point in the instruction stream (see `Opcode::Precompute`), so a site whose inputs
                // are computed is fine - which is what the merces circuits need, since their
                // Poseidon2 sites chain through secret multiplications.
                let mut inputs = Vec::with_capacity(node.inputs.len());
                for &input in &node.inputs {
                    let s = slot[input.index()].expect("precompute input not yet resolved");
                    if s.bank == Bank::Local {
                        eyre::bail!(
                            "codegen: precomputation site {} reads a Local (un-reshared MulLocal) \
                             value - it must be reshared first; this is a lowering invariant \
                             violation",
                            site_id.index()
                        );
                    }
                    inputs.push(SiteInput {
                        bank: s.bank,
                        slot: s.index,
                    });
                }
                site_inputs[site_id.index()] = inputs;
                // The Precompute node's own value is never read directly (only via
                // PrecomputeResult) - it needs no slot.
            }
            Op::PrecomputeResult(_) => {
                let Op::Precompute(site_id) = &nodes[node.inputs[0].index()].op else {
                    unreachable!("Graph::verify guarantees PrecomputeResult's input is Precompute");
                };
                let base = site_result_base[site_id.index()];
                let phys = result_phys[i].expect(
                    "every PrecomputeResult node that survives to codegen was counted \
                             into live_slots/live_nodes above",
                );
                slot[i] = Some(Slot {
                    bank: base.bank,
                    index: phys,
                });
            }
        }
        // Every batch anchored here is serviced now: all of its sites' inputs are resolved, and
        // `plan_precompute_batches` has checked that nothing reads its results before this point.
        for &batch_idx in &batches_at[i] {
            if let RuntimePlan::IsZeroReveal(fusion_idx) = runtime_plans[batch_idx] {
                let fusion = &fusion_plans[fusion_idx];
                debug_assert!(fusion_inputs[fusion_idx].is_empty());
                for pair in &fusion.pairs {
                    fusion_inputs[fusion_idx].push(site_inputs[pair.zero_test_site][0]);
                }
            }
            instructions.push(Instruction {
                op: Opcode::Precompute,
                dst: 0,
                a: u32::try_from(batch_idx).expect("more precompute batches than fit into u32"),
                b: 0,
            });
            // Site inputs were pinned to this anchor by the liveness extension above, so this is
            // where they become recyclable. A fused service retains the original IsZero operand,
            // not the intermediate result passed to Reveal.
            match runtime_plans[batch_idx] {
                RuntimePlan::Normal(plan_idx) => {
                    for &(_, site_node) in &plans[plan_idx].sites {
                        for &input in &nodes[site_node].inputs {
                            arena.free_if_dead(input, i, &mut slot);
                        }
                    }
                }
                RuntimePlan::IsZeroReveal(fusion_idx) => {
                    for pair in &fusion_plans[fusion_idx].pairs {
                        for &input in &nodes[pair.zero_test_node].inputs {
                            arena.free_if_dead(input, i, &mut slot);
                        }
                    }
                }
            }
        }
        i += 1;
    }

    // --- Assemble the planned batches; slot lists follow each plan's own site order ---
    let batches: Vec<PrecomputeBatch> = runtime_plans
        .iter()
        .map(|runtime| {
            if let RuntimePlan::IsZeroReveal(fusion_idx) = *runtime {
                let fusion = &fusion_plans[fusion_idx];
                let input_slots = fusion_inputs[fusion_idx].clone();
                let mut result_requests = Vec::new();
                let mut result_offsets = Vec::with_capacity(fusion.pairs.len() + 1);
                let mut result_targets = Vec::new();
                result_offsets.push(0);
                for pair in &fusion.pairs {
                    let source_site = pair.zero_test_site;
                    debug_assert_eq!(site_result_base[source_site].bank, Bank::Shared);
                    for (pos, &logical) in live_slots[source_site].iter().enumerate() {
                        debug_assert!(logical <= 1, "IsZero has exactly two result slots");
                        result_requests.push(logical);
                        result_targets.push(ResultTarget {
                            bank: Bank::Shared,
                            slot: result_phys[live_nodes[source_site][pos]]
                                .expect("every live source result has a physical slot"),
                        });
                    }

                    let reveal_base = site_result_base[pair.reveal_site];
                    debug_assert_eq!(reveal_base.bank, Bank::Public);
                    for (pos, &logical) in live_slots[pair.reveal_site].iter().enumerate() {
                        debug_assert_eq!(logical, 0);
                        result_requests.push(2 + logical);
                        result_targets.push(ResultTarget {
                            bank: Bank::Public,
                            slot: result_phys[live_nodes[pair.reveal_site][pos]]
                                .expect("every live Reveal result has a physical slot"),
                        });
                    }
                    result_offsets.push(
                        u32::try_from(result_requests.len()).expect("too many fused results"),
                    );
                }
                return PrecomputeBatch {
                    kind: BatchKind::IsZeroReveal,
                    sites: fusion.pairs.len(),
                    input_slots,
                    result_requests,
                    result_offsets,
                    result_targets,
                };
            }

            let RuntimePlan::Normal(plan_idx) = *runtime else {
                unreachable!("fused runtime plan returned above")
            };
            let plan = &plans[plan_idx];
            let mut input_slots = Vec::new();
            // Site-contiguous, ascending within a site: `result_requests[lo..hi]` (via
            // `result_offsets[site]..result_offsets[site + 1]`) is the sorted list of logical
            // slots this site actually needs, and `result_targets[lo..hi]` their destinations - two
            // sites in one batch may now have different live counts, which is exactly why a flat
            // `sites * capacity` shape (recovered by division) no longer works.
            let mut result_requests = Vec::new();
            let mut result_offsets = Vec::with_capacity(plan.sites.len() + 1);
            let mut result_targets = Vec::new();
            result_offsets.push(0u32);
            for &(site_id, _) in &plan.sites {
                input_slots.extend_from_slice(&site_inputs[site_id]);
                let base = site_result_base[site_id];
                debug_assert_eq!(
                    base.bank,
                    precompute_result_bank(plan.kind, plan.domain)
                        .expect("already validated while reserving site_result_base")
                );
                for (pos, &logical) in live_slots[site_id].iter().enumerate() {
                    result_requests.push(logical);
                    result_targets.push(ResultTarget {
                        bank: base.bank,
                        slot: result_phys[live_nodes[site_id][pos]]
                            .expect("every live precompute result has a physical slot"),
                    });
                }
                result_offsets.push(
                    u32::try_from(result_requests.len()).expect("too many precompute results"),
                );
            }
            PrecomputeBatch {
                kind: BatchKind::Precompute(plan.kind),
                sites: plan.sites.len(),
                input_slots,
                result_requests,
                result_offsets,
                result_targets,
            }
        })
        .collect();

    // Build a compile-time signal -> source table, then immediately project it into witness order.
    // This retains today's last-binding-wins behavior for the (normally unique) signal bindings,
    // without carrying the oversized signal address space into runtime.
    // Pass/codegen unit tests intentionally use hand-built graphs without a witness projection.
    // Preserve that diagnostic-only contract without requiring their synthetic signal metadata to
    // describe inputs that no runtime will ever project.
    let witness_sources = if graph.signal_to_witness.is_empty() {
        Vec::new()
    } else {
        let mut signal_sources = vec![None; graph.num_signals];
        *signal_sources
            .get_mut(0)
            .ok_or_else(|| eyre::eyre!("codegen: witness-bearing graph has no constant-one signal"))? =
            Some(WitnessSource::One);
        for &(signal, value) in graph.outputs() {
            let s = slot[value.index()].expect("output value not yet resolved");
            if s.bank == Bank::Local {
                eyre::bail!(
                    "codegen: a Local (MulLocal) value reached a circuit output directly - it must be \
                     reshared (Op::Round) first; this is a lowering invariant violation"
                );
            }
            let signal_index = signal.index() + 1;
            let destination = signal_sources.get_mut(signal_index).ok_or_else(|| {
                eyre::eyre!("codegen: output signal {signal_index} exceeds num_signals={}", graph.num_signals)
            })?;
            *destination = Some(WitnessSource::Slot {
                bank: s.bank,
                slot: s.index,
            });
        }
        for input_index in 0..graph.num_inputs {
            let signal = graph.num_outputs + input_index + 1;
            let destination = signal_sources.get_mut(signal).ok_or_else(|| {
                eyre::eyre!("codegen: input signal {signal} exceeds num_signals={}", graph.num_signals)
            })?;
            *destination = Some(WitnessSource::Input(
                u32::try_from(input_index).expect("input index does not fit into u32"),
            ));
        }
        graph
            .signal_to_witness
            .iter()
            .map(|&signal| {
                signal_sources
                    .get(signal)
                    .and_then(|source| *source)
                    .unwrap_or(WitnessSource::Zero)
            })
            .collect()
    };

    Ok(Program {
        instructions,
        constants,
        input_domains,
        inputs: input_bindings,
        rounds,
        round_operands,
        round_results,
        precompute_batches: batches,
        witness_sources,
        num_inputs: graph.num_inputs,
        slots: SlotCounts {
            public: arena.p.next,
            shared: arena.s.next,
            local: arena.l.next,
        },
    })
}

#[cfg(test)]
mod tests {
    use ark_bn254::{Fq, Fr};

    use super::*;
    use crate::ir::{Node, PrecomputeId, PrecomputeKind, PrecomputeSite, SignalIdx};

    #[test]
    fn slot_reuse_keeps_peak_width_below_node_count() {
        // A chain of 4 public additions where only the final sum is a circuit output - v2/v4/v6
        // are genuine SSA temporaries with no name of their own (matching how a single nested
        // circom expression like `out <== (((a+b)+c)+d)+e;` lowers: no intermediate
        // `LocalSignalWrite`, so none of them is a `graph.outputs()` entry - see
        // `frontend/inline.rs`). Each one's slot must free the instant the next addition consumes
        // it, so the 5 constants (permanently reserved) plus a couple of reused dynamic slots
        // should land well under one slot per node.
        let nodes = vec![
            Node::new(Op::Constant(Fr::from(1u64)), vec![]), // 0
            Node::new(Op::Constant(Fr::from(2u64)), vec![]), // 1
            Node::new(Op::Add, vec![ValueId::new(0), ValueId::new(1)]), // 2
            Node::new(Op::Constant(Fr::from(3u64)), vec![]), // 3
            Node::new(Op::Add, vec![ValueId::new(2), ValueId::new(3)]), // 4
            Node::new(Op::Constant(Fr::from(4u64)), vec![]), // 5
            Node::new(Op::Add, vec![ValueId::new(4), ValueId::new(5)]), // 6
            Node::new(Op::Constant(Fr::from(5u64)), vec![]), // 7
            Node::new(Op::Add, vec![ValueId::new(6), ValueId::new(7)]), // 8 (output)
        ];
        let graph: Graph<Fr> = Graph::from_parts(
            nodes,
            vec![(SignalIdx::new(0), ValueId::new(8))],
            vec![],
            vec![],
            vec![],
            vec![],
            0,
            1,
            2,
        );
        let program = compile(&graph).unwrap();
        assert!(
            (program.slots.public as usize) < graph.len(),
            "peak public-bank width ({}) should be well below the node count ({})",
            program.slots.public,
            graph.len()
        );
    }

    #[test]
    fn local_value_reaching_anything_but_reshare_is_rejected() {
        // x0, x1 = secret inputs; x2 = MulLocal(x0, x1), never reshared; x3 = Add(x2, x0) - a
        // Local value reaching a plain Add directly. mul_split/round_schedule never produce this
        // shape (MulLocal is always immediately wrapped by a Round), but codegen must still
        // reject it rather than silently mis-encode a Local slot as if it were Shared.
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]),
            Node::new(Op::Input(SignalIdx::new(2)), vec![]),
            Node::new(Op::MulLocal, vec![ValueId::new(0), ValueId::new(1)]),
            Node::new(Op::Add, vec![ValueId::new(2), ValueId::new(0)]),
        ];
        let mut graph: Graph<Fr> = Graph::from_parts(
            nodes,
            vec![(SignalIdx::new(0), ValueId::new(3))],
            vec![],
            vec![],
            vec![],
            vec![],
            2,
            1,
            4,
        );
        graph.mark_lowered();
        let err = compile(&graph).unwrap_err();
        assert!(err.to_string().contains("Local"), "{err}");
    }

    // --- Staged precomputation ---

    fn iszero_site() -> PrecomputeSite {
        PrecomputeSite {
            kind: PrecomputeKind::IsZero,
            header: "IsZero_0".to_owned(),
            num_inputs: 1,
            num_outputs: 1,
            num_intermediates: 1,
        }
    }

    fn reveal_site(n: usize) -> PrecomputeSite {
        PrecomputeSite {
            kind: PrecomputeKind::Reveal { n },
            header: format!("TACEO_REVEAL_{n}"),
            num_inputs: n,
            num_outputs: n,
            num_intermediates: 0,
        }
    }

    fn lowered_graph(
        nodes: Vec<Node<Fr>>,
        outputs: Vec<(SignalIdx, ValueId)>,
        sites: Vec<PrecomputeSite>,
        num_inputs: usize,
    ) -> Graph<Fr> {
        let mut graph = Graph::from_parts(
            nodes,
            outputs,
            sites,
            vec![],
            vec![],
            vec![],
            num_inputs,
            1,
            num_inputs + 4,
        );
        graph.mark_lowered();
        graph
    }

    /// The batching contract: N independent same-kind sites are **one** driver call, not N.
    #[test]
    fn same_kind_sites_at_one_stage_share_one_batch() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0
            Node::new(Op::Input(SignalIdx::new(2)), vec![]), // 1
            Node::new(Op::Precompute(PrecomputeId::new(0)), vec![ValueId::new(0)]), // 2
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(2)]), // 3
            Node::new(Op::Precompute(PrecomputeId::new(1)), vec![ValueId::new(1)]), // 4
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(4)]), // 5
            Node::new(Op::Add, vec![ValueId::new(3), ValueId::new(5)]), // 6
        ];
        let graph = lowered_graph(
            nodes,
            vec![(SignalIdx::new(0), ValueId::new(6))],
            vec![iszero_site(), iszero_site()],
            2,
        );
        let program = compile(&graph).unwrap();
        assert_eq!(program.precompute_batches.len(), 1);
        assert_eq!(program.precompute_batches[0].sites, 2);
        assert_eq!(
            program
                .instructions
                .iter()
                .filter(|instr| instr.op == Opcode::Precompute)
                .count(),
            1
        );
    }

    #[test]
    fn sole_shared_iszero_output_revealed_once_is_fused_at_codegen() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0: x
            Node::new(Op::Precompute(PrecomputeId::new(0)), vec![ValueId::new(0)]), // 1: IsZero
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(1)]), // 2: out
            Node::new(Op::PrecomputeResult(1), vec![ValueId::new(1)]), // 3: inv
            Node::new(Op::Precompute(PrecomputeId::new(1)), vec![ValueId::new(2)]), // 4: Reveal
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(4)]), // 5: revealed
        ];
        let graph = lowered_graph(
            nodes,
            vec![
                (SignalIdx::new(0), ValueId::new(5)),
                (SignalIdx::new(2), ValueId::new(2)),
                (SignalIdx::new(3), ValueId::new(3)),
            ],
            vec![iszero_site(), reveal_site(1)],
            1,
        );
        let program = compile(&graph).unwrap();

        assert_eq!(program.precompute_batches.len(), 1);
        let batch = &program.precompute_batches[0];
        assert_eq!(batch.kind, BatchKind::IsZeroReveal);
        assert_eq!(batch.sites, 1);
        assert_eq!(batch.result_requests, vec![0, 1, 2]);
        assert_eq!(
            batch
                .result_targets
                .iter()
                .map(|target| target.bank)
                .collect::<Vec<_>>(),
            vec![Bank::Shared, Bank::Shared, Bank::Public]
        );
    }

    #[test]
    fn two_eligible_iszero_reveal_pairs_fuse_as_one_batch() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0: x
            Node::new(Op::Input(SignalIdx::new(2)), vec![]), // 1: y
            Node::new(Op::Precompute(PrecomputeId::new(0)), vec![ValueId::new(0)]), // 2: IsZero(x)
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(2)]), // 3: x.out
            Node::new(Op::PrecomputeResult(1), vec![ValueId::new(2)]), // 4: x.inv
            Node::new(Op::Precompute(PrecomputeId::new(1)), vec![ValueId::new(1)]), // 5: IsZero(y)
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(5)]), // 6: y.out
            Node::new(Op::PrecomputeResult(1), vec![ValueId::new(5)]), // 7: y.inv
            Node::new(Op::Precompute(PrecomputeId::new(2)), vec![ValueId::new(3)]), // 8: Reveal(x.out)
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(8)]),              // 9
            Node::new(Op::Precompute(PrecomputeId::new(3)), vec![ValueId::new(6)]), // 10: Reveal(y.out)
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(10)]),             // 11
        ];
        let graph = lowered_graph(
            nodes,
            vec![
                (SignalIdx::new(0), ValueId::new(9)),
                (SignalIdx::new(2), ValueId::new(4)),
                (SignalIdx::new(3), ValueId::new(11)),
                (SignalIdx::new(4), ValueId::new(7)),
            ],
            vec![iszero_site(), iszero_site(), reveal_site(1), reveal_site(1)],
            2,
        );
        let program = compile(&graph).unwrap();

        assert_eq!(program.precompute_batches.len(), 1);
        let batch = &program.precompute_batches[0];
        assert_eq!(batch.kind, BatchKind::IsZeroReveal);
        assert_eq!(batch.sites, 2);
        assert_eq!(batch.result_offsets, vec![0, 3, 6]);
        assert_eq!(batch.result_requests, vec![0, 1, 2, 0, 1, 2]);
    }

    #[test]
    fn partially_revealed_iszero_batch_remains_unfused() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0: x
            Node::new(Op::Input(SignalIdx::new(2)), vec![]), // 1: y
            Node::new(Op::Precompute(PrecomputeId::new(0)), vec![ValueId::new(0)]), // 2: IsZero(x)
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(2)]), // 3: x.out
            Node::new(Op::PrecomputeResult(1), vec![ValueId::new(2)]), // 4: x.inv
            Node::new(Op::Precompute(PrecomputeId::new(1)), vec![ValueId::new(1)]), // 5: IsZero(y)
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(5)]), // 6: y.out
            Node::new(Op::PrecomputeResult(1), vec![ValueId::new(5)]), // 7: y.inv
            Node::new(Op::Precompute(PrecomputeId::new(2)), vec![ValueId::new(3)]), // 8: Reveal(x.out)
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(8)]),              // 9
        ];
        let graph = lowered_graph(
            nodes,
            vec![
                (SignalIdx::new(0), ValueId::new(9)),
                (SignalIdx::new(2), ValueId::new(4)),
                (SignalIdx::new(3), ValueId::new(6)),
                (SignalIdx::new(4), ValueId::new(7)),
            ],
            vec![iszero_site(), iszero_site(), reveal_site(1)],
            2,
        );
        let program = compile(&graph).unwrap();

        assert_eq!(program.precompute_batches.len(), 2);
        assert_eq!(
            program.precompute_batches[0].kind,
            BatchKind::Precompute(PrecomputeKind::IsZero)
        );
        assert_eq!(program.precompute_batches[0].sites, 2);
        assert!(program
            .precompute_batches
            .iter()
            .all(|batch| batch.kind != BatchKind::IsZeroReveal));
    }

    #[test]
    fn reveal_consuming_iszero_inverse_is_not_fused() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0: x
            Node::new(Op::Precompute(PrecomputeId::new(0)), vec![ValueId::new(0)]), // 1: IsZero
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(1)]), // 2: out
            Node::new(Op::PrecomputeResult(1), vec![ValueId::new(1)]), // 3: inv
            Node::new(Op::Precompute(PrecomputeId::new(1)), vec![ValueId::new(3)]), // 4: Reveal(inv)
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(4)]), // 5: revealed inv
        ];
        let graph = lowered_graph(
            nodes,
            vec![
                (SignalIdx::new(0), ValueId::new(5)),
                (SignalIdx::new(2), ValueId::new(2)),
                (SignalIdx::new(3), ValueId::new(3)),
            ],
            vec![iszero_site(), reveal_site(1)],
            1,
        );
        let program = compile(&graph).unwrap();

        assert_eq!(program.precompute_batches.len(), 2);
        assert!(program
            .precompute_batches
            .iter()
            .all(|batch| batch.kind != BatchKind::IsZeroReveal));
    }

    #[test]
    fn iszero_with_an_extra_computational_consumer_is_not_fused() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0: x
            Node::new(Op::Precompute(PrecomputeId::new(0)), vec![ValueId::new(0)]), // 1
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(1)]), // 2: out
            Node::new(Op::PrecomputeResult(1), vec![ValueId::new(1)]), // 3: inv
            Node::new(Op::Add, vec![ValueId::new(2), ValueId::new(0)]), // 4: extra reader
            Node::new(Op::Precompute(PrecomputeId::new(1)), vec![ValueId::new(2)]), // 5
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(5)]), // 6
        ];
        let graph = lowered_graph(
            nodes,
            vec![
                (SignalIdx::new(0), ValueId::new(6)),
                (SignalIdx::new(2), ValueId::new(3)),
                (SignalIdx::new(3), ValueId::new(4)),
            ],
            vec![iszero_site(), reveal_site(1)],
            1,
        );
        let program = compile(&graph).unwrap();

        assert_eq!(program.precompute_batches.len(), 2);
        assert!(program
            .precompute_batches
            .iter()
            .all(|batch| batch.kind != BatchKind::IsZeroReveal));
    }

    #[test]
    fn iszero_inverse_with_a_computational_consumer_is_not_fused() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0: x
            Node::new(Op::Precompute(PrecomputeId::new(0)), vec![ValueId::new(0)]), // 1
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(1)]), // 2: out
            Node::new(Op::PrecomputeResult(1), vec![ValueId::new(1)]), // 3: inv
            Node::new(Op::Add, vec![ValueId::new(3), ValueId::new(0)]), // 4: inv reader
            Node::new(Op::Precompute(PrecomputeId::new(1)), vec![ValueId::new(2)]), // 5
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(5)]), // 6
        ];
        let graph = lowered_graph(
            nodes,
            vec![
                (SignalIdx::new(0), ValueId::new(6)),
                (SignalIdx::new(2), ValueId::new(4)),
            ],
            vec![iszero_site(), reveal_site(1)],
            1,
        );
        let program = compile(&graph).unwrap();

        assert_eq!(program.precompute_batches.len(), 2);
        assert!(program
            .precompute_batches
            .iter()
            .all(|batch| batch.kind != BatchKind::IsZeroReveal));
    }

    #[test]
    fn public_iszero_reveal_path_is_not_fused() {
        let nodes = vec![
            Node::new(Op::Constant(Fr::from(0u64)), vec![]), // 0: public x
            Node::new(Op::Precompute(PrecomputeId::new(0)), vec![ValueId::new(0)]), // 1
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(1)]), // 2
            Node::new(Op::PrecomputeResult(1), vec![ValueId::new(1)]), // 3
            Node::new(Op::Precompute(PrecomputeId::new(1)), vec![ValueId::new(2)]), // 4
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(4)]), // 5
        ];
        let graph = lowered_graph(
            nodes,
            vec![
                (SignalIdx::new(0), ValueId::new(5)),
                (SignalIdx::new(2), ValueId::new(3)),
            ],
            vec![iszero_site(), reveal_site(1)],
            0,
        );
        let program = compile(&graph).unwrap();

        assert_eq!(program.precompute_batches.len(), 2);
        assert!(program
            .precompute_batches
            .iter()
            .all(|batch| batch.kind != BatchKind::IsZeroReveal));
    }

    #[test]
    fn non_bn254_iszero_reveal_path_is_not_fused() {
        let nodes: Vec<Node<Fq>> = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0
            Node::new(Op::Precompute(PrecomputeId::new(0)), vec![ValueId::new(0)]), // 1
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(1)]), // 2
            Node::new(Op::Precompute(PrecomputeId::new(1)), vec![ValueId::new(2)]), // 3
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(3)]), // 4
        ];
        let mut graph: Graph<Fq> = Graph::from_parts(
            nodes,
            vec![(SignalIdx::new(0), ValueId::new(4))],
            vec![iszero_site(), reveal_site(1)],
            vec![],
            vec![],
            vec![],
            1,
            1,
            5,
        );
        graph.mark_lowered();
        let program = compile(&graph).unwrap();
        assert!(program
            .precompute_batches
            .iter()
            .all(|batch| batch.kind != BatchKind::IsZeroReveal));
    }

    /// Codegen remains safe for a valid topological graph that was not level-sorted: an early
    /// result consumer closes the active batch instead of making a later independent site move the
    /// batch anchor past that consumer.
    #[test]
    fn early_consumer_defensively_splits_an_unsorted_batch() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0: x
            Node::new(Op::Input(SignalIdx::new(2)), vec![]), // 1: y
            Node::new(Op::Precompute(PrecomputeId::new(0)), vec![ValueId::new(0)]), // 2: A
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(2)]), // 3
            Node::new(Op::Add, vec![ValueId::new(3), ValueId::new(0)]), // 4: reads A
            Node::new(Op::Precompute(PrecomputeId::new(1)), vec![ValueId::new(1)]), // 5: B
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(5)]), // 6
            Node::new(Op::Add, vec![ValueId::new(4), ValueId::new(6)]), // 7
        ];
        let graph = lowered_graph(
            nodes,
            vec![(SignalIdx::new(0), ValueId::new(7))],
            vec![iszero_site(), iszero_site()],
            2,
        );
        let program = compile(&graph).unwrap();
        assert_eq!(program.precompute_batches.len(), 2);
        assert!(program
            .precompute_batches
            .iter()
            .all(|batch| batch.sites == 1));
    }

    /// Dependent sites can't share a driver call, and each batch's instruction must precede anything
    /// that reads its results. The positional assertion is what actually tests interleaving - an
    /// up-front phase would place both batches before instruction 0 and still pass a count check.
    #[test]
    fn chained_same_kind_sites_become_two_batches_in_stage_order() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0
            Node::new(Op::Precompute(PrecomputeId::new(0)), vec![ValueId::new(0)]), // 1
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(1)]), // 2
            // Reading site 0's result forces site 1 into a later stage.
            Node::new(Op::Add, vec![ValueId::new(2), ValueId::new(0)]), // 3
            Node::new(Op::Precompute(PrecomputeId::new(1)), vec![ValueId::new(3)]), // 4
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(4)]),  // 5
            Node::new(Op::Add, vec![ValueId::new(5), ValueId::new(0)]), // 6
        ];
        let graph = lowered_graph(
            nodes,
            vec![(SignalIdx::new(0), ValueId::new(6))],
            vec![iszero_site(), iszero_site()],
            1,
        );
        let program = compile(&graph).unwrap();
        assert_eq!(program.precompute_batches.len(), 2);
        assert!(program.precompute_batches.iter().all(|b| b.sites == 1));

        let batch_pos: Vec<usize> = (0..2)
            .map(|batch_idx| {
                program
                    .instructions
                    .iter()
                    .position(|instr| {
                        instr.op == Opcode::Precompute && instr.a as usize == batch_idx
                    })
                    .expect("every batch has an instruction")
            })
            .collect();
        assert!(
            batch_pos[0] < batch_pos[1],
            "batches must be serviced in stage order: {batch_pos:?}"
        );

        // Batch 0's result slot must be written before any instruction reads it.
        let result_slot = program.precompute_batches[0].result_targets[0].slot;
        let first_reader = program
            .instructions
            .iter()
            .position(|instr| {
                matches!(instr.op, Opcode::AddSS | Opcode::AddSP)
                    && (instr.a == result_slot || instr.b == result_slot)
            })
            .expect("something reads batch 0's result");
        assert!(
            batch_pos[0] < first_reader,
            "batch 0 is serviced at {} but read at {first_reader}",
            batch_pos[0]
        );
    }

    /// A site input's slot must still hold its value when the *batch* runs, which is later than the
    /// `Op::Precompute` node that reads it. Without the liveness extension the allocator could
    /// recycle it in between and a later instruction would clobber the gadget's input.
    ///
    /// Note this graph deliberately does **not** bind the site input to `graph.outputs()`, which is
    /// what masks the hazard on frontend-produced graphs (`inline_precomputed` binds every one).
    #[test]
    fn site_input_slot_survives_until_its_batch_runs() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0
            Node::new(Op::Input(SignalIdx::new(2)), vec![]), // 1
            // A computed value whose only graph reader is site 0's Precompute node.
            Node::new(Op::Add, vec![ValueId::new(0), ValueId::new(1)]), // 2
            Node::new(Op::Precompute(PrecomputeId::new(0)), vec![ValueId::new(2)]), // 3
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(3)]),  // 4
            // Site 1 is defined later, so the shared batch is anchored past node 3 - the window in
            // which node 2's slot must not be recycled.
            Node::new(Op::Add, vec![ValueId::new(0), ValueId::new(0)]), // 5
            Node::new(Op::Precompute(PrecomputeId::new(1)), vec![ValueId::new(5)]), // 6
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(6)]),  // 7
            Node::new(Op::Add, vec![ValueId::new(4), ValueId::new(7)]), // 8
        ];
        let graph = lowered_graph(
            nodes,
            vec![(SignalIdx::new(0), ValueId::new(8))],
            vec![iszero_site(), iszero_site()],
            2,
        );
        let program = compile(&graph).unwrap();
        assert_eq!(
            program.precompute_batches.len(),
            1,
            "both sites are stage 0"
        );
        let batch = &program.precompute_batches[0];
        let batch_pos = program
            .instructions
            .iter()
            .position(|instr| instr.op == Opcode::Precompute)
            .expect("the batch has an instruction");

        // No instruction before the batch may write to any of its input slots (other than the
        // instruction that legitimately produced that input in the first place).
        for input in &batch.input_slots {
            assert_eq!(input.bank, Bank::Shared);
            let clobbers = program.instructions[..batch_pos]
                .iter()
                .filter(|instr| {
                    !matches!(instr.op, Opcode::Precompute | Opcode::Reshare)
                        && instr.dst == input.slot
                })
                .count();
            assert!(
                clobbers <= 1,
                "slot {} is written {clobbers} times before its batch runs at {batch_pos}",
                input.slot
            );
        }
    }

    /// A literal passed to a gadget resolves to a `Public`-bank slot. This is the shape
    /// `circuits/merces/oblivious_vector/hash.circom` uses
    /// (`TACEO_PRECOMPUTATION_Poseidon2(4)([value, 0, r, commitDs()])`); rejecting it, as codegen
    /// once did, blocks that circuit outright.
    #[test]
    fn public_constant_site_input_is_recorded_as_a_public_bank_slot() {
        let nodes = vec![
            Node::new(Op::Constant(Fr::from(7u64)), vec![]), // 0
            Node::new(Op::Precompute(PrecomputeId::new(0)), vec![ValueId::new(0)]), // 1
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(1)]), // 2
        ];
        let graph = lowered_graph(
            nodes,
            vec![(SignalIdx::new(0), ValueId::new(2))],
            vec![iszero_site()],
            0,
        );
        let program = compile(&graph).unwrap();
        let batch = &program.precompute_batches[0];
        assert_eq!(batch.input_slots.len(), 1);
        assert_eq!(batch.input_slots[0].bank, Bank::Public);
    }

    /// Sparse result slots (some logical slots' `PrecomputeResult` node pruned by
    /// `passes::dead_signals` before codegen ever runs) must compact to exactly the surviving
    /// count, not the site's full reserved capacity - and each survivor must land at its position
    /// *within the survivors*, not at its original logical index.
    #[test]
    fn sparse_result_slots_are_compacted_in_order() {
        // A capacity-3 site (1 output + 2 intermediates) where only logical slots 0 and 2 survive -
        // slot 1's `PrecomputeResult` node simply never exists, exactly as `dead_signals` + `gc`
        // would leave it.
        let site = PrecomputeSite {
            kind: PrecomputeKind::IsZero,
            header: "IsZero_0".to_owned(),
            num_inputs: 1,
            num_outputs: 1,
            num_intermediates: 2,
        };
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0
            Node::new(Op::Precompute(PrecomputeId::new(0)), vec![ValueId::new(0)]), // 1
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(1)]), // 2: survives
            Node::new(Op::PrecomputeResult(2), vec![ValueId::new(1)]), // 3: survives
            Node::new(Op::Add, vec![ValueId::new(2), ValueId::new(3)]), // 4
        ];
        let graph = lowered_graph(
            nodes,
            vec![(SignalIdx::new(0), ValueId::new(4))],
            vec![site],
            1,
        );
        let program = compile(&graph).unwrap();

        assert_eq!(program.precompute_batches.len(), 1);
        let batch = &program.precompute_batches[0];
        assert_eq!(
            batch.result_requests,
            vec![0, 2],
            "requests logical slots 0 and 2 only"
        );
        assert_eq!(
            batch.result_offsets,
            vec![0, 2],
            "one site, both its requests"
        );
        assert_eq!(
            batch.result_targets.len(),
            2,
            "the reserved region is 2 wide (the live count), not the site's capacity of 3"
        );
        // The two surviving results must land at adjacent physical slots (base, base + 1), not at
        // their original logical indices 0 and 2.
        assert_eq!(
            batch.result_targets[1].slot,
            batch.result_targets[0].slot + 1
        );
    }

    /// A `Local` value feeding a site is a lowering-invariant violation, not a circuit shape.
    #[test]
    fn local_value_feeding_a_site_is_rejected() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0
            Node::new(Op::Input(SignalIdx::new(2)), vec![]), // 1
            Node::new(Op::MulLocal, vec![ValueId::new(0), ValueId::new(1)]), // 2
            Node::new(Op::Precompute(PrecomputeId::new(0)), vec![ValueId::new(2)]), // 3
            Node::new(Op::PrecomputeResult(0), vec![ValueId::new(3)]), // 4
        ];
        let graph = lowered_graph(
            nodes,
            vec![(SignalIdx::new(0), ValueId::new(4))],
            vec![iszero_site()],
            2,
        );
        let err = compile(&graph).unwrap_err().to_string();
        assert!(err.contains("Local"), "unexpected error: {err}");
    }
}
