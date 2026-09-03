//! `Graph` -> `Program`: not a `Pass` (it changes representation, not the IR), called by
//! `circom_mpc_compiler::compile` once `PassManager` has finished lowering. A single forward walk
//! over `graph.nodes()` (already topologically ordered) doing three things at
//! once: classifying each value's `Domain` (reusing `passes::mpc::domain`, the same analysis
//! `mul_split` used while lowering), linear-scan slot allocation over liveness, and instruction
//! emission.

use ark_bn254::Fr;
use circom_mpc_program::{
    Bank, BatchIdx, BatchKind, GadgetBatch, InputBinding, InputIdx, InputSignal, Instruction,
    Opcode, Program, ProgramParts, ResultSlot, ResultTarget, RoundEntry, RoundIdx, SiteInput, Slot,
    SlotCounts, WitnessSource,
};

use crate::{
    ir::{GadgetKind, Graph, Node, Op, RoundId, ValueId},
    passes::mpc::{
        domain::{Domain, compute_domains, signal_domain},
        gadget_schedule::{BatchPlan, IsZeroRevealPlan, ScheduledBatch, plan_gadget_batches},
    },
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

/// Where one node's value currently lives: a bank plus a bank-relative physical slot.
#[derive(Clone, Copy)]
struct Loc {
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
    fn free_if_dead(&mut self, value: ValueId, current: usize, slot: &mut [Option<Loc>]) {
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

/// Last node index (in graph order) that reads each value - a value with no reader at all keeps
/// its own index (dead by construction only if `gc` missed it, which it shouldn't - see
/// `Graph::gc`). A value referenced by `graph.outputs()` gets `nodes.len()` (never freed): its
/// slot must still hold the right value after the instruction stream finishes, when the direct
/// witness-source projection reads it - freeing it mid-stream would let a later instruction
/// clobber it.
fn compute_last_use(graph: &Graph) -> Vec<usize> {
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
fn select_opcode(op: &Op, da: Domain, db: Domain) -> eyre::Result<(Opcode, Bank, bool)> {
    use Domain::{Public, Shared};
    if da == Domain::Local || db == Domain::Local {
        eyre::bail!(
            "codegen: a Local-domain value reached {op:?} directly - it must only ever feed a \
             Round (rep3's reshare); this is a lowering invariant violation, not a supported circuit \
             shape"
        );
    }
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

/// Which bank a gadget site's results live in. Every kind but [`GadgetKind::Reveal`]
/// keeps the site's own domain (deterministic public work stays `Public`, a real share stays
/// `Shared`) - `Reveal`'s entire purpose is to leave the `Public` domain regardless of whether its
/// own input was `Shared`, since that is exactly what a genuine MPC open does. `precomputed` is
/// `true` only for a `Shared` site - callers (`codegen::compile`,
/// `passes::mpc::gadget_schedule::plan_gadget_batches`) already downgrade an all-public
/// `TACEO_PRECOMPUTATION_Poseidon2` site to an ordinary one before calling this, since the host has
/// nothing to precompute for it; `precomputed && domain != Shared` reaching here is their bug, not
/// the circuit's.
fn gadget_result_bank(kind: GadgetKind, domain: Domain, precomputed: bool) -> eyre::Result<Bank> {
    if domain == Domain::Local {
        eyre::bail!(
            "codegen: a gadget site reads a Local (un-reshared MulLocal) value - it must \
             be reshared first; this is a lowering invariant violation"
        );
    }
    if precomputed {
        eyre::ensure!(
            domain == Domain::Shared,
            "codegen: a host-precomputed {kind:?} site is all-Public - the caller should have \
             downgraded it to an ordinary gadget site before calling gadget_result_bank"
        );
        return Ok(Bank::Shared);
    }
    if matches!(kind, GadgetKind::Reveal { .. }) {
        return Ok(Bank::Public);
    }
    Ok(match domain {
        Domain::Public => Bank::Public,
        Domain::Shared => Bank::Shared,
        Domain::Local => unreachable!("checked above"),
    })
}

/// The scheduler's runtime batches plus the node at which each one is serviced.
struct BatchSchedule {
    plans: Vec<ScheduledBatch>,
    batches_at: Vec<Vec<usize>>,
}

/// Plans the gadget batches, folds in the fusions, and extends `last_use` so a site's inputs stay
/// alive until its batch's anchor.
fn plan_batches(graph: &Graph, domain: &[Domain], last_use: &mut [usize]) -> BatchSchedule {
    let nodes = graph.nodes();
    let plans = plan_gadget_batches(graph, domain);

    // A site's inputs must still hold their values when its *batch* runs, which is later than the
    // `Op::Gadget` node that reads them - so extend their lifetimes to the batch's anchor.
    // Without this the allocator recycles a witness-dead site input's slot between the node and
    // the service point (dead-code elimination frequently unpins gadget input signals from the
    // witness on real circuits).
    for plan in &plans {
        match plan {
            ScheduledBatch::Gadget(plan) => {
                for &(_, site_node) in &plan.sites {
                    for input in &nodes[site_node].inputs {
                        last_use[input.index()] = last_use[input.index()].max(plan.anchor);
                    }
                }
            }
            ScheduledBatch::IsZeroReveal(fusion) => {
                for site in &fusion.sites {
                    last_use[site.input.index()] = last_use[site.input.index()].max(fusion.anchor);
                }
            }
        }
    }

    // Batch indices anchored at each node, emitted right after that node is processed.
    let mut batches_at: Vec<Vec<usize>> = vec![Vec::new(); nodes.len()];
    for (batch_idx, plan) in plans.iter().enumerate() {
        batches_at[plan.anchor()].push(batch_idx);
    }

    BatchSchedule { plans, batches_at }
}

/// Where each site's surviving results live.
struct GadgetResultLayout {
    /// Per site, the logical result slots that survived to codegen, ascending.
    live_slots: Vec<Vec<u32>>,
    /// Parallel to `live_slots`: the `GadgetResult` node backing each surviving logical slot.
    live_nodes: Vec<Vec<usize>>,
    /// Node-indexed physical slot for every surviving `GadgetResult`.
    result_phys: Vec<Option<u32>>,
    site_result_base: Vec<Loc>,
}

/// Phase A's result: the reserved (never recycled) slot regions - constants, gadget results, kept
/// inputs - and the tables that map a surviving `GadgetResult` node to its physical slot.
struct Reservation {
    slot: Vec<Option<Loc>>,
    constants: Vec<Fr>,
    gadgets: GadgetResultLayout,
    input_domains: Vec<Bank>,
    input_bindings: Vec<InputBinding>,
    input_signals: Vec<InputSignal>,
    p_next: u32,
    s_next: u32,
}

/// Phase A: reserves the non-recycled regions of both banks.
///
/// Public bank: constants, public gadget results, then Public-domain kept `Op::Input`.
/// Shared bank: shared gadget results, then Shared-domain kept `Op::Input`.
fn reserve_slots(graph: &Graph, domain: &[Domain]) -> eyre::Result<Reservation> {
    let nodes = graph.nodes();
    let mut slot: Vec<Option<Loc>> = vec![None; nodes.len()];
    let mut constants: Vec<Fr> = Vec::new();
    let mut p_next: u32 = 0;
    let mut s_next: u32 = 0;

    for (i, node) in nodes.iter().enumerate() {
        if let Op::Constant(c) = &node.op {
            slot[i] = Some(Loc {
                bank: Bank::Public,
                index: p_next,
            });
            constants.push(*c);
            p_next += 1;
        }
    }

    let gadgets = reserve_gadget_results(graph, domain, &mut p_next, &mut s_next)?;
    let (input_domains, input_bindings) =
        reserve_inputs(graph, &mut slot, &mut p_next, &mut s_next)?;

    let input_signals: Vec<InputSignal> = graph
        .input_list()
        .iter()
        .map(|(name, offset, size)| InputSignal {
            name: name.clone(),
            offset: *offset,
            size: *size,
        })
        .collect();

    Ok(Reservation {
        slot,
        constants,
        gadgets,
        input_domains,
        input_bindings,
        input_signals,
        p_next,
        s_next,
    })
}

/// Reserves each gadget site's surviving result slots, contiguously and in site order.
fn reserve_gadget_results(
    graph: &Graph,
    domain: &[Domain],
    p_next: &mut u32,
    s_next: &mut u32,
) -> eyre::Result<GadgetResultLayout> {
    let nodes = graph.nodes();
    let num_sites = graph.gadget_sites().len();
    let mut site_domains = vec![Domain::Public; num_sites];
    for (i, node) in nodes.iter().enumerate() {
        if let Op::Gadget(site_id) = &node.op {
            site_domains[site_id.index()] = domain[i];
        }
    }

    // Every site's *surviving* result slots: `passes::dead_code` (run before `gc`) has already
    // dropped the `outputs` binding for every witness-dead result, and `gc` then deleted the
    // now-unreferenced `Op::GadgetResult` nodes - so a site's reserved region only needs to be
    // as wide as what's left, not its full `num_outputs + num_intermediates` capacity. On a
    // circuit with a large batch of gadget sites, this is the difference between thousands of
    // Poseidon2 result slots per site and the handful actually read.
    let mut live_slots: Vec<Vec<u32>> = vec![Vec::new(); num_sites];
    let mut live_nodes: Vec<Vec<usize>> = vec![Vec::new(); num_sites];
    for (i, node) in nodes.iter().enumerate() {
        if let Op::GadgetResult(k) = &node.op {
            let Op::Gadget(site_id) = &nodes[node.inputs[0].index()].op else {
                unreachable!("a GadgetResult's input is always its Gadget node");
            };
            live_slots[site_id.index()].push(*k);
            live_nodes[site_id.index()].push(i);
        }
    }
    debug_assert!(
        live_slots.iter().all(|s| s.windows(2).all(|w| w[0] < w[1])),
        "a site's surviving GadgetResult nodes must stay in ascending slot order - gc and \
         dead_code never reorder nodes, only drop them - since the flat, site-contiguous \
         request list below depends on it"
    );

    let mut result_phys: Vec<Option<u32>> = vec![None; nodes.len()];
    let mut site_result_base: Vec<Loc> = Vec::with_capacity(num_sites);
    for (site_id, site) in graph.gadget_sites().iter().enumerate() {
        // Mirrors `gadget_schedule::plan_gadget_batches`'s own downgrade: a wrapped site with
        // nothing to precompute (fully public) falls through to an ordinary gadget site instead
        // of erroring, so `site_result_base`'s bank always matches the batch `plan.precomputed`
        // built from the same site.
        let precomputed = site.precomputed && site_domains[site_id] == Domain::Shared;
        let bank = gadget_result_bank(site.kind, site_domains[site_id], precomputed)?;
        let base = match bank {
            Bank::Public => *p_next,
            Bank::Shared => *s_next,
            Bank::Local => unreachable!("gadget_result_bank never returns Local"),
        };
        site_result_base.push(Loc { bank, index: base });

        let mut physical_count = 0u32;
        for &node_idx in &live_nodes[site_id] {
            result_phys[node_idx] = Some(base + physical_count);
            physical_count += 1;
        }
        match bank {
            Bank::Public => *p_next += physical_count,
            Bank::Shared => *s_next += physical_count,
            Bank::Local => unreachable!("gadget_result_bank never returns Local"),
        }
    }

    Ok(GadgetResultLayout {
        live_slots,
        live_nodes,
        result_phys,
        site_result_base,
    })
}

/// Reserves one slot per kept `Op::Input` node, in its input's own bank.
fn reserve_inputs(
    graph: &Graph,
    slot: &mut [Option<Loc>],
    p_next: &mut u32,
    s_next: &mut u32,
) -> eyre::Result<(Vec<Bank>, Vec<InputBinding>)> {
    let mut input_domains: Vec<Bank> = Vec::with_capacity(graph.num_inputs());
    let mut input_bindings: Vec<InputBinding> = Vec::new();
    let nodes = graph.nodes();
    for input_index in 0..graph.num_inputs() {
        let sig = crate::ir::SignalIdx::new(graph.num_outputs() + input_index);
        input_domains.push(match signal_domain(graph, sig) {
            Domain::Public => Bank::Public,
            Domain::Shared => Bank::Shared,
            Domain::Local => unreachable!("signal_domain never returns Local"),
        });
    }
    for (i, node) in nodes.iter().enumerate() {
        if let Op::Input(sig) = &node.op {
            let input_index = sig.index() - graph.num_outputs();
            let bank = input_domains[input_index];
            let index = match bank {
                Bank::Public => {
                    *p_next += 1;
                    *p_next - 1
                }
                Bank::Shared => {
                    *s_next += 1;
                    *s_next - 1
                }
                Bank::Local => unreachable!("an input's domain is never Local"),
            };
            slot[i] = Some(Loc { bank, index });
            input_bindings.push(InputBinding {
                bank,
                slot: Slot::new(index),
                input_index: InputIdx::try_from(input_index)?,
            });
        }
    }
    Ok((input_domains, input_bindings))
}

/// Phase B's result: the instruction stream plus the per-site operand lists the batch tables are
/// assembled from.
struct Emission {
    instructions: Vec<Instruction>,
    rounds: Vec<RoundEntry>,
    round_operands: Vec<Slot>,
    round_results: Vec<Slot>,
    /// One entry per `GadgetId`, filled as each `Op::Gadget` node is walked.
    site_inputs: Vec<Vec<SiteInput>>,
}

/// The state Phase B threads through the forward walk: the recyclable arena, the live node ->
/// slot mapping, and the stream being built.
struct Emitter {
    arena: Arena,
    slot: Vec<Option<Loc>>,
    out: Emission,
}

impl Emitter {
    fn new(graph: &Graph, reservation: &mut Reservation, last_use: Vec<usize>) -> Self {
        let arena = Arena {
            p: BankAlloc::starting_at(reservation.p_next),
            s: BankAlloc::starting_at(reservation.s_next),
            l: BankAlloc::starting_at(0),
            p_reserved_end: reservation.p_next,
            s_reserved_end: reservation.s_next,
            last_use,
        };
        let out = Emission {
            instructions: Vec::new(),
            rounds: vec![
                RoundEntry {
                    operand_start: 0,
                    len: 0,
                    result_start: 0
                };
                graph.num_rounds()
            ],
            round_operands: Vec::new(),
            round_results: Vec::new(),
            site_inputs: vec![Vec::new(); graph.gadget_sites().len()],
        };
        Self {
            arena,
            slot: std::mem::take(&mut reservation.slot),
            out,
        }
    }

    /// Phase B: the forward walk over `graph.nodes()` allocating recyclable slots and emitting
    /// instructions, servicing each gadget batch at its anchor node.
    fn run(
        &mut self,
        graph: &Graph,
        domain: &[Domain],
        schedule: &BatchSchedule,
        reservation: &Reservation,
    ) -> eyre::Result<()> {
        let nodes = graph.nodes();
        let mut i = 0usize;
        while i < nodes.len() {
            let node = &nodes[i];
            match &node.op {
                Op::Constant(_) | Op::Input(_) => {
                    // Loc already assigned in Phase A.
                }
                Op::Add | Op::Sub | Op::Mul => self.emit_arith(nodes, i, domain)?,
                Op::MulLocal => self.emit_mul_local(nodes, i, domain)?,
                Op::Round(round_id) => {
                    let round_id = *round_id;
                    self.emit_round(nodes, i, round_id)?;
                    i += node.inputs.len(); // skip the RoundResult nodes just handled
                }
                Op::RoundResult(_) => {
                    unreachable!(
                        "every RoundResult is consumed by its Round's own arm above - codegen \
                         never visits one on its own"
                    );
                }
                Op::Gadget(site_id) => self.collect_site_inputs(nodes, i, site_id.index())?,
                Op::GadgetResult(_) => {
                    let Op::Gadget(site_id) = &nodes[node.inputs[0].index()].op else {
                        unreachable!("a GadgetResult's input is always its Gadget node");
                    };
                    self.slot[i] = Some(Loc {
                        bank: reservation.gadgets.site_result_base[site_id.index()].bank,
                        index: reservation.gadgets.result_phys[i].expect(
                            "every GadgetResult node that survives to codegen was counted into \
                             live_slots/live_nodes in Phase A",
                        ),
                    });
                }
            }
            self.service_batches(nodes, i, schedule)?;
            i += 1;
        }
        Ok(())
    }

    fn emit_arith(&mut self, nodes: &[Node], i: usize, domain: &[Domain]) -> eyre::Result<()> {
        let node = &nodes[i];
        let da = domain[node.inputs[0].index()];
        let db = domain[node.inputs[1].index()];
        let (opcode, dst_bank, swap) = select_opcode(&node.op, da, db)?;
        let sa = self.slot[node.inputs[0].index()].expect("operand not yet resolved");
        let sb = self.slot[node.inputs[1].index()].expect("operand not yet resolved");
        let (a, b) = if swap {
            (sb.index, sa.index)
        } else {
            (sa.index, sb.index)
        };
        let dst = self.arena.alloc(dst_bank);
        self.out.instructions.push(Instruction::Arith {
            op: opcode,
            dst: Slot::new(dst),
            a: Slot::new(a),
            b: Slot::new(b),
        });
        self.slot[i] = Some(Loc {
            bank: dst_bank,
            index: dst,
        });
        self.arena.free_if_dead(node.inputs[0], i, &mut self.slot);
        self.arena.free_if_dead(node.inputs[1], i, &mut self.slot);
        Ok(())
    }

    fn emit_mul_local(&mut self, nodes: &[Node], i: usize, domain: &[Domain]) -> eyre::Result<()> {
        let node = &nodes[i];
        let sa = self.slot[node.inputs[0].index()].expect("operand not yet resolved");
        let sb = self.slot[node.inputs[1].index()].expect("operand not yet resolved");
        if domain[node.inputs[0].index()] != Domain::Shared
            || domain[node.inputs[1].index()] != Domain::Shared
        {
            eyre::bail!(
                "codegen: MulLocal's operands must both be Shared (rep3's local_mul_vec needs two \
                 genuine shares) - got {:?}/{:?}",
                domain[node.inputs[0].index()],
                domain[node.inputs[1].index()]
            );
        }
        let dst = self.arena.alloc(Bank::Local);
        self.out.instructions.push(Instruction::Arith {
            op: Opcode::MulLocal,
            dst: Slot::new(dst),
            a: Slot::new(sa.index),
            b: Slot::new(sb.index),
        });
        self.slot[i] = Some(Loc {
            bank: Bank::Local,
            index: dst,
        });
        self.arena.free_if_dead(node.inputs[0], i, &mut self.slot);
        self.arena.free_if_dead(node.inputs[1], i, &mut self.slot);
        Ok(())
    }

    fn emit_round(&mut self, nodes: &[Node], i: usize, round_id: RoundId) -> eyre::Result<()> {
        let node = &nodes[i];
        let operand_start =
            u32::try_from(self.out.round_operands.len()).expect("too many round operands");
        for &input in &node.inputs {
            let s = self.slot[input.index()].expect("round operand not yet resolved");
            if s.bank != Bank::Local {
                eyre::bail!(
                    "codegen: a Round's operand must be a Local (MulLocal) value, got {:?}",
                    s.bank
                );
            }
            self.out.round_operands.push(Slot::new(s.index));
            self.arena.l.free(s.index, 0);
        }
        let len = u32::try_from(node.inputs.len()).expect("round has more slots than fit into u32");

        // round_schedule guarantees a Round node is immediately followed by exactly `len`
        // RoundResult(0..len) nodes, in slot order - see its own module doc. Codegen relies
        // on the same guarantee its own producer already asserts, rather than re-deriving
        // the mapping some other way.
        let result_start =
            u32::try_from(self.out.round_results.len()).expect("too many round results");
        for k in 0..node.inputs.len() {
            let result_idx = i + 1 + k;
            let expected_k = u32::try_from(k).expect("round has more slots than fit into u32");
            match nodes.get(result_idx).map(|n| &n.op) {
                Some(Op::RoundResult(slot_k)) if *slot_k == expected_k => {}
                other => eyre::bail!(
                    "codegen: Round {} expected RoundResult({expected_k}) at node {result_idx}, \
                     found {other:?} - round_schedule's adjacency invariant was violated",
                    round_id.index()
                ),
            }
            let dst = self.arena.alloc(Bank::Shared);
            self.out.round_results.push(Slot::new(dst));
            self.slot[result_idx] = Some(Loc {
                bank: Bank::Shared,
                index: dst,
            });
        }
        self.out.rounds[round_id.index()] = RoundEntry {
            operand_start,
            len,
            result_start,
        };
        self.out
            .instructions
            .push(Instruction::Reshare(RoundIdx::try_from(round_id.index())?));
        // Free every RoundResult(k) input that died the instant it was produced (rare - an unread
        // result would already have been dropped by an earlier gc in practice, but the allocator
        // handles it correctly regardless).
        for k in 0..node.inputs.len() {
            let result_idx = i + 1 + k;
            self.arena
                .free_if_dead(ValueId::new(result_idx), result_idx, &mut self.slot);
        }
        Ok(())
    }

    /// A site's inputs are ordinary operands, resolved like any other. They are *not* required to
    /// be bare `Op::Input`/`Op::Constant`: batches are serviced at their own point in the
    /// instruction stream (see `Opcode::Gadget`), so a site whose inputs are computed is fine -
    /// needed by circuits whose Poseidon2 sites chain through secret multiplications. The Gadget
    /// node's own value is never read directly (only via `GadgetResult`), so it needs no slot.
    fn collect_site_inputs(
        &mut self,
        nodes: &[Node],
        i: usize,
        site_id: usize,
    ) -> eyre::Result<()> {
        let node = &nodes[i];
        let mut inputs = Vec::with_capacity(node.inputs.len());
        for &input in &node.inputs {
            let s = self.slot[input.index()].expect("gadget input not yet resolved");
            if s.bank == Bank::Local {
                eyre::bail!(
                    "codegen: gadget site {site_id} reads a Local (un-reshared MulLocal) value - \
                     it must be reshared first; this is a lowering invariant violation"
                );
            }
            inputs.push(SiteInput {
                bank: s.bank,
                slot: Slot::new(s.index),
            });
        }
        self.out.site_inputs[site_id] = inputs;
        Ok(())
    }

    /// Every batch anchored at `i` is serviced now: all of its sites' inputs are resolved, and
    /// `plan_gadget_batches` has checked that nothing reads its results before this point.
    fn service_batches(
        &mut self,
        nodes: &[Node],
        i: usize,
        schedule: &BatchSchedule,
    ) -> eyre::Result<()> {
        for &batch_idx in &schedule.batches_at[i] {
            self.out
                .instructions
                .push(Instruction::Gadget(BatchIdx::try_from(batch_idx)?));
            // Site inputs were pinned to this anchor by the liveness extension in `plan_batches`,
            // so this is where they become recyclable. A fused service retains the original IsZero
            // operand, not the intermediate result passed to Reveal.
            match &schedule.plans[batch_idx] {
                ScheduledBatch::Gadget(plan) => {
                    for &(_, site_node) in &plan.sites {
                        for &input in &nodes[site_node].inputs {
                            self.arena.free_if_dead(input, i, &mut self.slot);
                        }
                    }
                }
                ScheduledBatch::IsZeroReveal(fusion) => {
                    for site in &fusion.sites {
                        self.arena.free_if_dead(site.input, i, &mut self.slot);
                    }
                }
            }
        }
        Ok(())
    }
}

/// Assembles the planned batches into their runtime tables; slot lists follow each plan's own site
/// order.
fn assemble_batches(
    schedule: &BatchSchedule,
    reservation: &Reservation,
    emission: &Emission,
) -> Vec<GadgetBatch> {
    schedule
        .plans
        .iter()
        .map(|plan| match plan {
            ScheduledBatch::IsZeroReveal(fusion) => {
                assemble_fused_batch(fusion, reservation, emission)
            }
            ScheduledBatch::Gadget(plan) => assemble_normal_batch(plan, reservation, emission),
        })
        .collect()
}

fn assemble_fused_batch(
    fusion: &IsZeroRevealPlan,
    reservation: &Reservation,
    emission: &Emission,
) -> GadgetBatch {
    let mut result_requests = Vec::new();
    let mut result_offsets = Vec::with_capacity(fusion.sites.len() + 1);
    let mut result_targets = Vec::new();
    result_offsets.push(0);
    for site in &fusion.sites {
        let source_site = site.zero_test_site;
        debug_assert_eq!(
            reservation.gadgets.site_result_base[source_site].bank,
            Bank::Shared,
            "an IsZero fused into IsZeroReveal must have Shared results"
        );
        for (pos, &logical) in reservation.gadgets.live_slots[source_site]
            .iter()
            .enumerate()
        {
            debug_assert!(logical <= 1, "IsZero has exactly two result slots");
            result_requests.push(ResultSlot::new(logical));
            result_targets.push(ResultTarget {
                bank: Bank::Shared,
                slot: Slot::new(
                    reservation.gadgets.result_phys
                        [reservation.gadgets.live_nodes[source_site][pos]]
                        .expect("every live source result has a physical slot"),
                ),
            });
        }

        debug_assert_eq!(
            reservation.gadgets.site_result_base[site.reveal_site].bank,
            Bank::Public,
            "the Reveal half of an IsZeroReveal fusion must have Public results"
        );
        for (pos, &logical) in reservation.gadgets.live_slots[site.reveal_site]
            .iter()
            .enumerate()
        {
            debug_assert_eq!(
                logical, 0,
                "a fused Reveal(1) site has exactly one logical result slot"
            );
            result_requests.push(ResultSlot::new(2 + logical));
            result_targets.push(ResultTarget {
                bank: Bank::Public,
                slot: Slot::new(
                    reservation.gadgets.result_phys
                        [reservation.gadgets.live_nodes[site.reveal_site][pos]]
                        .expect("every live Reveal result has a physical slot"),
                ),
            });
        }
        result_offsets.push(u32::try_from(result_requests.len()).expect("too many fused results"));
    }
    GadgetBatch {
        kind: BatchKind::IsZeroReveal,
        sites: fusion.sites.len(),
        input_slots: fusion
            .sites
            .iter()
            .map(|site| emission.site_inputs[site.zero_test_site][0])
            .collect(),
        result_requests,
        result_offsets,
        result_targets,
    }
}

fn assemble_normal_batch(
    plan: &BatchPlan,
    reservation: &Reservation,
    emission: &Emission,
) -> GadgetBatch {
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
        input_slots.extend_from_slice(&emission.site_inputs[site_id]);
        let base = reservation.gadgets.site_result_base[site_id];
        debug_assert_eq!(
            base.bank,
            gadget_result_bank(plan.kind, plan.domain, plan.precomputed)
                .expect("already validated while reserving site_result_base"),
            "a site's result bank must not change between reservation and assembly"
        );
        for (pos, &logical) in reservation.gadgets.live_slots[site_id].iter().enumerate() {
            result_requests.push(ResultSlot::new(logical));
            result_targets.push(ResultTarget {
                bank: base.bank,
                slot: Slot::new(
                    reservation.gadgets.result_phys[reservation.gadgets.live_nodes[site_id][pos]]
                        .expect("every live gadget result has a physical slot"),
                ),
            });
        }
        result_offsets.push(u32::try_from(result_requests.len()).expect("too many gadget results"));
    }
    GadgetBatch {
        kind: if plan.precomputed {
            let GadgetKind::Poseidon2 { t } = plan.kind else {
                unreachable!(
                    "a precomputed plan is always Poseidon2 - the frontend never marks any other \
                     kind precomputed (build.rs), got {:?}",
                    plan.kind
                );
            };
            BatchKind::PrecomputedPoseidon2 { t }
        } else {
            BatchKind::Gadget(plan.kind)
        },
        sites: plan.sites.len(),
        input_slots,
        result_requests,
        result_offsets,
        result_targets,
    }
}

/// Builds a compile-time signal -> source table, then immediately projects it into witness order.
/// This retains today's last-binding-wins behavior for the (normally unique) signal bindings,
/// without carrying the oversized signal address space into runtime.
///
/// Pass/codegen unit tests intentionally use hand-built graphs without a witness projection.
/// That diagnostic-only contract is preserved (empty result) without requiring their synthetic
/// signal metadata to describe inputs that no runtime will ever project.
fn build_witness_sources(graph: &Graph, slot: &[Option<Loc>]) -> eyre::Result<Vec<WitnessSource>> {
    if graph.signal_to_witness.is_empty() {
        return Ok(Vec::new());
    }
    let mut signal_sources = vec![None; graph.num_signals()];
    *signal_sources.get_mut(0).ok_or_else(|| {
        eyre::eyre!("codegen: witness-bearing graph has no constant-one signal")
    })? = Some(WitnessSource::One);
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
            eyre::eyre!(
                "codegen: output signal {signal_index} exceeds num_signals={}",
                graph.num_signals()
            )
        })?;
        *destination = Some(WitnessSource::Slot {
            bank: s.bank,
            slot: Slot::new(s.index),
        });
    }
    for input_index in 0..graph.num_inputs() {
        let signal = graph.num_outputs() + input_index + 1;
        let destination = signal_sources.get_mut(signal).ok_or_else(|| {
            eyre::eyre!(
                "codegen: input signal {signal} exceeds num_signals={}",
                graph.num_signals()
            )
        })?;
        *destination = Some(WitnessSource::Input(InputIdx::try_from(input_index)?));
    }
    Ok(graph
        .signal_to_witness
        .iter()
        .map(|&signal| {
            signal_sources
                .get(signal)
                .and_then(|source| *source)
                .unwrap_or(WitnessSource::Zero)
        })
        .collect())
}

/// Compiles a fully lowered graph (`PassManager::run` has already run - see
/// `circom_mpc_compiler::compile`) into a `Program`.
///
/// # Panics
///
/// Panics if an internal invariant that an earlier pass is responsible for maintaining (e.g. slot
/// or index bounds fitting into `u32`) is violated.
///
/// # Errors
///
/// Returns an error if `graph` isn't a validly lowered graph - e.g. a `Local`-domain value reaches
/// an arithmetic op directly, or a secret x secret `Mul` survived MPC lowering.
pub(crate) fn compile(graph: &Graph) -> eyre::Result<Program> {
    let domain = compute_domains(graph);
    let mut last_use = compute_last_use(graph);
    let schedule = plan_batches(graph, &domain, &mut last_use);
    let mut reservation = reserve_slots(graph, &domain)?;
    let mut emitter = Emitter::new(graph, &mut reservation, last_use);
    emitter.run(graph, &domain, &schedule, &reservation)?;
    let batches = assemble_batches(&schedule, &reservation, &emitter.out);
    let witness_sources = build_witness_sources(graph, &emitter.slot)?;

    Ok(Program::new(ProgramParts {
        instructions: emitter.out.instructions,
        constants: reservation.constants,
        input_domains: reservation.input_domains,
        inputs: reservation.input_bindings,
        input_signals: reservation.input_signals,
        rounds: emitter.out.rounds,
        round_operands: emitter.out.round_operands,
        round_results: emitter.out.round_results,
        gadget_batches: batches,
        witness_sources,
        num_inputs: graph.num_inputs(),
        slots: SlotCounts {
            public: emitter.arena.p.next,
            shared: emitter.arena.s.next,
            local: emitter.arena.l.next,
        },
    }))
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;

    use super::*;
    use crate::ir::{GadgetId, GadgetKind, GadgetSite, GraphParts, Node, SignalIdx};

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
        let graph = Graph::from_parts(GraphParts {
            nodes,
            outputs: vec![(SignalIdx::new(0), ValueId::new(8))],
            num_outputs: 1,
            num_signals: 2,
            ..Default::default()
        });
        let program =
            compile(&graph).expect("compile should succeed for this well-formed test graph");
        assert!(
            (program.slots().public as usize) < graph.len(),
            "peak public-bank width ({}) should be well below the node count ({})",
            program.slots().public,
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
        let graph = Graph::from_parts(GraphParts {
            nodes,
            outputs: vec![(SignalIdx::new(0), ValueId::new(3))],
            num_inputs: 2,
            num_outputs: 1,
            num_signals: 4,
            ..Default::default()
        });
        let err = compile(&graph)
            .expect_err("compile should reject a Local value reaching anything but Reshare");
        assert!(err.to_string().contains("Local"), "{err}");
    }

    // --- Staged batching ---

    fn iszero_site() -> GadgetSite {
        GadgetSite {
            kind: GadgetKind::IsZero,
            precomputed: false,
        }
    }

    fn reveal_site(n: usize) -> GadgetSite {
        GadgetSite {
            kind: GadgetKind::Reveal { n },
            precomputed: false,
        }
    }

    fn graph_with_sites(
        nodes: Vec<Node>,
        outputs: Vec<(SignalIdx, ValueId)>,
        sites: Vec<GadgetSite>,
        num_inputs: usize,
    ) -> Graph {
        Graph::from_parts(GraphParts {
            nodes,
            outputs,
            gadget_sites: sites,
            num_inputs,
            num_outputs: 1,
            num_signals: num_inputs + 4,
            ..Default::default()
        })
    }

    /// The batching contract: N independent same-kind sites are **one** driver call, not N.
    #[test]
    fn same_kind_sites_at_one_stage_share_one_batch() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0
            Node::new(Op::Input(SignalIdx::new(2)), vec![]), // 1
            Node::new(Op::Gadget(GadgetId::new(0)), vec![ValueId::new(0)]), // 2
            Node::new(Op::GadgetResult(0), vec![ValueId::new(2)]), // 3
            Node::new(Op::Gadget(GadgetId::new(1)), vec![ValueId::new(1)]), // 4
            Node::new(Op::GadgetResult(0), vec![ValueId::new(4)]), // 5
            Node::new(Op::Add, vec![ValueId::new(3), ValueId::new(5)]), // 6
        ];
        let graph = graph_with_sites(
            nodes,
            vec![(SignalIdx::new(0), ValueId::new(6))],
            vec![iszero_site(), iszero_site()],
            2,
        );
        let program =
            compile(&graph).expect("compile should succeed for this well-formed test graph");
        assert_eq!(program.gadget_batches().len(), 1);
        assert_eq!(program.gadget_batches()[0].sites, 2);
        assert_eq!(
            program
                .instructions()
                .iter()
                .filter(|instr| matches!(instr, Instruction::Gadget(_)))
                .count(),
            1
        );
    }

    #[test]
    fn sole_shared_iszero_output_revealed_once_is_fused_at_codegen() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0: x
            Node::new(Op::Gadget(GadgetId::new(0)), vec![ValueId::new(0)]), // 1: IsZero
            Node::new(Op::GadgetResult(0), vec![ValueId::new(1)]), // 2: out
            Node::new(Op::GadgetResult(1), vec![ValueId::new(1)]), // 3: inv
            Node::new(Op::Gadget(GadgetId::new(1)), vec![ValueId::new(2)]), // 4: Reveal
            Node::new(Op::GadgetResult(0), vec![ValueId::new(4)]), // 5: revealed
        ];
        let graph = graph_with_sites(
            nodes,
            vec![
                (SignalIdx::new(0), ValueId::new(5)),
                (SignalIdx::new(2), ValueId::new(2)),
                (SignalIdx::new(3), ValueId::new(3)),
            ],
            vec![iszero_site(), reveal_site(1)],
            1,
        );
        let program =
            compile(&graph).expect("compile should succeed for this well-formed test graph");

        assert_eq!(program.gadget_batches().len(), 1);
        let batch = &program.gadget_batches()[0];
        assert_eq!(batch.kind, BatchKind::IsZeroReveal);
        assert_eq!(batch.sites, 1);
        assert_eq!(
            batch
                .result_requests
                .iter()
                .map(|r| r.get())
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
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
            Node::new(Op::Gadget(GadgetId::new(0)), vec![ValueId::new(0)]), // 2: IsZero(x)
            Node::new(Op::GadgetResult(0), vec![ValueId::new(2)]), // 3: x.out
            Node::new(Op::GadgetResult(1), vec![ValueId::new(2)]), // 4: x.inv
            Node::new(Op::Gadget(GadgetId::new(1)), vec![ValueId::new(1)]), // 5: IsZero(y)
            Node::new(Op::GadgetResult(0), vec![ValueId::new(5)]), // 6: y.out
            Node::new(Op::GadgetResult(1), vec![ValueId::new(5)]), // 7: y.inv
            Node::new(Op::Gadget(GadgetId::new(2)), vec![ValueId::new(3)]), // 8: Reveal(x.out)
            Node::new(Op::GadgetResult(0), vec![ValueId::new(8)]), // 9
            Node::new(Op::Gadget(GadgetId::new(3)), vec![ValueId::new(6)]), // 10: Reveal(y.out)
            Node::new(Op::GadgetResult(0), vec![ValueId::new(10)]), // 11
        ];
        let graph = graph_with_sites(
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
        let program =
            compile(&graph).expect("compile should succeed for this well-formed test graph");

        assert_eq!(program.gadget_batches().len(), 1);
        let batch = &program.gadget_batches()[0];
        assert_eq!(batch.kind, BatchKind::IsZeroReveal);
        assert_eq!(batch.sites, 2);
        assert_eq!(batch.result_offsets, vec![0, 3, 6]);
        assert_eq!(
            batch
                .result_requests
                .iter()
                .map(|r| r.get())
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 0, 1, 2]
        );
    }

    #[test]
    fn fused_sites_follow_reveal_batch_order() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0: x
            Node::new(Op::Input(SignalIdx::new(2)), vec![]), // 1: y
            Node::new(Op::Gadget(GadgetId::new(0)), vec![ValueId::new(0)]), // 2: IsZero(x)
            Node::new(Op::GadgetResult(0), vec![ValueId::new(2)]), // 3: x.out
            Node::new(Op::GadgetResult(1), vec![ValueId::new(2)]), // 4: x.inv
            Node::new(Op::Gadget(GadgetId::new(1)), vec![ValueId::new(1)]), // 5: IsZero(y)
            Node::new(Op::GadgetResult(0), vec![ValueId::new(5)]), // 6: y.out
            Node::new(Op::GadgetResult(1), vec![ValueId::new(5)]), // 7: y.inv
            Node::new(Op::Gadget(GadgetId::new(2)), vec![ValueId::new(6)]), // 8: Reveal(y.out)
            Node::new(Op::GadgetResult(0), vec![ValueId::new(8)]), // 9
            Node::new(Op::Gadget(GadgetId::new(3)), vec![ValueId::new(3)]), // 10: Reveal(x.out)
            Node::new(Op::GadgetResult(0), vec![ValueId::new(10)]), // 11
        ];
        let graph = graph_with_sites(
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
        let program =
            compile(&graph).expect("compile should preserve the Reveal batch's site order");

        let batch = &program.gadget_batches()[0];
        assert_eq!(batch.kind, BatchKind::IsZeroReveal);
        assert_eq!(
            batch
                .input_slots
                .iter()
                .map(|input| input.slot)
                .collect::<Vec<_>>(),
            vec![program.inputs()[1].slot, program.inputs()[0].slot]
        );
    }

    #[test]
    fn partially_revealed_iszero_batch_remains_unfused() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0: x
            Node::new(Op::Input(SignalIdx::new(2)), vec![]), // 1: y
            Node::new(Op::Gadget(GadgetId::new(0)), vec![ValueId::new(0)]), // 2: IsZero(x)
            Node::new(Op::GadgetResult(0), vec![ValueId::new(2)]), // 3: x.out
            Node::new(Op::GadgetResult(1), vec![ValueId::new(2)]), // 4: x.inv
            Node::new(Op::Gadget(GadgetId::new(1)), vec![ValueId::new(1)]), // 5: IsZero(y)
            Node::new(Op::GadgetResult(0), vec![ValueId::new(5)]), // 6: y.out
            Node::new(Op::GadgetResult(1), vec![ValueId::new(5)]), // 7: y.inv
            Node::new(Op::Gadget(GadgetId::new(2)), vec![ValueId::new(3)]), // 8: Reveal(x.out)
            Node::new(Op::GadgetResult(0), vec![ValueId::new(8)]), // 9
        ];
        let graph = graph_with_sites(
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
        let program =
            compile(&graph).expect("compile should succeed for this well-formed test graph");

        assert_eq!(program.gadget_batches().len(), 2);
        assert_eq!(
            program.gadget_batches()[0].kind,
            BatchKind::Gadget(GadgetKind::IsZero)
        );
        assert_eq!(program.gadget_batches()[0].sites, 2);
        assert!(
            program
                .gadget_batches()
                .iter()
                .all(|batch| batch.kind != BatchKind::IsZeroReveal)
        );
    }

    #[test]
    fn reveal_consuming_iszero_inverse_is_not_fused() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0: x
            Node::new(Op::Gadget(GadgetId::new(0)), vec![ValueId::new(0)]), // 1: IsZero
            Node::new(Op::GadgetResult(0), vec![ValueId::new(1)]), // 2: out
            Node::new(Op::GadgetResult(1), vec![ValueId::new(1)]), // 3: inv
            Node::new(Op::Gadget(GadgetId::new(1)), vec![ValueId::new(3)]), // 4: Reveal(inv)
            Node::new(Op::GadgetResult(0), vec![ValueId::new(4)]), // 5: revealed inv
        ];
        let graph = graph_with_sites(
            nodes,
            vec![
                (SignalIdx::new(0), ValueId::new(5)),
                (SignalIdx::new(2), ValueId::new(2)),
                (SignalIdx::new(3), ValueId::new(3)),
            ],
            vec![iszero_site(), reveal_site(1)],
            1,
        );
        let program =
            compile(&graph).expect("compile should succeed for this well-formed test graph");

        assert_eq!(program.gadget_batches().len(), 2);
        assert!(
            program
                .gadget_batches()
                .iter()
                .all(|batch| batch.kind != BatchKind::IsZeroReveal)
        );
    }

    #[test]
    fn iszero_with_an_extra_computational_consumer_is_not_fused() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0: x
            Node::new(Op::Gadget(GadgetId::new(0)), vec![ValueId::new(0)]), // 1
            Node::new(Op::GadgetResult(0), vec![ValueId::new(1)]), // 2: out
            Node::new(Op::GadgetResult(1), vec![ValueId::new(1)]), // 3: inv
            Node::new(Op::Add, vec![ValueId::new(2), ValueId::new(0)]), // 4: extra reader
            Node::new(Op::Gadget(GadgetId::new(1)), vec![ValueId::new(2)]), // 5
            Node::new(Op::GadgetResult(0), vec![ValueId::new(5)]), // 6
        ];
        let graph = graph_with_sites(
            nodes,
            vec![
                (SignalIdx::new(0), ValueId::new(6)),
                (SignalIdx::new(2), ValueId::new(3)),
                (SignalIdx::new(3), ValueId::new(4)),
            ],
            vec![iszero_site(), reveal_site(1)],
            1,
        );
        let program =
            compile(&graph).expect("compile should succeed for this well-formed test graph");

        assert_eq!(program.gadget_batches().len(), 2);
        assert!(
            program
                .gadget_batches()
                .iter()
                .all(|batch| batch.kind != BatchKind::IsZeroReveal)
        );
    }

    #[test]
    fn iszero_inverse_with_a_computational_consumer_is_not_fused() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0: x
            Node::new(Op::Gadget(GadgetId::new(0)), vec![ValueId::new(0)]), // 1
            Node::new(Op::GadgetResult(0), vec![ValueId::new(1)]), // 2: out
            Node::new(Op::GadgetResult(1), vec![ValueId::new(1)]), // 3: inv
            Node::new(Op::Add, vec![ValueId::new(3), ValueId::new(0)]), // 4: inv reader
            Node::new(Op::Gadget(GadgetId::new(1)), vec![ValueId::new(2)]), // 5
            Node::new(Op::GadgetResult(0), vec![ValueId::new(5)]), // 6
        ];
        let graph = graph_with_sites(
            nodes,
            vec![
                (SignalIdx::new(0), ValueId::new(6)),
                (SignalIdx::new(2), ValueId::new(4)),
            ],
            vec![iszero_site(), reveal_site(1)],
            1,
        );
        let program =
            compile(&graph).expect("compile should succeed for this well-formed test graph");

        assert_eq!(program.gadget_batches().len(), 2);
        assert!(
            program
                .gadget_batches()
                .iter()
                .all(|batch| batch.kind != BatchKind::IsZeroReveal)
        );
    }

    #[test]
    fn public_iszero_reveal_path_is_not_fused() {
        let nodes = vec![
            Node::new(Op::Constant(Fr::from(0u64)), vec![]), // 0: public x
            Node::new(Op::Gadget(GadgetId::new(0)), vec![ValueId::new(0)]), // 1
            Node::new(Op::GadgetResult(0), vec![ValueId::new(1)]), // 2
            Node::new(Op::GadgetResult(1), vec![ValueId::new(1)]), // 3
            Node::new(Op::Gadget(GadgetId::new(1)), vec![ValueId::new(2)]), // 4
            Node::new(Op::GadgetResult(0), vec![ValueId::new(4)]), // 5
        ];
        let graph = graph_with_sites(
            nodes,
            vec![
                (SignalIdx::new(0), ValueId::new(5)),
                (SignalIdx::new(2), ValueId::new(3)),
            ],
            vec![iszero_site(), reveal_site(1)],
            0,
        );
        let program =
            compile(&graph).expect("compile should succeed for this well-formed test graph");

        assert_eq!(program.gadget_batches().len(), 2);
        assert!(
            program
                .gadget_batches()
                .iter()
                .all(|batch| batch.kind != BatchKind::IsZeroReveal)
        );
    }

    /// Codegen remains safe for a valid topological graph that was not level-sorted: an early
    /// result consumer closes the active batch instead of making a later independent site move the
    /// batch anchor past that consumer.
    #[test]
    fn early_consumer_defensively_splits_an_unsorted_batch() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0: x
            Node::new(Op::Input(SignalIdx::new(2)), vec![]), // 1: y
            Node::new(Op::Gadget(GadgetId::new(0)), vec![ValueId::new(0)]), // 2: A
            Node::new(Op::GadgetResult(0), vec![ValueId::new(2)]), // 3
            Node::new(Op::Add, vec![ValueId::new(3), ValueId::new(0)]), // 4: reads A
            Node::new(Op::Gadget(GadgetId::new(1)), vec![ValueId::new(1)]), // 5: B
            Node::new(Op::GadgetResult(0), vec![ValueId::new(5)]), // 6
            Node::new(Op::Add, vec![ValueId::new(4), ValueId::new(6)]), // 7
        ];
        let graph = graph_with_sites(
            nodes,
            vec![(SignalIdx::new(0), ValueId::new(7))],
            vec![iszero_site(), iszero_site()],
            2,
        );
        let program =
            compile(&graph).expect("compile should succeed for this well-formed test graph");
        assert_eq!(program.gadget_batches().len(), 2);
        assert!(
            program
                .gadget_batches()
                .iter()
                .all(|batch| batch.sites == 1)
        );
    }

    /// Dependent sites can't share a driver call, and each batch's instruction must precede anything
    /// that reads its results. The positional assertion is what actually tests interleaving - an
    /// up-front phase would place both batches before instruction 0 and still pass a count check.
    #[test]
    fn chained_same_kind_sites_become_two_batches_in_stage_order() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0
            Node::new(Op::Gadget(GadgetId::new(0)), vec![ValueId::new(0)]), // 1
            Node::new(Op::GadgetResult(0), vec![ValueId::new(1)]), // 2
            // Reading site 0's result forces site 1 into a later stage.
            Node::new(Op::Add, vec![ValueId::new(2), ValueId::new(0)]), // 3
            Node::new(Op::Gadget(GadgetId::new(1)), vec![ValueId::new(3)]), // 4
            Node::new(Op::GadgetResult(0), vec![ValueId::new(4)]),      // 5
            Node::new(Op::Add, vec![ValueId::new(5), ValueId::new(0)]), // 6
        ];
        let graph = graph_with_sites(
            nodes,
            vec![(SignalIdx::new(0), ValueId::new(6))],
            vec![iszero_site(), iszero_site()],
            1,
        );
        let program =
            compile(&graph).expect("compile should succeed for this well-formed test graph");
        assert_eq!(program.gadget_batches().len(), 2);
        assert!(program.gadget_batches().iter().all(|b| b.sites == 1));

        let batch_pos: Vec<usize> = (0..2)
            .map(|batch_idx| {
                program
                    .instructions()
                    .iter()
                    .position(|instr| matches!(instr, Instruction::Gadget(idx) if idx.index() == batch_idx))
                    .expect("every batch has an instruction")
            })
            .collect();
        assert!(
            batch_pos[0] < batch_pos[1],
            "batches must be serviced in stage order: {batch_pos:?}"
        );

        // Batch 0's result slot must be written before any instruction reads it.
        let result_slot = program.gadget_batches()[0].result_targets[0].slot;
        let first_reader = program
            .instructions()
            .iter()
            .position(|instr| {
                matches!(
                    instr,
                    Instruction::Arith {
                        op: Opcode::AddSS | Opcode::AddSP,
                        a,
                        b,
                        ..
                    } if *a == result_slot || *b == result_slot
                )
            })
            .expect("something reads batch 0's result");
        assert!(
            batch_pos[0] < first_reader,
            "batch 0 is serviced at {} but read at {first_reader}",
            batch_pos[0]
        );
    }

    /// A site input's slot must still hold its value when the *batch* runs, which is later than the
    /// `Op::Gadget` node that reads it. Without the liveness extension the allocator could
    /// recycle it in between and a later instruction would clobber the gadget's input.
    ///
    /// Note this graph deliberately does **not** bind the site input to `graph.outputs()`, which is
    /// what masks the hazard on frontend-produced graphs (`inline_precomputed` binds every one).
    #[test]
    fn site_input_slot_survives_until_its_batch_runs() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0
            Node::new(Op::Input(SignalIdx::new(2)), vec![]), // 1
            // A computed value whose only graph reader is site 0's Gadget node.
            Node::new(Op::Add, vec![ValueId::new(0), ValueId::new(1)]), // 2
            Node::new(Op::Gadget(GadgetId::new(0)), vec![ValueId::new(2)]), // 3
            Node::new(Op::GadgetResult(0), vec![ValueId::new(3)]),      // 4
            // Site 1 is defined later, so the shared batch is anchored past node 3 - the window in
            // which node 2's slot must not be recycled.
            Node::new(Op::Add, vec![ValueId::new(0), ValueId::new(0)]), // 5
            Node::new(Op::Gadget(GadgetId::new(1)), vec![ValueId::new(5)]), // 6
            Node::new(Op::GadgetResult(0), vec![ValueId::new(6)]),      // 7
            Node::new(Op::Add, vec![ValueId::new(4), ValueId::new(7)]), // 8
        ];
        let graph = graph_with_sites(
            nodes,
            vec![(SignalIdx::new(0), ValueId::new(8))],
            vec![iszero_site(), iszero_site()],
            2,
        );
        let program =
            compile(&graph).expect("compile should succeed for this well-formed test graph");
        assert_eq!(program.gadget_batches().len(), 1, "both sites are stage 0");
        let batch = &program.gadget_batches()[0];
        let batch_pos = program
            .instructions()
            .iter()
            .position(|instr| matches!(instr, Instruction::Gadget(_)))
            .expect("the batch has an instruction");

        // No instruction before the batch may write to any of its input slots (other than the
        // instruction that legitimately produced that input in the first place).
        for input in &batch.input_slots {
            assert_eq!(input.bank, Bank::Shared);
            let clobbers = program.instructions()[..batch_pos]
                .iter()
                .filter(
                    |instr| matches!(instr, Instruction::Arith { dst, .. } if *dst == input.slot),
                )
                .count();
            assert!(
                clobbers <= 1,
                "slot {} is written {clobbers} times before its batch runs at {batch_pos}",
                input.slot
            );
        }
    }

    /// A literal passed to a gadget resolves to a `Public`-bank slot. This is the shape a circuit
    /// like `Poseidon2(4)([value, 0, r, domainSeparator()])` uses; rejecting it, as codegen once
    /// did, blocks that circuit outright.
    #[test]
    fn public_constant_site_input_is_recorded_as_a_public_bank_slot() {
        let nodes = vec![
            Node::new(Op::Constant(Fr::from(7u64)), vec![]), // 0
            Node::new(Op::Gadget(GadgetId::new(0)), vec![ValueId::new(0)]), // 1
            Node::new(Op::GadgetResult(0), vec![ValueId::new(1)]), // 2
        ];
        let graph = graph_with_sites(
            nodes,
            vec![(SignalIdx::new(0), ValueId::new(2))],
            vec![iszero_site()],
            0,
        );
        let program =
            compile(&graph).expect("compile should succeed for this well-formed test graph");
        let batch = &program.gadget_batches()[0];
        assert_eq!(batch.input_slots.len(), 1);
        assert_eq!(batch.input_slots[0].bank, Bank::Public);
    }

    /// Sparse result slots (some logical slots' `GadgetResult` node pruned by
    /// `passes::dead_code` before codegen ever runs) must compact to exactly the surviving
    /// count, not the site's full reserved capacity - and each survivor must land at its position
    /// *within the survivors*, not at its original logical index.
    #[test]
    fn sparse_result_slots_are_compacted_in_order() {
        // A capacity-3 site (1 output + 2 intermediates) where only logical slots 0 and 2 survive -
        // slot 1's `GadgetResult` node simply never exists, exactly as `dead_code` + `gc`
        // would leave it.
        let site = GadgetSite {
            kind: GadgetKind::IsZero,
            precomputed: false,
        };
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0
            Node::new(Op::Gadget(GadgetId::new(0)), vec![ValueId::new(0)]), // 1
            Node::new(Op::GadgetResult(0), vec![ValueId::new(1)]), // 2: survives
            Node::new(Op::GadgetResult(2), vec![ValueId::new(1)]), // 3: survives
            Node::new(Op::Add, vec![ValueId::new(2), ValueId::new(3)]), // 4
        ];
        let graph = graph_with_sites(
            nodes,
            vec![(SignalIdx::new(0), ValueId::new(4))],
            vec![site],
            1,
        );
        let program =
            compile(&graph).expect("compile should succeed for this well-formed test graph");

        assert_eq!(program.gadget_batches().len(), 1);
        let batch = &program.gadget_batches()[0];
        assert_eq!(
            batch
                .result_requests
                .iter()
                .map(|r| r.get())
                .collect::<Vec<_>>(),
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
            batch.result_targets[1].slot.get(),
            batch.result_targets[0].slot.get() + 1
        );
    }

    /// A `Local` value feeding a site is a lowering-invariant violation, not a circuit shape.
    #[test]
    fn local_value_feeding_a_site_is_rejected() {
        let nodes = vec![
            Node::new(Op::Input(SignalIdx::new(1)), vec![]), // 0
            Node::new(Op::Input(SignalIdx::new(2)), vec![]), // 1
            Node::new(Op::MulLocal, vec![ValueId::new(0), ValueId::new(1)]), // 2
            Node::new(Op::Gadget(GadgetId::new(0)), vec![ValueId::new(2)]), // 3
            Node::new(Op::GadgetResult(0), vec![ValueId::new(3)]), // 4
        ];
        let graph = graph_with_sites(
            nodes,
            vec![(SignalIdx::new(0), ValueId::new(4))],
            vec![iszero_site()],
            2,
        );
        let err = compile(&graph)
            .expect_err("compile should reject this ill-formed test graph")
            .to_string();
        assert!(err.contains("Local"), "unexpected error: {err}");
    }
}
