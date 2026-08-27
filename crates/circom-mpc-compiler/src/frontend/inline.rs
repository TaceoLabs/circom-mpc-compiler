//! Recursive sub-component inlining: flattens a [`TemplateGraph`] tree (main plus every
//! subcomponent it instantiates, transitively) into one flat [`ir::Graph`].
//!
//! Every cross-template reference is resolved *at inlining time*: a handful of maps carry
//! already-resolved `ValueId`s across the recursion, and nothing is ever pushed to the graph that
//! isn't a genuine, permanent node (there is no `Op::Load` placeholder to chase through
//! afterwards). `sub_cmp_inputs` tracks which value was stored into a subcomponent's input port;
//! the returned `port_outputs` tracks which value a subcomponent's output port resolves to, handed
//! back to whichever caller reads it via `SubCmpOutput`.
//!
//! A template's own signal reads (`TemplateOp::LocalSignal`) resolve against its own writes first
//! (`local_writes`), regardless of nesting level - so a subcomponent reading back its own output
//! signal resolves the same way a top-level circuit does.

use rustc_hash::FxHashMap;

use super::build::{AcceleratedInstance, SubGraphInstance, TemplateGraph, TemplateOp};
use crate::ir::{self, AcceleratorId, AcceleratorSite, Op, SignalIdx, ValueId};

/// Recursively inlines `template` (at the given `signal_offset` in the enclosing circuit's flat
/// signal space) into `nodes`/`outputs`. `is_root` identifies main independently of that numeric
/// offset (when main declares no signals, its first child legitimately starts at offset zero
/// too). `input_mapping` carries the values the *caller* stored into this template's own input
/// ports (empty for main, which has no caller).
///
/// `accelerator_sites` accumulates one entry per recognized gadget instance encountered anywhere in
/// the recursion, in encounter order - that order is the contract the runtime's supplied traces
/// must follow.
///
/// Returns this template's own output-port map, so a caller holding a `SubCmpOutput` reference
/// can resolve it once this call returns.
pub(super) fn inline_template(
    nodes: &mut Vec<ir::Node>,
    outputs: &mut Vec<(SignalIdx, ValueId)>,
    accelerator_sites: &mut Vec<AcceleratorSite>,
    template: TemplateGraph,
    signal_offset: usize,
    is_root: bool,
    input_mapping: &FxHashMap<usize, ValueId>,
) -> FxHashMap<usize, ValueId> {
    let mut port_outputs = FxHashMap::default();
    // this template's own signal writes, keyed by local (pre-offset) signal index; lets a
    // template read back a signal it just wrote without re-deriving anything.
    let mut local_writes: FxHashMap<usize, ValueId> = FxHashMap::default();
    // resolved output-port maps of local subcomponent instances, filled in lazily on first use
    let mut already_inlined: FxHashMap<usize, FxHashMap<usize, ValueId>> = FxHashMap::default();
    // values stored into local subcomponent instances' input ports, by (instance, port)
    let mut sub_cmp_inputs: Vec<FxHashMap<usize, ValueId>> =
        vec![FxHashMap::default(); template.sub_graphs.len()];
    let mut sub_graphs: Vec<Option<_>> = template.sub_graphs.into_iter().map(Some).collect();

    // local_remap[i] is the resolved outer ValueId for this template's local node i. Only
    // populated for nodes that produce a usable value (Real ops, LocalSignal reads, SubCmpOutput
    // reads) — LocalSignalWrite/SubCmpInput are sinks, never referenced by index.
    let mut local_remap: Vec<Option<ValueId>> = vec![None; template.nodes.len()];

    for (local_idx, node) in template.nodes.into_iter().enumerate() {
        match node.op {
            TemplateOp::Real(op) => {
                let inputs = node
                    .inputs
                    .iter()
                    .map(|&v| local_remap[v.index()].expect("value used before it was resolved"))
                    .collect();
                let new_id = ValueId::new(nodes.len());
                nodes.push(ir::Node::new(op, inputs));
                local_remap[local_idx] = Some(new_id);
            }
            TemplateOp::LocalSignal(signal) => {
                let resolved = if let Some(&v) = local_writes.get(&signal) {
                    v
                } else if !is_root {
                    *input_mapping.get(&signal).unwrap_or_else(|| {
                        panic!("subcomponent input signal {signal} read before it was provided")
                    })
                } else {
                    // a genuine external circuit input, read at runtime
                    let new_id = ValueId::new(nodes.len());
                    nodes.push(ir::Node::new(Op::Input(SignalIdx::new(signal)), vec![]));
                    new_id
                };
                if !is_root {
                    // this subcomponent's own input signal is still part of the circuit's flat
                    // signal space and must be addressable by signal_to_witness
                    outputs.push((SignalIdx::new(signal + signal_offset), resolved));
                }
                local_remap[local_idx] = Some(resolved);
            }
            TemplateOp::LocalSignalWrite(signal) => {
                let value =
                    local_remap[node.inputs[0].index()].expect("value used before it was resolved");
                local_writes.insert(signal, value);
                if !is_root {
                    port_outputs.insert(signal, value);
                }
                outputs.push((SignalIdx::new(signal + signal_offset), value));
            }
            TemplateOp::SubCmpInput { sub_cmp, port } => {
                let value =
                    local_remap[node.inputs[0].index()].expect("value used before it was resolved");
                sub_cmp_inputs[sub_cmp].insert(port, value);
            }
            TemplateOp::SubCmpOutput { sub_cmp, port } => {
                let map = already_inlined.entry(sub_cmp).or_insert_with(|| {
                    let instance = sub_graphs[sub_cmp]
                        .take()
                        .expect("subcomponent instance consumed twice");
                    inline_sub_graph_instance(
                        nodes,
                        outputs,
                        accelerator_sites,
                        instance,
                        signal_offset,
                        &sub_cmp_inputs[sub_cmp],
                    )
                });
                let resolved = *map.get(&port).unwrap_or_else(|| {
                    panic!("subcomponent output port {port} read before it was produced")
                });
                local_remap[local_idx] = Some(resolved);
            }
        }
    }

    // Any subcomponent instance whose outputs are never read (declares none at all, like
    // AliasCheck, or simply has no caller interested in them) is otherwise never inlined by the
    // SubCmpOutput arm above - none of its signals would reach `outputs`,
    // silently leaving them as zero in the witness. Its inputs are already fully resolved by this
    // point (every SubCmpInput targeting it was processed in the loop above), so inlining it now
    // is still topologically sound.
    for (instance, inputs) in sub_graphs.into_iter().zip(sub_cmp_inputs) {
        if let Some(instance) = instance {
            // Nothing in this template holds a SubCmpOutput reference to it (that's exactly why
            // it's still Some here) - its port_outputs map has no reader, so discard it.
            inline_sub_graph_instance(
                nodes,
                outputs,
                accelerator_sites,
                instance,
                signal_offset,
                &inputs,
            );
        }
    }

    port_outputs
}

/// Dispatches one subcomponent instance to whichever inlining strategy applies: recurse into a
/// compiled body, or (for a recognized gadget) turn it into a accelerator site instead of
/// compiling anything - see [`inline_accelerated`].
///
/// `parent_offset` is the *enclosing* template's own absolute signal offset (the `signal_offset`
/// `inline_template` was itself called with). Circom's `CreateCmpBucket::signal_offset` - the value
/// stored in `instance`'s own `signal_offset` field - is always relative to the immediate father's
/// signal frame (`compiler::intermediate_representation::create_component_bucket`: "signal offset
/// with respect to the start of the father's signals"), never globally absolute. That is harmless at
/// depth 2 (main instantiates a leaf directly: the father *is* main, whose own absolute offset is 0,
/// so father-relative and globally-absolute coincide) but wrong at depth 3+ (main instantiates a mid
/// template that itself instantiates a leaf): the leaf's offset must accumulate the mid template's
/// own placement, or the leaf's signals collide with whatever unrelated signal happens to occupy that
/// low, unadjusted offset elsewhere in the flat witness - a silently wrong witness, not a panic.
fn inline_sub_graph_instance(
    nodes: &mut Vec<ir::Node>,
    outputs: &mut Vec<(SignalIdx, ValueId)>,
    accelerator_sites: &mut Vec<AcceleratorSite>,
    instance: SubGraphInstance,
    parent_offset: usize,
    sub_cmp_inputs: &FxHashMap<usize, ValueId>,
) -> FxHashMap<usize, ValueId> {
    match instance {
        SubGraphInstance::Compiled {
            template,
            signal_offset,
        } => inline_template(
            nodes,
            outputs,
            accelerator_sites,
            template,
            parent_offset + signal_offset,
            false,
            sub_cmp_inputs,
        ),
        SubGraphInstance::Accelerated(site) => inline_accelerated(
            nodes,
            outputs,
            accelerator_sites,
            site,
            parent_offset,
            sub_cmp_inputs,
        ),
    }
}

/// Turns one recognized gadget instance into an `Op::Accelerator` node plus one
/// `Op::AcceleratorResult` per result slot, instead of recursing into a compiled body. Result
/// slots `0..num_outputs` are the gadget's own outputs (signals `signal_offset ..`), slots
/// `num_outputs..` are its subtree's intermediate signals in flat order (signals
/// `signal_offset + num_outputs + num_inputs ..`).
fn inline_accelerated(
    nodes: &mut Vec<ir::Node>,
    outputs: &mut Vec<(SignalIdx, ValueId)>,
    accelerator_sites: &mut Vec<AcceleratorSite>,
    site: AcceleratedInstance,
    parent_offset: usize,
    sub_cmp_inputs: &FxHashMap<usize, ValueId>,
) -> FxHashMap<usize, ValueId> {
    let AcceleratedInstance {
        kind,
        header,
        signal_offset,
        num_inputs,
        num_outputs,
        num_intermediates,
        precomputed,
    } = site;
    let signal_offset = parent_offset + signal_offset;
    // Cross-checks the circuit's actual signal layout against what the gadget's VM
    // implementation is prepared to produce, for every kind whose result count has a closed form
    // (Poseidon2's doesn't - see `AcceleratorKind::expected_results`, checked instead at
    // gadget-call time). A mismatch (a widened AliasCheck, a Num2Bits site with intermediates) is
    // a compile-time panic naming the discrepancy, not a silently truncated or garbage witness.
    let actual_results = num_outputs + num_intermediates;
    if let Some(expected) = kind.expected_results() {
        assert_eq!(
            actual_results, expected,
            "accelerated component `{header}` has {actual_results} result slots (signal layout), \
             but {kind:?} expects {expected}",
        );
    }

    let site_id = AcceleratorId::new(accelerator_sites.len());
    accelerator_sites.push(AcceleratorSite {
        kind,
        header,
        num_inputs,
        num_outputs,
        num_intermediates,
        precomputed,
    });

    // The site's inputs, in port order. `TemplateOp::SubCmpInput`'s `port` (and `sub_cmp_inputs`'
    // keys) are the wrapped component's own *local signal index*, which - like every template's -
    // numbers outputs first, then inputs (matching `TemplateOp::LocalSignal`/`LocalSignalWrite`,
    // see `frontend/build.rs`), so input k lives at local signal `num_outputs + k`, not at k
    // directly. Each is also a genuine witness signal (the wrapped component's own input port) -
    // bind it into `outputs`, same as the LocalSignal arm above does for a regular subcomponent's
    // input signal.
    let inputs: Vec<ValueId> = (0..num_inputs)
        .map(|k| {
            let local_signal = num_outputs + k;
            let value = *sub_cmp_inputs.get(&local_signal).unwrap_or_else(|| {
                panic!(
                    "accelerated component input signal {local_signal} read before it was provided"
                )
            });
            outputs.push((SignalIdx::new(signal_offset + local_signal), value));
            value
        })
        .collect();

    let accelerator_id = ValueId::new(nodes.len());
    nodes.push(ir::Node::new(Op::Accelerator(site_id), inputs));

    let mut port_outputs = FxHashMap::default();
    for slot in 0..(num_outputs + num_intermediates) {
        let result_id = ValueId::new(nodes.len());
        let slot_u32 = u32::try_from(slot).expect("accelerator site has more than u32::MAX slots");
        nodes.push(ir::Node::new(
            Op::AcceleratorResult(slot_u32),
            vec![accelerator_id],
        ));
        let signal = if slot < num_outputs {
            port_outputs.insert(slot, result_id);
            signal_offset + slot
        } else {
            signal_offset + num_outputs + num_inputs + (slot - num_outputs)
        };
        outputs.push((SignalIdx::new(signal), result_id));
    }
    port_outputs
}
