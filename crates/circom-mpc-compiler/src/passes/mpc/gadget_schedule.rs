//! Placement analysis for gadget batches, used by codegen.
//! Sites normally coalesce by `(kind, network stage, domain, precomputed)`. A valid but
//! non-level-sorted graph may place an early result consumer before a later independent site; in
//! that case the active batch is closed and a new one is started instead of rejecting the
//! circuit. `precomputed` is part of the key so a host-supplied site never coalesces with one the
//! driver still has to service.

use rustc_hash::FxHashMap;

use super::{domain::Domain, level};
use crate::ir::{GadgetKind, Graph, Op, ValueId};

#[derive(Debug, Clone)]
pub(crate) struct BatchPlan {
    pub(crate) kind: GadgetKind,
    pub(crate) domain: Domain,
    pub(crate) sites: Vec<(usize, usize)>,
    pub(crate) anchor: usize,
    pub(crate) stage: usize,
    pub(crate) precomputed: bool,
    deadline: usize,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct IsZeroRevealSite {
    pub(crate) zero_test_site: usize,
    pub(crate) reveal_site: usize,
    pub(crate) input: ValueId,
}

#[derive(Debug)]
pub(crate) struct IsZeroRevealPlan {
    pub(crate) anchor: usize,
    pub(crate) sites: Vec<IsZeroRevealSite>,
}

#[derive(Debug)]
pub(crate) enum ScheduledBatch {
    Gadget(BatchPlan),
    IsZeroReveal(IsZeroRevealPlan),
}

impl ScheduledBatch {
    pub(crate) fn anchor(&self) -> usize {
        match self {
            Self::Gadget(plan) => plan.anchor,
            Self::IsZeroReveal(plan) => plan.anchor,
        }
    }
}

/// Graph relationships shared by ordinary batch placement and its fusion post-pass.
struct ScheduleIndex {
    site_node: Vec<usize>,
    first_reader: Vec<usize>,
    result_readers: Vec<usize>,
    auxiliary_result_read: Vec<bool>,
}

impl ScheduleIndex {
    fn new(graph: &Graph) -> Self {
        let nodes = graph.nodes();
        let mut site_node = vec![usize::MAX; graph.gadget_sites().len()];
        let mut first_reader = vec![nodes.len(); graph.gadget_sites().len()];
        let mut result_readers = vec![0usize; nodes.len()];
        let mut auxiliary_result_read = vec![false; graph.gadget_sites().len()];

        for (reader, node) in nodes.iter().enumerate() {
            if let Op::Gadget(site_id) = node.op {
                site_node[site_id.index()] = reader;
            }
            for &input in &node.inputs {
                let result = &nodes[input.index()];
                let Op::GadgetResult(slot) = result.op else {
                    continue;
                };
                let producer = &nodes[result.inputs[0].index()];
                let Op::Gadget(site_id) = producer.op else {
                    unreachable!("a GadgetResult's input is always its Gadget node");
                };
                let site = site_id.index();
                result_readers[input.index()] += 1;
                first_reader[site] = first_reader[site].min(reader);
                auxiliary_result_read[site] |= slot != 0;
            }
        }

        Self {
            site_node,
            first_reader,
            result_readers,
            auxiliary_result_read,
        }
    }
}

pub(crate) fn plan_gadget_batches(graph: &Graph, domains: &[Domain]) -> Vec<ScheduledBatch> {
    let index = ScheduleIndex::new(graph);
    let plans = plan_plain_batches(graph, domains, &index);
    fuse_zero_test_reveals(graph, plans, &index)
}

fn plan_plain_batches(graph: &Graph, domains: &[Domain], index: &ScheduleIndex) -> Vec<BatchPlan> {
    let sites = graph.gadget_sites();
    if sites.is_empty() {
        return Vec::new();
    }

    let stages = level::site_stages(graph, domains);
    let mut plans = Vec::<BatchPlan>::new();
    let mut active = FxHashMap::<(GadgetKind, usize, Domain, bool), usize>::default();
    for (site_id, site) in sites.iter().enumerate() {
        let node = index.site_node[site_id];
        let stage = stages[site_id];
        let domain = domains[node];
        // A wrapped Poseidon2 site that turns out fully public has nothing for the host to
        // precompute (its inputs never depend on any party's secret data) - fall through to an
        // ordinary driver-serviced site instead of the host-precomputed path. This costs nothing
        // extra: an all-public gadget batch already runs with no network round (every input is a
        // trivial share - see `poseidon2::mask_budget`), so the two paths are equally free here.
        let precomputed = site.precomputed && domain == Domain::Shared;
        let key = (site.kind, stage, domain, precomputed);

        let append_to = active.get(&key).copied().filter(|&idx| {
            let plan = &plans[idx];
            plan.anchor.max(node) < plan.deadline.min(index.first_reader[site_id])
        });
        if let Some(idx) = append_to {
            let plan = &mut plans[idx];
            plan.sites.push((site_id, node));
            plan.anchor = plan.anchor.max(node);
            plan.deadline = plan.deadline.min(index.first_reader[site_id]);
        } else {
            let idx = plans.len();
            plans.push(BatchPlan {
                kind: site.kind,
                domain,
                sites: vec![(site_id, node)],
                anchor: node,
                stage,
                precomputed,
                deadline: index.first_reader[site_id],
            });
            active.insert(key, idx);
        }
    }

    // Hash-map iteration never affects output: plans are ordered solely by structural data.
    plans.sort_by_key(|plan| (plan.stage, plan.sites[0].0));
    plans
}

fn match_fusion_site(
    nodes: &[crate::ir::Node],
    index: &ScheduleIndex,
    site_plan: &[usize],
    reveal_site: usize,
    reveal_node: usize,
) -> Option<(usize, IsZeroRevealSite)> {
    let [zero_test_result] = nodes[reveal_node].inputs.as_slice() else {
        return None;
    };
    if !matches!(nodes[zero_test_result.index()].op, Op::GadgetResult(0))
        || index.result_readers[zero_test_result.index()] != 1
    {
        return None;
    }
    let zero_test_node = nodes[zero_test_result.index()].inputs[0].index();
    let Op::Gadget(zero_test_site_id) = nodes[zero_test_node].op else {
        return None;
    };
    let zero_test_site = zero_test_site_id.index();
    let [input] = nodes[zero_test_node].inputs.as_slice() else {
        return None;
    };
    if index.auxiliary_result_read[zero_test_site] {
        return None;
    }
    let source_plan = site_plan[zero_test_site];
    (source_plan != usize::MAX).then_some((
        source_plan,
        IsZeroRevealSite {
            zero_test_site,
            reveal_site,
            input: *input,
        },
    ))
}

fn match_fusion_batch(
    graph: &Graph,
    plan: &BatchPlan,
    index: &ScheduleIndex,
    site_plan: &[usize],
) -> Option<(usize, Vec<IsZeroRevealSite>)> {
    let mut source_plan = None;
    let mut sites = Vec::with_capacity(plan.sites.len());
    for &(reveal_site, reveal_node) in &plan.sites {
        let (source, site) =
            match_fusion_site(graph.nodes(), index, site_plan, reveal_site, reveal_node)?;
        if source_plan.is_some_and(|current| current != source) {
            return None;
        }
        source_plan = Some(source);
        sites.push(site);
    }
    Some((source_plan?, sites))
}

/// Replaces complete, aligned `IsZero` and `Reveal(1)` batches with the VM shortcut.
fn fuse_zero_test_reveals(
    graph: &Graph,
    plans: Vec<BatchPlan>,
    index: &ScheduleIndex,
) -> Vec<ScheduledBatch> {
    let mut site_plan = vec![usize::MAX; graph.gadget_sites().len()];
    for (plan_idx, plan) in plans.iter().enumerate() {
        for &(site_id, _) in &plan.sites {
            site_plan[site_id] = plan_idx;
        }
    }

    let mut replaced_sources = vec![false; plans.len()];
    let mut replacements: Vec<Option<IsZeroRevealPlan>> = (0..plans.len()).map(|_| None).collect();
    for (reveal_plan_idx, reveal_plan) in plans.iter().enumerate() {
        if reveal_plan.domain != Domain::Shared || reveal_plan.kind != (GadgetKind::Reveal { n: 1 })
        {
            continue;
        }
        let Some((source_plan, sites)) = match_fusion_batch(graph, reveal_plan, index, &site_plan)
        else {
            continue;
        };
        let source = &plans[source_plan];
        if source.domain != Domain::Shared
            || source.kind != GadgetKind::IsZero
            || source.sites.len() != sites.len()
        {
            continue;
        }
        debug_assert!(
            !replaced_sources[source_plan],
            "a result cannot have two sole readers"
        );
        replaced_sources[source_plan] = true;
        replacements[reveal_plan_idx] = Some(IsZeroRevealPlan {
            anchor: reveal_plan.anchor,
            sites,
        });
    }

    plans
        .into_iter()
        .enumerate()
        .filter_map(|(idx, plan)| {
            if replaced_sources[idx] {
                None
            } else if let Some(fusion) = replacements[idx].take() {
                Some(ScheduledBatch::IsZeroReveal(fusion))
            } else {
                Some(ScheduledBatch::Gadget(plan))
            }
        })
        .collect()
}
