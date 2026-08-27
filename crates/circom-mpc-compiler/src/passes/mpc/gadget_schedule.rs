//! Placement analysis for gadget batches, shared by codegen and `Graph::mpc_summary`.
//! Sites normally coalesce by `(kind, network stage, domain, precomputed)`. A valid but
//! non-level-sorted graph may place an early result consumer before a later independent site; in
//! that case the active batch is closed and a new one is started instead of rejecting the
//! circuit. `precomputed` is part of the key so a host-supplied site never coalesces with one the
//! driver still has to service.

use rustc_hash::FxHashMap;

use crate::ir::{GadgetKind, Graph, Op};

use super::domain::Domain;
use super::level;

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

pub(crate) fn plan_gadget_batches(graph: &Graph, domains: &[Domain]) -> Vec<BatchPlan> {
    let nodes = graph.nodes();
    let sites = graph.gadget_sites();
    if sites.is_empty() {
        return Vec::new();
    }

    let stages = level::site_stages(graph, domains);
    let mut site_node = vec![usize::MAX; sites.len()];
    for (i, node) in nodes.iter().enumerate() {
        if let Op::Gadget(site_id) = &node.op {
            site_node[site_id.index()] = i;
        }
    }

    // A result node merely names a batch slot; the deadline is its first real reader.
    let mut first_reader = vec![nodes.len(); sites.len()];
    for (i, node) in nodes.iter().enumerate() {
        for input in &node.inputs {
            if !matches!(nodes[input.index()].op, Op::GadgetResult(_)) {
                continue;
            }
            let producer = &nodes[nodes[input.index()].inputs[0].index()];
            if let Op::Gadget(site_id) = &producer.op {
                first_reader[site_id.index()] = first_reader[site_id.index()].min(i);
            }
        }
    }

    let mut plans = Vec::<BatchPlan>::new();
    let mut active = FxHashMap::<(GadgetKind, usize, Domain, bool), usize>::default();
    for (site_id, site) in sites.iter().enumerate() {
        let node = site_node[site_id];
        let stage = stages[site_id];
        let domain = domains[node];
        let key = (site.kind, stage, domain, site.precomputed);

        let append_to = active.get(&key).copied().filter(|&idx| {
            let plan = &plans[idx];
            plan.anchor.max(node) < plan.deadline.min(first_reader[site_id])
        });
        if let Some(idx) = append_to {
            let plan = &mut plans[idx];
            plan.sites.push((site_id, node));
            plan.anchor = plan.anchor.max(node);
            plan.deadline = plan.deadline.min(first_reader[site_id]);
        } else {
            let idx = plans.len();
            plans.push(BatchPlan {
                kind: site.kind,
                domain,
                sites: vec![(site_id, node)],
                anchor: node,
                stage,
                precomputed: site.precomputed,
                deadline: first_reader[site_id],
            });
            active.insert(key, idx);
        }
    }

    // Hash-map iteration never affects output: plans are ordered solely by structural data.
    plans.sort_by_key(|plan| (plan.stage, plan.sites[0].0));
    plans
}
