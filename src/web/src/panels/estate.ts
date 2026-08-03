// Pure derivation (no I/O): condense a WorkloadGraph into an estate summary. Kept pure so it can be
// unit-tested Azure-free, mirroring the house rule that scoring/graph math are pure functions.
//
// IMPORTANT: none of these are blast-radius or SPOF measures. Canonical blast radius (which treats
// redundant dependents as *degraded, not down*) lives in `src/shared/blast_radius.py` and is
// consumed via its own read model (issue #56). Reimplementing that math here would risk divergence,
// so this module reports only raw, factual graph properties with no risk implication.

import type { WorkloadGraph } from "../api/types";

/** Most depended-on node by NON-REDUNDANT in-degree. Raw graph fan-in — NOT a SPOF/blast measure. */
export type MostDependedOn = {
  nodeId: string;
  name: string;
  /** How many dependents reach this node via a single (non-redundant) edge. */
  inDegree: number;
};

export type EstateSummary = {
  nodeCount: number;
  edgeCount: number;
  tiers: string[];
  roles: string[];
  /** Edges with `redundant === false` — single-path dependencies (no backup path). A factual graph
   *  property, not a blast-radius claim. */
  singlePathEdges: number;
  /** Node with the highest NON-REDUNDANT in-degree, or null when no non-redundant edges exist. A
   *  node reached only via redundant edges is deliberately NOT surfaced here (it has a backup path,
   *  so raw fan-in over redundant edges would overstate its importance). */
  mostDependedOn: MostDependedOn | null;
};

/**
 * Summarise a workload's dependency graph. Everything here comes straight from the graph read model
 * (nodes/edges) — no blast-radius recompute, no invented data, no risk labelling. `singlePathEdges`
 * and `mostDependedOn` are conservative, purely factual graph facts so the estate view needs no
 * extra backend endpoint.
 */
export function summariseGraph(graph: WorkloadGraph): EstateSummary {
  const tiers = new Set<string>();
  const roles = new Set<string>();
  for (const node of graph.nodes) {
    if (node.tier) tiers.add(node.tier);
    if (node.role) roles.add(node.role);
  }

  let singlePathEdges = 0;
  // In-degree over NON-REDUNDANT edges only. A dependent reached via a redundant edge has a backup
  // path, so it is excluded — counting it would mislabel a redundantly-reached node as important.
  const nonRedundantInDegree = new Map<string, number>();
  for (const edge of graph.edges) {
    if (!edge.redundant) {
      singlePathEdges += 1;
      nonRedundantInDegree.set(edge.target, (nonRedundantInDegree.get(edge.target) ?? 0) + 1);
    }
  }

  const nameById = new Map(graph.nodes.map((n) => [n.id, n.name]));
  let mostDependedOn: MostDependedOn | null = null;
  for (const [nodeId, count] of nonRedundantInDegree) {
    if (
      mostDependedOn === null ||
      count > mostDependedOn.inDegree ||
      (count === mostDependedOn.inDegree && nodeId.localeCompare(mostDependedOn.nodeId) < 0)
    ) {
      mostDependedOn = { nodeId, name: nameById.get(nodeId) ?? nodeId, inDegree: count };
    }
  }

  return {
    nodeCount: graph.nodes.length,
    edgeCount: graph.edges.length,
    tiers: Array.from(tiers).sort(),
    roles: Array.from(roles).sort(),
    singlePathEdges,
    mostDependedOn,
  };
}
