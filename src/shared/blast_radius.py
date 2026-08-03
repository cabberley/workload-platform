"""Pure blast-radius math over the dependency graph.

No I/O, no Azure — just graph logic, so it is fully unit-testable. Given a typed
`WorkloadGraph`, compute which nodes go *down* when a given node fails, honoring
redundancy (a redundant dependency edge degrades rather than downs the dependent).
"""
from __future__ import annotations

from collections import defaultdict

from shared.contracts import DependencyEdge, HealthState, WorkloadGraph


def _dependents_index(edges: list[DependencyEdge]) -> dict[str, list[DependencyEdge]]:
    """Map target -> edges whose source depends on that target."""
    idx: dict[str, list[DependencyEdge]] = defaultdict(list)
    for e in edges:
        idx[e.target].append(e)
    return idx


def compute_impact(graph: WorkloadGraph, failed_node: str) -> dict[str, HealthState]:
    """Return the health state of every node given `failed_node` has gone down.

    Rules:
      * The failed node is `down`.
      * A node with a **non-redundant** dependency on a `down` node is `down`.
      * A node whose only affected dependencies are **redundant** is `degraded`.
      * Effects propagate transitively (a downed dependent downs *its* dependents).
      * Everything else stays `up`.
    """
    node_ids = {n.id for n in graph.nodes}
    node_ids.add(failed_node)
    dependents = _dependents_index(graph.edges)

    state: dict[str, HealthState] = {nid: HealthState.up for nid in node_ids}
    state[failed_node] = HealthState.down

    # Iterate to a fixed point (graphs are small; estates are thousands of nodes at most).
    changed = True
    while changed:
        changed = False
        for target, edges in dependents.items():
            if state.get(target) != HealthState.down:
                continue
            for edge in edges:
                src = edge.source
                if state.get(src) == HealthState.down:
                    continue
                if edge.redundant:
                    if state.get(src) == HealthState.up:
                        state[src] = HealthState.degraded
                        changed = True
                else:
                    state[src] = HealthState.down
                    changed = True
    return state


def blast_radius(graph: WorkloadGraph, failed_node: str) -> int:
    """Count of nodes that go **down** (excluding the failed node itself) if it fails."""
    impact = compute_impact(graph, failed_node)
    return sum(
        1 for nid, st in impact.items() if st == HealthState.down and nid != failed_node
    )


def rank_spofs(graph: WorkloadGraph) -> list[tuple[str, int]]:
    """Rank nodes by blast radius (descending). Single points of failure surface at the top."""
    scored = [(n.id, blast_radius(graph, n.id)) for n in graph.nodes]
    scored.sort(key=lambda pair: pair[1], reverse=True)
    return scored
