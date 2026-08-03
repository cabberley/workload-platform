"""Dependency & Blast Radius module — build the typed dependency graph, rank SPOFs.

Combines **auto-derived** edges (Azure LB/App Gateway backend pools, private links, replication)
with customer **Dependency Packs**, then uses the pure `shared.blast_radius` logic to compute
each node's blast radius and surface single points of failure. Runs as an ACA **Job** (0→10),
event-triggered after discovery.

Estate node ids are Azure ARM resource ids (discovery keys nodes by resource id). The topology
client resolves Load Balancer members to their owning VM's ARM id, so auto-edge endpoints line up
with estate node ids by direct match; any id absent from the estate is skipped and surfaced rather
than invented as a node.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Protocol, cast

from modules.dependency_graph.topology import NetworkTopologyClient
from shared.blast_radius import blast_radius, rank_spofs
from shared.contracts import (
    AgentResponse,
    DependencyEdge,
    EdgeType,
    Finding,
    ModuleKind,
    ModuleManifest,
    ModuleRunResult,
    PackType,
    ResourceNode,
    ScaleProfile,
    ScaleTrigger,
    Severity,
    SourceReference,
    WorkloadGraph,
)
from shared.module_base import Module, ModuleContext


class _PackManifestLike(Protocol):
    """The slice of a pack manifest this module reads (provenance id)."""

    id: str


class _LoadedPack(Protocol):
    """The slice of a loaded pack this module reads: manifest id + parsed body."""

    manifest: _PackManifestLike
    body: dict[str, Any]


class _DependencyPackSource(Protocol):
    """Narrow view of the packs engine: verified Dependency Packs for a workload.

    Duck-typed so the module stays decoupled from the packs engine's concrete type and unit tests
    can inject a lightweight fake. The real ``PacksEngine.load_for_workload`` verifies signatures
    (fail closed) before returning packs.
    """

    def load_for_workload(self, workload: str, pack_type: PackType) -> list[_LoadedPack]:
        ...

_MANIFEST = ModuleManifest(
    name="dependency_graph",
    displayName="Dependency & Blast Radius",
    kind=ModuleKind.job,
    consumes=[PackType.dependency],
    produces=["WorkloadGraph", "spofs", "Finding[]"],
    scaleProfile=ScaleProfile(
        kind=ModuleKind.job,
        minReplicas=0,
        maxReplicas=10,
        triggers=[ScaleTrigger(type="azure-queue", metadata={"queueName": "dependency"})],
        cpu=0.5,
        memoryGi=1.0,
    ),
)


def edges_from_backend_pool(lb_id: str, member_ids: list[str]) -> list[DependencyEdge]:
    """Auto-derive typed dependency edges from an LB/App Gateway backend pool.

    Two directions capture the full redundancy story so the pure blast-radius math ranks the
    balancer as the single point of failure it is:

    * ``member -> lb`` (**non-redundant**): every member depends on the balancer to receive
      traffic and has no alternate ingress, so losing the LB **downs all members** (SPOF).
    * ``lb -> member`` (**redundant** when ``len(member_ids) > 1``): the balanced service depends
      on its members, which are redundant peers, so losing *one* member only **degrades** the
      service (losing the sole member downs it).
    """
    edges: list[DependencyEdge] = []
    redundant_peers = len(member_ids) > 1
    for member in member_ids:
        edges.append(
            DependencyEdge(
                source=member, target=lb_id, type=EdgeType.load_balances,
                redundant=False, origin="auto",
            )
        )
        edges.append(
            DependencyEdge(
                source=lb_id, target=member, type=EdgeType.load_balances,
                redundant=redundant_peers, origin="auto",
            )
        )
    return edges


def spof_findings(graph: WorkloadGraph, threshold: int = 1) -> list[Finding]:
    """Emit a Finding for each node whose failure downs more than `threshold` nodes."""
    findings: list[Finding] = []
    for node_id, radius in rank_spofs(graph):
        if radius < threshold:
            continue
        sev = (
            Severity.critical if radius >= 5
            else Severity.high if radius >= 2
            else Severity.medium
        )
        findings.append(
            Finding(
                id=f"spof::{node_id}",
                module="dependency_graph",
                title="Single point of failure",
                passed=False,
                severity=sev,
                nodeId=node_id,
                blastRadius=radius,
                evidence=[SourceReference(kind="resource", id=node_id,
                                          detail=f"blast radius = {radius}")],
                detail=f"Failure of {node_id} takes down {radius} dependent node(s).",
            )
        )
    return findings


class DependencyGraphModule(Module):
    @property
    def manifest(self) -> ModuleManifest:
        return _MANIFEST

    def run(self, ctx: ModuleContext, *, scope: dict[str, str] | None = None) -> ModuleRunResult:
        scope = scope or {}
        workloads = self._resolve_workloads(ctx, scope)
        estate_by_workload = self._estate_by_workload(ctx, workloads)
        nodes = _merge_nodes(estate_by_workload, workloads)

        auto_edges, unresolved = self._auto_edges(ctx, scope, nodes)
        pack_edges = self._pack_edges(ctx, workloads, estate_by_workload)
        edges = _dedupe_edges(auto_edges + pack_edges)

        graph = WorkloadGraph(nodes=nodes, edges=edges)
        findings = spof_findings(graph)
        top = rank_spofs(graph)[:5]

        risks = [f"{nid}: blast radius {r}" for nid, r in top if r > 0]
        if unresolved:
            risks.append(f"{len(unresolved)} backend-pool member(s) unresolved to estate nodes")
        response = AgentResponse(
            agentName="dependency_graph",
            taskType="build-graph-and-blast-radius",
            inputSummary=(
                f"workloads={workloads or 'all'}; nodes={len(nodes)}; edges={len(edges)} "
                f"(auto={len(auto_edges)}, pack={len(pack_edges)}); "
                f"unresolvedMembers={len(unresolved)}"
            ),
            findings=[f"{len(findings)} SPOF(s) identified"],
            risks=risks,
            sourceReferences=[
                SourceReference(kind="resource", id=nid, detail=f"blast radius = {r}")
                for nid, r in top if r > 0
            ],
            confidence=1.0,
            nextActions=["route-findings"] if findings else [],
        )
        return ModuleRunResult(module=self.name, ok=True, findings=findings, response=response,
                               graph=graph,
                               extra={"topSpofs": top, "unresolvedMembers": unresolved})

    @staticmethod
    def _resolve_workloads(ctx: ModuleContext, scope: dict[str, str]) -> list[str]:
        """Resolve the workload(s) to build: an explicit scope target, else every known workload.

        Fail closed: with no state view we simply have no workloads (empty graph), never a crash.
        """
        target = scope.get("workload")
        if target:
            return [target]
        if ctx.state is None:
            return []
        return list(ctx.state.list_workloads())

    @staticmethod
    def _estate_by_workload(
        ctx: ModuleContext, workloads: list[str]
    ) -> dict[str, list[ResourceNode]]:
        """Read each workload's estate **separately** so pack roles stay workload-scoped (FIX 3)."""
        if ctx.state is None:
            return {}
        return {workload: ctx.state.get_estate(workload) for workload in workloads}

    @staticmethod
    def _auto_edges(
        ctx: ModuleContext, scope: dict[str, str], nodes: list[ResourceNode]
    ) -> tuple[list[DependencyEdge], list[str]]:
        """Derive edges from network topology, resolving members to real estate nodes.

        Returns ``(edges, unresolved_member_ids)``. Fail closed: no client => no auto edges. A
        backend-pool member (or the balancer itself) that cannot be resolved to an estate node is
        **skipped and surfaced** — never turned into a phantom-endpoint edge (FIX 2).

        TODO(human): extend beyond LB/App-Gateway backend pools to auto-derive private-link and
        replication edges from ``BackendPool.private_link_ids`` / ``replica_ids`` once the
        topology client populates them (depth/typed-edge semantics to be decided).
        """
        client = ctx.clients.get("network")
        if client is None:
            return [], []
        network = cast(NetworkTopologyClient, client)
        node_ids = {n.id for n in nodes}
        pool_scope = scope.get("scope") or scope.get("workload") or ""

        edges: list[DependencyEdge] = []
        unresolved: list[str] = []
        for pool in network.backend_pools(pool_scope):
            lb_node = _resolve_member(pool.load_balancer_id, node_ids)
            if lb_node is None:
                unresolved.append(pool.load_balancer_id)
                continue
            members: list[str] = []
            for raw_member in pool.member_ids:
                resolved = _resolve_member(raw_member, node_ids)
                if resolved is None:
                    unresolved.append(raw_member)
                else:
                    members.append(resolved)
            # FIX A: dedupe resolved members BEFORE the count-based redundancy flag is derived —
            # two IP-configs owned by one VM must count as a single (non-redundant) member.
            edges.extend(edges_from_backend_pool(lb_node, _dedupe_preserving_order(members)))
        return edges, _dedupe_preserving_order(unresolved)

    @staticmethod
    def _pack_edges(
        ctx: ModuleContext,
        workloads: list[str],
        estate_by_workload: dict[str, list[ResourceNode]],
    ) -> list[DependencyEdge]:
        """Resolve customer Dependency Pack edges to node/role ids, tagged ``origin='pack:<id>'``.

        Each pack edge names a namespaced ``source``/``target`` — ``role:<name>`` (expanded to the
        nodes carrying that role), ``id:<resourceId>`` (a concrete node), or ``type:<resourceType>``
        (all nodes of that Azure type). Unresolvable/unnamespaced references are skipped (fail
        closed).

        FIX 3: each workload's packs are resolved **only** against that workload's own estate, so a
        role in one workload never satisfies another workload's reference. Edges are merged and
        deduped by the caller.
        """
        if ctx.packs is None:
            return []
        packs = cast(_DependencyPackSource, ctx.packs)
        edges: list[DependencyEdge] = []
        for workload in workloads:
            wl_nodes = estate_by_workload.get(workload, [])
            node_ids = {n.id for n in wl_nodes}
            role_index: dict[str, list[str]] = defaultdict(list)
            type_index: dict[str, list[str]] = defaultdict(list)
            for node in wl_nodes:
                if node.role:
                    role_index[node.role].append(node.id)
                type_index[node.type].append(node.id)
            for pack in packs.load_for_workload(workload, PackType.dependency):
                edges.extend(_edges_from_pack(pack, node_ids, role_index, type_index))
        return edges


def _merge_nodes(
    estate_by_workload: dict[str, list[ResourceNode]], workloads: list[str]
) -> list[ResourceNode]:
    """Flatten per-workload estates into one node list for the graph, deduping by node id."""
    nodes: list[ResourceNode] = []
    seen: set[str] = set()
    for workload in workloads:
        for node in estate_by_workload.get(workload, []):
            if node.id in seen:
                continue
            seen.add(node.id)
            nodes.append(node)
    return nodes


def _ancestor_ids(resource_id: str) -> list[str]:
    """Yield ``resource_id`` then each parent Azure resource id (stripping ``/type/name`` pairs).

    Fallback for a backend member that is a *child* of an estate node (e.g. a sub-resource id):
    it resolves to the owning ancestor the estate surfaced as a node.
    """
    out = [resource_id]
    parts = resource_id.split("/")
    while len(parts) > 2:
        parts = parts[:-2]
        candidate = "/".join(parts)
        if candidate:
            out.append(candidate)
    return out


def _resolve_member(member_id: str, node_ids: set[str]) -> str | None:
    """Resolve a topology member reference to an estate ``ResourceNode.id`` or ``None``.

    The topology client already resolves Load Balancer members to owning-VM ARM ids, and discovery
    keys estate nodes by ARM resource id, so the common case is a direct id match. An id-ancestry
    fallback covers a member that is a sub-resource of an estate node. Anything else returns
    ``None`` so the caller skips + surfaces it (never a phantom node).
    """
    for candidate in _ancestor_ids(member_id):
        if candidate in node_ids:
            return candidate
    return None


def _dedupe_preserving_order(values: list[str]) -> list[str]:
    """Return ``values`` with duplicates removed, preserving first-seen order."""
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _resolve_ref(
    ref: str,
    node_ids: set[str],
    role_index: dict[str, list[str]],
    type_index: dict[str, list[str]],
) -> list[str]:
    """Resolve a namespaced pack edge endpoint to concrete node ids.

    Supported forms (the canonical shipped format is ``role:<name>``):
      * ``role:<name>``      -> every node carrying that role
      * ``id:<resourceId>``  -> that node if present in the estate
      * ``type:<azureType>`` -> every node of that Azure resource type

    Bare/unnamespaced or unknown-namespace references resolve to nothing (fail closed): packs must
    use the explicit namespaced form so a reference is never silently ambiguous.
    """
    namespace, sep, name = ref.partition(":")
    if not sep or not name:
        return []
    if namespace == "role":
        return list(role_index.get(name, []))
    if namespace == "id":
        return [name] if name in node_ids else []
    if namespace == "type":
        return list(type_index.get(name, []))
    return []


def _coerce_edge_type(value: object) -> EdgeType:
    """Map a pack-declared edge type to :class:`EdgeType`, defaulting to ``depends_on``."""
    if isinstance(value, str):
        try:
            return EdgeType(value)
        except ValueError:
            return EdgeType.depends_on
    return EdgeType.depends_on


def _edges_from_pack(
    pack: _LoadedPack,
    node_ids: set[str],
    role_index: dict[str, list[str]],
    type_index: dict[str, list[str]],
) -> list[DependencyEdge]:
    """Expand one Dependency Pack's declared edges against the estate, tagging provenance."""
    origin = f"pack:{pack.manifest.id}"
    out: list[DependencyEdge] = []
    for raw in pack.body.get("edges", []):
        source = raw.get("source")
        target = raw.get("target")
        if not source or not target:
            continue
        etype = _coerce_edge_type(raw.get("type"))
        redundant = bool(raw.get("redundant", False))
        for src in _resolve_ref(source, node_ids, role_index, type_index):
            for tgt in _resolve_ref(target, node_ids, role_index, type_index):
                if src == tgt:
                    continue
                out.append(
                    DependencyEdge(
                        source=src, target=tgt, type=etype, redundant=redundant, origin=origin
                    )
                )
    return out


def _dedupe_edges(edges: list[DependencyEdge]) -> list[DependencyEdge]:
    """Drop duplicate edges (same source/target/type/redundant/origin), preserving order."""
    seen: set[tuple[str, str, str, bool, str]] = set()
    out: list[DependencyEdge] = []
    for edge in edges:
        key = (edge.source, edge.target, edge.type.value, edge.redundant, edge.origin)
        if key in seen:
            continue
        seen.add(key)
        out.append(edge)
    return out


# Keep an explicit reference so linters see the imported helper is part of the public surface.
__all__ = [
    "DependencyGraphModule",
    "NetworkTopologyClient",
    "blast_radius",
    "edges_from_backend_pool",
    "spof_findings",
]
