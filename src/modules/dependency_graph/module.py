"""Dependency & Blast Radius module — build the typed dependency graph, rank SPOFs.

Combines **auto-derived** edges (Azure LB/App Gateway backend pools, private links, replication)
with customer **Dependency Packs**, then uses the pure `shared.blast_radius` logic to compute
each node's blast radius and surface single points of failure. Runs as an ACA **Job** (0→10),
event-triggered after discovery.
"""
from __future__ import annotations

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
    ScaleProfile,
    ScaleTrigger,
    Severity,
    SourceReference,
    WorkloadGraph,
)
from shared.module_base import Module, ModuleContext

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
    """Auto-derive redundant dependency edges from an LB/App Gateway backend pool.

    Each member depends on the LB to receive traffic; members are redundant peers, so losing
    one member is *degraded*, but losing the LB is *down* for all members.
    """
    edges: list[DependencyEdge] = []
    for member in member_ids:
        edges.append(
            DependencyEdge(
                source=member, target=lb_id, type=EdgeType.load_balances,
                redundant=len(member_ids) > 1, origin="auto",
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
        # Auto-derived + pack edges arrive in issue #4; the skeleton builds an empty graph and
        # surfaces it on ``graph`` so the API (single writer) can persist it.
        graph = WorkloadGraph(nodes=[], edges=[])
        findings = spof_findings(graph)
        top = rank_spofs(graph)[:5]
        response = AgentResponse(
            agentName="dependency_graph",
            taskType="build-graph-and-blast-radius",
            inputSummary=f"scope={scope or 'all'}; nodes={len(graph.nodes)}",
            findings=[f"{len(findings)} SPOF(s) identified"],
            risks=[f"{nid}: blast radius {r}" for nid, r in top if r > 0],
            confidence=1.0,
            nextActions=["route-findings"] if findings else [],
        )
        return ModuleRunResult(module=self.name, ok=True, findings=findings, response=response,
                               graph=graph,
                               extra={"topSpofs": top})


# Keep an explicit reference so linters see the imported helper is part of the public surface.
__all__ = ["DependencyGraphModule", "edges_from_backend_pool", "spof_findings", "blast_radius"]
