"""Auto-RCA correlation tests (issue #50) — pure, synthetic graphs + findings.

Covers graph-wide, multi-detection correlation and confidence gating around
``RCA_CONFIDENCE_FLOOR``: a single upstream SPOF, two independent clusters, purely-downstream
symptoms, redundant-only impact, and the low-confidence support path. All fixtures are synthetic
and Azure-free (guardrails: advisory only, provenance on every conclusion, fail-closed).
"""
from __future__ import annotations

from modules.aiops.rca import (
    RCA_CONFIDENCE_FLOOR,
    correlate_rca,
    correlate_root_cause,
)
from shared.contracts import (
    AgentResponse,
    DependencyEdge,
    Finding,
    ResourceNode,
    Severity,
    SourceReference,
    WorkloadGraph,
)


def _node(node_id: str) -> ResourceNode:
    return ResourceNode(id=node_id, name=node_id, type="synthetic")


def _edge(source: str, target: str, *, redundant: bool = False) -> DependencyEdge:
    return DependencyEdge(source=source, target=target, redundant=redundant)


def _finding(node_id: str, *, metric: str = "latency_ms") -> Finding:
    """A synthetic detection pinned to a symptom node, carrying cited metric evidence."""
    return Finding(
        id=f"detect::{metric}::{node_id}",
        module="aiops",
        title=f"Telemetry breach on {node_id}",
        passed=False,
        severity=Severity.high,
        nodeId=node_id,
        evidence=[SourceReference(kind="metric", id=metric, detail=f"breach at {node_id}")],
        packId="telemetry-baseline", packVersion="1.0.0",
    )


def _unlocalized_finding() -> Finding:
    """A detection that could not be pinned to a node (no ``nodeId``)."""
    return Finding(
        id="detect::orphan",
        module="aiops",
        title="Unlocalized telemetry breach",
        passed=False,
        severity=Severity.high,
        nodeId=None,
        evidence=[SourceReference(kind="metric", id="orphan_metric", detail="no node")],
        packId="telemetry-baseline", packVersion="1.0.0",
    )


def _cited_node_ids(resp: AgentResponse) -> set[str]:
    return {ref.id for ref in resp.sourceReferences}


# --------------------------------------------------------------------------------------
# (a) A single upstream SPOF explaining many downstream symptoms -> confident root cause.
# --------------------------------------------------------------------------------------
def test_single_spof_explains_downstream_is_confident_root_cause() -> None:
    graph = WorkloadGraph(
        nodes=[_node("odb"), _node("web1"), _node("web2"), _node("web3")],
        edges=[_edge("web1", "odb"), _edge("web2", "odb"), _edge("web3", "odb")],
    )
    findings = [_finding("odb"), _finding("web1"), _finding("web2"), _finding("web3")]

    resp = correlate_root_cause(findings, graph)

    assert resp.confidence >= RCA_CONFIDENCE_FLOOR
    assert resp.nextActions == ["propose-remediation"]
    assert "odb" in resp.recommendations[0]
    assert "root cause" in resp.recommendations[0].lower()
    # Provenance: symptom evidence AND the identified root-cause node are cited.
    assert "odb" in _cited_node_ids(resp)
    assert "latency_ms" in _cited_node_ids(resp)
    assert any(ref.kind == "resource" and ref.id == "odb" for ref in resp.sourceReferences)
    # Blast radius is conveyed as a risk.
    assert any("blast radius" in r for r in resp.risks)


# --------------------------------------------------------------------------------------
# (b) Two INDEPENDENT clusters with no common upstream -> surfaced as multiple, support path.
# --------------------------------------------------------------------------------------
def test_two_independent_clusters_surface_low_confidence_support() -> None:
    graph = WorkloadGraph(
        nodes=[_node("dbA"), _node("webA"), _node("dbB"), _node("webB")],
        edges=[_edge("webA", "dbA"), _edge("webB", "dbB")],
    )
    findings = [_finding("dbA"), _finding("dbB")]

    resp = correlate_root_cause(findings, graph)

    assert resp.confidence < RCA_CONFIDENCE_FLOOR
    assert resp.nextActions == ["recommend-contact-support"]
    # Not force-fit to one: the independent clusters are surfaced explicitly.
    joined = " ".join(resp.recommendations).lower()
    assert "independent" in joined
    assert "2" in " ".join(resp.recommendations)
    # No confident root cause asserted -> no 'resource' provenance ref, but symptoms still cited.
    assert not any(ref.kind == "resource" for ref in resp.sourceReferences)
    assert "latency_ms" in _cited_node_ids(resp)
    assert "propose-remediation" not in resp.nextActions


# --------------------------------------------------------------------------------------
# (c) A purely downstream symptom set -> RCA points UPSTREAM, not at the symptom nodes.
# --------------------------------------------------------------------------------------
def test_downstream_only_symptoms_point_upstream() -> None:
    graph = WorkloadGraph(
        nodes=[_node("odb"), _node("web1"), _node("web2")],
        edges=[_edge("web1", "odb"), _edge("web2", "odb")],
    )
    # Only the downstream web nodes are symptomatic; odb itself has no finding.
    findings = [_finding("web1"), _finding("web2")]

    resp = correlate_root_cause(findings, graph)

    assert resp.confidence >= RCA_CONFIDENCE_FLOOR
    assert resp.nextActions == ["propose-remediation"]
    # Points at the upstream cause, not the symptom nodes.
    assert "odb" in resp.recommendations[0]
    assert "web1" not in resp.recommendations[0]
    assert "web2" not in resp.recommendations[0]
    assert any(ref.kind == "resource" and ref.id == "odb" for ref in resp.sourceReferences)


# --------------------------------------------------------------------------------------
# (d) Redundant-only impact (degraded, not down) does NOT inflate a false root cause.
# --------------------------------------------------------------------------------------
def test_redundant_only_impact_does_not_inflate_false_root_cause() -> None:
    # api depends on odb (non-redundant -> down) and on cache (redundant -> degraded only).
    graph = WorkloadGraph(
        nodes=[_node("odb"), _node("api"), _node("cache")],
        edges=[_edge("api", "odb"), _edge("api", "cache", redundant=True)],
    )
    findings = [_finding("odb"), _finding("api")]

    resp = correlate_root_cause(findings, graph)

    assert resp.confidence >= RCA_CONFIDENCE_FLOOR
    assert resp.nextActions == ["propose-remediation"]
    # The real (down-causing) SPOF is named, not the redundant cache.
    assert "odb" in resp.recommendations[0]
    assert "cache" not in resp.recommendations[0]
    assert any(ref.kind == "resource" and ref.id == "odb" for ref in resp.sourceReferences)
    assert not any(ref.kind == "resource" and ref.id == "cache" for ref in resp.sourceReferences)


# --------------------------------------------------------------------------------------
# (e) Low-confidence / ambiguous -> support path, no assertion (also single-finding backstop).
# --------------------------------------------------------------------------------------
def test_single_leaf_symptom_no_blast_is_low_confidence_support() -> None:
    graph = WorkloadGraph(
        nodes=[_node("odb"), _node("web1")],
        edges=[_edge("web1", "odb")],  # web1 is a leaf; nothing depends on it -> radius 0
    )
    resp = correlate_root_cause([_finding("web1")], graph)

    assert resp.confidence < RCA_CONFIDENCE_FLOOR
    assert resp.nextActions == ["recommend-contact-support"]
    assert "propose-remediation" not in resp.nextActions
    # Fail-closed: no confident root-cause resource asserted.
    assert not any(ref.kind == "resource" for ref in resp.sourceReferences)


def test_missing_graph_multi_symptom_fails_closed_to_support() -> None:
    resp = correlate_root_cause([_finding("web1"), _finding("web2")], graph=None)

    assert resp.confidence < RCA_CONFIDENCE_FLOOR
    assert resp.nextActions == ["recommend-contact-support"]
    # Symptoms are still summarized and their evidence cited (provenance preserved).
    assert len(resp.findings) == 2
    assert "latency_ms" in _cited_node_ids(resp)


def test_ambiguous_independent_upstreams_are_not_asserted() -> None:
    # A single symptom that non-redundantly depends on two unrelated upstreams: both fully explain
    # it, but they are mutually independent -> ambiguous -> surface, do not assert.
    graph = WorkloadGraph(
        nodes=[_node("svc"), _node("up1"), _node("up2")],
        edges=[_edge("svc", "up1"), _edge("svc", "up2")],
    )
    findings = [_finding("svc"), _finding("up1"), _finding("up2")]

    resp = correlate_root_cause(findings, graph)

    # up1 and up2 each cover svc but not each other -> best coverage < 1 -> below the floor.
    assert resp.confidence < RCA_CONFIDENCE_FLOOR
    assert resp.nextActions == ["recommend-contact-support"]


def test_agent_response_shape_and_provenance_present() -> None:
    graph = WorkloadGraph(
        nodes=[_node("odb"), _node("web1")],
        edges=[_edge("web1", "odb")],
    )
    resp = correlate_root_cause([_finding("odb"), _finding("web1")], graph)

    assert isinstance(resp, AgentResponse)
    assert resp.agentName == "aiops"
    assert resp.taskType == "auto-rca"
    assert 0.0 <= resp.confidence <= 1.0
    assert resp.findings  # symptoms summarized
    assert resp.sourceReferences  # provenance never empty for a real correlation
    assert resp.nextActions  # always advises a next step (advisory only)


# ======================================================================================
# Regression tests for the 5 reviewed defects (2 HIGH, 3 MED).
# ======================================================================================


# HIGH 1 — degraded (redundant) impact must NOT count as full causal coverage.
def test_degraded_redundant_impact_is_not_causal_coverage() -> None:
    # api depends on cache via a REDUNDANT edge, so cache failing only DEGRADES api (never down).
    graph = WorkloadGraph(
        nodes=[_node("api"), _node("cache")],
        edges=[_edge("api", "cache", redundant=True)],
    )
    findings = [_finding("api"), _finding("cache")]

    resp = correlate_root_cause(findings, graph)

    # cache cannot causally explain api (degraded ≠ down) -> partial coverage -> fail closed.
    assert resp.confidence < RCA_CONFIDENCE_FLOOR
    assert resp.nextActions == ["recommend-contact-support"]
    assert "propose-remediation" not in resp.nextActions
    # No confident root cause asserted (esp. not the redundant cache).
    assert not any(ref.kind == "resource" for ref in resp.sourceReferences)
    assert not any("probable root cause" in rec for rec in resp.recommendations)


# HIGH 2a — an unlocalized finding must fail closed, never be dropped from the denominator.
def test_unlocalized_finding_fails_closed() -> None:
    graph = WorkloadGraph(
        nodes=[_node("odb"), _node("web1")],
        edges=[_edge("web1", "odb")],
    )
    findings = [_finding("odb"), _unlocalized_finding()]

    resp = correlate_root_cause(findings, graph)

    assert resp.confidence < RCA_CONFIDENCE_FLOOR
    assert resp.nextActions == ["recommend-contact-support"]
    assert not any(ref.kind == "resource" for ref in resp.sourceReferences)
    # The unlocalized finding is still surfaced (not silently excluded).
    assert len(resp.findings) == 2


# HIGH 2b — symptom nodes absent from a (possibly empty) graph must fail closed.
def test_offgraph_symptom_nodes_fail_closed() -> None:
    resp = correlate_root_cause(
        [_finding("ghost"), _finding("ghost2")], WorkloadGraph(nodes=[], edges=[])
    )
    assert resp.confidence < RCA_CONFIDENCE_FLOOR
    assert resp.nextActions == ["recommend-contact-support"]
    # Off-graph candidate must never be asserted as a root cause.
    assert not any(ref.kind == "resource" for ref in resp.sourceReferences)
    assert not any("ghost" in rec for rec in resp.recommendations)


def test_offgraph_symptom_with_partial_graph_fails_closed() -> None:
    # web1 exists in the graph, but web2 (also symptomatic) does not.
    graph = WorkloadGraph(nodes=[_node("odb"), _node("web1")], edges=[_edge("web1", "odb")])
    resp = correlate_root_cause([_finding("web1"), _finding("web2")], graph)
    assert resp.confidence < RCA_CONFIDENCE_FLOOR
    assert resp.nextActions == ["recommend-contact-support"]


# MED 3 — duplicate input must never raise confidence or flip the branch.
def test_duplicate_finding_cannot_raise_confidence() -> None:
    graph = WorkloadGraph(
        nodes=[_node("odb"), _node("web1")],
        edges=[_edge("web1", "odb")],  # web1 is an isolated leaf (radius 0)
    )
    single = correlate_root_cause([_finding("web1")], graph)
    duplicated = correlate_root_cause([_finding("web1"), _finding("web1")], graph)

    # The duplicate is normalized away: identical low-confidence support outcome.
    assert single.confidence == duplicated.confidence
    assert single.confidence < RCA_CONFIDENCE_FLOOR
    assert duplicated.confidence < RCA_CONFIDENCE_FLOOR
    assert duplicated.nextActions == ["recommend-contact-support"]
    assert "propose-remediation" not in duplicated.nextActions


# MED 4 — a dependency cycle must fail closed, not assert an arbitrary tied candidate.
def test_dependency_cycle_fails_closed() -> None:
    graph = WorkloadGraph(
        nodes=[_node("a"), _node("b")],
        edges=[_edge("a", "b"), _edge("b", "a")],  # a <-> b cycle
    )
    resp = correlate_root_cause([_finding("a"), _finding("b")], graph)

    # Every tied candidate is downed by another -> indistinguishable -> fail closed.
    assert resp.confidence < RCA_CONFIDENCE_FLOOR
    assert resp.nextActions == ["recommend-contact-support"]
    assert not any(ref.kind == "resource" for ref in resp.sourceReferences)


# MED 5 — a confident single-finding RCA must carry root-cause resource provenance.
def test_single_finding_confident_has_resource_provenance() -> None:
    # Direct single-node API: a positive blast radius yields a confident assertion.
    resp = correlate_rca(_finding("odb"), {"odb": 3})
    assert resp.confidence >= RCA_CONFIDENCE_FLOOR
    assert resp.nextActions == ["propose-remediation"]
    assert any(ref.kind == "resource" and ref.id == "odb" for ref in resp.sourceReferences)
    # The metric evidence is still present alongside the asserted node.
    assert any(ref.kind == "metric" for ref in resp.sourceReferences)


def test_single_finding_confident_provenance_via_correlate_root_cause() -> None:
    # A confident single symptom routed through the graph-wide entrypoint also cites the node.
    graph = WorkloadGraph(
        nodes=[_node("odb"), _node("web1")],
        edges=[_edge("web1", "odb")],  # odb has a dependent -> positive blast radius
    )
    resp = correlate_root_cause([_finding("odb")], graph)
    assert resp.confidence >= RCA_CONFIDENCE_FLOOR
    assert resp.nextActions == ["propose-remediation"]
    assert any(ref.kind == "resource" and ref.id == "odb" for ref in resp.sourceReferences)


# HIGH (round 3) — a dangling edge endpoint must never be asserted as an UNKNOWN root cause.
def test_dangling_edge_endpoint_fails_closed() -> None:
    # `ghost` is an edge target but is NOT a declared node -> graph integrity violated.
    graph = WorkloadGraph(
        nodes=[_node("api"), _node("web")],
        edges=[_edge("web", "api"), _edge("api", "ghost")],
    )
    resp = correlate_root_cause([_finding("api"), _finding("web")], graph)

    assert resp.confidence < RCA_CONFIDENCE_FLOOR
    assert resp.nextActions == ["recommend-contact-support"]
    assert "propose-remediation" not in resp.nextActions
    # The dangling id must never be admitted as a candidate / asserted / cited.
    assert not any(ref.kind == "resource" for ref in resp.sourceReferences)
    assert "ghost" not in _cited_node_ids(resp)
    assert all("ghost" not in rec for rec in resp.recommendations)


# MED (round 3) — distinct-metric findings on one node must retain ALL titles + evidence.
def test_single_node_multiple_metrics_retain_all_symptoms_and_evidence() -> None:
    graph = WorkloadGraph(
        nodes=[_node("odb"), _node("web1")],
        edges=[_edge("web1", "odb")],  # odb has a dependent -> confident single-node RCA
    )
    cpu = _finding("odb", metric="cpu_pct")
    latency = _finding("odb", metric="latency_ms")

    resp = correlate_root_cause([cpu, latency], graph)

    # Both distinct symptoms are preserved (neither title dropped).
    assert cpu.title in resp.findings
    assert latency.title in resp.findings
    # Both metric references are retained, alongside the asserted root-cause resource ref.
    cited = {(ref.kind, ref.id) for ref in resp.sourceReferences}
    assert ("metric", "cpu_pct") in cited
    assert ("metric", "latency_ms") in cited
    assert resp.confidence >= RCA_CONFIDENCE_FLOOR
    assert any(ref.kind == "resource" and ref.id == "odb" for ref in resp.sourceReferences)
    assert resp.nextActions == ["propose-remediation"]
