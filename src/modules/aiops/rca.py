"""Auto-RCA correlation over the typed dependency graph (issue #50).

Pure logic — no I/O, no Azure. Given a set of active detections (``Finding``s, each pinned to a
symptom ``nodeId`` with cited ``evidence``) and the ``WorkloadGraph``, correlate to the most likely
*root-cause* entity and emit a provenance-bearing :class:`AgentResponse`.

Design (guardrails: advisory only, provenance on every conclusion, fail-closed):

* Reuse the canonical blast-radius math in :mod:`shared.blast_radius` — never reimplement it.
* Candidate root causes are the symptom nodes *plus* their upstream dependency ancestors, so a
  purely downstream symptom is **explained by**, not ranked as, its upstream cause.
* Each candidate is scored by *explanatory power* — the fraction of observed symptoms its
  hypothetical failure (``compute_impact``) would take ``down`` (redundant/``degraded`` impact does
  NOT count as causal coverage) — combined with graph position (blast radius / upstream-ness). The
  most upstream node that explains the symptom set wins.
* Confidence is gated by ``RCA_CONFIDENCE_FLOOR``: a single dominant candidate covering every
  symptom is confident; partial explanations or multiple independent symptom clusters fall below
  the floor and we **surface + advise contacting support**, never asserting a root cause and never
  proposing (auto-)remediation.

The single-finding case delegates to :func:`correlate_rca`, preserving the original localization
semantics so existing behavior is subsumed, not duplicated.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field

from shared.blast_radius import blast_radius, compute_impact
from shared.contracts import (
    AgentResponse,
    Finding,
    HealthState,
    SourceReference,
    WorkloadGraph,
)

# Confidence below which we do not assert an RCA — we advise contacting support instead.
RCA_CONFIDENCE_FLOOR = 0.6


def correlate_rca(finding: Finding, blast_radius_of: dict[str, int]) -> AgentResponse:
    """Localize likely root cause for a single finding using blast radius; gate by confidence.

    Preserved single-node semantics (issue subsumes, does not fork): confidence 0.8 when the
    symptom node has a positive blast radius (it is a single point of failure), else 0.4 — below
    the floor, so we advise contacting support rather than asserting.
    """
    node = finding.nodeId or "unknown"
    radius = blast_radius_of.get(node, 0)
    return _single_node_response(
        node=node,
        titles=[finding.title],
        evidence=list(finding.evidence),
        radius=radius,
        input_summary=f"finding={finding.id}",
    )


def _single_node_response(
    *,
    node: str,
    titles: list[str],
    evidence: list[SourceReference],
    radius: int,
    input_summary: str,
) -> AgentResponse:
    """Build a single-node RCA response, aggregating ALL symptom titles + evidence for that node.

    Legacy confidence calc (0.8 with a positive blast radius, else 0.4). When confident we append
    the asserted root-cause ``resource`` reference; below the floor we surface + advise support.
    """
    confidence = 0.8 if radius > 0 else 0.4
    if confidence >= RCA_CONFIDENCE_FLOOR:
        refs = _dedup_refs(
            [*evidence, SourceReference(kind="resource", id=node,
                                        detail=f"identified root cause: blast radius {radius}")]
        )
        return AgentResponse(
            agentName="aiops",
            taskType="auto-rca",
            inputSummary=input_summary,
            findings=titles,
            risks=[f"blast radius {radius}"] if radius else [],
            recommendations=[f"Investigate {node} (blast radius {radius}) as probable root cause."],
            sourceReferences=refs,
            confidence=confidence,
            nextActions=["propose-remediation"],
        )
    return AgentResponse(
        agentName="aiops",
        taskType="auto-rca",
        inputSummary=input_summary,
        findings=titles,
        risks=[],
        recommendations=["Root cause not confidently localized."],
        sourceReferences=evidence,
        confidence=confidence,
        nextActions=["recommend-contact-support"],
    )



@dataclass(frozen=True)
class _Candidate:
    """A hypothesized root-cause node and how well its failure explains the symptom set."""

    node_id: str
    coverage: float          # fraction of symptom nodes its failure would take DOWN (not degraded)
    radius: int              # blast radius (count of DOWN nodes) — graph position / upstream-ness
    explained: frozenset[str]
    impact: dict[str, HealthState]
    is_symptom: bool


@dataclass
class _Correlation:
    """Result of scoring: the ranked candidates and the derived confidence + cluster count."""

    ranked: list[_Candidate]
    confidence: float
    clusters: int
    maximal: list[_Candidate] = field(default_factory=list)


def _depends_on_index(graph: WorkloadGraph) -> dict[str, list[str]]:
    """Map a node -> the nodes it directly depends on (its upstream targets)."""
    idx: dict[str, list[str]] = defaultdict(list)
    for e in graph.edges:
        idx[e.source].append(e.target)
    return idx


def _candidate_nodes(graph: WorkloadGraph, symptom_nodes: list[str]) -> list[str]:
    """Symptom nodes plus their transitive upstream dependency ancestors (dedup, stable order)."""
    depends_on = _depends_on_index(graph)
    seen: dict[str, None] = {}
    queue: deque[str] = deque(symptom_nodes)
    for s in symptom_nodes:
        seen.setdefault(s, None)
    while queue:
        node = queue.popleft()
        for upstream in depends_on.get(node, []):
            if upstream not in seen:
                seen[upstream] = None
                queue.append(upstream)
    return list(seen)


def _score_candidates(graph: WorkloadGraph, symptom_nodes: list[str]) -> list[_Candidate]:
    """Score every candidate by explanatory coverage of the symptom set + graph position."""
    symptom_set = set(symptom_nodes)
    total = len(symptom_nodes)
    scored: list[_Candidate] = []
    for cid in _candidate_nodes(graph, symptom_nodes):
        impact = compute_impact(graph, cid)
        explained = {
            s for s in symptom_nodes
            if s == cid or impact.get(s) == HealthState.down
        }
        scored.append(
            _Candidate(
                node_id=cid,
                coverage=len(explained) / total if total else 0.0,
                radius=blast_radius(graph, cid),
                explained=frozenset(explained),
                impact=impact,
                is_symptom=cid in symptom_set,
            )
        )
    # Rank by explanatory power, then upstream-ness (blast radius), then prefer a symptomatic node.
    scored.sort(key=lambda c: (c.coverage, c.radius, c.is_symptom, c.node_id), reverse=True)
    return scored


def _count_clusters(symptom_nodes: list[str], scored: list[_Candidate]) -> int:
    """Independent symptom clusters: symptoms co-explained by a common candidate are one cluster."""
    parent: dict[str, str] = {s: s for s in symptom_nodes}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        parent[find(a)] = find(b)

    for cand in scored:
        members = list(cand.explained)
        for other in members[1:]:
            union(members[0], other)
    return len({find(s) for s in symptom_nodes})


def _maximal_candidates(top: list[_Candidate]) -> list[_Candidate]:
    """Reduce equal-coverage candidates to the upstream-most: drop those downed by another."""
    maximal: list[_Candidate] = []
    for cand in top:
        downed_by_other = any(
            other.node_id != cand.node_id
            and other.impact.get(cand.node_id) == HealthState.down
            for other in top
        )
        if not downed_by_other:
            maximal.append(cand)
    return maximal


def _correlate(graph: WorkloadGraph, symptom_nodes: list[str]) -> _Correlation:
    """Score candidates and derive a confidence in [0,1] with fail-closed gating."""
    scored = _score_candidates(graph, symptom_nodes)
    if not scored:
        return _Correlation(ranked=[], confidence=0.0, clusters=len(symptom_nodes))

    best_cov = scored[0].coverage
    clusters = _count_clusters(symptom_nodes, scored)
    top = [c for c in scored if c.coverage == best_cov]
    maximal = _maximal_candidates(top)
    # Exactly one upstream-most candidate ⇒ unambiguous. Zero (e.g. a dependency cycle where every
    # tied candidate is downed by another) or many ⇒ indistinguishable ⇒ fail closed to support.
    ambiguous = len(maximal) != 1

    if best_cov >= 1.0 and not ambiguous:
        # One candidate explains every symptom: confident, scaled by its upstream reach.
        radius_factor = min(1.0, scored[0].radius / len(symptom_nodes)) if symptom_nodes else 0.0
        confidence = min(0.95, 0.7 + 0.25 * radius_factor)
    elif best_cov >= 1.0 and ambiguous:
        # Multiple independent full explanations — genuinely ambiguous, surface below the floor.
        confidence = 0.5
    else:
        # Partial explanation and/or multiple independent clusters — fail closed below the floor.
        confidence = min(0.55, best_cov * 0.6)

    return _Correlation(ranked=scored, confidence=confidence, clusters=clusters, maximal=maximal)


def _dedup_refs(refs: list[SourceReference]) -> list[SourceReference]:
    seen: set[tuple[str, str, str | None]] = set()
    out: list[SourceReference] = []
    for r in refs:
        key = (r.kind, r.id, r.detail)
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def _dedup_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse duplicate detections by node + metric identity (order-preserving).

    Duplicates must never inflate the coverage denominator or flip the single-vs-multi branch, so
    we normalize before any counting or confidence derivation.
    """
    seen: set[tuple[str | None, tuple[tuple[str, str, str], ...]]] = set()
    out: list[Finding] = []
    for f in findings:
        evidence_key = tuple(sorted((e.kind, e.id, e.detail or "") for e in f.evidence))
        key = (f.nodeId, evidence_key)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def correlate_root_cause(
    findings: list[Finding], graph: WorkloadGraph | None
) -> AgentResponse:
    """Correlate multiple active detections over the dependency graph to a likely root cause.

    Fail-closed and advisory only: below :data:`RCA_CONFIDENCE_FLOOR` (partial explanation,
    ambiguity, missing/incomplete graph, or multiple independent clusters) we surface the symptoms
    and advise contacting support — we never assert a root cause and never propose remediation.
    """
    findings = _dedup_findings(findings)

    symptom_evidence = _dedup_refs([ref for f in findings for ref in f.evidence])
    symptom_titles = [f.title for f in findings]

    symptom_nodes: list[str] = []
    for f in findings:
        if f.nodeId is not None and f.nodeId not in symptom_nodes:
            symptom_nodes.append(f.nodeId)
    input_summary = f"symptoms={len(findings)}; nodes={symptom_nodes or 'none'}"

    # Fail-closed gate: correlate only when EVERY finding is localized to a node, every symptom
    # node exists in a non-empty graph, AND the graph is internally intact — every edge endpoint
    # (source and target) is a declared node. A dangling edge endpoint (an id used by an edge but
    # absent from ``graph.nodes``) makes ``compute_impact`` untrustworthy and could otherwise be
    # admitted as an UNKNOWN upstream candidate, so we reject such a graph outright.
    graph_node_ids = {n.id for n in graph.nodes} if graph is not None else set()
    all_localized = bool(findings) and all(f.nodeId for f in findings)
    nodes_present = bool(graph_node_ids) and all(s in graph_node_ids for s in symptom_nodes)
    graph_intact = graph is not None and all(
        e.source in graph_node_ids and e.target in graph_node_ids for e in graph.edges
    )
    if (
        not all_localized
        or graph is None
        or not symptom_nodes
        or not nodes_present
        or not graph_intact
    ):
        return AgentResponse(
            agentName="aiops",
            taskType="auto-rca",
            inputSummary=input_summary,
            findings=symptom_titles,
            risks=[],
            recommendations=[
                "Root cause could not be correlated: unlocalized finding(s), symptom node(s) "
                "absent from the graph, or dangling graph edge endpoint(s) (fail-closed)."
            ],
            sourceReferences=symptom_evidence,
            confidence=0.0,
            nextActions=["recommend-contact-support"],
        )

    # Single unique symptom node: preserve the original single-node localization semantics, but
    # aggregate ALL deduplicated titles + evidence for that node (distinct metrics on one resource
    # must not be dropped).
    if len(symptom_nodes) == 1:
        node = symptom_nodes[0]
        return _single_node_response(
            node=node,
            titles=symptom_titles,
            evidence=symptom_evidence,
            radius=blast_radius(graph, node),
            input_summary=input_summary,
        )

    result = _correlate(graph, symptom_nodes)
    best = result.ranked[0]
    covered = len(best.explained)
    n = len(symptom_nodes)

    if result.confidence >= RCA_CONFIDENCE_FLOOR:
        root_ref = SourceReference(
            kind="resource",
            id=best.node_id,
            detail=f"identified root cause: explains {covered}/{n} symptoms, blast radius "
            f"{best.radius}",
        )
        return AgentResponse(
            agentName="aiops",
            taskType="auto-rca",
            inputSummary=input_summary,
            findings=symptom_titles,
            risks=[
                f"blast radius {best.radius}",
                f"{covered}/{n} correlated symptom(s) explained by {best.node_id}",
            ],
            recommendations=[
                f"Investigate {best.node_id} (explains {covered}/{n} symptoms, blast radius "
                f"{best.radius}) as the probable root cause."
            ],
            sourceReferences=_dedup_refs([*symptom_evidence, root_ref]),
            confidence=result.confidence,
            nextActions=["propose-remediation"],
        )

    # Below the floor — surface, do not assert a root cause; advise support (never remediate).
    recommendations = [
        f"Root cause could not be confidently localized across {n} correlated symptom(s)."
    ]
    if result.clusters > 1:
        cluster_reps = [c.node_id for c in result.maximal] or symptom_nodes
        recommendations.append(
            f"{result.clusters} independent symptom clusters detected — likely distinct root "
            f"causes (candidates: {cluster_reps}); do not force-fit to one."
        )
    return AgentResponse(
        agentName="aiops",
        taskType="auto-rca",
        inputSummary=input_summary,
        findings=symptom_titles,
        risks=[f"{result.clusters} independent symptom cluster(s)"] if result.clusters > 1 else [],
        recommendations=recommendations,
        sourceReferences=symptom_evidence,
        confidence=result.confidence,
        nextActions=["recommend-contact-support"],
    )





__all__ = [
    "RCA_CONFIDENCE_FLOOR",
    "correlate_rca",
    "correlate_root_cause",
]
