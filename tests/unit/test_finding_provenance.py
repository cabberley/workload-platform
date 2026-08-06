"""Fail-closed coverage for the Finding pack/structural provenance invariant (issue #83).

Guardrail #8 (Provenance) says *every finding cites its evidence (resource id, metric, pack +
version)*. Issue #59 enforced the *evidence* half (a finding must cite ≥1 attributable
``SourceReference``). Issue #83 enforces the *attribution-kind* half as a construction-time
invariant on :class:`~shared.contracts.Finding`:

* a **pack-derived** finding (``provenance=pack``, the default) MUST carry a non-blank ``packId``
  **and** ``packVersion``;
* a **structural/derived** finding (``provenance=structural``) MUST name an allowlisted
  :class:`~shared.contracts.StructuralFindingKind` and MUST NOT carry pack id/version;
* anything else (no pack provenance and not explicitly structural) is INVALID and raises — there is
  no silent default that hides missing provenance.

All fixtures are synthetic / clearly-fake (guardrail #2).
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from modules.dependency_graph.module import spof_findings
from shared.contracts import (
    STRUCTURAL_FINDING_EMITTERS,
    DependencyEdge,
    EdgeType,
    Finding,
    ProvenanceKind,
    ResourceNode,
    Severity,
    SourceReference,
    StructuralFindingKind,
    WorkloadGraph,
)


def _evidence() -> list[SourceReference]:
    return [SourceReference(kind="resource", id="/synthetic/node-1", detail="synthetic")]


# --------------------------------------------------------------------------------------
# (a) A pack-derived finding missing packId OR packVersion is REJECTED.
# --------------------------------------------------------------------------------------
def test_pack_finding_missing_pack_id_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Finding(
            id="q1", module="quality_checks", title="rule", passed=False,
            provenance=ProvenanceKind.pack, packVersion="1.0.0", evidence=_evidence(),
        )


def test_pack_finding_missing_pack_version_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Finding(
            id="q1", module="quality_checks", title="rule", passed=False,
            provenance=ProvenanceKind.pack, packId="waf-baseline", evidence=_evidence(),
        )


@pytest.mark.parametrize("blank", ["", "   ", "\t"])
def test_pack_finding_blank_pack_provenance_is_rejected(blank: str) -> None:
    # A present-but-blank packId/packVersion is not real provenance — fail closed.
    with pytest.raises(ValidationError):
        Finding(
            id="q1", module="quality_checks", title="rule", passed=False,
            packId=blank, packVersion=blank, evidence=_evidence(),
        )


# --------------------------------------------------------------------------------------
# (b) An unmarked finding with NO pack provenance is REJECTED (default is pack, needs id+version).
# --------------------------------------------------------------------------------------
def test_unmarked_finding_without_pack_provenance_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Finding(id="q1", module="quality_checks", title="rule", passed=False, evidence=_evidence())


def test_pack_finding_with_id_and_version_is_accepted() -> None:
    finding = Finding(
        id="q1", module="quality_checks", title="rule", passed=False,
        packId="waf-baseline", packVersion="1.2.0", evidence=_evidence(),
    )
    assert finding.provenance is ProvenanceKind.pack
    assert finding.structuralKind is None


# --------------------------------------------------------------------------------------
# (c) Each structural finding kind is explicitly marked and ACCEPTED.
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize("kind", list(StructuralFindingKind))
def test_structural_finding_kinds_are_accepted(kind: StructuralFindingKind) -> None:
    finding = Finding(
        id=f"{kind.value}::/synthetic/node-1", module=STRUCTURAL_FINDING_EMITTERS[kind],
        title="structural", passed=False, provenance=ProvenanceKind.structural,
        structuralKind=kind, evidence=_evidence(),
    )
    assert finding.provenance is ProvenanceKind.structural
    assert finding.structuralKind is kind
    assert finding.packId is None and finding.packVersion is None


def test_structural_finding_without_kind_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Finding(
            id="s1", module="dependency_graph", title="structural", passed=False,
            provenance=ProvenanceKind.structural, evidence=_evidence(),
        )


def test_structural_finding_carrying_pack_id_is_rejected() -> None:
    # A structural finding must not masquerade as pack-derived — keep provenance honest.
    with pytest.raises(ValidationError):
        Finding(
            id="s1", module="dependency_graph", title="structural", passed=False,
            provenance=ProvenanceKind.structural, structuralKind=StructuralFindingKind.spof,
            packId="waf-baseline", packVersion="1.2.0", evidence=_evidence(),
        )


@pytest.mark.parametrize("blank", ["", "   ", "\t"])
def test_structural_finding_with_blank_pack_id_is_rejected(blank: str) -> None:
    # FIX A: a structural finding must have NO pack identity AT ALL — a present-but-blank packId
    # (whitespace) is still pack identity and must be rejected (both must be exactly None).
    with pytest.raises(ValidationError):
        Finding(
            id="s1", module="dependency_graph", title="structural", passed=False,
            provenance=ProvenanceKind.structural, structuralKind=StructuralFindingKind.spof,
            packId=blank, evidence=_evidence(),
        )


@pytest.mark.parametrize("blank", ["", "   ", "\t"])
def test_structural_finding_with_blank_pack_version_is_rejected(blank: str) -> None:
    # FIX A: same for a present-but-blank packVersion on a structural finding.
    with pytest.raises(ValidationError):
        Finding(
            id="s1", module="dependency_graph", title="structural", passed=False,
            provenance=ProvenanceKind.structural, structuralKind=StructuralFindingKind.spof,
            packVersion=blank, evidence=_evidence(),
        )


def test_pack_finding_declaring_structural_kind_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Finding(
            id="q1", module="quality_checks", title="rule", passed=False,
            packId="waf-baseline", packVersion="1.2.0",
            structuralKind=StructuralFindingKind.spof, evidence=_evidence(),
        )


# --------------------------------------------------------------------------------------
# FIX C (issue #83, guardrail #8): structural provenance is bound to its authorized emitter module.
# --------------------------------------------------------------------------------------
def test_structural_spof_from_authorized_module_is_accepted() -> None:
    finding = Finding(
        id="spof::/synthetic/be", module="dependency_graph", title="structural", passed=False,
        provenance=ProvenanceKind.structural, structuralKind=StructuralFindingKind.spof,
        evidence=_evidence(),
    )
    assert finding.module == "dependency_graph"
    assert finding.structuralKind is StructuralFindingKind.spof


@pytest.mark.parametrize("module", ["quality_checks", "aiops", "discovery", "not-a-module"])
def test_structural_spof_from_unauthorized_module_is_rejected(module: str) -> None:
    # A caller cannot mint a packless "critical" spof finding under a module that is not the
    # authorized emitter (dependency_graph) to bypass the pack-citation requirement (guardrail #8).
    with pytest.raises(ValidationError):
        Finding(
            id="spof::/synthetic/be", module=module, title="structural", passed=False,
            provenance=ProvenanceKind.structural, structuralKind=StructuralFindingKind.spof,
            evidence=_evidence(),
        )


def test_every_structural_kind_has_a_mapped_emitter() -> None:
    # Exhaustiveness: the fail-closed-on-unmapped-kind path is real, not vacuous — every enumerated
    # StructuralFindingKind must have an authorized emitter, so adding a kind without a mapping
    # would be caught here (and would fail closed at validation).
    missing = [k for k in StructuralFindingKind if k not in STRUCTURAL_FINDING_EMITTERS]
    assert not missing, f"StructuralFindingKind(s) with no authorized emitter mapping: {missing}"
    assert all(emitter for emitter in STRUCTURAL_FINDING_EMITTERS.values()), (
        "every authorized emitter module must be a non-empty module name"
    )


# --------------------------------------------------------------------------------------
# (d) The dependency_graph structural findings still validate + are marked structural.
# --------------------------------------------------------------------------------------
def _spof_graph() -> WorkloadGraph:
    # Two front-ends non-redundantly depend on one shared backend → the backend is a SPOF.
    nodes = [
        ResourceNode(id="be", name="backend", type="db"),
        ResourceNode(id="fe1", name="frontend-1", type="app"),
        ResourceNode(id="fe2", name="frontend-2", type="app"),
    ]
    edges = [
        DependencyEdge(source="fe1", target="be", type=EdgeType.depends_on, redundant=False),
        DependencyEdge(source="fe2", target="be", type=EdgeType.depends_on, redundant=False),
    ]
    return WorkloadGraph(nodes=nodes, edges=edges)


def test_dependency_graph_spof_findings_are_structural_and_valid() -> None:
    findings = spof_findings(_spof_graph())
    assert findings, "expected the shared backend to surface as a single point of failure"
    for finding in findings:
        assert finding.provenance is ProvenanceKind.structural
        assert finding.structuralKind is StructuralFindingKind.spof
        assert finding.packId is None and finding.packVersion is None
        assert finding.evidence, "structural findings must still cite evidence (issue #59)"
    backend = next(f for f in findings if f.nodeId == "be")
    assert backend.blastRadius >= 2
    assert backend.severity in {Severity.high, Severity.critical}


# --------------------------------------------------------------------------------------
# FIX B (1): post-construction mutation into an invalid provenance state must raise
# (validate_assignment=True re-runs the invariant on every attribute assignment).
# --------------------------------------------------------------------------------------
def _pack_finding() -> Finding:
    return Finding(
        id="q1", module="quality_checks", title="rule", passed=False,
        packId="waf-baseline", packVersion="1.2.0", evidence=_evidence(),
    )


def test_assigning_pack_id_none_on_pack_finding_raises() -> None:
    finding = _pack_finding()
    with pytest.raises(ValidationError):
        finding.packId = None


def test_assigning_pack_version_blank_on_pack_finding_raises() -> None:
    finding = _pack_finding()
    with pytest.raises(ValidationError):
        finding.packVersion = "   "


def test_flipping_provenance_to_structural_without_kind_raises() -> None:
    finding = _pack_finding()
    with pytest.raises(ValidationError):
        finding.provenance = ProvenanceKind.structural


def test_valid_reassignment_still_allowed() -> None:
    # Sanity: a mutation that keeps provenance valid must NOT raise (e.g. bumping the version).
    finding = _pack_finding()
    finding.packVersion = "1.3.0"
    assert finding.packVersion == "1.3.0"


# --------------------------------------------------------------------------------------
# FIX B (2): a finding whose provenance was corrupted (bypassing validation) is rejected at the
# persistence boundary by revalidate_finding_provenance (defense in depth).
# --------------------------------------------------------------------------------------
def test_persistence_revalidation_rejects_corrupted_pack_finding() -> None:
    from shared.provenance import revalidate_finding_provenance

    # model_construct bypasses validation, simulating a finding that reached persistence in an
    # invalid provenance state (pack-derived but with no packId/packVersion).
    corrupted = Finding.model_construct(
        id="q1", module="quality_checks", title="rule", passed=False,
        provenance=ProvenanceKind.pack, packId=None, packVersion=None, evidence=_evidence(),
    )
    with pytest.raises(ValidationError):
        revalidate_finding_provenance([corrupted])


def test_persistence_revalidation_accepts_valid_findings() -> None:
    from shared.provenance import revalidate_finding_provenance

    # A well-formed pack finding and a well-formed structural finding both pass the boundary check.
    revalidate_finding_provenance([_pack_finding(), *spof_findings(_spof_graph())])

