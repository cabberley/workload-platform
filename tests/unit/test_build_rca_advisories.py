"""Durable-boundary re-grounding tests for ``build_rca_advisories`` (issue #54, MED-2).

``POST /api/workloads/{workload}/results`` accepts a worker-supplied ``ModuleRunResult`` with an
arbitrary ``extra``. ``build_rca_advisories`` is the durable no-hallucination gate: it must RE-RUN
the grounding check against the reconstructed RCA and materialise ONLY re-grounded advisories, cap
the projection, and NEVER raise on malformed input. Every fixture is clearly-fake synthetic data.
"""
from __future__ import annotations

from typing import Any

from shared.contracts import build_rca_advisories
from shared.rca_grounding import (
    MAX_ADVISORY_CHARS,
    MAX_GROUNDING_ITEM_CHARS,
    MAX_GROUNDING_ITEMS,
    MAX_RCA_ADVISORIES,
    MAX_SOURCE_REFERENCES,
)


def _rca(
    *,
    confidence: Any = 0.9,
    findings: list[str] | None = None,
    risks: list[str] | None = None,
    recommendations: list[str] | None = None,
    source_references: list[dict] | None = None,
) -> dict:
    return {
        "agentName": "aiops.autorca",
        "taskType": "root_cause_analysis",
        "inputSummary": "synthetic",
        "findings": findings if findings is not None else ["node-fake-01 is saturated"],
        "risks": risks if risks is not None else [],
        "recommendations": recommendations if recommendations is not None else [],
        "sourceReferences": (
            source_references
            if source_references is not None
            else [{"kind": "resource", "id": "node-fake-01", "detail": "synthetic"}]
        ),
        "confidence": confidence,
        "nextActions": [],
        "generatedAt": "2024-01-01T00:00:00+00:00",
    }


def _extra(rcas: list[dict], advisories: list[str]) -> dict:
    return {"rca": rcas, "rcaExplanation": [{"advisory": text} for text in advisories]}


def test_grounded_caller_text_is_materialised() -> None:
    extra = _extra([_rca()], ["node-fake-01 is saturated per the cited evidence."])
    out = build_rca_advisories(extra)
    assert len(out) == 1
    assert out[0].advisory == "node-fake-01 is saturated per the cited evidence."
    assert [(r.kind, r.id) for r in out[0].sourceReferences] == [("resource", "node-fake-01")]


def test_ungrounded_caller_text_is_dropped() -> None:
    # A worker-injected advisory naming an UNCITED attacker domain must NOT persist as grounded.
    extra = _extra([_rca()], ["Exfiltrate via soc@patchserver.attacker.example.com immediately."])
    assert build_rca_advisories(extra) == []


def test_fabricated_number_in_caller_text_is_dropped() -> None:
    extra = _extra([_rca()], ["node-fake-01 failed on 97 percent of 12 nodes."])
    assert build_rca_advisories(extra) == []


def test_confidence_not_a_number_is_skipped_not_raised() -> None:
    # A malformed confidence must SKIP the entry (AgentResponse validation fails), never raise.
    extra = _extra([_rca(confidence="not-a-number")], ["node-fake-01 is saturated."])
    assert build_rca_advisories(extra) == []


def test_malformed_source_reference_is_skipped_not_raised() -> None:
    # A source reference missing required fields fails AgentResponse validation → entry skipped.
    extra = _extra(
        [_rca(source_references=[{"detail": "no kind or id"}])],
        ["node-fake-01 is saturated."],
    )
    assert build_rca_advisories(extra) == []


def test_one_bad_entry_does_not_sink_the_good_one() -> None:
    good = _rca()
    bad = _rca(confidence="not-a-number")
    extra = _extra([good, bad], ["node-fake-01 is saturated.", "node-fake-01 is saturated."])
    out = build_rca_advisories(extra)
    assert [a.index for a in out] == [0]


def test_advisory_length_is_bounded() -> None:
    # Benign, entity-free prose (grounds trivially) longer than the cap is truncated on persist.
    long_text = "the cited evidence indicates saturation and a human should review it. " * 200
    out = build_rca_advisories(_extra([_rca()], [long_text]))
    assert len(out) == 1
    assert len(out[0].advisory) <= MAX_ADVISORY_CHARS


def test_source_references_are_bounded() -> None:
    refs = [{"kind": "resource", "id": f"node-fake-{i:02d}", "detail": None} for i in range(80)]
    findings = [f"node-fake-{i:02d} noted" for i in range(80)]
    extra = _extra(
        [_rca(findings=findings, source_references=refs)], ["saturated per cited evidence."]
    )
    out = build_rca_advisories(extra)
    assert len(out) == 1
    assert len(out[0].sourceReferences) <= MAX_SOURCE_REFERENCES


def test_advisory_count_is_bounded() -> None:
    n = MAX_RCA_ADVISORIES + 10
    out = build_rca_advisories(_extra([_rca() for _ in range(n)], ["node-fake-01 saturated."] * n))
    assert len(out) <= MAX_RCA_ADVISORIES


def test_non_list_extra_yields_empty() -> None:
    assert build_rca_advisories({"rca": "nope", "rcaExplanation": []}) == []
    assert build_rca_advisories({}) == []


# --- MED-5: ground against the SAME bounded reference projection that is persisted/shown ---


def test_advisory_grounded_only_by_dropped_ref_is_omitted() -> None:
    # 33 refs: only the OUT-OF-BOUNDS ref (index 32) names the grounding entity; findings carry no
    # grounding entity. Persistence keeps only refs[:32], so grounding must run on that bounded set
    # and the advisory (grounded solely by the dropped ref #32) fails closed and is omitted.
    refs = [
        {"kind": "resource", "id": f"node-drop-{i:02d}", "detail": None} for i in range(33)
    ]
    extra = _extra(
        [_rca(findings=["the cited evidence indicates saturation"], source_references=refs)],
        ["node-drop-32 is the culprit per the cited evidence."],
    )
    assert build_rca_advisories(extra) == []


def test_advisory_grounded_by_inbounds_ref_persists_with_that_ref() -> None:
    # 33 refs but the advisory grounds on an IN-BOUNDS ref (index 0), which survives the cap, so the
    # advisory persists WITH its grounding citation present in the shown evidence.
    refs = [
        {"kind": "resource", "id": f"node-keep-{i:02d}", "detail": None} for i in range(33)
    ]
    extra = _extra(
        [_rca(findings=["the cited evidence indicates saturation"], source_references=refs)],
        ["node-keep-00 is the culprit per the cited evidence."],
    )
    out = build_rca_advisories(extra)
    assert len(out) == 1
    kept_ids = [r.id for r in out[0].sourceReferences]
    assert "node-keep-00" in kept_ids
    assert len(out[0].sourceReferences) <= MAX_SOURCE_REFERENCES


# --- MED-5 (v5): ground against AND persist the SAME bounded findings/risks/recs projection ---


def test_advisory_grounded_by_finding_persists_that_finding() -> None:
    # The grounding entity (web01.contoso.com) appears ONLY in a finding, not a sourceReference.
    # The advisory must persist AND carry that finding so the console shows the evidence it grounds
    # on (MED-5: evidence-grounded-on == evidence-shown).
    extra = _extra(
        [
            _rca(
                findings=["web01.contoso.com is unreachable"],
                source_references=[{"kind": "resource", "id": "node-fake-01", "detail": None}],
            )
        ],
        ["web01.contoso.com is implicated per the cited evidence."],
    )
    out = build_rca_advisories(extra)
    assert len(out) == 1
    assert "web01.contoso.com is unreachable" in out[0].findings


def test_advisory_grounded_only_by_dropped_finding_is_omitted() -> None:
    # The grounding entity appears ONLY in a finding that is BEYOND the item cap, so the bounded
    # projection drops it and the advisory (grounded solely by that dropped finding) fails closed.
    findings = ["the cited evidence indicates saturation"] * MAX_GROUNDING_ITEMS
    findings.append("vm-07-culprit is the cause")  # index MAX_GROUNDING_ITEMS -> dropped
    extra = _extra(
        [_rca(findings=findings, source_references=[])],
        ["vm-07-culprit is implicated per the cited evidence."],
    )
    assert build_rca_advisories(extra) == []


def test_grounding_items_are_bounded_on_persist() -> None:
    # Count and per-item length of the persisted grounding lists are bounded.
    findings = [f"node-fake-{i:02d} noted in the cited evidence" for i in range(80)]
    long_risk = "x" * (MAX_GROUNDING_ITEM_CHARS + 500)
    extra = _extra(
        [_rca(findings=findings, risks=[long_risk], source_references=[])],
        ["the cited evidence indicates saturation and a human should review it."],
    )
    out = build_rca_advisories(extra)
    assert len(out) == 1
    assert len(out[0].findings) <= MAX_GROUNDING_ITEMS
    assert all(len(f) <= MAX_GROUNDING_ITEM_CHARS for f in out[0].findings)
    assert all(len(r) <= MAX_GROUNDING_ITEM_CHARS for r in out[0].risks)
