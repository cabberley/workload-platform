"""Pure advisory-remediation lookup tests (issue #52) — synthetic, Azure-free.

Covers the fail-closed gates required by the issue: a confident RCA (>= floor) + a matching Ops
pack ⇒ advisory steps citing pack id + version; RCA below the floor ⇒ "call support" with no steps;
RCA >= floor but no matching category ⇒ "call support"; the catch-all (`*`/`default`) match path;
and malformed/oversized remediation sections rejected fail-closed by the pure parser. All fixtures
are clearly-fake (guardrails: advisory only, provenance on every conclusion, fail-closed).
"""
from __future__ import annotations

from typing import Any

from modules.aiops.rca import RCA_CONFIDENCE_FLOOR
from modules.aiops.remediation import (
    CALL_SUPPORT_ACTION,
    MAX_STEPS_PER_CATEGORY,
    RemediationStep,
    RemediationTable,
    _is_valid_category_key,
    extract_root_cause_node_id,
    node_category,
    parse_remediation_table,
    propose_remediation,
)
from shared.contracts import AgentResponse, ResourceNode, SourceReference

_ROOT = "/subscriptions/00000000/rg/epic/odb-01"


def _rca(
    *, confidence: float, root_node: str | None = _ROOT
) -> AgentResponse:
    """A synthetic RCA response; when ``root_node`` is set it asserts that root-cause resource."""
    refs: list[SourceReference] = [
        SourceReference(kind="metric", id="odb_latency_ms", detail="breach"),
    ]
    if root_node is not None:
        refs.append(
            SourceReference(
                kind="resource", id=root_node, detail="identified root cause: blast radius 3"
            )
        )
    return AgentResponse(
        agentName="aiops",
        taskType="auto-rca",
        inputSummary="symptoms=1",
        findings=["Telemetry breach on odb"],
        recommendations=["Investigate odb as probable root cause."],
        sourceReferences=refs,
        confidence=confidence,
        nextActions=["propose-remediation"] if confidence >= RCA_CONFIDENCE_FLOOR else [
            "recommend-contact-support"
        ],
    )


def _table(
    steps_by_category: dict[str, list[RemediationStep]],
    *,
    pack_id: str = "synthetic-remediation-advisory",
    version: str = "1.0.0",
) -> RemediationTable:
    return RemediationTable(
        pack_id=pack_id,
        pack_version=version,
        steps_by_category={k: tuple(v) for k, v in steps_by_category.items()},
    )


# --------------------------------------------------------------------------------------
# node_category / extract_root_cause_node_id
# --------------------------------------------------------------------------------------
def test_node_category_uses_classified_role_not_raw_azure_type() -> None:
    # MED 1: a Discovery-shaped node keeps a raw Azure resource type but a classified role — the
    # category must come from the role so it matches authored 'odb' remediation.
    node = ResourceNode(
        id=_ROOT, name="odb-01", type="Microsoft.Compute/virtualMachines", role="ODB"
    )
    assert node_category(node) == "odb"


def test_node_category_none_when_no_role_available() -> None:
    # No classified role ⇒ None ⇒ "call support" (never a resource-type token that never matches).
    assert node_category(None) is None
    assert node_category(
        ResourceNode(id="x", name="x", type="Microsoft.Compute/virtualMachines")
    ) is None
    assert node_category(ResourceNode(id="x", name="x", type="epic/odb", role="   ")) is None


def test_extract_root_cause_node_id_returns_asserted_resource() -> None:
    assert extract_root_cause_node_id(_rca(confidence=0.9)) == _ROOT


def test_extract_root_cause_node_id_none_when_not_asserted() -> None:
    assert extract_root_cause_node_id(_rca(confidence=0.4, root_node=None)) is None


# --------------------------------------------------------------------------------------
# propose_remediation — the fail-closed gates
# --------------------------------------------------------------------------------------
def test_confident_rca_with_matching_pack_returns_advisory_steps_with_citations() -> None:
    rca = _rca(confidence=0.9)
    tables = [
        _table({"odb": [
            RemediationStep(description="Check odb failover.", runbook="https://aka.ms/odb",
                            escalate_severity="high"),
            RemediationStep(description="Review odb latency."),
        ]})
    ]
    out = propose_remediation(rca, root_cause_category="odb", tables=tables)

    assert out.nextActions == ["Check odb failover.", "Review odb latency."]
    assert out.taskType == "guided-remediation"
    # Every emitted remediation cites its source pack id + version (provenance).
    pack_cites = {(r.id, r.detail) for r in out.sourceReferences if r.kind == "pack"}
    assert pack_cites == {("synthetic-remediation-advisory", "version 1.0.0")}
    # The advisory text carries the pack provenance + escalation/runbook hints.
    assert any("Check odb failover." in rec and "synthetic-remediation-advisory@1.0.0" in rec
               for rec in out.recommendations)
    assert any("escalate/call support at severity >= high" in rec for rec in out.recommendations)


def test_guided_remediation_free_text_never_leaks_resource_id() -> None:
    # MED 4: an RCA recommendation carrying a resource id must NOT be re-emitted as guided-
    # remediation advisory free text — the id stays solely in sourceReferences provenance.
    leaky = "/subscriptions/0000/resourceGroups/customer-prod/providers/x/odb-01"
    rca = AgentResponse(
        agentName="aiops",
        taskType="auto-rca",
        inputSummary="symptoms=1",
        recommendations=[f"Investigate {leaky} as probable root cause."],
        sourceReferences=[
            SourceReference(kind="resource", id=leaky, detail="identified root cause: radius 3"),
        ],
        confidence=0.9,
        nextActions=["propose-remediation"],
    )
    tables = [_table({"odb": [RemediationStep(description="Check odb failover.")]})]
    out = propose_remediation(rca, root_cause_category="odb", tables=tables)

    assert all("/subscriptions/" not in rec for rec in out.recommendations)
    assert all("/subscriptions/" not in act for act in out.nextActions)
    # Provenance is retained: the resource id is still cited in sourceReferences.
    assert any(r.kind == "resource" and r.id == leaky for r in out.sourceReferences)


def test_rca_below_floor_calls_support_and_emits_no_steps() -> None:
    rca = _rca(confidence=RCA_CONFIDENCE_FLOOR - 0.1, root_node=None)
    tables = [_table({"odb": [RemediationStep(description="Should not be used.")]})]
    out = propose_remediation(rca, root_cause_category="odb", tables=tables)

    assert out.nextActions == [CALL_SUPPORT_ACTION]
    # No advisory pack step leaked into recommendations, and no pack citation was added.
    assert not any("Should not be used." in rec for rec in out.recommendations)
    assert all(r.kind != "pack" for r in out.sourceReferences)


def test_confident_rca_no_matching_category_calls_support() -> None:
    rca = _rca(confidence=0.9)
    tables = [_table({"database": [RemediationStep(description="db-specific step")]})]
    out = propose_remediation(rca, root_cause_category="odb", tables=tables)

    assert out.nextActions == [CALL_SUPPORT_ACTION]
    assert not any("db-specific step" in rec for rec in out.recommendations)


def test_confident_rca_no_category_calls_support() -> None:
    # A confident RCA whose root-cause node has no derivable category ⇒ support (fail-closed).
    rca = _rca(confidence=0.9)
    tables = [_table({"odb": [RemediationStep(description="unused")]})]
    out = propose_remediation(rca, root_cause_category=None, tables=tables)
    assert out.nextActions == [CALL_SUPPORT_ACTION]


def test_catch_all_star_matches_when_no_exact_category() -> None:
    rca = _rca(confidence=0.9)
    tables = [_table({"*": [RemediationStep(description="Generic catch-all advisory.")]})]
    out = propose_remediation(rca, root_cause_category="mystery-kind", tables=tables)
    assert out.nextActions == ["Generic catch-all advisory."]


def test_catch_all_default_matches_when_no_exact_category() -> None:
    rca = _rca(confidence=0.9)
    tables = [_table({"default": [RemediationStep(description="Default advisory.")]})]
    out = propose_remediation(rca, root_cause_category="mystery-kind", tables=tables)
    assert out.nextActions == ["Default advisory."]


def test_exact_category_wins_over_catch_all() -> None:
    rca = _rca(confidence=0.9)
    tables = [_table({
        "odb": [RemediationStep(description="Exact odb step.")],
        "*": [RemediationStep(description="Catch-all step.")],
    })]
    out = propose_remediation(rca, root_cause_category="odb", tables=tables)
    assert out.nextActions == ["Exact odb step."]


def test_multiple_packs_ordered_deterministically_by_pack_identity() -> None:
    rca = _rca(confidence=0.9)
    tables = [
        _table({"odb": [RemediationStep(description="from pack-b")]}, pack_id="pack-b"),
        _table({"odb": [RemediationStep(description="from pack-a")]}, pack_id="pack-a"),
    ]
    out = propose_remediation(rca, root_cause_category="odb", tables=tables)
    # Deterministic order by (pack_id, pack_version): pack-a before pack-b, input order aside.
    assert out.nextActions == ["from pack-a", "from pack-b"]


# --------------------------------------------------------------------------------------
# parse_remediation_table — fail-closed parsing / bounds
# --------------------------------------------------------------------------------------
def test_parse_valid_remediations_builds_table() -> None:
    body = {"remediations": {
        "odb": [{"description": "Check failover.", "runbook": "https://aka.ms/x",
                 "escalateSeverity": "high"}],
        "web": [{"description": "Check probes."}],
    }}
    table, notes = parse_remediation_table("p", "1.0.0", body)
    assert notes == []
    assert table is not None
    assert set(table.steps_by_category) == {"odb", "web"}
    assert table.steps_by_category["odb"][0] == RemediationStep(
        description="Check failover.", runbook="https://aka.ms/x", escalate_severity="high"
    )


def test_parse_absent_remediations_is_not_an_error() -> None:
    table, notes = parse_remediation_table("p", "1.0.0", {"default": "ticket"})
    assert table is None
    assert notes == []


def test_parse_non_mapping_remediations_fails_closed() -> None:
    table, notes = parse_remediation_table("p", "1.0.0", {"remediations": ["nope"]})
    assert table is None
    assert notes and "not an object" in notes[0]


def test_parse_oversized_step_list_rejected_fail_closed() -> None:
    oversized = [{"description": f"step {i}"} for i in range(MAX_STEPS_PER_CATEGORY + 1)]
    table, notes = parse_remediation_table("p", "1.0.0", {"remediations": {"odb": oversized}})
    assert table is None
    assert notes and "fail-closed" in notes[0]


def test_parse_oversized_description_rejected_fail_closed() -> None:
    body = {"remediations": {"odb": [{"description": "x" * 501}]}}
    table, notes = parse_remediation_table("p", "1.0.0", body)
    assert table is None
    assert notes and "description exceeds" in notes[0]


def test_parse_unknown_step_field_rejected_fail_closed() -> None:
    # An unknown field could smuggle an executable action — reject the whole category fail-closed.
    body: dict[str, Any] = {"remediations": {"odb": [
        {"description": "ok", "command": "rm -rf /"},
    ]}}
    table, notes = parse_remediation_table("p", "1.0.0", body)
    assert table is None
    assert notes and "unknown field" in notes[0]


def test_parse_one_bad_step_rejects_whole_table_fail_closed() -> None:
    # MED 2: all-or-nothing — a valid 'odb' category + an invalid 'web' category ⇒ NO table at all
    # (the whole pack is rejected and surfaced), never a partial table.
    body = {"remediations": {
        "odb": [{"description": "good"}],
        "web": [{"description": ""}],  # empty desc invalidates the ENTIRE table
    }}
    table, notes = parse_remediation_table("p", "1.0.0", body)
    assert table is None
    assert notes and "whole table rejected" in notes[0]


def test_parse_empty_category_rejects_whole_table() -> None:
    body = {"remediations": {
        "odb": [{"description": "good"}],
        "web": [],  # empty category list invalidates the ENTIRE table
    }}
    table, notes = parse_remediation_table("p", "1.0.0", body)
    assert table is None
    assert notes and "fail-closed" in notes[0]


def test_parse_array_valued_escalate_severity_fails_closed_no_typeerror() -> None:
    # MED 2: an unhashable (array) escalateSeverity must fail closed, not raise TypeError at the
    # set-membership test.
    body: dict[str, Any] = {"remediations": {"odb": [
        {"description": "ok", "escalateSeverity": ["high", "critical"]},
    ]}}
    table, notes = parse_remediation_table("p", "1.0.0", body)
    assert table is None
    assert notes and "escalateSeverity" in notes[0]


def test_parse_non_string_category_key_fails_closed() -> None:
    body = {"remediations": {1: [{"description": "ok"}]}}
    table, notes = parse_remediation_table("p", "1.0.0", body)
    assert table is None
    assert notes and "category key" in notes[0]


# --------------------------------------------------------------------------------------
# MED A — category-key bounds + reserved catch-all enforcement (keys AND roles)
# --------------------------------------------------------------------------------------
def test_parse_schema_invalid_category_key_rejects_whole_table() -> None:
    # A key that violates the schema category-key pattern (e.g. contains ':') must reject the
    # ENTIRE table (all-or-nothing), never parse successfully alongside valid keys.
    body = {"remediations": {
        "odb": [{"description": "good"}],
        "odb::evil": [{"description": "smuggled"}],
    }}
    table, notes = parse_remediation_table("p", "1.0.0", body)
    assert table is None
    assert notes and "pattern/length" in notes[0]


def test_parse_oversized_category_key_rejects_whole_table() -> None:
    body = {"remediations": {"a" * 65: [{"description": "good"}]}}
    table, notes = parse_remediation_table("p", "1.0.0", body)
    assert table is None
    assert notes and "pattern/length" in notes[0]


def test_node_role_matching_schema_invalid_token_is_none() -> None:
    # A hostile role that isn't a valid category key ⇒ None ⇒ support (never a lucky exact match).
    node = ResourceNode(id="x", name="x", type="epic/odb", role="odb::evil")
    assert node_category(node) is None


def test_node_role_reserved_catch_all_tokens_never_match() -> None:
    # A node claiming role '*' or 'default' must NOT hit the pack catch-all — its category is
    # invalid ⇒ None ⇒ support (closes the "hostile role smuggles a catch-all" path).
    assert node_category(ResourceNode(id="x", name="x", type="epic/x", role="*")) is None
    assert node_category(ResourceNode(id="x", name="x", type="epic/x", role="default")) is None
    assert node_category(ResourceNode(id="x", name="x", type="epic/x", role="DEFAULT")) is None


def test_node_role_oversized_is_none() -> None:
    node = ResourceNode(id="x", name="x", type="epic/x", role="a" * 65)
    assert node_category(node) is None


def test_catch_all_keys_are_valid_pack_keys_but_not_valid_roles() -> None:
    # The catch-all tokens are VALID keys inside a pack (the parser accepts them)...
    body = {"remediations": {"*": [{"description": "catch-all advice"}]}}
    table, notes = parse_remediation_table("p", "1.0.0", body)
    assert table is not None and not notes
    # ...and both '*' and 'default' are valid category keys per the schema mirror (they are the
    # documented catch-alls a pack may author), while a bad token like 'odb::evil' is not.
    assert _is_valid_category_key("*") is True
    assert _is_valid_category_key("default") is True
    assert _is_valid_category_key("odb") is True
    assert _is_valid_category_key("odb::evil") is False


# --------------------------------------------------------------------------------------
# MED B — resource ids only in sourceReferences, never in ANY emitted free-text field
# --------------------------------------------------------------------------------------
def _leaky_rca(confidence: float) -> AgentResponse:
    leaky = "/subscriptions/0000/resourceGroups/customer-prod/providers/x/odb-01"
    return AgentResponse(
        agentName="aiops",
        taskType="auto-rca",
        inputSummary=f"symptoms=1; nodes=['{leaky}']",
        findings=["Telemetry breach on odb"],
        risks=[f"Cascading outage explained by {leaky}"],
        recommendations=[f"Investigate {leaky} as probable root cause."],
        sourceReferences=[
            SourceReference(kind="resource", id=leaky, detail="identified root cause: radius 3"),
        ],
        confidence=confidence,
        nextActions=["propose-remediation"],
    )


def _assert_no_resource_id_in_free_text(out: AgentResponse) -> None:
    for text in [out.inputSummary, *out.risks, *out.recommendations, *out.nextActions]:
        assert "/subscriptions/" not in text


def test_success_path_free_text_is_pii_free_across_all_fields() -> None:
    rca = _leaky_rca(0.9)
    tables = [_table({"odb": [RemediationStep(description="Check odb failover.")]})]
    out = propose_remediation(rca, root_cause_category="odb", tables=tables)

    _assert_no_resource_id_in_free_text(out)
    # Provenance is retained solely in sourceReferences.
    leaky = "/subscriptions/0000/resourceGroups/customer-prod/providers/x/odb-01"
    assert any(r.kind == "resource" and r.id == leaky for r in out.sourceReferences)


def test_support_path_free_text_is_pii_free_across_all_fields() -> None:
    rca = _leaky_rca(0.9)
    # No matching category ⇒ support path — must ALSO be PII-free on every emitted field.
    tables = [_table({"database": [RemediationStep(description="db step")]})]
    out = propose_remediation(rca, root_cause_category="odb", tables=tables)

    assert out.nextActions == [CALL_SUPPORT_ACTION]
    _assert_no_resource_id_in_free_text(out)
    leaky = "/subscriptions/0000/resourceGroups/customer-prod/providers/x/odb-01"
    assert any(r.kind == "resource" and r.id == leaky for r in out.sourceReferences)
