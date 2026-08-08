"""Pure LB transform layer — membership→edges, aggregate health, filtered-log signals (issue #49).

All fixtures are obviously synthetic (zeroed GUIDs, fake ids, no PII/PHI). These tests are fully
Azure/network-free: they exercise only the pure validators/mappings in
:mod:`shared.connectors.lb`.
"""
from __future__ import annotations

import math

import pytest
from pydantic import ValidationError

from shared.connectors import FetchResult
from shared.connectors.lb import (
    ALLOWED_LOG_METRICS,
    ALLOWED_MEMBER_HEALTH,
    MAX_LOG_VALUE,
    MAX_RESOURCE_ID_LEN,
    SUPPLEMENTAL_HEALTH_TAG,
    SUPPLEMENTAL_SOURCE_TAG,
    BackendMemberHint,
    LbSignalError,
    LogSignalHint,
    aggregate_health,
    apply_health,
    dependency_edges,
    log_signals,
    parse_signals_atomic,
    signals_from_result,
    signals_to_raw,
    to_agent_response,
    to_source_reference,
    validate_log_hint,
    validate_member_hint,
)
from shared.contracts import EdgeType, HealthState, ResourceNode
from support.connectors import (
    FAKE_LB_ID,
    FAKE_LB_MEMBER_A,
    FAKE_LB_MEMBER_B,
)

_ORIGIN = "connector:netscaler"
_SOURCE = "netscaler"


def _member(
    lb_id: str = FAKE_LB_ID, member_id: str = FAKE_LB_MEMBER_A, health: str = "up"
) -> dict[str, object]:
    return {"kind": "backend-member", "lbId": lb_id, "memberId": member_id, "health": health}


def _log(
    lb_id: str = FAKE_LB_ID, metric: str = "error_rate", value: float = 0.02
) -> dict[str, object]:
    return {"kind": "log-signal", "lbId": lb_id, "metric": metric, "value": value}


def _node(node_id: str = FAKE_LB_ID, *, role: str | None = "lb") -> ResourceNode:
    return ResourceNode(
        id=node_id, name="lb-01", type="Fake.Network/loadBalancers", workload="epic",
        tier="delivery", role=role, tags={"epic-role": "lb"},
    )


# --------------------------------------------------------------------------------------
# validate_member_hint / validate_log_hint
# --------------------------------------------------------------------------------------
def test_validate_member_hint_accepts_well_formed() -> None:
    hint = validate_member_hint(_member(), max_field_len=512)
    assert hint.lb_id == FAKE_LB_ID
    assert hint.member_id == FAKE_LB_MEMBER_A
    assert hint.health == "up"


def test_validate_member_hint_rejects_unexpected_key_pii_smuggle() -> None:
    bad = _member()
    bad["free_text_note"] = "unexpected-noise"
    with pytest.raises(LbSignalError):
        validate_member_hint(bad, max_field_len=512)


def test_validate_member_hint_rejects_unknown_kind() -> None:
    bad = _member()
    bad["kind"] = "not-a-member"
    with pytest.raises(LbSignalError):
        validate_member_hint(bad, max_field_len=512)


def test_validate_member_hint_rejects_health_outside_allowlist() -> None:
    with pytest.raises(LbSignalError):
        validate_member_hint(_member(health="on-fire"), max_field_len=512)


def test_validate_member_hint_rejects_email_in_member_id() -> None:
    with pytest.raises(LbSignalError):
        validate_member_hint(_member(member_id="nurse@hospital.example"), max_field_len=512)


def test_validate_member_hint_rejects_oversized_id() -> None:
    with pytest.raises(LbSignalError):
        validate_member_hint(_member(member_id="a" * 9), max_field_len=8)


def test_validate_member_hint_rejects_non_mapping() -> None:
    with pytest.raises(LbSignalError):
        validate_member_hint(["not", "a", "dict"], max_field_len=512)


def test_validate_log_hint_accepts_well_formed() -> None:
    hint = validate_log_hint(_log(), max_field_len=512)
    assert hint.lb_id == FAKE_LB_ID
    assert hint.metric == "error_rate"
    assert hint.value == pytest.approx(0.02)


def test_validate_log_hint_rejects_unexpected_key() -> None:
    bad = _log()
    bad["free_text_note"] = "unexpected-noise"
    with pytest.raises(LbSignalError):
        validate_log_hint(bad, max_field_len=512)


def test_validate_log_hint_rejects_metric_outside_allowlist() -> None:
    with pytest.raises(LbSignalError):
        validate_log_hint(_log(metric="raw_log_body"), max_field_len=512)


@pytest.mark.parametrize(
    "value", [-1.0, float("nan"), float("inf"), MAX_LOG_VALUE * 2, "0.1", True]
)
def test_validate_log_hint_rejects_bad_value(value: object) -> None:
    bad = _log()
    bad["value"] = value
    with pytest.raises(LbSignalError):
        validate_log_hint(bad, max_field_len=512)


# --------------------------------------------------------------------------------------
# parse_signals_atomic
# --------------------------------------------------------------------------------------
def test_parse_signals_atomic_accepts_mixed_kinds() -> None:
    signals = parse_signals_atomic(
        [_member(), _member(member_id=FAKE_LB_MEMBER_B, health="down"), _log()],
        max_records=100,
        max_field_len=512,
    )
    assert len(signals.members) == 2
    assert len(signals.logs) == 1


def test_parse_signals_atomic_rejects_entire_batch_on_one_bad_record() -> None:
    with pytest.raises(LbSignalError):
        parse_signals_atomic(
            [_member(), _member(health="melting")], max_records=100, max_field_len=512
        )


def test_parse_signals_atomic_rejects_unknown_kind() -> None:
    with pytest.raises(LbSignalError):
        parse_signals_atomic([{"kind": "mystery"}], max_records=100, max_field_len=512)


def test_parse_signals_atomic_rejects_too_many_records() -> None:
    with pytest.raises(LbSignalError):
        parse_signals_atomic([_member(), _member()], max_records=1, max_field_len=512)


# --------------------------------------------------------------------------------------
# signals_from_result / signals_to_raw — untrusted re-validation
# --------------------------------------------------------------------------------------
def test_signals_from_result_unavailable_yields_empty() -> None:
    signals = signals_from_result(FetchResult(available=False, error="NoCredential"))
    assert signals.members == []
    assert signals.logs == []


def test_signals_to_raw_round_trips_through_signals_from_result() -> None:
    original = parse_signals_atomic([_member(), _log()], max_records=100, max_field_len=512)
    raw = signals_to_raw(original)
    rehydrated = signals_from_result(FetchResult(available=True, raw=raw))
    assert rehydrated.members == original.members
    assert rehydrated.logs == original.logs


@pytest.mark.parametrize(
    "raw",
    [
        {"kind": "backend-member", "lb_id": FAKE_LB_ID, "member_id": FAKE_LB_MEMBER_A,
         "health": "smoldering"},
        {"kind": "backend-member", "lb_id": "nurse@x.example", "member_id": FAKE_LB_MEMBER_A,
         "health": "up"},
        {"kind": "backend-member", "lb_id": FAKE_LB_ID, "member_id": FAKE_LB_MEMBER_A,
         "health": "up", "note": "free text"},
        {"kind": "log-signal", "lb_id": FAKE_LB_ID, "metric": "patient_row", "value": 1.0},
    ],
)
def test_signals_from_result_rejects_untrusted_malicious_raw(raw: dict[str, object]) -> None:
    with pytest.raises(LbSignalError):
        signals_from_result(FetchResult(available=True, raw=[raw]))


def test_signals_from_result_rejects_unknown_kind() -> None:
    with pytest.raises(LbSignalError):
        signals_from_result(FetchResult(available=True, raw=[{"kind": "weird"}]))


# --------------------------------------------------------------------------------------
# dependency_edges
# --------------------------------------------------------------------------------------
def test_dependency_edges_maps_membership_to_load_balances() -> None:
    members = [
        BackendMemberHint(lb_id=FAKE_LB_ID, member_id=FAKE_LB_MEMBER_A, health="up"),
        BackendMemberHint(lb_id=FAKE_LB_ID, member_id=FAKE_LB_MEMBER_B, health="down"),
    ]
    edges = dependency_edges(
        members, {FAKE_LB_ID, FAKE_LB_MEMBER_A, FAKE_LB_MEMBER_B}, origin=_ORIGIN
    )
    # BOTH directions per member: member -> lb (SPOF ingress) and lb -> member (redundant peer).
    assert len(edges) == 4
    assert all(e.type is EdgeType.load_balances for e in edges)
    assert all(e.origin == _ORIGIN for e in edges)

    member_to_lb = {e.source: e for e in edges if e.target == FAKE_LB_ID}
    lb_to_member = {e.target: e for e in edges if e.source == FAKE_LB_ID}
    assert set(member_to_lb) == {FAKE_LB_MEMBER_A, FAKE_LB_MEMBER_B}
    assert set(lb_to_member) == {FAKE_LB_MEMBER_A, FAKE_LB_MEMBER_B}
    # member -> lb is ALWAYS non-redundant (losing the LB downs every member — the SPOF edge).
    assert all(e.redundant is False for e in member_to_lb.values())
    # A pool with 2 known members ⇒ loss of one is degraded not down ⇒ lb -> member is redundant.
    assert all(e.redundant is True for e in lb_to_member.values())


def test_dependency_edges_single_member_pool_not_redundant() -> None:
    members = [BackendMemberHint(lb_id=FAKE_LB_ID, member_id=FAKE_LB_MEMBER_A, health="up")]
    edges = dependency_edges(members, {FAKE_LB_ID, FAKE_LB_MEMBER_A}, origin=_ORIGIN)
    # Both directions emitted, but neither is redundant with a single known member.
    assert len(edges) == 2
    member_to_lb = next(e for e in edges if e.target == FAKE_LB_ID)
    lb_to_member = next(e for e in edges if e.source == FAKE_LB_ID)
    assert member_to_lb.redundant is False
    assert lb_to_member.redundant is False


def test_dependency_edges_phantom_member_does_not_inflate_redundancy() -> None:
    # FIX B: a member NOT in known_ids must NOT count toward redundancy — a single REAL backend
    # stays non-redundant (fail closed) even when a phantom/unknown member is parsed alongside it.
    members = [
        BackendMemberHint(lb_id=FAKE_LB_ID, member_id=FAKE_LB_MEMBER_A, health="up"),
        BackendMemberHint(lb_id=FAKE_LB_ID, member_id=FAKE_LB_MEMBER_B, health="up"),
    ]
    # Only member A is a known estate node; B is a phantom.
    edges = dependency_edges(members, {FAKE_LB_ID, FAKE_LB_MEMBER_A}, origin=_ORIGIN)
    assert len(edges) == 2  # only A yields edges
    lb_to_member = next(e for e in edges if e.source == FAKE_LB_ID)
    assert lb_to_member.redundant is False


def test_dependency_edges_self_member_does_not_inflate_redundancy() -> None:
    # A self-member (member_id == lb_id) is skipped AND must not count toward redundancy, so a
    # single real backend alongside a self-member stays non-redundant.
    members = [
        BackendMemberHint(lb_id=FAKE_LB_ID, member_id=FAKE_LB_ID, health="up"),
        BackendMemberHint(lb_id=FAKE_LB_ID, member_id=FAKE_LB_MEMBER_A, health="up"),
    ]
    edges = dependency_edges(members, {FAKE_LB_ID, FAKE_LB_MEMBER_A}, origin=_ORIGIN)
    assert len(edges) == 2
    lb_to_member = next(e for e in edges if e.source == FAKE_LB_ID)
    assert lb_to_member.redundant is False


def test_dependency_edges_drops_edge_with_unknown_endpoint() -> None:
    members = [BackendMemberHint(lb_id=FAKE_LB_ID, member_id=FAKE_LB_MEMBER_A, health="up")]
    assert dependency_edges(members, {FAKE_LB_ID}, origin=_ORIGIN) == []


def test_dependency_edges_drops_self_edge() -> None:
    members = [BackendMemberHint(lb_id=FAKE_LB_ID, member_id=FAKE_LB_ID, health="up")]
    assert dependency_edges(members, {FAKE_LB_ID}, origin=_ORIGIN) == []


def test_dependency_edges_dedupes() -> None:
    members = [
        BackendMemberHint(lb_id=FAKE_LB_ID, member_id=FAKE_LB_MEMBER_A, health="up"),
        BackendMemberHint(lb_id=FAKE_LB_ID, member_id=FAKE_LB_MEMBER_A, health="down"),
    ]
    edges = dependency_edges(members, {FAKE_LB_ID, FAKE_LB_MEMBER_A}, origin=_ORIGIN)
    # Duplicate member hint ⇒ still exactly the two directed edges, de-duped.
    assert len(edges) == 2
    assert {(e.source, e.target) for e in edges} == {
        (FAKE_LB_MEMBER_A, FAKE_LB_ID),
        (FAKE_LB_ID, FAKE_LB_MEMBER_A),
    }


def test_dependency_edges_drops_bypass_constructed_invalid_id() -> None:
    # model_construct bypasses field validators — the boundary re-check must drop it.
    bad = BackendMemberHint.model_construct(
        lb_id="nurse@x.example", member_id=FAKE_LB_MEMBER_A, health="up"
    )
    assert dependency_edges([bad], {FAKE_LB_ID, FAKE_LB_MEMBER_A}, origin=_ORIGIN) == []


# --------------------------------------------------------------------------------------
# aggregate_health
# --------------------------------------------------------------------------------------
def _members(*healths: str) -> list[BackendMemberHint]:
    return [
        BackendMemberHint(lb_id=FAKE_LB_ID, member_id=f"/rg/fake/m{i}", health=h)
        for i, h in enumerate(healths)
    ]


@pytest.mark.parametrize(
    ("healths", "expected"),
    [
        (("up", "up"), HealthState.up),
        (("down", "down"), HealthState.down),
        (("unknown", "unknown"), HealthState.unknown),
        (("up", "down"), HealthState.degraded),
        (("up", "degraded"), HealthState.degraded),
        (("up", "unknown"), HealthState.degraded),
    ],
)
def test_aggregate_health_reduces_per_lb(healths: tuple[str, ...], expected: HealthState) -> None:
    result = aggregate_health(_members(*healths))
    assert result == {FAKE_LB_ID: expected}


def test_aggregate_health_ignores_bypass_constructed_invalid() -> None:
    bad = BackendMemberHint.model_construct(
        lb_id=FAKE_LB_ID, member_id=FAKE_LB_MEMBER_A, health="x"
    )
    assert aggregate_health([bad]) == {}


# --------------------------------------------------------------------------------------
# apply_health
# --------------------------------------------------------------------------------------
def test_apply_health_annotates_matching_node_only() -> None:
    other = _node(node_id="/rg/fake/other-lb")
    result = apply_health([_node(), other], {FAKE_LB_ID: HealthState.degraded}, source=_SOURCE)
    assert result.annotated_ids == [FAKE_LB_ID]
    annotated = next(n for n in result.nodes if n.id == FAKE_LB_ID)
    assert annotated.tags[SUPPLEMENTAL_SOURCE_TAG] == _SOURCE
    assert annotated.tags[SUPPLEMENTAL_HEALTH_TAG] == "degraded"
    untouched = next(n for n in result.nodes if n.id == other.id)
    assert SUPPLEMENTAL_HEALTH_TAG not in untouched.tags


def test_apply_health_preserves_prior_connector_provenance() -> None:
    node = _node()
    node.tags[SUPPLEMENTAL_SOURCE_TAG] = "citrix"
    result = apply_health([node], {FAKE_LB_ID: HealthState.up}, source=_SOURCE)
    annotated = result.nodes[0]
    assert annotated.tags[SUPPLEMENTAL_SOURCE_TAG] == "citrix,netscaler"


def test_apply_health_never_mutates_authoritative_fields() -> None:
    node = _node()
    result = apply_health([node], {FAKE_LB_ID: HealthState.down}, source=_SOURCE)
    annotated = result.nodes[0]
    assert (annotated.id, annotated.name, annotated.type, annotated.workload, annotated.role) == (
        node.id, node.name, node.type, node.workload, node.role
    )
    # Original input node is not mutated in place.
    assert SUPPLEMENTAL_HEALTH_TAG not in node.tags


def test_apply_health_drops_health_matching_no_node() -> None:
    result = apply_health([_node()], {"/rg/fake/ghost": HealthState.down}, source=_SOURCE)
    assert result.annotated_ids == []


# --------------------------------------------------------------------------------------
# log_signals
# --------------------------------------------------------------------------------------
def test_log_signals_keeps_known_lb_only() -> None:
    logs = [
        LogSignalHint(lb_id=FAKE_LB_ID, metric="error_rate", value=0.02),
        LogSignalHint(lb_id="/rg/fake/ghost", metric="reset_rate", value=1.0),
    ]
    kept = log_signals(logs, {FAKE_LB_ID})
    assert [h.lb_id for h in kept] == [FAKE_LB_ID]


def test_log_signals_drops_bypass_constructed_invalid() -> None:
    bad = LogSignalHint.model_construct(lb_id=FAKE_LB_ID, metric="patient_row", value=1.0)
    assert log_signals([bad], {FAKE_LB_ID}) == []


# --------------------------------------------------------------------------------------
# provenance + AgentResponse egress (aggregate-only)
# --------------------------------------------------------------------------------------
def test_to_source_reference_cites_connector() -> None:
    ref = to_source_reference(_SOURCE, FAKE_LB_ID)
    assert ref.kind == "connector"
    assert ref.id == _SOURCE
    assert ref.detail == FAKE_LB_ID


def test_to_agent_response_is_aggregate_and_pii_free() -> None:
    aggregate = {FAKE_LB_ID: HealthState.degraded}
    edges = dependency_edges(
        [BackendMemberHint(lb_id=FAKE_LB_ID, member_id=FAKE_LB_MEMBER_A, health="up")],
        {FAKE_LB_ID, FAKE_LB_MEMBER_A},
        origin=_ORIGIN,
    )
    logs = [LogSignalHint(lb_id=FAKE_LB_ID, metric="error_rate", value=0.02)]
    resp = to_agent_response(
        agent_name="netscaler-connector", source=_SOURCE, available=True,
        aggregate=aggregate, edges=edges, logs=logs,
    )
    assert resp.agentName == "netscaler-connector"
    assert resp.confidence == 1.0
    assert any("degraded" in r for r in resp.risks)
    assert all(ref.kind == "connector" for ref in resp.sourceReferences)
    # No free-form/raw-log field ever appears — only closed metric names + numeric aggregates.
    blob = " ".join(resp.findings)
    assert "error_rate" in blob


def test_to_agent_response_unavailable_has_zero_confidence() -> None:
    resp = to_agent_response(
        agent_name="f5-connector", source="f5", available=False,
        aggregate={}, edges=[], logs=[],
    )
    assert resp.confidence == 0.0
    assert resp.risks == []


# --------------------------------------------------------------------------------------
# closed-vocabulary + bound sanity
# --------------------------------------------------------------------------------------
def test_member_health_vocabulary_matches_healthstate() -> None:
    assert {s.value for s in HealthState} == ALLOWED_MEMBER_HEALTH


def test_log_metric_vocabulary_is_closed() -> None:
    assert "error_rate" in ALLOWED_LOG_METRICS
    with pytest.raises(ValidationError):
        LogSignalHint(lb_id=FAKE_LB_ID, metric="free_text", value=1.0)


def test_resource_id_bound_is_enforced() -> None:
    with pytest.raises(ValidationError):
        BackendMemberHint(
            lb_id=FAKE_LB_ID, member_id="/" + "a" * MAX_RESOURCE_ID_LEN, health="up"
        )


def test_log_value_must_be_finite() -> None:
    assert not math.isfinite(float("inf"))
    with pytest.raises(ValidationError):
        LogSignalHint(lb_id=FAKE_LB_ID, metric="error_rate", value=float("inf"))
