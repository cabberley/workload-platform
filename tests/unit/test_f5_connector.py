"""F5 BIG-IP (iControl REST) connector — pure ``parse_icontrol`` + fail-closed edge wiring (#49).

All fixtures are obviously synthetic (zeroed GUIDs, fake hosts, no PII/PHI); there is no real
network, credential, or iControl schema. The shared edge machinery is exercised once in
``test_connector_edge.py``; here we test the F5-specific pure mapping and the end-to-end wiring.
"""
from __future__ import annotations

import importlib
import sys

import httpx
import pytest

from shared.connectors.f5 import (
    EDGE_ORIGIN,
    F5Client,
    F5Config,
    F5Connector,
    parse_icontrol,
)
from shared.connectors.lb import (
    LbSignalError,
    aggregate_health,
    dependency_edges,
    log_signals,
    signals_from_result,
)
from shared.contracts import EdgeType, HealthState
from support.connectors import (
    FAKE_LB_ID,
    FAKE_LB_MEMBER_A,
    FAKE_LB_MEMBER_B,
    MockLbTokenProvider,
    synthetic_icontrol_payload,
)

APPROVED_HOST = "bigip.approved.test"
APPROVED_BASE_URL = f"https://{APPROVED_HOST}"


def _config(**overrides: object) -> F5Config:
    base: dict[str, object] = {"base_url": APPROVED_BASE_URL, "approved_hosts": (APPROVED_HOST,)}
    base.update(overrides)
    return F5Config(**base)  # type: ignore[arg-type]


def _client_with(
    transport: httpx.MockTransport, *, config: F5Config | None = None, **kwargs: object
) -> F5Client:
    cfg = config or _config()
    provider = MockLbTokenProvider()
    http_client = httpx.Client(transport=transport)
    return F5Client(
        cfg, client=http_client, credential_provider=provider, **kwargs  # type: ignore[arg-type]
    )


def _raise_if_called(request: httpx.Request) -> httpx.Response:
    raise AssertionError("no HTTP request should have been made")


# --------------------------------------------------------------------------------------
# parse_icontrol — pure
# --------------------------------------------------------------------------------------
def test_parse_icontrol_maps_membership_and_logs() -> None:
    records = parse_icontrol(synthetic_icontrol_payload())
    kinds = [r["kind"] for r in records]
    assert kinds.count("backend-member") == 2
    assert kinds.count("log-signal") == 1
    member_a = next(r for r in records if r.get("memberId") == FAKE_LB_MEMBER_A)
    assert member_a["lbId"] == FAKE_LB_ID
    assert member_a["health"] == "up"


@pytest.mark.parametrize(
    ("state", "session", "expected"),
    [
        ("up", "monitor-enabled", "up"),
        ("down", "monitor-enabled", "down"),
        ("unchecked", "monitor-enabled", "unknown"),
        ("up", "user-disabled", "degraded"),
        ("bogus", "monitor-enabled", "unknown"),
    ],
)
def test_parse_icontrol_state_and_session_mapping(
    state: str, session: str, expected: str
) -> None:
    payload = synthetic_icontrol_payload(members=((FAKE_LB_MEMBER_A, state, session),), logs=())
    records = parse_icontrol(payload)
    assert records[0]["health"] == expected


@pytest.mark.parametrize("payload", [["not", "a", "dict"], "string", 42])
def test_parse_icontrol_rejects_non_object_payload(payload: object) -> None:
    with pytest.raises(LbSignalError):
        parse_icontrol(payload)


def test_parse_icontrol_rejects_non_list_items() -> None:
    with pytest.raises(LbSignalError):
        parse_icontrol({"items": {"fullPath": FAKE_LB_ID}})


def test_parse_icontrol_rejects_bad_members_reference() -> None:
    with pytest.raises(LbSignalError):
        parse_icontrol({"items": [{"fullPath": FAKE_LB_ID, "membersReference": []}]})


def test_parse_icontrol_present_but_empty_items_yields_no_records() -> None:
    # An explicitly-present but EMPTY membership list is a legitimate zero-members success.
    assert parse_icontrol({"items": []}) == []


def test_parse_icontrol_missing_items_envelope_fails_closed() -> None:
    # FIX C: an ABSENT membership envelope must fail closed (never silently "zero members").
    with pytest.raises(LbSignalError):
        parse_icontrol({})


def test_parse_icontrol_pool_missing_members_reference_fails_closed() -> None:
    # A pool lacking a membersReference object must fail closed.
    with pytest.raises(LbSignalError):
        parse_icontrol({"items": [{"fullPath": FAKE_LB_ID}]})


def test_parse_icontrol_members_reference_missing_items_fails_closed() -> None:
    # A membersReference whose ``items`` is absent (not a list) must fail closed.
    with pytest.raises(LbSignalError):
        parse_icontrol({"items": [{"fullPath": FAKE_LB_ID, "membersReference": {}}]})


def test_parse_icontrol_unnamed_pool_with_empty_members_fails_closed() -> None:
    # An unnamed pool (no ``fullPath``) must fail closed UNCONDITIONALLY — even with an empty member
    # list it emits no records, so validating the identifier only via its members would fail-OPEN.
    with pytest.raises(LbSignalError):
        parse_icontrol({"items": [{"membersReference": {"items": []}}]})


def test_parse_icontrol_valid_plus_unnamed_pool_fails_closed_atomically() -> None:
    # A response mixing one valid pool and one malformed (unnamed) one must RAISE for the whole
    # response (atomic fail closed), never partially succeed.
    payload = synthetic_icontrol_payload(logs=())
    payload["items"].append({"membersReference": {"items": []}})
    with pytest.raises(LbSignalError):
        parse_icontrol(payload)


def test_parse_icontrol_named_pool_with_empty_members_succeeds() -> None:
    # A well-formed (named) pool with an explicitly-present EMPTY members list is a legit
    # zero-members success — this case must NOT be broken.
    assert parse_icontrol(
        {"items": [{"fullPath": FAKE_LB_ID, "membersReference": {"items": []}}]}
    ) == []


# --------------------------------------------------------------------------------------
# End-to-end wiring through the shared transform
# --------------------------------------------------------------------------------------
def test_fetch_raw_end_to_end_produces_edges_health_and_logs() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=synthetic_icontrol_payload())

    result = _client_with(httpx.MockTransport(handle)).fetch_raw()
    assert result.available is True

    signals = signals_from_result(result)
    known = {FAKE_LB_ID, FAKE_LB_MEMBER_A, FAKE_LB_MEMBER_B}
    edges = dependency_edges(signals.members, known, origin=EDGE_ORIGIN)
    # Both directions per member (2 members ⇒ 4 edges).
    assert len(edges) == 4
    assert all(e.type is EdgeType.load_balances for e in edges)
    assert all(e.origin == "connector:f5" for e in edges)
    assert all(e.redundant is False for e in edges if e.target == FAKE_LB_ID)
    assert all(e.redundant is True for e in edges if e.source == FAKE_LB_ID)

    assert aggregate_health(signals.members) == {FAKE_LB_ID: HealthState.degraded}
    assert len(log_signals(signals.logs, known)) == 1


def test_module_off_by_default_is_inert_without_credential() -> None:
    spy = MockLbTokenProvider()
    http_client = httpx.Client(transport=httpx.MockTransport(_raise_if_called))
    client = F5Client(F5Config(), client=http_client, credential_provider=spy)
    result = client.fetch_raw()
    assert result.available is False
    assert result.error == "InvalidEndpoint"
    assert spy.calls == 0


def test_fetch_raw_uses_keyless_env_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("F5_READ_TOKEN", "fake-env-token")
    seen: dict[str, str] = {}

    def handle(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, json=synthetic_icontrol_payload(members=(), logs=()))

    http_client = httpx.Client(transport=httpx.MockTransport(handle))
    client = F5Client(_config(), client=http_client)  # no provider ⇒ env-name fallback
    assert client.fetch_raw().available is True
    assert seen.get("authorization") == "Bearer fake-env-token"


def test_fetch_raw_unexpected_vendor_field_is_dropped_never_egresses() -> None:
    payload = synthetic_icontrol_payload()
    # A free-text field on a raw iControl member is never read by the projector, so it is DROPPED.
    payload["items"][0]["membersReference"]["items"][0]["free_text_note"] = "unexpected-noise"

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    result = _client_with(httpx.MockTransport(handle)).fetch_raw()
    assert result.available is True
    blob = repr(result.raw)
    assert "free_text_note" not in blob
    assert "unexpected-noise" not in blob


def test_fetch_raw_pii_in_projected_id_fails_closed_atomically() -> None:
    # A PII value in a field the projector DOES read (memberId) fails the charset gate.
    payload = synthetic_icontrol_payload(
        members=(("nurse@hospital.example", "up", "monitor-enabled"),), logs=()
    )

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    result = _client_with(httpx.MockTransport(handle)).fetch_raw()
    assert result.available is False
    assert result.raw == []


def test_f5_client_satisfies_connector_protocol() -> None:
    assert isinstance(_client_with(httpx.MockTransport(_raise_if_called)), F5Connector)


def test_importing_f5_does_not_import_httpx(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "httpx", None)
    for mod in ("shared.connectors.f5", "shared.connectors.edge"):
        monkeypatch.delitem(sys.modules, mod, raising=False)
    reloaded = importlib.import_module("shared.connectors.f5")
    assert reloaded is not None
