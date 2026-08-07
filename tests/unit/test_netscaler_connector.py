"""Citrix NetScaler (NITRO) connector — pure ``parse_nitro`` + fail-closed edge integration (#49).

All fixtures are obviously synthetic (zeroed GUIDs, fake hosts, no PII/PHI); there is no real
network, credential, or NITRO schema. The shared edge machinery (retry, bounded reads, observer,
endpoint validation) is exercised once in ``test_connector_edge.py``; here we test the
NetScaler-specific pure mapping and the end-to-end wiring through the shared transform.
"""
from __future__ import annotations

import importlib
import sys

import httpx
import pytest

from shared.connectors.lb import (
    LbSignalError,
    aggregate_health,
    dependency_edges,
    log_signals,
    parse_signals_atomic,
    signals_from_result,
)
from shared.connectors.netscaler import (
    EDGE_ORIGIN,
    NetScalerClient,
    NetScalerConfig,
    NetScalerConnector,
    parse_nitro,
)
from shared.contracts import EdgeType, HealthState
from support.connectors import (
    FAKE_LB_ID,
    FAKE_LB_MEMBER_A,
    FAKE_LB_MEMBER_B,
    MockLbTokenProvider,
    synthetic_nitro_payload,
)

APPROVED_HOST = "netscaler.approved.test"
APPROVED_BASE_URL = f"https://{APPROVED_HOST}"


def _config(**overrides: object) -> NetScalerConfig:
    base: dict[str, object] = {"base_url": APPROVED_BASE_URL, "approved_hosts": (APPROVED_HOST,)}
    base.update(overrides)
    return NetScalerConfig(**base)  # type: ignore[arg-type]


def _client_with(
    transport: httpx.MockTransport, *, config: NetScalerConfig | None = None, **kwargs: object
) -> NetScalerClient:
    cfg = config or _config()
    provider = MockLbTokenProvider()
    http_client = httpx.Client(transport=transport)
    return NetScalerClient(
        cfg, client=http_client, credential_provider=provider, **kwargs  # type: ignore[arg-type]
    )


def _raise_if_called(request: httpx.Request) -> httpx.Response:
    raise AssertionError("no HTTP request should have been made")


# --------------------------------------------------------------------------------------
# parse_nitro — pure
# --------------------------------------------------------------------------------------
def test_parse_nitro_maps_membership_and_logs() -> None:
    records = parse_nitro(synthetic_nitro_payload())
    kinds = [r["kind"] for r in records]
    assert kinds.count("backend-member") == 2
    assert kinds.count("log-signal") == 1
    member_a = next(r for r in records if r.get("memberId") == FAKE_LB_MEMBER_A)
    assert member_a["lbId"] == FAKE_LB_ID
    assert member_a["health"] == "up"


@pytest.mark.parametrize(
    ("nitro_state", "expected"),
    [("UP", "up"), ("DOWN", "down"), ("OUT OF SERVICE", "degraded"), ("bogus", "unknown")],
)
def test_parse_nitro_state_mapping(nitro_state: str, expected: str) -> None:
    payload = synthetic_nitro_payload(members=((FAKE_LB_MEMBER_A, nitro_state),), logs=())
    records = parse_nitro(payload)
    assert records[0]["health"] == expected


def test_parse_nitro_rejects_non_zero_errorcode() -> None:
    payload = synthetic_nitro_payload()
    payload["errorcode"] = 1
    with pytest.raises(LbSignalError):
        parse_nitro(payload)


@pytest.mark.parametrize("payload", [["not", "a", "dict"], "string", 42])
def test_parse_nitro_rejects_non_object_payload(payload: object) -> None:
    with pytest.raises(LbSignalError):
        parse_nitro(payload)


def test_parse_nitro_rejects_non_list_binding() -> None:
    with pytest.raises(LbSignalError):
        parse_nitro({"lbvserver_binding": {"name": FAKE_LB_ID}})


def test_parse_nitro_present_but_empty_binding_yields_no_records() -> None:
    # An explicitly-present but EMPTY membership list is a legitimate zero-members success.
    assert parse_nitro({"errorcode": 0, "lbvserver_binding": []}) == []


def test_parse_nitro_missing_membership_envelope_fails_closed() -> None:
    # FIX C: an ABSENT membership envelope must fail closed — a malformed/error payload can never
    # be silently read as "zero members" and suppress topology (fail-OPEN).
    with pytest.raises(LbSignalError):
        parse_nitro({"errorcode": 0})


def test_parse_nitro_binding_missing_members_fails_closed() -> None:
    # A binding lacking a ``members`` list must fail closed (not treated as zero members).
    with pytest.raises(LbSignalError):
        parse_nitro({"errorcode": 0, "lbvserver_binding": [{"name": FAKE_LB_ID}]})


def test_parse_nitro_unnamed_binding_with_empty_members_fails_closed() -> None:
    # An unnamed binding (no ``name``) must fail closed UNCONDITIONALLY — even with an empty member
    # list it emits no records, so validating the identifier only via its members would fail-OPEN.
    with pytest.raises(LbSignalError):
        parse_nitro({"errorcode": 0, "lbvserver_binding": [{"members": []}]})


def test_parse_nitro_valid_plus_unnamed_binding_fails_closed_atomically() -> None:
    # A response mixing one valid binding and one malformed (unnamed) one must RAISE for the whole
    # response (atomic fail closed), never partially succeed.
    payload = synthetic_nitro_payload(logs=())
    payload["lbvserver_binding"].append({"members": []})
    with pytest.raises(LbSignalError):
        parse_nitro(payload)


def test_parse_nitro_named_binding_with_empty_members_succeeds() -> None:
    # A well-formed (named) binding with an explicitly-present EMPTY members list is a legit
    # zero-members success — this case must NOT be broken.
    assert parse_nitro(
        {"errorcode": 0, "lbvserver_binding": [{"name": FAKE_LB_ID, "members": []}]}
    ) == []


# --------------------------------------------------------------------------------------
# End-to-end wiring through the shared transform
# --------------------------------------------------------------------------------------
def test_fetch_raw_end_to_end_produces_edges_health_and_logs() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=synthetic_nitro_payload())

    result = _client_with(httpx.MockTransport(handle)).fetch_raw()
    assert result.available is True

    signals = signals_from_result(result)
    known = {FAKE_LB_ID, FAKE_LB_MEMBER_A, FAKE_LB_MEMBER_B}
    edges = dependency_edges(signals.members, known, origin=EDGE_ORIGIN)
    # Both directions per member (2 members ⇒ 4 edges).
    assert len(edges) == 4
    assert all(e.type is EdgeType.load_balances for e in edges)
    assert all(e.origin == "connector:netscaler" for e in edges)
    # member -> lb is the non-redundant SPOF edge; lb -> member is redundant (2-member pool).
    assert all(e.redundant is False for e in edges if e.target == FAKE_LB_ID)
    assert all(e.redundant is True for e in edges if e.source == FAKE_LB_ID)

    # up + down member ⇒ aggregate degraded.
    assert aggregate_health(signals.members) == {FAKE_LB_ID: HealthState.degraded}
    assert len(log_signals(signals.logs, known)) == 1


def test_module_off_by_default_is_inert_without_credential() -> None:
    spy = MockLbTokenProvider()
    http_client = httpx.Client(transport=httpx.MockTransport(_raise_if_called))
    client = NetScalerClient(NetScalerConfig(), client=http_client, credential_provider=spy)
    result = client.fetch_raw()
    assert result.available is False
    assert result.error == "InvalidEndpoint"  # empty base_url ⇒ inert
    assert spy.calls == 0  # never resolves a credential when off


def test_fetch_raw_uses_keyless_env_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSCALER_READ_TOKEN", "fake-env-token")
    seen: dict[str, str] = {}

    def handle(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, json=synthetic_nitro_payload(members=(), logs=()))

    http_client = httpx.Client(transport=httpx.MockTransport(handle))
    client = NetScalerClient(_config(), client=http_client)  # no provider ⇒ env-name fallback
    assert client.fetch_raw().available is True
    assert seen.get("authorization") == "Bearer fake-env-token"


def test_fetch_raw_unexpected_vendor_field_is_dropped_never_egresses() -> None:
    payload = synthetic_nitro_payload()
    # A free-text field on a raw NITRO member is a field the projector never reads, so it is
    # DROPPED (never copied into a signal) — no unexpected key can ride the boundary.
    payload["lbvserver_binding"][0]["members"][0]["free_text_note"] = "unexpected-noise"

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    result = _client_with(httpx.MockTransport(handle)).fetch_raw()
    assert result.available is True
    blob = repr(result.raw)
    assert "free_text_note" not in blob
    assert "unexpected-noise" not in blob


def test_fetch_raw_pii_in_projected_id_fails_closed_atomically() -> None:
    # A PII value placed in a field the projector DOES read (memberId) fails the charset gate ⇒ the
    # whole fetch fails closed rather than egressing it.
    payload = synthetic_nitro_payload(
        members=(("nurse@hospital.example", "UP"),), logs=()
    )

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    result = _client_with(httpx.MockTransport(handle)).fetch_raw()
    assert result.available is False
    assert result.raw == []


def test_netscaler_client_satisfies_connector_protocol() -> None:
    client = _client_with(httpx.MockTransport(_raise_if_called))
    assert isinstance(client, NetScalerConnector)


def test_importing_netscaler_does_not_import_httpx(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "httpx", None)
    for mod in ("shared.connectors.netscaler", "shared.connectors.edge"):
        monkeypatch.delitem(sys.modules, mod, raising=False)
    reloaded = importlib.import_module("shared.connectors.netscaler")
    assert reloaded is not None


def test_parse_signals_atomic_rejects_member_missing_id() -> None:
    # A NITRO member with no resourceId shapes to memberId=None ⇒ atomic validation fails closed.
    payload = synthetic_nitro_payload(members=(), logs=())
    payload["lbvserver_binding"][0]["members"] = [{"state": "UP"}]
    records = parse_nitro(payload)
    with pytest.raises(LbSignalError):
        parse_signals_atomic(records, max_records=100, max_field_len=512)
