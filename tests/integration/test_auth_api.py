"""Integration tests for keyless Entra RBAC on the API (issue #64).

Drives the real FastAPI app with a ``TestClient``, overriding ONLY the store and the auth-validator
dependency with an injected, network-free validator over a synthetic key. Proves deny-by-default
enforcement, the health carve-out, and that the audit actor comes from the VALIDATED ``oid`` — never
a spoofable header. All fixtures are synthetic (no PHI/PII, no secrets, no real Entra).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.app.main import app, get_auth_validator, get_store
from shared.audit import PRINCIPAL_ID_HEADER, SYSTEM_ACTOR
from shared.auth.config import ENV_AUDIENCE, ENV_MODE, ENV_TENANT_ID
from shared.auth.errors import AuthConfigError
from shared.state import LocalStateStore
from support.auth import FAKE_OID, TokenFactory, build_test_validator

VM_TYPE = "Microsoft.Compute/virtualMachines"
_NODES = [{"id": "vm1", "name": "vm1", "type": VM_TYPE, "tags": {}}]


@pytest.fixture
def auth_on(tmp_path):
    """TestClient with auth ENABLED via an injected keyless validator + isolated store."""
    factory = TokenFactory()
    store = LocalStateStore(str(tmp_path))
    validator = build_test_validator(factory)
    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_auth_validator] = lambda: validator
    with TestClient(app) as client:
        yield client, factory, store
    app.dependency_overrides.clear()


@pytest.fixture
def auth_off(tmp_path):
    """TestClient with auth DISABLED (validator None) — the documented local-dev / no-auth path."""
    store = LocalStateStore(str(tmp_path))
    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_auth_validator] = lambda: None
    with TestClient(app) as client:
        yield client, store
    app.dependency_overrides.clear()


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --------------------------------------------------------------------------------------
# Health carve-out — probes must never require auth.
# --------------------------------------------------------------------------------------
def test_health_endpoints_reachable_without_auth_when_enabled(auth_on) -> None:
    client, _factory, _store = auth_on
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/health/ready").status_code in (200, 503)  # readiness may be 503
    assert client.get("/").status_code == 200


# --------------------------------------------------------------------------------------
# Write endpoints — deny-by-default, fail closed.
# --------------------------------------------------------------------------------------
def test_post_without_token_is_401(auth_on) -> None:
    client, _factory, _store = auth_on
    resp = client.post("/api/workloads/epic/estate", json=_NODES)
    assert resp.status_code == 401


def test_reader_token_on_post_is_403(auth_on) -> None:
    client, factory, _store = auth_on
    token = factory.mint(roles=["Workloads.Reader"])
    resp = client.post("/api/workloads/epic/estate", json=_NODES, headers=_bearer(token))
    assert resp.status_code == 403


def test_operator_token_on_post_is_allowed(auth_on) -> None:
    client, factory, _store = auth_on
    token = factory.mint(roles=["Workloads.Operator"])
    resp = client.post("/api/workloads/epic/estate", json=_NODES, headers=_bearer(token))
    assert resp.status_code == 200
    assert resp.json() == {"count": 1}


def test_admin_token_on_post_is_allowed(auth_on) -> None:
    client, factory, _store = auth_on
    token = factory.mint(roles=["Workloads.Admin"])
    resp = client.post("/api/workloads/epic/estate", json=_NODES, headers=_bearer(token))
    assert resp.status_code == 200


def test_no_role_token_on_post_is_403(auth_on) -> None:
    client, factory, _store = auth_on
    token = factory.mint(roles=[])
    resp = client.post("/api/workloads/epic/estate", json=_NODES, headers=_bearer(token))
    assert resp.status_code == 403


def test_expired_token_on_post_is_401(auth_on) -> None:
    client, factory, _store = auth_on
    token = factory.mint(roles=["Workloads.Operator"], expires_in=-3600.0)
    resp = client.post("/api/workloads/epic/estate", json=_NODES, headers=_bearer(token))
    assert resp.status_code == 401


# --------------------------------------------------------------------------------------
# Read endpoints — require at least Reader when auth is enabled.
# --------------------------------------------------------------------------------------
def test_get_without_token_is_401(auth_on) -> None:
    client, _factory, _store = auth_on
    assert client.get("/api/workloads").status_code == 401


def test_get_with_reader_token_is_allowed(auth_on) -> None:
    client, factory, _store = auth_on
    token = factory.mint(roles=["Workloads.Reader"])
    resp = client.get("/api/workloads", headers=_bearer(token))
    assert resp.status_code == 200


def test_get_with_operator_token_is_allowed(auth_on) -> None:
    client, factory, _store = auth_on
    token = factory.mint(roles=["Workloads.Operator"])
    assert client.get("/api/workloads", headers=_bearer(token)).status_code == 200


# --------------------------------------------------------------------------------------
# Audit actor comes from the VALIDATED oid — the spoofable header is ignored.
# --------------------------------------------------------------------------------------
def test_audit_actor_derives_from_validated_oid_not_spoofed_header(auth_on) -> None:
    client, factory, store = auth_on
    token = factory.mint(roles=["Workloads.Operator"])
    # Attacker also supplies the raw principal-id header trying to forge the audit actor.
    headers = _bearer(token) | {PRINCIPAL_ID_HEADER: "attacker-supplied-oid"}
    resp = client.post("/api/workloads/epic/estate", json=_NODES, headers=headers)
    assert resp.status_code == 200
    events = store.list_audit()
    assert events, "estate write must have emitted an audit event"
    actors = {e.actor for e in events}
    assert actors == {FAKE_OID}
    assert "attacker-supplied-oid" not in actors


def test_no_auth_path_falls_back_to_header_actor(auth_off) -> None:
    client, store = auth_off
    headers = {PRINCIPAL_ID_HEADER: "obj-worker-123"}
    resp = client.post("/api/workloads/epic/estate", json=_NODES, headers=headers)
    assert resp.status_code == 200
    events = store.list_audit()
    assert events and {e.actor for e in events} == {"obj-worker-123"}


def test_no_auth_path_without_header_is_system_actor(auth_off) -> None:
    client, store = auth_off
    resp = client.post("/api/workloads/epic/estate", json=_NODES)
    assert resp.status_code == 200
    events = store.list_audit()
    assert events and {e.actor for e in events} == {SYSTEM_ACTOR}


# --------------------------------------------------------------------------------------
# Error bodies never leak the token or PII.
# --------------------------------------------------------------------------------------
def test_401_body_does_not_leak_token(auth_on) -> None:
    client, factory, _store = auth_on
    token = factory.mint(roles=["Workloads.Operator"], audience="api://wrong")
    resp = client.post("/api/workloads/epic/estate", json=_NODES, headers=_bearer(token))
    assert resp.status_code == 401
    body = resp.text
    assert token not in body
    assert FAKE_OID not in body
    assert resp.json()["detail"] == "authentication failed"


def test_403_body_does_not_leak_principal(auth_on) -> None:
    client, factory, _store = auth_on
    token = factory.mint(roles=["Workloads.Reader"])
    resp = client.post("/api/workloads/epic/estate", json=_NODES, headers=_bearer(token))
    assert resp.status_code == 403
    assert FAKE_OID not in resp.text
    assert resp.json()["detail"] == "insufficient role"


def test_all_mutating_post_endpoints_require_operator(auth_on) -> None:
    """Every state-mutating POST must reject a Reader token (deny-by-default across the surface)."""
    client, factory, _store = auth_on
    reader = factory.mint(roles=["Workloads.Reader"])
    h = _bearer(reader)
    graph = {"nodes": _NODES, "edges": []}
    findings = [
        {"id": "f1", "module": "quality_checks", "title": "t", "passed": False,
         "severity": "high", "nodeId": "vm1", "packId": "p", "packVersion": "1.0.0",
         "evidence": [{"kind": "resource", "id": "vm1"}]}
    ]
    result = {"module": "quality_checks", "ok": True}
    assert client.post("/api/workloads/epic/estate", json=_NODES, headers=h).status_code == 403
    assert client.post("/api/workloads/epic/graph", json=graph, headers=h).status_code == 403
    assert client.post("/api/workloads/epic/findings", json=findings, headers=h).status_code == 403
    assert client.post("/api/workloads/epic/snapshot", headers=h).status_code == 403
    assert client.post("/api/workloads/epic/results", json=result, headers=h).status_code == 403
    assert client.post(
        "/api/modules/quality_checks/run", json={"scope": {}}, headers=h
    ).status_code == 403


# --------------------------------------------------------------------------------------
# Fail-closed startup — a deployed API must REFUSE to serve when required + unconfigured (#64).
# --------------------------------------------------------------------------------------
def test_startup_refuses_when_required_but_unconfigured(monkeypatch) -> None:
    """mode=required (default) + no tenant/audience ⇒ the startup guard aborts (never wide-open)."""
    monkeypatch.setenv(ENV_MODE, "required")
    monkeypatch.delenv(ENV_TENANT_ID, raising=False)
    monkeypatch.delenv(ENV_AUDIENCE, raising=False)
    app.dependency_overrides.clear()
    with pytest.raises(AuthConfigError), TestClient(app):
        pass
    app.dependency_overrides.clear()


def test_startup_refuses_on_partial_config(monkeypatch) -> None:
    """A partial config (tenant present, audience blank) always aborts startup, in any mode."""
    monkeypatch.setenv(ENV_MODE, "required")
    monkeypatch.setenv(ENV_TENANT_ID, "00000000-0000-0000-0000-000000000000")
    monkeypatch.delenv(ENV_AUDIENCE, raising=False)
    app.dependency_overrides.clear()
    with pytest.raises(AuthConfigError), TestClient(app):
        pass
    app.dependency_overrides.clear()


def test_startup_permits_when_mode_disabled(monkeypatch) -> None:
    """mode=disabled is the deliberate no-auth opt-out ⇒ startup succeeds and serves."""
    monkeypatch.setenv(ENV_MODE, "disabled")
    monkeypatch.delenv(ENV_TENANT_ID, raising=False)
    monkeypatch.delenv(ENV_AUDIENCE, raising=False)
    app.dependency_overrides.clear()
    with TestClient(app) as client:
        assert client.get("/api/health").status_code == 200
    app.dependency_overrides.clear()
