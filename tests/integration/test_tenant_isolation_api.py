"""API-level tenant isolation tests (issue #65) — proves NO cross-tenant leakage over the real app.

Drives the real FastAPI app with a ``TestClient``, overriding ONLY the store, the auth validator,
and the tenancy config with injected, network-free values. Covers BOTH:

* the **single-tenant default** — the customer-owned instance keeps working with no tenancy config;
* the **2-tenant MSP overlay** — tenant A cannot read or write tenant B's state or read models, and
  a missing / off-allowlist / mismatched tenant **fails closed (403)**.

All fixtures are synthetic (no PHI/PII, no secrets, no real Entra).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.app.main import app, get_auth_validator, get_store, get_tenancy_config
from api.app.tenancy import build_tenancy_config
from shared.state import LocalStateStore
from support.auth import FAKE_ISSUER, TokenFactory, build_test_validator

VM_TYPE = "Microsoft.Compute/virtualMachines"
TENANT_A = "00000000-0000-0000-0000-00000000000a"
TENANT_B = "00000000-0000-0000-0000-00000000000b"
TENANT_C = "00000000-0000-0000-0000-00000000000c"  # never on any allowlist
HOST_TENANT = "00000000-0000-0000-0000-0000000000ff"  # the shared worker/host identity's tenant


def _nodes(node_id: str) -> list[dict]:
    return [{"id": node_id, "name": node_id, "type": VM_TYPE, "tags": {}}]


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --------------------------------------------------------------------------------------
# Single-tenant DEFAULT — backward-safe: no tenancy config, no auth, still round-trips.
# --------------------------------------------------------------------------------------
@pytest.fixture
def single_default(tmp_path):
    """Auth disabled + default tenancy config (single, implicit 'default' tenant)."""
    store = LocalStateStore(str(tmp_path))
    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_auth_validator] = lambda: None
    app.dependency_overrides[get_tenancy_config] = lambda: build_tenancy_config({})
    with TestClient(app) as client:
        yield client, store
    app.dependency_overrides.clear()


def test_single_tenant_default_round_trips(single_default) -> None:
    client, _store = single_default
    assert client.post("/api/workloads/epic/estate", json=_nodes("vm1")).status_code == 200
    resp = client.get("/api/workloads/epic/estate")
    assert resp.status_code == 200
    assert [n["id"] for n in resp.json()] == ["vm1"]
    assert client.get("/api/workloads").json() == ["epic"]


# --------------------------------------------------------------------------------------
# 2-tenant MSP overlay — auth on, multi mode with an A/B allowlist.
# --------------------------------------------------------------------------------------
@pytest.fixture
def overlay(tmp_path):
    """Auth ENABLED + multi tenancy over an isolated store; tokens carry a `tid` per tenant."""
    factory = TokenFactory()
    store = LocalStateStore(str(tmp_path))
    validator = build_test_validator(factory)
    config = build_tenancy_config(
        {"WP_TENANCY_MODE": "multi", "WP_ALLOWED_TENANTS": f"{TENANT_A},{TENANT_B}"}
    )
    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_auth_validator] = lambda: validator
    app.dependency_overrides[get_tenancy_config] = lambda: config
    with TestClient(app) as client:
        yield client, factory, store
    app.dependency_overrides.clear()


def _op_token(factory: TokenFactory, tid: str) -> str:
    return factory.mint(roles=["Workloads.Operator"], tid=tid, issuer=FAKE_ISSUER)


def test_overlay_estate_is_isolated_between_tenants(overlay) -> None:
    client, factory, _store = overlay
    a = _bearer(_op_token(factory, TENANT_A))
    b = _bearer(_op_token(factory, TENANT_B))

    # Both tenants write to the SAME workload name "epic" with different estates.
    r_a = client.post("/api/workloads/epic/estate", json=_nodes("vm-a"), headers=a)
    r_b = client.post("/api/workloads/epic/estate", json=_nodes("vm-b"), headers=b)
    assert r_a.status_code == 200
    assert r_b.status_code == 200

    # Each tenant reads back ONLY its own estate — no cross-tenant leakage.
    a_ids = [n["id"] for n in client.get("/api/workloads/epic/estate", headers=a).json()]
    b_ids = [n["id"] for n in client.get("/api/workloads/epic/estate", headers=b).json()]
    assert a_ids == ["vm-a"]
    assert b_ids == ["vm-b"]


def test_overlay_list_workloads_is_isolated(overlay) -> None:
    client, factory, _store = overlay
    a = _bearer(_op_token(factory, TENANT_A))
    b = _bearer(_op_token(factory, TENANT_B))
    client.post("/api/workloads/epic/estate", json=_nodes("vm-a"), headers=a)
    client.post("/api/workloads/citrix/estate", json=_nodes("vm-a2"), headers=a)
    client.post("/api/workloads/epic/estate", json=_nodes("vm-b"), headers=b)

    assert client.get("/api/workloads", headers=a).json() == ["citrix", "epic"]
    assert client.get("/api/workloads", headers=b).json() == ["epic"]


def test_overlay_tenant_b_cannot_read_tenant_a_only_workload(overlay) -> None:
    client, factory, _store = overlay
    a = _bearer(_op_token(factory, TENANT_A))
    b = _bearer(_op_token(factory, TENANT_B))
    client.post("/api/workloads/secret/estate", json=_nodes("vm-a"), headers=a)
    # Tenant B queries the same workload name — sees nothing (deny-by-default), never A's data.
    assert client.get("/api/workloads/secret/estate", headers=b).json() == []


def test_overlay_missing_tid_fails_closed(overlay) -> None:
    """multi overlay: a valid token with NO tid is denied (fail closed) — never a default."""
    client, factory, _store = overlay
    token = factory.mint(roles=["Workloads.Operator"])  # no tid
    resp = client.post("/api/workloads/epic/estate", json=_nodes("vm1"), headers=_bearer(token))
    assert resp.status_code == 403
    assert "tenant" in resp.json()["detail"].lower()


def test_overlay_offlist_tid_fails_closed(overlay) -> None:
    client, factory, _store = overlay
    token = _op_token(factory, TENANT_C)  # valid token, tenant not on the allowlist
    resp = client.post("/api/workloads/epic/estate", json=_nodes("vm1"), headers=_bearer(token))
    assert resp.status_code == 403


def test_overlay_host_worker_token_cannot_write_client_partition(overlay) -> None:
    """A shared-worker/host-identity token cannot silently write into a client tenant's partition.

    Regression guard for the multi-overlay worker path (ADR 0017 "Known limitation", follow-up
    #122): the worker runs as the platform identity, so its ``tid`` is the deployment/host tenant,
    which is NOT on the allowlist. Its Operator-role write is rejected (403) BEFORE any state is
    persisted, and a client tenant that shares the workload name still sees nothing written by the
    host token.
    """
    client, factory, _store = overlay
    host = _bearer(_op_token(factory, HOST_TENANT))
    resp = client.post("/api/workloads/epic/estate", json=_nodes("vm-host"), headers=host)
    assert resp.status_code == 403  # fail-closed: host tenant not on the client allowlist

    # And nothing leaked into a client tenant's partition for that shared workload name.
    a = _bearer(_op_token(factory, TENANT_A))
    assert client.get("/api/workloads/epic/estate", headers=a).json() == []
    assert client.get("/api/workloads", headers=a).json() == []


def test_overlay_read_with_missing_tid_fails_closed(overlay) -> None:
    client, factory, _store = overlay
    token = factory.mint(roles=["Workloads.Reader"])  # no tid
    assert client.get("/api/workloads", headers=_bearer(token)).status_code == 403


def test_overlay_fail_closed_body_has_no_pii(overlay) -> None:
    client, factory, _store = overlay
    token = _op_token(factory, TENANT_C)
    resp = client.post("/api/workloads/epic/estate", json=_nodes("vm1"), headers=_bearer(token))
    assert resp.status_code == 403
    assert TENANT_C not in resp.text
    assert token not in resp.text


# --------------------------------------------------------------------------------------
# Single mode with a configured tenant — a token for another directory is denied.
# --------------------------------------------------------------------------------------
@pytest.fixture
def single_configured(tmp_path):
    """Auth ENABLED + single mode pinned to TENANT_A."""
    factory = TokenFactory()
    store = LocalStateStore(str(tmp_path))
    validator = build_test_validator(factory)
    config = build_tenancy_config({"WP_TENANT_ID": TENANT_A})
    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_auth_validator] = lambda: validator
    app.dependency_overrides[get_tenancy_config] = lambda: config
    with TestClient(app) as client:
        yield client, factory, store
    app.dependency_overrides.clear()


def test_single_mode_matching_tid_is_allowed(single_configured) -> None:
    client, factory, _store = single_configured
    token = _op_token(factory, TENANT_A)
    resp = client.post("/api/workloads/epic/estate", json=_nodes("vm1"), headers=_bearer(token))
    assert resp.status_code == 200


def test_single_mode_mismatched_tid_fails_closed(single_configured) -> None:
    """A token minted for a DIFFERENT directory is denied in single mode (fail closed)."""
    client, factory, _store = single_configured
    token = _op_token(factory, TENANT_B)
    resp = client.post("/api/workloads/epic/estate", json=_nodes("vm1"), headers=_bearer(token))
    assert resp.status_code == 403
