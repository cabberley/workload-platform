"""API-level per-tenant module + pack-import isolation tests (issue #68).

Drives the real FastAPI app with a ``TestClient`` over a 2-tenant MSP overlay (auth ON, multi mode,
A/B allowlist) wired with a REAL ``PacksEngine`` (registry + digest-addressed content store + a
pinned Ed25519 trust root). Proves the two isolation guarantees end to end:

* **Per-tenant module enable/disable** — a module disabled by tenant A is reported disabled and
  fails closed (403) at the run surface FOR A ONLY, while tenant B (which set no config) keeps the
  default-enabled behaviour; the disabled-set is per-tenant and never leaks across tenants.
* **Per-tenant custom pack import** — a pack imported by tenant A is visible and assignable ONLY to
  tenant A; tenant B never sees it in its catalogue and cannot assign it (fail closed).

All fixtures are synthetic (no PHI/PII, no secrets, no real Entra; the Ed25519 keypair is ephemeral
and in-process).
"""
from __future__ import annotations

import base64
import copy
from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.app.main import (
    app,
    get_auth_validator,
    get_clients,
    get_pack_content_store,
    get_pack_import_verifier,
    get_pack_registry,
    get_packs,
    get_store,
    get_tenancy_config,
)
from api.app.tenancy import build_tenancy_config
from packs_engine.content_store import LocalPackContentStore
from packs_engine.engine import PacksEngine
from packs_engine.registry import PackRegistry
from shared.contracts import TrustBundle, TrustedPublicKey
from shared.signing import ED25519_ALG, Ed25519Signer, TrustBundleVerifier, sign_pack
from shared.state import LocalStateStore
from support.auth import FAKE_ISSUER, TokenFactory, build_test_validator

VM_TYPE = "Microsoft.Compute/virtualMachines"
TENANT_A = "00000000-0000-0000-0000-00000000000a"
TENANT_B = "00000000-0000-0000-0000-00000000000b"


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _op_token(factory: TokenFactory, tid: str) -> str:
    return factory.mint(roles=["Workloads.Operator"], tid=tid, issuer=FAKE_ISSUER)


def _trust_verifier(signer: Ed25519Signer) -> TrustBundleVerifier:
    pub = signer.verifier().public_bytes()
    bundle = TrustBundle(
        keys=[
            TrustedPublicKey(
                key_id=signer.key_id,
                algorithm=ED25519_ALG,
                public_key=base64.b64encode(pub).decode("ascii"),
            )
        ]
    )
    return TrustBundleVerifier.from_bundle(bundle)


def _importable_pack(pack_id: str = "epic-core", version: str = "1.0.0") -> dict[str, Any]:
    return {
        "manifest": {
            "id": pack_id,
            "type": "workload",
            "name": pack_id,
            "version": version,
            "targets": ["epic"],
            "author": "microsoft",
        },
        "body": {"workload": "epic", "x": 1},
    }


def _signed_bundle(pack: dict[str, Any], signer: Ed25519Signer) -> dict[str, Any]:
    signed = copy.deepcopy(pack)
    signed["manifest"]["pack_signature"] = sign_pack(signed, signer).model_dump()
    return {"pack": signed}


@pytest.fixture
def overlay(tmp_path):
    """Auth ENABLED + multi tenancy over an isolated store, wired with a real PacksEngine."""
    factory = TokenFactory()
    store = LocalStateStore(str(tmp_path / "state"))
    validator = build_test_validator(factory)
    config = build_tenancy_config(
        {"WP_TENANCY_MODE": "multi", "WP_ALLOWED_TENANTS": f"{TENANT_A},{TENANT_B}"}
    )
    # A real engine so an imported pack resolves end-to-end; empty registry/content root ⇒ no
    # built-in/shared packs, so the catalogue is exactly each tenant's OWN imports.
    root = tmp_path / "content"
    root.mkdir()
    registry = PackRegistry(str(root / "registry" / "index.json"))
    content_store = LocalPackContentStore(str(tmp_path / "store"))
    signer = Ed25519Signer.generate("test-kid")
    verifier = _trust_verifier(signer)
    engine = PacksEngine(
        root, registry=registry, content_store=content_store, import_verifier=verifier
    )

    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_auth_validator] = lambda: validator
    app.dependency_overrides[get_tenancy_config] = lambda: config
    app.dependency_overrides[get_packs] = lambda: engine
    app.dependency_overrides[get_clients] = lambda: {}
    app.dependency_overrides[get_pack_registry] = lambda: registry
    app.dependency_overrides[get_pack_content_store] = lambda: content_store
    app.dependency_overrides[get_pack_import_verifier] = lambda: verifier
    with TestClient(app) as client:
        yield client, factory, signer
    app.dependency_overrides.clear()


@pytest.fixture
def overlay_with_shared_pack(tmp_path):
    """Like :func:`overlay`, but the shared registry holds a built-in pack ``shared-baseline``.

    Publishing a SIGNED entry to the registry makes ``shared-baseline`` a built-in/shared pack the
    catalogue surfaces and the engine reserves (``reserved_pack_ids``), so a tenant import reusing
    that id must be rejected (disjoint id-space, FIX 3).
    """
    factory = TokenFactory()
    store = LocalStateStore(str(tmp_path / "state"))
    validator = build_test_validator(factory)
    config = build_tenancy_config(
        {"WP_TENANCY_MODE": "multi", "WP_ALLOWED_TENANTS": f"{TENANT_A},{TENANT_B}"}
    )
    root = tmp_path / "content"
    root.mkdir()
    registry = PackRegistry(str(root / "registry" / "index.json"))
    content_store = LocalPackContentStore(str(tmp_path / "store"))
    signer = Ed25519Signer.generate("test-kid")
    verifier = _trust_verifier(signer)
    engine = PacksEngine(
        root, registry=registry, content_store=content_store, import_verifier=verifier
    )
    # Publish a SIGNED shared/built-in pack into the registry so its id is reserved platform-wide.
    shared_source = _importable_pack(pack_id="shared-baseline")
    registry.publish(shared_source, signature=sign_pack(shared_source, signer))

    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_auth_validator] = lambda: validator
    app.dependency_overrides[get_tenancy_config] = lambda: config
    app.dependency_overrides[get_packs] = lambda: engine
    app.dependency_overrides[get_clients] = lambda: {}
    app.dependency_overrides[get_pack_registry] = lambda: registry
    app.dependency_overrides[get_pack_content_store] = lambda: content_store
    app.dependency_overrides[get_pack_import_verifier] = lambda: verifier
    with TestClient(app) as client:
        yield client, factory, signer
    app.dependency_overrides.clear()


# --------------------------------------------------------------------------------------
# Per-tenant module enable/disable.
# --------------------------------------------------------------------------------------
def test_module_config_is_per_tenant_and_isolated(overlay) -> None:
    client, factory, _signer = overlay
    a = _bearer(_op_token(factory, TENANT_A))
    b = _bearer(_op_token(factory, TENANT_B))

    # Tenant A disables quality_checks; tenant B sets nothing.
    assert client.put(
        "/api/modules/config", json={"disabled": ["quality_checks"]}, headers=a
    ).status_code == 200

    # GET config is per-tenant: A sees its disable, B sees an empty set (default-enabled).
    assert client.get("/api/modules/config", headers=a).json() == {"disabled": ["quality_checks"]}
    assert client.get("/api/modules/config", headers=b).json() == {"disabled": []}


def test_list_modules_reflects_per_tenant_disable(overlay) -> None:
    client, factory, _signer = overlay
    a = _bearer(_op_token(factory, TENANT_A))
    b = _bearer(_op_token(factory, TENANT_B))
    client.put("/api/modules/config", json={"disabled": ["quality_checks"]}, headers=a)

    def _enabled(headers: dict[str, str], name: str) -> bool:
        mods = client.get("/api/modules", headers=headers).json()
        return next(m["enabled"] for m in mods if m["name"] == name)

    # Same catalogue, DIFFERENT effective enablement per tenant.
    assert _enabled(a, "quality_checks") is False
    assert _enabled(b, "quality_checks") is True
    # A non-disabled module stays enabled for both.
    assert _enabled(a, "discovery") is True
    assert _enabled(b, "discovery") is True


def test_disabled_module_run_fails_closed_403_for_that_tenant_only(overlay) -> None:
    client, factory, _signer = overlay
    a = _bearer(_op_token(factory, TENANT_A))
    b = _bearer(_op_token(factory, TENANT_B))
    client.put("/api/modules/config", json={"disabled": ["quality_checks"]}, headers=a)

    # Tenant A: the disabled module is unusable — 403 fixed reason, BEFORE any run/write.
    denied = client.post("/api/modules/quality_checks/run", json={"scope": {}}, headers=a)
    assert denied.status_code == 403
    assert "disabled" in denied.json()["detail"].lower()
    # The fail-closed body carries no tenant id / token (issue #96 / no-PII).
    assert TENANT_A not in denied.text

    # Tenant B (default-enabled) can still run the SAME module.
    allowed = client.post("/api/modules/quality_checks/run", json={"scope": {}}, headers=b)
    assert allowed.status_code == 200


def test_module_config_rejects_unknown_module_fail_closed(overlay) -> None:
    client, factory, _signer = overlay
    a = _bearer(_op_token(factory, TENANT_A))
    resp = client.put("/api/modules/config", json={"disabled": ["not_a_module"]}, headers=a)
    assert resp.status_code == 422
    assert "unknown module" in resp.json()["detail"].lower()
    # Nothing was persisted — the tenant is still default-enabled.
    assert client.get("/api/modules/config", headers=a).json() == {"disabled": []}


def test_re_enabling_a_module_restores_run(overlay) -> None:
    client, factory, _signer = overlay
    a = _bearer(_op_token(factory, TENANT_A))
    client.put("/api/modules/config", json={"disabled": ["quality_checks"]}, headers=a)
    assert client.post(
        "/api/modules/quality_checks/run", json={"scope": {}}, headers=a
    ).status_code == 403
    # Clear the disabled set ⇒ the module is usable again (replace semantics).
    client.put("/api/modules/config", json={"disabled": []}, headers=a)
    assert client.post(
        "/api/modules/quality_checks/run", json={"scope": {}}, headers=a
    ).status_code == 200


# --------------------------------------------------------------------------------------
# Per-tenant custom pack import.
# --------------------------------------------------------------------------------------
def _import_ids(client: TestClient, headers: dict[str, str]) -> set[tuple[str, str]]:
    return {(p["id"], p["version"]) for p in client.get("/api/packs", headers=headers).json()}


def test_imported_pack_is_visible_only_to_importing_tenant(overlay) -> None:
    client, factory, signer = overlay
    a = _bearer(_op_token(factory, TENANT_A))
    b = _bearer(_op_token(factory, TENANT_B))

    # Tenant A imports a signed pack.
    resp = client.post(
        "/api/packs/import", json=_signed_bundle(_importable_pack(), signer), headers=a
    )
    assert resp.status_code == 200, resp.text

    # Visible ONLY to tenant A; tenant B's catalogue never shows it (deny-by-default).
    assert ("epic-core", "1.0.0") in _import_ids(client, a)
    assert ("epic-core", "1.0.0") not in _import_ids(client, b)
    assert _import_ids(client, b) == set()


def test_tenant_b_cannot_assign_tenant_a_import_fail_closed(overlay) -> None:
    client, factory, signer = overlay
    a = _bearer(_op_token(factory, TENANT_A))
    b = _bearer(_op_token(factory, TENANT_B))

    # Tenant A imports the pack; tenant B seeds a workload of the SAME name.
    assert client.post(
        "/api/packs/import", json=_signed_bundle(_importable_pack(), signer), headers=a
    ).status_code == 200
    nodes = [{"id": "vm-b", "name": "vm-b", "type": VM_TYPE, "tags": {}}]
    assert client.post("/api/workloads/epic/estate", json=nodes, headers=b).status_code == 200

    # Tenant B cannot assign a pack it cannot see — fail closed (422), NOT another tenant's import.
    assign = client.put(
        "/api/workloads/epic/pack-assignments",
        json={"packId": "epic-core", "version": "1.0.0"},
        headers=b,
    )
    assert assign.status_code == 422
    assert "visible to this tenant" in assign.json()["detail"].lower()


def test_importing_tenant_can_assign_its_own_import(overlay) -> None:
    client, factory, signer = overlay
    a = _bearer(_op_token(factory, TENANT_A))
    # Import a signed rule pack (its own id namespace) and seed A's workload.
    assert client.post(
        "/api/packs/import", json=_signed_bundle(_importable_pack(), signer), headers=a
    ).status_code == 200
    nodes = [{"id": "vm-a", "name": "vm-a", "type": VM_TYPE, "tags": {}}]
    assert client.post("/api/workloads/epic/estate", json=nodes, headers=a).status_code == 200
    # Tenant A CAN assign its own visible, verified import.
    assign = client.put(
        "/api/workloads/epic/pack-assignments",
        json={"packId": "epic-core", "version": "1.0.0"},
        headers=a,
    )
    assert assign.status_code == 200, assign.text


def test_same_id_version_imported_by_both_tenants_is_disjoint(overlay) -> None:
    client, factory, signer = overlay
    a = _bearer(_op_token(factory, TENANT_A))
    b = _bearer(_op_token(factory, TENANT_B))
    # Both tenants import the SAME id@version — each sees exactly one, its own (no collision).
    for headers in (a, b):
        assert client.post(
            "/api/packs/import", json=_signed_bundle(_importable_pack(), signer), headers=headers
        ).status_code == 200
    assert _import_ids(client, a) == {("epic-core", "1.0.0")}
    assert _import_ids(client, b) == {("epic-core", "1.0.0")}


# --------------------------------------------------------------------------------------
# Atomic per-tenant version immutability (FIX 2, issue #68).
# --------------------------------------------------------------------------------------
def test_reimport_same_id_version_same_content_is_idempotent(overlay) -> None:
    client, factory, signer = overlay
    a = _bearer(_op_token(factory, TENANT_A))
    bundle = _signed_bundle(_importable_pack(), signer)
    first = client.post("/api/packs/import", json=bundle, headers=a)
    assert first.status_code == 200, first.text
    # Re-importing the IDENTICAL id@version + content is idempotent (200), not a conflict, and the
    # stored digest/createdAt are unchanged (first-writer preserved).
    second = client.post("/api/packs/import", json=bundle, headers=a)
    assert second.status_code == 200, second.text
    assert second.json()["digest"] == first.json()["digest"]
    assert second.json()["createdAt"] == first.json()["createdAt"]
    assert _import_ids(client, a) == {("epic-core", "1.0.0")}


def test_reimport_same_id_version_different_content_conflicts_409(overlay) -> None:
    client, factory, signer = overlay
    a = _bearer(_op_token(factory, TENANT_A))
    first_pack = _importable_pack()
    first_pack["body"] = {"workload": "epic", "x": 1}
    assert client.post(
        "/api/packs/import", json=_signed_bundle(first_pack, signer), headers=a
    ).status_code == 200
    first_digest = next(
        p["digest"] for p in client.get("/api/packs", headers=a).json() if p["id"] == "epic-core"
    )
    # A DIFFERENT-content import of the SAME id@version is an immutable-version conflict (409); the
    # FIRST content is preserved (never overwritten).
    second_pack = _importable_pack()
    second_pack["body"] = {"workload": "epic", "x": 999}
    conflict = client.post(
        "/api/packs/import", json=_signed_bundle(second_pack, signer), headers=a
    )
    assert conflict.status_code == 409
    assert "immutable version conflict" in conflict.json()["detail"].lower()
    preserved = next(
        p["digest"] for p in client.get("/api/packs", headers=a).json() if p["id"] == "epic-core"
    )
    assert preserved == first_digest  # first content preserved


# --------------------------------------------------------------------------------------
# Disjoint id-space — a tenant import may never take a shipped/shared pack id (FIX 3, issue #68).
# --------------------------------------------------------------------------------------
def test_import_colliding_with_shared_pack_id_is_rejected_409(overlay_with_shared_pack) -> None:
    client, factory, signer = overlay_with_shared_pack
    a = _bearer(_op_token(factory, TENANT_A))
    # ``shared-baseline`` is published to the shared registry (built-in/shared). A tenant import
    # reusing that id would be admitted+assignable yet silently resolve to NOTHING at runtime
    # (shipped-wins-by-id) — so it is rejected up front (409, fixed reason), keeping the
    # tenant-import id-space DISJOINT from shipped/shared.
    collide = client.post(
        "/api/packs/import",
        json=_signed_bundle(_importable_pack(pack_id="shared-baseline"), signer),
        headers=a,
    )
    assert collide.status_code == 409
    assert "reserved by a platform pack" in collide.json()["detail"].lower()
    # The catalogue still shows shared-baseline exactly once (the SHARED pack), signed by the
    # platform key — the rejected import recorded nothing (admission fails before any store write).
    catalogue = client.get("/api/packs", headers=a).json()
    baseline = [p for p in catalogue if p["id"] == "shared-baseline"]
    assert len(baseline) == 1 and baseline[0]["signed"] is True


def test_disjoint_id_import_still_works_end_to_end(overlay_with_shared_pack) -> None:
    client, factory, signer = overlay_with_shared_pack
    a = _bearer(_op_token(factory, TENANT_A))
    # A tenant import in its OWN (disjoint) id-space imports, lists, assigns AND resolves.
    assert client.post(
        "/api/packs/import", json=_signed_bundle(_importable_pack(pack_id="tenant-own"), signer),
        headers=a,
    ).status_code == 200
    assert ("tenant-own", "1.0.0") in _import_ids(client, a)
    nodes = [{"id": "vm-a", "name": "vm-a", "type": VM_TYPE, "tags": {}}]
    assert client.post("/api/workloads/epic/estate", json=nodes, headers=a).status_code == 200
    assign = client.put(
        "/api/workloads/epic/pack-assignments",
        json={"packId": "tenant-own", "version": "1.0.0"},
        headers=a,
    )
    assert assign.status_code == 200, assign.text


@pytest.fixture
def overlay_registry_no_engine(tmp_path):
    """Auth+multi overlay with a wired SHARED ``PackRegistry`` (holding ``shared-baseline``) but NO
    ``PacksEngine`` (``get_packs`` yields None).

    Proves the reserved-id set is engine-INDEPENDENT: even without an engine, the shared on-disk
    registry ids must still be reserved at import admission (MED-1 completion, issue #68).
    """
    factory = TokenFactory()
    store = LocalStateStore(str(tmp_path / "state"))
    validator = build_test_validator(factory)
    config = build_tenancy_config(
        {"WP_TENANCY_MODE": "multi", "WP_ALLOWED_TENANTS": f"{TENANT_A},{TENANT_B}"}
    )
    root = tmp_path / "content"
    root.mkdir()
    registry = PackRegistry(str(root / "registry" / "index.json"))
    content_store = LocalPackContentStore(str(tmp_path / "store"))
    signer = Ed25519Signer.generate("test-kid")
    verifier = _trust_verifier(signer)
    # The shared registry holds a built-in/shared pack id, but NO engine is wired.
    shared_source = _importable_pack(pack_id="shared-baseline")
    registry.publish(shared_source, signature=sign_pack(shared_source, signer))

    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_auth_validator] = lambda: validator
    app.dependency_overrides[get_tenancy_config] = lambda: config
    app.dependency_overrides[get_packs] = lambda: None
    app.dependency_overrides[get_clients] = lambda: {}
    app.dependency_overrides[get_pack_registry] = lambda: registry
    app.dependency_overrides[get_pack_content_store] = lambda: content_store
    app.dependency_overrides[get_pack_import_verifier] = lambda: verifier
    with TestClient(app) as client:
        yield client, factory, signer
    app.dependency_overrides.clear()


def test_shared_registry_id_reserved_without_engine_409(overlay_registry_no_engine) -> None:
    client, factory, signer = overlay_registry_no_engine
    a = _bearer(_op_token(factory, TENANT_A))
    # With NO PacksEngine wired, a tenant import reusing a SHARED-registry id must STILL be rejected
    # (the reserved set unions the shared on-disk registry ids, engine-independent) — else the
    # disjoint-id / successful-but-unusable-assignment defect re-opens.
    collide = client.post(
        "/api/packs/import",
        json=_signed_bundle(_importable_pack(pack_id="shared-baseline"), signer),
        headers=a,
    )
    assert collide.status_code == 409
    assert "reserved by a platform pack" in collide.json()["detail"].lower()


def test_disjoint_id_import_and_assign_without_engine(overlay_registry_no_engine) -> None:
    client, factory, signer = overlay_registry_no_engine
    a = _bearer(_op_token(factory, TENANT_A))
    # A disjoint id still imports, lists and assigns even without an engine (runtime resolution
    # needs an engine and is covered by the real-engine end-to-end test).
    assert client.post(
        "/api/packs/import", json=_signed_bundle(_importable_pack(pack_id="tenant-own"), signer),
        headers=a,
    ).status_code == 200
    assert ("tenant-own", "1.0.0") in _import_ids(client, a)
    nodes = [{"id": "vm-a", "name": "vm-a", "type": VM_TYPE, "tags": {}}]
    assert client.post("/api/workloads/epic/estate", json=nodes, headers=a).status_code == 200
    assign = client.put(
        "/api/workloads/epic/pack-assignments",
        json={"packId": "tenant-own", "version": "1.0.0"},
        headers=a,
    )
    assert assign.status_code == 200, assign.text
