"""Integration tests for the customer pack lifecycle (issue #37).

Drives the FastAPI core with a ``TestClient`` and the dependency-override pattern (isolated store,
tmp-path pack registry, injected Ed25519 trust root). Proves the guardrails end-to-end:

  * import is **fail-closed** — a tampered, unsigned, or untrusted bundle is rejected 400 and never
    reaches the registry; a properly signed bundle verifies, is published, and appears in the
    registry (single-writer via the API core);
  * assignment is **single-writer with provenance** — PUT records ``assignedBy``/``assignedAt`` and
    the GET/list read models expose it for MS + customer visibility;
  * module runs **resolve the assigned pack version**, and an unassigned workload **falls back** to
    today's behavior (all target-matching packs) — a run never fails merely because nothing is
    assigned.

All fixtures are synthetic, clearly-fake resources — no PHI/PII, no secrets (the Ed25519 keypair
is ephemeral and in-process).
"""
from __future__ import annotations

import copy
from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.app.main import (
    app,
    get_clients,
    get_pack_registry,
    get_pack_verifier,
    get_packs,
    get_store,
)
from packs_engine.engine import Pack
from packs_engine.registry import PackRef, PackRegistry
from shared.contracts import PackManifest, PackType
from shared.signing import Ed25519Signer, sign_pack
from shared.state import LocalStateStore

VM_TYPE = "Microsoft.Compute/virtualMachines"


# --------------------------------------------------------------------------------------
# Fakes + synthetic fixtures.
# --------------------------------------------------------------------------------------
class FakePacks:
    """Stand-in packs engine returning pre-built, already-'verified' packs (target-aware)."""

    def __init__(self, packs: list[Pack]) -> None:
        self._packs = packs

    def load_for_workload(self, workload: str, pack_type: PackType) -> list[Pack]:
        return [
            p
            for p in self._packs
            if p.manifest.type == pack_type
            and (not p.manifest.targets or workload in p.manifest.targets)
        ]


def _rule_pack(
    version: str, rule_id: str, required_tag: str, pack_id: str = "waf-reliability-baseline"
) -> Pack:
    manifest = PackManifest(
        id=pack_id,
        type=PackType.rule,
        name="WAF Reliability",
        version=version,
        targets=["epic"],
    )
    body: dict[str, Any] = {
        "rules": [
            {
                "id": rule_id,
                "title": f"rule {rule_id}",
                "resourceType": VM_TYPE,
                "requiredTag": required_tag,
                "severity": "high",
            }
        ]
    }
    return Pack(manifest=manifest, body=body)


def _registry_pack_dict(pack_id: str, version: str, pack_type: str = "rule") -> dict[str, Any]:
    """A minimal synthetic pack dict for seeding the registry via ``publish`` (verified content)."""
    return {
        "manifest": {
            "id": pack_id,
            "type": pack_type,
            "name": pack_id,
            "version": version,
            "targets": ["epic"],
            "author": "microsoft",
        },
        "body": {"rules": []},
    }


def _importable_pack(version: str = "1.0.0", *, body_x: int = 1) -> dict[str, Any]:
    """A minimal, synthetic pack dict suitable for the registry's ``publish``."""
    return {
        "manifest": {
            "id": "epic-core",
            "type": "workload",
            "name": "Epic core",
            "version": version,
            "targets": ["epic"],
            "author": "microsoft",
        },
        "body": {"workload": "epic", "x": body_x},
    }


@pytest.fixture
def wired(tmp_path):
    """TestClient with isolated store + tmp registry + injected Ed25519 trust root."""
    store = LocalStateStore(str(tmp_path / "state"))
    rule_packs = [
        _rule_pack("1.0.0", "rule-v1", "tag-v1"),
        _rule_pack("2.0.0", "rule-v2", "tag-v2"),
    ]
    packs = FakePacks(rule_packs)
    registry = PackRegistry(str(tmp_path / "registry" / "index.json"))
    # Seed the registry with the VERIFIED digests of the exact packs the engine serves, so an
    # assignment (bound to a verified registry entry at write time) resolves at run time ONLY when
    # a content pack's canonical digest matches the registry's verified digest (issue #37).
    for _p in rule_packs:
        registry.publish(_p.source)
    signer = Ed25519Signer.generate("test-kid")

    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_packs] = lambda: packs
    app.dependency_overrides[get_clients] = lambda: {}
    app.dependency_overrides[get_pack_registry] = lambda: registry
    app.dependency_overrides[get_pack_verifier] = lambda: signer.verifier()
    with TestClient(app) as client:
        yield client, store, registry, signer
    app.dependency_overrides.clear()


def _signed_bundle(pack: dict[str, Any], signer: Ed25519Signer) -> dict[str, Any]:
    signature = sign_pack(pack, signer)
    return {"pack": pack, "signature": signature.model_dump()}


def _seed_untagged_vm(client: TestClient, workload: str) -> None:
    nodes = [{"id": "vm-bad", "name": "vm-bad", "type": VM_TYPE, "tags": {}}]
    assert client.post(f"/api/workloads/{workload}/estate", json=nodes).status_code == 200


# --------------------------------------------------------------------------------------
# Import — fail-closed verification, then publish into the registry (single writer).
# --------------------------------------------------------------------------------------
def test_import_verifies_and_registers_signed_bundle(wired):
    client, _store, registry, signer = wired
    pack = _importable_pack("1.0.0")

    resp = client.post("/api/packs/import", json=_signed_bundle(pack, signer))
    assert resp.status_code == 200, resp.text
    entry = resp.json()
    assert entry["id"] == "epic-core"
    assert entry["version"] == "1.0.0"
    assert entry["type"] == "workload"

    # The API is the single writer of the registry: the verified version is now published.
    assert registry.get(PackRef(id="epic-core", version="1.0.0")) is not None


def test_import_rejects_tampered_bundle_fail_closed(wired):
    client, _store, registry, signer = wired
    pack = _importable_pack("1.0.0", body_x=1)
    bundle = _signed_bundle(pack, signer)
    # Tamper with the pack AFTER signing — the signature no longer covers these bytes.
    tampered = copy.deepcopy(bundle)
    tampered["pack"]["body"]["x"] = 999

    resp = client.post("/api/packs/import", json=tampered)
    assert resp.status_code == 400
    assert "signature" in resp.json()["detail"].lower() or "tamper" in resp.json()["detail"].lower()
    # Nothing was published — fail closed leaves the registry untouched.
    assert registry.get(PackRef(id="epic-core", version="1.0.0")) is None


def test_import_rejects_unsigned_bundle_fail_closed(wired):
    client, _store, registry, _signer = wired
    resp = client.post("/api/packs/import", json={"pack": _importable_pack("1.0.0")})
    assert resp.status_code == 400
    assert "unsigned" in resp.json()["detail"].lower()
    assert registry.get(PackRef(id="epic-core", version="1.0.0")) is None


def test_import_rejects_when_no_trust_root_configured_fail_closed(wired, tmp_path):
    client, _store, registry, signer = wired
    # No trust root: a present signature cannot be verified ⇒ import must fail closed.
    app.dependency_overrides[get_pack_verifier] = lambda: None
    pack = _importable_pack("1.0.0")
    resp = client.post("/api/packs/import", json=_signed_bundle(pack, signer))
    assert resp.status_code == 400
    assert "trust root" in resp.json()["detail"].lower()
    assert registry.get(PackRef(id="epic-core", version="1.0.0")) is None


def test_import_rejects_wrong_key_signature_fail_closed(wired):
    client, _store, registry, _signer = wired
    # A bundle signed by a DIFFERENT key than the injected trust root must not verify.
    other = Ed25519Signer.generate("attacker-kid")
    resp = client.post("/api/packs/import", json=_signed_bundle(_importable_pack("1.0.0"), other))
    assert resp.status_code == 400
    assert registry.get(PackRef(id="epic-core", version="1.0.0")) is None


def test_import_conflicting_version_is_rejected(wired):
    client, _store, _registry, signer = wired
    first = client.post(
        "/api/packs/import", json=_signed_bundle(_importable_pack("1.0.0", body_x=1), signer)
    )
    assert first.status_code == 200
    # Same id@version, different content ⇒ immutable-version conflict (409).
    resp = client.post(
        "/api/packs/import", json=_signed_bundle(_importable_pack("1.0.0", body_x=2), signer)
    )
    assert resp.status_code == 409
    # Re-importing IDENTICAL content is idempotent (200).
    resp2 = client.post(
        "/api/packs/import", json=_signed_bundle(_importable_pack("1.0.0", body_x=1), signer)
    )
    assert resp2.status_code == 200


# --------------------------------------------------------------------------------------
# Assignment — single writer, with provenance, visible to MS + customer.
# --------------------------------------------------------------------------------------
def test_put_and_get_pack_assignment_records_provenance(wired):
    client, _store, _registry, _signer = wired
    resp = client.put(
        "/api/workloads/epic/pack-assignments",
        json={"packId": "waf-reliability-baseline", "version": "1.0.0",
              "assignedBy": "customer@example.test"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["workload"] == "epic"
    assert body["packId"] == "waf-reliability-baseline"
    assert body["version"] == "1.0.0"
    assert body["assignedBy"] == "customer@example.test"
    assert body["assignedAt"]  # provenance timestamp set by the core

    got = client.get("/api/workloads/epic/pack-assignments").json()
    assert [(a["packId"], a["version"]) for a in got] == [("waf-reliability-baseline", "1.0.0")]


def test_put_assignment_replaces_prior_version(wired):
    client, _store, _registry, _signer = wired
    for v, who in (("1.0.0", "ms@example.test"), ("2.0.0", "customer@example.test")):
        assert client.put(
            "/api/workloads/epic/pack-assignments",
            json={"packId": "waf-reliability-baseline", "version": v, "assignedBy": who},
        ).status_code == 200
    got = client.get("/api/workloads/epic/pack-assignments").json()
    assert len(got) == 1
    assert got[0]["version"] == "2.0.0"
    assert got[0]["assignedBy"] == "customer@example.test"


def test_list_pack_assignments_spans_workloads(wired):
    client, _store, registry, _signer = wired
    # Both assigned versions must be verified registry entries first (fail-closed binding).
    registry.publish(_registry_pack_dict("rules", "2.0.0"))
    registry.publish(_registry_pack_dict("ops", "1.0.0"))
    client.put("/api/workloads/epic/pack-assignments",
               json={"packId": "rules", "version": "2.0.0", "assignedBy": "a@example.test"})
    client.put("/api/workloads/sap/pack-assignments",
               json={"packId": "ops", "version": "1.0.0", "assignedBy": "b@example.test"})
    listed = client.get("/api/pack-assignments").json()
    assert {(a["workload"], a["packId"]) for a in listed} == {("epic", "rules"), ("sap", "ops")}


def test_put_assignment_rejects_unverified_pack_fail_closed(wired):
    client, _store, _registry, _signer = wired
    # MED #1: an assignment may only ever point at a VERIFIED, imported registry entry. A pack
    # id@version that was never imported must be rejected (fail closed) and persist NOTHING —
    # otherwise a run could later resolve engine content that was never signature-verified.
    resp = client.put(
        "/api/workloads/epic/pack-assignments",
        json={"packId": "never-imported", "version": "9.9.9",
              "assignedBy": "attacker@example.test"},
    )
    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"].lower()
    assert "verified" in detail or "registry" in detail
    # Nothing was stored — the read models stay empty.
    assert client.get("/api/workloads/epic/pack-assignments").json() == []
    assert client.get("/api/pack-assignments").json() == []


def test_put_assignment_accepts_after_import_binds_to_verified_entry(wired):
    client, _store, registry, signer = wired
    # Import a signed bundle through the fail-closed flow so it lands (verified) in the registry.
    resp = client.post("/api/packs/import", json=_signed_bundle(_importable_pack("3.1.0"), signer))
    assert resp.status_code == 200, resp.text
    assert registry.get(PackRef(id="epic-core", version="3.1.0")) is not None
    # Now the assignment to that exact verified entry is accepted and stored.
    assign = client.put(
        "/api/workloads/epic/pack-assignments",
        json={"packId": "epic-core", "version": "3.1.0", "assignedBy": "ms@example.test"},
    )
    assert assign.status_code == 200, assign.text
    got = client.get("/api/workloads/epic/pack-assignments").json()
    assert [(a["packId"], a["version"]) for a in got] == [("epic-core", "3.1.0")]


# --------------------------------------------------------------------------------------
# Resolve-per-workload — a run uses the ASSIGNED version; unassigned falls back.
# --------------------------------------------------------------------------------------
def _run_pack_versions(client: TestClient, workload: str) -> set[str]:
    resp = client.post(
        "/api/modules/quality_checks/run", json={"scope": {"workload": workload}}
    )
    assert resp.status_code == 200, resp.text
    return {f["packVersion"] for f in resp.json()["findings"]}


def _run_pack_refs(client: TestClient, workload: str) -> set[tuple[str, str]]:
    resp = client.post(
        "/api/modules/quality_checks/run", json={"scope": {"workload": workload}}
    )
    assert resp.status_code == 200, resp.text
    return {(f["packId"], f["packVersion"]) for f in resp.json()["findings"]}


def test_unassigned_workload_resolves_single_latest_version(wired):
    client, _store, _registry, _signer = wired
    _seed_untagged_vm(client, "epic")
    # MED #2 / DOCUMENTED fallback: no assignment ⇒ the id resolves DETERMINISTICALLY to a SINGLE
    # highest-semver version (2.0.0), never every version — the run is still never blocked for lack
    # of an assignment, it just never runs multiple versions of one id.
    assert _run_pack_versions(client, "epic") == {"2.0.0"}


def test_two_ids_assigned_older_plus_unassigned_latest(tmp_path):
    # MED #2: with two pack ids — one assigned to an OLDER version, one unassigned — the assigned id
    # runs its pinned version and the unassigned id runs its latest. Neither runs multiple versions.
    store = LocalStateStore(str(tmp_path / "state"))
    rel_v1 = _rule_pack("1.0.0", "rel-v1", "tag-rel-v1", pack_id="waf-reliability-baseline")
    rule_packs = [
        rel_v1,
        _rule_pack("2.0.0", "rel-v2", "tag-rel-v2", pack_id="waf-reliability-baseline"),
        _rule_pack("1.0.0", "sec-v1", "tag-sec-v1", pack_id="waf-security-baseline"),
        _rule_pack("2.0.0", "sec-v2", "tag-sec-v2", pack_id="waf-security-baseline"),
    ]
    packs = FakePacks(rule_packs)
    registry = PackRegistry(str(tmp_path / "registry" / "index.json"))
    # Publish the assigned pack's VERIFIED digest (its source) so resolution runs those exact bytes.
    registry.publish(rel_v1.source)
    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_packs] = lambda: packs
    app.dependency_overrides[get_clients] = lambda: {}
    app.dependency_overrides[get_pack_registry] = lambda: registry
    try:
        with TestClient(app) as client:
            _seed_untagged_vm(client, "epic")
            assert client.put(
                "/api/workloads/epic/pack-assignments",
                json={"packId": "waf-reliability-baseline", "version": "1.0.0",
                      "assignedBy": "customer@example.test"},
            ).status_code == 200
            # Assigned id pinned to older 1.0.0; unassigned id resolves to its latest 2.0.0.
            assert _run_pack_refs(client, "epic") == {
                ("waf-reliability-baseline", "1.0.0"),
                ("waf-security-baseline", "2.0.0"),
            }
    finally:
        app.dependency_overrides.clear()


def test_run_assigned_pack_with_tampered_content_runs_nothing(tmp_path):
    # HIGH (security): if the content-root pack carrying the assigned id@version has a DIFFERENT
    # digest than the registry's verified digest (tampered/unrelated bytes), the assigned id runs
    # NOTHING — fail closed, never substituting another version.
    store = LocalStateStore(str(tmp_path / "state"))
    verified = _rule_pack("1.0.0", "rule-v1", "tag-v1")  # the bytes whose digest we register
    tampered = _rule_pack("1.0.0", "rule-tampered", "tag-tampered")  # same ref, different digest
    packs = FakePacks([tampered, _rule_pack("2.0.0", "rule-v2", "tag-v2")])
    registry = PackRegistry(str(tmp_path / "registry" / "index.json"))
    registry.publish(verified.source)
    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_packs] = lambda: packs
    app.dependency_overrides[get_clients] = lambda: {}
    app.dependency_overrides[get_pack_registry] = lambda: registry
    try:
        with TestClient(app) as client:
            _seed_untagged_vm(client, "epic")
            assert client.put(
                "/api/workloads/epic/pack-assignments",
                json={"packId": "waf-reliability-baseline", "version": "1.0.0",
                      "assignedBy": "customer@example.test"},
            ).status_code == 200
            # The assigned id's only content pack has a mismatched digest ⇒ it runs nothing, and no
            # other version is substituted ⇒ zero findings.
            assert _run_pack_refs(client, "epic") == set()
    finally:
        app.dependency_overrides.clear()


def test_run_resolves_the_assigned_pack_version(wired):
    client, _store, _registry, _signer = wired
    _seed_untagged_vm(client, "epic")
    assert client.put(
        "/api/workloads/epic/pack-assignments",
        json={"packId": "waf-reliability-baseline", "version": "1.0.0",
              "assignedBy": "customer@example.test"},
    ).status_code == 200

    # With an assignment, the run resolves ONLY the pinned version — v2.0.0 is filtered out.
    assert _run_pack_versions(client, "epic") == {"1.0.0"}

    # Re-pin to 2.0.0 and confirm the run now resolves that version instead.
    assert client.put(
        "/api/workloads/epic/pack-assignments",
        json={"packId": "waf-reliability-baseline", "version": "2.0.0",
              "assignedBy": "customer@example.test"},
    ).status_code == 200
    assert _run_pack_versions(client, "epic") == {"2.0.0"}
