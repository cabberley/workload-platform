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

import base64
import copy
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.app.main import (
    app,
    get_clients,
    get_pack_import_verifier,
    get_pack_registry,
    get_packs,
    get_store,
)
from packs_engine.canonical import canonical_bytes, canonical_digest
from packs_engine.content_store import LocalPackContentStore
from packs_engine.engine import Pack, PacksEngine
from packs_engine.registry import PackRef, PackRegistry
from shared.contracts import PackManifest, PackSignature, PackType, TrustBundle, TrustedPublicKey
from shared.signing import ED25519_ALG, Ed25519Signer, TrustBundleVerifier, sign_pack
from shared.state import LocalStateStore

VM_TYPE = "Microsoft.Compute/virtualMachines"


def _trust_verifier(signer: Ed25519Signer) -> TrustBundleVerifier:
    """A shared-trust-root verifier pinning ONLY ``signer``'s public key (mirrors #89 wiring).

    Import admission and the runtime resolver both verify against a :class:`TrustBundleVerifier`
    built from a pinned :class:`TrustBundle`; tests inject one pinning the ephemeral test key so a
    pack signed by that key is trusted and anything else (unsigned / unpinned key / tampered) fails
    closed — exactly as the real ``$WP_TRUST_BUNDLE_PATH`` bundle would.
    """
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


def _publish_signed(registry: PackRegistry, pack_source: dict[str, Any], signer: Ed25519Signer):
    """Publish a pack into the registry WITH a verified detached signature (issue #89, R2).

    The persisted signature makes ``entry.detached_signature()`` non-None and its ``key_id`` pinned,
    so both the runtime resolver and the assignment trust gate (FINDING B) accept the entry. The
    canonical digest excludes ``pack_signature``, so a signed publish keeps the SAME digest the
    engine's served content matches on.
    """
    return registry.publish(pack_source, signature=sign_pack(pack_source, signer))


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
    """TestClient with isolated store + tmp registry + injected SHARED trust-bundle verifier."""
    store = LocalStateStore(str(tmp_path / "state"))
    rule_packs = [
        _rule_pack("1.0.0", "rule-v1", "tag-v1"),
        _rule_pack("2.0.0", "rule-v2", "tag-v2"),
    ]
    packs = FakePacks(rule_packs)
    registry = PackRegistry(str(tmp_path / "registry" / "index.json"))
    signer = Ed25519Signer.generate("test-kid")
    # Seed the registry with the VERIFIED, SIGNED digests of the exact packs the engine serves, so
    # an assignment (bound to a signed+trusted registry entry at write time — FINDING B) resolves at
    # run time ONLY when a content pack's canonical digest matches the registry's verified digest
    # (issue #37/#89). Publishing WITH the signature is what makes the entry trusted/runnable.
    for _p in rule_packs:
        _publish_signed(registry, _p.source, signer)

    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_packs] = lambda: packs
    app.dependency_overrides[get_clients] = lambda: {}
    app.dependency_overrides[get_pack_registry] = lambda: registry
    app.dependency_overrides[get_pack_import_verifier] = lambda: _trust_verifier(signer)
    with TestClient(app) as client:
        yield client, store, registry, signer
    app.dependency_overrides.clear()


def _signed_bundle(pack: dict[str, Any], signer: Ed25519Signer) -> dict[str, Any]:
    """Return an import request body whose pack carries its detached signature EMBEDDED in the
    manifest (``manifest.pack_signature``) — the single source of truth the runtime also reads.

    There is no separate top-level ``signature`` field anymore (FINDING A): the client submits the
    signed pack itself. The signature covers canonical bytes (which exclude ``pack_signature``), so
    embedding it does not change what was signed.
    """
    signed = copy.deepcopy(pack)
    signed["manifest"]["pack_signature"] = sign_pack(signed, signer).model_dump()
    return {"pack": signed}


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
    # FIX 1: the verified detached signature is PERSISTED on the entry, so it is SIGNED (not
    # legacy-untrusted) — else the runtime resolver would fail it closed and it could never run.
    assert entry["signed"] is True

    # The API is the single writer of the registry: the verified version is now published.
    published = registry.get(PackRef(id="epic-core", version="1.0.0"))
    assert published is not None
    assert published.detached_signature() is not None  # signature durably recorded


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
    # An empty/reject-all trust bundle (no keys pinned): a present signature cannot verify against
    # any trusted key ⇒ import must fail closed (same reject-all default the real bundle uses until
    # Microsoft keys are pinned).
    app.dependency_overrides[get_pack_import_verifier] = TrustBundleVerifier.reject_all
    pack = _importable_pack("1.0.0")
    resp = client.post("/api/packs/import", json=_signed_bundle(pack, signer))
    assert resp.status_code == 400
    detail = resp.json()["detail"].lower()
    assert "trusted" in detail or "tampered" in detail
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
    _seed_untagged_vm(client, "epic")  # FIX 3: workload must exist in the tenant catalogue
    resp = client.put(
        "/api/workloads/epic/pack-assignments",
        json={"packId": "waf-reliability-baseline", "version": "1.0.0"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["workload"] == "epic"
    assert body["packId"] == "waf-reliability-baseline"
    assert body["version"] == "1.0.0"
    # FIX 4: assignedBy is DERIVED server-side from the authenticated principal — with auth disabled
    # and no principal header the audit-safe system actor is recorded (never a caller-supplied str).
    assert body["assignedBy"] == "system"
    assert body["assignedAt"]  # provenance timestamp set by the core

    got = client.get("/api/workloads/epic/pack-assignments").json()
    assert [(a["packId"], a["version"]) for a in got] == [("waf-reliability-baseline", "1.0.0")]


def test_put_assignment_derives_assignedby_from_principal_ignoring_client(wired):
    # FIX 4: assignedBy cannot be spoofed. A client-supplied assignedBy in the body is IGNORED, and
    # the value is derived from the authenticated principal's audit-safe id (the validated OID),
    # never a caller-supplied email/PII.
    client, _store, _registry, _signer = wired
    _seed_untagged_vm(client, "epic")
    resp = client.put(
        "/api/workloads/epic/pack-assignments",
        json={"packId": "waf-reliability-baseline", "version": "1.0.0",
              "assignedBy": "attacker@example.test"},
        headers={"x-ms-client-principal-id": "oid-1234"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["assignedBy"] == "oid-1234"  # principal-derived, NOT the spoofed email
    got = client.get("/api/workloads/epic/pack-assignments").json()
    assert got[0]["assignedBy"] == "oid-1234"


def test_put_assignment_rejects_unknown_workload_fail_closed(wired):
    # FIX 3: assigning to a workload that does not exist in the tenant catalogue is an unknown-
    # resource error — reject 404 (constant, PII-free detail) and persist NOTHING.
    client, _store, _registry, _signer = wired
    resp = client.put(
        "/api/workloads/ghost/pack-assignments",
        json={"packId": "waf-reliability-baseline", "version": "1.0.0"},
    )
    assert resp.status_code == 404, resp.text
    assert "unknown workload" in resp.json()["detail"].lower()
    assert "ghost" not in resp.json()["detail"]  # caller-controlled name never echoed
    assert client.get("/api/workloads/ghost/pack-assignments").json() == []
    assert client.get("/api/pack-assignments").json() == []


def test_put_assignment_rejects_unauditable_identifiers_fail_closed(wired):
    # FIX 5: an assignment whose derived audit subject (packId:version) is not audit-safe cannot be
    # recorded — reject 422 (constant detail) BEFORE any mutation so no unaudited assignment lands.
    client, _store, _registry, _signer = wired
    _seed_untagged_vm(client, "epic")
    resp = client.put(
        "/api/workloads/epic/pack-assignments",
        json={"packId": "pack@evil", "version": "1.0.0"},  # '@' is audit-forbidden
    )
    assert resp.status_code == 422, resp.text
    assert "auditable" in resp.json()["detail"].lower()
    assert client.get("/api/workloads/epic/pack-assignments").json() == []


def test_put_assignment_replaces_prior_version(wired):
    client, _store, _registry, _signer = wired
    _seed_untagged_vm(client, "epic")  # FIX 3: workload must exist
    for v in ("1.0.0", "2.0.0"):
        assert client.put(
            "/api/workloads/epic/pack-assignments",
            json={"packId": "waf-reliability-baseline", "version": v},
        ).status_code == 200
    got = client.get("/api/workloads/epic/pack-assignments").json()
    assert len(got) == 1
    assert got[0]["version"] == "2.0.0"
    assert got[0]["assignedBy"] == "system"  # FIX 4: server-derived


def test_list_pack_assignments_spans_workloads(wired):
    client, _store, registry, signer = wired
    _seed_untagged_vm(client, "epic")  # FIX 3: both workloads must exist
    _seed_untagged_vm(client, "sap")
    # Both assigned versions must be SIGNED+TRUSTED registry entries first (FINDING B binding).
    _publish_signed(registry, _registry_pack_dict("rules", "2.0.0"), signer)
    _publish_signed(registry, _registry_pack_dict("ops", "1.0.0"), signer)
    client.put("/api/workloads/epic/pack-assignments",
               json={"packId": "rules", "version": "2.0.0"})
    client.put("/api/workloads/sap/pack-assignments",
               json={"packId": "ops", "version": "1.0.0"})
    listed = client.get("/api/pack-assignments").json()
    assert {(a["workload"], a["packId"]) for a in listed} == {("epic", "rules"), ("sap", "ops")}


def test_put_assignment_rejects_unsigned_legacy_entry_fail_closed(wired):
    # FINDING B (issue #89, R2): a legacy entry published WITHOUT a signature is one the runtime
    # resolver refuses to run (entry.detached_signature() is None → skipped). It must therefore be
    # UN-assignable — reject 4xx (fail closed) and persist NOTHING, so assignment can only ever bind
    # a version the runtime will actually run.
    client, _store, registry, _signer = wired
    _seed_untagged_vm(client, "epic")
    registry.publish(_registry_pack_dict("legacy-unsigned", "1.0.0"))  # NO signature (legacy)
    resp = client.put(
        "/api/workloads/epic/pack-assignments",
        json={"packId": "legacy-unsigned", "version": "1.0.0"},
    )
    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"].lower()
    assert "unsigned" in detail or "trusted" in detail
    assert client.get("/api/workloads/epic/pack-assignments").json() == []
    assert client.get("/api/pack-assignments").json() == []


def test_put_assignment_rejects_untrusted_key_entry_fail_closed(wired):
    # FINDING B: an entry SIGNED by a key that is NOT pinned in the shared trust bundle is one the
    # runtime refuses (import_verifier.verify_pack fails on an unknown key_id). Assignment must
    # mirror that trust gate and reject it (fail closed), persisting NOTHING.
    client, _store, registry, _signer = wired
    _seed_untagged_vm(client, "epic")
    attacker = Ed25519Signer.generate("attacker-kid")  # not pinned in the wired trust bundle
    _publish_signed(registry, _registry_pack_dict("attacker-pack", "1.0.0"), attacker)
    resp = client.put(
        "/api/workloads/epic/pack-assignments",
        json={"packId": "attacker-pack", "version": "1.0.0"},
    )
    assert resp.status_code == 422, resp.text
    assert "trusted" in resp.json()["detail"].lower()
    assert client.get("/api/workloads/epic/pack-assignments").json() == []
    assert client.get("/api/pack-assignments").json() == []


def test_put_assignment_rejects_unverified_pack_fail_closed(wired):
    client, _store, _registry, _signer = wired
    _seed_untagged_vm(client, "epic")
    # MED #1: an assignment may only ever point at a VERIFIED, imported registry entry. A pack
    # id@version that was never imported must be rejected (fail closed) and persist NOTHING —
    # otherwise a run could later resolve engine content that was never signature-verified.
    resp = client.put(
        "/api/workloads/epic/pack-assignments",
        json={"packId": "never-imported", "version": "9.9.9"},
    )
    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"].lower()
    assert "verified" in detail or "registry" in detail
    # Nothing was stored — the read models stay empty.
    assert client.get("/api/workloads/epic/pack-assignments").json() == []
    assert client.get("/api/pack-assignments").json() == []


def test_put_assignment_accepts_after_import_binds_to_verified_entry(wired):
    client, _store, registry, signer = wired
    _seed_untagged_vm(client, "epic")  # FIX 3: workload must exist
    # Import a signed bundle through the fail-closed flow so it lands (verified) in the registry.
    resp = client.post("/api/packs/import", json=_signed_bundle(_importable_pack("3.1.0"), signer))
    assert resp.status_code == 200, resp.text
    assert registry.get(PackRef(id="epic-core", version="3.1.0")) is not None
    # FIX 1: the imported entry persisted the verified signature, so it is SIGNED (not legacy-
    # untrusted) and can be resolved/executed under an assignment.
    assert resp.json()["signed"] is True
    assert registry.get(PackRef(id="epic-core", version="3.1.0")).detached_signature() is not None
    # Now the assignment to that exact verified entry is accepted and stored.
    assign = client.put(
        "/api/workloads/epic/pack-assignments",
        json={"packId": "epic-core", "version": "3.1.0"},
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
    signer = Ed25519Signer.generate("test-kid")
    # Publish the assigned pack's VERIFIED, SIGNED digest (its source) so resolution runs those
    # exact bytes AND the assignment trust gate (FINDING B) accepts it.
    _publish_signed(registry, rel_v1.source, signer)
    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_packs] = lambda: packs
    app.dependency_overrides[get_clients] = lambda: {}
    app.dependency_overrides[get_pack_registry] = lambda: registry
    app.dependency_overrides[get_pack_import_verifier] = lambda: _trust_verifier(signer)
    try:
        with TestClient(app) as client:
            _seed_untagged_vm(client, "epic")
            assert client.put(
                "/api/workloads/epic/pack-assignments",
                json={"packId": "waf-reliability-baseline", "version": "1.0.0"},
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
    signer = Ed25519Signer.generate("test-kid")
    _publish_signed(registry, verified.source, signer)
    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_packs] = lambda: packs
    app.dependency_overrides[get_clients] = lambda: {}
    app.dependency_overrides[get_pack_registry] = lambda: registry
    app.dependency_overrides[get_pack_import_verifier] = lambda: _trust_verifier(signer)
    try:
        with TestClient(app) as client:
            _seed_untagged_vm(client, "epic")
            assert client.put(
                "/api/workloads/epic/pack-assignments",
                json={"packId": "waf-reliability-baseline", "version": "1.0.0"},
            ).status_code == 200
            # The assigned id's only content pack has a mismatched digest ⇒ it runs nothing, and no
            # other version is substituted ⇒ zero findings.
            assert _run_pack_refs(client, "epic") == set()
    finally:
        app.dependency_overrides.clear()


# --------------------------------------------------------------------------------------
# Trust-boundary invariant (issue #125 follow-up). The assignment gate is a METADATA-only
# pre-filter; the CRYPTOGRAPHIC trust boundary is import admission + the runtime resolver, which
# both re-verify the signature over the pack's canonical BYTES against the shared trust bundle.
# These two tests pin that boundary as a regression: a metadata-forged entry PASSES the gate yet
# runs NOTHING, and a genuinely signed+trusted entry runs end-to-end (the gate isn't over-
# rejecting).
# --------------------------------------------------------------------------------------
def _importable_rule_pack(
    pack_id: str, version: str = "1.0.0", *, required_tag: str = "backup"
) -> dict[str, Any]:
    """A real, self-consistent rule pack dict (its OWN id namespace; never shipped) that
    quality_checks can execute against an untagged VM to produce a FAIL finding."""
    return {
        "manifest": {
            "id": pack_id,
            "type": "rule",
            "name": pack_id,
            "version": version,
            "targets": ["epic"],
            "author": "microsoft",
        },
        "body": {
            "rules": [
                {
                    "id": f"{pack_id}-01",
                    "title": "VMs carry the required tag",
                    "resourceType": VM_TYPE,
                    "requiredTag": required_tag,
                    "severity": "high",
                    "description": "Imported rule.",
                }
            ]
        },
    }


def _real_engine(tmp_path) -> tuple[PackRegistry, LocalPackContentStore, Path]:
    """Build an EMPTY content root plus a registry + digest-addressed content store for a real
    PacksEngine — so ``load_for_workload`` runs the SAME ``_resolve_imported_packs`` byte-level
    signature re-verification the worker/runtime does. Returns ``(registry, content_store, root)``.
    """
    root = tmp_path / "content"
    root.mkdir()
    registry = PackRegistry(str(root / "registry" / "index.json"))
    content_store = LocalPackContentStore(tmp_path / "store")
    return registry, content_store, root


def test_metadata_forged_assignment_passes_gate_but_runtime_runs_nothing(tmp_path):
    """A registry entry FORGED directly on disk — pinned ``key_id`` + ``canonical_digest`` equal to
    the entry digest, but an INVALID signature — PASSES the metadata-only assignment gate yet the
    runtime resolver runs NOTHING.

    This pins the exact residual tracked in follow-up issue #125: the assignment gate is a
    metadata/structural pre-filter, NOT the cryptographic trust boundary. The security boundary is
    the byte-level signature verification enforced at IMPORT admission and INDEPENDENTLY re-enforced
    by the runtime (``PacksEngine._resolve_imported_packs``) against the shared trust bundle — so a
    metadata-forged entry can never cause execution even though it satisfies the gate.
    """
    signer = Ed25519Signer.generate("test-kid")
    verifier = _trust_verifier(signer)
    registry, content_store, root = _real_engine(tmp_path)
    engine = PacksEngine(
        root, registry=registry, content_store=content_store, import_verifier=verifier
    )
    pack = _importable_rule_pack("forged-rule", "1.0.0")
    digest = canonical_digest(pack)
    # FORGE: a well-formed PackSignature whose key_id IS pinned in the bundle and whose
    # canonical_digest binds this exact content (== entry.digest), but whose signature BYTES are
    # bogus (64 zero bytes ⇒ never verify against the pinned Ed25519 public key). This satisfies all
    # THREE metadata checks the assign gate enforces, yet fails the real crypto the runtime runs.
    forged = PackSignature(
        algorithm=ED25519_ALG,
        signature=base64.b64encode(b"\x00" * 64).decode("ascii"),
        key_id=signer.key_id,
        canonical_digest=digest,
    )
    entry = registry.publish(pack, signature=forged)
    content_store.put(entry.digest, canonical_bytes(pack))
    # Sanity: the forged entry genuinely satisfies the assign gate's three metadata checks.
    stored = entry.detached_signature()
    assert stored is not None
    assert stored.key_id in verifier.key_ids()
    assert stored.canonical_digest == entry.digest

    store = LocalStateStore(str(tmp_path / "state"))
    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_packs] = lambda: engine
    app.dependency_overrides[get_clients] = lambda: {}
    app.dependency_overrides[get_pack_registry] = lambda: registry
    app.dependency_overrides[get_pack_import_verifier] = lambda: verifier
    try:
        with TestClient(app) as client:
            _seed_untagged_vm(client, "epic")
            # (1) The metadata-forged entry PASSES the assignment gate — the KNOWN, documented
            # limitation tracked as issue #125.
            assert client.put(
                "/api/workloads/epic/pack-assignments",
                json={"packId": "forged-rule", "version": "1.0.0"},
            ).status_code == 200
            # (2) The runtime resolver re-verifies the signature BYTES against the shared trust
            # bundle, the bogus signature fails, and the pack is skipped fail-closed ⇒ zero
            # findings. A metadata-forged assignment CANNOT cause execution.
            assert _run_pack_refs(client, "epic") == set()
    finally:
        app.dependency_overrides.clear()


def test_signed_trusted_import_assign_run_end_to_end(tmp_path):
    """The positive counterpart: a genuinely SIGNED + TRUSTED pack — imported into the same real
    engine (registry + content store + pinned trust root), assigned via the API — RESOLVES and RUNS
    at runtime. Proves import↔assign↔runtime share ONE trust root and the gate is not over-
    rejecting legitimate packs.
    """
    signer = Ed25519Signer.generate("test-kid")
    verifier = _trust_verifier(signer)
    registry, content_store, root = _real_engine(tmp_path)
    engine = PacksEngine(
        root, registry=registry, content_store=content_store, import_verifier=verifier
    )
    pack = _importable_rule_pack("trusted-rule", "1.0.0")
    # Genuine admission: publish WITH the real detached signature, then store the verified canonical
    # bytes the runtime re-verifies (mirrors the import single-writer + content-store materialize).
    entry = registry.publish(pack, signature=sign_pack(pack, signer))
    content_store.put(entry.digest, canonical_bytes(pack))

    store = LocalStateStore(str(tmp_path / "state"))
    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_packs] = lambda: engine
    app.dependency_overrides[get_clients] = lambda: {}
    app.dependency_overrides[get_pack_registry] = lambda: registry
    app.dependency_overrides[get_pack_import_verifier] = lambda: verifier
    try:
        with TestClient(app) as client:
            _seed_untagged_vm(client, "epic")
            assert client.put(
                "/api/workloads/epic/pack-assignments",
                json={"packId": "trusted-rule", "version": "1.0.0"},
            ).status_code == 200
            # The signed+trusted pack's signature re-verifies against the pinned bundle at runtime,
            # so it resolves and runs against the untagged VM ⇒ exactly its one finding.
            assert _run_pack_refs(client, "epic") == {("trusted-rule", "1.0.0")}
    finally:
        app.dependency_overrides.clear()


def test_run_resolves_the_assigned_pack_version(wired):
    client, _store, _registry, _signer = wired
    _seed_untagged_vm(client, "epic")
    assert client.put(
        "/api/workloads/epic/pack-assignments",
        json={"packId": "waf-reliability-baseline", "version": "1.0.0"},
    ).status_code == 200

    # With an assignment, the run resolves ONLY the pinned version — v2.0.0 is filtered out.
    assert _run_pack_versions(client, "epic") == {"1.0.0"}

    # Re-pin to 2.0.0 and confirm the run now resolves that version instead.
    assert client.put(
        "/api/workloads/epic/pack-assignments",
        json={"packId": "waf-reliability-baseline", "version": "2.0.0"},
    ).status_code == 200
    assert _run_pack_versions(client, "epic") == {"2.0.0"}
