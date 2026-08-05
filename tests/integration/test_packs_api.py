"""Integration tests for the read-only pack-registry catalogue endpoint (issue #57).

Drives the FastAPI app with a ``TestClient`` and proves ``GET /api/packs`` is a thin, keyless,
PII-free, fail-closed projection of the wired pack registry (:meth:`PacksEngine.registry_entries`):

* no engine / no registry wired  -> ``[]`` (empty catalogue, never an error, never fabricated);
* a populated registry           -> one view per published version, id/version/type/digest only.

All fixtures are synthetic, clearly-fake packs (no PHI/PII, no secrets, no signing keys).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.app.main import app, get_packs
from packs_engine.engine import PacksEngine
from packs_engine.registry import PackRegistry


def _fake_pack(pack_id: str, version: str, pack_type: str = "rule") -> dict:
    """A minimal, clearly-fake pack document (manifest + inert body) for publishing."""
    return {
        "manifest": {"id": pack_id, "version": version, "type": pack_type},
        "body": {"note": "synthetic test pack — not customer content"},
    }


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def test_packs_empty_when_no_engine_wired(client: TestClient) -> None:
    """Fail closed: no packs engine at all -> empty catalogue, HTTP 200 (not an error)."""
    app.dependency_overrides[get_packs] = lambda: None
    resp = client.get("/api/packs")
    assert resp.status_code == 200
    assert resp.json() == []


def test_packs_empty_when_no_registry_wired(client: TestClient, tmp_path) -> None:
    """An engine with NO registry (no import subsystem) also yields an empty catalogue."""
    engine = PacksEngine(tmp_path)  # no registry= -> registry_entries() returns []
    app.dependency_overrides[get_packs] = lambda: engine
    resp = client.get("/api/packs")
    assert resp.status_code == 200
    assert resp.json() == []


def test_packs_lists_published_versions(client: TestClient, tmp_path) -> None:
    """A populated registry is projected to one keyless, PII-free view per published version."""
    registry = PackRegistry(index_path=tmp_path / "registry" / "index.json")
    registry.publish(_fake_pack("rule.tls.fake", "1.0.0", "rule"))
    registry.publish(_fake_pack("rule.tls.fake", "1.2.0", "rule"))
    registry.publish(_fake_pack("wl.atlas.fake", "2.0.0", "workload"))
    engine = PacksEngine(tmp_path, registry=registry)
    app.dependency_overrides[get_packs] = lambda: engine

    resp = client.get("/api/packs")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 3

    refs = {(e["id"], e["version"]) for e in body}
    assert refs == {
        ("rule.tls.fake", "1.0.0"),
        ("rule.tls.fake", "1.2.0"),
        ("wl.atlas.fake", "2.0.0"),
    }

    entry = next(e for e in body if e["version"] == "1.2.0")
    assert entry["type"] == "rule"
    # digest is a lowercase sha256 hex (the version identity, not a secret).
    assert len(entry["digest"]) == 64 and entry["digest"] == entry["digest"].lower()
    assert set(entry) == {"id", "version", "type", "digest", "createdAt", "signed"}
    # Published without a verified detached signature -> fail-closed 'signed' is False, and NO raw
    # key id / signature bytes are ever egressed.
    assert entry["signed"] is False
    assert "keyId" not in entry and "signature" not in entry


def test_registry_entries_accessor_empty_without_registry(tmp_path) -> None:
    """Unit: the engine accessor itself fails closed to [] when no registry is wired."""
    assert PacksEngine(tmp_path).registry_entries() == []
