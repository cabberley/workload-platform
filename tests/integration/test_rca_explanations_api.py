"""Integration tests for the in-boundary grounded RCA advisory console read path (issue #54).

Drives the real FastAPI app with a ``TestClient`` against an isolated store. Proves:

* ``GET /api/workloads/{workload}/rca-explanations`` requires auth (deny-by-default) and returns the
  persisted, grounded advisory as the BOUNDED, PII-safe ``RcaAdvisory`` projection (NOT the blanket
  ``redact_tree`` egress projection — the grounded advisory text survives verbatim);
* only GROUNDED/non-empty advisories are ever surfaced (fail-closed by absence);
* the endpoint is read-only and never mutates state.

All fixtures are synthetic (no PHI/PII, no secrets, no real Entra, no real resource ids).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.app.main import app, get_auth_validator, get_store
from shared.state import LocalStateStore
from support.auth import TokenFactory, build_test_validator


def _rca_extra(*, confidence: float, advisory: str) -> dict:
    """A synthetic aiops ``extra`` carrying one index-aligned RCA + advisory (clearly fake ids)."""
    return {
        "rca": [
            {
                "agentName": "aiops.autorca",
                "taskType": "root_cause_analysis",
                "inputSummary": "synthetic",
                "findings": ["node-fake-01 is saturated"],
                "risks": [],
                "recommendations": [],
                "sourceReferences": [
                    {"kind": "resource", "id": "node-fake-01", "detail": "synthetic"},
                    {"kind": "metric", "id": "cpu_saturation_ratio", "detail": None},
                ],
                "confidence": confidence,
                "nextActions": [],
                "generatedAt": "2024-01-01T00:00:00+00:00",
            }
        ],
        "rcaExplanation": [{"advisory": advisory}],
    }


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
    """TestClient with auth DISABLED (the documented local-dev / no-auth path)."""
    store = LocalStateStore(str(tmp_path))
    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_auth_validator] = lambda: None
    with TestClient(app) as client:
        yield client, store
    app.dependency_overrides.clear()


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _post_results(client, factory, *, workload="epic", confidence, advisory) -> None:
    """Seed a run through the API (scoped store) so the read hits the tenant-partitioned write."""
    headers = {}
    if factory is not None:
        headers = _bearer(factory.mint(roles=["Workloads.Operator"]))
    result = {
        "module": "aiops",
        "ok": True,
        "extra": _rca_extra(confidence=confidence, advisory=advisory),
    }
    resp = client.post(f"/api/workloads/{workload}/results", json=result, headers=headers)
    assert resp.status_code == 200, resp.text


def test_get_rca_explanations_without_token_is_401(auth_on) -> None:
    client, factory, _store = auth_on
    _post_results(client, factory, confidence=0.9, advisory="node-fake-01 saturated.")
    assert client.get("/api/workloads/epic/rca-explanations").status_code == 401


def test_get_rca_explanations_with_reader_token_returns_grounded_advisory(auth_on) -> None:
    client, factory, _store = auth_on
    _post_results(
        client, factory, confidence=0.9, advisory="node-fake-01 saturated cpu_saturation_ratio."
    )
    token = factory.mint(roles=["Workloads.Reader"])
    resp = client.get("/api/workloads/epic/rca-explanations", headers=_bearer(token))
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    advisory = body[0]
    # The grounded advisory text survives verbatim — this is the explicit PII-safe projection, NOT
    # the blanket redact_tree egress that neutralizes free text on the /run path.
    assert advisory["advisory"] == "node-fake-01 saturated cpu_saturation_ratio."
    assert advisory["index"] == 0
    assert advisory["agentName"] == "aiops.autorca"
    assert advisory["confidence"] == 0.9
    assert [(r["kind"], r["id"]) for r in advisory["sourceReferences"]] == [
        ("resource", "node-fake-01"),
        ("metric", "cpu_saturation_ratio"),
    ]
    # The bounded read model carries ONLY the vetted fields — no open free-text / dict smuggling.
    assert set(advisory) == {
        "index",
        "agentName",
        "taskType",
        "confidence",
        "advisory",
        "findings",
        "risks",
        "recommendations",
        "sourceReferences",
        "generatedAt",
    }


def test_get_rca_explanations_empty_when_none(auth_off) -> None:
    client, _store = auth_off
    resp = client.get("/api/workloads/never-run/rca-explanations")
    assert resp.status_code == 200
    assert resp.json() == []


def test_get_rca_explanations_omits_ungrounded_run(auth_off) -> None:
    client, _store = auth_off
    # An ungrounded/empty advisory is never persisted, so the read path surfaces nothing.
    _post_results(client, None, confidence=0.3, advisory="")
    resp = client.get("/api/workloads/epic/rca-explanations")
    assert resp.status_code == 200
    assert resp.json() == []


def test_get_rca_explanations_is_read_only(auth_off) -> None:
    client, _store = auth_off
    _post_results(client, None, confidence=0.9, advisory="node-fake-01 saturated.")
    before = client.get("/api/workloads/epic/rca-explanations").json()
    client.get("/api/workloads/epic/rca-explanations")
    after = client.get("/api/workloads/epic/rca-explanations").json()
    assert before == after and len(after) == 1
