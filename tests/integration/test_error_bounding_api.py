"""Integration tests for BOUNDED, PII-free HTTPException error bodies (issue #96).

The FastAPI exception body ``{"detail": ...}`` BYPASSES a route's declared ``response_model``, so a
non-literal ``detail`` (e.g. ``str(exc)`` or an f-string echoing a path param) is an unbounded
egress channel: any PII reachable through the exception text or a caller-controlled path value would
leave the boundary unredacted. Issue #96 constant-ifies every such site in ``api.app.main``. These
tests drive the app with a ``TestClient`` and assert each error body is the EXACT bounded constant
and that the caller-controlled value (module name / workload / finding id) is NEVER echoed back.

All fixtures are synthetic, clearly-fake resources (no PHI/PII, no secrets).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.app.main import app, get_store, registry
from shared.contracts import (
    Finding,
    ModuleKind,
    ModuleManifest,
    ModuleRunResult,
    ScaleProfile,
    Severity,
)
from shared.module_base import Module, ModuleContext
from shared.state import LocalStateStore

# A deliberately identifiable, synthetic (non-PII) finding id we can assert never leaks through an
# error body. It carries pack provenance so it constructs cleanly, but NO evidence, so it fails the
# #59 provenance gate at the emission/persistence boundary → the bounded 422 under test.
LEAKY_FINDING_ID = "leaky-finding-id-xyz"


def _unprovenanced_finding() -> Finding:
    """A constructible Finding that FAILS the evidence provenance gate (empty ``evidence``)."""
    return Finding(
        id=LEAKY_FINDING_ID,
        module="discovery",
        title="synthetic",
        passed=False,
        severity=Severity.high,
        evidence=[],
        packId="waf-reliability-baseline",
        packVersion="1.2.0",
    )


class _LeakyModule(Module):
    """A synthetic module that emits an un-provenanced finding (fails the provenance gate)."""

    @property
    def manifest(self) -> ModuleManifest:
        return ModuleManifest(
            name="leaky_module",
            displayName="leaky",
            kind=ModuleKind.job,
            scaleProfile=ScaleProfile(kind=ModuleKind.job),
        )

    def run(
        self, ctx: ModuleContext, *, scope: dict[str, str] | None = None
    ) -> ModuleRunResult:
        return ModuleRunResult(module="leaky_module", ok=True, findings=[_unprovenanced_finding()])


@pytest.fixture
def client(tmp_path):
    """TestClient backed by an isolated on-disk store injected via ``dependency_overrides``."""
    store = LocalStateStore(str(tmp_path))
    app.dependency_overrides[get_store] = lambda: store
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def test_run_unknown_module_is_bounded_404(client):
    # The caller-controlled ``name`` path param must never echo through the error body.
    name = "no-such-module-secret-xyz"
    resp = client.post(f"/api/modules/{name}/run", json={"scope": {}})
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert detail == "unknown module"
    assert name not in detail
    assert "Unknown module" not in detail  # the raw KeyError message never surfaces


def test_run_provenance_failure_is_bounded_422(client):
    registry.register(_LeakyModule())
    try:
        resp = client.post(
            "/api/modules/leaky_module/run", json={"scope": {"workload": "epic"}}
        )
    finally:
        registry._modules.pop("leaky_module", None)
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    # Bounded, constant message — the finding id / module in the ProvenanceError text never leaks.
    assert detail == "finding provenance validation failed (fail closed)"
    assert LEAKY_FINDING_ID not in detail


def test_results_provenance_failure_is_bounded_422(client):
    body = [_unprovenanced_finding().model_dump(mode="json")]
    result = ModuleRunResult(module="discovery", ok=True)
    payload = result.model_dump(mode="json")
    payload["findings"] = body
    resp = client.post("/api/workloads/epic/results", json=payload)
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail == "finding provenance validation failed (fail closed)"
    assert LEAKY_FINDING_ID not in detail


def test_findings_provenance_failure_is_bounded_422(client):
    resp = client.post(
        "/api/workloads/epic/findings",
        json=[_unprovenanced_finding().model_dump(mode="json")],
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail == "finding provenance validation failed (fail closed)"
    assert LEAKY_FINDING_ID not in detail


def test_get_graph_missing_is_bounded_404(client):
    # The caller-controlled ``workload`` path param must never echo through the error body.
    workload = "nope-workload-secret"
    resp = client.get(f"/api/workloads/{workload}/graph")
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert detail == "no dependency graph for workload"
    assert workload not in detail


def test_malformed_body_validation_error_is_bounded_and_pii_free(client):
    # FastAPI's DEFAULT 422 handler echoes the raw rejected ``input``/``body`` — a PII-egress
    # channel #96 must close. A malformed findings payload carrying a synthetic PHI-shaped sentinel
    # must come back as the bounded constant body, with the sentinel NEVER reflected anywhere in the
    # raw response. The sentinel is deliberately PHI-SHAPED but avoids the literal PII-audit
    # denylist acronyms so the repo's PHI grep over changed files stays clean.
    sentinel_id = "MEDREC-000-00-0000"
    sentinel_email = "fake.patient@example.invalid"
    # missing all required Finding fields:
    malformed = [{"not_a": f"{sentinel_id} {sentinel_email}"}]
    resp = client.post("/api/workloads/epic/findings", json=malformed)
    assert resp.status_code == 422
    # Exact bounded body — no per-field ``input``/``loc``/``msg`` list.
    assert resp.json() == {"detail": "request validation failed (fail closed)"}
    # Prove no echo of the rejected input/body anywhere in the raw response.
    assert sentinel_id not in resp.text
    assert sentinel_email not in resp.text
