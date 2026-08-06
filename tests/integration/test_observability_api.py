"""Integration tests for the self-observability API surface (issue #60).

Drives the FastAPI app with a ``TestClient`` to prove:
  * ``/api/health`` stays a LIVENESS probe with its existing shape (the compose-smoke gate) plus
    only-additive fields, and never fails on dependency trouble;
  * ``/api/health/ready`` reflects real dependencies and FAILS CLOSED (HTTP 503) when one errors;
  * ``/api/metrics`` returns a keyless JSON snapshot, and the module-run boundary records metrics;
  * the request-boundary tracing seam emits a PII-free span when an exporter is wired.

All fixtures are synthetic and Azure-free; no secrets, no PII.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.app.main import (
    ReadinessProviders,
    app,
    get_clients,
    get_metrics,
    get_packs,
    get_readiness_providers,
    get_store,
    get_tracer,
    tracer,
)
from shared.observability import MetricsRegistry, SpanData, Tracer
from shared.state import LocalStateStore


@pytest.fixture
def client(tmp_path):
    """TestClient with an isolated local store + fresh metrics; packs absent, clients empty."""
    store = LocalStateStore(str(tmp_path))
    metrics = MetricsRegistry()
    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_packs] = lambda: None
    app.dependency_overrides[get_clients] = lambda: {}
    app.dependency_overrides[get_metrics] = lambda: metrics
    # Readiness resolves its dependencies through this provider bundle (guarded inside the handler),
    # not the Depends-injected values above — so inject isolated builders here too.
    providers = ReadinessProviders(store=lambda: store, packs=lambda: None, clients=lambda: {})
    app.dependency_overrides[get_readiness_providers] = lambda: providers
    with TestClient(app) as c:
        yield c, metrics
    app.dependency_overrides.clear()


# --------------------------------------------------------------------------------------
# Liveness — existing shape preserved, only-additive fields, dependency-independent.
# --------------------------------------------------------------------------------------
def test_health_liveness_keeps_existing_shape(client) -> None:
    c, _metrics = client
    resp = c.get("/api/health")
    assert resp.status_code == 200
    body = resp.json()
    # Existing keys the compose-smoke gate depends on — unchanged.
    assert body["status"] == "ok"
    assert body["service"] == "workloads-platform-api"
    assert isinstance(body["modules"], list)
    assert all("module" in m and "status" in m for m in body["modules"])
    # Additive-only fields.
    assert body["live"] is True
    assert body["kind"] == "liveness"


def test_health_liveness_unaffected_by_broken_store() -> None:
    """Liveness must NOT depend on dependencies: a broken store still returns 200."""

    class _BoomStore(LocalStateStore):
        def list_workloads(self) -> list[str]:
            raise RuntimeError("store down")

    app.dependency_overrides[get_store] = lambda: _BoomStore.__new__(_BoomStore)
    try:
        with TestClient(app) as c:
            resp = c.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["live"] is True
    finally:
        app.dependency_overrides.clear()


# --------------------------------------------------------------------------------------
# Readiness — reflects real dependencies, fails closed with a per-dependency breakdown.
# --------------------------------------------------------------------------------------
def test_readiness_all_ready(client) -> None:
    c, _metrics = client
    resp = c.get("/api/health/ready")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ready"] is True
    names = {d["name"]: d["ok"] for d in body["dependencies"]}
    assert names == {"state_store": True, "packs_engine": True, "edge_clients": True}
    # packs are intentionally absent here → still ready, with a non-sensitive detail.
    packs = next(d for d in body["dependencies"] if d["name"] == "packs_engine")
    assert packs["detail"] == "absent"


def test_readiness_fails_closed_on_store_reachability_error(tmp_path) -> None:
    """A store whose reachability read raises ⇒ 503 with state_store not ok, no secret leak."""

    class _BoomStore(LocalStateStore):
        def list_workloads(self) -> list[str]:
            raise RuntimeError("secret://conn-str")

    store = _BoomStore(str(tmp_path))
    providers = ReadinessProviders(store=lambda: store, packs=lambda: None, clients=lambda: {})
    app.dependency_overrides[get_readiness_providers] = lambda: providers
    try:
        with TestClient(app) as c:
            resp = c.get("/api/health/ready")
        assert resp.status_code == 503
        body = resp.json()
        assert body["ready"] is False
        store_dep = next(d for d in body["dependencies"] if d["name"] == "state_store")
        assert store_dep["ok"] is False
        assert store_dep["detail"] == "probe error"
        # No secret / connection string surfaced anywhere in the body.
        assert "secret" not in resp.text and "conn-str" not in resp.text
    finally:
        app.dependency_overrides.clear()


def test_readiness_fails_closed_503_not_500_on_store_build_error() -> None:
    """MED 1: a store *builder* that raises (invalid config) ⇒ fail-closed 503, never HTTP 500."""

    def _boom_build_store():
        raise ValueError("Unknown WORKLOADS_STATE_BACKEND='secret://oops'")

    providers = ReadinessProviders(
        store=_boom_build_store, packs=lambda: None, clients=lambda: {}
    )
    app.dependency_overrides[get_readiness_providers] = lambda: providers
    try:
        with TestClient(app, raise_server_exceptions=False) as c:
            resp = c.get("/api/health/ready")
        assert resp.status_code == 503  # NOT 500 — readiness must never 500
        body = resp.json()
        assert body["ready"] is False
        # Full per-dependency breakdown is present even when a builder blew up.
        names = {d["name"]: d for d in body["dependencies"]}
        assert set(names) == {"state_store", "packs_engine", "edge_clients"}
        assert names["state_store"]["ok"] is False
        assert names["state_store"]["detail"] == "probe error"
        # Non-store deps are still healthy and reported.
        assert names["packs_engine"]["ok"] is True
        assert names["edge_clients"]["ok"] is True
        # Config text (which could carry a secret) is never echoed.
        assert "secret" not in resp.text and "WORKLOADS_STATE_BACKEND" not in resp.text
    finally:
        app.dependency_overrides.clear()


def test_readiness_fails_closed_on_client_build_error() -> None:
    """A client-registry builder that raises ⇒ 503 with edge_clients not ok (no 500)."""

    def _boom_build_clients():
        raise RuntimeError("client build boom")

    store_ok = LocalStateStore()
    providers = ReadinessProviders(
        store=lambda: store_ok, packs=lambda: None, clients=_boom_build_clients
    )
    app.dependency_overrides[get_readiness_providers] = lambda: providers
    try:
        with TestClient(app, raise_server_exceptions=False) as c:
            resp = c.get("/api/health/ready")
        assert resp.status_code == 503
        clients_dep = next(
            d for d in resp.json()["dependencies"] if d["name"] == "edge_clients"
        )
        assert clients_dep["ok"] is False
        assert clients_dep["detail"] == "probe error"
    finally:
        app.dependency_overrides.clear()


# --------------------------------------------------------------------------------------
# Metrics — read-only JSON snapshot; the run boundary records counts + durations.
# --------------------------------------------------------------------------------------
def test_metrics_endpoint_empty_snapshot(client) -> None:
    c, _metrics = client
    resp = c.get("/api/metrics")
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"counters": [], "durations": []}


def test_run_endpoint_records_module_metrics(client) -> None:
    c, _metrics = client
    resp = c.post("/api/modules/discovery/run", json={"scope": {}})
    assert resp.status_code == 200

    snap = c.get("/api/metrics").json()
    run_counters = [s for s in snap["counters"] if s["name"] == "module_runs_total"]
    assert run_counters, "module run should have been counted at the API boundary"
    counter = run_counters[0]
    assert counter["labels"]["module"] == "discovery"
    assert counter["labels"]["outcome"] in {"ok", "error"}
    # Bounded, low-cardinality labels only — no PII / resource ids.
    assert set(counter["labels"]) <= {"module", "outcome"}
    assert any(d["name"] == "module_run_duration_ms" for d in snap["durations"])


def test_unknown_module_run_still_404_and_no_metric(client) -> None:
    c, _metrics = client
    resp = c.post("/api/modules/nope/run", json={"scope": {}})
    assert resp.status_code == 404
    # A 404 (module not found) short-circuits before the traced/measured run block.
    assert c.get("/api/metrics").json()["counters"] == []


def test_metrics_egress_drops_unknown_and_redacts_pii_labels(client) -> None:
    # Issue #91: the raw registry accepts arbitrary label maps, but /api/metrics projects onto the
    # bounded MetricsSnapshotView — unexpected keys are dropped and free-form values redacted, so no
    # caller-injected PII can egress even though it lives in the in-process registry.
    c, metrics = client
    metrics.increment(
        "module_runs_total",
        labels={
            "module": "discovery",  # allow-listed key, PII-free value → survives
            "outcome": "/subscriptions/abc/resourceGroups/rg",  # allowed key, PII value → redacted
            "email": "alice@contoso.com",  # unknown key → dropped
        },
    )
    metrics.observe_duration(
        "module_run_duration_ms",
        12.0,
        labels={"module": "discovery", "customer": "acme@corp.com"},
    )
    body = c.get("/api/metrics").json()
    counter = next(s for s in body["counters"] if s["name"] == "module_runs_total")
    # Unknown key dropped; only the allow-list survives.
    assert set(counter["labels"]) <= {"module", "outcome"}
    assert "email" not in counter["labels"]
    assert counter["labels"]["module"] == "discovery"
    # The Azure resource path value is not proven PII-free → coerced to the redaction placeholder.
    assert counter["labels"]["outcome"] == "[redacted]"
    duration = next(d for d in body["durations"] if d["name"] == "module_run_duration_ms")
    assert set(duration["labels"]) <= {"module", "outcome"}
    assert "customer" not in duration["labels"]
    # The raw PII text never appears anywhere in the serialized egress payload.
    serialized = c.get("/api/metrics").text
    assert "alice@contoso.com" not in serialized
    assert "acme@corp.com" not in serialized
    assert "/subscriptions/" not in serialized


# --------------------------------------------------------------------------------------
# Tracing — request-boundary seam emits a PII-free span when an exporter is wired.
# --------------------------------------------------------------------------------------
def test_request_boundary_tracing_exports_pii_free_span(tmp_path) -> None:
    recorded: list[SpanData] = []

    class _Exporter:
        def export(self, span: SpanData) -> None:
            recorded.append(span)

    store = LocalStateStore(str(tmp_path))
    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_packs] = lambda: None
    app.dependency_overrides[get_clients] = lambda: {}
    # The request-boundary middleware uses the process `tracer`; swap in a wired one.
    original_exporter = tracer._exporter
    tracer._exporter = _Exporter()
    try:
        with TestClient(app) as c:
            assert c.get("/api/health").status_code == 200
    finally:
        tracer._exporter = original_exporter
        app.dependency_overrides.clear()

    http_spans = [s for s in recorded if s.name == "http.request"]
    assert http_spans, "request-boundary span should have been exported"
    attrs = http_spans[0].attributes
    assert attrs["http.method"] == "GET"
    # Route TEMPLATE only (no param values) — the health route has no params.
    assert attrs["http.route"] == "/api/health"
    assert attrs["http.status_code"] == "200"


def test_get_tracer_and_get_metrics_are_singletons() -> None:
    assert get_tracer() is tracer
    assert isinstance(get_metrics(), MetricsRegistry)
    assert isinstance(get_tracer(), Tracer)
