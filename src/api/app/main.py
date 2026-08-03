"""API core — FastAPI app: health, the module registry, cycle orchestration, and durable state.

The API is the **single writer** of shared state. Modules submit their results here (rather than
writing concurrently) and the API persists them via the :class:`~shared.state.StateStore`. Modules
that the API runs in-process receive a *read-only* ``ReadOnlyState`` view. This keeps ``api`` at
low replica counts while the compute-heavy modules scale freely.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from time import perf_counter
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel

from shared.blast_radius import compute_impact, graph_revision
from shared.contracts import (
    DriftReport,
    Finding,
    HealthState,
    MetricsSnapshot,
    ModuleRunResult,
    ReadinessReport,
    ResourceNode,
    WorkloadGraph,
)
from shared.module_base import build_default_registry, run_module
from shared.observability import (
    DEP_EDGE_CLIENTS,
    DEP_PACKS_ENGINE,
    DEP_STATE_STORE,
    MetricsRegistry,
    ProbeResult,
    Tracer,
    aggregate_readiness,
    process_metrics,
    store_reachable_probe,
)
from shared.state import (
    ReadOnlyState,
    StateStore,
    build_state_store,
    compute_drift,
)

app = FastAPI(
    title="Workloads Platform API",
    version="0.1.0",
    description="In-boundary control plane for discovery, quality, dependency, AIOps and alerts.",
)

# The ASGI next-handler signature for the request-boundary tracing middleware below.
RequestHandler = Callable[[Request], Awaitable[Response]]

registry = build_default_registry()

# Process-wide self-observability (issue #60). Both are keyless and cheap to construct:
#   * `metrics` is THE process-wide in-process registry of counters/durations (module runs,
#     connector fail-closed counts). It is the SAME instance the composition root wires connector
#     fail-closed observers into (see `cli.wiring`), so a real fail-closed event in a connector
#     shows up in the `/api/metrics` snapshot operators read.
#   * `tracer` is an OTel-STYLE seam that is a NO-OP by default (no exporter ⇒ no export, no
#     network, no secret). A concrete exporter is a downstream decision (see `Tracer`'s
#     TODO(human)); the composition root can wire one without touching endpoint code.
# They are module-level singletons exposed as FastAPI dependencies so tests can override them.
metrics = process_metrics()
tracer = Tracer()


def get_metrics() -> MetricsRegistry:
    """Return the process-wide in-process metrics registry (single instance)."""
    return metrics


def get_tracer() -> Tracer:
    """Return the process-wide tracer seam (no-op by default; overridable in tests)."""
    return tracer


MetricsDep = Annotated[MetricsRegistry, Depends(get_metrics)]
TracerDep = Annotated[Tracer, Depends(get_tracer)]


@app.middleware("http")
async def trace_requests(request: Request, call_next: RequestHandler) -> Response:
    """API **request-boundary** tracing seam (issue #60): wrap each request in a span.

    No-op unless an exporter is wired into the process ``tracer`` (default exports nothing, touches
    no network, needs no secret). Span attributes are deliberately **PII-free and low-cardinality**:
    only the HTTP method, the matched *route template* (e.g. ``/api/workloads/{workload}/findings``
    — the parameter NAMES, never the actual values, so no resource id/PII leaks) and the numeric
    status code. If routing did not resolve a template we fall back to ``"unmatched"`` rather than
    echoing the raw path (which could carry identifying values).
    """
    with tracer.start_span("http.request", attributes={"http.method": request.method}) as span:
        response = await call_next(request)
        route = request.scope.get("route")
        template = getattr(route, "path_format", None) or getattr(route, "path", None)
        span.set_attribute("http.route", template if isinstance(template, str) else "unmatched")
        span.set_attribute("http.status_code", str(response.status_code))
        return response

# The single writable store, owned exclusively by the API process. Built lazily from config so
# tests can override the `get_store` dependency with an isolated backend.
_store: StateStore | None = None


def get_store() -> StateStore:
    """Return the process-wide writable store (the single writer). Cached after first build."""
    global _store
    if _store is None:
        _store = build_state_store()
    return _store


StoreDep = Annotated[StateStore, Depends(get_store)]


# The packs engine and edge-client registry are built once per process and injected into modules
# the API runs in-process, mirroring `get_store`. They are cached and exposed as FastAPI
# dependencies so tests can override them with fakes via `app.dependency_overrides`. Both are
# built by the composition root (`cli.wiring`) — the single place that knows concrete client types.
_packs: object | None = None
_packs_built = False
_clients: Mapping[str, object] | None = None


def get_packs() -> object | None:
    """Return the process-wide verified packs engine (or ``None`` if no content root). Cached."""
    global _packs, _packs_built
    if not _packs_built:
        from cli.wiring import build_packs_engine

        _packs = build_packs_engine()
        _packs_built = True
    return _packs


def get_clients() -> Mapping[str, object]:
    """Return the process-wide keyless edge-client registry (possibly partial/empty). Cached."""
    global _clients
    if _clients is None:
        from cli.wiring import build_client_registry

        _clients = build_client_registry()
    return _clients


PacksDep = Annotated[object | None, Depends(get_packs)]
ClientsDep = Annotated[Mapping[str, object], Depends(get_clients)]


@app.get("/api/health")
def health() -> dict[str, object]:
    """**Liveness** probe: true while the process is up; NEVER depends on external dependencies.

    Used by CI smoke and platform liveness probes. Its existing shape (``status``/``service``/
    ``modules``) is preserved exactly — the compose-smoke gate parses those keys — and only
    additive fields are appended: ``live`` (always ``True`` here — reaching this handler proves the
    process is serving) and ``kind`` (to distinguish it from the readiness endpoint). Readiness of
    dependencies lives at ``/api/health/ready`` so liveness can never be dragged down by a slow or
    unreachable dependency (which would cause an unnecessary restart loop).
    """
    return {
        "status": "ok",
        "service": "workloads-platform-api",
        "modules": [m.health() for m in registry.enabled_modules()],
        "live": True,
        "kind": "liveness",
    }


@dataclass
class ReadinessProviders:
    """Lazy builders for the dependencies readiness probes — resolved INSIDE the handler.

    Readiness must never construct these via ``Depends`` (FastAPI would build them *before* the
    handler runs, so a raising builder — e.g. an invalid ``WORKLOADS_STATE_BACKEND`` —
    would surface as HTTP 500, not the required fail-closed 503). Instead the endpoint depends on
    this bundle of *callables* (which is cheap and never raises) and invokes each under its own
    guarded try/except. Tests override :func:`get_readiness_providers` to inject raising/failing
    builders.
    """

    store: Callable[[], StateStore]
    packs: Callable[[], object | None]
    clients: Callable[[], Mapping[str, object]]


def get_readiness_providers() -> ReadinessProviders:
    """Bundle the dependency builders for readiness (never calls them — cannot raise here)."""
    return ReadinessProviders(store=get_store, packs=get_packs, clients=get_clients)


ReadinessProvidersDep = Annotated[ReadinessProviders, Depends(get_readiness_providers)]


@app.get("/api/health/ready")
def readiness(response: Response, providers: ReadinessProvidersDep) -> ReadinessReport:
    """**Readiness** probe (fail-closed): are real dependencies actually usable right now?

    Every dependency is probed at the I/O edge under its OWN guarded try/except (construction AND
    use) and the results are folded with the PURE
    :func:`~shared.observability.aggregate_readiness`:

      * ``state_store`` — construct the store, then do a cheap, backend-agnostic reachability read
        via the ``StateStore`` interface (:func:`~shared.observability.store_reachable_probe`); ANY
        error (including a raising ``build_state_store`` on invalid config) ⇒ not ready.
      * ``packs_engine`` — verified/built, or **intentionally absent** (no content root). Absent is
        a deliberate, ready state (modules fail closed on ``packs=None``); an error while building
        or inspecting ⇒ not ready.
      * ``edge_clients`` — the keyless edge-client registry was constructed (a mapping). A build
        error, missing registry, or inspection error ⇒ not ready.

    Because the probes are guarded here rather than resolved via ``Depends``, the endpoint can
    **never 500** on a dependency error: it answers **HTTP 503** with a structured per-dependency
    breakdown whenever the aggregate is not ready. Every ``detail`` is a short, bounded,
    non-sensitive string — NO secrets, connection strings, resource ids, or PII (exception text is
    never echoed).
    """
    probes = [
        _store_probe(providers.store),
        _packs_probe(providers.packs),
        _clients_probe(providers.clients),
    ]
    report = aggregate_readiness(probes)
    if not report.ready:
        response.status_code = 503
    return report


def _store_probe(build_store: Callable[[], StateStore]) -> ProbeResult:
    """Thin edge: construct the store then probe reachability; ANY error ⇒ not ready.

    Store *construction* itself can raise (e.g. an invalid ``WORKLOADS_STATE_BACKEND``); that is
    guarded here so readiness fails closed instead of 500. Reachability is then delegated to the
    backend-agnostic :func:`~shared.observability.store_reachable_probe` (also guarded). The
    exception is deliberately NOT echoed — it could carry a connection string.
    """
    try:
        store = build_store()
    except Exception:  # noqa: BLE001 - fail closed: store build error ⇒ not ready, never 500
        return ProbeResult(name=DEP_STATE_STORE, ok=False, detail="probe error")
    return store_reachable_probe(store)


def _packs_probe(build_packs: Callable[[], object | None]) -> ProbeResult:
    """Thin edge: packs engine built/verified or intentionally absent ⇒ ready; any error ⇒ not.

    ``build_packs()`` returning ``None`` means no content root was found — a deliberate, fail-closed
    configuration (modules assess nothing), reported READY with an ``"absent"`` detail. Any error
    building or inspecting ⇒ not ready (fail closed); the exception is not echoed.
    """
    try:
        packs = build_packs()
        if packs is None:
            return ProbeResult(name=DEP_PACKS_ENGINE, ok=True, detail="absent")
        return ProbeResult(name=DEP_PACKS_ENGINE, ok=True, detail="built")
    except Exception:  # noqa: BLE001 - fail closed: any build/inspection error ⇒ not ready
        return ProbeResult(name=DEP_PACKS_ENGINE, ok=False, detail="probe error")


def _clients_probe(build_clients: Callable[[], Mapping[str, object]]) -> ProbeResult:
    """Thin edge: the keyless edge-client registry was constructed (a mapping) ⇒ ready.

    We only assert the registry builds and is a mapping — we do NOT connect to any client (that
    would be I/O with side effects and could leak identifying detail). A build error, missing
    registry, or inspection error ⇒ not ready (fail closed); the exception is not echoed.
    """
    try:
        clients = build_clients()
        if isinstance(clients, Mapping):
            return ProbeResult(
                name=DEP_EDGE_CLIENTS, ok=True, detail=f"constructed ({len(clients)} clients)"
            )
        return ProbeResult(name=DEP_EDGE_CLIENTS, ok=False, detail="not constructed")
    except Exception:  # noqa: BLE001 - fail closed: any build/inspection error ⇒ not ready
        return ProbeResult(name=DEP_EDGE_CLIENTS, ok=False, detail="probe error")


@app.get("/api/metrics")
def get_metrics_snapshot(metrics: MetricsDep) -> MetricsSnapshot:
    """Read-only, vendor-neutral JSON snapshot of the in-process metrics registry.

    Keyless and PII-free: labels are bounded, low-cardinality names (module name + outcome) with
    numeric measures only — no resource ids, connection strings, or free text. This is deliberately
    JSON (not Prometheus text) to stay vendor-neutral.
    """
    return metrics.snapshot()


@app.get("/api/modules")
def list_modules() -> list[dict[str, object]]:
    """Enumerate modules and their scale profiles (drives infra + the web console)."""
    return [m.model_dump() for m in registry.manifests()]


class RunRequest(BaseModel):
    scope: dict[str, str] = {}


@app.post("/api/modules/{name}/run")
def run_module_endpoint(
    name: str,
    req: RunRequest,
    store: StoreDep,
    packs: PacksDep,
    clients: ClientsDep,
    metrics: MetricsDep,
    tracer: TracerDep,
) -> ModuleRunResult:
    """Run a single module by name (also how the ACA Job worker's compute is exercised in-process).

    Compute and write are separated: :func:`~shared.module_base.run_module` computes the result
    with a **read-only** state view (it cannot write shared state), the verified ``packs`` engine,
    and the keyless edge-client registry injected here at the boundary; then — because this is the
    API, the single writer — the endpoint commits the run atomically when the scope carries a
    ``workload`` (findings always, plus estate/graph when the run produced them). The API keeps its
    fast in-process ``ReadOnlyState`` view (it is co-located with the store); only the worker reads
    over HTTP.

    Self-observability (issue #60) is applied HERE at the module-run boundary, never inside the
    module: the run is wrapped in a tracing span (no-op unless an exporter is wired) and its count
    + duration + outcome are recorded on the in-process metrics registry with bounded, PII-free
    labels (module name + ``ok``/``error`` outcome only).
    """
    try:
        module = registry.get(name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    started = perf_counter()
    ok = False
    with tracer.start_span("module.run", attributes={"module": name}) as span:
        try:
            result = run_module(
                module, scope=req.scope, state=ReadOnlyState(store), packs=packs, clients=clients
            )
            workload = req.scope.get("workload")
            if workload:
                store.commit_run(workload, result)  # API is the single writer
            ok = result.ok
            return result
        finally:
            duration_ms = (perf_counter() - started) * 1000.0
            span.set_attribute("outcome", "ok" if ok else "error")
            metrics.record_module_run(name, ok=ok, duration_ms=duration_ms)


# --------------------------------------------------------------------------------------
# Submit endpoints — modules/workers hand results to the API, which persists them (writer).
# The request body is a fully typed `ModuleRunResult`, so FastAPI validates the ENTIRE payload
# before the endpoint runs: a bad graph rejects the whole submit and nothing is written. The
# commit itself is atomic (single transaction / manifest commit point), so even a mid-write error
# leaves state unchanged.
# --------------------------------------------------------------------------------------
@app.post("/api/workloads/{workload}/results")
def submit_results(workload: str, result: ModuleRunResult, store: StoreDep) -> dict[str, object]:
    """Accept a validated ``ModuleRunResult`` and persist estate/graph/findings atomically."""
    return {"workload": workload, "persisted": store.commit_run(workload, result)}


@app.post("/api/workloads/{workload}/estate")
def put_estate(workload: str, nodes: list[ResourceNode], store: StoreDep) -> dict[str, int]:
    """Replace the persisted estate for ``workload``."""
    store.put_estate(workload, nodes)
    return {"count": len(nodes)}


@app.post("/api/workloads/{workload}/graph")
def put_graph(workload: str, graph: WorkloadGraph, store: StoreDep) -> dict[str, int]:
    """Replace the persisted dependency graph for ``workload``."""
    store.put_graph(workload, graph)
    return {"nodes": len(graph.nodes), "edges": len(graph.edges)}


@app.post("/api/workloads/{workload}/findings")
def add_findings(workload: str, findings: list[Finding], store: StoreDep) -> dict[str, int]:
    """Upsert findings into the current set for ``workload``."""
    store.add_findings(workload, findings)
    return {"count": len(findings)}


@app.post("/api/workloads/{workload}/snapshot")
def snapshot(workload: str, store: StoreDep) -> dict[str, str]:
    """Freeze the current findings into a point-in-time snapshot; return its id."""
    return {"snapshotId": store.snapshot(workload)}


# --------------------------------------------------------------------------------------
# Read endpoints — read models the web console/API query (estate, graph, findings, drift).
# --------------------------------------------------------------------------------------
@app.get("/api/workloads")
def list_workloads(store: StoreDep) -> list[str]:
    """List every workload the store knows about."""
    return store.list_workloads()


@app.get("/api/workloads/{workload}/estate")
def get_estate(workload: str, store: StoreDep) -> list[ResourceNode]:
    """Return the latest estate for ``workload`` (empty list if none)."""
    return store.get_estate(workload)


class GraphResponse(WorkloadGraph):
    """The dependency graph plus a server-computed topology revision (issue #56 round 3).

    ADDITIVE local response model: it is exactly a :class:`WorkloadGraph` (same ``nodes``/``edges``)
    with one extra ``graphRevision`` field, so existing consumers that parse only ``nodes``/
    ``edges`` are unaffected. ``graphRevision`` is :func:`shared.blast_radius.graph_revision` over
    the FULL topology; the impact endpoint returns the SAME value so the web can detect that an
    impact was computed against a different topology than the one it is displaying — WITHOUT hashing
    the graph itself in TypeScript (no TS/Python divergence). The shared ``WorkloadGraph`` contract
    is left untouched (this projection lives at the API edge, like ``ImpactResult``).
    """

    graphRevision: str


@app.get("/api/workloads/{workload}/graph")
def get_graph(workload: str, store: StoreDep) -> GraphResponse:
    """Return the latest dependency graph for ``workload`` + its revision (404 if none)."""
    graph = store.get_graph(workload)
    if graph is None:
        raise HTTPException(status_code=404, detail=f"no graph for workload {workload!r}")
    return GraphResponse(
        nodes=graph.nodes, edges=graph.edges, graphRevision=graph_revision(graph)
    )


class ImpactResult(BaseModel):
    """Read model for a single blast-radius simulation ("what breaks if ``failedNode`` is down").

    Presentation-only projection of the CANONICAL server-side math in
    :func:`shared.blast_radius.compute_impact` — it is *not* a cross-module contract, so it lives
    here in the API app rather than in ``shared.contracts``. The endpoint never reimplements the
    math: ``states`` is exactly ``compute_impact(graph, failedNode)`` and ``down``/``degraded``/
    ``blastRadius`` are derived from it (``blastRadius`` == ``len(down)`` == ``blast_radius(...)``).
    ``graphRevision`` is the SAME server-computed :func:`shared.blast_radius.graph_revision` the
    graph endpoint returns, so the web can fail closed when the two were computed on different
    topologies (edge-level staleness a node-id check alone would miss).
    """

    failedNode: str
    states: dict[str, HealthState]
    blastRadius: int
    down: list[str]
    degraded: list[str]
    graphRevision: str


@app.get("/api/workloads/{workload}/impact")
def get_impact(workload: str, node: str, store: StoreDep) -> ImpactResult:
    """Return the canonical blast-radius impact of failing ``node`` in ``workload``'s graph.

    Thin, read-only, fail-closed: 404 if no graph is persisted (mirrors :func:`get_graph`), and
    404 if ``node`` is not a member of that graph — we never silently return an all-up map for an
    unknown node. The impact itself is the canonical :func:`shared.blast_radius.compute_impact`
    result (no TypeScript/duplicate math anywhere); this endpoint only projects it into lists.

    Cost is bounded: ``compute_impact`` and ``graph_revision`` are pure, in-memory traversals over
    a single small persisted graph (estates are thousands of nodes at most) with no I/O, so there
    is no unbounded work to throttle — a concurrency limiter would be over-engineering. The web
    side already cancels superseded requests via ``AbortSignal`` and guards against launching a new
    simulation until the prior one settles.
    """
    graph = store.get_graph(workload)
    if graph is None:
        raise HTTPException(status_code=404, detail=f"no graph for workload {workload!r}")
    if node not in {n.id for n in graph.nodes}:
        raise HTTPException(
            status_code=404, detail=f"node {node!r} not in graph for workload {workload!r}"
        )
    states = compute_impact(graph, node)
    down = sorted(
        nid for nid, st in states.items() if st == HealthState.down and nid != node
    )
    degraded = sorted(nid for nid, st in states.items() if st == HealthState.degraded)
    return ImpactResult(
        failedNode=node,
        states=states,
        blastRadius=len(down),
        down=down,
        degraded=degraded,
        graphRevision=graph_revision(graph),
    )


@app.get("/api/workloads/{workload}/findings")
def get_findings(
    workload: str, store: StoreDep, module: str | None = None
) -> list[Finding]:
    """Return current findings for ``workload``, optionally filtered to one ``module``."""
    return store.get_findings(workload, module)


# The previous-snapshot read models below exist so the worker's read-only `ApiStateReader` can
# implement the FULL `ReadableState` Protocol over HTTP — reassessments/aiops run in the worker
# and must read prior state to compute drift/detections without ever holding a writable store.
@app.get("/api/workloads/{workload}/previous-findings")
def get_previous_findings(workload: str, store: StoreDep) -> list[Finding]:
    """Return the findings captured by the most recent snapshot for ``workload`` (empty if none)."""
    return store.get_previous_findings(workload)


@app.get("/api/workloads/{workload}/previous-node-ids")
def get_previous_node_ids(workload: str, store: StoreDep) -> list[str]:
    """Return the estate node ids captured by the most recent snapshot (empty if none)."""
    return store.get_previous_node_ids(workload)


@app.get("/api/workloads/{workload}/drift")
def get_drift(workload: str, store: StoreDep) -> DriftReport:
    """Return drift (findings + estate node deltas) between the last snapshot and now."""
    return compute_drift(
        store.get_previous_findings(workload),
        store.get_findings(workload),
        workload=workload,
        previous_nodes=store.get_previous_node_ids(workload),
        current_nodes=[node.id for node in store.get_estate(workload)],
    )


@app.get("/")
def root() -> dict[str, str]:
    return {"name": "workloads-platform", "docs": "/docs", "health": "/api/health"}
