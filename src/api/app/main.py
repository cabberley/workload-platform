"""API core — FastAPI app: health, the module registry, cycle orchestration, and durable state.

The API is the **single writer** of shared state. Modules submit their results here (rather than
writing concurrently) and the API persists them via the :class:`~shared.state.StateStore`. Modules
that the API runs in-process receive a *read-only* ``ReadOnlyState`` view. This keeps ``api`` at
low replica counts while the compute-heavy modules scale freely.
"""
from __future__ import annotations

import hashlib
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from time import perf_counter
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field

from packs_engine.engine import PacksEngine
from shared.audit import AuditEmitter, resolve_actor
from shared.blast_radius import compute_impact, graph_revision
from shared.contracts import (
    AuditAction,
    AuditResult,
    DriftReport,
    Finding,
    HealthState,
    MetricsSnapshotView,
    ModuleManifest,
    ModuleRunResult,
    ReadinessReport,
    ResourceNode,
    WorkloadGraph,
    is_audit_safe,
    redact_node_tags,
    redact_tree,
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
from shared.provenance import ProvenanceError, enforce_finding_provenance
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


def get_audit_emitter(store: StoreDep, metrics: MetricsDep) -> AuditEmitter:
    """Return an audit emitter bound to the single-writer store (issue #59).

    Built per request over the same ``StoreDep`` the endpoints use, so a test overriding
    ``get_store`` with an isolated backend automatically audits into that same backend. The process
    ``metrics`` registry is injected so a durable-append failure (fail-closed, issue #99) is
    surfaced as the PII-free ``audit_emit_failures_total`` counter on ``/api/metrics``.
    """
    return AuditEmitter(store, metrics=metrics)


AuditDep = Annotated[AuditEmitter, Depends(get_audit_emitter)]


def _emit_or_fail_closed(
    audit: AuditEmitter,
    *,
    actor: str,
    action: AuditAction,
    subject: str,
    result: AuditResult,
) -> None:
    """Emit a fail-closed audit record as a state-mutation PRECONDITION (audit-BEFORE-write, #99).

    The ACCEPTED, compliance-first decision (ADR 0014) is that a hard audit-store outage must BLOCK
    security-material mutations. To guarantee that, the consequential endpoints call this and let it
    return *before* they mutate durable state:

      * a durable-append failure raises :class:`~shared.audit.AuditPersistenceError` (the emitter is
        fail-closed for these actions) — so the mutation is never performed and the API surfaces a
        5xx;
      * a rejected (un-constructable / PII-invalid) event yields ``None`` from
        :meth:`~shared.audit.AuditEmitter.emit` — which we ALSO convert to a fail-closed 5xx, so a
        subject we could not record can never let the write proceed.

    Either way the caller must not mutate state unless this returns normally, so no committed-but-
    unaudited state can result. Over-recording (an audit record whose subsequent write then fails)
    is the deliberately-chosen safe direction for a repudiation control; committed-unaudited state
    is not.
    """
    event = audit.emit(actor=actor, action=action, subject=subject, result=result)
    if event is None:
        raise HTTPException(status_code=500, detail="audit precondition failed (fail closed)")


def _workload_token(workload: str) -> str:
    """Return an opaque, bounded, PII-free token for the caller-controlled ``workload`` id.

    The workload name reaches the API from the caller and is only weakly constrained by the audit
    contract's :func:`~shared.contracts.is_audit_safe` denylist, which still admits values that look
    like PII (e.g. ``John.Doe``, ``MRN-123456``, ``123-45-6789``). To keep the durable audit
    subjects of the state-mutating endpoints **PII-free BY CONSTRUCTION**, we never embed the raw
    name — we derive a one-way, fixed-charset, fixed-length digest (``wl:<sha256(workload)>``, the
    full 64-char hex). A hash cannot carry PII (or unbounded text) regardless of the input, while
    the trail stays correlatable via the stable per-workload token. The FULL digest is retained (not
    a truncated prefix) so the token is collision-resistant (>=128-bit): a caller controlling
    workload names cannot birthday-collide two distinct names to the same token and make their
    durable audit subjects ambiguous. Tightening the authoritative workload-ID *grammar* itself (in
    the ``shared.contracts`` contract) is a separate follow-up owned by the tenant-isolation work
    (#65); it is deliberately NOT attempted here.
    """
    digest = hashlib.sha256(workload.encode("utf-8")).hexdigest()
    return f"wl:{digest}"


def _finding_emitted_subject(workload: str, count: int) -> str:
    """The exact PII-free subject a ``finding.emitted`` event carries: workload id + finding count.

    Kept as the single source of truth so the pre-write validation checks the *same* string the
    emitter will later build (never drifting apart).
    """
    return f"{workload}#count={count}"


def _run_executed_subject(module: str) -> str:
    """The exact subject a ``run.executed`` event carries: the module identity.

    Single source of truth so the pre-write validation checks the SAME string the emitter later
    builds (they can never drift apart).
    """
    return module


def _require_auditable_run_subject(module: str) -> None:
    """Reject (422) unless the derived ``run.executed`` subject is audit-safe — before any write.

    ``run.executed`` is emitted with the module identity as its subject. A non-audit-safe module id
    (PII / control chars / resource *path* / oversized) would commit the run and THEN drop the
    ``run.executed`` event (state persisted, audit lost). We validate the exact derived subject at
    the boundary and fail closed instead: no un-auditable run is ever persisted.
    """
    if not is_audit_safe(_run_executed_subject(module)):
        raise HTTPException(
            status_code=422,
            detail="module id is not a bounded, PII-free identifier (fail closed)",
        )


def _require_auditable_findings_subject(workload: str, count: int) -> None:
    """Reject (422) unless the DERIVED ``finding.emitted`` subject is audit-safe — before any write.

    A findings write derives a ``finding.emitted`` audit subject (``<workload>#count=N``) from the
    workload id. If that derived subject is PII/oversized/control-bearing (including a workload id
    that is individually ≤256 but whose ``#count=N`` suffix pushes it over the limit), the event
    would fail closed and be silently dropped — persisting findings we cannot audit (and letting a
    PII/oversized workload id into state). Validating the exact derived subject (which is a strict
    superset of validating the raw workload id) fails closed at the boundary: no un-auditable
    findings write is ever accepted.
    """
    if not is_audit_safe(_finding_emitted_subject(workload, count)):
        raise HTTPException(
            status_code=422,
            detail="workload id is not a bounded, PII-free identifier (fail closed)",
        )


def _emit_findings_persisted(
    audit: AuditEmitter, *, actor: str, workload: str, count: int
) -> None:
    """Emit a PII-free ``finding.emitted`` event as a PRECONDITION for persisting findings (#59).

    The subject encodes ONLY the non-PII workload id and a COUNT of findings
    (``<workload>#count=N``) — never a resource id, log body, or other free text. Provenance is
    validated by the caller BEFORE this is called (so a malformed submission is rejected 422 without
    recording a spurious event), and the durable findings write happens AFTER this returns.
    ``finding.emitted`` is a **security-material** action, so emission is fail-CLOSED (issue #99 /
    ADR 0014): a durable-append failure (or a rejected event) surfaces as 5xx via
    :func:`_emit_or_fail_closed`, so findings can never be persisted with no audit record
    (audit-BEFORE-write). See :func:`_workload_token` for the note on the workload id embedded here.
    """
    _emit_or_fail_closed(
        audit,
        actor=actor,
        action=AuditAction.finding_emitted,
        subject=_finding_emitted_subject(workload, count),
        result=AuditResult.success,
    )


def _audit_run_executed(audit: AuditEmitter, *, actor: str, module: str, ok: bool) -> None:
    """Emit the fail-closed ``run.executed`` audit record (subject = the module id; #59, ADR 0014).

    Used as a PRECONDITION on the committing paths (before ``commit_run``) so an audit-store outage
    blocks the commit, and in the ``run_module`` ``finally`` for non-committing (failed / no-
    workload) runs so those are still recorded. Fail-closed via :func:`_emit_or_fail_closed`.
    """
    _emit_or_fail_closed(
        audit,
        actor=actor,
        action=AuditAction.run_executed,
        subject=_run_executed_subject(module),
        result=AuditResult.success if ok else AuditResult.failure,
    )


# --------------------------------------------------------------------------------------
# State-mutating audit coverage (issue #99). `put_estate`/`put_graph`/`snapshot` replace/freeze
# durable state but previously emitted NO audit event. Each now records a PII-free event with a
# bounded, DERIVED subject, emitted as an audit-BEFORE-write PRECONDITION (see
# `_emit_or_fail_closed`): the audit record is durably appended FIRST and only then is the state
# mutation performed, so a hard audit-store outage BLOCKS the mutation (the ACCEPTED decision,
# ADR 0014) rather than leaving committed-but-unaudited state.
#
# The subject is PII-free BY CONSTRUCTION: it is built from the opaque `_workload_token` digest
# (never the raw caller-controlled workload name) plus a bounded COUNT — e.g. `wl:<digest>#estate=N`
# — so no PII (or unbounded text) can appear regardless of the workload name.
#
# ASSUMPTION / TODO(human): the `AuditAction` enum (in the CONTRACT `src/shared/contracts.py`, out
# of scope for this issue's disjointness) has no `estate.replaced`/`graph.replaced`/
# `snapshot.created` members, so these reuse `AuditAction.run_executed` — the umbrella
# "consequential state mutation by the single writer" action (`commit_run` already records
# estate+graph writes as `run.executed`). The operation is disambiguated by the derived subject
# (`#estate=`/`#graph=`/`#snapshot`). Dedicated action members would be cleaner and belong in a
# follow-up CONTRACT change via the Architect + an ADR (they'd also be fail-closed by the same
# `FAIL_CLOSED_ACTIONS` set).
# --------------------------------------------------------------------------------------
def _estate_replaced_subject(workload: str, count: int) -> str:
    """PII-free-by-construction estate-replacement subject: opaque workload token + node COUNT."""
    return f"{_workload_token(workload)}#estate={count}"


def _graph_replaced_subject(workload: str, nodes: int, edges: int) -> str:
    """PII-free-by-construction graph subject: opaque workload token + node/edge counts."""
    return f"{_workload_token(workload)}#graph=nodes={nodes},edges={edges}"


def _snapshot_created_subject(workload: str) -> str:
    """PII-free-by-construction snapshot subject: opaque workload token + a bounded intent marker.

    The store-generated snapshot id (``snap::<workload>::<seq>``) embeds the raw workload name and
    is only known AFTER the write, so — to keep this a true audit-BEFORE-write precondition AND
    PII-free by construction — the durable subject records the bounded intent (``wl:<digest>#
    snapshot``) rather than the post-write id. Over-recording is the safe direction for a
    repudiation control (ADR 0014).
    """
    return f"{_workload_token(workload)}#snapshot"


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

        engine = build_packs_engine()
        if engine is not None:
            # The API is the single writer, so it (not the store-less composition root) gives the
            # pack-verify trust gate a store-backed audit emitter — a fail-closed rejection of a
            # tampered/invalid pack is then recorded to the append-only audit log (issue #59).
            engine.attach_audit_emitter(AuditEmitter(get_store(), metrics=metrics))
        _packs = engine
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


class ModuleHealth(BaseModel):
    """Bounded per-module liveness entry in the health payload (module id + fixed status)."""

    module: str
    status: str


class HealthResponse(BaseModel):
    """Bounded liveness response (issue #91): explicit fields, no free-form egress.

    Preserves the exact shape the compose-smoke gate parses (``status``/``service``/``modules``)
    plus the additive ``live``/``kind`` fields — now as a typed contract so the egress surface is
    statically bounded instead of a raw ``dict``.
    """

    status: str
    service: str
    modules: list[ModuleHealth] = Field(default_factory=list)
    live: bool
    kind: str


@app.get("/api/health")
def health() -> HealthResponse:
    """**Liveness** probe: true while the process is up; NEVER depends on external dependencies.

    Used by CI smoke and platform liveness probes. Its existing shape (``status``/``service``/
    ``modules``) is preserved exactly — the compose-smoke gate parses those keys — and only
    additive fields are appended: ``live`` (always ``True`` here — reaching this handler proves the
    process is serving) and ``kind`` (to distinguish it from the readiness endpoint). Readiness of
    dependencies lives at ``/api/health/ready`` so liveness can never be dragged down by a slow or
    unreachable dependency (which would cause an unnecessary restart loop).

    The response is a bounded :class:`HealthResponse` contract (issue #91) rather than a raw dict,
    so the egress surface is statically PII-free-and-bounded.
    """
    return HealthResponse(
        status="ok",
        service="workloads-platform-api",
        modules=[ModuleHealth.model_validate(m.health()) for m in registry.enabled_modules()],
        live=True,
        kind="liveness",
    )


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
def get_metrics_snapshot(metrics: MetricsDep) -> MetricsSnapshotView:
    """Read-only, vendor-neutral JSON snapshot of the in-process metrics registry.

    Keyless and PII-free: the raw registry accepts arbitrary label maps, so on egress the snapshot
    is projected onto the bounded :class:`MetricsSnapshotView` (issue #91) — label KEYS are the
    closed :class:`MetricLabelKey` allow-list (``module``/``outcome``) and every VALUE is coerced
    through the platform sanitizer, dropping any unexpected label. In production only the sanctioned
    low-cardinality labels are emitted, so this projection is loss-free for real traffic while
    guaranteeing no free-form label can egress. Deliberately JSON (not Prometheus text) to stay
    vendor-neutral.
    """
    return MetricsSnapshotView.from_snapshot(metrics.snapshot())


@app.get("/api/modules")
def list_modules() -> list[ModuleManifest]:
    """Enumerate modules and their scale profiles (drives infra + the web console)."""
    return registry.manifests()


class PackRegistryEntryView(BaseModel):
    """Read model for one published pack version in the wired pack registry (issue #57).

    Presentation-only projection of a :class:`~packs_engine.registry.RegistryEntry` — it is not a
    cross-module contract, so (like :class:`ImpactResult`) it lives here in the API app rather than
    in ``shared.contracts``. Deliberately keyless and PII-free: it carries only the pack's own
    identity (``id``/``version``/``type``), its content-address (``digest`` — the version identity,
    not a secret), its publish timestamp, and a boolean ``signed`` derived from whether the entry
    carries a well-formed detached signature. The raw ``keyId`` and signature bytes are NOT egressed
    — the console only needs to know a version exists and whether it is signed.
    """

    id: str
    version: str
    type: str
    digest: str
    createdAt: str
    signed: bool


@app.get("/api/packs")
def list_packs(packs: PacksDep) -> list[PackRegistryEntryView]:
    """Read-only catalogue of published pack versions in the wired registry (issue #57).

    Thin, keyless, PII-free and fail-closed: when no packs engine / registry is wired (no content
    root, or the import subsystem is absent) this returns ``[]`` — an empty catalogue is never an
    error and never a fabricated entry. Mirrors the ``GET /api/modules`` pattern (project an
    in-process read surface for the console) and never verifies/activates anything; it only reads
    what the registry recorded at admission. ``signed`` reflects whether the entry carries a
    well-formed detached signature (a version identity/provenance signal for the console — the
    runtime resolver still independently re-verifies trust before any pack executes).
    """
    return _pack_catalogue.project(packs)


class _PackCatalogueEgress:
    """Egress projection for the pack-registry catalogue read (issue #57).

    Exposed as a method (a reviewed projection the response boundary trusts, mirroring
    :class:`_EstateEgress`) so the route hands back the value FastAPI coerces through its declared
    ``list[PackRegistryEntryView]`` response model. The view carries only the pack's own identity
    (id/version/type), its content-address ``digest`` (the version identity — not a secret), a
    publish timestamp, and a boolean ``signed``; the raw key id / signature bytes are never
    egressed. Fail-closed: no wired ``PacksEngine`` (hence no registry) ⇒ an empty catalogue.
    """

    @staticmethod
    def project(packs: object) -> list[PackRegistryEntryView]:
        if not isinstance(packs, PacksEngine):
            return []
        return [
            PackRegistryEntryView(
                id=entry.ref.id,
                version=entry.ref.version,
                type=entry.type.value,
                digest=entry.digest,
                createdAt=entry.createdAt.isoformat(),
                signed=entry.detached_signature() is not None,
            )
            for entry in packs.registry_entries()
        ]


_pack_catalogue = _PackCatalogueEgress()


class RunRequest(BaseModel):
    scope: dict[str, str] = {}


class _EstateEgress:
    """Egress projection for estate reads — redacts customer-controlled ``ResourceNode.tags``.

    Exposed as a method (a reviewed sanitizer projection the response boundary trusts) so redaction
    runs on the outbound copy while FastAPI still enforces the declared ``list[ResourceNode]``
    response model. Each node is passed through :func:`~shared.contracts.redact_node_tags`, which
    DEFAULT-REDACTS customer tags (default-deny): every tag VALUE becomes the redaction placeholder
    and every tag KEY becomes a positional placeholder unless its key is platform-owned, so a PII
    key can never egress. The stored estate and the in-process copy used for internal impact/graph
    analysis keep their raw keys and values (issue #91).
    """

    @staticmethod
    def redact(nodes: list[ResourceNode]) -> list[ResourceNode]:
        return [redact_node_tags(node) for node in nodes]


_estate_egress = _EstateEgress()


def _redact_run_result_for_egress(result: ModuleRunResult) -> ModuleRunResult:
    """Project a ``ModuleRunResult`` onto its egress shape (issue #91).

    DEFAULT-REDACTS the two customer-controlled/customer-derived free-form surfaces before the
    result crosses the HTTP response boundary: every ``ResourceNode.tags`` (in ``estate`` and in
    ``graph.nodes``) is sanitized via :func:`~shared.contracts.redact_node_tags` (tag values
    redacted, and tag keys redacted to positional placeholders unless the key is platform-owned),
    and the nested ``extra`` structure is recursively sanitized via
    :func:`~shared.contracts.redact_tree` (every string/bytes/object leaf redacted; only
    numbers/bools/None/enums survive, and only exact platform/module schema keys survive while
    customer-/workload-derived keys become placeholders). Applied to a COPY only — the result the
    API persisted (``commit_run``) and any internal analysis keep raw values.
    """
    update: dict[str, Any] = {"extra": redact_tree(result.extra)}
    if result.estate is not None:
        update["estate"] = [redact_node_tags(n) for n in result.estate]
    if result.graph is not None:
        update["graph"] = result.graph.model_copy(
            update={"nodes": [redact_node_tags(n) for n in result.graph.nodes]}
        )
    return result.model_copy(update=update)


@app.post("/api/modules/{name}/run")
def run_module_endpoint(
    name: str,
    req: RunRequest,
    request: Request,
    store: StoreDep,
    packs: PacksDep,
    clients: ClientsDep,
    metrics: MetricsDep,
    tracer: TracerDep,
    audit: AuditDep,
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

    Audit (issue #59): the executed run is recorded as a ``run.executed`` event — actor = the
    non-PII principal id from the request (else ``system``), subject = the module name, result =
    success/failure — to the append-only audit log, in the ``finally`` so a failed run is audited
    too. Auditing never disrupts the run (the emitter swallows its own errors).
    """
    try:
        module = registry.get(name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    # Validate the derived run.executed subject (the module id) before any write, so a run whose
    # audit event would be dropped is never persisted (defense in depth; registered names are safe).
    _require_auditable_run_subject(name)
    actor = resolve_actor(request.headers)
    started = perf_counter()
    ok = False
    run_audited = False
    with tracer.start_span("module.run", attributes={"module": name}) as span:
        try:
            result = run_module(
                module, scope=req.scope, state=ReadOnlyState(store), packs=packs, clients=clients
            )
            ok = result.ok
            workload = req.scope.get("workload")
            if workload:
                # Validate the exact derived finding.emitted subject + provenance before any write
                # (fail closed) so a malformed run is rejected 422 without a spurious audit event.
                _require_auditable_findings_subject(workload, len(result.findings))
                enforce_finding_provenance(result.findings)
                # Audit-BEFORE-write (fail-closed, ADR 0014): record run.executed (+
                # finding.emitted) FIRST so a hard audit-store outage BLOCKS the commit rather than
                # leaving committed-but-unaudited state. Set ``run_audited`` up front so the
                # ``finally`` never re-emits run.executed on this path (whether the append below
                # succeeds, or fails 5xx).
                run_audited = True
                _audit_run_executed(audit, actor=actor, module=name, ok=ok)
                if result.findings:
                    _emit_findings_persisted(
                        audit, actor=actor, workload=workload, count=len(result.findings)
                    )
                store.commit_run(workload, result)  # API is the single writer
            return _redact_run_result_for_egress(result)
        except ProvenanceError as exc:
            # Fail closed: an un-provenanced finding is rejected before any write; surface a clean
            # 422 (never a 500) and persist nothing. The run is still audited (failure) in the
            # ``finally`` below.
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        finally:
            duration_ms = (perf_counter() - started) * 1000.0
            span.set_attribute("outcome", "ok" if ok else "error")
            metrics.record_module_run(name, ok=ok, duration_ms=duration_ms)
            if not run_audited:
                # Non-committing run (failed, or no-workload scope): no state was mutated, so record
                # run.executed here. Fail-closed emission blocks nothing material on this path.
                _audit_run_executed(audit, actor=actor, module=name, ok=ok)


# --------------------------------------------------------------------------------------
# Submit endpoints — modules/workers hand results to the API, which persists them (writer).
# The request body is a fully typed `ModuleRunResult`, so FastAPI validates the ENTIRE payload
# before the endpoint runs: a bad graph rejects the whole submit and nothing is written. The
# commit itself is atomic (single transaction / manifest commit point), so even a mid-write error
# leaves state unchanged.
# --------------------------------------------------------------------------------------
class PersistCounts(BaseModel):
    """Bounded per-kind write counts returned by an atomic ``commit_run`` (issue #91)."""

    estate: int = Field(ge=0)
    graph: int = Field(ge=0)
    findings: int = Field(ge=0)


class ResultsResponse(BaseModel):
    """Bounded response for the results-submit endpoint (workload id + per-kind counts)."""

    workload: str
    persisted: PersistCounts


@app.post("/api/workloads/{workload}/results")
def submit_results(
    workload: str,
    result: ModuleRunResult,
    request: Request,
    store: StoreDep,
    audit: AuditDep,
) -> ResultsResponse:
    """Accept a validated ``ModuleRunResult`` and persist estate/graph/findings atomically.

    This is how the compute-only ACA worker hands a completed run to the API (the single writer),
    so the executed run is audited here too (issue #59): a ``run.executed`` event, subject = the
    result's module, result = success/failure from ``result.ok``. Findings persist through the
    central provenance gate (an un-provenanced finding fails closed with a 422 and NOTHING is
    written); on success a PII-free ``finding.emitted`` event is also recorded. Auditing never
    blocks the write.

    Returns a bounded :class:`ResultsResponse` (issue #91) rather than a raw dict.
    """
    actor = resolve_actor(request.headers)
    # Validate BOTH derived audit subjects (run.executed + finding.emitted) before any write, so a
    # non-audit-safe module id or workload id can never persist state whose audit event is dropped.
    _require_auditable_run_subject(result.module)
    _require_auditable_findings_subject(workload, len(result.findings))
    # TODO(human): This is the SECOND findings-ingestion path (see add_findings). Structural-
    # provenance trust (issue #83) is enforced only by the contract-level module-emitter allowlist +
    # persistence revalidation, which apply here too (commit_run funnels through the same Finding
    # validator). But `result.module` / `Finding.module` are self-declared, so full enforcement
    # needs PER-MODULE identities or a signed, module-bound submission capability — #64 + #79 as
    # designed (a single shared worker identity) cannot distinguish modules. No auth logic here yet.
    #
    # Audit-BEFORE-write (fail-closed, ADR 0014): validate provenance FIRST (a malformed submission
    # is rejected 422 without a spurious audit event), then record run.executed (+ finding.emitted)
    # BEFORE commit so a hard audit-store outage BLOCKS the commit (5xx, nothing persisted) rather
    # than leaving committed-but-unaudited state. commit_run re-enforces provenance at the durable
    # boundary; both ProvenanceError sources share the single 422 below (no new error-body site).
    try:
        enforce_finding_provenance(result.findings)
        _audit_run_executed(audit, actor=actor, module=result.module, ok=result.ok)
        if result.findings:
            _emit_findings_persisted(
                audit, actor=actor, workload=workload, count=len(result.findings)
            )
        persisted = store.commit_run(workload, result)
    except ProvenanceError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return ResultsResponse(workload=workload, persisted=PersistCounts.model_validate(persisted))


class EstateWriteResult(BaseModel):
    """Bounded response for the estate-replace endpoint (count of persisted nodes)."""

    count: int = Field(ge=0)


class GraphWriteResult(BaseModel):
    """Bounded response for the graph-replace endpoint (node + edge counts)."""

    nodes: int = Field(ge=0)
    edges: int = Field(ge=0)


class FindingsWriteResult(BaseModel):
    """Bounded response for the findings-upsert endpoint (count of upserted findings)."""

    count: int = Field(ge=0)


@app.post("/api/workloads/{workload}/estate")
def put_estate(
    workload: str,
    nodes: list[ResourceNode],
    request: Request,
    store: StoreDep,
    audit: AuditDep,
) -> EstateWriteResult:
    """Replace the persisted estate for ``workload`` (audited, fail-closed — issue #99).

    Records a PII-free ``estate replaced`` audit event (subject = ``wl:<digest>#estate=N`` — an
    opaque one-way workload token + node COUNT only, never the raw workload name or estate content;
    PII-free BY CONSTRUCTION, see :func:`_workload_token`). Estate is security-material, so the
    event is emitted as an audit-BEFORE-write PRECONDITION (ADR 0014): the durable append happens
    FIRST and the state is replaced only if it succeeds, so a hard audit-store outage BLOCKS the
    write (5xx, nothing replaced) rather than leaving committed-but-unaudited state.
    """
    count = len(nodes)
    _emit_or_fail_closed(
        audit,
        actor=resolve_actor(request.headers),
        action=AuditAction.run_executed,
        subject=_estate_replaced_subject(workload, count),
        result=AuditResult.success,
    )
    store.put_estate(workload, nodes)
    return EstateWriteResult(count=count)


@app.post("/api/workloads/{workload}/graph")
def put_graph(
    workload: str, graph: WorkloadGraph, request: Request, store: StoreDep, audit: AuditDep
) -> GraphWriteResult:
    """Replace the persisted dependency graph for ``workload`` (audited, fail-closed — issue #99).

    Records a PII-free ``graph replaced`` audit event (subject ``wl:<digest>#graph=nodes=N,edges=M``
    — an opaque one-way workload token + node/edge COUNTS only, never the raw name or graph content;
    PII-free BY CONSTRUCTION). The graph is security-material, so the event is emitted as an audit-
    BEFORE-write PRECONDITION (ADR 0014): a durable-append failure BLOCKS the write and surfaces as
    5xx (nothing replaced).
    """
    node_count = len(graph.nodes)
    edge_count = len(graph.edges)
    _emit_or_fail_closed(
        audit,
        actor=resolve_actor(request.headers),
        action=AuditAction.run_executed,
        subject=_graph_replaced_subject(workload, node_count, edge_count),
        result=AuditResult.success,
    )
    store.put_graph(workload, graph)
    return GraphWriteResult(nodes=node_count, edges=edge_count)


@app.post("/api/workloads/{workload}/findings")
def add_findings(
    workload: str,
    findings: list[Finding],
    request: Request,
    store: StoreDep,
    audit: AuditDep,
) -> FindingsWriteResult:
    """Upsert findings into the current set for ``workload``.

    Findings persist through the central provenance gate (issue #59): a finding without evidence /
    sourceReferences fails closed with a 422 and NOTHING is written on either backend. On a
    successful write a PII-free ``finding.emitted`` event (subject = ``<workload>#count=N``) is
    recorded to the append-only audit log; auditing never blocks the write.

    Findings persist through the central provenance gate (issue #59): a finding without evidence /
    sourceReferences fails closed with a 422 and NOTHING is written on either backend. On acceptance
    a PII-free ``finding.emitted`` event (subject = ``<workload>#count=N``) is recorded as an audit-
    BEFORE-write PRECONDITION (ADR 0014): the durable append happens FIRST and the findings are
    written only if it succeeds, so a hard audit-store outage BLOCKS the write (5xx, nothing
    persisted) rather than leaving committed-but-unaudited findings.

    Returns a bounded :class:`FindingsWriteResult` (issue #91) rather than a raw dict.
    """
    # Validate the exact derived finding.emitted subject before any write (fail closed).
    _require_auditable_findings_subject(workload, len(findings))
    # TODO(human): Structural-provenance trust (issue #83) is CURRENTLY enforced only by the
    # module-emitter allowlist in shared.contracts (STRUCTURAL_FINDING_EMITTERS) — a defense-in-
    # depth check that a structural/pack-less finding's self-declared `module` matches the single
    # module authorized to emit that StructuralFindingKind (e.g. spof -> dependency_graph). This
    # guards against an HONEST module mismatch but NOT a dishonest caller: `Finding.module` is
    # self-declared. NOTE: findings are ingested via BOTH this path (POST /findings -> add_findings)
    # AND POST /results (submit_results -> commit_run), so the self-declared-`module` gap applies to
    # both; the contract-level module-binding + persistence revalidation cover both, but neither
    # verifies the DECLARER. FULL enforcement requires PER-MODULE identities (NOT the single shared
    # worker identity #79 currently provisions) OR a signed, module-bound submission capability —
    # #64 (Entra auth) + #79 as currently designed are INSUFFICIENT, because they cannot distinguish
    # `dependency_graph` from another module sharing the one worker identity. Do NOT add auth logic
    # here until per-module identities or a module-bound capability exist.
    #
    # Audit-BEFORE-write (fail-closed, ADR 0014): validate provenance FIRST (a malformed submission
    # is rejected 422 without a spurious finding.emitted event), then record finding.emitted BEFORE
    # the write so a hard audit-store outage BLOCKS it (5xx, nothing persisted). The emit is
    # UNCONDITIONAL — even an EMPTY submission is audited (`#count=0`) before store.add_findings,
    # because add_findings([]) is NOT a no-op on the durable store (it creates the workload manifest
    # and advances its version), so skipping the audit for the empty case would allow a committed-
    # but-unaudited mutation. add_findings re-enforces provenance at the durable boundary; both
    # ProvenanceError sources share the single 422 below (no new error-body site).
    try:
        enforce_finding_provenance(findings)
        _emit_findings_persisted(
            audit, actor=resolve_actor(request.headers), workload=workload, count=len(findings)
        )
        store.add_findings(workload, findings)
    except ProvenanceError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return FindingsWriteResult(count=len(findings))


class SnapshotResult(BaseModel):
    """Bounded response for the snapshot endpoint (the new snapshot's id)."""

    snapshotId: str


@app.post("/api/workloads/{workload}/snapshot")
def snapshot(
    workload: str, request: Request, store: StoreDep, audit: AuditDep
) -> SnapshotResult:
    """Freeze current findings into a point-in-time snapshot; return its id (audited — issue #99).

    Records a PII-free ``snapshot created`` audit event (subject = ``wl:<digest>#snapshot`` — an
    opaque one-way workload token + a bounded intent marker; PII-free BY CONSTRUCTION, and NOT the
    store-generated id which embeds the raw workload name and is only known post-write). A snapshot
    is security-material state, so the event is emitted as an audit-BEFORE-write PRECONDITION
    (ADR 0014): the durable append happens FIRST and the snapshot is frozen only if it succeeds, so
    a hard audit-store outage BLOCKS the write (5xx, nothing frozen).
    """
    _emit_or_fail_closed(
        audit,
        actor=resolve_actor(request.headers),
        action=AuditAction.run_executed,
        subject=_snapshot_created_subject(workload),
        result=AuditResult.success,
    )
    snapshot_id = store.snapshot(workload)
    return SnapshotResult(snapshotId=snapshot_id)


# --------------------------------------------------------------------------------------
# Read endpoints — read models the web console/API query (estate, graph, findings, drift).
# --------------------------------------------------------------------------------------
@app.get("/api/workloads")
def list_workloads(store: StoreDep) -> list[str]:
    """List every workload the store knows about."""
    return store.list_workloads()


@app.get("/api/workloads/{workload}/estate")
def get_estate(workload: str, store: StoreDep) -> list[ResourceNode]:
    """Return the latest estate for ``workload`` (empty list if none).

    Customer-controlled ``ResourceNode.tags`` are DEFAULT-REDACTED at this egress projection via
    :func:`~shared.contracts.redact_node_tags` (issue #91): every tag VALUE becomes the redaction
    placeholder and every tag KEY becomes a positional placeholder unless its key is platform-owned,
    so a PII key cannot egress. The stored estate and the in-process copy used for internal
    impact/graph analysis keep the raw keys and values.
    """
    return _estate_egress.redact(store.get_estate(workload))


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
    """Return the latest dependency graph for ``workload`` + its revision (404 if none).

    Customer-controlled ``ResourceNode.tags`` on the graph nodes are DEFAULT-REDACTED at this egress
    projection via :func:`~shared.contracts.redact_node_tags` (issue #91): tag values are redacted
    and tag keys are redacted to positional placeholders unless the key is platform-owned. The
    persisted graph and the revision (computed over the FULL raw topology) are unaffected.
    """
    graph = store.get_graph(workload)
    if graph is None:
        raise HTTPException(status_code=404, detail=f"no graph for workload {workload!r}")
    return GraphResponse(
        nodes=[redact_node_tags(n) for n in graph.nodes],
        edges=graph.edges,
        graphRevision=graph_revision(graph),
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


class RootResponse(BaseModel):
    """Bounded service-index response for ``GET /`` (fixed name + doc/health hrefs, issue #91)."""

    name: str
    docs: str
    health: str


@app.get("/")
def root() -> RootResponse:
    return RootResponse(name="workloads-platform", docs="/docs", health="/api/health")
