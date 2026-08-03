"""API core — FastAPI app: health, the module registry, cycle orchestration, and durable state.

The API is the **single writer** of shared state. Modules submit their results here (rather than
writing concurrently) and the API persists them via the :class:`~shared.state.StateStore`. Modules
that the API runs in-process receive a *read-only* ``ReadOnlyState`` view. This keeps ``api`` at
low replica counts while the compute-heavy modules scale freely.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from shared.contracts import (
    DriftReport,
    Finding,
    ModuleRunResult,
    ResourceNode,
    WorkloadGraph,
)
from shared.module_base import build_default_registry, run_module
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

registry = build_default_registry()

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
    """Liveness + per-module health. Used by CI smoke and platform probes."""
    return {
        "status": "ok",
        "service": "workloads-platform-api",
        "modules": [m.health() for m in registry.enabled_modules()],
    }


@app.get("/api/modules")
def list_modules() -> list[dict[str, object]]:
    """Enumerate modules and their scale profiles (drives infra + the web console)."""
    return [m.model_dump() for m in registry.manifests()]


class RunRequest(BaseModel):
    scope: dict[str, str] = {}


@app.post("/api/modules/{name}/run")
def run_module_endpoint(
    name: str, req: RunRequest, store: StoreDep, packs: PacksDep, clients: ClientsDep
) -> ModuleRunResult:
    """Run a single module by name (also how the ACA Job worker's compute is exercised in-process).

    Compute and write are separated: :func:`~shared.module_base.run_module` computes the result
    with a **read-only** state view (it cannot write shared state), the verified ``packs`` engine,
    and the keyless edge-client registry injected here at the boundary; then — because this is the
    API, the single writer — the endpoint commits the run atomically when the scope carries a
    ``workload`` (findings always, plus estate/graph when the run produced them). The API keeps its
    fast in-process ``ReadOnlyState`` view (it is co-located with the store); only the worker reads
    over HTTP.
    """
    try:
        module = registry.get(name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    result = run_module(
        module, scope=req.scope, state=ReadOnlyState(store), packs=packs, clients=clients
    )
    workload = req.scope.get("workload")
    if workload:
        store.commit_run(workload, result)  # API is the single writer
    return result


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


@app.get("/api/workloads/{workload}/graph")
def get_graph(workload: str, store: StoreDep) -> WorkloadGraph:
    """Return the latest dependency graph for ``workload`` (404 if none persisted yet)."""
    graph = store.get_graph(workload)
    if graph is None:
        raise HTTPException(status_code=404, detail=f"no graph for workload {workload!r}")
    return graph


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
