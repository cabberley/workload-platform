"""API core — FastAPI app: health, the module registry, cycle orchestration, and durable state.

The API is the **single writer** of shared state. Modules submit their results here (rather than
writing concurrently) and the API persists them via the :class:`~shared.state.StateStore`. Modules
that the API runs in-process receive a *read-only* ``ReadOnlyState`` view. This keeps ``api`` at
low replica counts while the compute-heavy modules scale freely.
"""
from __future__ import annotations

import base64
import binascii
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from packs_engine.registry import (
    DEFAULT_INDEX_PATH,
    ImmutableVersionError,
    InvalidVersionError,
    PackRef,
    PackRegistry,
    RegistryError,
)
from shared.contracts import (
    DriftReport,
    Finding,
    ModuleRunResult,
    PackAssignment,
    PackSignature,
    ResourceNode,
    WorkloadGraph,
)
from shared.module_base import build_default_registry, run_module
from shared.signing import Ed25519Verifier, Verifier, verify_pack
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


# The pack registry (issue #34) is the immutable, content-addressed index that `import` publishes
# verified versions into. Built once per process from the on-disk index path (overridable via
# `WP_REGISTRY_INDEX` so a deployment can relocate it); tests override `get_pack_registry` with an
# isolated tmp-path registry via `app.dependency_overrides`.
_pack_registry: PackRegistry | None = None

# Env var *name* only — the value (a base64 raw Ed25519 public key) is supplied at runtime by
# identity / Key Vault, never embedded here (keyless).
ENV_PACK_PUBLIC_KEY = "WP_PACK_PUBLIC_KEY"
ENV_REGISTRY_INDEX = "WP_REGISTRY_INDEX"


def get_pack_registry() -> PackRegistry:
    """Return the process-wide pack registry (import's publish target). Cached after first build."""
    global _pack_registry
    if _pack_registry is None:
        index_path = os.environ.get(ENV_REGISTRY_INDEX)
        _pack_registry = PackRegistry(Path(index_path) if index_path else DEFAULT_INDEX_PATH)
    return _pack_registry


def get_pack_verifier() -> Verifier | None:
    """Build the detached-signature trust root from ``WP_PACK_PUBLIC_KEY`` (base64 raw Ed25519).

    Mirrors ``scripts/validate_packs.py``'s trust-root pattern: no private key is ever read — only
    a public trust root, and only when explicitly configured. Returns ``None`` when unconfigured;
    the ``import`` endpoint then fails **closed** (a present signature that cannot be verified is
    rejected), never open. Tests inject an ``Ed25519Verifier`` via ``app.dependency_overrides``.

    TODO(human): point ``WP_PACK_PUBLIC_KEY`` at the real Azure Key Vault public trust root (export
    the KV signing key's public bytes to the API by identity — same follow-up as issue #35), so the
    core verifies imports against the same key the release pipeline signs with. Until then a signed
    bundle cannot be verified and — per fail-closed — imports are rejected.
    """
    b64 = os.environ.get(ENV_PACK_PUBLIC_KEY)
    if not b64:
        return None
    try:
        return Ed25519Verifier.from_public_bytes(base64.b64decode(b64, validate=True))
    except (binascii.Error, ValueError):
        # A malformed trust root is treated as *no* trust root (fail closed): a present signature
        # can then never be verified, so imports are rejected rather than silently trusted.
        return None


PackRegistryDep = Annotated[PackRegistry, Depends(get_pack_registry)]
VerifierDep = Annotated[Verifier | None, Depends(get_pack_verifier)]


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
    name: str, req: RunRequest, store: StoreDep, packs: PacksDep, clients: ClientsDep,
    packs_registry: PackRegistryDep,
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
    workload = req.scope.get("workload")
    # Resolve the packs view the module sees to a SINGLE deterministic version per pack id (#37).
    # The resolver is applied to EVERY run — workload-scoped or not — so no run can execute multiple
    # versions of one id. With a workload, each id carrying an assignment runs EXACTLY that version
    # and only if the content pack's canonical digest matches the registry's VERIFIED digest (bytes
    # bound to signature-verified content); an id with no assignment (or a workload-less run)
    # resolves to the highest valid semver — a single version, never every one. So a run never
    # fails merely because nothing is assigned (documented fallback in `cli.wiring`).
    from cli.wiring import resolve_packs_for_workload

    assigned_versions = (
        {a.packId: a.version for a in store.get_pack_assignments(workload)} if workload else {}
    )
    resolved_packs = resolve_packs_for_workload(packs, assigned_versions, packs_registry)
    result = run_module(
        module, scope=req.scope, state=ReadOnlyState(store), packs=resolved_packs, clients=clients
    )
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
# Pack lifecycle (issue #37) — the CUSTOMER side. Import a signed bundle (verify fail-closed,
# then register the version) and assign a pack version per workload. Writes go ONLY through the
# API core (single writer); the SPA never mutates. Assignment reads give MS + customer visibility.
# --------------------------------------------------------------------------------------
class PackImportRequest(BaseModel):
    """A signed pack bundle to import: the pack itself plus its detached signature envelope.

    ``signature`` is optional in the wire shape ONLY so an unsigned bundle is rejected with an
    explicit fail-closed 400 (rather than a 422 schema error) — it is never optional in effect.
    """

    pack: dict[str, object]
    signature: PackSignature | None = None


@app.post("/api/packs/import")
def import_pack(
    req: PackImportRequest, packs_registry: PackRegistryDep, verifier: VerifierDep
) -> dict[str, object]:
    """Verify a signed bundle's detached signature (fail-closed), then publish the version.

    Fail-closed at every step — a bundle is registered ONLY if its signature cryptographically
    verifies against the injected trust root:

    * no ``signature`` (unsigned)            → 400 (never trusted);
    * no trust root configured (``None``)    → 400 (a present signature cannot be verified);
    * signature invalid / tampered / wrong   → 400 (:func:`shared.signing.verify_pack` is False);
    * malformed manifest / non-semver version→ 400 (registry ``publish`` rejects it);
    * immutable-version conflict             → 409 (same ``id@version``, different content).

    Only after verification does it call :meth:`PackRegistry.publish` (the immutability gate) and
    return the resulting :class:`~packs_engine.registry.RegistryEntry`.

    TODO(human): materialize the verified imported pack's BYTES into a digest-addressed content
    store (ADR pending — local disk vs Azure Blob/Files/Table, with statefulness/billing/MSP-
    tenancy implications) so import->assign->run resolves a BRAND-NEW pack. Today the registry is a
    pure metadata index (id@version -> verified digest); assigned resolution runs a pack only when
    a content-root pack's canonical digest matches that verified digest, so a just-imported pack
    whose bytes are not yet in the content root safely runs nothing under its assignment.
    """
    signature = req.signature
    if signature is None:
        raise HTTPException(
            status_code=400, detail="import rejected: bundle is unsigned (fail closed)"
        )
    if verifier is None:
        raise HTTPException(
            status_code=400,
            detail=(
                "import rejected: no pack trust root is configured, so a present signature cannot "
                "be verified (set WP_PACK_PUBLIC_KEY); failing closed"
            ),
        )
    if not verify_pack(req.pack, signature, verifier):
        raise HTTPException(
            status_code=400,
            detail="import rejected: detached signature is invalid or the bundle was tampered",
        )
    try:
        entry = packs_registry.publish(req.pack)
    except ImmutableVersionError as exc:
        raise HTTPException(status_code=409, detail=f"import rejected: {exc}") from exc
    except (InvalidVersionError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"import rejected: {exc}") from exc
    except RegistryError as exc:
        raise HTTPException(status_code=400, detail=f"import rejected: {exc}") from exc
    return entry.to_dict()


class PackAssignmentRequest(BaseModel):
    """Assign a pack version to the path workload. ``assignedAt`` is set by the core (provenance).
    """

    packId: str
    version: str
    assignedBy: str


@app.put("/api/workloads/{workload}/pack-assignments")
def put_pack_assignment(
    workload: str, req: PackAssignmentRequest, store: StoreDep, packs_registry: PackRegistryDep
) -> PackAssignment:
    """Pin ``workload`` to ``packId@version`` (single writer; records assignedBy/assignedAt).

    Fail-closed binding to VERIFIED content: an assignment may only point at an EXACT immutable
    registry entry for ``packId@version``. The registry holds *only* signature-verified imported
    packs (``POST /api/packs/import`` publishes into it after :func:`shared.signing.verify_pack`),
    so requiring ``registry.get(packId@version)`` before persisting guarantees a workload can never
    be pinned to an un-imported / unverified version. If no such entry exists we persist NOTHING
    and reject 422 — a run can then never resolve unverified content under an assigned id.
    """
    if packs_registry.get(PackRef(id=req.packId, version=req.version)) is None:
        raise HTTPException(
            status_code=422,
            detail=(
                f"assignment rejected: {req.packId}@{req.version} is not a verified, imported pack "
                "in the registry (import it via POST /api/packs/import first); failing closed"
            ),
        )
    assignment = PackAssignment(
        workload=workload,
        packId=req.packId,
        version=req.version,
        assignedBy=req.assignedBy,
    )
    store.put_pack_assignment(assignment)  # API is the single writer
    return assignment


@app.get("/api/workloads/{workload}/pack-assignments")
def get_pack_assignments(workload: str, store: StoreDep) -> list[PackAssignment]:
    """Return the pack-version assignments for ``workload`` (MS + customer visibility)."""
    return store.get_pack_assignments(workload)


@app.get("/api/pack-assignments")
def list_pack_assignments(store: StoreDep) -> list[PackAssignment]:
    """Return every pack-version assignment across all workloads (MS + customer visibility)."""
    return store.list_pack_assignments()


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
