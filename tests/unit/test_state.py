"""Durable state (local backend) round-trips, snapshots/drift, single-writer view, and API.

All tests use the deterministic ``LocalStateStore`` in an isolated ``tmp_path`` so they are
Azure-free and hermetic. The FastAPI tests override the ``get_store`` dependency to point at the
same isolated backend. Each test below is written so it would fail without the corresponding fix.
"""
from __future__ import annotations

import importlib.util
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.app.main import app, get_store, registry
from modules.dependency_graph.module import DependencyGraphModule
from modules.discovery.module import DiscoveryModule
from shared.contracts import (
    DependencyEdge,
    EdgeType,
    Finding,
    ModuleKind,
    ModuleManifest,
    ModuleRunResult,
    ResourceNode,
    ScaleProfile,
    Severity,
    WorkloadGraph,
)
from shared.module_base import Module, ModuleContext, run_module
from shared.state import (
    LocalStateStore,
    ReadableState,
    ReadOnlyState,
    StateStore,
    build_state_store,
    compute_drift,
    encode_storage_key,
)

WORKER_SOURCE = (
    Path(__file__).resolve().parents[2] / "src" / "cli" / "worker.py"
).read_text(encoding="utf-8")


# --------------------------------------------------------------------------------------
# Fixtures + synthetic (clearly-fake) data.
# --------------------------------------------------------------------------------------
@pytest.fixture()
def store(tmp_path) -> LocalStateStore:
    return LocalStateStore(str(tmp_path))


def _nodes() -> list[ResourceNode]:
    return [
        ResourceNode(id="vm-odb-1", name="odb-1", type="Microsoft.Compute/virtualMachines",
                     workload="epic", tier="database", role="odb", tags={"env": "test"}),
        ResourceNode(id="lb-web", name="web-lb", type="Microsoft.Network/loadBalancers",
                     workload="epic", tier="web", role="lb"),
    ]


def _graph() -> WorkloadGraph:
    return WorkloadGraph(
        nodes=_nodes(),
        edges=[DependencyEdge(source="lb-web", target="vm-odb-1", type=EdgeType.depends_on)],
    )


def _finding(fid: str, module: str, *, passed: bool | None) -> Finding:
    return Finding(id=fid, module=module, title=fid, passed=passed, severity=Severity.high)


def _azure_tables_installed() -> bool:
    """True if ``azure.data.tables`` is importable.

    ``importlib.util.find_spec`` raises ``ModuleNotFoundError`` when an intermediate parent (here
    ``azure.data``) is absent, so guard it rather than letting collection fail.
    """
    try:
        return importlib.util.find_spec("azure.data.tables") is not None
    except ModuleNotFoundError:
        return False


class _SyntheticModule(Module):
    """A fake module that returns synthetic estate/graph/findings (no business logic)."""

    @property
    def manifest(self) -> ModuleManifest:
        return ModuleManifest(
            name="synthetic", displayName="Synthetic", kind=ModuleKind.job,
            scaleProfile=ScaleProfile(kind=ModuleKind.job),
        )

    def run(self, ctx: ModuleContext, *, scope: dict[str, str] | None = None) -> ModuleRunResult:
        return ModuleRunResult(
            module="synthetic", ok=True,
            estate=_nodes(), graph=_graph(),
            findings=[_finding("q1", "quality_checks", passed=False)],
        )


# --------------------------------------------------------------------------------------
# Round trips.
# --------------------------------------------------------------------------------------
def test_estate_round_trip(store: LocalStateStore) -> None:
    assert store.get_estate("epic") == []
    store.put_estate("epic", _nodes())
    loaded = store.get_estate("epic")
    assert [n.id for n in loaded] == ["vm-odb-1", "lb-web"]
    assert loaded[0].role == "odb"
    assert loaded[0].tags == {"env": "test"}


def test_put_estate_replaces_previous(store: LocalStateStore) -> None:
    store.put_estate("epic", _nodes())
    store.put_estate("epic", [_nodes()[0]])
    loaded = store.get_estate("epic")
    assert [n.id for n in loaded] == ["vm-odb-1"]


def test_graph_round_trip(store: LocalStateStore) -> None:
    assert store.get_graph("epic") is None
    store.put_graph("epic", _graph())
    loaded = store.get_graph("epic")
    assert loaded is not None
    assert [n.id for n in loaded.nodes] == ["vm-odb-1", "lb-web"]
    assert loaded.edges[0].source == "lb-web"
    assert loaded.edges[0].type == EdgeType.depends_on


def test_findings_round_trip_and_module_filter(store: LocalStateStore) -> None:
    store.add_findings("epic", [
        _finding("q1", "quality_checks", passed=False),
        _finding("spof::vm-odb-1", "dependency_graph", passed=False),
    ])
    all_findings = store.get_findings("epic")
    assert {f.id for f in all_findings} == {"q1", "spof::vm-odb-1"}
    quality = store.get_findings("epic", module="quality_checks")
    assert [f.id for f in quality] == ["q1"]


def test_add_findings_upserts_by_id(store: LocalStateStore) -> None:
    store.add_findings("epic", [_finding("q1", "quality_checks", passed=False)])
    store.add_findings("epic", [_finding("q1", "quality_checks", passed=True)])
    findings = store.get_findings("epic")
    assert len(findings) == 1
    assert findings[0].passed is True


def test_list_workloads_unions_all_kinds(store: LocalStateStore) -> None:
    store.put_estate("epic", _nodes())
    store.put_graph("sap", _graph())
    store.add_findings("citrix", [_finding("q1", "quality_checks", passed=False)])
    assert store.list_workloads() == ["citrix", "epic", "sap"]


# --------------------------------------------------------------------------------------
# Snapshots + previous findings/nodes + drift  (fix 6: estate drift capable).
# --------------------------------------------------------------------------------------
def test_snapshot_captures_current_findings(store: LocalStateStore) -> None:
    assert store.get_previous_findings("epic") == []
    store.add_findings("epic", [_finding("q1", "quality_checks", passed=False)])
    snap_id = store.snapshot("epic")
    assert snap_id == "snap::epic::000001"
    previous = store.get_previous_findings("epic")
    assert [f.id for f in previous] == ["q1"]


def test_snapshot_captures_estate_node_ids(store: LocalStateStore) -> None:
    store.put_estate("epic", _nodes())
    store.add_findings("epic", [_finding("q1", "quality_checks", passed=False)])
    store.snapshot("epic")
    assert store.get_previous_node_ids("epic") == ["vm-odb-1", "lb-web"]
    assert [f.id for f in store.get_previous_findings("epic")] == ["q1"]


def test_previous_findings_returns_latest_snapshot(store: LocalStateStore) -> None:
    store.add_findings("epic", [_finding("q1", "quality_checks", passed=False)])
    first = store.snapshot("epic")
    store.add_findings("epic", [_finding("q2", "quality_checks", passed=False)])
    second = store.snapshot("epic")
    assert (first, second) == ("snap::epic::000001", "snap::epic::000002")
    previous = store.get_previous_findings("epic")
    assert {f.id for f in previous} == {"q1", "q2"}


def test_compute_drift_new_recovered_still() -> None:
    previous = [
        _finding("q1", "quality_checks", passed=False),
        _finding("q2", "quality_checks", passed=False),
    ]
    current = [
        _finding("q1", "quality_checks", passed=False),   # still failing
        _finding("q2", "quality_checks", passed=True),    # recovered
        _finding("q3", "quality_checks", passed=False),   # new failure
    ]
    drift = compute_drift(previous, current, workload="epic")
    assert drift.workload == "epic"
    assert [f.id for f in drift.newFailures] == ["q3"]
    assert [f.id for f in drift.recovered] == ["q2"]
    assert [f.id for f in drift.stillFailing] == ["q1"]


def test_compute_drift_reports_estate_node_deltas() -> None:
    drift = compute_drift(
        [], [], workload="epic", previous_nodes=["a", "b"], current_nodes=["b", "c"]
    )
    assert drift.addedNodes == ["c"]
    assert drift.removedNodes == ["a"]


def test_snapshot_then_drift_via_store(store: LocalStateStore) -> None:
    store.add_findings("epic", [_finding("q1", "quality_checks", passed=False)])
    store.snapshot("epic")
    store.add_findings("epic", [_finding("q1", "quality_checks", passed=True)])
    drift = compute_drift(
        store.get_previous_findings("epic"), store.get_findings("epic"), workload="epic"
    )
    assert [f.id for f in drift.recovered] == ["q1"]
    assert drift.newFailures == []


# --------------------------------------------------------------------------------------
# Fix 3 — snapshot id allocation is atomic under concurrency (distinct ids, no errors).
# --------------------------------------------------------------------------------------
def test_snapshots_get_distinct_ids_in_quick_succession(store: LocalStateStore) -> None:
    a = store.snapshot("epic")
    b = store.snapshot("epic")
    assert a != b


def test_concurrent_snapshots_get_distinct_ids(store: LocalStateStore) -> None:
    store.add_findings("epic", [_finding("q1", "quality_checks", passed=False)])
    results: list[str] = []
    errors: list[Exception] = []
    lock = threading.Lock()

    def take() -> None:
        try:
            snap = store.snapshot("epic")
        except Exception as exc:  # pragma: no cover - only hit on a regression
            with lock:
                errors.append(exc)
        else:
            with lock:
                results.append(snap)

    threads = [threading.Thread(target=take) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(results) == 6
    assert len(set(results)) == 6  # every id is unique — no read-modify-write collision


# --------------------------------------------------------------------------------------
# Fix 1 — key encoding is deterministic and injection-proof (pure, no Azure).
# --------------------------------------------------------------------------------------
def test_encode_storage_key_blocks_odata_injection() -> None:
    malicious = "epic' or PartitionKey ne '"
    encoded = encode_storage_key(malicious)
    # Only hex characters — cannot contain a quote or an OData operator, so it cannot alter a
    # filter or the partition it targets.
    assert set(encoded) <= set("0123456789abcdef")
    assert "'" not in encoded
    # Deterministic and reversible (writes/reads round-trip to the same key).
    assert encode_storage_key(malicious) == encoded
    assert bytes.fromhex(encoded).decode() == malicious


def test_encode_storage_key_distinct_and_stable() -> None:
    assert encode_storage_key("epic") == "65706963"
    assert encode_storage_key("epic") != encode_storage_key("sap")


# --------------------------------------------------------------------------------------
# Fix 4 (+ round-2 re-flag) — the module-facing view exposes no path to a writer.
# --------------------------------------------------------------------------------------
_WRITE_METHODS = ("put_estate", "put_graph", "add_findings", "snapshot", "commit_run")


def test_module_state_view_is_read_only(store: LocalStateStore) -> None:
    view = ReadOnlyState(store)
    for writer in _WRITE_METHODS:
        assert not hasattr(view, writer)
    # The footgun: the writable store must not be reachable as an attribute of the view.
    assert not hasattr(view, "_backend")
    for attr in vars(view).values():
        assert attr is not store
    for reader in (
        "list_workloads", "get_estate", "get_graph", "get_findings",
        "get_previous_findings", "get_previous_node_ids",
    ):
        assert hasattr(view, reader)
    # Structural checks: it is a ReadableState but not a full (writable) StateStore.
    assert isinstance(view, ReadableState)
    assert not isinstance(view, StateStore)


def test_read_only_bound_methods_self_has_no_writer(store: LocalStateStore) -> None:
    # Round-2 re-flag: a captured bound read method must NOT expose a writable backend via its
    # ``__self__`` (the old code bound directly to the store, so ``_get_estate.__self__`` WAS the
    # writable store). Now every bound method's ``__self__`` is the private read-only reader.
    view = ReadOnlyState(store)
    bound_selves = [
        getattr(attr, "__self__", None) for attr in vars(view).values()
    ]
    assert any(owner is not None for owner in bound_selves)  # they really are bound methods
    for owner in bound_selves:
        if owner is None:
            continue
        assert owner is not store
        for writer in _WRITE_METHODS:
            assert not hasattr(owner, writer)
    # And the obvious traversal a careless module might try is dead:
    assert not hasattr(view.get_estate.__self__, "put_estate")


def test_read_only_view_reads_through_to_backend(store: LocalStateStore) -> None:
    store.put_estate("epic", _nodes())
    view = ReadOnlyState(store)
    assert [n.id for n in view.get_estate("epic")] == ["vm-odb-1", "lb-web"]
    assert view.list_workloads() == ["epic"]


def test_module_context_state_is_read_only(store: LocalStateStore) -> None:
    ctx = ModuleContext(state=ReadOnlyState(store))
    assert ctx.state is not None
    assert not hasattr(ctx.state, "put_estate")
    assert not hasattr(ctx.state, "_backend")


def test_module_context_defaults_backward_compatible() -> None:
    ctx = ModuleContext()
    assert ctx.state is None
    assert ctx.config == {}


# --------------------------------------------------------------------------------------
# Fix 2/3 — commit_run: atomic persist with is-not-None (clear vs untouch) semantics.
# --------------------------------------------------------------------------------------
def test_commit_run_writes_all_present_outputs(store: LocalStateStore) -> None:
    result = ModuleRunResult(
        module="synthetic", ok=True, estate=_nodes(), graph=_graph(),
        findings=[_finding("q1", "quality_checks", passed=False)],
    )
    counts = store.commit_run("epic", result)
    assert counts == {"estate": 2, "graph": 1, "findings": 1}
    assert [n.id for n in store.get_estate("epic")] == ["vm-odb-1", "lb-web"]
    assert store.get_graph("epic") is not None
    assert [f.id for f in store.get_findings("epic")] == ["q1"]


def test_commit_run_empty_estate_clears_state(store: LocalStateStore) -> None:
    store.put_estate("epic", _nodes())
    # An explicit empty estate (not None) CLEARS stale state — is-not-None, not truthiness.
    store.commit_run("epic", ModuleRunResult(module="discovery", estate=[]))
    assert store.get_estate("epic") == []


def test_commit_run_none_estate_leaves_state_untouched(store: LocalStateStore) -> None:
    store.put_estate("epic", _nodes())
    # estate defaults to None => "this run did not touch the estate" => existing state preserved.
    store.commit_run(
        "epic",
        ModuleRunResult(module="quality_checks",
                        findings=[_finding("q1", "quality_checks", passed=False)]),
    )
    assert [n.id for n in store.get_estate("epic")] == ["vm-odb-1", "lb-web"]
    assert [f.id for f in store.get_findings("epic")] == ["q1"]


def test_commit_run_is_all_or_nothing(store: LocalStateStore, monkeypatch) -> None:
    # Seed a known estate, then force the graph write to fail mid-commit. Because commit_run runs
    # in ONE transaction, the estate write must roll back — no partial mutation.
    store.put_estate("epic", [_nodes()[0]])

    def boom(_conn, _workload, _graph) -> None:
        raise RuntimeError("graph write failed")

    monkeypatch.setattr(store, "_write_graph", boom)
    result = ModuleRunResult(module="discovery", estate=_nodes(), graph=_graph())
    with pytest.raises(RuntimeError, match="graph write failed"):
        store.commit_run("epic", result)
    # Estate is unchanged from before the failed commit (rolled back).
    assert [n.id for n in store.get_estate("epic")] == ["vm-odb-1"]


# --------------------------------------------------------------------------------------
# Factory selection + Fix 5 (azure extra).
# --------------------------------------------------------------------------------------
def test_factory_builds_local_backend(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("WORKLOADS_STATE_BACKEND", "local")
    monkeypatch.setenv("WORKLOADS_STATE_DIR", str(tmp_path))
    built = build_state_store()
    assert isinstance(built, LocalStateStore)


def test_factory_rejects_unknown_backend(monkeypatch) -> None:
    monkeypatch.setenv("WORKLOADS_STATE_BACKEND", "mystery")
    with pytest.raises(ValueError, match="mystery"):
        build_state_store()


@pytest.mark.skipif(
    _azure_tables_installed(),
    reason="azure extra is installed; the missing-deps path cannot be exercised",
)
def test_azure_backend_without_extra_raises_actionable_error(monkeypatch) -> None:
    monkeypatch.setenv("WORKLOADS_STATE_BACKEND", "azure")
    monkeypatch.setenv("WORKLOADS_STATE_TABLE_ENDPOINT", "https://x.table.core.windows.net")
    monkeypatch.setenv("WORKLOADS_STATE_BLOB_ENDPOINT", "https://x.blob.core.windows.net")
    with pytest.raises(RuntimeError, match=r"pip install \.\[azure\]"):
        build_state_store()


# --------------------------------------------------------------------------------------
# Fix 1 — single-writer: run_module is COMPUTE-ONLY and the worker never writes state.
# --------------------------------------------------------------------------------------
def test_run_module_is_compute_only_and_does_not_persist(store: LocalStateStore) -> None:
    module = _SyntheticModule()
    result = run_module(module, scope={"workload": "epic"}, state=ReadOnlyState(store))
    # It computed the synthetic outputs...
    assert result.estate is not None and len(result.estate) == 2
    assert result.graph is not None
    # ...but wrote nothing: compute is separated from persistence (the API is the only writer).
    assert store.list_workloads() == []


def test_worker_source_does_not_write_state() -> None:
    # The worker must not import/construct a StateStore or call any persist/commit path — it POSTs
    # results to the API (the single writer) instead. Guarding on source keeps the invariant real.
    assert "StateStore" not in WORKER_SOURCE
    assert "build_state_store" not in WORKER_SOURCE
    assert "persist_run" not in WORKER_SOURCE
    assert "commit_run" not in WORKER_SOURCE
    assert "put_estate" not in WORKER_SOURCE
    # It computes then hands off over HTTP.
    assert "run_module" in WORKER_SOURCE
    assert "httpx" in WORKER_SOURCE
    assert "/api/workloads/" in WORKER_SOURCE


def test_only_src_api_calls_the_write_surface() -> None:
    # Repo-wide guard: persist/commit/put_* are only *called* from inside src/api (the writer).
    # state.py defines them; module code and the worker must not invoke them.
    src = Path(__file__).resolve().parents[2] / "src"
    offenders: list[str] = []
    for path in src.rglob("*.py"):
        rel = path.relative_to(src).as_posix()
        if rel.startswith("api/") or rel == "shared/state.py":
            continue  # the API is the writer; state.py defines the surface
        text = path.read_text(encoding="utf-8")
        for needle in (".commit_run(", ".put_estate(", ".put_graph(", ".add_findings("):
            if needle in text:
                offenders.append(f"{rel}:{needle}")
    assert offenders == []


# --------------------------------------------------------------------------------------
# Fix 2 — the real modules surface estate / graph on their result (so the API can persist).
# --------------------------------------------------------------------------------------
def test_discovery_module_emits_estate() -> None:
    result = run_module(DiscoveryModule(), scope={"workload": "epic"})
    # estate is a list (present, is-not-None) — populated with real ARG nodes in issue #2.
    assert result.estate is not None
    assert isinstance(result.estate, list)


def test_dependency_graph_module_emits_graph() -> None:
    result = run_module(DependencyGraphModule(), scope={"workload": "epic"})
    assert result.graph is not None
    assert isinstance(result.graph, WorkloadGraph)


# --------------------------------------------------------------------------------------
# FastAPI endpoints (TestClient) — override the store dependency with an isolated backend.
# --------------------------------------------------------------------------------------
@pytest.fixture()
def client(tmp_path):
    isolated = LocalStateStore(str(tmp_path))
    app.dependency_overrides[get_store] = lambda: isolated
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture()
def synthetic_module():
    registry.register(_SyntheticModule())
    try:
        yield
    finally:
        registry._modules.pop("synthetic", None)


def test_health_still_works(client: TestClient) -> None:
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_api_estate_and_workloads_round_trip(client: TestClient) -> None:
    payload = [n.model_dump(mode="json") for n in _nodes()]
    resp = client.post("/api/workloads/epic/estate", json=payload)
    assert resp.status_code == 200
    assert resp.json() == {"count": 2}

    resp = client.get("/api/workloads/epic/estate")
    assert resp.status_code == 200
    assert [n["id"] for n in resp.json()] == ["vm-odb-1", "lb-web"]

    assert client.get("/api/workloads").json() == ["epic"]


def test_api_graph_404_then_200(client: TestClient) -> None:
    assert client.get("/api/workloads/epic/graph").status_code == 404
    resp = client.post("/api/workloads/epic/graph", json=_graph().model_dump(mode="json"))
    assert resp.status_code == 200
    got = client.get("/api/workloads/epic/graph")
    assert got.status_code == 200
    assert [n["id"] for n in got.json()["nodes"]] == ["vm-odb-1", "lb-web"]


def test_api_submit_results_persists_estate_graph_findings(client: TestClient) -> None:
    result = ModuleRunResult(
        module="synthetic", ok=True, estate=_nodes(), graph=_graph(),
        findings=[_finding("q1", "quality_checks", passed=False)],
    ).model_dump(mode="json")
    resp = client.post("/api/workloads/epic/results", json=result)
    assert resp.status_code == 200
    assert resp.json()["persisted"] == {"estate": 2, "graph": 1, "findings": 1}

    assert len(client.get("/api/workloads/epic/estate").json()) == 2
    assert client.get("/api/workloads/epic/graph").status_code == 200
    assert [f["id"] for f in client.get("/api/workloads/epic/findings").json()] == ["q1"]


def test_api_malformed_combined_submit_writes_nothing(client: TestClient) -> None:
    # Valid estate, invalid graph — the whole typed payload is rejected up front, so estate must
    # NOT be written (fix 7: all-or-nothing, no partial mutation).
    bad = {
        "module": "discovery",
        "ok": True,
        "estate": [n.model_dump(mode="json") for n in _nodes()],
        "graph": {"nodes": "not-a-list"},
    }
    resp = client.post("/api/workloads/epic/results", json=bad)
    assert resp.status_code == 422
    assert client.get("/api/workloads/epic/estate").json() == []
    assert client.get("/api/workloads").json() == []


def test_api_run_module_persists_when_workload_scope(
    client: TestClient, synthetic_module
) -> None:
    resp = client.post("/api/modules/synthetic/run", json={"scope": {"workload": "epic"}})
    assert resp.status_code == 200
    body = resp.json()
    assert body["module"] == "synthetic"
    # The single-writer path actually persisted the run's outputs (fix 2).
    assert len(client.get("/api/workloads/epic/estate").json()) == 2
    assert client.get("/api/workloads/epic/graph").status_code == 200
    assert [f["id"] for f in client.get("/api/workloads/epic/findings").json()] == ["q1"]


def test_api_run_module_without_workload_does_not_persist(
    client: TestClient, synthetic_module
) -> None:
    resp = client.post("/api/modules/synthetic/run", json={"scope": {}})
    assert resp.status_code == 200
    assert client.get("/api/workloads").json() == []


def test_run_module_response_schema_is_typed(client: TestClient) -> None:
    # Fix 8: run endpoint returns a typed ModuleRunResult, not an untyped dict.
    schema = client.get("/openapi.json").json()
    ref = schema["paths"]["/api/modules/{name}/run"]["post"]["responses"]["200"][
        "content"]["application/json"]["schema"]["$ref"]
    assert ref.endswith("/ModuleRunResult")


def test_api_snapshot_and_drift(client: TestClient) -> None:
    client.post(
        "/api/workloads/epic/findings",
        json=[_finding("q1", "quality_checks", passed=False).model_dump(mode="json")],
    )
    snap = client.post("/api/workloads/epic/snapshot")
    assert snap.status_code == 200
    assert snap.json()["snapshotId"] == "snap::epic::000001"

    # q1 recovers; q2 is a new failure.
    client.post(
        "/api/workloads/epic/findings",
        json=[
            _finding("q1", "quality_checks", passed=True).model_dump(mode="json"),
            _finding("q2", "quality_checks", passed=False).model_dump(mode="json"),
        ],
    )
    drift = client.get("/api/workloads/epic/drift").json()
    assert [f["id"] for f in drift["recovered"]] == ["q1"]
    assert [f["id"] for f in drift["newFailures"]] == ["q2"]


def test_api_drift_reports_estate_node_changes(client: TestClient) -> None:
    # Snapshot with one node, then swap the estate: drift must surface the node delta (fix 6).
    client.post("/api/workloads/epic/estate", json=[_nodes()[0].model_dump(mode="json")])
    client.post("/api/workloads/epic/snapshot")
    client.post("/api/workloads/epic/estate", json=[_nodes()[1].model_dump(mode="json")])
    drift = client.get("/api/workloads/epic/drift").json()
    assert drift["addedNodes"] == ["lb-web"]
    assert drift["removedNodes"] == ["vm-odb-1"]
