"""Durable state (local backend) round-trips, snapshots/drift, single-writer view, and API.

All tests use the deterministic ``LocalStateStore`` in an isolated ``tmp_path`` so they are
Azure-free and hermetic. The FastAPI tests override the ``get_store`` dependency to point at the
same isolated backend. Each test below is written so it would fail without the corresponding fix.
"""
from __future__ import annotations

import importlib.util
import json
import sqlite3
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
    ImportedPack,
    ModuleKind,
    ModuleManifest,
    ModuleRunResult,
    PackType,
    ResourceNode,
    ScaleProfile,
    Severity,
    SourceReference,
    TenantModuleConfig,
    WorkloadGraph,
)
from shared.module_base import Module, ModuleContext, run_module
from shared.state import (
    AzureStateStore,
    ImportConflictError,
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
    # Every finding carries provenance (issue #59): the run-module emission guard rejects a finding
    # without ``evidence`` (fail closed), so synthetic fixtures cite a synthetic source reference.
    return Finding(
        id=fid, module=module, title=fid, passed=passed, severity=Severity.high,
        evidence=[SourceReference(kind="resource", id=f"node-{fid}")],
        packId="waf-reliability-baseline", packVersion="1.2.0",
    )


def _azure_tables_installed() -> bool:
    """True if ``azure.data.tables`` is importable.

    ``importlib.util.find_spec`` raises ``ModuleNotFoundError`` when an intermediate parent (here
    ``azure.data``) is absent, so guard it rather than letting collection fail.
    """
    try:
        return importlib.util.find_spec("azure.data.tables") is not None
    except ModuleNotFoundError:
        return False


def _azure_core_installed() -> bool:
    """True if ``azure.core`` (exceptions + ``MatchConditions``) is importable.

    The azure-mocked tests below need only ``azure.core`` (installed as a transitive dep), NOT
    ``azure.data.tables``/``azure.storage.blob`` — those SDKs are fully faked. ``AzureStateStore``
    imports ``azure.core`` lazily inside its methods, so the fakes exercise the real conditional
    write / manifest logic without any live Azure or the heavy table/blob SDKs.
    """
    try:
        return importlib.util.find_spec("azure.core") is not None
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


def test_cross_module_same_id_findings_both_persist(store: LocalStateStore) -> None:
    # R5: findings are identified by (module, finding_id). A dependency_graph SPOF FAIL and an
    # imported quality_checks rule minting the SAME id (``spof::N``) are DISTINCT rows — the
    # quality_checks PASS must NOT overwrite (hide) the dependency_graph single-point-of-failure.
    store.add_findings("epic", [_finding("spof::vm-odb-1", "dependency_graph", passed=False)])
    store.add_findings("epic", [_finding("spof::vm-odb-1", "quality_checks", passed=True)])

    all_findings = store.get_findings("epic")
    assert len(all_findings) == 2
    by_module = {f.module: f for f in all_findings}
    # The shipped dependency_graph FAIL is intact — the imported PASS did not clobber it.
    assert by_module["dependency_graph"].id == "spof::vm-odb-1"
    assert by_module["dependency_graph"].passed is False
    assert by_module["quality_checks"].passed is True
    # And a per-module read still returns only that module's row.
    dep = store.get_findings("epic", module="dependency_graph")
    assert [(f.id, f.passed) for f in dep] == [("spof::vm-odb-1", False)]


def test_same_module_same_id_still_upserts(store: LocalStateStore) -> None:
    # Within ONE (module, id) the new write still wins (unchanged last-wins semantics).
    store.add_findings("epic", [_finding("spof::n", "dependency_graph", passed=False)])
    store.add_findings("epic", [_finding("spof::n", "dependency_graph", passed=True)])
    rows = store.get_findings("epic", module="dependency_graph")
    assert [(f.id, f.passed) for f in rows] == [("spof::n", True)]


# --------------------------------------------------------------------------------------
# R6 — legacy `findings` PK migration: (workload, finding_id) → (workload, module, finding_id).
# An on-disk state.db created before the R5 change keeps the 2-column PK; without migration the new
# ON CONFLICT(workload, module, finding_id) upsert raises OperationalError. The store migrates it
# atomically at init.
# --------------------------------------------------------------------------------------
_LEGACY_TS = "2020-01-01T00:00:00Z"


def _legacy_findings_db(db_path: Path, rows: list[tuple], *, module_not_null: bool = True) -> None:
    """Create a state.db carrying the LEGACY findings schema (PK (workload, finding_id))."""
    module_decl = "module TEXT NOT NULL" if module_not_null else "module TEXT"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "CREATE TABLE findings ("
            " workload TEXT NOT NULL, finding_id TEXT NOT NULL, " + module_decl + ","
            " data TEXT NOT NULL, updated_at TEXT NOT NULL,"
            " PRIMARY KEY (workload, finding_id))"
        )
        conn.executemany(
            "INSERT INTO findings (workload, finding_id, module, data, updated_at)"
            " VALUES (?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()
    finally:
        conn.close()


def _findings_ddl(db_path: Path) -> str:
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='findings'"
        ).fetchone()
        return str(row[0]) if row else ""
    finally:
        conn.close()


def _raw_findings(db_path: Path) -> list[tuple[str, str, str]]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return [
            (str(r["workload"]), str(r["finding_id"]), str(r["module"]))
            for r in conn.execute(
                "SELECT workload, finding_id, module FROM findings ORDER BY module, finding_id"
            )
        ]
    finally:
        conn.close()


def _legacy_row(fid: str, module: str, *, passed: bool, module_col: str | None = ...) -> tuple:
    data = _finding(fid, module, passed=passed).model_dump_json()
    col = module if module_col is ... else module_col
    return ("epic", fid, col, data, _LEGACY_TS)


def test_migrates_legacy_findings_pk_and_preserves_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    _legacy_findings_db(db_path, [
        _legacy_row("spof::vm-1", "dependency_graph", passed=False),
        _legacy_row("q1", "quality_checks", passed=False),
    ])
    assert "primary key (workload, finding_id)" in _findings_ddl(db_path).lower()

    store = LocalStateStore(str(tmp_path))

    # (a) the migration ran — the table now declares the 3-column PK.
    ddl = "".join(_findings_ddl(db_path).lower().split())
    assert "primarykey(workload,module,finding_id)" in ddl

    # (b) all legacy rows survive with correct module values (checked at the column level).
    assert _raw_findings(db_path) == [
        ("epic", "spof::vm-1", "dependency_graph"),
        ("epic", "q1", "quality_checks"),
    ]
    assert {(f.id, f.module, f.passed) for f in store.get_findings("epic")} == {
        ("spof::vm-1", "dependency_graph", False),
        ("q1", "quality_checks", False),
    }

    # (c) the new PK is active: the SAME finding_id under a DIFFERENT module persists as a 2nd row.
    store.add_findings("epic", [_finding("spof::vm-1", "quality_checks", passed=True)])
    spof_rows = {
        (f.module, f.passed) for f in store.get_findings("epic") if f.id == "spof::vm-1"
    }
    assert spof_rows == {("dependency_graph", False), ("quality_checks", True)}

    # (d) re-writing the same (workload, module, finding_id) upserts last-wins (one row).
    store.add_findings("epic", [_finding("spof::vm-1", "dependency_graph", passed=True)])
    dep = store.get_findings("epic", module="dependency_graph")
    assert [(f.id, f.passed) for f in dep] == [("spof::vm-1", True)]


def test_findings_pk_migration_is_idempotent(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    _legacy_findings_db(db_path, [_legacy_row("q1", "quality_checks", passed=False)])
    LocalStateStore(str(tmp_path))  # first init migrates
    migrated_ddl = _findings_ddl(db_path)
    # Second init against the already-migrated DB is a no-op and must not raise.
    LocalStateStore(str(tmp_path))
    assert _findings_ddl(db_path) == migrated_ddl
    assert _raw_findings(db_path) == [("epic", "q1", "quality_checks")]


def test_findings_pk_migration_backfills_null_module_from_data(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    # A partial legacy shape: nullable module column, NULL for this row, but module in data JSON.
    _legacy_findings_db(
        db_path,
        [_legacy_row("spof::vm-1", "dependency_graph", passed=False, module_col=None)],
        module_not_null=False,
    )
    store = LocalStateStore(str(tmp_path))
    # The migration backfilled the module column from data JSON — the row survives, module correct.
    assert _raw_findings(db_path) == [("epic", "spof::vm-1", "dependency_graph")]
    assert [(f.id, f.module) for f in store.get_findings("epic")] == [
        ("spof::vm-1", "dependency_graph")
    ]


def test_azure_merge_findings_is_module_qualified() -> None:
    # R5: the Azure backend merges committed findings by (module, id), not id alone — so an
    # imported quality_checks PASS ``spof::N`` cannot clobber the dependency_graph SPOF FAIL. This
    # exercises the pure staticmethod directly; no azure SDK / network is required.
    previous = [_finding("spof::vm-1", "dependency_graph", passed=False)]
    new = [_finding("spof::vm-1", "quality_checks", passed=True)]
    merged = AzureStateStore._merge_findings(previous, new)
    by_module = {f.module: f for f in merged}
    assert len(merged) == 2
    assert by_module["dependency_graph"].passed is False   # shipped SPOF FAIL preserved
    assert by_module["quality_checks"].passed is True
    # New-wins still applies WITHIN the same (module, id).
    merged2 = AzureStateStore._merge_findings(
        [_finding("spof::vm-1", "dependency_graph", passed=False)],
        [_finding("spof::vm-1", "dependency_graph", passed=True)],
    )
    assert [(f.module, f.passed) for f in merged2] == [("dependency_graph", True)]


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


def test_compute_drift_cross_module_same_id_is_module_qualified() -> None:
    # R5: drift keys findings by (module, id). A dependency_graph FAIL ``spof::N`` that RECOVERS
    # (now PASS) while an imported quality_checks rule NEWLY fails with the SAME id ``spof::N`` must
    # be diffed as one recovery + one new failure — never masked as "unchanged" by id-only keying.
    previous = [_finding("spof::N", "dependency_graph", passed=False)]
    current = [
        _finding("spof::N", "dependency_graph", passed=True),    # dep_graph SPOF recovered
        _finding("spof::N", "quality_checks", passed=False),     # imported rule newly failing
    ]
    drift = compute_drift(previous, current, workload="epic")
    assert [(f.module, f.id) for f in drift.newFailures] == [("quality_checks", "spof::N")]
    assert [(f.module, f.id) for f in drift.recovered] == [("dependency_graph", "spof::N")]
    assert drift.stillFailing == []


def test_compute_drift_cross_module_pass_does_not_mask_shipped_fail() -> None:
    # A cross-module PASS with a colliding id must NOT be reported as recovering a DIFFERENT
    # module's still-live FAIL.
    previous = [_finding("spof::N", "dependency_graph", passed=False)]
    current = [
        _finding("spof::N", "dependency_graph", passed=False),   # dep_graph SPOF still failing
        _finding("spof::N", "quality_checks", passed=True),      # imported rule passes (advisory)
    ]
    drift = compute_drift(previous, current, workload="epic")
    assert drift.recovered == []
    assert [(f.module, f.id) for f in drift.stillFailing] == [("dependency_graph", "spof::N")]


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
    #
    # HONESTY (Round-3): this only guards the ORDINARY/bound-method path. Python has no true
    # ``private``: determined name-mangled access (``reader._StateReader__backend``) still reaches
    # the writable store. That is obfuscation, not isolation, so we deliberately do NOT assert such
    # access is impossible. The real single-writer guarantee is the PROCESS boundary (worker
    # computes, only the API writes); here we only assert the accidental-use guard holds.
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
    # Document (not assert-as-impossible) the known name-mangled backdoor: it exists, by design of
    # Python's attribute model; the guard's job is only to stop accidental/ordinary writes.
    reader_self = view._get_estate.__self__
    assert getattr(reader_self, "_StateReader__backend", None) is store


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


# --------------------------------------------------------------------------------------
# Round-3 Azure hardening — exercised against *faked* Table + Blob clients (no live Azure, no
# azure-data-tables / azure-storage-blob; only ``azure.core`` for the real exception types +
# ``MatchConditions`` that ``AzureStateStore`` uses). The fakes model exactly the two guarantees
# the fixes rely on: (a) ``create_entity`` fails if the row exists; (b) ``update_entity`` with an
# ``etag`` fails (ResourceModifiedError) if that etag is stale — i.e. optimistic concurrency.
# --------------------------------------------------------------------------------------
azure_only = pytest.mark.skipif(
    not _azure_core_installed(),
    reason="azure.core (exceptions + MatchConditions) is not installed",
)


class _FakeEntity(dict):
    """A dict that also carries ``.metadata['etag']`` like ``azure.data.tables.TableEntity``."""

    def __init__(self, data: dict[str, object], *, etag: str) -> None:
        super().__init__(data)
        self.metadata = {"etag": etag}


class _FakeTable:
    """In-memory stand-in for ``TableClient`` with real ETag optimistic-concurrency semantics."""

    def __init__(self) -> None:
        self.rows: dict[tuple[str, str], dict[str, object]] = {}
        self.etags: dict[tuple[str, str], str] = {}
        self._seq = 0
        self.lock = threading.Lock()

    def _new_etag(self) -> str:
        self._seq += 1
        return f"W/etag-{self._seq}"

    def get_entity(self, partition_key: str, row_key: str) -> _FakeEntity:
        from azure.core.exceptions import ResourceNotFoundError

        with self.lock:
            key = (partition_key, row_key)
            if key not in self.rows:
                raise ResourceNotFoundError(f"no entity {key}")
            return _FakeEntity(self.rows[key], etag=self.etags[key])

    def create_entity(self, entity: dict[str, object]) -> None:
        from azure.core.exceptions import ResourceExistsError

        with self.lock:
            key = (str(entity["PartitionKey"]), str(entity["RowKey"]))
            if key in self.rows:
                raise ResourceExistsError(f"entity exists {key}")
            self.rows[key] = dict(entity)
            self.etags[key] = self._new_etag()

    def update_entity(
        self,
        entity: dict[str, object],
        *,
        mode: str = "merge",
        etag: str | None = None,
        match_condition: object = None,
    ) -> None:
        from azure.core.exceptions import ResourceModifiedError, ResourceNotFoundError

        with self.lock:
            key = (str(entity["PartitionKey"]), str(entity["RowKey"]))
            if key not in self.rows:
                raise ResourceNotFoundError(f"no entity {key}")
            if etag is not None and etag != self.etags[key]:
                raise ResourceModifiedError(f"etag mismatch {key}")
            if mode == "replace":
                self.rows[key] = dict(entity)
            else:
                self.rows[key].update(dict(entity))
            self.etags[key] = self._new_etag()

    def query_entities(
        self, query: str, *, parameters: dict[str, object] | None = None
    ) -> list[dict[str, object]]:
        # The store only ever filters on ``PartitionKey eq @pk``; return matching row copies.
        pk = str((parameters or {})["pk"])
        with self.lock:
            return [dict(v) for (p, _r), v in self.rows.items() if p == pk]

    def upsert_entity(self, entity: dict[str, object], *, mode: str = "merge") -> None:
        # Create-or-replace/merge in one call (no ETag), like ``TableClient.upsert_entity``.
        with self.lock:
            key = (str(entity["PartitionKey"]), str(entity["RowKey"]))
            if key in self.rows and mode != "replace":
                self.rows[key].update(dict(entity))
            else:
                self.rows[key] = dict(entity)
            self.etags[key] = self._new_etag()

    def list_entities(self) -> list[dict[str, object]]:
        # Whole-table scan (copies), like ``TableClient.list_entities``.
        with self.lock:
            return [dict(v) for v in self.rows.values()]


class _FakeTableService:
    def __init__(self) -> None:
        self._tables: dict[str, _FakeTable] = {}

    def get_table_client(self, name: str) -> _FakeTable:
        return self._tables.setdefault(name, _FakeTable())


class _FakeDownloader:
    def __init__(self, data: bytes, encoding: str | None) -> None:
        self._data = data
        self._encoding = encoding

    def readall(self) -> str | bytes:
        return self._data.decode(self._encoding) if self._encoding else self._data


class _FakeContainer:
    def __init__(self) -> None:
        self.blobs: dict[str, bytes] = {}
        self.writes: list[tuple[str, bool]] = []
        self.lock = threading.Lock()

    def download_blob(self, name: str, *, encoding: str | None = None) -> _FakeDownloader:
        from azure.core.exceptions import ResourceNotFoundError

        with self.lock:
            if name not in self.blobs:
                raise ResourceNotFoundError(f"no blob {name}")
            return _FakeDownloader(self.blobs[name], encoding)

    def upload_blob(self, name: str, data: bytes, *, overwrite: bool = False) -> None:
        from azure.core.exceptions import ResourceExistsError

        with self.lock:
            self.writes.append((name, overwrite))
            if name in self.blobs and not overwrite:
                raise ResourceExistsError(f"blob exists {name}")
            self.blobs[name] = bytes(data)


def _azure_store() -> tuple[AzureStateStore, _FakeTableService, _FakeContainer]:
    service = _FakeTableService()
    container = _FakeContainer()
    store = AzureStateStore(table_service=service, container=container)  # type: ignore[arg-type]
    return store, service, container


def _run_result(
    *,
    estate: list[ResourceNode] | None = None,
    graph: WorkloadGraph | None = None,
    findings: list[Finding] | None = None,
) -> ModuleRunResult:
    return ModuleRunResult(
        module="synthetic", ok=True, estate=estate, graph=graph, findings=findings or [],
    )


@azure_only
def test_azure_commit_run_round_trips_through_manifest() -> None:
    store, service, _container = _azure_store()
    store.commit_run(
        "epic",
        _run_result(estate=_nodes(), graph=_graph(),
                    findings=[_finding("q1", "quality_checks", passed=False)]),
    )
    assert [n.id for n in store.get_estate("epic")] == ["vm-odb-1", "lb-web"]
    assert store.get_graph("epic") is not None
    assert [f.id for f in store.get_findings("epic")] == ["q1"]
    assert store.list_workloads() == ["epic"]
    # The manifest is the single commit point: exactly one index entity backs all four reads.
    index = service.get_table_client("workloads")
    assert len(index.rows) == 1


@azure_only
def test_azure_mid_commit_failure_is_invisible(monkeypatch: pytest.MonkeyPatch) -> None:
    # Fix 1: readers resolve through the manifest, so a commit that dies before the manifest write
    # leaves the prior committed version fully visible (no partial findings/estate leak).
    store, _service, _container = _azure_store()
    store.commit_run(
        "epic",
        _run_result(estate=_nodes(), findings=[_finding("q1", "quality_checks", passed=True)]),
    )
    good_nodes = [n.id for n in store.get_estate("epic")]
    good_findings = [f.id for f in store.get_findings("epic")]

    original = store._write_blob

    def boom(name: str, data: str) -> None:
        if "/findings/" in name:
            raise RuntimeError("blob upload failed mid-commit")
        original(name, data)

    monkeypatch.setattr(store, "_write_blob", boom)
    with pytest.raises(RuntimeError, match="mid-commit"):
        store.commit_run(
            "epic",
            _run_result(estate=[], findings=[_finding("q2", "quality_checks", passed=False)]),
        )
    # The failed commit never touched the manifest → prior version is intact.
    assert [n.id for n in store.get_estate("epic")] == good_nodes
    assert [f.id for f in store.get_findings("epic")] == good_findings


@azure_only
def test_azure_reads_ignore_blobs_not_referenced_by_manifest() -> None:
    # Fix 1: reads NEVER scan component blobs directly; a stray blob no manifest points at is
    # invisible (an attacker planting a findings blob cannot inject findings).
    store, _service, container = _azure_store()
    store.commit_run("epic", _run_result(findings=[_finding("q1", "quality_checks", passed=True)]))
    scope = encode_storage_key("epic")
    stray = json.dumps([_finding("HACK", "quality_checks", passed=False).model_dump(mode="json")])
    container.upload_blob(f"{scope}/findings/deadbeef.json", stray.encode("utf-8"), overwrite=True)
    assert [f.id for f in store.get_findings("epic")] == ["q1"]


@azure_only
def test_azure_concurrent_commits_preserve_all_findings_via_etag_retry() -> None:
    # Fix 1: concurrent commits use unique (uuid) blob names + an ETag-conditional manifest write,
    # so the loser retries and MERGES rather than clobbering — every finding survives.
    store, _service, _container = _azure_store()
    store.commit_run(
        "epic", _run_result(findings=[_finding("base", "quality_checks", passed=True)])
    )

    def add(i: int) -> None:
        store.add_findings("epic", [_finding(f"f{i}", "quality_checks", passed=False)])

    threads = [threading.Thread(target=add, args=(i,)) for i in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    ids = sorted(f.id for f in store.get_findings("epic"))
    assert ids == sorted(["base", "f0", "f1", "f2", "f3", "f4"])


@azure_only
def test_azure_snapshot_captures_one_coherent_version() -> None:
    # Fix 2: the snapshot resolves ONE manifest version and reads estate + findings from it, so a
    # later commit cannot produce a mixed snapshot.
    store, _service, _container = _azure_store()
    store.commit_run(
        "epic",
        _run_result(estate=_nodes(), findings=[_finding("q1", "quality_checks", passed=True)]),
    )
    snapshot_id = store.snapshot("epic")
    # Advance to a new version: different estate + an added finding.
    store.commit_run(
        "epic",
        _run_result(
            estate=[_nodes()[0]], findings=[_finding("q2", "quality_checks", passed=False)]
        ),
    )
    assert store.get_previous_node_ids("epic") == ["vm-odb-1", "lb-web"]
    assert [f.id for f in store.get_previous_findings("epic")] == ["q1"]
    assert snapshot_id.startswith("snap::epic::")
    # Current state reflects the newer version (estate swapped, findings merged).
    assert [n.id for n in store.get_estate("epic")] == ["vm-odb-1"]
    assert sorted(f.id for f in store.get_findings("epic")) == ["q1", "q2"]


@azure_only
def test_azure_empty_estate_clears_via_manifest() -> None:
    # Fix 2 (is-not-None semantics) carried through the manifest: an explicit empty estate clears.
    store, _service, _container = _azure_store()
    store.commit_run("epic", _run_result(estate=_nodes()))
    assert [n.id for n in store.get_estate("epic")] == ["vm-odb-1", "lb-web"]
    store.commit_run("epic", _run_result(estate=[]))
    assert store.get_estate("epic") == []


@azure_only
def test_azure_write_blob_is_create_if_absent() -> None:
    # Issue #81: blob writes are write-once (create-if-absent). The SDK-level upload must use
    # overwrite=False so an in-place clobber of a committed artifact fails closed rather than
    # silently overwriting — backing the storage-layer immutability/versioning posture.
    from azure.core.exceptions import ResourceExistsError

    store, _service, container = _azure_store()
    store._write_blob("state/x/deadbeef.json", "first")
    # Every real write went through overwrite=False (no unconditional clobber anywhere).
    assert container.writes == [("state/x/deadbeef.json", False)]
    # Re-writing the SAME name is rejected (write-once), not silently overwritten.
    with pytest.raises(ResourceExistsError):
        store._write_blob("state/x/deadbeef.json", "second")
    # The original bytes are intact — the second (clobbering) write never landed.
    assert container.blobs["state/x/deadbeef.json"] == b"first"


@azure_only
def test_azure_commit_uses_unconditional_free_write_once_blobs() -> None:
    # The commit path addresses each component blob by a UNIQUE version-scoped name, so create-if-
    # absent never collides; and the manifest UPDATE path (a Table entity, not a blob) still works
    # across repeated commits — the create-if-absent blob change is contract-safe.
    store, _service, container = _azure_store()
    store.commit_run("epic", _run_result(estate=_nodes(), findings=[
        _finding("q1", "quality_checks", passed=True),
    ]))
    # A second commit (manifest update path) succeeds and merges — no blob-name collision.
    store.commit_run("epic", _run_result(findings=[_finding("q2", "quality_checks", passed=False)]))
    assert sorted(f.id for f in store.get_findings("epic")) == ["q1", "q2"]
    # No write ever used overwrite=True: every blob upload is create-if-absent (write-once).
    assert container.writes, "expected at least one blob write"
    assert all(overwrite is False for _name, overwrite in container.writes)
    # All version-scoped names are unique (write-once guarantee, no clobber).
    names = [name for name, _overwrite in container.writes]
    assert len(names) == len(set(names))


# --------------------------------------------------------------------------------------
# Per-tenant imported packs + module config (issue #68) — Azure Table backend round-trips
# and scope isolation. ``scope`` is the tenant-namespace carrier the API threads; here we drive
# disjoint scopes directly to prove the Azure backend never crosses records between two scopes.
# --------------------------------------------------------------------------------------
_IMP_SCOPE_A = "aaaaaaaa.__imports"
_IMP_SCOPE_B = "bbbbbbbb.__imports"
_MOD_SCOPE_A = "aaaaaaaa.__modules"
_MOD_SCOPE_B = "bbbbbbbb.__modules"


def _az_imported(
    scope: str,
    pack_id: str = "epic-core",
    version: str = "1.0.0",
    digest: str = "sha256:aaa",
    pack_type: PackType = PackType.workload,
    signature: str | None = None,
    key_id: str | None = None,
) -> ImportedPack:
    return ImportedPack(
        scope=scope,
        packId=pack_id,
        version=version,
        packType=pack_type,
        digest=digest,
        signature=signature,
        keyId=key_id,
        importedBy="tester",
    )


@azure_only
def test_azure_put_and_get_imported_pack_round_trips() -> None:
    store, _service, _container = _azure_store()
    assert store.get_imported_pack(_IMP_SCOPE_A, "epic-core", "1.0.0") is None
    store.put_imported_pack(
        _az_imported(_IMP_SCOPE_A, signature="sig", key_id="test-kid", pack_type=PackType.rule)
    )
    got = store.get_imported_pack(_IMP_SCOPE_A, "epic-core", "1.0.0")
    assert got is not None
    assert got.packId == "epic-core"
    assert got.version == "1.0.0"
    assert got.packType is PackType.rule
    assert got.digest == "sha256:aaa"
    assert got.signature == "sig"
    assert got.keyId == "test-kid"


@azure_only
def test_azure_imported_pack_replaces_same_id_version() -> None:
    store, _service, _container = _azure_store()
    store.put_imported_pack(_az_imported(_IMP_SCOPE_A, digest="sha256:aaa"))
    store.put_imported_pack(_az_imported(_IMP_SCOPE_A, digest="sha256:bbb"))
    got = store.get_imported_pack(_IMP_SCOPE_A, "epic-core", "1.0.0")
    assert got is not None and got.digest == "sha256:bbb"
    assert len(store.list_imported_packs(_IMP_SCOPE_A)) == 1


@azure_only
def test_azure_imported_pack_is_scope_isolated() -> None:
    store, _service, _container = _azure_store()
    store.put_imported_pack(_az_imported(_IMP_SCOPE_A, digest="sha256:aaa"))
    assert store.get_imported_pack(_IMP_SCOPE_B, "epic-core", "1.0.0") is None
    store.put_imported_pack(_az_imported(_IMP_SCOPE_B, digest="sha256:bbb"))
    a = store.get_imported_pack(_IMP_SCOPE_A, "epic-core", "1.0.0")
    b = store.get_imported_pack(_IMP_SCOPE_B, "epic-core", "1.0.0")
    assert a is not None and a.digest == "sha256:aaa"
    assert b is not None and b.digest == "sha256:bbb"


@azure_only
def test_azure_list_imported_packs_is_scope_filtered_at_storage_layer() -> None:
    # FIX 4 (issue #68): the Azure list filters by ``PartitionKey eq`` at the backend, so a query
    # for one tenant never returns another tenant's rows even at the storage layer.
    store, _service, _container = _azure_store()
    assert store.list_imported_packs(_IMP_SCOPE_A) == []
    store.put_imported_pack(_az_imported(_IMP_SCOPE_A, pack_id="a-pack"))
    store.put_imported_pack(_az_imported(_IMP_SCOPE_B, pack_id="b-pack"))
    assert {(p.scope, p.packId) for p in store.list_imported_packs(_IMP_SCOPE_A)} == {
        (_IMP_SCOPE_A, "a-pack")
    }
    assert {(p.scope, p.packId) for p in store.list_imported_packs(_IMP_SCOPE_B)} == {
        (_IMP_SCOPE_B, "b-pack")
    }


@azure_only
def test_azure_try_record_imported_pack_atomic_immutability() -> None:
    # FIX 2 (issue #68): create_entity is the atomic guard — a same-digest re-import is idempotent
    # (returns the stored record), a different-digest re-import conflicts and preserves the first.
    store, _service, _container = _azure_store()
    first = store.try_record_imported_pack(
        _az_imported(_IMP_SCOPE_A, digest="sha256:aaa", key_id="kid-1")
    )
    same = store.try_record_imported_pack(
        _az_imported(_IMP_SCOPE_A, digest="sha256:aaa", key_id="kid-2")
    )
    assert same.keyId == first.keyId == "kid-1"
    assert len(store.list_imported_packs(_IMP_SCOPE_A)) == 1
    with pytest.raises(ImportConflictError):
        store.try_record_imported_pack(_az_imported(_IMP_SCOPE_A, digest="sha256:bbb"))
    got = store.get_imported_pack(_IMP_SCOPE_A, "epic-core", "1.0.0")
    assert got is not None and got.digest == "sha256:aaa"  # first content preserved


@azure_only
def test_azure_module_config_round_trips_and_is_scope_isolated() -> None:
    store, _service, _container = _azure_store()
    assert store.get_module_config(_MOD_SCOPE_A) is None
    store.put_module_config(TenantModuleConfig(scope=_MOD_SCOPE_A, disabled=["quality_checks"]))
    got = store.get_module_config(_MOD_SCOPE_A)
    assert got is not None and got.disabled == ["quality_checks"]
    # A different tenant scope is untouched (isolation), and replace semantics hold.
    assert store.get_module_config(_MOD_SCOPE_B) is None
    store.put_module_config(TenantModuleConfig(scope=_MOD_SCOPE_A, disabled=["drift"]))
    replaced = store.get_module_config(_MOD_SCOPE_A)
    assert replaced is not None and replaced.disabled == ["drift"]
