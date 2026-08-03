"""Durable single-writer state + read models for the Workloads Platform.

The **API core is the SINGLE WRITER** of shared state. Capability modules receive a read-only
``ReadableState`` view via ``ModuleContext.state`` and never mutate shared state directly — they
submit their ``ModuleRunResult`` to the API, which persists it. This keeps writes serialized
through one owner and lets the compute-heavy modules scale independently.

Two backends implement the SAME ``StateStore`` Protocol:

* ``LocalStateStore`` — stdlib :mod:`sqlite3` for the small transactional store plus JSON blobs
  for snapshots. No Azure, deterministic, used in dev/CI. State dir is configurable via
  ``WORKLOADS_STATE_DIR`` (default under the OS temp dir).
* ``AzureStateStore`` — Azure Table Storage (transactional) + Blob Storage (point-in-time
  snapshots), keyless via Managed Identity. All ``azure`` SDK imports are guarded inside methods
  or :data:`typing.TYPE_CHECKING`, so importing this module never requires azure packages and all
  network stays strictly at the edge.

Select a backend with :func:`build_state_store` (env ``WORKLOADS_STATE_BACKEND=local|azure``,
default ``local``). Unknown backends fail closed.
"""
from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import tempfile
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from shared.contracts import (
    DriftReport,
    Finding,
    ModuleRunResult,
    ResourceNode,
    WorkloadGraph,
)

if TYPE_CHECKING:  # pragma: no cover - typing-only imports, never needed at runtime
    from azure.data.tables import TableClient, TableServiceClient
    from azure.storage.blob import ContainerClient

__all__ = [
    "AzureStateStore",
    "LocalStateStore",
    "ReadOnlyState",
    "ReadableState",
    "StateStore",
    "build_state_store",
    "compute_drift",
    "encode_storage_key",
    "persist_run",
]

_ENV_BACKEND = "WORKLOADS_STATE_BACKEND"
_ENV_STATE_DIR = "WORKLOADS_STATE_DIR"
_DEFAULT_DIR_NAME = "workloads-platform-state"


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def encode_storage_key(value: str) -> str:
    """Encode an arbitrary string into a storage-safe, injection-proof key.

    Azure Table ``PartitionKey``/``RowKey`` forbid ``/ \\ # ?``, control characters and more, and
    a raw value interpolated into an OData ``$filter`` is an injection vector (a workload named
    ``x' or PartitionKey ne '`` would rewrite the query). Hex-encoding the UTF-8 bytes yields a
    deterministic key drawn only from ``[0-9a-f]`` — it can contain neither a quote nor an OData
    operator, so it can never alter the filter or the partition it targets. Deterministic and
    reversible, so writes and reads round-trip to the same key.
    """
    return value.encode("utf-8").hex()


# --------------------------------------------------------------------------------------
# Protocols — the typed surface. ReadableState is what modules get; StateStore adds writes
# and is owned exclusively by the API core (single writer).
# --------------------------------------------------------------------------------------
@runtime_checkable
class ReadableState(Protocol):
    """Read-only projection of shared state handed to modules (the single-writer guarantee)."""

    def list_workloads(self) -> list[str]:
        """Return every workload known to the store (any of estate/graph/findings/snapshots)."""
        ...

    def get_estate(self, workload: str) -> list[ResourceNode]:
        """Return the latest persisted estate for ``workload`` (empty if none)."""
        ...

    def get_graph(self, workload: str) -> WorkloadGraph | None:
        """Return the latest persisted dependency graph for ``workload`` (``None`` if none)."""
        ...

    def get_findings(self, workload: str, module: str | None = None) -> list[Finding]:
        """Return current findings for ``workload``, optionally filtered to one ``module``."""
        ...

    def get_previous_findings(self, workload: str) -> list[Finding]:
        """Return the findings captured by the most recent snapshot (for #5 drift)."""
        ...

    def get_previous_node_ids(self, workload: str) -> list[str]:
        """Return the estate node ids captured by the most recent snapshot (for estate drift)."""
        ...


@runtime_checkable
class StateStore(ReadableState, Protocol):
    """Writable durable state. Only the API process constructs one (it is the single writer)."""

    def put_estate(self, workload: str, nodes: list[ResourceNode]) -> None:
        """Replace the estate for ``workload`` with ``nodes``."""
        ...

    def put_graph(self, workload: str, graph: WorkloadGraph) -> None:
        """Replace the dependency graph for ``workload``."""
        ...

    def add_findings(self, workload: str, findings: list[Finding]) -> None:
        """Upsert ``findings`` into the current set for ``workload`` (keyed by finding id)."""
        ...

    def snapshot(self, workload: str) -> str:
        """Freeze the current findings into a point-in-time snapshot; return its id."""
        ...


# --------------------------------------------------------------------------------------
# Read-only view — the object handed to modules. It captures ONLY the read callables and keeps
# no reference to the writable store, so there is no ``.put_*``/``.snapshot`` reachable from a
# module holding this view.
#
# NOTE: perfect in-process immutability is impossible in Python, and it is not the real boundary.
# In production the isolation boundary is the *process* boundary: modules deploy as their own ACA
# apps and reach state only through the API over HTTP — they never hold a store reference. This
# wrapper simply removes the in-process footgun (no `ctx.state._backend.put_estate(...)`).
# --------------------------------------------------------------------------------------
class ReadOnlyState:
    """Read-only projection over a :class:`StateStore` — the only state passed to modules.

    Captures the backend's read methods as bound callables and stores no reference to the backend
    object, so the writable store is not reachable as an attribute of this view. Exposes exactly
    the ``ReadableState`` surface and nothing else.
    """

    def __init__(self, backend: ReadableState) -> None:
        self._list_workloads = backend.list_workloads
        self._get_estate = backend.get_estate
        self._get_graph = backend.get_graph
        self._get_findings = backend.get_findings
        self._get_previous_findings = backend.get_previous_findings
        self._get_previous_node_ids = backend.get_previous_node_ids

    def list_workloads(self) -> list[str]:
        return self._list_workloads()

    def get_estate(self, workload: str) -> list[ResourceNode]:
        return self._get_estate(workload)

    def get_graph(self, workload: str) -> WorkloadGraph | None:
        return self._get_graph(workload)

    def get_findings(self, workload: str, module: str | None = None) -> list[Finding]:
        return self._get_findings(workload, module)

    def get_previous_findings(self, workload: str) -> list[Finding]:
        return self._get_previous_findings(workload)

    def get_previous_node_ids(self, workload: str) -> list[str]:
        return self._get_previous_node_ids(workload)


# --------------------------------------------------------------------------------------
# Local backend — stdlib sqlite3 + JSON. Deterministic, Azure-free, used by unit tests.
# --------------------------------------------------------------------------------------
def _default_state_dir() -> Path:
    return Path(tempfile.gettempdir()) / _DEFAULT_DIR_NAME


_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS estate ("
    " workload TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS graph ("
    " workload TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS findings ("
    " workload TEXT NOT NULL, finding_id TEXT NOT NULL, module TEXT NOT NULL,"
    " data TEXT NOT NULL, updated_at TEXT NOT NULL,"
    " PRIMARY KEY (workload, finding_id))",
    "CREATE TABLE IF NOT EXISTS snapshots ("
    " seq INTEGER PRIMARY KEY AUTOINCREMENT, workload TEXT NOT NULL,"
    " data TEXT NOT NULL, created_at TEXT NOT NULL)",
)


class LocalStateStore:
    """Local, deterministic ``StateStore`` backed by a single sqlite database + JSON payloads."""

    def __init__(self, state_dir: str | Path | None = None) -> None:
        base = Path(state_dir) if state_dir else _default_state_dir()
        base.mkdir(parents=True, exist_ok=True)
        self._db_path = base / "state.db"
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            for stmt in _SCHEMA:
                conn.execute(stmt)

    # -- reads ---------------------------------------------------------------------------
    def list_workloads(self) -> list[str]:
        query = (
            "SELECT workload FROM estate"
            " UNION SELECT workload FROM graph"
            " UNION SELECT workload FROM findings"
            " UNION SELECT workload FROM snapshots"
        )
        with self._connect() as conn:
            rows = conn.execute(query).fetchall()
        return sorted({row["workload"] for row in rows})

    def get_estate(self, workload: str) -> list[ResourceNode]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT data FROM estate WHERE workload = ?", (workload,)
            ).fetchone()
        if row is None:
            return []
        return [ResourceNode.model_validate(item) for item in json.loads(row["data"])]

    def get_graph(self, workload: str) -> WorkloadGraph | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT data FROM graph WHERE workload = ?", (workload,)
            ).fetchone()
        if row is None:
            return None
        return WorkloadGraph.model_validate_json(row["data"])

    def get_findings(self, workload: str, module: str | None = None) -> list[Finding]:
        with self._connect() as conn:
            if module is None:
                rows = conn.execute(
                    "SELECT data FROM findings WHERE workload = ?"
                    " ORDER BY module, finding_id",
                    (workload,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT data FROM findings WHERE workload = ? AND module = ?"
                    " ORDER BY finding_id",
                    (workload, module),
                ).fetchall()
        return [Finding.model_validate_json(row["data"]) for row in rows]

    def get_previous_findings(self, workload: str) -> list[Finding]:
        snap = self._latest_snapshot(workload)
        if snap is None:
            return []
        return [Finding.model_validate(item) for item in snap.get("findings", [])]

    def get_previous_node_ids(self, workload: str) -> list[str]:
        snap = self._latest_snapshot(workload)
        if snap is None:
            return []
        return [str(node_id) for node_id in snap.get("nodes", [])]

    def _latest_snapshot(self, workload: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT data FROM snapshots WHERE workload = ? ORDER BY seq DESC LIMIT 1",
                (workload,),
            ).fetchone()
        if row is None:
            return None
        payload: dict[str, Any] = json.loads(row["data"])
        return payload

    # -- writes (API core only) ----------------------------------------------------------
    def put_estate(self, workload: str, nodes: list[ResourceNode]) -> None:
        payload = json.dumps([node.model_dump(mode="json") for node in nodes])
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO estate (workload, data, updated_at) VALUES (?, ?, ?)"
                " ON CONFLICT(workload) DO UPDATE SET"
                " data = excluded.data, updated_at = excluded.updated_at",
                (workload, payload, _now_iso()),
            )

    def put_graph(self, workload: str, graph: WorkloadGraph) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO graph (workload, data, updated_at) VALUES (?, ?, ?)"
                " ON CONFLICT(workload) DO UPDATE SET"
                " data = excluded.data, updated_at = excluded.updated_at",
                (workload, graph.model_dump_json(), _now_iso()),
            )

    def add_findings(self, workload: str, findings: list[Finding]) -> None:
        now = _now_iso()
        rows = [
            (workload, finding.id, finding.module, finding.model_dump_json(), now)
            for finding in findings
        ]
        with self._connect() as conn:
            conn.executemany(
                "INSERT INTO findings (workload, finding_id, module, data, updated_at)"
                " VALUES (?, ?, ?, ?, ?)"
                " ON CONFLICT(workload, finding_id) DO UPDATE SET"
                " module = excluded.module, data = excluded.data,"
                " updated_at = excluded.updated_at",
                rows,
            )

    def snapshot(self, workload: str) -> str:
        """Freeze current findings + estate node ids into a snapshot; return its id.

        The sequence is allocated atomically by the ``AUTOINCREMENT`` primary key on a single
        ``INSERT`` — never a read-modify-write of ``MAX(seq)`` — so concurrent callers can never
        compute the same id or overwrite each other's snapshot.
        """
        findings = self.get_findings(workload)
        node_ids = [node.id for node in self.get_estate(workload)]
        payload = json.dumps(
            {
                "findings": [finding.model_dump(mode="json") for finding in findings],
                "nodes": node_ids,
            }
        )
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO snapshots (workload, data, created_at) VALUES (?, ?, ?)",
                (workload, payload, _now_iso()),
            )
            seq = int(cursor.lastrowid or 0)
        return f"snap::{workload}::{seq:06d}"


# --------------------------------------------------------------------------------------
# Azure backend — same Protocol, azure SDK imports guarded. Not exercised by unit tests, but a
# complete, typed implementation: Table Storage for the transactional store, Blob Storage for
# point-in-time snapshots, keyless via Managed Identity. Network stays at the edge (client
# construction in ``from_env``; each method does exactly one round trip family).
# --------------------------------------------------------------------------------------
_AZ_FINDINGS_TABLE = "findings"
_AZ_SNAPSHOTS_TABLE = "snapshots"
_AZ_INDEX_TABLE = "workloads"
_AZ_INDEX_PARTITION = "_index"
_BATCH_LIMIT = 100


class AzureStateStore:
    """Azure ``StateStore``: Table Storage + Blob snapshots, keyless via Managed Identity."""

    def __init__(
        self,
        *,
        table_service: TableServiceClient,
        container: ContainerClient,
    ) -> None:
        self._tables = table_service
        self._container = container

    @classmethod
    def from_env(cls) -> AzureStateStore:
        """Construct clients from env using ``DefaultAzureCredential`` (the network edge).

        Required env: ``WORKLOADS_STATE_TABLE_ENDPOINT``, ``WORKLOADS_STATE_BLOB_ENDPOINT``.
        Optional: ``WORKLOADS_STATE_CONTAINER`` (default ``state``). No secrets — identity only.

        The azure SDKs are optional (see the ``azure`` extra in ``pyproject.toml``). If they are
        not installed we fail closed with an actionable message rather than a bare ImportError.
        """
        try:
            from azure.core.exceptions import ResourceExistsError
            from azure.data.tables import TableServiceClient
            from azure.identity import DefaultAzureCredential
            from azure.storage.blob import BlobServiceClient
        except ImportError as exc:
            raise RuntimeError(
                "The 'azure' state backend needs optional dependencies that are not installed. "
                "Install them with:  pip install .[azure]"
            ) from exc

        credential = DefaultAzureCredential()
        table_endpoint = os.environ["WORKLOADS_STATE_TABLE_ENDPOINT"]
        blob_endpoint = os.environ["WORKLOADS_STATE_BLOB_ENDPOINT"]
        container_name = os.environ.get("WORKLOADS_STATE_CONTAINER", "state")

        table_service = TableServiceClient(endpoint=table_endpoint, credential=credential)
        for table in (_AZ_FINDINGS_TABLE, _AZ_SNAPSHOTS_TABLE, _AZ_INDEX_TABLE):
            table_service.create_table_if_not_exists(table)

        blob_service = BlobServiceClient(account_url=blob_endpoint, credential=credential)
        container = blob_service.get_container_client(container_name)
        with contextlib.suppress(ResourceExistsError):
            container.create_container()
        return cls(table_service=table_service, container=container)

    # -- helpers -------------------------------------------------------------------------
    def _table(self, name: str) -> TableClient:
        return self._tables.get_table_client(name)

    def _touch_workload(self, workload: str) -> None:
        # RowKey is the injection-proof encoded key; the raw name is kept as a property so
        # ``list_workloads`` can return it verbatim.
        self._table(_AZ_INDEX_TABLE).upsert_entity(
            {
                "PartitionKey": _AZ_INDEX_PARTITION,
                "RowKey": encode_storage_key(workload),
                "workload": workload,
            }
        )

    def _read_blob(self, name: str) -> str | None:
        from azure.core.exceptions import ResourceNotFoundError

        try:
            downloader = self._container.download_blob(name, encoding="utf-8")
        except ResourceNotFoundError:
            return None
        return str(downloader.readall())

    def _write_blob(self, name: str, data: str) -> None:
        self._container.upload_blob(name, data.encode("utf-8"), overwrite=True)

    # -- reads ---------------------------------------------------------------------------
    def list_workloads(self) -> list[str]:
        entities = self._table(_AZ_INDEX_TABLE).query_entities(
            "PartitionKey eq @pk", parameters={"pk": _AZ_INDEX_PARTITION}
        )
        return sorted({str(entity["workload"]) for entity in entities})

    def get_estate(self, workload: str) -> list[ResourceNode]:
        raw = self._read_blob(f"estate/{encode_storage_key(workload)}.json")
        if raw is None:
            return []
        return [ResourceNode.model_validate(item) for item in json.loads(raw)]

    def get_graph(self, workload: str) -> WorkloadGraph | None:
        raw = self._read_blob(f"graph/{encode_storage_key(workload)}.json")
        if raw is None:
            return None
        return WorkloadGraph.model_validate_json(raw)

    def get_findings(self, workload: str, module: str | None = None) -> list[Finding]:
        # Parameterized OData: untrusted values are bound, never interpolated, and the partition
        # key is the injection-proof encoded workload.
        query = "PartitionKey eq @pk"
        parameters: dict[str, object] = {"pk": encode_storage_key(workload)}
        if module is not None:
            query += " and module eq @module"
            parameters["module"] = module
        entities = self._table(_AZ_FINDINGS_TABLE).query_entities(query, parameters=parameters)
        findings = [Finding.model_validate_json(str(entity["data"])) for entity in entities]
        findings.sort(key=lambda finding: (finding.module, finding.id))
        return findings

    def get_previous_findings(self, workload: str) -> list[Finding]:
        snap = self._latest_snapshot(workload)
        if snap is None:
            return []
        return [Finding.model_validate(item) for item in snap.get("findings", [])]

    def get_previous_node_ids(self, workload: str) -> list[str]:
        snap = self._latest_snapshot(workload)
        if snap is None:
            return []
        return [str(node_id) for node_id in snap.get("nodes", [])]

    def _latest_snapshot(self, workload: str) -> dict[str, Any] | None:
        entities = list(
            self._table(_AZ_SNAPSHOTS_TABLE).query_entities(
                "PartitionKey eq @pk", parameters={"pk": encode_storage_key(workload)}
            )
        )
        if not entities:
            return None
        latest = max(entities, key=lambda entity: str(entity["RowKey"]))
        raw = self._read_blob(str(latest["blob"]))
        if raw is None:
            return None
        payload: dict[str, Any] = json.loads(raw)
        return payload

    # -- writes (API core only) ----------------------------------------------------------
    def put_estate(self, workload: str, nodes: list[ResourceNode]) -> None:
        payload = json.dumps([node.model_dump(mode="json") for node in nodes])
        self._write_blob(f"estate/{encode_storage_key(workload)}.json", payload)
        self._touch_workload(workload)

    def put_graph(self, workload: str, graph: WorkloadGraph) -> None:
        self._write_blob(f"graph/{encode_storage_key(workload)}.json", graph.model_dump_json())
        self._touch_workload(workload)

    def add_findings(self, workload: str, findings: list[Finding]) -> None:
        table = self._table(_AZ_FINDINGS_TABLE)
        partition = encode_storage_key(workload)
        entities = [
            {
                "PartitionKey": partition,
                "RowKey": encode_storage_key(finding.id),
                "module": finding.module,
                "data": finding.model_dump_json(),
            }
            for finding in findings
        ]
        for start in range(0, len(entities), _BATCH_LIMIT):
            chunk = entities[start : start + _BATCH_LIMIT]
            table.submit_transaction([("upsert", entity) for entity in chunk])
        self._touch_workload(workload)

    def snapshot(self, workload: str) -> str:
        """Freeze current findings + estate node ids into a snapshot; return its id.

        The sequence RowKey is claimed with a conditional ``create_entity`` (fails if it already
        exists); on conflict we bump the sequence and retry, so two concurrent snapshots can never
        collide or overwrite one another. The blob is written only after the RowKey is claimed.
        """
        from azure.core.exceptions import ResourceExistsError

        table = self._table(_AZ_SNAPSHOTS_TABLE)
        partition = encode_storage_key(workload)
        findings = self.get_findings(workload)
        node_ids = [node.id for node in self.get_estate(workload)]
        payload = json.dumps(
            {
                "findings": [finding.model_dump(mode="json") for finding in findings],
                "nodes": node_ids,
            }
        )
        existing = list(
            table.query_entities("PartitionKey eq @pk", parameters={"pk": partition})
        )
        seq = max((int(str(entity["RowKey"])) for entity in existing), default=0) + 1
        while True:
            snapshot_id = f"snap::{workload}::{seq:06d}"
            blob_name = f"snapshots/{partition}/{seq:06d}.json"
            try:
                table.create_entity(
                    {
                        "PartitionKey": partition,
                        "RowKey": f"{seq:06d}",
                        "snapshot_id": snapshot_id,
                        "blob": blob_name,
                        "created_at": _now_iso(),
                    }
                )
            except ResourceExistsError:
                seq += 1
                continue
            self._write_blob(blob_name, payload)
            return snapshot_id


# --------------------------------------------------------------------------------------
# Factory + drift read model.
# --------------------------------------------------------------------------------------
def build_state_store() -> StateStore:
    """Select and construct the writable ``StateStore`` from config (API core only).

    ``WORKLOADS_STATE_BACKEND`` = ``local`` (default) | ``azure``. Any other value fails closed.
    """
    backend = os.environ.get(_ENV_BACKEND, "local").strip().lower()
    if backend == "local":
        return LocalStateStore(os.environ.get(_ENV_STATE_DIR))
    if backend == "azure":
        return AzureStateStore.from_env()
    raise ValueError(f"Unknown {_ENV_BACKEND}={backend!r}; expected 'local' or 'azure'")


def persist_run(store: StateStore, workload: str, result: ModuleRunResult) -> dict[str, int]:
    """Persist a module run's outputs on the single-writer path: estate, graph, findings.

    The caller is the writer (the API core, or the CLI worker acting as a single-shot writer).
    ``result`` is an already-validated ``ModuleRunResult``, so this performs writes only — there
    is no validation here and therefore no partial-mutation-on-invalid-input hazard.
    """
    counts = {"estate": 0, "graph": 0, "findings": 0}
    if result.estate:
        store.put_estate(workload, result.estate)
        counts["estate"] = len(result.estate)
    if result.graph is not None:
        store.put_graph(workload, result.graph)
        counts["graph"] = 1
    if result.findings:
        store.add_findings(workload, result.findings)
        counts["findings"] = len(result.findings)
    return counts


def compute_drift(
    previous: list[Finding],
    current: list[Finding],
    *,
    workload: str,
    previous_nodes: Iterable[str] = (),
    current_nodes: Iterable[str] = (),
) -> DriftReport:
    """Pure drift between the previous snapshot and the current state.

    * ``newFailures`` — failing now, not failing in the previous snapshot.
    * ``recovered``   — failing in the previous snapshot, no longer failing now.
    * ``stillFailing``— failing in both.
    * ``addedNodes``/``removedNodes`` — estate node ids gained/lost since the previous snapshot.

    A finding is "failing" when ``passed is False`` (fail-closed: ``None``/unknown is not a fail).
    """
    prev_failing = {finding.id: finding for finding in previous if finding.passed is False}
    cur_failing = {finding.id: finding for finding in current if finding.passed is False}

    new_failures = [f for fid, f in cur_failing.items() if fid not in prev_failing]
    still_failing = [f for fid, f in cur_failing.items() if fid in prev_failing]
    recovered = [f for fid, f in prev_failing.items() if fid not in cur_failing]

    prev_ids = set(previous_nodes)
    cur_ids = set(current_nodes)

    return DriftReport(
        workload=workload,
        newFailures=sorted(new_failures, key=lambda f: f.id),
        recovered=sorted(recovered, key=lambda f: f.id),
        stillFailing=sorted(still_failing, key=lambda f: f.id),
        addedNodes=sorted(cur_ids - prev_ids),
        removedNodes=sorted(prev_ids - cur_ids),
    )
