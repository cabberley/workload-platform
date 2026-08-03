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
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable
from uuid import uuid4

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

    def commit_run(self, workload: str, result: ModuleRunResult) -> dict[str, int]:
        """Persist a whole module run **atomically** (all-or-nothing).

        Estate and graph use ``is not None`` semantics: ``None`` leaves existing state untouched,
        an empty value CLEARS it. Findings are upserted. On any error nothing is written.
        Returns the count of items written per kind.
        """
        ...

    def snapshot(self, workload: str) -> str:
        """Freeze the current findings into a point-in-time snapshot; return its id."""
        ...


# --------------------------------------------------------------------------------------
# Read-only view — the object handed to modules.
#
# NOTE: Python has no true ``private``, so this is NOT a security sandbox and does NOT claim
# structural isolation. Determined, out-of-band access can still reach the backend via the mangled
# attribute (e.g. ``reader._StateReader__backend``) — name-mangling is obfuscation, not isolation.
# The REAL single-writer guarantee is the *process* boundary: in production modules deploy as their
# own ACA apps and reach state only through the API over HTTP — they never hold a store reference.
# The wrapper below is only an ACCIDENTAL-USE guard: it blocks the ordinary/bound-method write path
# (no ``.put_*`` on the view, and no bound read method whose ``__self__`` exposes a writer).
# --------------------------------------------------------------------------------------
class _StateReader:
    """Dedicated read-only view over a backend, exposing ONLY the read methods.

    A bound read method's ``__self__`` (this object) has no ``put_*``/``add_findings``/``snapshot``/
    ``commit_run`` to reach, so the ordinary write path is closed. This is an ACCIDENTAL-USE guard,
    not a sandbox: the backend is held under a name-mangled attribute, which merely obscures rather
    than prevents access (``self._StateReader__backend`` still resolves it). The real isolation
    boundary is the process boundary (see the module note above).
    """

    def __init__(self, backend: ReadableState) -> None:
        self.__backend = backend

    def list_workloads(self) -> list[str]:
        return self.__backend.list_workloads()

    def get_estate(self, workload: str) -> list[ResourceNode]:
        return self.__backend.get_estate(workload)

    def get_graph(self, workload: str) -> WorkloadGraph | None:
        return self.__backend.get_graph(workload)

    def get_findings(self, workload: str, module: str | None = None) -> list[Finding]:
        return self.__backend.get_findings(workload, module)

    def get_previous_findings(self, workload: str) -> list[Finding]:
        return self.__backend.get_previous_findings(workload)

    def get_previous_node_ids(self, workload: str) -> list[str]:
        return self.__backend.get_previous_node_ids(workload)


class ReadOnlyState:
    """Read-only projection handed to modules — the only state a module ever sees.

    Reads are served by a private :class:`_StateReader`; this object captures only that reader's
    bound read methods. Consequently neither ``ReadOnlyState`` nor any of its bound read methods'
    ``__self__`` exposes a write method or the writable store (accidental-use guard — the real
    boundary is the process boundary).
    """

    def __init__(self, backend: ReadableState) -> None:
        reader = _StateReader(backend)
        self._list_workloads = reader.list_workloads
        self._get_estate = reader.get_estate
        self._get_graph = reader.get_graph
        self._get_findings = reader.get_findings
        self._get_previous_findings = reader.get_previous_findings
        self._get_previous_node_ids = reader.get_previous_node_ids

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

    @contextlib.contextmanager
    def _transaction(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        """Yield a connection wrapped in a single explicit transaction (commit/rollback/close).

        ``immediate=True`` issues ``BEGIN IMMEDIATE`` so a write lock is taken up front: reads and
        the write that follow are point-in-time atomic (a concurrent writer cannot interleave).
        Any exception rolls the whole transaction back — nothing is partially written.
        """
        conn = self._connect()
        conn.isolation_level = None  # take manual control of transaction boundaries
        conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
        try:
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    # -- read helpers (operate on a caller-provided connection so they compose in a txn) -----
    @staticmethod
    def _read_estate(conn: sqlite3.Connection, workload: str) -> list[ResourceNode]:
        row = conn.execute(
            "SELECT data FROM estate WHERE workload = ?", (workload,)
        ).fetchone()
        if row is None:
            return []
        return [ResourceNode.model_validate(item) for item in json.loads(row["data"])]

    @staticmethod
    def _read_findings(
        conn: sqlite3.Connection, workload: str, module: str | None = None
    ) -> list[Finding]:
        if module is None:
            rows = conn.execute(
                "SELECT data FROM findings WHERE workload = ? ORDER BY module, finding_id",
                (workload,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT data FROM findings WHERE workload = ? AND module = ?"
                " ORDER BY finding_id",
                (workload, module),
            ).fetchall()
        return [Finding.model_validate_json(row["data"]) for row in rows]

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
            return self._read_estate(conn, workload)

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
            return self._read_findings(conn, workload, module)

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

    # -- write helpers (operate on a caller-provided connection so they compose in a txn) ----
    @staticmethod
    def _write_estate(
        conn: sqlite3.Connection, workload: str, nodes: list[ResourceNode]
    ) -> None:
        payload = json.dumps([node.model_dump(mode="json") for node in nodes])
        conn.execute(
            "INSERT INTO estate (workload, data, updated_at) VALUES (?, ?, ?)"
            " ON CONFLICT(workload) DO UPDATE SET"
            " data = excluded.data, updated_at = excluded.updated_at",
            (workload, payload, _now_iso()),
        )

    @staticmethod
    def _write_graph(
        conn: sqlite3.Connection, workload: str, graph: WorkloadGraph
    ) -> None:
        conn.execute(
            "INSERT INTO graph (workload, data, updated_at) VALUES (?, ?, ?)"
            " ON CONFLICT(workload) DO UPDATE SET"
            " data = excluded.data, updated_at = excluded.updated_at",
            (workload, graph.model_dump_json(), _now_iso()),
        )

    @staticmethod
    def _write_findings(
        conn: sqlite3.Connection, workload: str, findings: list[Finding]
    ) -> None:
        now = _now_iso()
        rows = [
            (workload, finding.id, finding.module, finding.model_dump_json(), now)
            for finding in findings
        ]
        conn.executemany(
            "INSERT INTO findings (workload, finding_id, module, data, updated_at)"
            " VALUES (?, ?, ?, ?, ?)"
            " ON CONFLICT(workload, finding_id) DO UPDATE SET"
            " module = excluded.module, data = excluded.data,"
            " updated_at = excluded.updated_at",
            rows,
        )

    # -- writes (API core only) ----------------------------------------------------------
    def put_estate(self, workload: str, nodes: list[ResourceNode]) -> None:
        with self._transaction() as conn:
            self._write_estate(conn, workload, nodes)

    def put_graph(self, workload: str, graph: WorkloadGraph) -> None:
        with self._transaction() as conn:
            self._write_graph(conn, workload, graph)

    def add_findings(self, workload: str, findings: list[Finding]) -> None:
        with self._transaction() as conn:
            self._write_findings(conn, workload, findings)

    def commit_run(self, workload: str, result: ModuleRunResult) -> dict[str, int]:
        """Persist a whole run in ONE sqlite transaction — all-or-nothing.

        Estate/graph use ``is not None`` (an explicit empty estate clears stale state); findings
        are upserted. If any write raises, the transaction rolls back and nothing is committed, so
        a valid-estate + bad-graph submit can never leave estate mutated.
        """
        counts = {"estate": 0, "graph": 0, "findings": 0}
        with self._transaction() as conn:
            if result.estate is not None:
                self._write_estate(conn, workload, result.estate)
                counts["estate"] = len(result.estate)
            if result.graph is not None:
                self._write_graph(conn, workload, result.graph)
                counts["graph"] = 1
            if result.findings:
                self._write_findings(conn, workload, result.findings)
                counts["findings"] = len(result.findings)
        return counts

    def snapshot(self, workload: str) -> str:
        """Freeze current findings + estate node ids into a point-in-time snapshot; return its id.

        The read of findings/estate AND the snapshot ``INSERT`` run inside a single
        ``BEGIN IMMEDIATE`` transaction, so a concurrent update cannot produce a mixed snapshot.
        The sequence is allocated atomically by the ``AUTOINCREMENT`` primary key on that single
        ``INSERT`` — never a read-modify-write of ``MAX(seq)`` — so concurrent callers can never
        compute the same id or overwrite each other's snapshot.
        """
        with self._transaction(immediate=True) as conn:
            findings = self._read_findings(conn, workload)
            node_ids = [node.id for node in self._read_estate(conn, workload)]
            payload = json.dumps(
                {
                    "findings": [finding.model_dump(mode="json") for finding in findings],
                    "nodes": node_ids,
                }
            )
            cursor = conn.execute(
                "INSERT INTO snapshots (workload, data, created_at) VALUES (?, ?, ?)",
                (workload, payload, _now_iso()),
            )
            seq = int(cursor.lastrowid or 0)
        return f"snap::{workload}::{seq:06d}"


# --------------------------------------------------------------------------------------
# Azure backend — same Protocol, azure SDK imports guarded (so ``import shared.state`` never needs
# azure packages). Not exercised in production by unit tests, but fully implemented, typed, and
# covered by azure-*mocked* tests. Design: a per-scope **manifest** entity in Table Storage is the
# SINGLE commit point and the SOLE read path; it points at immutable, version-scoped JSON blobs in
# Blob Storage (estate/graph/findings). Keyless via Managed Identity; network stays at the edge.
# --------------------------------------------------------------------------------------
_AZ_SNAPSHOTS_TABLE = "snapshots"
_AZ_INDEX_TABLE = "workloads"
_AZ_INDEX_PARTITION = "_index"
_MAX_COMMIT_RETRIES = 8


class AzureStateStore:
    """Azure ``StateStore``: a manifest entity points at version-scoped blobs; keyless MI.

    Every commit writes each touched component (estate/graph/findings) to a **unique**
    version-scoped blob, then flips the per-scope manifest with an **ETag-conditional** write. All
    reads resolve the current blob paths from the manifest FIRST, so a commit that fails before the
    manifest write is invisible, and concurrent commits never clobber one another's blobs (unique
    ids) — the ETag loser re-reads and retries. The manifest is the only commit point AND the only
    read path.
    """

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
        for table in (_AZ_SNAPSHOTS_TABLE, _AZ_INDEX_TABLE):
            table_service.create_table_if_not_exists(table)

        blob_service = BlobServiceClient(account_url=blob_endpoint, credential=credential)
        container = blob_service.get_container_client(container_name)
        with contextlib.suppress(ResourceExistsError):
            container.create_container()
        return cls(table_service=table_service, container=container)

    # -- helpers -------------------------------------------------------------------------
    def _table(self, name: str) -> TableClient:
        return self._tables.get_table_client(name)

    def _index_table(self) -> TableClient:
        return self._table(_AZ_INDEX_TABLE)

    def _read_blob(self, name: str) -> str | None:
        from azure.core.exceptions import ResourceNotFoundError

        try:
            downloader = self._container.download_blob(name, encoding="utf-8")
        except ResourceNotFoundError:
            return None
        return str(downloader.readall())

    def _write_blob(self, name: str, data: str) -> None:
        self._container.upload_blob(name, data.encode("utf-8"), overwrite=True)

    # -- the manifest: the single commit point AND the sole read path --------------------
    def _manifest_with_etag(self, workload: str) -> tuple[dict[str, Any] | None, str | None]:
        """Read the per-scope manifest entity and its ETag (both ``None`` if it does not exist).

        The manifest is written atomically as one entity, so its mere presence means "committed";
        the ETag lets a concurrent commit detect that it lost the race and retry.
        """
        from azure.core.exceptions import ResourceNotFoundError

        try:
            entity = self._index_table().get_entity(
                _AZ_INDEX_PARTITION, encode_storage_key(workload)
            )
        except ResourceNotFoundError:
            return None, None
        metadata = getattr(entity, "metadata", None)
        etag = metadata.get("etag") if metadata else None
        return dict(entity), etag

    def _manifest(self, workload: str) -> dict[str, Any] | None:
        manifest, _etag = self._manifest_with_etag(workload)
        return manifest

    # -- component resolution: read blobs THROUGH one manifest (never a component directly) ---
    def _estate_of(self, manifest: dict[str, Any] | None) -> list[ResourceNode]:
        if manifest is None:
            return []
        blob = str(manifest.get("estate_blob") or "")
        raw = self._read_blob(blob) if blob else None
        if raw is None:
            return []
        return [ResourceNode.model_validate(item) for item in json.loads(raw)]

    def _graph_of(self, manifest: dict[str, Any] | None) -> WorkloadGraph | None:
        if manifest is None:
            return None
        blob = str(manifest.get("graph_blob") or "")
        raw = self._read_blob(blob) if blob else None
        if raw is None:
            return None
        return WorkloadGraph.model_validate_json(raw)

    def _findings_of(
        self, manifest: dict[str, Any] | None, module: str | None = None
    ) -> list[Finding]:
        if manifest is None:
            return []
        blob = str(manifest.get("findings_blob") or "")
        raw = self._read_blob(blob) if blob else None
        if raw is None:
            return []
        findings = [Finding.model_validate(item) for item in json.loads(raw)]
        if module is not None:
            findings = [finding for finding in findings if finding.module == module]
        findings.sort(key=lambda finding: (finding.module, finding.id))
        return findings

    @staticmethod
    def _merge_findings(previous: list[Finding], new: list[Finding]) -> list[Finding]:
        """Additive upsert of findings by id (new wins), preserving prior findings."""
        by_id = {finding.id: finding for finding in previous}
        for finding in new:
            by_id[finding.id] = finding
        return list(by_id.values())

    def _commit(
        self,
        workload: str,
        *,
        estate: list[ResourceNode] | None,
        graph: WorkloadGraph | None,
        findings: list[Finding],
    ) -> dict[str, int]:
        """Atomic commit via the manifest — the SINGLE commit point.

        Each touched component is written to a **unique** version-scoped blob (so concurrent
        commits never clobber a shared name), then the per-scope manifest is flipped with an
        **ETag-conditional** write. On a precondition failure we re-read the manifest, recompute
        the next version, rewrite the version-scoped blobs, and retry (bounded). Because readers
        resolve everything through the manifest, a failure before the manifest write is invisible.
        ``estate``/``graph`` of ``None`` leave the existing pointer untouched; an empty estate list
        clears the estate; findings are merged additively onto the current committed set.
        """
        from azure.core import MatchConditions
        from azure.core.exceptions import ResourceExistsError, ResourceModifiedError

        scope = encode_storage_key(workload)
        last_error: Exception | None = None
        for _attempt in range(_MAX_COMMIT_RETRIES):
            manifest, etag = self._manifest_with_etag(workload)
            version = (int(manifest["version"]) + 1) if manifest else 1
            estate_blob = str(manifest["estate_blob"]) if manifest else ""
            graph_blob = str(manifest["graph_blob"]) if manifest else ""
            findings_blob = str(manifest["findings_blob"]) if manifest else ""
            commit_id = uuid4().hex  # unique per attempt: concurrent commits can't clobber blobs

            counts = {"estate": 0, "graph": 0, "findings": 0}
            if estate is not None:
                estate_blob = f"{scope}/estate/{commit_id}.json"
                self._write_blob(
                    estate_blob, json.dumps([node.model_dump(mode="json") for node in estate])
                )
                counts["estate"] = len(estate)
            if graph is not None:
                graph_blob = f"{scope}/graph/{commit_id}.json"
                self._write_blob(graph_blob, graph.model_dump_json())
                counts["graph"] = 1
            if findings:
                merged = self._merge_findings(self._findings_of(manifest), findings)
                findings_blob = f"{scope}/findings/{commit_id}.json"
                self._write_blob(
                    findings_blob,
                    json.dumps([finding.model_dump(mode="json") for finding in merged]),
                )
                counts["findings"] = len(findings)

            entity = {
                "PartitionKey": _AZ_INDEX_PARTITION,
                "RowKey": scope,
                "workload": workload,
                "estate_blob": estate_blob,
                "graph_blob": graph_blob,
                "findings_blob": findings_blob,
                "version": version,
                "complete": True,
                "committed_at": _now_iso(),
            }
            try:
                if manifest is None:
                    # First commit: create fails if a concurrent commit created it first.
                    self._index_table().create_entity(entity)
                else:
                    # Commit point: conditional on the ETag we read — loser retries.
                    self._index_table().update_entity(
                        entity,
                        mode="replace",
                        etag=etag,
                        match_condition=MatchConditions.IfNotModified,
                    )
                return counts
            except (ResourceExistsError, ResourceModifiedError) as exc:
                last_error = exc
                continue
        raise RuntimeError(
            "AzureStateStore.commit_run: manifest contention exceeded "
            f"{_MAX_COMMIT_RETRIES} retries"
        ) from last_error

    # -- reads (ALL resolve through the manifest) ----------------------------------------
    def list_workloads(self) -> list[str]:
        entities = self._index_table().query_entities(
            "PartitionKey eq @pk", parameters={"pk": _AZ_INDEX_PARTITION}
        )
        return sorted({str(entity["workload"]) for entity in entities})

    def get_estate(self, workload: str) -> list[ResourceNode]:
        return self._estate_of(self._manifest(workload))

    def get_graph(self, workload: str) -> WorkloadGraph | None:
        return self._graph_of(self._manifest(workload))

    def get_findings(self, workload: str, module: str | None = None) -> list[Finding]:
        return self._findings_of(self._manifest(workload), module)

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
        # Only ``complete`` snapshots are visible (a snapshot whose blob upload never finished is
        # never exposed), so readers can never observe a dangling latest-pointer.
        entities = [
            entity
            for entity in self._table(_AZ_SNAPSHOTS_TABLE).query_entities(
                "PartitionKey eq @pk", parameters={"pk": encode_storage_key(workload)}
            )
            if entity.get("complete")
        ]
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
        self._commit(workload, estate=nodes, graph=None, findings=[])

    def put_graph(self, workload: str, graph: WorkloadGraph) -> None:
        self._commit(workload, estate=None, graph=graph, findings=[])

    def add_findings(self, workload: str, findings: list[Finding]) -> None:
        self._commit(workload, estate=None, graph=None, findings=findings)

    def commit_run(self, workload: str, result: ModuleRunResult) -> dict[str, int]:
        """Persist a whole run atomically through the manifest. See :meth:`_commit`."""
        return self._commit(
            workload, estate=result.estate, graph=result.graph, findings=result.findings
        )

    def snapshot(self, workload: str) -> str:
        """Freeze ONE coherent committed version into a point-in-time snapshot; return its id.

        Estate and findings are read from a SINGLE manifest resolution (one version), so a commit
        that interleaves cannot yield a mixed snapshot. Two-phase pointer so it is exposed only
        after its blob exists AND ids stay collision-free: (1) claim the sequence RowKey with a
        conditional ``create_entity`` marked ``complete=False`` (retry with a bumped sequence on
        conflict); (2) upload the snapshot blob, THEN mark the pointer ``complete=True``. Readers
        list only ``complete`` snapshots, so a failure before the blob finishes leaves no dangling
        pointer.
        """
        from azure.core.exceptions import ResourceExistsError

        table = self._table(_AZ_SNAPSHOTS_TABLE)
        partition = encode_storage_key(workload)
        manifest = self._manifest(workload)  # resolve ONE version, then read both from it
        version = int(manifest["version"]) if manifest else 0
        node_ids = [node.id for node in self._estate_of(manifest)]
        findings = self._findings_of(manifest)
        payload = json.dumps(
            {
                "findings": [finding.model_dump(mode="json") for finding in findings],
                "nodes": node_ids,
                "version": version,
            }
        )
        existing = list(
            table.query_entities("PartitionKey eq @pk", parameters={"pk": partition})
        )
        seq = max((int(str(entity["RowKey"])) for entity in existing), default=0) + 1
        while True:
            snapshot_id = f"snap::{workload}::{seq:06d}"
            blob_name = f"snapshots/{partition}/{seq:06d}.json"
            row_key = f"{seq:06d}"
            try:
                # Phase 1 — claim the sequence (invisible: complete=False).
                table.create_entity(
                    {
                        "PartitionKey": partition,
                        "RowKey": row_key,
                        "snapshot_id": snapshot_id,
                        "blob": blob_name,
                        "version": version,
                        "complete": False,
                        "created_at": _now_iso(),
                    }
                )
            except ResourceExistsError:
                seq += 1
                continue
            # Phase 2 — upload the blob, THEN expose the snapshot by marking it complete.
            self._write_blob(blob_name, payload)
            table.update_entity(
                {"PartitionKey": partition, "RowKey": row_key, "complete": True},
                mode="merge",
            )
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
