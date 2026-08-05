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

from shared.audit import GENESIS_HASH, chain_event
from shared.contracts import (
    AuditEvent,
    DriftReport,
    Finding,
    ModuleRunResult,
    ResourceNode,
    WorkloadGraph,
)
from shared.provenance import enforce_finding_provenance, revalidate_finding_provenance

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

    def append_audit(self, event: AuditEvent) -> None:
        """Append one event to the tamper-evident, **append-only** audit log.

        Append-only is a hard invariant: an implementation must only ever add a new event and must
        never rewrite or delete a prior one (see issue #59). The backends enforce this at rest.
        """
        ...

    def list_audit(self, *, limit: int | None = None) -> list[AuditEvent]:
        """Return audit events in chronological (append) order; ``limit`` caps the count."""
        ...

    def audit_head(self) -> str:
        """Return the anchored chain HEAD (latest ``entryHash``), or the genesis anchor if empty.

        The HEAD is updated as part of the same append operation as the event it anchors, so a
        reader can pass it to :func:`shared.audit.verify_audit_chain` to detect a truncated tail
        (an otherwise-valid but shortened chain whose terminal hash no longer matches the HEAD).
        """
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


def _has_module_qualified_pk(findings_ddl: str) -> bool:
    """True if a ``findings`` table DDL declares the 3-column PK ``(workload, module, finding_id)``.

    Whitespace-insensitive so it matches regardless of how the DDL was formatted when created.
    """
    normalized = "".join(findings_ddl.lower().split())
    return "primarykey(workload,module,finding_id)" in normalized


_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS estate ("
    " workload TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS graph ("
    " workload TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS findings ("
    " workload TEXT NOT NULL, finding_id TEXT NOT NULL, module TEXT NOT NULL,"
    " data TEXT NOT NULL, updated_at TEXT NOT NULL,"
    " PRIMARY KEY (workload, module, finding_id))",
    "CREATE TABLE IF NOT EXISTS snapshots ("
    " seq INTEGER PRIMARY KEY AUTOINCREMENT, workload TEXT NOT NULL,"
    " data TEXT NOT NULL, created_at TEXT NOT NULL)",
    # Append-only audit trail (issue #59). ``seq`` gives a total append order; the triggers below
    # make append-only a hard, storage-enforced invariant — a prior event can never be rewritten or
    # deleted, so the log is tamper-evident even against the single writer itself.
    "CREATE TABLE IF NOT EXISTS audit ("
    " seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL,"
    " data TEXT NOT NULL, recorded_at TEXT NOT NULL)",
    "CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit"
    " BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit"
    " BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END",
    # Anchored hash-chain HEAD (issue #59, tamper-evidence). A single mutable row holding the
    # latest ``entryHash``; advanced in the SAME transaction that appends its event. It is
    # deliberately NOT append-only (it is a moving pointer, not the log) — the immutable evidence
    # is the ``audit`` rows; the HEAD lets a reader detect a truncated tail via verify_audit_chain.
    "CREATE TABLE IF NOT EXISTS audit_head ("
    " id INTEGER PRIMARY KEY CHECK (id = 0), head TEXT NOT NULL)",
)


class LocalStateStore:
    """Local, deterministic ``StateStore`` backed by a single sqlite database + JSON payloads."""

    def __init__(self, state_dir: str | Path | None = None) -> None:
        base = Path(state_dir) if state_dir else _default_state_dir()
        base.mkdir(parents=True, exist_ok=True)
        self._db_path = base / "state.db"
        self._init_schema()
        self._migrate_findings_pk()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            for stmt in _SCHEMA:
                conn.execute(stmt)

    def _migrate_findings_pk(self) -> None:
        """Upgrade a legacy ``findings`` table to the module-qualified primary key (idempotent).

        The ``findings`` primary key evolved from ``(workload, finding_id)`` to
        ``(workload, module, finding_id)`` (issue #44 R5) so two modules can emit findings that
        share a ``finding_id`` — e.g. a quality_checks rule id ``spof`` and a dependency_graph SPOF
        finding both key ``spof::<node>`` — without one silently overwriting the other. Because the
        table is created with ``CREATE TABLE IF NOT EXISTS``, a ``state.db`` written before this
        change keeps its old 2-column PK; the new ``ON CONFLICT(workload, module, finding_id)``
        upsert then has no matching constraint and raises ``OperationalError`` on the next findings
        write (and the state DB persists across runs — which is what drift detection relies on).
        This atomic migration rewrites such a legacy table into the new shape, backfilling
        ``module`` from the stored Finding JSON (``data``) when the column value is NULL. It is a
        no-op when the table is absent (a fresh DB already has the new shape from ``_SCHEMA``) or
        already has the 3-column PK, so it is safe to run on every init. Runs AFTER ``_init_schema``
        so the ``CREATE TABLE IF NOT EXISTS`` has already no-oped on a legacy DB before we fix its
        PK.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='findings'"
            ).fetchone()
            if row is None:
                return  # no findings table yet — nothing to migrate
            if _has_module_qualified_pk(str(row["sql"] or "")):
                return  # already the new 3-column PK — idempotent no-op
            columns = {str(c["name"]) for c in conn.execute("PRAGMA table_info(findings)")}
            if "data" not in columns:
                raise RuntimeError(
                    "Cannot migrate legacy 'findings' table: no 'data' column to source the "
                    "module from — refusing to drop rows (fail closed)."
                )
            has_module_col = "module" in columns
            # Fixed, fully-static SQL per branch (no interpolation) — module is backfilled from the
            # stored Finding JSON (``$.module``) when the column is missing/NULL.
            if has_module_col:
                unresolved_sql = (
                    "SELECT COUNT(*) AS n FROM findings"
                    " WHERE COALESCE(module, json_extract(data, '$.module')) IS NULL"
                )
                insert_sql = (
                    "INSERT INTO findings_new (workload, finding_id, module, data, updated_at)"
                    " SELECT workload, finding_id,"
                    " COALESCE(module, json_extract(data, '$.module')),"
                    " data, updated_at FROM findings"
                )
            else:
                unresolved_sql = (
                    "SELECT COUNT(*) AS n FROM findings"
                    " WHERE json_extract(data, '$.module') IS NULL"
                )
                insert_sql = (
                    "INSERT INTO findings_new (workload, finding_id, module, data, updated_at)"
                    " SELECT workload, finding_id, json_extract(data, '$.module'),"
                    " data, updated_at FROM findings"
                )
            unresolved = conn.execute(unresolved_sql).fetchone()
            if unresolved is not None and int(unresolved["n"]) > 0:
                raise RuntimeError(
                    f"Cannot migrate legacy 'findings' table: {int(unresolved['n'])} row(s) have "
                    "no resolvable module (NULL column and no '$.module' in data JSON) — refusing "
                    "to drop rows (fail closed)."
                )
            conn.isolation_level = None  # take manual control of the migration transaction
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    "CREATE TABLE findings_new ("
                    " workload TEXT NOT NULL, finding_id TEXT NOT NULL, module TEXT NOT NULL,"
                    " data TEXT NOT NULL, updated_at TEXT NOT NULL,"
                    " PRIMARY KEY (workload, module, finding_id))"
                )
                conn.execute(insert_sql)
                conn.execute("DROP TABLE findings")
                conn.execute("ALTER TABLE findings_new RENAME TO findings")
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise

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
        # Central provenance gate (issue #59, HIGH-1): no finding is persisted without evidence /
        # sourceReferences. This is the authoritative choke point — every write path (API /results,
        # /findings, /run commit, and any future writer) funnels through here — so a finding lacking
        # provenance fails closed BEFORE any row is written, inside the caller's transaction, so the
        # whole write rolls back and NOTHING is persisted.
        enforce_finding_provenance(findings)
        # Defense in depth (issue #83): also re-assert the pack-vs-structural provenance invariant
        # at this durable boundary, so a finding that somehow reached persistence in an invalid
        # provenance state (bypassing construction/assignment validation) is rejected fail-closed.
        revalidate_finding_provenance(findings)
        now = _now_iso()
        rows = [
            (workload, finding.id, finding.module, finding.model_dump_json(), now)
            for finding in findings
        ]
        conn.executemany(
            "INSERT INTO findings (workload, finding_id, module, data, updated_at)"
            " VALUES (?, ?, ?, ?, ?)"
            " ON CONFLICT(workload, module, finding_id) DO UPDATE SET"
            " data = excluded.data, updated_at = excluded.updated_at",
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

    # -- audit trail (append-only, hash-chained) -----------------------------------------
    def append_audit(self, event: AuditEvent) -> None:
        """Append one hash-chained audit event in a single ``BEGIN IMMEDIATE`` transaction.

        The write lock is taken up front so the read of the current HEAD, the row INSERT, and the
        HEAD advance are point-in-time atomic — a concurrent appender cannot interleave, so the
        chain stays strictly linear. The event is linked onto the current HEAD (or the genesis
        anchor for the first event) via :func:`shared.audit.chain_event`; the row INSERT is blocked
        from any later rewrite by the append-only triggers, and the mutable ``audit_head`` pointer
        is advanced to the new ``entryHash`` in the SAME transaction. If anything raises, the whole
        transaction rolls back and neither the row nor the HEAD moves.
        """
        with self._transaction(immediate=True) as conn:
            row = conn.execute("SELECT head FROM audit_head WHERE id = 0").fetchone()
            prev_hash = str(row["head"]) if row is not None else GENESIS_HASH
            chained = chain_event(event, prev_hash)
            conn.execute(
                "INSERT INTO audit (event_id, data, recorded_at) VALUES (?, ?, ?)",
                (chained.id, chained.model_dump_json(), chained.recordedAt.isoformat()),
            )
            conn.execute(
                "INSERT INTO audit_head (id, head) VALUES (0, ?)"
                " ON CONFLICT(id) DO UPDATE SET head = excluded.head",
                (chained.entryHash,),
            )

    def list_audit(self, *, limit: int | None = None) -> list[AuditEvent]:
        """Return audit events in append (``seq``) order, oldest first; ``limit`` caps the count."""
        query = "SELECT data FROM audit ORDER BY seq ASC"
        params: tuple[int, ...] = ()
        if limit is not None:
            query += " LIMIT ?"
            params = (limit,)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [AuditEvent.model_validate_json(row["data"]) for row in rows]

    def audit_head(self) -> str:
        """Return the anchored chain HEAD (latest ``entryHash``), or the genesis anchor if empty."""
        with self._connect() as conn:
            row = conn.execute("SELECT head FROM audit_head WHERE id = 0").fetchone()
        return str(row["head"]) if row is not None else GENESIS_HASH


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
_AZ_AUDIT_TABLE = "audit"
_AZ_AUDIT_PARTITION = "_audit"
# Reserved RowKey (in the audit partition) for the anchored chain HEAD entity. Sorts after the
# zero-padded numeric event RowKeys, and is skipped by ``list_audit`` so it is never mistaken for an
# event. It holds the latest ``entryHash`` (``head``) and the next chain index (``index``).
_AZ_AUDIT_HEAD_ROW = "_head"
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
        for table in (_AZ_SNAPSHOTS_TABLE, _AZ_INDEX_TABLE, _AZ_AUDIT_TABLE):
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
        """Write a blob **create-if-absent** (write-once) — never clobber an existing name.

        Every blob this store writes is addressed by a UNIQUE, version-scoped name: the commit
        components use a per-attempt ``{commit_id}=uuid4().hex`` (``_commit``) and the snapshot
        blob uses a table-claimed monotonic sequence (``snapshot``). None of these paths ever
        legitimately re-write an existing name — the mutable commit point is the *manifest table
        entity*, guarded by its own ETag, NOT a blob. So we upload with ``overwrite=False``, which
        the Azure SDK sends as a conditional ``If-None-Match: *`` create: a name collision (a
        ret/racing rewrite, or an attacker overwriting a committed artifact in place) FAILS CLOSED
        with ``ResourceExistsError`` instead of silently clobbering. This is the SDK-level
        tamper-RESISTANCE that backs the storage-layer immutability/versioning posture (issue #81)
        and the append-only hash-chain tamper-EVIDENCE (issue #59). Blob **versioning** on the
        account (see ``infra/bicep/modules/core.bicep``) additionally retains any prior bytes.
        """
        self._container.upload_blob(name, data.encode("utf-8"), overwrite=False)

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
        """Additive upsert of findings by ``(module, id)`` (new wins), preserving prior findings.

        Findings are identified by the MODULE-QUALIFIED key ``(module, finding_id)`` — a finding
        id is only unique within its emitting module (e.g. a quality_checks rule id ``spof`` mints
        the same ``spof::<node>`` id a dependency_graph SPOF finding uses). Keying by id alone would
        let one module's finding overwrite another's — e.g. an imported quality_checks PASS
        ``spof::N`` clobbering the dependency_graph SPOF FAIL and hiding a real single point of
        failure. Qualifying by ``(module, id)`` keeps cross-module same-id findings distinct;
        new-wins applies only WITHIN the same ``(module, id)``.
        """
        by_key = {(finding.module, finding.id): finding for finding in previous}
        for finding in new:
            by_key[(finding.module, finding.id)] = finding
        return list(by_key.values())

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

        # Central provenance gate (issue #59, HIGH-1): reject any un-provenanced finding BEFORE any
        # blob is written, so neither the Azure nor the local backend can ever persist a finding
        # without evidence. Raising here (before the first ``_write_blob``) leaves storage intact.
        enforce_finding_provenance(findings)
        # Defense in depth (issue #83): re-assert the pack-vs-structural provenance invariant at the
        # durable boundary too, so an invalid-provenance finding is rejected before any blob write.
        revalidate_finding_provenance(findings)
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

    # -- audit trail (append-only, hash-chained) -----------------------------------------
    def _audit_head_with_etag(self) -> tuple[dict[str, Any] | None, str | None]:
        """Read the anchored chain HEAD entity + its ETag (both ``None`` if no event yet)."""
        from azure.core.exceptions import ResourceNotFoundError

        try:
            entity = self._table(_AZ_AUDIT_TABLE).get_entity(
                _AZ_AUDIT_PARTITION, _AZ_AUDIT_HEAD_ROW
            )
        except ResourceNotFoundError:
            return None, None
        metadata = getattr(entity, "metadata", None)
        etag = metadata.get("etag") if metadata else None
        return dict(entity), etag

    def append_audit(self, event: AuditEvent) -> None:
        """Append one hash-chained audit event, advancing the anchored HEAD **atomically**.

        The event row and the chain HEAD live in the SAME partition (``_AZ_AUDIT_PARTITION``), so
        both writes are committed in a SINGLE Azure Table entity-group transaction
        (``submit_transaction``) — either both land or neither does. There is therefore **no
        window** in which the HEAD points at an event row that does not exist (no orphan), and
        **no fork**:

        1. Read the current HEAD entity (``head`` hash + next ``index``) and its ETag, or the
           genesis anchor if this is the first event.
        2. Build the chained event row (create-only) AND the HEAD row (create for the first event,
           else an ETag-conditional ``IfNotModified`` replace) and submit them as ONE transaction.
        3. If the transaction fails (a concurrent appender advanced the HEAD, so our ETag is stale,
           or the event/HEAD row already exists), retry from step 1 with the fresh HEAD — the chain
           stays strictly linear. The event row is create-only, so a prior row is never rewritten.

        Because the two writes are atomic, an event-insert failure cannot advance the HEAD, and a
        HEAD advance cannot occur without its event row — the chain can never be poisoned.
        """
        from azure.core import MatchConditions
        from azure.core.exceptions import HttpResponseError

        table = self._table(_AZ_AUDIT_TABLE)
        last_error: Exception | None = None
        for _attempt in range(_MAX_COMMIT_RETRIES):
            head_entity, etag = self._audit_head_with_etag()
            prev_hash = str(head_entity["head"]) if head_entity else GENESIS_HASH
            index = (int(head_entity["index"]) + 1) if head_entity else 1
            chained = chain_event(event, prev_hash)
            event_row = {
                "PartitionKey": _AZ_AUDIT_PARTITION,
                "RowKey": f"{index:012d}",
                "event_id": chained.id,
                "data": chained.model_dump_json(),
                "recorded_at": chained.recordedAt.isoformat(),
            }
            head_row = {
                "PartitionKey": _AZ_AUDIT_PARTITION,
                "RowKey": _AZ_AUDIT_HEAD_ROW,
                "head": chained.entryHash,
                "index": index,
            }
            head_op: tuple[str, dict[str, Any], dict[str, Any]] | tuple[str, dict[str, Any]] = (
                ("create", head_row)
                if head_entity is None
                else (
                    "update",
                    head_row,
                    {
                        "mode": "replace",
                        "etag": etag,
                        "match_condition": MatchConditions.IfNotModified,
                    },
                )
            )
            # ONE partition, ONE transaction: the immutable event row + HEAD advance land together.
            operations = [("create", event_row), head_op]
            try:
                table.submit_transaction(operations)
            except HttpResponseError as exc:  # TableTransactionError (ETag/exists) — retry cleanly
                last_error = exc
                continue
            return
        raise RuntimeError(
            f"AzureStateStore.append_audit: chain HEAD contention exceeded "
            f"{_MAX_COMMIT_RETRIES} retries"
        ) from last_error

    def list_audit(self, *, limit: int | None = None) -> list[AuditEvent]:
        """Return audit events in chain (``RowKey``) order; ``limit`` caps the count.

        The reserved HEAD entity is filtered out — it is the anchor pointer, not an event.
        """
        entities = [
            entity
            for entity in self._table(_AZ_AUDIT_TABLE).query_entities(
                "PartitionKey eq @pk", parameters={"pk": _AZ_AUDIT_PARTITION}
            )
            if str(entity["RowKey"]) != _AZ_AUDIT_HEAD_ROW
        ]
        entities.sort(key=lambda entity: str(entity["RowKey"]))
        events = [AuditEvent.model_validate_json(str(entity["data"])) for entity in entities]
        return events[:limit] if limit is not None else events

    def audit_head(self) -> str:
        """Return the anchored chain HEAD (latest ``entryHash``), or the genesis anchor if empty."""
        head_entity, _etag = self._audit_head_with_etag()
        return str(head_entity["head"]) if head_entity else GENESIS_HASH


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

    Findings are identified by the MODULE-QUALIFIED key ``(module, id)``: a finding id is only
    unique within its emitting module, so a quality_checks ``spof::N`` and a dependency_graph
    ``spof::N`` are DISTINCT findings. Keying by id alone would mis-diff them — e.g. report a
    quality_checks ``spof::N`` PASS as "recovered" against a dependency_graph ``spof::N`` FAIL,
    hiding a still-live single point of failure.
    """
    prev_failing = {
        (finding.module, finding.id): finding for finding in previous if finding.passed is False
    }
    cur_failing = {
        (finding.module, finding.id): finding for finding in current if finding.passed is False
    }

    new_failures = [f for key, f in cur_failing.items() if key not in prev_failing]
    still_failing = [f for key, f in cur_failing.items() if key in prev_failing]
    recovered = [f for key, f in prev_failing.items() if key not in cur_failing]

    prev_ids = set(previous_nodes)
    cur_ids = set(current_nodes)

    return DriftReport(
        workload=workload,
        newFailures=sorted(new_failures, key=lambda f: (f.module, f.id)),
        recovered=sorted(recovered, key=lambda f: (f.module, f.id)),
        stillFailing=sorted(still_failing, key=lambda f: (f.module, f.id)),
        addedNodes=sorted(cur_ids - prev_ids),
        removedNodes=sorted(prev_ids - cur_ids),
    )
