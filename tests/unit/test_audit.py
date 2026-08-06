"""Audit trail + provenance guard (issue #59).

Covers the append-only audit-event contract and its PII-free validators, the emitter, append-only
persistence on BOTH state backends (local + azure-mocked), emission from the wired consequential
paths (run executed, pack-verify failure), and the provenance completeness guard. All tests use
the deterministic ``LocalStateStore`` (and a faked Table client for the azure backend) so they stay
Azure-free and hermetic.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from api.app.main import _workload_token as workload_token
from api.app.main import app, get_metrics, get_store, registry
from packs_engine.engine import PacksEngine, PackVerificationError, compute_sha256
from shared.audit import (
    AUDIT_ACTION_LABEL,
    FAIL_CLOSED_ACTIONS,
    GENESIS_HASH,
    METRIC_AUDIT_EMIT_FAILURES,
    PRINCIPAL_ID_HEADER,
    SYSTEM_ACTOR,
    AuditEmitter,
    AuditPersistenceError,
    AuditSink,
    chain_event,
    compute_entry_hash,
    resolve_actor,
    verify_audit_chain,
)
from shared.contracts import (
    AuditAction,
    AuditEvent,
    AuditResult,
    DependencyEdge,
    Finding,
    ModuleKind,
    ModuleManifest,
    ModuleRunResult,
    ResourceNode,
    ScaleProfile,
    Severity,
    SourceReference,
    WorkloadGraph,
    is_audit_safe,
)
from shared.module_base import Module, ModuleContext, run_module
from shared.observability import MetricsRegistry
from shared.provenance import (
    ProvenanceError,
    enforce_finding_provenance,
    finding_has_provenance,
)
from shared.state import AzureStateStore, LocalStateStore


# --------------------------------------------------------------------------------------
# Fixtures + helpers.
# --------------------------------------------------------------------------------------
@pytest.fixture()
def store(tmp_path) -> LocalStateStore:
    return LocalStateStore(str(tmp_path))


def _event(**overrides: object) -> AuditEvent:
    base: dict[str, object] = {
        "actor": "principal-abc",
        "action": AuditAction.run_executed,
        "subject": "quality_checks",
        "result": AuditResult.success,
    }
    base.update(overrides)
    return AuditEvent(**base)  # type: ignore[arg-type]


def _finding_with_evidence(fid: str = "q1") -> Finding:
    return Finding(
        id=fid, module="quality_checks", title=fid, passed=False, severity=Severity.high,
        evidence=[SourceReference(kind="resource", id=f"node-{fid}")],
        packId="waf-reliability-baseline", packVersion="1.2.0",
    )


def _azure_core_installed() -> bool:
    try:
        return importlib.util.find_spec("azure.core") is not None
    except ModuleNotFoundError:
        return False


azure_only = pytest.mark.skipif(
    not _azure_core_installed(), reason="azure.core (exception types) is not installed"
)


# --------------------------------------------------------------------------------------
# Contract shape + PII-free validators (fail closed).
# --------------------------------------------------------------------------------------
def test_audit_event_shape_and_defaults() -> None:
    event = _event(packId="epic-rules", packVersion="1.2.0")
    assert event.actor == "principal-abc"
    assert event.action is AuditAction.run_executed
    assert event.subject == "quality_checks"
    assert event.result is AuditResult.success
    assert event.packId == "epic-rules"
    assert event.packVersion == "1.2.0"
    assert event.id  # auto-generated, non-empty
    assert event.recordedAt.tzinfo is not None  # timezone-aware UTC


def test_audit_event_is_frozen_and_forbids_extra() -> None:
    event = _event()
    with pytest.raises(ValidationError):
        event.actor = "someone-else"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        AuditEvent(actor="a", action=AuditAction.run_executed, subject="s",
                   result=AuditResult.success, bogus="x")  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "bad",
    [
        "user@contoso.com",            # email (PII)
        "Jane Doe",                    # a name (whitespace/free text)
        "log body with spaces",        # free text / log body
        "/subscriptions/abc/resourceGroups/rg/providers/x",  # resource path
        "line\nbreak",                 # control char
        "",                            # empty
        "x" * 300,                     # too long
    ],
)
def test_audit_event_rejects_pii_and_free_text(bad: str) -> None:
    # actor + subject are required id fields and must fail closed on any PII / free text.
    with pytest.raises(ValidationError):
        _event(actor=bad)
    with pytest.raises(ValidationError):
        _event(subject=bad)


def test_audit_event_rejects_pii_in_optional_pack_fields() -> None:
    with pytest.raises(ValidationError):
        _event(packId="/subscriptions/xyz/pack")
    with pytest.raises(ValidationError):
        _event(packVersion="v 1.0")  # whitespace


def test_is_audit_safe_matches_validator() -> None:
    assert is_audit_safe("principal-abc")
    assert is_audit_safe("epic-rules")
    assert not is_audit_safe("a@b.com")
    assert not is_audit_safe("has space")
    assert not is_audit_safe("/subscriptions/x")
    assert not is_audit_safe("")


def test_emitted_records_carry_no_pii_markers(store: LocalStateStore) -> None:
    # Everything that lands in the log serialises without any resource path / email marker.
    emitter = AuditEmitter(store)
    emitter.emit(actor="principal-1", action=AuditAction.pack_verify, subject="epic-rules",
                 result=AuditResult.failure, pack_id="epic-rules", pack_version="1.0.0")
    for event in store.list_audit():
        blob = event.model_dump_json().lower()
        assert "/subscriptions/" not in blob
        assert "@" not in blob


# --------------------------------------------------------------------------------------
# Emitter — persists, never raises, fails closed on invalid input.
# --------------------------------------------------------------------------------------
def test_emitter_persists_event(store: LocalStateStore) -> None:
    emitter = AuditEmitter(store)
    returned = emitter.emit(actor="p1", action=AuditAction.run_executed,
                            subject="discovery", result=AuditResult.success)
    events = store.list_audit()
    assert len(events) == 1
    assert returned is not None
    assert events[0].id == returned.id
    assert events[0].action is AuditAction.run_executed
    assert events[0].subject == "discovery"


def test_emitter_none_sink_is_noop() -> None:
    emitter = AuditEmitter(None)
    assert emitter.emit(actor="p1", action=AuditAction.run_executed,
                        subject="discovery", result=AuditResult.success) is not None


def test_emitter_best_effort_for_non_material_action_on_persistence_error() -> None:
    # A NON-material action (the pack.verify FAILURE breadcrumb) stays best-effort/fail-open: a
    # persistence error is swallowed and the event is returned, so the audited action is not broken.
    class _BoomSink:
        def append_audit(self, event: AuditEvent) -> None:
            raise RuntimeError("storage down")

    emitter = AuditEmitter(_BoomSink())
    event = emitter.emit(actor="p1", action=AuditAction.pack_verify,
                         subject="epic-rules", result=AuditResult.failure)
    assert event is not None  # returned (not raised) — best-effort allowance


@pytest.mark.parametrize("action", sorted(FAIL_CLOSED_ACTIONS, key=lambda a: a.value))
def test_emitter_fails_closed_for_material_action_on_persistence_error(
    action: AuditAction,
) -> None:
    # A security-material action (issue #99): a persistence failure PROPAGATES as
    # AuditPersistenceError so the audited mutation fails closed instead of silently succeeding.
    class _BoomSink:
        def append_audit(self, event: AuditEvent) -> None:
            raise RuntimeError("storage down")

    emitter = AuditEmitter(_BoomSink())
    with pytest.raises(AuditPersistenceError):
        emitter.emit(actor="p1", action=action, subject="discovery", result=AuditResult.success)


def test_emitter_surfaces_persistence_failure_metric() -> None:
    # Both fail-open and fail-closed failures increment the PII-free audit_emit_failures counter on
    # the injected metrics registry, so an audit-store outage is observable on /api/metrics (#99).
    class _BoomSink:
        def append_audit(self, event: AuditEvent) -> None:
            raise RuntimeError("storage down")

    reg = MetricsRegistry()
    emitter = AuditEmitter(_BoomSink(), metrics=reg)
    # Fail-open (non-material) still records the metric.
    emitter.emit(actor="p1", action=AuditAction.pack_verify,
                 subject="epic-rules", result=AuditResult.failure)
    # Fail-closed (material) records the metric before raising.
    with pytest.raises(AuditPersistenceError):
        emitter.emit(actor="p1", action=AuditAction.run_executed,
                     subject="discovery", result=AuditResult.success)
    failures = [s for s in reg.snapshot().counters if s.name == METRIC_AUDIT_EMIT_FAILURES]
    assert sum(s.value for s in failures) == 2
    labels = {v for s in failures for k, v in s.labels.items() if k == AUDIT_ACTION_LABEL}
    assert labels == {AuditAction.pack_verify.value, AuditAction.run_executed.value}


def test_emitter_fails_closed_on_pii_input(store: LocalStateStore) -> None:
    emitter = AuditEmitter(store)
    # A subject smuggling a resource path is rejected at construction → nothing is persisted.
    result = emitter.emit(actor="p1", action=AuditAction.run_executed,
                          subject="/subscriptions/x/rg", result=AuditResult.success)
    assert result is None
    assert store.list_audit() == []


def test_localstore_satisfies_audit_sink(store: LocalStateStore) -> None:
    assert isinstance(store, AuditSink)


# --------------------------------------------------------------------------------------
# resolve_actor — non-PII principal id or the system sentinel (fail safe).
# --------------------------------------------------------------------------------------
def test_resolve_actor_reads_principal_id_header() -> None:
    assert resolve_actor({PRINCIPAL_ID_HEADER: "obj-123"}) == "obj-123"


def test_resolve_actor_defaults_to_system() -> None:
    assert resolve_actor(None) == SYSTEM_ACTOR
    assert resolve_actor({}) == SYSTEM_ACTOR


def test_resolve_actor_rejects_pii_header_value() -> None:
    # A name/email in the header must never become the actor — fall back to system.
    assert resolve_actor({PRINCIPAL_ID_HEADER: "jane@contoso.com"}) == SYSTEM_ACTOR


def test_resolve_actor_prefers_validated_principal_over_header() -> None:
    # A validated oid takes precedence and the spoofable header is ignored entirely (issue #64).
    assert (
        resolve_actor({PRINCIPAL_ID_HEADER: "attacker-oid"}, principal_id="validated-oid")
        == "validated-oid"
    )


def test_resolve_actor_validated_principal_used_even_with_no_headers() -> None:
    assert resolve_actor(None, principal_id="validated-oid") == "validated-oid"


def test_resolve_actor_non_safe_validated_principal_falls_back_to_system_not_header() -> None:
    # A defensively-unsafe validated id must NOT silently fall through to the spoofable header.
    assert (
        resolve_actor({PRINCIPAL_ID_HEADER: "obj-123"}, principal_id="jane@contoso.com")
        == SYSTEM_ACTOR
    )


# --------------------------------------------------------------------------------------
# Append-only persistence — local: chronological order + storage-enforced immutability.
# --------------------------------------------------------------------------------------
def test_local_audit_appends_in_order(store: LocalStateStore) -> None:
    first = _event(subject="discovery")
    second = _event(subject="quality_checks", result=AuditResult.failure)
    store.append_audit(first)
    store.append_audit(second)
    events = store.list_audit()
    assert [e.subject for e in events] == ["discovery", "quality_checks"]
    assert store.list_audit(limit=1)[0].id == first.id


def test_local_audit_is_append_only(store: LocalStateStore, tmp_path) -> None:
    store.append_audit(_event())
    db = Path(tmp_path) / "state.db"
    conn = sqlite3.connect(db)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE audit SET data = '{}'")
            conn.commit()
        conn.rollback()
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM audit")
            conn.commit()
    finally:
        conn.close()
    # The original event survived both tamper attempts.
    assert len(store.list_audit()) == 1


# --------------------------------------------------------------------------------------
# Append-only persistence — azure backend (faked Table client), same contract.
# --------------------------------------------------------------------------------------
class _FakeEntity(dict):
    """A dict that also carries ``.metadata['etag']`` like ``azure.data.tables.TableEntity``."""

    def __init__(self, data: dict[str, object], *, etag: str) -> None:
        super().__init__(data)
        self.metadata = {"etag": etag}


class _FakeAuditTable:
    """In-memory ``TableClient`` stand-in with real ETag optimistic-concurrency semantics.

    Models the guarantees the audit store relies on: ``create`` never overwrites an existing row
    (append-only for event rows); an ETag-conditional ``update`` fails if the ETag is stale; and
    ``submit_transaction`` is an ATOMIC entity-group transaction (all preconditions checked first,
    then every op applied — or nothing, on any failure). ``fail_transactions`` forces the next
    transaction(s) to fail, to exercise the atomic event+HEAD append path.
    """

    def __init__(self) -> None:
        self.rows: dict[tuple[str, str], dict[str, object]] = {}
        self.etags: dict[tuple[str, str], str] = {}
        self._seq = 0
        self.fail_transactions = False

    def _new_etag(self) -> str:
        self._seq += 1
        return f"W/etag-{self._seq}"

    def get_entity(self, partition_key: str, row_key: str) -> _FakeEntity:
        from azure.core.exceptions import ResourceNotFoundError

        key = (partition_key, row_key)
        if key not in self.rows:
            raise ResourceNotFoundError(f"no entity {key}")
        return _FakeEntity(self.rows[key], etag=self.etags[key])

    def create_entity(self, entity: dict[str, object]) -> None:
        from azure.core.exceptions import ResourceExistsError

        key = (str(entity["PartitionKey"]), str(entity["RowKey"]))
        if key in self.rows:  # append-only: never overwrite an existing event row
            raise ResourceExistsError(f"exists {key}")
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

    def submit_transaction(self, operations: list) -> None:
        """Atomic entity-group transaction over ONE partition (all-or-nothing)."""
        from azure.core.exceptions import (
            HttpResponseError,
            ResourceExistsError,
            ResourceModifiedError,
        )

        if self.fail_transactions:  # simulate a failing event+HEAD append
            raise HttpResponseError(message="injected transaction failure")
        partitions = {str(op[1]["PartitionKey"]) for op in operations}
        assert len(partitions) == 1, "entity-group transaction must be single-partition"
        # Phase 1 — validate ALL preconditions before applying ANY op (atomicity).
        for op in operations:
            action, entity = op[0], op[1]
            opts = op[2] if len(op) > 2 else {}
            key = (str(entity["PartitionKey"]), str(entity["RowKey"]))
            if action == "create" and key in self.rows:
                raise ResourceExistsError(f"exists {key}")
            if action == "update":
                etag = opts.get("etag")
                if etag is not None and key in self.etags and etag != self.etags[key]:
                    raise ResourceModifiedError(f"etag mismatch {key}")
        # Phase 2 — apply every op.
        for op in operations:
            action, entity = op[0], op[1]
            opts = op[2] if len(op) > 2 else {}
            key = (str(entity["PartitionKey"]), str(entity["RowKey"]))
            if action == "update" and opts.get("mode") != "replace" and key in self.rows:
                self.rows[key].update(dict(entity))
            else:
                self.rows[key] = dict(entity)
            self.etags[key] = self._new_etag()

    def query_entities(
        self, query: str, *, parameters: dict[str, object] | None = None
    ) -> list[dict[str, object]]:
        pk = str((parameters or {})["pk"])
        return [dict(v) for (p, _r), v in self.rows.items() if p == pk]


class _FakeAuditService:
    def __init__(self) -> None:
        self._tables: dict[str, _FakeAuditTable] = {}

    def get_table_client(self, name: str) -> _FakeAuditTable:
        return self._tables.setdefault(name, _FakeAuditTable())


def _azure_store() -> AzureStateStore:
    return AzureStateStore(
        table_service=_FakeAuditService(),  # type: ignore[arg-type]
        container=object(),  # type: ignore[arg-type]  # audit paths never touch the blob container
    )


@azure_only
def test_azure_audit_appends_in_order_and_hash_chains() -> None:
    store = _azure_store()
    first = _event(subject="discovery")
    second = _event(subject="quality_checks", result=AuditResult.failure)
    store.append_audit(first)
    store.append_audit(second)
    events = store.list_audit()
    assert [e.subject for e in events] == ["discovery", "quality_checks"]
    # Every persisted record is hash-chained and the anchored HEAD tracks the tail.
    assert events[0].prevHash == GENESIS_HASH
    assert events[1].prevHash == events[0].entryHash
    assert verify_audit_chain(events, head=store.audit_head()) is None


@azure_only
def test_azure_audit_head_entity_is_hidden_from_list() -> None:
    store = _azure_store()
    store.append_audit(_event(subject="discovery"))
    events = store.list_audit()
    # The reserved HEAD anchor entity must never surface as an audit event.
    assert len(events) == 1
    assert store.audit_head() == events[0].entryHash


@azure_only
def test_azure_append_is_atomic_head_not_advanced_on_failure() -> None:
    # HIGH-1: event row + HEAD advance are ONE entity-group transaction. If the append fails, the
    # HEAD must NOT move and no orphan/partial row may appear — the chain stays consistent.
    store = _azure_store()
    store.append_audit(_event(subject="one"))
    head_before = store.audit_head()
    table = store._table("audit")
    table.fail_transactions = True  # simulate the event insert (and thus the whole txn) failing
    with pytest.raises(RuntimeError):
        store.append_audit(_event(subject="two"))
    table.fail_transactions = False
    assert store.audit_head() == head_before  # HEAD did NOT advance (no poisoned chain)
    events = store.list_audit()
    assert [e.subject for e in events] == ["one"]  # no orphan row landed
    assert verify_audit_chain(events, head=store.audit_head()) is None
    # And the log is still usable — a subsequent append chains cleanly onto the unchanged HEAD.
    store.append_audit(_event(subject="three"))
    events = store.list_audit()
    assert [e.subject for e in events] == ["one", "three"]
    assert verify_audit_chain(events, head=store.audit_head()) is None


@azure_only
def test_azure_store_satisfies_audit_sink() -> None:
    assert isinstance(_azure_store(), AuditSink)


# --------------------------------------------------------------------------------------
# Provenance completeness guard (issue #59).
# --------------------------------------------------------------------------------------
def test_finding_has_provenance() -> None:
    assert finding_has_provenance(_finding_with_evidence())
    # #83-valid (pack-derived) yet evidence-empty: exercises the orthogonal #59 evidence guard.
    naked = Finding(id="x", module="quality_checks", title="x", passed=False,
                    packId="waf-reliability-baseline", packVersion="1.2.0")
    assert not finding_has_provenance(naked)


def test_enforce_provenance_raises_on_missing_evidence() -> None:
    # #83-valid (pack-derived) yet evidence-empty: exercises the orthogonal #59 evidence guard.
    naked = Finding(id="x", module="quality_checks", title="x", passed=False,
                    packId="waf-reliability-baseline", packVersion="1.2.0")
    with pytest.raises(ProvenanceError):
        enforce_finding_provenance([naked])
    # A finding WITH evidence passes cleanly.
    enforce_finding_provenance([_finding_with_evidence()])


class _EvidencelessModule(Module):
    """A misbehaving module that emits a finding with no provenance."""

    def __init__(self, *, evidence: bool) -> None:
        self._evidence = evidence

    @property
    def manifest(self) -> ModuleManifest:
        return ModuleManifest(name="quality_checks", displayName="QC", kind=ModuleKind.job,
                              scaleProfile=ScaleProfile(kind=ModuleKind.job))

    def run(self, ctx: ModuleContext, *, scope: dict[str, str] | None = None) -> ModuleRunResult:
        finding = _finding_with_evidence() if self._evidence else Finding(
            id="x", module="quality_checks", title="x", passed=False,
            packId="waf-reliability-baseline", packVersion="1.2.0")
        return ModuleRunResult(module="quality_checks", ok=True, findings=[finding])


def test_run_module_fails_closed_without_provenance() -> None:
    with pytest.raises(ProvenanceError):
        run_module(_EvidencelessModule(evidence=False), scope={})


def test_run_module_allows_provenanced_findings() -> None:
    result = run_module(_EvidencelessModule(evidence=True), scope={})
    assert len(result.findings) == 1


# --------------------------------------------------------------------------------------
# Pack-verify emission — a fail-closed rejection is audited; a clean load is not.
# --------------------------------------------------------------------------------------
def _write_pack(path: Path, *, signature: str) -> None:
    body = {"x": 1}
    body_bytes = json.dumps(body, sort_keys=True).encode()
    manifest = {
        "id": "epic-rules", "type": "rule", "name": "Epic rules", "version": "1.0.0",
        "sha256": compute_sha256(body_bytes), "signature": signature,
    }
    path.write_text(json.dumps({"manifest": manifest, "body": body}), encoding="utf-8")


def test_engine_audits_pack_verify_failure(tmp_path) -> None:
    content = Path(tmp_path) / "content"
    content.mkdir()
    _write_pack(content / "rule.json", signature="deadbeef")  # wrong HMAC → fail closed
    store = LocalStateStore(str(Path(tmp_path) / "state"))
    engine = PacksEngine(content, signing_secret=b"secret", audit_emitter=AuditEmitter(store))

    with pytest.raises(PackVerificationError):
        engine.load_all(verify_sig=True)

    events = store.list_audit()
    assert len(events) == 1
    assert events[0].action is AuditAction.pack_verify
    assert events[0].result is AuditResult.failure
    assert events[0].subject == "epic-rules"
    assert events[0].packVersion == "1.0.0"


def _write_pack_with_identity(
    path: Path, *, pack_id: str, version: str, signature: str = "deadbeef"
) -> None:
    body = {"x": 1}
    body_bytes = json.dumps(body, sort_keys=True).encode()
    manifest = {
        "id": pack_id, "type": "rule", "name": "Malicious", "version": version,
        "sha256": compute_sha256(body_bytes), "signature": signature,
    }
    path.write_text(json.dumps({"manifest": manifest, "body": body}), encoding="utf-8")


def test_engine_audits_pack_verify_failure_with_unsafe_identity(tmp_path) -> None:
    # R4 LOW-2: a malicious pack whose id/version are NOT audit-safe must still be REJECTED *and*
    # audited — the failure event must use an opaque, audit-safe identifier so it is never dropped,
    # and must never leak the raw unsafe value.
    content = Path(tmp_path) / "content"
    content.mkdir()
    unsafe_id = "attacker@evil.com"                       # email (PII) → not audit-safe
    unsafe_version = "/subscriptions/1111-2222/v1"        # resource path → not audit-safe
    _write_pack_with_identity(content / "rule.json", pack_id=unsafe_id, version=unsafe_version)
    store = LocalStateStore(str(Path(tmp_path) / "state"))
    engine = PacksEngine(content, signing_secret=b"secret", audit_emitter=AuditEmitter(store))

    with pytest.raises(PackVerificationError):
        engine.load_all(verify_sig=True)  # still fails closed (verification behavior unchanged)

    events = store.list_audit()
    assert len(events) == 1  # the rejection is AUDITED, not silently dropped
    ev = events[0]
    assert ev.action is AuditAction.pack_verify
    assert ev.result is AuditResult.failure
    # Identifiers are the opaque sha256 digest of the raw unsafe values — deterministic, audit-safe.
    assert ev.packId == hashlib.sha256(unsafe_id.encode("utf-8")).hexdigest()
    assert ev.packVersion == hashlib.sha256(unsafe_version.encode("utf-8")).hexdigest()
    assert ev.subject == ev.packId
    assert is_audit_safe(ev.packId)
    assert is_audit_safe(ev.packVersion)
    assert is_audit_safe(ev.subject)
    # The raw unsafe values never appear anywhere in the serialized event (no leak).
    blob = ev.model_dump_json().lower()
    assert "attacker" not in blob
    assert "@" not in blob
    assert "/subscriptions/" not in blob


def test_engine_hashes_pack_id_with_format_control(tmp_path) -> None:
    # R5 LOW: a Cf format char (U+202E RLO) survives NFKC, so a packId/packVersion carrying it is
    # NOT audit-safe and must be sha256-hashed by _audit_safe_identifier — never stored verbatim.
    content = Path(tmp_path) / "content"
    content.mkdir()
    unsafe_id = "epic\u202erules"          # RIGHT-TO-LEFT OVERRIDE embedded in the id
    unsafe_version = "1.0\u200b0"           # ZERO WIDTH SPACE embedded in the version
    _write_pack_with_identity(content / "rule.json", pack_id=unsafe_id, version=unsafe_version)
    store = LocalStateStore(str(Path(tmp_path) / "state"))
    engine = PacksEngine(content, signing_secret=b"secret", audit_emitter=AuditEmitter(store))

    with pytest.raises(PackVerificationError):
        engine.load_all(verify_sig=True)  # still fails closed

    events = store.list_audit()
    assert len(events) == 1  # the rejection is AUDITED, not dropped
    ev = events[0]
    assert ev.packId == hashlib.sha256(unsafe_id.encode("utf-8")).hexdigest()
    assert ev.packVersion == hashlib.sha256(unsafe_version.encode("utf-8")).hexdigest()
    assert ev.subject == ev.packId
    # The raw Cf-bearing values are never persisted verbatim.
    blob = ev.model_dump_json()
    assert "\u202e" not in blob
    assert "\u200b" not in blob


# ``chr(0xD800)`` builds the lone surrogate at RUNTIME on purpose: embedding it as a source string
# literal would put a lone surrogate into this module's code constants, which cannot be marshalled
# to a ``.pyc`` (``UnicodeEncodeError`` at import). Building it via ``chr`` keeps the source pure.
def _expected_surrogate_digest(surrogate: str) -> str:
    # Mirror ``_audit_safe_identifier``'s TOTAL, INJECTIVE encoding (surrogatepass) so a lone
    # surrogate is hashed deterministically instead of raising ``UnicodeEncodeError`` on strict
    # UTF-8 encode — and without colliding with its literal escape text (see the injective test).
    return hashlib.sha256(surrogate.encode("utf-8", errors="surrogatepass")).hexdigest()


def test_engine_audits_pack_verify_failure_with_lone_surrogate_id(tmp_path) -> None:
    # R6 LOW: a lone surrogate in the packId (parsed from real JSON) is not audit-safe (Cs → C*),
    # so it falls to the sha256 branch of _audit_safe_identifier. That branch must use a TOTAL
    # encoding so it NEVER raises UnicodeEncodeError — otherwise the required pack.verify failure
    # audit would be suppressed AND the expected PackVerificationError masked.
    surrogate = chr(0xD800)  # lone high surrogate, un-encodable by strict UTF-8
    content = Path(tmp_path) / "content"
    content.mkdir()
    _write_pack_with_identity(content / "rule.json", pack_id=surrogate, version="1.0.0")
    # Prove the fixture went through REAL JSON parsing and yields a lone surrogate back.
    parsed = json.loads((content / "rule.json").read_text(encoding="utf-8"))
    assert parsed["manifest"]["id"] == surrogate
    store = LocalStateStore(str(Path(tmp_path) / "state"))
    engine = PacksEngine(content, signing_secret=b"secret", audit_emitter=AuditEmitter(store))

    with pytest.raises(PackVerificationError):  # NOT UnicodeEncodeError
        engine.load_all(verify_sig=True)

    events = store.list_audit()
    assert len(events) == 1  # the rejection is AUDITED, not dropped/crashed
    ev = events[0]
    assert ev.action is AuditAction.pack_verify
    assert ev.result is AuditResult.failure
    assert ev.packId == _expected_surrogate_digest(surrogate)  # stable 64-char sha256 digest
    assert len(ev.packId) == 64
    assert ev.subject == ev.packId
    assert is_audit_safe(ev.packId)
    # The raw surrogate never appears in the serialized event (no leak / no crash on serialize).
    assert surrogate not in ev.model_dump_json()


def test_engine_audits_pack_verify_failure_with_lone_surrogate_version(tmp_path) -> None:
    # R6 LOW: same guarantee when the lone surrogate is in the packVersion field.
    surrogate = chr(0xDC00)  # lone low surrogate
    content = Path(tmp_path) / "content"
    content.mkdir()
    _write_pack_with_identity(content / "rule.json", pack_id="epic-rules", version=surrogate)
    parsed = json.loads((content / "rule.json").read_text(encoding="utf-8"))
    assert parsed["manifest"]["version"] == surrogate
    store = LocalStateStore(str(Path(tmp_path) / "state"))
    engine = PacksEngine(content, signing_secret=b"secret", audit_emitter=AuditEmitter(store))

    with pytest.raises(PackVerificationError):  # NOT UnicodeEncodeError
        engine.load_all(verify_sig=True)

    events = store.list_audit()
    assert len(events) == 1
    ev = events[0]
    assert ev.packVersion == _expected_surrogate_digest(surrogate)
    assert len(ev.packVersion) == 64
    assert ev.packId == "epic-rules"  # the safe field is still stored verbatim
    assert is_audit_safe(ev.packVersion)
    assert surrogate not in ev.model_dump_json()


def test_audit_safe_identifier_lone_surrogate_is_deterministic() -> None:
    # R6 LOW: hashing the same lone-surrogate value twice yields the same digest (no crash).
    from packs_engine.engine import _audit_safe_identifier

    surrogate = chr(0xD800)
    first = _audit_safe_identifier(surrogate)
    second = _audit_safe_identifier(surrogate)
    assert first == second == _expected_surrogate_digest(surrogate)
    assert len(first) == 64 and first.isascii()


def test_engine_verify_rejects_lone_surrogate_sha256_without_crash(tmp_path) -> None:
    # R6 sweep: a lone surrogate in the manifest sha256/signature fields would make
    # hmac.compare_digest raise TypeError, masking the error type AND evading the failure audit.
    # The .isascii() guard in verify() converts it to a fail-closed PackVerificationError that IS
    # audited. (A non-ASCII digest can never equal a real ASCII hex/base64 value, so no pack's
    # pass/fail verdict changes.)
    surrogate = chr(0xD800)
    content = Path(tmp_path) / "content"
    content.mkdir()
    body = {"x": 1}
    manifest = {
        "id": "epic-rules", "type": "rule", "name": "Malicious", "version": "1.0.0",
        "sha256": surrogate, "signature": "deadbeef",
    }
    (content / "rule.json").write_text(
        json.dumps({"manifest": manifest, "body": body}), encoding="utf-8"
    )
    store = LocalStateStore(str(Path(tmp_path) / "state"))
    engine = PacksEngine(content, signing_secret=b"secret", audit_emitter=AuditEmitter(store))

    with pytest.raises(PackVerificationError):  # NOT TypeError
        engine.load_all(verify_sig=True)

    events = store.list_audit()
    assert len(events) == 1  # rejection audited, not dropped
    assert events[0].action is AuditAction.pack_verify
    assert events[0].result is AuditResult.failure
    assert surrogate not in events[0].model_dump_json()


def test_audit_safe_identifier_encoding_is_injective() -> None:
    # R7 LOW-2: the digest input must be INJECTIVE so distinct unsafe identifiers never collide to
    # one audit id. The OLD ``backslashreplace`` mapped a lone surrogate and its literal escape text
    # to IDENTICAL bytes; ``surrogatepass`` keeps them distinct.
    from packs_engine.engine import _audit_safe_identifier

    surrogate = chr(0xD800)      # lone surrogate (unsafe → hashed)
    literal_text = "\\ud800"      # the ASCII text backslash-u-d-8-0-0

    # The bug: under backslashreplace the two encode to the SAME bytes (would collide when hashed).
    assert surrogate.encode("utf-8", errors="backslashreplace") == literal_text.encode(
        "utf-8", errors="backslashreplace"
    )
    # The fix: surrogatepass encodes them to DIFFERENT bytes, so their digests differ.
    id_surrogate = _audit_safe_identifier(surrogate)
    digest_literal = hashlib.sha256(
        literal_text.encode("utf-8", errors="surrogatepass")
    ).hexdigest()
    assert id_surrogate == hashlib.sha256(
        surrogate.encode("utf-8", errors="surrogatepass")
    ).hexdigest()
    assert id_surrogate != digest_literal          # no collision between the two encodings
    assert len(id_surrogate) == 64 and id_surrogate.isascii()


def test_engine_audits_pack_verify_failure_with_yaml_native_body(tmp_path) -> None:
    # R7 LOW-1: a YAML-authored pack whose body is a YAML-native ``!!set`` (a Python ``set``) is not
    # JSON-serializable. Serializing it in the AUDITED verify path raised ``TypeError`` BEFORE any
    # audit was written — masking the rejection and emitting ZERO pack.verify events. The guard
    # converts it to a fail-closed ``PackVerificationError`` that IS audited exactly once.
    content = Path(tmp_path) / "content"
    content.mkdir()
    yaml_text = (
        "manifest:\n"
        "  id: epic-rules\n"
        "  type: rule\n"
        "  name: Malicious\n"
        "  version: 1.0.0\n"
        f"  sha256: \"{'0' * 64}\"\n"
        "  signature: deadbeef\n"
        "body: !!set\n"
        "  ? a\n"
        "  ? b\n"
    )
    (content / "rule.yaml").write_text(yaml_text, encoding="utf-8")
    store = LocalStateStore(str(Path(tmp_path) / "state"))
    engine = PacksEngine(content, signing_secret=b"secret", audit_emitter=AuditEmitter(store))

    with pytest.raises(PackVerificationError):  # NOT TypeError
        engine.load_all(verify_sig=True)

    events = store.list_audit()
    assert len(events) == 1  # the non-serializable body is rejected AND audited, not crashed
    ev = events[0]
    assert ev.action is AuditAction.pack_verify
    assert ev.result is AuditResult.failure
    assert ev.packId == "epic-rules"  # safe id → verbatim, stable audit-safe identifier
    assert is_audit_safe(ev.subject)


def test_engine_does_not_audit_successful_verify(tmp_path) -> None:
    content = Path(tmp_path) / "content"
    content.mkdir()
    store = LocalStateStore(str(Path(tmp_path) / "state"))
    engine = PacksEngine(content, audit_emitter=AuditEmitter(store))
    engine.load_all(verify_sig=False)  # no verification performed → no audit noise
    assert store.list_audit() == []


# --------------------------------------------------------------------------------------
# API integration — run.executed is audited (success + failure) into the single-writer store.
# --------------------------------------------------------------------------------------
class _OkModule(Module):
    @property
    def manifest(self) -> ModuleManifest:
        return ModuleManifest(name="audit_ok", displayName="ok", kind=ModuleKind.job,
                              scaleProfile=ScaleProfile(kind=ModuleKind.job))

    def run(self, ctx: ModuleContext, *, scope: dict[str, str] | None = None) -> ModuleRunResult:
        return ModuleRunResult(module="audit_ok", ok=True)


class _FailModule(Module):
    @property
    def manifest(self) -> ModuleManifest:
        return ModuleManifest(name="audit_fail", displayName="fail", kind=ModuleKind.job,
                              scaleProfile=ScaleProfile(kind=ModuleKind.job))

    def run(self, ctx: ModuleContext, *, scope: dict[str, str] | None = None) -> ModuleRunResult:
        return ModuleRunResult(module="audit_fail", ok=False)


@pytest.fixture()
def audit_client(tmp_path):
    isolated = LocalStateStore(str(tmp_path))
    app.dependency_overrides[get_store] = lambda: isolated
    for module in (_OkModule(), _FailModule()):
        registry.register(module)
    with TestClient(app) as client:
        yield client, isolated
    app.dependency_overrides.clear()
    registry._modules.pop("audit_ok", None)
    registry._modules.pop("audit_fail", None)


def test_run_endpoint_audits_success_with_actor(audit_client) -> None:
    client, store = audit_client
    resp = client.post("/api/modules/audit_ok/run", json={"scope": {}},
                       headers={PRINCIPAL_ID_HEADER: "obj-42"})
    assert resp.status_code == 200
    events = [e for e in store.list_audit() if e.action is AuditAction.run_executed]
    assert len(events) == 1
    assert events[0].subject == "audit_ok"
    assert events[0].result is AuditResult.success
    assert events[0].actor == "obj-42"


def test_run_endpoint_audits_failure(audit_client) -> None:
    client, store = audit_client
    client.post("/api/modules/audit_fail/run", json={"scope": {}})
    events = [e for e in store.list_audit() if e.action is AuditAction.run_executed]
    assert len(events) == 1
    assert events[0].subject == "audit_fail"
    assert events[0].result is AuditResult.failure
    assert events[0].actor == SYSTEM_ACTOR  # no principal header → system


def test_results_endpoint_audits_run(audit_client) -> None:
    client, store = audit_client
    result = ModuleRunResult(module="discovery", ok=True)
    resp = client.post("/api/workloads/epic/results", json=result.model_dump(mode="json"))
    assert resp.status_code == 200
    events = [e for e in store.list_audit() if e.action is AuditAction.run_executed]
    assert len(events) == 1
    assert events[0].subject == "discovery"
    assert events[0].result is AuditResult.success


# --------------------------------------------------------------------------------------
# HIGH-2 — AuditEvent.id is PII-validated like every other string field (fail closed).
# --------------------------------------------------------------------------------------
def test_audit_event_default_id_is_audit_safe() -> None:
    # The default-generated id (uuid4 hex) is always a bounded, PII-free identifier.
    for _ in range(20):
        assert is_audit_safe(_event().id)


@pytest.mark.parametrize(
    "bad_id",
    [
        "alice@example.com",                                   # email (PII)
        "/subscriptions/1234abcd/resourceGroups/rg",           # resource path
        "/SUBSCRIPTIONS/ABCD",                                 # case-variant resource path
        "line\nbreak",                                         # control char
        "tab\tchar",                                           # control char
        "has space",                                           # whitespace / free text
        "",                                                    # empty
        "x" * 300,                                             # oversized (> 256)
    ],
)
def test_audit_event_id_rejects_pii_control_and_oversized(bad_id: str) -> None:
    # A caller-supplied id can no longer smuggle PII / control / oversized values — reject at
    # construction, exactly like actor/subject/packId/packVersion.
    with pytest.raises(ValidationError):
        _event(id=bad_id)


def test_every_audit_event_string_field_is_pii_validated() -> None:
    # id, actor, subject, packId, packVersion — a resource id / email is un-constructable in ANY.
    resource = "/subscriptions/abc/resourceGroups/rg"
    with pytest.raises(ValidationError):
        _event(id=resource)
    with pytest.raises(ValidationError):
        _event(actor=resource)
    with pytest.raises(ValidationError):
        _event(subject=resource)
    with pytest.raises(ValidationError):
        _event(packId=resource)
    with pytest.raises(ValidationError):
        _event(packVersion="user@contoso.com")


# --------------------------------------------------------------------------------------
# MED-3 — tamper-evident hash chaining + verify_audit_chain (pure, deterministic).
# --------------------------------------------------------------------------------------
def test_chain_hashing_is_deterministic() -> None:
    event = _event()
    assert compute_entry_hash(event, GENESIS_HASH) == compute_entry_hash(event, GENESIS_HASH)
    # The hash covers the logical event only — setting prevHash/entryHash doesn't change it.
    chained = chain_event(event, GENESIS_HASH)
    assert compute_entry_hash(chained, GENESIS_HASH) == chained.entryHash


def test_local_chain_verifies_and_anchors_head(store: LocalStateStore) -> None:
    for subject in ("discovery", "quality_checks", "aiops"):
        store.append_audit(_event(subject=subject))
    events = store.list_audit()
    assert events[0].prevHash == GENESIS_HASH
    assert events[1].prevHash == events[0].entryHash
    assert events[2].prevHash == events[1].entryHash
    assert store.audit_head() == events[-1].entryHash
    assert verify_audit_chain(events, head=store.audit_head()) is None


def test_verify_detects_tampered_field(store: LocalStateStore) -> None:
    for subject in ("discovery", "quality_checks", "aiops"):
        store.append_audit(_event(subject=subject))
    events = store.list_audit()
    # Edit a stored field but keep its (now stale) entryHash → recompute mismatches at that index.
    tampered = list(events)
    tampered[1] = events[1].model_copy(update={"subject": "tampered"})
    assert verify_audit_chain(tampered, head=store.audit_head()) == 1


def test_verify_detects_reordering(store: LocalStateStore) -> None:
    for subject in ("discovery", "quality_checks", "aiops"):
        store.append_audit(_event(subject=subject))
    events = store.list_audit()
    reordered = [events[0], events[2], events[1]]
    assert verify_audit_chain(reordered, head=store.audit_head()) == 1


def test_verify_detects_truncated_tail(store: LocalStateStore) -> None:
    for subject in ("discovery", "quality_checks", "aiops"):
        store.append_audit(_event(subject=subject))
    events = store.list_audit()
    head = store.audit_head()
    truncated = events[:-1]
    # The anchored HEAD makes a dropped tail detectable even though the shorter chain is internally
    # consistent (without the anchor, truncation would be invisible).
    assert verify_audit_chain(truncated, head=head) == len(truncated)
    assert verify_audit_chain(truncated) is None


# --------------------------------------------------------------------------------------
# HIGH-1 — central provenance gate: no un-provenanced finding persists on EITHER backend.
# --------------------------------------------------------------------------------------
def _naked_finding(fid: str = "np1") -> Finding:
    # #83-valid (pack-derived) yet evidence-empty: exercises the orthogonal #59 evidence guard.
    return Finding(id=fid, module="quality_checks", title=fid, passed=False,
                   packId="waf-reliability-baseline", packVersion="1.2.0")


def test_local_add_findings_rejects_missing_provenance(store: LocalStateStore) -> None:
    with pytest.raises(ProvenanceError):
        store.add_findings("epic", [_naked_finding()])
    assert store.get_findings("epic") == []  # nothing persisted (fail closed)


def test_local_commit_run_rejects_missing_provenance(store: LocalStateStore) -> None:
    result = ModuleRunResult(module="quality_checks", ok=True, findings=[_naked_finding()])
    with pytest.raises(ProvenanceError):
        store.commit_run("epic", result)
    assert store.get_findings("epic") == []


@azure_only
def test_azure_commit_rejects_missing_provenance_before_any_write() -> None:
    # The gate fires at the top of the manifest commit, BEFORE any blob/table write, so the azure
    # backend can never persist a finding without evidence either (container never touched).
    store = _azure_store()
    with pytest.raises(ProvenanceError):
        store.add_findings("epic", [_naked_finding()])
    with pytest.raises(ProvenanceError):
        store.commit_run(
            "epic", ModuleRunResult(module="quality_checks", ok=True, findings=[_naked_finding()])
        )


def test_results_endpoint_rejects_missing_provenance(audit_client) -> None:
    client, store = audit_client
    result = ModuleRunResult(module="discovery", ok=True, findings=[_naked_finding()])
    resp = client.post("/api/workloads/epic/results", json=result.model_dump(mode="json"))
    assert resp.status_code == 422
    assert store.get_findings("epic") == []  # nothing written
    assert store.list_audit() == []  # neither run.executed nor finding.emitted recorded


def test_findings_endpoint_rejects_missing_provenance(audit_client) -> None:
    client, store = audit_client
    resp = client.post(
        "/api/workloads/epic/findings",
        json=[_naked_finding().model_dump(mode="json")],
    )
    assert resp.status_code == 422
    assert store.get_findings("epic") == []
    assert store.list_audit() == []


# --------------------------------------------------------------------------------------
# MED-4 — finding.emitted recorded (PII-free subject) after a successful findings persist.
# --------------------------------------------------------------------------------------
def _finding_json() -> dict[str, object]:
    return _finding_with_evidence().model_dump(mode="json")


def test_results_endpoint_emits_finding_emitted(audit_client) -> None:
    client, store = audit_client
    result = ModuleRunResult(
        module="discovery", ok=True, findings=[_finding_with_evidence("f1")]
    )
    resp = client.post("/api/workloads/epic/results", json=result.model_dump(mode="json"))
    assert resp.status_code == 200
    emitted = [e for e in store.list_audit() if e.action is AuditAction.finding_emitted]
    assert len(emitted) == 1
    assert emitted[0].result is AuditResult.success
    assert emitted[0].subject == "epic#count=1"  # PII-free: workload id + count only
    blob = emitted[0].model_dump_json().lower()
    assert "/subscriptions/" not in blob and "@" not in blob


def test_findings_endpoint_emits_finding_emitted(audit_client) -> None:
    client, store = audit_client
    resp = client.post(
        "/api/workloads/epic/findings",
        json=[_finding_json(), _finding_with_evidence("f2").model_dump(mode="json")],
    )
    assert resp.status_code == 200
    emitted = [e for e in store.list_audit() if e.action is AuditAction.finding_emitted]
    assert len(emitted) == 1
    assert emitted[0].result is AuditResult.success
    assert emitted[0].subject == "epic#count=2"
    # The finding.emitted event is hash-chained into the append-only trail like every other event.
    assert verify_audit_chain(store.list_audit(), head=store.audit_head()) is None


# --------------------------------------------------------------------------------------
# MED-2 — an un-auditable (PII/oversized/control) workload id is rejected fail-closed BEFORE any
# findings write, on all three finding-emitting paths, so we never persist findings we can't audit.
# --------------------------------------------------------------------------------------
def test_run_endpoint_rejects_unsafe_workload(audit_client) -> None:
    client, store = audit_client
    resp = client.post(
        "/api/modules/audit_ok/run",
        json={"scope": {"workload": "user@example.com"}},
    )
    assert resp.status_code == 422
    assert store.get_findings("user@example.com") == []  # nothing persisted
    # No finding.emitted for an un-auditable workload (the run itself is still audited as failure).
    assert [e for e in store.list_audit() if e.action is AuditAction.finding_emitted] == []


def test_results_endpoint_rejects_unsafe_workload(audit_client) -> None:
    client, store = audit_client
    result = ModuleRunResult(module="discovery", ok=True, findings=[_finding_with_evidence("f1")])
    resp = client.post(
        "/api/workloads/user@example.com/results", json=result.model_dump(mode="json")
    )
    assert resp.status_code == 422
    assert store.get_findings("user@example.com") == []  # nothing written
    assert store.list_audit() == []  # neither run.executed nor finding.emitted recorded


def test_findings_endpoint_rejects_unsafe_workload(audit_client) -> None:
    client, store = audit_client
    resp = client.post(
        "/api/workloads/user@example.com/findings",
        json=[_finding_with_evidence("f1").model_dump(mode="json")],
    )
    assert resp.status_code == 422
    assert store.get_findings("user@example.com") == []
    assert store.list_audit() == []


def test_findings_endpoint_accepts_safe_workload_and_emits(audit_client) -> None:
    # A normal (audit-safe) workload id still persists and emits finding.emitted (regression guard).
    client, store = audit_client
    resp = client.post(
        "/api/workloads/epic-prod/findings",
        json=[_finding_with_evidence("f1").model_dump(mode="json")],
    )
    assert resp.status_code == 200
    emitted = [e for e in store.list_audit() if e.action is AuditAction.finding_emitted]
    assert len(emitted) == 1
    assert emitted[0].subject == "epic-prod#count=1"


# --------------------------------------------------------------------------------------
# LOW-3 — is_audit_safe rejects the full Cc control range (C0, DEL 0x7F, C1 0x80-0x9F).
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize("ctrl", ["\x00", "\x1f", "\x7f", "\x80", "\x81", "\x85", "\x9f"])
def test_is_audit_safe_rejects_all_control_chars(ctrl: str) -> None:
    assert not is_audit_safe(f"principal{ctrl}abc")


@pytest.mark.parametrize("ctrl", ["\x7f", "\x85", "\x81"])
def test_audit_event_rejects_control_chars_in_every_field(ctrl: str) -> None:
    # DEL / C1 controls must be un-constructable in id, actor, subject, packId AND packVersion.
    payload = f"principal{ctrl}abc"
    with pytest.raises(ValidationError):
        _event(id=payload)
    with pytest.raises(ValidationError):
        _event(actor=payload)
    with pytest.raises(ValidationError):
        _event(subject=payload)
    with pytest.raises(ValidationError):
        _event(packId=payload)
    with pytest.raises(ValidationError):
        _event(packVersion=payload)


# --------------------------------------------------------------------------------------
# R5 LOW — is_audit_safe rejects the WHOLE Unicode "Other" (C*) group, incl. format chars (Cf)
# that survive NFKC (RLO/ZWSP/LRM/RLM/BOM), while legitimate non-ASCII letters still pass.
# --------------------------------------------------------------------------------------
_FORMAT_CONTROLS = ["\u202e", "\u200b", "\u200e", "\u200f", "\ufeff"]  # RLO, ZWSP, LRM, RLM, BOM


@pytest.mark.parametrize("fmt", _FORMAT_CONTROLS)
def test_is_audit_safe_rejects_unicode_format_controls(fmt: str) -> None:
    assert not is_audit_safe(f"principal{fmt}abc")


@pytest.mark.parametrize("fmt", _FORMAT_CONTROLS)
def test_audit_event_rejects_format_controls_in_every_field(fmt: str) -> None:
    # Cf format chars must be un-constructable in id, actor, subject, packId AND packVersion.
    payload = f"principal{fmt}abc"
    with pytest.raises(ValidationError):
        _event(id=payload)
    with pytest.raises(ValidationError):
        _event(actor=payload)
    with pytest.raises(ValidationError):
        _event(subject=payload)
    with pytest.raises(ValidationError):
        _event(packId=payload)
    with pytest.raises(ValidationError):
        _event(packVersion=payload)


@pytest.mark.parametrize("legit", ["café", "naïve", "Zürich", "Ångström"])
def test_is_audit_safe_accepts_legitimate_non_ascii_letters(legit: str) -> None:
    # Regression: accented letters are category Ll/Lu (not C*) and must NOT be over-rejected.
    assert is_audit_safe(legit)
    event = _event(actor=legit, subject=legit)
    assert event.actor == legit
    assert event.subject == legit


# --------------------------------------------------------------------------------------
# R3 HIGH-1 — a present-but-empty/unknown SourceReference does NOT satisfy provenance.
# --------------------------------------------------------------------------------------
def _finding_with_ref(kind: str, ref_id: str, fid: str = "e1") -> Finding:
    return Finding(
        id=fid, module="quality_checks", title=fid, passed=False,
        evidence=[SourceReference(kind=kind, id=ref_id)],
        packId="waf-reliability-baseline", packVersion="1.2.0",
    )


@pytest.mark.parametrize(
    ("kind", "ref_id"),
    [
        ("", ""),            # wholly empty reference
        ("", "node-1"),      # blank kind
        ("resource", ""),    # blank id
        ("resource", "   "), # whitespace-only id
        ("bogus", "node-1"), # unsupported kind
    ],
)
def test_finding_has_provenance_rejects_empty_or_unknown_reference(kind: str, ref_id: str) -> None:
    assert finding_has_provenance(_finding_with_ref(kind, ref_id)) is False
    with pytest.raises(ProvenanceError):
        enforce_finding_provenance([_finding_with_ref(kind, ref_id)])


def test_finding_has_provenance_accepts_every_supported_kind() -> None:
    for kind in ("resource", "metric", "log", "pack", "connector"):
        assert finding_has_provenance(_finding_with_ref(kind, "real-id")) is True


def test_local_rejects_empty_reference_on_both_write_paths(store: LocalStateStore) -> None:
    with pytest.raises(ProvenanceError):
        store.add_findings("epic", [_finding_with_ref("", "node-1")])
    assert store.get_findings("epic") == []
    with pytest.raises(ProvenanceError):
        store.commit_run(
            "epic",
            ModuleRunResult(
                module="quality_checks", ok=True, findings=[_finding_with_ref("resource", "")]
            ),
        )
    assert store.get_findings("epic") == []


@azure_only
def test_azure_rejects_empty_reference_before_any_write() -> None:
    store = _azure_store()
    with pytest.raises(ProvenanceError):
        store.add_findings("epic", [_finding_with_ref("", "node-1")])
    with pytest.raises(ProvenanceError):
        store.commit_run(
            "epic",
            ModuleRunResult(
                module="quality_checks", ok=True, findings=[_finding_with_ref("resource", "")]
            ),
        )


def test_results_endpoint_rejects_empty_reference(audit_client) -> None:
    client, store = audit_client
    result = ModuleRunResult(
        module="discovery", ok=True, findings=[_finding_with_ref("", "node-1")]
    )
    resp = client.post("/api/workloads/epic/results", json=result.model_dump(mode="json"))
    assert resp.status_code == 422
    assert store.get_findings("epic") == []
    assert store.list_audit() == []


def test_findings_endpoint_rejects_empty_reference(audit_client) -> None:
    client, store = audit_client
    resp = client.post(
        "/api/workloads/epic/findings",
        json=[_finding_with_ref("resource", "").model_dump(mode="json")],
    )
    assert resp.status_code == 422
    assert store.get_findings("epic") == []
    assert store.list_audit() == []


def test_findings_endpoint_accepts_valid_reference(audit_client) -> None:
    client, store = audit_client
    resp = client.post(
        "/api/workloads/epic/findings",
        json=[_finding_with_ref("resource", "node-1").model_dump(mode="json")],
    )
    assert resp.status_code == 200
    assert len(store.get_findings("epic")) == 1


# --------------------------------------------------------------------------------------
# R3 HIGH-2 — Unicode compatibility forms are NFKC-normalized before the PII checks, and the
# normalized (canonical) value is what gets persisted.
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "disguised",
    [
        "alice\uff20example.com",                    # fullwidth '＠' → '@' after NFKC (an email)
        "\uff0fsubscriptions\uff0f0000-1111",        # fullwidth '／' → '/subscriptions/' path
    ],
)
def test_is_audit_safe_rejects_unicode_compatibility_forms(disguised: str) -> None:
    assert is_audit_safe(disguised) is False


@pytest.mark.parametrize(
    "disguised",
    ["alice\uff20example.com", "\uff0fsubscriptions\uff0f0000-1111"],
)
def test_audit_event_rejects_compatibility_forms_in_every_field(disguised: str) -> None:
    with pytest.raises(ValidationError):
        _event(id=disguised)
    with pytest.raises(ValidationError):
        _event(actor=disguised)
    with pytest.raises(ValidationError):
        _event(subject=disguised)
    with pytest.raises(ValidationError):
        _event(packId=disguised)
    with pytest.raises(ValidationError):
        _event(packVersion=disguised)


def test_normal_value_round_trips_unchanged() -> None:
    event = _event(actor="principal-abc", subject="quality_checks")
    assert event.actor == "principal-abc"  # already-canonical ASCII is untouched
    assert event.subject == "quality_checks"


def test_audit_event_persists_nfkc_canonical_value() -> None:
    # A benign compatibility form (fullwidth digits) canonicalizes to ASCII and is what persists,
    # so a later read can never observe an un-normalized variant of the field.
    event = _event(actor="node-\uff11\uff12\uff13")  # 'node-１２３' → 'node-123'
    assert event.actor == "node-123"


# --------------------------------------------------------------------------------------
# R3 MED-3 — a workload id that is individually <=256 but whose derived finding.emitted subject
# ('<workload>#count=N') exceeds 256 is rejected fail-closed on all three paths (nothing persists).
# --------------------------------------------------------------------------------------
def _oversized_derived_workload() -> str:
    # 250 chars: audit-safe on its own (<=256), but '<workload>#count=N' (>=258) blows the limit.
    return "w" * 250


def test_run_endpoint_rejects_oversized_derived_subject(audit_client) -> None:
    client, store = audit_client
    workload = _oversized_derived_workload()
    assert is_audit_safe(workload)  # the raw id alone would pass — only the derived subject fails
    resp = client.post("/api/modules/audit_ok/run", json={"scope": {"workload": workload}})
    assert resp.status_code == 422
    assert store.get_findings(workload) == []
    assert [e for e in store.list_audit() if e.action is AuditAction.finding_emitted] == []


def test_results_endpoint_rejects_oversized_derived_subject(audit_client) -> None:
    client, store = audit_client
    workload = _oversized_derived_workload()
    result = ModuleRunResult(module="discovery", ok=True, findings=[_finding_with_evidence("f1")])
    resp = client.post(f"/api/workloads/{workload}/results", json=result.model_dump(mode="json"))
    assert resp.status_code == 422
    assert store.get_findings(workload) == []
    assert store.list_audit() == []


def test_findings_endpoint_rejects_oversized_derived_subject(audit_client) -> None:
    client, store = audit_client
    workload = _oversized_derived_workload()
    resp = client.post(
        f"/api/workloads/{workload}/findings",
        json=[_finding_with_evidence("f1").model_dump(mode="json")],
    )
    assert resp.status_code == 422
    assert store.get_findings(workload) == []
    assert store.list_audit() == []


# --------------------------------------------------------------------------------------
# R4 MEDIUM-1 — the derived run.executed subject is validated BEFORE any state write, so a
# non-audit-safe module id can never commit state whose run.executed audit event is then dropped.
# --------------------------------------------------------------------------------------
class _UnsafeNameModule(Module):
    """A module whose registered name is NOT audit-safe — models an attacker-controlled subject."""

    @property
    def manifest(self) -> ModuleManifest:
        return ModuleManifest(name="bad@evil.com", displayName="bad", kind=ModuleKind.job,
                              scaleProfile=ScaleProfile(kind=ModuleKind.job))

    def run(self, ctx: ModuleContext, *, scope: dict[str, str] | None = None) -> ModuleRunResult:
        return ModuleRunResult(module="bad@evil.com", ok=True)


def test_run_endpoint_rejects_unsafe_module_subject(audit_client) -> None:
    client, store = audit_client
    registry.register(_UnsafeNameModule())
    try:
        resp = client.post(
            "/api/modules/bad@evil.com/run", json={"scope": {"workload": "epic"}}
        )
    finally:
        registry._modules.pop("bad@evil.com", None)
    assert resp.status_code == 422
    assert store.get_findings("epic") == []          # nothing committed
    assert store.list_audit() == []                  # no run.executed emitted (validated pre-write)


def test_results_endpoint_rejects_unsafe_module_subject(audit_client) -> None:
    client, store = audit_client
    # The /results path commits state; a non-audit-safe result.module must be rejected BEFORE the
    # commit so state is never persisted with its run.executed event dropped.
    result = ModuleRunResult(module="attacker@example.com", ok=True)
    resp = client.post("/api/workloads/epic/results", json=result.model_dump(mode="json"))
    assert resp.status_code == 422
    assert store.get_findings("epic") == []
    assert store.list_audit() == []  # nothing committed, no run.executed emitted


def test_results_endpoint_rejects_oversized_module_subject(audit_client) -> None:
    client, store = audit_client
    result = ModuleRunResult(module="m" * 300, ok=True)  # >256 → derived subject not audit-safe
    resp = client.post("/api/workloads/epic/results", json=result.model_dump(mode="json"))
    assert resp.status_code == 422
    assert store.get_findings("epic") == []
    assert store.list_audit() == []


def test_results_endpoint_normal_module_still_emits_run_executed(audit_client) -> None:
    # Regression: an audit-safe module id still commits and emits run.executed (no false rejection).
    client, store = audit_client
    result = ModuleRunResult(module="discovery", ok=True)
    resp = client.post("/api/workloads/epic/results", json=result.model_dump(mode="json"))
    assert resp.status_code == 200
    executed = [e for e in store.list_audit() if e.action is AuditAction.run_executed]
    assert len(executed) == 1
    assert executed[0].subject == "discovery"
    assert executed[0].result is AuditResult.success


# --------------------------------------------------------------------------------------
# #99 Part 1 — the state-mutating estate/graph/snapshot endpoints now emit a PII-free audit event
# with a bounded, DERIVED subject built from the OPAQUE workload token (never the raw workload name
# — PII-free by construction) plus a count / intent marker (never estate content).
# --------------------------------------------------------------------------------------
def _resource_nodes() -> list[ResourceNode]:
    return [
        ResourceNode(id="n1", name="web", type="Microsoft.Web/sites"),
        ResourceNode(id="n2", name="db", type="Microsoft.Sql/servers"),
    ]


def _workload_graph() -> WorkloadGraph:
    return WorkloadGraph(nodes=_resource_nodes(), edges=[DependencyEdge(source="n1", target="n2")])


def test_estate_endpoint_emits_audit(audit_client) -> None:
    client, store = audit_client
    payload = [n.model_dump(mode="json") for n in _resource_nodes()]
    resp = client.post(
        "/api/workloads/epic/estate", json=payload, headers={PRINCIPAL_ID_HEADER: "obj-7"}
    )
    assert resp.status_code == 200
    expected = f"{workload_token('epic')}#estate=2"
    events = [e for e in store.list_audit() if e.subject == expected]
    assert len(events) == 1
    assert events[0].result is AuditResult.success
    assert events[0].actor == "obj-7"
    blob = events[0].model_dump_json().lower()
    assert "/subscriptions/" not in blob and "@" not in blob  # PII-free
    # The estate event is hash-chained into the append-only trail like every other event.
    assert verify_audit_chain(store.list_audit(), head=store.audit_head()) is None


def test_graph_endpoint_emits_audit(audit_client) -> None:
    client, store = audit_client
    resp = client.post("/api/workloads/epic/graph", json=_workload_graph().model_dump(mode="json"))
    assert resp.status_code == 200
    expected = f"{workload_token('epic')}#graph=nodes=2,edges=1"
    events = [e for e in store.list_audit() if e.subject == expected]
    assert len(events) == 1
    assert events[0].result is AuditResult.success


def test_snapshot_endpoint_emits_audit(audit_client) -> None:
    client, store = audit_client
    resp = client.post("/api/workloads/epic/snapshot")
    assert resp.status_code == 200
    # The durable subject is the bounded, PII-free INTENT marker (opaque token + ``#snapshot``):
    # the store-generated id (which embeds the raw workload name) is NOT put in the subject.
    expected = f"{workload_token('epic')}#snapshot"
    events = [e for e in store.list_audit() if e.subject == expected]
    assert len(events) == 1
    assert events[0].result is AuditResult.success
    assert resp.json()["snapshotId"].startswith("snap::epic::")  # id still returned to the caller


def test_empty_findings_submission_emits_count_zero_before_write(audit_client) -> None:
    # MEDIUM-1 (#99 R2): even an EMPTY findings submission is audited (audit-before-write), because
    # add_findings([]) still mutates durable state (manifest/version). Exactly one finding.emitted
    # with `#count=0` is recorded, and it precedes the (successful) write.
    client, store = audit_client
    resp = client.post("/api/workloads/epic/findings", json=[])
    assert resp.status_code == 200
    expected = "epic#count=0"
    events = [e for e in store.list_audit() if e.subject == expected]
    assert len(events) == 1
    assert events[0].result is AuditResult.success


def test_state_mutation_subject_is_pii_free_by_construction(audit_client) -> None:
    # A PII-looking workload name (is_audit_safe admits it — see the reviewer's John.Doe case) is
    # accepted, but its raw value NEVER reaches the durable audit subject: the subject is the opaque
    # one-way workload token, so no PII (or unbounded text) can be persisted regardless of the name.
    client, store = audit_client
    pii = "John.Doe"
    resp = client.post("/api/workloads/John.Doe/estate", json=[])
    assert resp.status_code == 200
    subjects = [e.subject for e in store.list_audit()]
    assert subjects == [f"{workload_token(pii)}#estate=0"]
    assert pii not in subjects[0]  # the raw PII-looking name is not embedded
    assert subjects[0].startswith("wl:")  # opaque digest token


# --------------------------------------------------------------------------------------
# #99 Part 2 — fail-CLOSED, audit-BEFORE-write at the API boundary: when the durable audit append
# fails, the state-mutating request FAILS (5xx) and the mutation is NEVER performed (no committed-
# but-unaudited state), and the failure is surfaced on the process metrics registry.
# --------------------------------------------------------------------------------------
class _AuditFailingStore(LocalStateStore):
    """A store whose audit append always fails, and which records any state mutation invoked (#99).

    ``mutations`` proves audit-BEFORE-write: because the endpoints emit the audit record as a
    precondition, a durable-append failure must raise BEFORE any ``put_estate``/``put_graph``/
    ``add_findings``/``snapshot``/``commit_run`` is invoked, so ``mutations`` stays empty and the
    underlying state is unchanged.
    """

    def __init__(self, root: str) -> None:
        super().__init__(root)
        self.mutations: list[str] = []

    def append_audit(self, event: AuditEvent) -> None:
        raise RuntimeError("audit store down")

    def put_estate(self, workload: str, nodes: list[ResourceNode]) -> None:
        self.mutations.append("put_estate")
        super().put_estate(workload, nodes)

    def put_graph(self, workload: str, graph: WorkloadGraph) -> None:
        self.mutations.append("put_graph")
        super().put_graph(workload, graph)

    def add_findings(self, workload: str, findings: list[Finding]) -> None:
        self.mutations.append("add_findings")
        super().add_findings(workload, findings)

    def snapshot(self, workload: str) -> str:
        self.mutations.append("snapshot")
        return super().snapshot(workload)

    def commit_run(self, workload: str, result: ModuleRunResult) -> dict[str, int]:
        self.mutations.append("commit_run")
        return super().commit_run(workload, result)


@pytest.fixture()
def failclosed_client(tmp_path):
    isolated = _AuditFailingStore(str(tmp_path))
    reg = MetricsRegistry()
    app.dependency_overrides[get_store] = lambda: isolated
    app.dependency_overrides[get_metrics] = lambda: reg
    # raise_server_exceptions=False so the propagated AuditPersistenceError surfaces as a 500
    # response (the real ASGI behaviour) rather than being re-raised into the test.
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client, isolated, reg
    app.dependency_overrides.clear()


def test_estate_endpoint_fails_closed_when_audit_append_fails(failclosed_client) -> None:
    client, store, reg = failclosed_client
    payload = [n.model_dump(mode="json") for n in _resource_nodes()]
    resp = client.post("/api/workloads/epic/estate", json=payload)
    assert resp.status_code == 500  # fail-closed: a durable audit append failure surfaces as 5xx
    # audit-BEFORE-write: the mutation was NEVER invoked, so no committed-but-unaudited estate.
    assert store.mutations == []
    assert store.get_estate("epic") == []
    failures = [s for s in reg.snapshot().counters if s.name == METRIC_AUDIT_EMIT_FAILURES]
    assert sum(s.value for s in failures) == 1  # the outage is observable on /api/metrics


def test_graph_endpoint_fails_closed_when_audit_append_fails(failclosed_client) -> None:
    client, store, _reg = failclosed_client
    resp = client.post("/api/workloads/epic/graph", json=_workload_graph().model_dump(mode="json"))
    assert resp.status_code == 500
    assert store.mutations == []  # graph never replaced
    assert store.get_graph("epic") is None


def test_snapshot_endpoint_fails_closed_when_audit_append_fails(failclosed_client) -> None:
    client, store, _reg = failclosed_client
    resp = client.post("/api/workloads/epic/snapshot")
    assert resp.status_code == 500
    assert store.mutations == []  # no snapshot frozen


def test_findings_endpoint_fails_closed_when_audit_append_fails(failclosed_client) -> None:
    # The finding.emitted path is fail-closed AND audit-before-write (#99): a durable audit outage
    # blocks the findings write entirely (no committed-but-unaudited findings).
    client, store, _reg = failclosed_client
    resp = client.post(
        "/api/workloads/epic/findings",
        json=[_finding_with_evidence("f1").model_dump(mode="json")],
    )
    assert resp.status_code == 500
    assert store.mutations == []  # the write was never invoked
    assert store.get_findings("epic") == []


def test_empty_findings_submission_fails_closed_when_audit_append_fails(failclosed_client) -> None:
    # MEDIUM-1 (#99 R2): store.add_findings(workload, []) is NOT a durable no-op — the Azure store
    # creates the workload manifest and advances its version even for an empty list. So the EMPTY
    # case must be audit-before-write too: under a failing audit sink an empty submission must 5xx
    # and NEVER invoke the (manifest/version-advancing) write.
    client, store, _reg = failclosed_client
    resp = client.post("/api/workloads/epic/findings", json=[])
    assert resp.status_code == 500
    assert store.mutations == []  # add_findings([]) was never invoked — no manifest / version bump
    assert store.get_findings("epic") == []


def test_results_endpoint_fails_closed_when_audit_append_fails(failclosed_client) -> None:
    # The /results commit path (run.executed + finding.emitted) is likewise audit-before-write: an
    # audit outage blocks the commit (nothing persisted).
    client, store, _reg = failclosed_client
    result = ModuleRunResult(module="discovery", ok=True, findings=[_finding_with_evidence("f1")])
    resp = client.post("/api/workloads/epic/results", json=result.model_dump(mode="json"))
    assert resp.status_code == 500
    assert store.mutations == []
    assert store.get_findings("epic") == []

