"""Audit emitter — the keyless seam that records consequential actions to the audit trail (#59).

The audit *contract* (:class:`~shared.contracts.AuditEvent`) and the append-only *persistence*
(:meth:`shared.state.StateStore.append_audit`) live elsewhere; this module is the thin, injectable
*emitter* that binds them. It is composed at the API boundary exactly like the state store / packs
engine / edge clients (see ``cli.wiring`` and ``api.app.main``) and handed to the consequential
code paths, so those paths depend only on this small seam rather than on the concrete store.

Design properties (all guardrail-driven):
  * **Keyless & in-boundary.** Emission is a local state write; no network egress, no secrets.
  * **PII-free by construction.** Events are built through :class:`~shared.contracts.AuditEvent`,
    whose validators reject emails/names/log-bodies/resource-paths — a PII-bearing event simply
    cannot be constructed, so nothing sensitive is ever persisted.
  * **Fail-CLOSED for security-material actions (issue #99, ADR 0014).** For the consequential
    state-mutating actions in :data:`FAIL_CLOSED_ACTIONS` (``run.executed`` / ``finding.emitted`` —
    which also carry the estate/graph/snapshot replacements), a durable-append failure PROPAGATES
    as :class:`AuditPersistenceError` so the audited mutation FAILS (the API returns 5xx) rather
    than silently succeeding with no tamper-evident record — the ACCEPTED, compliance-first policy.
    A **narrow, documented allowance** keeps genuinely non-material events (the ``pack.verify``
    FAILURE breadcrumb, module toggles) best-effort/fail-OPEN: a lost breadcrumb there does not
    correspond to an unrecorded successful mutation (the pack is already rejected fail-closed
    regardless, and it is emitted mid-pack-load where raising would convert a safe rejection into a
    crash). A rejected event (PII/validation) is still logged class-name-only and dropped.
  * **Failure is observable.** Any durable-append failure (fail-open or fail-closed) increments the
    PII-free :data:`METRIC_AUDIT_EMIT_FAILURES` counter on the injected process metrics registry, so
    an audit-store outage is visible on ``/api/metrics`` and can drive health/alerting.
  * **Actor is a non-PII principal id.** :func:`resolve_actor` reads ONLY the object/principal id
    header and falls back to the ``system`` principal — it never reads a name/email header.
"""
from __future__ import annotations

import hashlib
import logging
from collections.abc import Mapping, Sequence
from typing import Protocol, runtime_checkable

from pydantic import ValidationError

from shared.contracts import AuditAction, AuditEvent, AuditResult, is_audit_safe

logger = logging.getLogger(__name__)

# The system/automated principal used when no human/managed-identity principal id is present (e.g.
# an internal worker-driven run). A stable, non-PII sentinel — never a name or email.
SYSTEM_ACTOR = "system"

# The ONLY request header we read for actor identity: the caller's object/principal id (a guid),
# injected by Azure Easy Auth / the managed-identity front door. We deliberately never read the
# ``*-principal-name`` header (an email/UPN — PII).
PRINCIPAL_ID_HEADER = "x-ms-client-principal-id"

# --------------------------------------------------------------------------------------
# Fail-closed audit policy (issue #99, ADR 0014).
# --------------------------------------------------------------------------------------
# Metric name for a durable audit-append failure, surfaced on the process metrics registry so an
# audit-store outage is visible on ``/api/metrics`` and can drive health/alerting. Low-cardinality:
# the only label (:data:`AUDIT_ACTION_LABEL`) is the PII-free ``AuditAction`` value.
METRIC_AUDIT_EMIT_FAILURES = "audit_emit_failures_total"
AUDIT_ACTION_LABEL = "action"

# Security-material actions whose durable audit record is REQUIRED: losing the record would mean a
# consequential state mutation succeeded with NO durable, tamper-evident account of it. For these,
# emission is FAIL-CLOSED — a durable-append failure propagates (as :class:`AuditPersistenceError`)
# so the audited mutation fails/rolls back (the API returns 5xx) instead of silently succeeding
# unrecorded. The state-mutating ``put_estate``/``put_graph``/``snapshot`` writes and the run/
# findings writes are ALL recorded with these two actions (see ``api.app.main``), so they are all
# fail-closed. Everything else (the ``pack.verify`` FAILURE breadcrumb, module toggles) is the
# NARROW, documented allowance and stays best-effort/fail-open. This is the ACCEPTED, compliance-
# first decision — see ``docs/adr/0014-fail-closed-audit-emission.md``.
FAIL_CLOSED_ACTIONS: frozenset[AuditAction] = frozenset(
    {AuditAction.run_executed, AuditAction.finding_emitted}
)


class AuditPersistenceError(RuntimeError):
    """Raised when a FAIL-CLOSED audit event could not be durably persisted (issue #99).

    Propagated out of :meth:`AuditEmitter.emit` for a security-material action (see
    :data:`FAIL_CLOSED_ACTIONS`) so the audited mutation fails (the API surfaces 5xx) instead of
    silently succeeding with no durable, tamper-evident record.
    """


@runtime_checkable
class MetricsCounter(Protocol):
    """The minimal counter surface the emitter needs to surface a failure signal.

    Satisfied structurally by :class:`shared.observability.MetricsRegistry`, so the emitter never
    imports the concrete registry (keeps ``shared.audit`` free of an observability dependency).
    """

    def increment(
        self, name: str, *, labels: Mapping[str, str] | None = ..., amount: int = ...
    ) -> None:
        """Add to the counter identified by ``name`` + ``labels``."""
        ...


# --------------------------------------------------------------------------------------
# Tamper-evident hash chaining (issue #59, MED-3).
#
# Every persisted audit record is linked into a hash chain: ``entryHash = sha256(canonical_bytes
# (event) || prevHash)``, where ``prevHash`` is the previous record's ``entryHash`` (or the fixed
# genesis anchor for the very first event). The storage layer maintains an anchored chain HEAD (the
# latest ``entryHash``) updated in the SAME append operation, so a reader can recompute the chain
# and compare its terminal hash to the HEAD. This makes storage-layer edits, reordering, and
# tail-truncation DETECTABLE on read (see :func:`verify_audit_chain`). It does NOT by itself prevent
# a sufficiently privileged principal from deleting the whole store — storage immutability is a
# documented follow-up (see ADR 0006). The chaining functions are PURE (no I/O), so they are
# trivially unit-testable and deterministic: the same event sequence always yields the same hashes.
# --------------------------------------------------------------------------------------

# Fixed, documented genesis anchor — the ``prevHash`` of the first event in a chain. 64 zeros
# mirrors a SHA-256 hex digest width and can never collide with a real ``entryHash``.
GENESIS_HASH = "0" * 64


def compute_entry_hash(event: AuditEvent, prev_hash: str) -> str:
    """Return the chain hash for ``event`` linked onto ``prev_hash`` (pure, deterministic)."""
    digest = hashlib.sha256()
    digest.update(event.canonical_bytes())
    digest.update(prev_hash.encode("utf-8"))
    return digest.hexdigest()


def chain_event(event: AuditEvent, prev_hash: str) -> AuditEvent:
    """Return a copy of ``event`` with ``prevHash``/``entryHash`` populated for persistence.

    ``model_copy`` is used (the contract is ``frozen``) so the original event is never mutated; the
    hash fields are excluded from :meth:`AuditEvent.canonical_bytes`, so setting them does not
    change the event's own hash.
    """
    return event.model_copy(
        update={"prevHash": prev_hash, "entryHash": compute_entry_hash(event, prev_hash)}
    )


def verify_audit_chain(
    events: Sequence[AuditEvent],
    *,
    head: str | None = None,
    genesis: str = GENESIS_HASH,
) -> int | None:
    """Recompute the hash chain over ``events`` and return the index of the first broken link.

    Returns ``None`` iff the chain is intact. Detects (fail-closed on read):
      * a **tampered field** — the recomputed ``entryHash`` no longer matches the stored one;
      * a **reorder / insertion / deletion** in the middle — an entry's ``prevHash`` no longer
        matches the running chain head;
      * a **truncated tail** — when the anchored ``head`` is supplied, an otherwise-valid but
        shortened chain whose terminal hash != ``head`` returns ``len(events)`` (a position past
        the end, meaning "entries are missing from the tail").

    ``events`` must be supplied in chain (append) order. Pure over the read sequence.
    """
    prev = genesis
    for index, event in enumerate(events):
        if event.prevHash != prev:
            return index
        if event.entryHash != compute_entry_hash(event, prev):
            return index
        prev = event.entryHash or ""
    if head is not None and prev != head:
        return len(events)
    return None


@runtime_checkable
class AuditSink(Protocol):
    """The minimal append-only write surface the emitter needs (satisfied by ``StateStore``)."""

    def append_audit(self, event: AuditEvent) -> None:
        """Append one event to the tamper-evident, append-only audit log."""
        ...


def resolve_actor(headers: Mapping[str, str] | None) -> str:
    """Resolve a non-PII principal id from request headers, else the ``system`` actor (fail safe).

    Reads ONLY :data:`PRINCIPAL_ID_HEADER` (an object/principal id). If it is absent, blank, or —
    defensively — not a bounded PII-free identifier, we fall back to :data:`SYSTEM_ACTOR` rather
    than risk recording a name/email. Never raises.
    """
    if headers is None:
        return SYSTEM_ACTOR
    raw = (headers.get(PRINCIPAL_ID_HEADER) or "").strip()
    if raw and is_audit_safe(raw):
        return raw
    return SYSTEM_ACTOR


class AuditEmitter:
    """Builds and persists :class:`~shared.contracts.AuditEvent` records.

    Construct with a durable ``sink`` (the API's single-writer ``StateStore``) or ``None`` (a
    no-op emitter — used where no store is wired, so callers need no null checks). Optionally pass a
    ``metrics`` counter (the process :class:`shared.observability.MetricsRegistry`) so a durable-
    append failure is surfaced as a health signal.

    Emission is **fail-closed for security-material actions** (see :data:`FAIL_CLOSED_ACTIONS`): a
    persistence failure on those actions raises :class:`AuditPersistenceError` so the audited
    mutation fails rather than proceeding unrecorded. Non-material actions stay best-effort. A
    rejected (PII/invalid) event is always logged class-name-only and dropped (never persisted).
    """

    def __init__(
        self, sink: AuditSink | None, *, metrics: MetricsCounter | None = None
    ) -> None:
        self._sink = sink
        self._metrics = metrics

    def emit(
        self,
        *,
        actor: str,
        action: AuditAction,
        subject: str,
        result: AuditResult,
        pack_id: str | None = None,
        pack_version: str | None = None,
    ) -> AuditEvent | None:
        """Build a PII-free event and append it to the log. Returns the event, or ``None``.

        Rejects (returns ``None``, persists nothing) an event whose fields fail the PII/validity
        validators. On a durable-append failure the outcome depends on the action's materiality
        (issue #99): for an action in :data:`FAIL_CLOSED_ACTIONS` the failure is surfaced as a
        metric and re-raised as :class:`AuditPersistenceError` (fail-closed — the audited mutation
        must fail); for any other action it is surfaced as a metric, logged, and swallowed (the
        narrow best-effort allowance). Success returns the persisted event.
        """
        try:
            event = AuditEvent(
                actor=actor,
                action=action,
                subject=subject,
                result=result,
                packId=pack_id,
                packVersion=pack_version,
            )
        except ValidationError:
            # Fail closed: refuse to emit (and never echo the rejected value). The action proceeds.
            logger.error("audit event rejected (fail closed) action=%s", action.value)
            return None
        if self._sink is not None:
            try:
                self._sink.append_audit(event)
            except Exception as exc:  # noqa: BLE001 - policy decided per action materiality below
                self._on_persist_failure(event, exc)
        return event

    def _on_persist_failure(self, event: AuditEvent, exc: Exception) -> None:
        """Surface a durable-append failure as a metric, then fail-closed or swallow (issue #99).

        Always increments :data:`METRIC_AUDIT_EMIT_FAILURES` (PII-free, action-labelled) on the
        injected metrics registry so the outage is observable. For a security-material action
        (:data:`FAIL_CLOSED_ACTIONS`) it then raises :class:`AuditPersistenceError` so the audited
        mutation fails closed; otherwise it logs and returns (the audited action proceeds).
        """
        fail_closed = event.action in FAIL_CLOSED_ACTIONS
        if self._metrics is not None:
            self._metrics.increment(
                METRIC_AUDIT_EMIT_FAILURES, labels={AUDIT_ACTION_LABEL: event.action.value}
            )
        logger.error(
            "audit persistence failed action=%s result=%s error=%s fail_closed=%s",
            event.action.value,
            event.result.value,
            type(exc).__name__,
            fail_closed,
        )
        if fail_closed:
            raise AuditPersistenceError(
                f"durable audit append failed for security-material action {event.action.value}"
            ) from exc
