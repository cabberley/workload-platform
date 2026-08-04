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
  * **Never breaks the audited action.** :meth:`AuditEmitter.emit` never raises: a rejected event
    (PII/validation) or a persistence error is logged with a **class-name-only** message and
    dropped, so recording an action can never crash the action itself. The append-only store is
    the durable guarantee; the emitter is the best-effort writer in front of it.
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
    """Builds and persists :class:`~shared.contracts.AuditEvent` records. Never raises.

    Construct with a durable ``sink`` (the API's single-writer ``StateStore``) or ``None`` (a
    no-op emitter — used where no store is wired, so callers need no null checks).
    """

    def __init__(self, sink: AuditSink | None) -> None:
        self._sink = sink

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

        Never raises: if the event is rejected by its validators (PII/invalid) or the append fails,
        the emitter logs a class-name-only message and returns ``None``/the event respectively, so
        the audited action is never disrupted by an audit failure.
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
            except Exception as exc:  # noqa: BLE001 - audit must never break the audited action
                logger.error(
                    "audit persistence failed action=%s result=%s error=%s",
                    event.action.value,
                    event.result.value,
                    type(exc).__name__,
                )
        return event
