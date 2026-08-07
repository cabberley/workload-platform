"""Pure, vendor-neutral transform layer for the load-balancer connectors (issue #49).

The two LB connectors — Citrix **NetScaler** (NITRO REST, :mod:`shared.connectors.netscaler`) and
**F5 BIG-IP** (iControl REST, :mod:`shared.connectors.f5`) — speak different wire schemas but feed
the platform the SAME three PII-safe signals:

* **backend-pool membership → dependency edges** (feeds smart blast radius). A pure
  :func:`dependency_edges` maps membership to typed :class:`~shared.contracts.DependencyEdge`
  objects (``EdgeType.load_balances``), emitting BOTH directions per validated member — a
  non-redundant ``member -> lb`` ingress edge (losing the LB *downs* every member — the SPOF edge)
  and an ``lb -> member`` edge tagged ``redundant=True`` when the pool has ≥2 known members (losing
  one member is *degraded*, not *down*). This mirrors the framework's ``edges_from_backend_pool``
  convention and is a DEFERRED mapping (see ADR 0015 — never merged into the persisted graph).
* **aggregate LB health** — a pure :func:`aggregate_health` reduces per-member health tokens to a
  single :class:`~shared.contracts.HealthState` per LB, then :func:`apply_health` annotates the
  matching authoritative estate node with a closed-vocabulary tag (never creating/mutating a node).
* **filtered-log-derived signals** — :func:`log_signals` keeps only bounded, closed-vocabulary
  **aggregate** numeric datapoints (e.g. an error rate). There is **no** free-form/raw-log field in
  the schema, so a raw log body can never ride along.

Everything here is a **pure function** with **no I/O** — the network sits at the connector edge on
:class:`shared.connectors.edge.HttpEdgeClient`. Each signal schema is a **closed** key set validated
atomically: any unexpected key, oversized/charset-invalid id, non-allowlisted health token, or
out-of-range metric **rejects the whole batch** (fail closed) — never a partially-fabricated set.

TODO(human): the concrete NITRO / iControl object models, health vocabularies, and log-summary
shapes are an EXTERNAL dependency owned by the product/network team. The vocabularies and bounds
here are conservative synthetic placeholders exercised only by synthetic fixtures; confirm and
replace them (with an ADR) once the real vendor contracts are published.
"""
from __future__ import annotations

import math
import re
from collections.abc import Iterable, Sequence
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from shared.connectors.base import FetchResult
from shared.contracts import (
    AgentResponse,
    DependencyEdge,
    EdgeType,
    HealthState,
    ResourceNode,
    SourceReference,
)

__all__ = [
    "ALLOWED_LOG_METRICS",
    "ALLOWED_MEMBER_HEALTH",
    "BACKEND_MEMBER_KIND",
    "LB_EDGE_TYPE",
    "LOG_SIGNAL_KIND",
    "MAX_LOG_VALUE",
    "MAX_RESOURCE_ID_LEN",
    "SUPPLEMENTAL_HEALTH_TAG",
    "SUPPLEMENTAL_SOURCE_TAG",
    "BackendMemberHint",
    "LbSignalError",
    "LbSignals",
    "LogSignalHint",
    "SupplementalResult",
    "aggregate_health",
    "apply_health",
    "dependency_edges",
    "log_signals",
    "parse_signals_atomic",
    "signals_from_result",
    "signals_to_raw",
    "to_agent_response",
    "to_source_reference",
    "validate_log_hint",
    "validate_member_hint",
]

# The two signal kinds this layer understands. Anything else fails the whole fetch (atomic). A
# ``backend-member`` record carries a pool member + its health; a ``log-signal`` record carries one
# aggregate numeric log datapoint. There is deliberately no free-form field on either.
BACKEND_MEMBER_KIND = "backend-member"
LOG_SIGNAL_KIND = "log-signal"

# The CLOSED health vocabulary a member may report — aligned 1:1 with ``HealthState`` so the
# aggregate reduces to a contract enum with no lossy remap. Anything outside this set rejects the
# whole fetch; no free-form string is ever admitted.
ALLOWED_MEMBER_HEALTH: frozenset[str] = frozenset({"up", "down", "degraded", "unknown"})

# The CLOSED vocabulary of aggregate, filtered-log-derived metrics. Each is a numeric aggregate
# (rate/count) — never a raw log body. TODO(human): confirm the real metric set with the network
# team once the vendor log-summary contract is published.
ALLOWED_LOG_METRICS: frozenset[str] = frozenset({"error_rate", "reset_rate", "conn_drops"})

# The typed edge a backend-pool membership maps to: the LB ``load_balances`` each backend member.
LB_EDGE_TYPE = EdgeType.load_balances

# Supplemental, non-authoritative provenance tags — expressed with ONLY the existing
# ``ResourceNode.tags`` field (no contract change). ``aegis:source`` marks the contributing
# connector(s); ``aegis:lb-health`` carries the closed-vocabulary aggregate health token.
SUPPLEMENTAL_SOURCE_TAG = "aegis:source"
SUPPLEMENTAL_HEALTH_TAG = "aegis:lb-health"

# A resource id is used ONLY to match an already-discovered estate node id; it is never written as
# new data. It must still pass a strict charset/length gate so a PII-like value (e.g. an email) is
# rejected outright. Azure/estate node ids use only these characters.
_RESOURCE_ID_RE = re.compile(r"^[A-Za-z0-9/_.\-]+$")

# A HARD, module-level ceiling on a resource id's length — the model's OWN self-validation bound,
# independent of any injected config so the invariant holds no matter how a hint is constructed.
MAX_RESOURCE_ID_LEN = 1024

# A HARD ceiling on an aggregate log metric value — a sanity bound so a bogus/huge datapoint fails
# closed rather than propagating. Values must be finite and non-negative.
MAX_LOG_VALUE = 1e12


class LbSignalError(ValueError):
    """Raised when a raw LB signal is unknown/malformed/oversized/out-of-range — fail closed."""


def _resource_id_ok(value: object) -> bool:
    """True iff ``value`` is a well-formed, bounded, charset-restricted resource id (no PII)."""
    return (
        isinstance(value, str)
        and 1 <= len(value) <= MAX_RESOURCE_ID_LEN
        and bool(_RESOURCE_ID_RE.match(value))
    )


def _health_ok(value: object) -> bool:
    """True iff ``value`` is a member of the CLOSED member-health vocabulary."""
    return isinstance(value, str) and value in ALLOWED_MEMBER_HEALTH


def _log_metric_ok(value: object) -> bool:
    """True iff ``value`` is a member of the CLOSED aggregate log-metric vocabulary."""
    return isinstance(value, str) and value in ALLOWED_LOG_METRICS


def _log_value_ok(value: object) -> bool:
    """True iff ``value`` is a finite, non-negative, bounded numeric (no bool, no NaN/inf)."""
    return (
        isinstance(value, int | float)
        and not isinstance(value, bool)
        and math.isfinite(value)
        and 0.0 <= float(value) <= MAX_LOG_VALUE
    )


class BackendMemberHint(BaseModel):
    """A validated backend-pool membership signal — an LB id, a member id, and a health token.

    Both ids are only ever matched against an existing estate node id (never written as new data);
    ``health`` is a CLOSED-allowlist token. No free-form field exists on purpose. The invariants are
    enforced by pydantic **field validators** DIRECTLY on this model, so they hold no matter HOW a
    hint is constructed — including :func:`signals_from_result` rehydrating an *injected* connector
    's untrusted ``FetchResult.raw``. ``extra="forbid"`` rejects any smuggled extra key.
    """

    model_config = ConfigDict(extra="forbid")

    lb_id: str
    member_id: str
    health: str

    @field_validator("lb_id", "member_id")
    @classmethod
    def _validate_ids(cls, value: str) -> str:
        if not _resource_id_ok(value):
            raise ValueError("id out of bounds or contains disallowed characters")
        return value

    @field_validator("health")
    @classmethod
    def _validate_health(cls, value: str) -> str:
        if not _health_ok(value):
            raise ValueError("health not in the closed allowlist")
        return value


class LogSignalHint(BaseModel):
    """A validated, bounded, **aggregate** filtered-log-derived signal — an LB id + metric + value.

    ``lb_id`` is only ever matched against an existing estate node id; ``metric`` is a
    CLOSED-allowlist token; ``value`` is a finite, non-negative, bounded numeric. There is
    deliberately no free-form/raw-log field, so a raw log body can never ride along.
    """

    model_config = ConfigDict(extra="forbid")

    lb_id: str
    metric: str
    value: float

    @field_validator("lb_id")
    @classmethod
    def _validate_lb_id(cls, value: str) -> str:
        if not _resource_id_ok(value):
            raise ValueError("lb_id out of bounds or contains disallowed characters")
        return value

    @field_validator("metric")
    @classmethod
    def _validate_metric(cls, value: str) -> str:
        if not _log_metric_ok(value):
            raise ValueError("metric not in the closed allowlist")
        return value

    @field_validator("value")
    @classmethod
    def _validate_value(cls, value: float) -> float:
        if not _log_value_ok(value):
            raise ValueError("value is not a finite, non-negative, bounded numeric")
        return value


class LbSignals(BaseModel):
    """The atomic result of parsing an LB fetch: bounded membership + aggregate log signals.

    Both lists are validated together; if ANY record in the batch is invalid the whole parse raises
    (fail closed) — never a partially-accepted set.
    """

    model_config = ConfigDict(extra="forbid")

    members: list[BackendMemberHint] = Field(default_factory=list)
    logs: list[LogSignalHint] = Field(default_factory=list)


class SupplementalResult(BaseModel):
    """Result of applying aggregate LB health onto the authoritative estate.

    ``nodes`` is the SAME estate as the input (same ids, same order, authoritative fields untouched)
    with the supplemental tag(s) added to matched LB nodes only. ``annotated_ids`` lists the ids
    that received a tag. A connector never adds or removes a node.
    """

    model_config = ConfigDict(extra="forbid")

    nodes: list[ResourceNode] = Field(default_factory=list)
    annotated_ids: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------------------
# Pure validation + mapping — no I/O, fully unit-testable with synthetic payloads.
# --------------------------------------------------------------------------------------
def _require_bounded_id(value: Any, *, max_field_len: int) -> str:
    """Return ``value`` iff it is a bounded, charset-restricted string, else fail closed."""
    if not isinstance(value, str):
        raise LbSignalError("id must be a string")
    if not (1 <= len(value) <= max_field_len):
        raise LbSignalError("id length out of bounds")
    if not _RESOURCE_ID_RE.match(value):
        raise LbSignalError("id contains disallowed characters")
    return value


def validate_member_hint(raw: Any, *, max_field_len: int) -> BackendMemberHint:
    """Strictly validate ONE raw ``backend-member`` record → hint, or raise :class:`LbSignalError`.

    Fail closed on: a non-mapping; a wrong/absent ``kind``; a missing/oversized/charset-invalid
    ``lbId`` or ``memberId``; a ``health`` outside :data:`ALLOWED_MEMBER_HEALTH`; or ANY unexpected
    key (so a payload smuggling a free-text field is rejected outright — PII never even enters the
    mapping).
    """
    if not isinstance(raw, dict):
        raise LbSignalError("member record is not a mapping")
    unexpected = set(raw) - {"kind", "lbId", "memberId", "health"}
    if unexpected:
        raise LbSignalError(f"unexpected member field(s): {sorted(unexpected)}")
    if raw.get("kind") != BACKEND_MEMBER_KIND:
        raise LbSignalError(f"unknown member kind: {raw.get('kind')!r}")
    lb_id = _require_bounded_id(raw.get("lbId"), max_field_len=max_field_len)
    member_id = _require_bounded_id(raw.get("memberId"), max_field_len=max_field_len)
    health = raw.get("health")
    if not _health_ok(health):
        raise LbSignalError("health not in the closed allowlist")
    return BackendMemberHint(lb_id=lb_id, member_id=member_id, health=str(health))


def validate_log_hint(raw: Any, *, max_field_len: int) -> LogSignalHint:
    """Strictly validate ONE raw ``log-signal`` record → hint, or raise :class:`LbSignalError`.

    Fail closed on: a non-mapping; a wrong/absent ``kind``; a missing/oversized/charset-invalid
    ``lbId``; a ``metric`` outside :data:`ALLOWED_LOG_METRICS`; a ``value`` that is not a finite,
    non-negative, bounded numeric; or ANY unexpected key.
    """
    if not isinstance(raw, dict):
        raise LbSignalError("log record is not a mapping")
    unexpected = set(raw) - {"kind", "lbId", "metric", "value"}
    if unexpected:
        raise LbSignalError(f"unexpected log field(s): {sorted(unexpected)}")
    if raw.get("kind") != LOG_SIGNAL_KIND:
        raise LbSignalError(f"unknown log kind: {raw.get('kind')!r}")
    lb_id = _require_bounded_id(raw.get("lbId"), max_field_len=max_field_len)
    metric = raw.get("metric")
    if not _log_metric_ok(metric):
        raise LbSignalError("metric not in the closed allowlist")
    value = raw.get("value")
    if not _log_value_ok(value):
        raise LbSignalError("value is not a finite, non-negative, bounded numeric")
    assert isinstance(value, int | float)  # narrowed by _log_value_ok; bool already excluded
    return LogSignalHint(lb_id=lb_id, metric=str(metric), value=float(value))


def parse_signals_atomic(
    records: Sequence[Any], *, max_records: int, max_field_len: int
) -> LbSignals:
    """Validate ALL records atomically → :class:`LbSignals`, dispatching on ``kind``.

    If the batch is oversized, or ANY single record is unknown/malformed/schema-invalid, the whole
    call raises (fail closed) — never a partially-accepted, partially-fabricated set. A record's
    ``kind`` selects the member or log validator; an unrecognized ``kind`` fails closed.
    """
    if len(records) > max_records:
        raise LbSignalError(f"too many signal records: {len(records)} > {max_records}")
    members: list[BackendMemberHint] = []
    logs: list[LogSignalHint] = []
    for record in records:
        if not isinstance(record, dict):
            raise LbSignalError("signal record is not a mapping")
        kind = record.get("kind")
        if kind == BACKEND_MEMBER_KIND:
            members.append(validate_member_hint(record, max_field_len=max_field_len))
        elif kind == LOG_SIGNAL_KIND:
            logs.append(validate_log_hint(record, max_field_len=max_field_len))
        else:
            raise LbSignalError(f"unknown signal kind: {kind!r}")
    return LbSignals(members=members, logs=logs)


def signals_from_result(result: FetchResult) -> LbSignals:
    """Rehydrate validated :class:`LbSignals` from a fetch result — pure, UNTRUSTED input.

    Unavailable ⇒ empty signals (fail closed). The ``result`` may come from ANY connector wired into
    a consuming module — including an injected test double or a misconfigured/alternate connector —
    so its ``raw`` is treated as **untrusted**: every record is re-validated by constructing the
    corresponding hint model through its field validators (charset/length/closed-vocabulary +
    ``extra="forbid"``). If ANY record is invalid the whole batch is rejected (atomic, fail closed),
    so a smuggled PII value can never reach persisted state.
    """
    if not result.available:
        return LbSignals()
    members: list[BackendMemberHint] = []
    logs: list[LogSignalHint] = []
    try:
        for record in result.raw:
            kind = record.get("kind")
            payload = {k: v for k, v in record.items() if k != "kind"}
            if kind == BACKEND_MEMBER_KIND:
                members.append(BackendMemberHint.model_validate(payload))
            elif kind == LOG_SIGNAL_KIND:
                logs.append(LogSignalHint.model_validate(payload))
            else:
                raise LbSignalError(f"unknown signal kind: {kind!r}")
    except ValidationError as exc:
        raise LbSignalError("untrusted LB record failed re-validation") from exc
    return LbSignals(members=members, logs=logs)


def signals_to_raw(signals: LbSignals) -> list[dict[str, Any]]:
    """Normalize validated signals to internal wire records carrying a ``kind`` discriminator.

    These records populate ``FetchResult.raw``; :func:`signals_from_result` re-validates them
    (untrusted) by dispatching on ``kind``. Only closed-vocabulary / charset-bounded values appear.
    """
    raw: list[dict[str, Any]] = []
    for member in signals.members:
        raw.append(
            {
                "kind": BACKEND_MEMBER_KIND,
                "lb_id": member.lb_id,
                "member_id": member.member_id,
                "health": member.health,
            }
        )
    for log in signals.logs:
        raw.append(
            {"kind": LOG_SIGNAL_KIND, "lb_id": log.lb_id, "metric": log.metric, "value": log.value}
        )
    return raw


def dependency_edges(
    members: Iterable[BackendMemberHint], known_ids: Iterable[str], *, origin: str
) -> list[DependencyEdge]:
    """Map backend-pool membership to typed ``load_balances`` edges — pure (feeds blast radius).

    Two directions are emitted per validated member, mirroring the framework convention
    :func:`modules.dependency_graph.module.edges_from_backend_pool`, so the pure blast-radius math
    ranks the balancer as the single point of failure it is:

    * ``member --load_balances--> lb`` (**always non-redundant**): every member depends on the LB
      for ingress, so losing the LB **downs all members** — the critical SPOF edge.
    * ``lb --load_balances--> member`` (**redundant** when the LB's pool has ≥2 known members): the
      balanced service depends on redundant member peers, so losing *one* member only **degrades**
      it (losing the sole member downs it).

    An edge is produced for a member ONLY when BOTH endpoints exactly match an existing estate node
    id (a phantom endpoint never becomes an edge) and differ (no self-edge). ``redundant`` on the
    ``lb -> member`` edge is derived from the count of DISTINCT members that pass that SAME gate
    (known, charset-valid, non-self) — NOT over all parsed members — so a phantom/unknown or
    self member can never falsely mark a single-real-backend LB redundant (fail closed). Each edge
    carries the connector's ``origin`` (e.g. ``connector:netscaler``) so a consumer can attribute +
    de-dupe it. Every hint is RE-VALIDATED at this boundary so a bypass-constructed
    (``model_construct``) hint with a charset-invalid/oversized id is dropped (fail closed).

    This is a PURE, DEFERRED mapping returned for a FUTURE, merge-aware integration — it is
    intentionally NOT merged into the persisted graph (the ``dependency_graph`` module
    UPSERT-REPLACES a workload's graph, so a naive edge merge would wipe the authoritative
    auto/pack edges). See ADR ``docs/adr/0015-citrix-dependency-edge-merge-deferred.md`` and the
    ``dependency_graph`` module's ``_lb_assist``; the connectors contribute supplemental estate
    NODE (health) annotations only.
    """
    materialized = list(members)
    known = set(known_ids)
    # Pool size per LB counted ONLY over members that pass the SAME gate used to emit an edge:
    # member id known, both ids charset-valid, and non-self. A phantom/unknown or self member never
    # inflates the count, so a single-real-backend LB stays correctly NON-redundant (fail closed).
    pool: dict[str, set[str]] = {}
    for hint in materialized:
        if not _resource_id_ok(hint.lb_id) or not _resource_id_ok(hint.member_id):
            continue
        if hint.lb_id == hint.member_id:
            continue
        if hint.lb_id not in known or hint.member_id not in known:
            continue
        pool.setdefault(hint.lb_id, set()).add(hint.member_id)
    out: list[DependencyEdge] = []
    seen: set[tuple[str, str]] = set()
    for hint in materialized:
        if not _resource_id_ok(hint.lb_id) or not _resource_id_ok(hint.member_id):
            continue
        lb_id, member_id = hint.lb_id, hint.member_id
        if lb_id == member_id or lb_id not in known or member_id not in known:
            continue
        redundant = len(pool.get(lb_id, set())) > 1
        # member -> lb: always non-redundant (losing the LB downs every member — the SPOF edge).
        member_to_lb = (member_id, lb_id)
        if member_to_lb not in seen:
            seen.add(member_to_lb)
            out.append(
                DependencyEdge(
                    source=member_id,
                    target=lb_id,
                    type=LB_EDGE_TYPE,
                    redundant=False,
                    origin=origin,
                )
            )
        # lb -> member: redundant when the LB has ≥2 known member peers (losing one degrades).
        lb_to_member = (lb_id, member_id)
        if lb_to_member not in seen:
            seen.add(lb_to_member)
            out.append(
                DependencyEdge(
                    source=lb_id,
                    target=member_id,
                    type=LB_EDGE_TYPE,
                    redundant=redundant,
                    origin=origin,
                )
            )
    return out


def aggregate_health(members: Iterable[BackendMemberHint]) -> dict[str, HealthState]:
    """Reduce per-member health tokens to a single aggregate :class:`HealthState` per LB — pure.

    Rule per LB (over the distinct set of its members' health tokens): all ``up`` ⇒ ``up``; all
    ``down`` ⇒ ``down``; all ``unknown`` ⇒ ``unknown``; any other mix (including ``up``+``unknown``,
    which is a monitoring gap) ⇒ ``degraded``. Every hint is RE-VALIDATED here so a
    bypass-constructed hint with an invalid id/health is ignored (fail closed).
    """
    tokens: dict[str, set[str]] = {}
    for hint in members:
        if not _resource_id_ok(hint.lb_id) or not _health_ok(hint.health):
            continue
        tokens.setdefault(hint.lb_id, set()).add(hint.health)
    out: dict[str, HealthState] = {}
    for lb_id, distinct in tokens.items():
        if distinct == {"up"}:
            out[lb_id] = HealthState.up
        elif distinct == {"down"}:
            out[lb_id] = HealthState.down
        elif distinct == {"unknown"}:
            out[lb_id] = HealthState.unknown
        else:
            out[lb_id] = HealthState.degraded
    return out


def apply_health(
    authoritative: Iterable[ResourceNode],
    aggregate: dict[str, HealthState],
    *,
    source: str,
) -> SupplementalResult:
    """Apply aggregate LB health onto the **authoritative** estate — pure, estate always wins.

    A health is applied ONLY when its LB id exactly matches an existing node id; the matched node is
    COPIED with ``source`` unioned into the ``aegis:source`` provenance set plus a closed
    ``aegis:lb-health`` token. Provenance is ADDITIVE — a pre-existing ``aegis:source`` (e.g. from
    another connector) is preserved and this connector is unioned into it, never overwritten.
    Authoritative fields (id/name/type/workload/tier/role) are never changed, no node is ever
    created from a signal, and a health that matches nothing is dropped.

    This is the persistence-adjacent boundary, so each entry is re-checked (``HealthState`` values
    are a closed enum, so a bad token cannot appear) before a tag is written.
    """
    authoritative_nodes = list(authoritative)
    known_ids = {node.id for node in authoritative_nodes}
    health_by_id = {
        lb_id: state.value for lb_id, state in aggregate.items() if lb_id in known_ids
    }
    out: list[ResourceNode] = []
    annotated_ids: list[str] = []
    for node in authoritative_nodes:
        if node.id not in health_by_id:
            out.append(node)
            continue
        new_tags = dict(node.tags)
        existing_source = new_tags.get(SUPPLEMENTAL_SOURCE_TAG, "")
        sources = {s for s in existing_source.split(",") if s} | {source}
        new_tags[SUPPLEMENTAL_SOURCE_TAG] = ",".join(sorted(sources))
        new_tags[SUPPLEMENTAL_HEALTH_TAG] = health_by_id[node.id]
        out.append(node.model_copy(update={"tags": new_tags}))
        annotated_ids.append(node.id)
    return SupplementalResult(nodes=out, annotated_ids=annotated_ids)


def log_signals(
    logs: Iterable[LogSignalHint], known_ids: Iterable[str]
) -> list[LogSignalHint]:
    """Keep only aggregate log signals whose LB id matches an existing estate node — pure.

    A signal for an unknown/phantom LB is dropped (supplement-only). Every hint is RE-VALIDATED here
    so a bypass-constructed hint with an invalid id/metric/value is dropped (fail closed). Only
    closed-vocabulary, bounded aggregate datapoints survive — never a raw log body.
    """
    known = set(known_ids)
    out: list[LogSignalHint] = []
    for hint in logs:
        if (
            not _resource_id_ok(hint.lb_id)
            or not _log_metric_ok(hint.metric)
            or not _log_value_ok(hint.value)
        ):
            continue
        if hint.lb_id in known:
            out.append(hint)
    return out


def to_source_reference(source: str, resource_id: str) -> SourceReference:
    """Provenance for an LB supplemental signal — cites the connector + resource id."""
    return SourceReference(kind="connector", id=source, detail=resource_id)


def to_agent_response(
    *,
    agent_name: str,
    source: str,
    available: bool,
    aggregate: dict[str, HealthState],
    edges: Sequence[DependencyEdge],
    logs: Sequence[LogSignalHint],
) -> AgentResponse:
    """Summarize the LB signals into the canonical :class:`AgentResponse` — pure and PII-safe.

    Only **aggregates** cross the boundary: per-LB health states, a backend-edge count, and
    aggregate log metric values. No raw log body, no free-form string, and no credential is ever
    referenced. When ``available`` is ``False`` (the connector failed closed) the response surfaces
    the gap with zero confidence and no fabricated data.
    """
    findings = [f"lb {lb_id} aggregate health: {state.value}" for lb_id, state in sorted(
        aggregate.items()
    )]
    findings.append(f"backend-pool dependency edges: {len(edges)}")
    for log in logs:
        findings.append(f"lb {log.lb_id} {log.metric}: {log.value}")
    risks = [
        f"lb {lb_id} is {state.value}"
        for lb_id, state in sorted(aggregate.items())
        if state in (HealthState.down, HealthState.degraded)
    ]
    references = [to_source_reference(source, lb_id) for lb_id in sorted(aggregate)]
    confidence = 1.0 if available and (aggregate or edges or logs) else 0.0
    return AgentResponse(
        agentName=agent_name,
        taskType="lb-health-and-dependencies",
        inputSummary=(
            f"{source} read-only connector: {len(aggregate)} LB(s), {len(edges)} edge(s), "
            f"{len(logs)} aggregate log signal(s)"
        ),
        findings=findings,
        risks=risks,
        recommendations=[],
        sourceReferences=references,
        confidence=confidence,
        nextActions=[],
    )
