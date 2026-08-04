"""Pure signal-shaping for the platform's Log Analytics telemetry export (issue #86).

This module is **pure logic ⟂ I/O** (house rule): every function here takes the platform's
already-computed, in-boundary signals as shared Pydantic contracts (``ResourceNode`` / ``Finding``
from ``shared.contracts``, ``FetchResult`` from ``shared.connectors``) and returns typed,
**PII-free** row objects that match — exactly — the four custom Log Analytics tables the baseline
Grafana boards read (documented in ``infra/grafana/README.md``):

| Table                | Board-read columns                                                   |
|----------------------|----------------------------------------------------------------------|
| ``WpNodeState_CL``   | ``Workload_s``, ``State_s`` (up/degraded/down/unknown), ``TimeGenerated`` |
| ``WpSpof_CL``        | ``Workload_s`` (string), ``NodeRef_s`` (string, **opaque** node ref) |
| ``WpFinding_CL``     | ``Workload_s`` (string), ``BlastRadius_d`` (real), ``TimeGenerated`` |
| ``WpConnectorFetch_CL`` | ``Connector_s`` (string), ``Success_b`` (bool), ``TimeGenerated`` |

Guardrails realised here (the emit path only ever sees the output of these functions):

* **PII-free / opaque.** No raw resource id, node id, name, tag, config, or log body is ever placed
  in a row. ``NodeRef_s`` is a keyless, deterministic, non-reversible digest
  (:func:`opaque_node_ref`) so the raw node id never leaves. Only the aggregate schema fields + the
  mandatory ``TimeGenerated`` system column are emitted.
* **Fail closed.** A node with no positive health evidence maps to ``unknown`` — never a guessed
  ``up`` (guardrail #6). Anything that cannot be reduced to a safe, bounded row is dropped rather
  than emitted unbounded.

Because these are pure, they get fast, Azure-free unit tests. The Azure SDK / Logs Ingestion call
lives only at the thin edge client in :mod:`modules.telemetry_export.exporter`.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from shared.connectors import FetchResult
from shared.contracts import Finding, HealthState, ResourceNode, Severity

# Domain-separation prefix for the opaque node-ref digest. Mirrors the #78 opaque finding-id scheme
# (``modules.alerts.module.opaque_finding_id``) but is DEFINED HERE — module isolation forbids the
# telemetry_export module from importing the alerts module, and there is no shared opaque-node-ref
# helper to reuse. Bumping ``v1`` yields a different, non-colliding token space; keeping it stable
# keeps ``NodeRef_s`` deterministic so the SPOF board can ``dcount`` distinct nodes over time.
_NODE_REF_DOMAIN = b"wp-node-ref:v1|"

# Worst-severity → node health mapping, mirroring the platform's canonical rule (the web
# ``src/web/src/graph/health.ts`` derivation): critical/high ⇒ down, medium/low ⇒ degraded.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.info: 0,
    Severity.low: 1,
    Severity.medium: 2,
    Severity.high: 3,
    Severity.critical: 4,
}


def opaque_node_ref(node_id: str) -> str:
    """Opaque, keyless, deterministic, non-reversible token for a raw node id.

    ``WpSpof_CL.NodeRef_s`` must identify a single-point-of-failure node to the board WITHOUT ever
    emitting the raw Azure resource/node id (which is PII-adjacent estate topology). This digest is:

    * **keyless** — a plain domain-separated SHA-256, NO secret/HMAC key (keyless guardrail);
    * **deterministic/stable** — same node id ⇒ same token, so ``dcount(NodeRef_s)`` is meaningful
      and stable across export runs;
    * **non-reversible & PII-free** — a one-way digest; neither the node id nor any substring of it
      can appear in the 64-hex output;
    * **bounded & control-free** — always 64 lowercase hex chars.

    ``errors="surrogatepass"`` makes the encoding total for ANY ``str`` (even a lone surrogate that
    strict UTF-8 cannot encode), so hashing never raises — mirroring
    :func:`modules.alerts.module.opaque_finding_id`.
    """
    return hashlib.sha256(
        _NODE_REF_DOMAIN + node_id.encode("utf-8", errors="surrogatepass")
    ).hexdigest()


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    """Render a datetime as an ISO-8601 UTC string the Logs Ingestion API accepts for TimeGenerated.

    A naive datetime is assumed UTC (the platform stamps ``createdAt`` with ``datetime.now(UTC)``);
    an aware datetime is normalised to UTC so the emitted ``TimeGenerated`` is unambiguous.
    """
    aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return aware.astimezone(UTC).isoformat()


# --------------------------------------------------------------------------------------
# Typed, PII-free export rows. Each carries snake_case, fully-typed fields and knows how to render
# itself as the exact Log Analytics custom-table column dict (``*_s`` string / ``*_d`` real /
# ``*_b`` bool + the mandatory ``TimeGenerated`` system column). Keeping the column-name mapping in
# one explicit, unit-tested method means the schema contract can never silently drift.
# --------------------------------------------------------------------------------------
class WpNodeStateRow(BaseModel):
    """One row for ``WpNodeState_CL`` — a single node's health state, labelled by workload."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    workload: str
    state: HealthState
    time_generated: datetime = Field(default_factory=_utcnow)

    def to_la_columns(self) -> dict[str, object]:
        return {
            "Workload_s": self.workload,
            "State_s": self.state.value,
            "TimeGenerated": _iso(self.time_generated),
        }


class WpSpofRow(BaseModel):
    """One row for ``WpSpof_CL`` — an opaque ref to a single-point-of-failure node, per workload.

    ``TimeGenerated`` is the mandatory Log Analytics system column (the SPOF board filters on the
    dashboard time range); the board itself reads only ``Workload_s`` + ``NodeRef_s``.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    workload: str
    node_ref: str = Field(description="Opaque node ref (see opaque_node_ref) — never a raw id")
    time_generated: datetime = Field(default_factory=_utcnow)

    def to_la_columns(self) -> dict[str, object]:
        return {
            "Workload_s": self.workload,
            "NodeRef_s": self.node_ref,
            "TimeGenerated": _iso(self.time_generated),
        }


class WpFindingRow(BaseModel):
    """One row for ``WpFinding_CL`` — a finding's blast radius, labelled by workload."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    workload: str
    blast_radius: float = Field(ge=0.0)
    time_generated: datetime = Field(default_factory=_utcnow)

    def to_la_columns(self) -> dict[str, object]:
        return {
            "Workload_s": self.workload,
            "BlastRadius_d": self.blast_radius,
            "TimeGenerated": _iso(self.time_generated),
        }


class WpConnectorFetchRow(BaseModel):
    """One row for ``WpConnectorFetch_CL`` — a connector's fetch success at a point in time."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    connector: str
    success: bool
    time_generated: datetime = Field(default_factory=_utcnow)

    def to_la_columns(self) -> dict[str, object]:
        return {
            "Connector_s": self.connector,
            "Success_b": self.success,
            "TimeGenerated": _iso(self.time_generated),
        }


# --------------------------------------------------------------------------------------
# Pure shaping functions.
# --------------------------------------------------------------------------------------
def _is_failure(finding: Finding) -> bool:
    """Fail-closed failure test: ONLY ``passed is False`` counts.

    A ``passed`` of ``None`` (unknown/observation) is NOT treated as a failure.
    """
    return finding.passed is False


def _worst_failing_severity(findings: Sequence[Finding]) -> Severity | None:
    """The highest severity among failing findings, or ``None`` if none are failing."""
    worst: Severity | None = None
    for finding in findings:
        if not _is_failure(finding):
            continue
        if worst is None or _SEVERITY_RANK[finding.severity] > _SEVERITY_RANK[worst]:
            worst = finding.severity
    return worst


def _state_for_node(findings: Sequence[Finding]) -> HealthState:
    """Derive one node's health state from its findings — fail closed to ``unknown``.

    * any failing finding ⇒ ``down`` (worst severity high/critical) else ``degraded``;
    * else, positive health evidence (at least one ``passed is True`` finding) ⇒ ``up``;
    * else (no findings, or only ``unknown``/observation findings) ⇒ ``unknown`` — we never GUESS
      ``up`` without evidence (guardrail #6).
    """
    worst = _worst_failing_severity(findings)
    if worst is not None:
        if _SEVERITY_RANK[worst] >= _SEVERITY_RANK[Severity.high]:
            return HealthState.down
        return HealthState.degraded
    if any(f.passed is True for f in findings):
        return HealthState.up
    return HealthState.unknown


def shape_node_states(
    workload: str,
    nodes: Sequence[ResourceNode],
    findings: Sequence[Finding],
    *,
    at: datetime | None = None,
) -> list[WpNodeStateRow]:
    """Shape ``WpNodeState_CL`` rows: one per estate node, its state derived from its findings.

    PII-free: a row carries ONLY the workload label + the derived state string (never the node id).
    ``at`` stamps ``TimeGenerated`` (defaults to now, UTC) so a run's node states share one instant.
    """
    stamp = at if at is not None else _utcnow()
    by_node: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.nodeId is None:
            continue
        by_node.setdefault(finding.nodeId, []).append(finding)
    return [
        WpNodeStateRow(
            workload=workload,
            state=_state_for_node(by_node.get(node.id, [])),
            time_generated=stamp,
        )
        for node in nodes
    ]


def shape_spofs(
    workload: str,
    findings: Sequence[Finding],
    *,
    at: datetime | None = None,
) -> list[WpSpofRow]:
    """Shape ``WpSpof_CL`` rows from single-point-of-failure findings — node id **opaqued**.

    A SPOF is a failing finding that names a node and downs at least one dependent node
    (``blastRadius >= 1``) — the shape the dependency_graph module emits. The node id is replaced by
    :func:`opaque_node_ref` so no raw id is exported; rows are de-duplicated by opaque ref so a node
    flagged by several findings counts once.
    """
    stamp = at if at is not None else _utcnow()
    rows: list[WpSpofRow] = []
    seen: set[str] = set()
    for finding in findings:
        if not _is_failure(finding) or finding.nodeId is None or finding.blastRadius < 1:
            continue
        ref = opaque_node_ref(finding.nodeId)
        if ref in seen:
            continue
        seen.add(ref)
        rows.append(WpSpofRow(workload=workload, node_ref=ref, time_generated=stamp))
    return rows


def shape_findings(
    workload: str,
    findings: Sequence[Finding],
) -> list[WpFindingRow]:
    """Shape ``WpFinding_CL`` rows: the blast radius of each **failing** finding (an active risk).

    Fail-closed risk semantics: only ``passed is False`` findings are emitted, so the blast-radius
    distribution / peak boards reflect surfaced risk — not passing checks or unknown observations.
    ``TimeGenerated`` uses the finding's own ``createdAt`` (real provenance time). PII-free: only
    the workload label + the numeric blast radius are emitted (no node id, title, or detail).
    """
    return [
        WpFindingRow(
            workload=workload,
            blast_radius=float(max(finding.blastRadius, 0)),
            time_generated=finding.createdAt,
        )
        for finding in findings
        if _is_failure(finding)
    ]


def shape_connector_fetch(
    connector: str,
    result: FetchResult,
    *,
    at: datetime | None = None,
) -> WpConnectorFetchRow:
    """Shape a single ``WpConnectorFetch_CL`` row from a connector's fetch envelope.

    Reads ONLY the PII-free ``FetchResult.available`` flag (never ``raw`` payloads or the ``error``
    class name), so no fetched content or boundary detail can leak into telemetry. ``connector`` is
    a low-cardinality connector name (e.g. ``"system_pulse"``, ``"azure_monitor"``).
    """
    return WpConnectorFetchRow(
        connector=connector,
        success=result.available,
        time_generated=at if at is not None else _utcnow(),
    )


def shape_connector_fetches(
    results: Mapping[str, FetchResult],
    *,
    at: datetime | None = None,
) -> list[WpConnectorFetchRow]:
    """Shape ``WpConnectorFetch_CL`` rows for a batch of ``{connector_name: FetchResult}``."""
    stamp = at if at is not None else _utcnow()
    return [
        shape_connector_fetch(connector, result, at=stamp)
        for connector, result in results.items()
    ]


__all__ = [
    "WpConnectorFetchRow",
    "WpFindingRow",
    "WpNodeStateRow",
    "WpSpofRow",
    "opaque_node_ref",
    "shape_connector_fetch",
    "shape_connector_fetches",
    "shape_findings",
    "shape_node_states",
    "shape_spofs",
]
