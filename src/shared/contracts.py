"""Shared domain contracts for the Workloads Platform.

Every analytical/agent output and every cross-boundary payload is a Pydantic model defined here.
Do not fork these shapes in modules — import them. See `.github/copilot-instructions.md`.
"""
from __future__ import annotations

import json
import unicodedata
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _utcnow() -> datetime:
    return datetime.now(UTC)


# --------------------------------------------------------------------------------------
# AgentResponse — the canonical shape every analytical/agent task returns.
# --------------------------------------------------------------------------------------
class SourceReference(BaseModel):
    """Provenance for a finding — always cite evidence (fail-closed, auditable)."""

    kind: str = Field(description="resource | metric | log | pack | connector")
    id: str = Field(description="Azure resource id, metric name, pack id, etc.")
    detail: str | None = None


# The supported provenance kinds. A finding's evidence is only *attributable* when at least one of
# its references names a known kind AND a non-blank id (see ``shared.provenance``); a present-but-
# empty/unknown reference does not satisfy the provenance guarantee (fail closed).
SOURCE_REFERENCE_KINDS: frozenset[str] = frozenset(
    {"resource", "metric", "log", "pack", "connector"}
)


class AgentResponse(BaseModel):
    """Canonical analytical output. Keep field names stable across the platform."""

    agentName: str
    taskType: str
    inputSummary: str
    findings: list[str] = Field(default_factory=list)
    risks: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    sourceReferences: list[SourceReference] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    nextActions: list[str] = Field(default_factory=list)
    generatedAt: datetime = Field(default_factory=_utcnow)


# --------------------------------------------------------------------------------------
# Packs — the five signed, versioned content types.
# --------------------------------------------------------------------------------------
class PackType(StrEnum):
    workload = "workload"
    rule = "rule"
    telemetry = "telemetry"
    dependency = "dependency"
    ops = "ops"


class PackSignature(BaseModel):
    """Detached, asymmetric signature envelope over a pack's *canonical bytes* (issue #35).

    Self-describing and provenance-bearing so verification needs no external state: it names the
    ``algorithm``, carries the base64 detached ``signature`` over
    :func:`packs_engine.canonical.canonical_bytes`, a ``key_id`` hint identifying the signing key
    (never a secret), and the ``canonical_digest`` (SHA-256 hex over the same canonical bytes) it
    covers — binding the signature to a specific pack version identity so a tampered pack is
    rejected fail-closed.

    This is **deliberately distinct** from the legacy HMAC :attr:`PackManifest.signature` (a
    symmetric hex MAC over the body-only sha256): the two mechanisms are independent gates and are
    never conflated. Like ``sha256``/``signature``, this envelope is a *volatile integrity* field
    excluded from version identity (see ``EXCLUDED_MANIFEST_FIELDS``) so signing a pack does not
    change its version.
    """

    model_config = ConfigDict(extra="forbid")

    algorithm: str = Field(description="Signature algorithm identifier, e.g. 'ed25519'")
    signature: str = Field(description="Base64 detached signature over canonical_bytes(pack)")
    key_id: str = Field(description="Key id / hint identifying the signing key (never a secret)")
    canonical_digest: str = Field(
        description="SHA-256 hex over canonical_bytes(pack) this signature covers (identity bind)"
    )


class PackManifest(BaseModel):
    """Metadata + integrity for a signed content pack."""

    id: str
    type: PackType
    name: str
    version: str = Field(description="Semantic version, e.g. 1.2.0")
    targets: list[str] = Field(
        default_factory=list, description="Workload kinds this applies to (epic, sap, bespoke, ...)"
    )
    sha256: str | None = Field(default=None, description="Content hash; verified before execute")
    signature: str | None = Field(default=None, description="Legacy HMAC signature over sha256")
    pack_signature: PackSignature | None = Field(
        default=None,
        description=(
            "Detached asymmetric signature over canonical bytes (issue #35). Independent of and "
            "kept separate from the legacy HMAC `signature`; excluded from version identity."
        ),
    )
    author: str = "microsoft"


# --------------------------------------------------------------------------------------
# Module manifest / scaling — what makes modules independently scalable.
# --------------------------------------------------------------------------------------
class ModuleKind(StrEnum):
    service = "service"   # long-running ACA app
    job = "job"           # ACA Job (batch, scale-to-zero)


class ScaleTrigger(BaseModel):
    type: str = Field(description="KEDA scaler: azure-queue | cron | cpu | memory | custom")
    metadata: dict[str, str] = Field(default_factory=dict)


class ScaleProfile(BaseModel):
    kind: ModuleKind
    minReplicas: int = 0
    maxReplicas: int = 10
    triggers: list[ScaleTrigger] = Field(default_factory=list)
    cpu: float = 0.5
    memoryGi: float = 1.0


class ModuleManifest(BaseModel):
    """Declares a capability module and how it scales independently."""

    name: str
    displayName: str
    kind: ModuleKind
    enabled: bool = True
    consumes: list[PackType] = Field(default_factory=list)
    produces: list[str] = Field(default_factory=list)
    scaleProfile: ScaleProfile


# --------------------------------------------------------------------------------------
# Domain models — estate, dependency graph, findings.
# --------------------------------------------------------------------------------------
class ResourceNode(BaseModel):
    """A discovered element of the estate, classified into workload/tier/role."""

    id: str = Field(description="Azure resource id or logical node id")
    name: str
    type: str = Field(description="Azure resource type or logical type")
    workload: str | None = None
    tier: str | None = None
    role: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)


class EdgeType(StrEnum):
    depends_on = "depends_on"
    load_balances = "load_balances"
    replicates_to = "replicates_to"
    routes_to = "routes_to"


class DependencyEdge(BaseModel):
    """Typed dependency between two nodes. Drives smart blast radius."""

    source: str = Field(description="node id that depends")
    target: str = Field(description="node id it depends on")
    type: EdgeType = EdgeType.depends_on
    redundant: bool = Field(
        default=False,
        description="True if source has redundant peers for target (loss is degraded not down)",
    )
    origin: str = Field(default="auto", description="auto | pack:<id> | user")


class HealthState(StrEnum):
    up = "up"
    degraded = "degraded"
    down = "down"
    unknown = "unknown"


class Severity(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Finding(BaseModel):
    """A single PASS/FAIL/observation with provenance and blast-radius context."""

    id: str
    module: str
    title: str
    passed: bool | None = None
    severity: Severity = Severity.info
    nodeId: str | None = None
    blastRadius: int = Field(default=0, description="Count of nodes that go down if nodeId fails")
    evidence: list[SourceReference] = Field(default_factory=list)
    packId: str | None = None
    packVersion: str | None = None
    detail: str | None = None
    createdAt: datetime = Field(default_factory=_utcnow)


class WorkloadGraph(BaseModel):
    """The estate as nodes + typed edges. Consumed by blast-radius analysis."""

    nodes: list[ResourceNode] = Field(default_factory=list)
    edges: list[DependencyEdge] = Field(default_factory=list)


class ModuleRunResult(BaseModel):
    """Uniform envelope a module returns to the API core.

    ``estate`` and ``graph`` are optional typed carriers so a run's outputs can be handed to the
    API (the single writer) for persistence without the module writing state itself. Modules
    populate them in their own issues (#2/#3/#4); the core just persists whatever is present.
    """

    module: str
    ok: bool = True
    findings: list[Finding] = Field(default_factory=list)
    estate: list[ResourceNode] | None = Field(
        default=None,
        description=(
            "Estate nodes produced by this run (persisted by the API single writer). "
            "None = this run did not touch the estate; an empty list explicitly CLEARS it."
        ),
    )
    graph: WorkloadGraph | None = Field(
        default=None,
        description=(
            "Dependency graph produced by this run (persisted by the API single writer). "
            "None = this run did not touch the graph."
        ),
    )
    response: AgentResponse | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class DriftReport(BaseModel):
    """Drift read model: current findings vs the previous snapshot (drives #5 reassessments).

    A finding is "failing" when ``passed is False`` (fail-closed — unknown is not a failure).
    Estate drift is expressed as node-id deltas between the last snapshot and now.
    """

    workload: str
    newFailures: list[Finding] = Field(
        default_factory=list, description="Failing now, not failing in the previous snapshot"
    )
    recovered: list[Finding] = Field(
        default_factory=list, description="Failing in the previous snapshot, no longer failing"
    )
    stillFailing: list[Finding] = Field(
        default_factory=list, description="Failing in both the previous snapshot and now"
    )
    addedNodes: list[str] = Field(
        default_factory=list,
        description="Estate node ids present now but absent from the previous snapshot",
    )
    removedNodes: list[str] = Field(
        default_factory=list,
        description="Estate node ids present in the previous snapshot but gone now",
    )


# --------------------------------------------------------------------------------------
# Audit trail — tamper-evident, append-only record of consequential actions (issue #59).
#
# An ``AuditEvent`` records WHO (a non-PII principal id), did WHAT (``action``), to WHICH subject,
# with WHICH pack + version, and the RESULT (success/failure) at a timestamp. It is deliberately
# minimal and **PII-free by construction**: every id-bearing field is validated to reject emails,
# names, whitespace/free-text (log bodies), and Azure resource *paths* (``/subscriptions/`` …).
# Persisted append-only through the SAME state layer as every other read model (see
# ``shared.state``), so it works on BOTH the local and Azure backends. The model is ``frozen`` so a
# constructed event cannot be mutated in place, reinforcing the append-only, tamper-evident intent.
# --------------------------------------------------------------------------------------
class AuditAction(StrEnum):
    """The consequential actions the platform records in its audit trail."""

    pack_import = "pack.import"
    pack_verify = "pack.verify"
    pack_assign = "pack.assign"
    run_executed = "run.executed"
    finding_emitted = "finding.emitted"
    module_enabled = "module.enabled"
    module_disabled = "module.disabled"


class AuditResult(StrEnum):
    """The outcome of an audited action — fail-closed callers record ``failure`` on any error."""

    success = "success"
    failure = "failure"


# Substrings that betray PII, a log body, or an Azure resource *path*, and must never leak into an
# audit record. Matched case-insensitively. ``@`` catches emails; the resource-path markers catch a
# subscription/resource-group/provider id being smuggled into a free-text field.
_AUDIT_FORBIDDEN_SUBSTRINGS = ("/subscriptions/", "/resourcegroups/", "/providers/", "@")
_AUDIT_MAX_LEN = 256


def is_audit_safe(value: str) -> bool:
    """Return ``True`` iff ``value`` is a bounded, PII-free identifier fit for an audit record.

    Fail-closed: the value is FIRST NFKC-normalized (so Unicode compatibility forms — e.g. a
    fullwidth ``＠`` or fullwidth ``／`` — canonicalize to their ASCII equivalents and cannot slip a
    disguised email / resource *path* past the checks), then rejects the empty string, anything
    longer than :data:`_AUDIT_MAX_LEN`, any whitespace or Unicode ``Other`` (``C*``) character, and
    any of the :data:`_AUDIT_FORBIDDEN_SUBSTRINGS` (emails and Azure resource *paths*). A
    non-``str`` is never safe.

    The ``C*`` rejection covers the WHOLE "Other" group, not just controls: ``Cc`` (C0 0x00-0x1F,
    DEL 0x7F, C1 0x80-0x9F), ``Cf`` (format chars — e.g. U+202E RIGHT-TO-LEFT OVERRIDE, U+200B
    ZERO WIDTH SPACE, U+200E/200F LRM/RLM, U+FEFF BOM — which SURVIVE NFKC and would otherwise
    persist invisibly / deceptively), ``Cs`` (surrogates), ``Co`` (private-use), and ``Cn``
    (unassigned). None of these are legitimate in an audit identifier. Ordinary letters/marks/
    punctuation are untouched, so accented text (e.g. ``café`` = ``Ll``) still passes.
    """
    if not isinstance(value, str):
        return False
    value = unicodedata.normalize("NFKC", value)
    if not value or len(value) > _AUDIT_MAX_LEN:
        return False
    if any(ch.isspace() or unicodedata.category(ch)[0] == "C" for ch in value):
        return False
    lowered = value.lower()
    return not any(marker in lowered for marker in _AUDIT_FORBIDDEN_SUBSTRINGS)


def _assert_audit_safe(value: str, *, field: str) -> str:
    """Return the NFKC-canonical ``value`` if audit-safe, else raise ``ValueError`` (fail closed).

    The value is NFKC-normalized and the normalized (canonical) form is what gets persisted, so a
    later read can never see an un-normalized Unicode-compatibility variant of a field. The error
    names only the offending *field* — never the rejected value — so a validation failure cannot
    itself leak the PII/free-text it just refused.
    """
    normalized = unicodedata.normalize("NFKC", value) if isinstance(value, str) else value
    if not is_audit_safe(normalized):
        raise ValueError(
            f"AuditEvent.{field} is not a bounded, PII-free identifier (fail closed)"
        )
    return normalized


class AuditEvent(BaseModel):
    """One append-only, PII-free audit record of a consequential action.

    Every id-bearing field is validated PII-free at construction (see :func:`is_audit_safe`), so a
    record carrying an email, a name, a log body, or an Azure resource *path* can never be built —
    the audit surface fails closed rather than persisting sensitive data. ``frozen`` makes the
    record immutable once created (tamper-evident / append-only in spirit); the storage layer
    enforces append-only at rest.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(default_factory=lambda: uuid4().hex, description="Opaque unique event id")
    actor: str = Field(
        description="Non-PII principal id (object id / principal id) — never a name or email"
    )
    action: AuditAction
    subject: str = Field(
        description="Non-PII id of the acted-on subject (module name, pack id, workload id)"
    )
    packId: str | None = Field(default=None, description="Pack id involved, if any")
    packVersion: str | None = Field(default=None, description="Pack version involved, if any")
    result: AuditResult
    recordedAt: datetime = Field(default_factory=_utcnow)
    # Tamper-evidence (issue #59, hash chaining). Populated by the storage layer at append time —
    # NOT by callers — so they are excluded from :meth:`canonical_bytes` (an event's identity is its
    # own fields, independent of where it lands in the chain). ``prevHash`` links to the previous
    # entry's ``entryHash`` (or the genesis anchor for the first event); ``entryHash`` is the
    # SHA-256 over this event's canonical bytes concatenated with ``prevHash``.
    prevHash: str | None = Field(default=None, description="entryHash of the previous chain entry")
    entryHash: str | None = Field(default=None, description="SHA-256 chain hash of this entry")

    @field_validator("id", "actor", "subject")
    @classmethod
    def _validate_required_ids(cls, value: str, info: Any) -> str:
        return _assert_audit_safe(value, field=str(info.field_name))

    @field_validator("packId", "packVersion")
    @classmethod
    def _validate_optional_ids(cls, value: str | None, info: Any) -> str | None:
        if value is None:
            return None
        return _assert_audit_safe(value, field=str(info.field_name))

    def canonical_bytes(self) -> bytes:
        """Return a stable UTF-8 serialization of the event's identity fields (excluding hashes).

        Deterministic by construction — recursively sorted keys, compact separators, and a
        JSON-mode dump (so ``recordedAt`` is a fixed ISO-8601 string) — mirroring the canonical
        serialization used for pack version identity (``packs_engine.canonical.canonical_bytes``)
        and graph revisions (``shared.blast_radius.graph_revision``). ``prevHash``/``entryHash`` are
        excluded so the hash covers only the logical event, never the chain linkage itself.
        """
        payload = self.model_dump(mode="json", exclude={"prevHash", "entryHash"})
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


# --------------------------------------------------------------------------------------
# Self-observability — readiness, internal metrics (issue #60).
#
# These are the API's *own* health/metrics contracts, distinct from the customer-workload
# ``HealthState`` above. They carry ONLY low-cardinality names and numeric measures — never a
# secret, connection string, resource id, or any PII (see ``shared.observability``).
# --------------------------------------------------------------------------------------
class DependencyStatus(BaseModel):
    """Readiness of a single platform dependency (state store, packs engine, edge clients).

    ``detail`` is a short, bounded, non-sensitive note (e.g. ``"reachable"``, ``"absent"``,
    ``"probe error"``) — never a secret, connection string, resource id, or PII.
    """

    name: str = Field(description="Low-cardinality dependency name, e.g. 'state_store'")
    ok: bool = Field(description="True only when the dependency was positively verified ready")
    detail: str | None = Field(
        default=None, description="Short, non-sensitive status note (no secrets/PII)"
    )


class ReadinessReport(BaseModel):
    """Aggregated readiness across the platform's dependencies (fail-closed).

    ``ready`` is True only when EVERY probed dependency reports ``ok`` (and at least one was
    probed). An errored or unknown probe leaves its ``ok`` False, which forces ``ready`` False —
    the readiness endpoint then answers HTTP 503. Liveness is a separate, dependency-free signal.
    """

    ready: bool = Field(description="Overall readiness; True only if all dependencies are ok")
    dependencies: list[DependencyStatus] = Field(default_factory=list)


class MetricSample(BaseModel):
    """One counter reading: a name, bounded low-cardinality labels, and a non-negative count."""

    name: str
    labels: dict[str, str] = Field(default_factory=dict)
    value: int = Field(ge=0)


class DurationSample(BaseModel):
    """Aggregated duration stats for a named, labelled measure (milliseconds).

    Stores only aggregates (count + sum + min/max), never per-event rows, so nothing
    request-identifying or PII-bearing is retained.
    """

    name: str
    labels: dict[str, str] = Field(default_factory=dict)
    count: int = Field(ge=0)
    totalMs: float = Field(ge=0.0)
    minMs: float = Field(ge=0.0)
    maxMs: float = Field(ge=0.0)


class MetricsSnapshot(BaseModel):
    """Point-in-time, vendor-neutral snapshot of the in-process metrics registry.

    Deliberately JSON (not Prometheus text) and keyless. Labels are bounded and low-cardinality
    (module name + outcome only); there are no resource ids, connection strings, or PII.
    """

    counters: list[MetricSample] = Field(default_factory=list)
    durations: list[DurationSample] = Field(default_factory=list)
