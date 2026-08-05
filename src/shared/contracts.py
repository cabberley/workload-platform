"""Shared domain contracts for the Workloads Platform.

Every analytical/agent output and every cross-boundary payload is a Pydantic model defined here.
Do not fork these shapes in modules — import them. See `.github/copilot-instructions.md`.
"""
from __future__ import annotations

import json
import unicodedata
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import Enum, StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


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


class TrustedPublicKey(BaseModel):
    """One pinned Ed25519 PUBLIC key in the trust bundle (issue #89) — provenance, never a secret.

    The customer platform is **verification-only and keyless**: it holds Microsoft's distributed
    PUBLIC keys and NEVER any private key. The verifier selects the entry whose ``key_id`` matches a
    pack signature's ``key_id`` (:class:`PackSignature`) and checks the detached signature with it.
    Rotation = publish a new ``key_id`` + ``public_key`` into the bundle; retire by removing it.
    """

    model_config = ConfigDict(extra="forbid")

    key_id: str = Field(description="Key id matching PackSignature.key_id (never a secret)")
    algorithm: str = Field(default="ed25519", description="Signature algorithm; only 'ed25519'")
    public_key: str = Field(description="Base64 raw 32-byte Ed25519 PUBLIC key (never a secret)")


class TrustBundle(BaseModel):
    """The pinned set of trusted Ed25519 PUBLIC keys used to verify imported packs (issue #89).

    A bundled, in-boundary trust root: Microsoft signs packs **OFFLINE**; this platform only
    **VERIFIES** with the public keys pinned here. **Fail-closed by construction** — an EMPTY bundle
    trusts nothing, so every pack import is rejected until real keys are pinned. Distribution today
    is a bundled file loaded at composition; a future "bundle updated via signed pack-registry
    metadata" path is a clean extension (a documented hook — remote fetch is NOT built here).
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=1, description="Bundle format version")
    keys: list[TrustedPublicKey] = Field(
        default_factory=list, description="Pinned trusted public keys, keyed by key id"
    )


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


class ProvenanceKind(StrEnum):
    """How a :class:`Finding` is attributed — the explicit provenance marker (guardrail #8, #83).

    Distinguishes the two legitimate kinds of finding so provenance is a declared, enforced fact
    rather than an implicit ``packId is None`` guess:

    * ``pack`` — derived from a signed, versioned pack (Rule / Telemetry / …). MUST carry a
      non-blank ``packId`` **and** ``packVersion`` (cite the pack + version).
    * ``structural`` — computed by the platform itself from the estate / dependency graph (e.g. a
      single-point-of-failure), so it legitimately has **no** pack. MUST name one of the
      enumerated :class:`StructuralFindingKind` values, so pack-less findings are an explicit,
      allowlisted set — never an accidental omission.
    """

    pack = "pack"
    structural = "structural"


class StructuralFindingKind(StrEnum):
    """Allowlist of platform-computed (pack-less) finding kinds (guardrail #8, issue #83).

    A structural finding is derived by the platform itself, not from any signed pack, so it carries
    no ``packId`` / ``packVersion`` by design. Only these enumerated kinds may be marked
    ``ProvenanceKind.structural``; every other finding must be pack-derived. Add a member here (and
    to the ADR) when a genuinely new platform-internal finding kind is introduced — never widen the
    set implicitly.
    """

    spof = "spof"  # dependency & blast-radius single point of failure (dependency_graph module)


# Single source of truth (issue #83, guardrail #8): each structural finding kind is emitted by
# exactly one platform module, so a structural/pack-less finding can only be attributed to the
# module actually authorized to compute it. The ``_enforce_provenance`` validator rejects a
# structural finding whose ``module`` does not match its kind's authorized emitter, AND rejects any
# ``StructuralFindingKind`` missing from this map (fail closed — a new kind added without an emitter
# mapping is invalid until wired in). NOTE (residual): ``Finding.module`` is *self-declared* on this
# branch; binding it to an AUTHENTICATED per-component caller identity is the #64 (Entra auth) +
# #79 (per-component identities) follow-up — see ADR 0013.
STRUCTURAL_FINDING_EMITTERS: dict[StructuralFindingKind, str] = {
    StructuralFindingKind.spof: "dependency_graph",
}


class Finding(BaseModel):
    """A single PASS/FAIL/observation with provenance and blast-radius context.

    Provenance is a **fail-closed, enforced invariant** (issue #83): a finding is valid ONLY if it
    is either (a) ``provenance=pack`` with BOTH ``packId`` and ``packVersion`` present/non-blank, or
    (b) ``provenance=structural`` naming an allowlisted :class:`StructuralFindingKind`. Neither
    (missing pack id/version and not explicitly structural) raises at construction — no silent
    default hides missing provenance. This complements issue #59's *evidence* guard
    (``shared.provenance``): #59 requires each finding cite ≥1 attributable ``SourceReference``,
    while #83 requires it declare and prove its pack-vs-structural attribution kind — the two are
    orthogonal (a pack-derived finding can still fail the evidence guard, and vice-versa).

    ``validate_assignment=True`` (issue #83): the provenance invariant is re-run on *every*
    attribute assignment, not only at construction, so mutating a provenance field into an invalid
    combination (e.g. ``finding.packId = None`` on a pack finding) raises immediately rather than
    silently producing an invalid, persisted finding.
    """

    model_config = ConfigDict(validate_assignment=True)

    id: str
    module: str
    title: str
    passed: bool | None = None
    severity: Severity = Severity.info
    nodeId: str | None = None
    blastRadius: int = Field(default=0, description="Count of nodes that go down if nodeId fails")
    evidence: list[SourceReference] = Field(default_factory=list)
    provenance: ProvenanceKind = Field(
        default=ProvenanceKind.pack,
        description="Explicit attribution marker: pack-derived (default) or structural/derived.",
    )
    packId: str | None = None
    packVersion: str | None = None
    structuralKind: StructuralFindingKind | None = Field(
        default=None,
        description="Set (from the allowlist) iff provenance=structural; None for pack findings.",
    )
    detail: str | None = None
    createdAt: datetime = Field(default_factory=_utcnow)

    @model_validator(mode="after")
    def _enforce_provenance(self) -> Finding:
        """Fail closed unless provenance is complete (pack id+version) or explicitly structural."""
        if self.provenance is ProvenanceKind.pack:
            if not (self.packId and self.packId.strip()):
                raise ValueError(
                    f"pack-derived Finding {self.id!r} must carry a non-blank packId "
                    "(guardrail #8: cite the pack + version); mark it structural if it is "
                    "platform-computed"
                )
            if not (self.packVersion and self.packVersion.strip()):
                raise ValueError(
                    f"pack-derived Finding {self.id!r} must carry a non-blank packVersion "
                    "(guardrail #8: cite the pack + version)"
                )
            if self.structuralKind is not None:
                raise ValueError(
                    f"pack-derived Finding {self.id!r} must not declare a structuralKind"
                )
        else:  # ProvenanceKind.structural
            if self.structuralKind is None:
                raise ValueError(
                    f"structural Finding {self.id!r} must name an allowlisted structuralKind "
                    f"(one of {[k.value for k in StructuralFindingKind]}); a pack-less finding "
                    "must be an explicit, enumerated platform-internal kind"
                )
            if self.packId is not None or self.packVersion is not None:
                raise ValueError(
                    f"structural Finding {self.id!r} must not carry packId/packVersion "
                    "(it is platform-computed, not pack-derived); both must be exactly None, "
                    "not merely blank"
                )
            authorized_emitter = STRUCTURAL_FINDING_EMITTERS.get(self.structuralKind)
            if authorized_emitter is None:
                # Fail closed: a StructuralFindingKind with no authorized-emitter mapping is not
                # yet a legitimate structural kind (adding a kind without wiring its emitter must
                # never silently pass). Keep STRUCTURAL_FINDING_EMITTERS exhaustive.
                raise ValueError(
                    f"structural Finding {self.id!r} declares structuralKind "
                    f"{self.structuralKind.value!r}, which has no authorized emitter module "
                    "(guardrail #8: pack-less structural findings must map to an authorized "
                    "platform emitter); refusing to accept (fail closed)"
                )
            if self.module != authorized_emitter:
                raise ValueError(
                    f"structural Finding {self.id!r} of kind {self.structuralKind.value!r} may "
                    f"only be emitted by module {authorized_emitter!r}, not {self.module!r} "
                    "(guardrail #8: structural provenance is bound to its authorized emitter); "
                    "refusing to accept (fail closed)"
                )
        return self


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


# The placeholder a value is coerced to when it cannot be *proven* PII-free-and-bounded on egress.
# Egress redaction reuses the SAME sanitized-string gate that guards audit subjects/finding ids
# (:func:`is_audit_safe`) — it does NOT fork a second notion of "safe" — so a value only survives
# unredacted when it is a bounded, PII-free identifier; anything else becomes this constant.
REDACTED = "[redacted]"


def redact_value(value: Any) -> str:
    """PURE egress redaction: return the NFKC-canonical ``value`` iff provably PII-free, else drop.

    Reuses the platform's single sanitized-string gate (:func:`is_audit_safe`) so a free-form value
    that could carry PII, a log body, an Azure resource *path*, an email, control/format characters,
    or is oversized is coerced to :data:`REDACTED` rather than echoed. A bounded, PII-free
    identifier (e.g. ``"discovery"``, ``"ok"``, ``"production"``) passes through as its canonical
    form. Deterministic and I/O-free so it can run inside a Pydantic validator at the serialization
    boundary — never echoing caller-supplied free-form text unredacted.
    """
    if not isinstance(value, str):
        return REDACTED
    normalized = unicodedata.normalize("NFKC", value)
    return normalized if is_audit_safe(normalized) else REDACTED


# The EXACT platform/module-DEFINED schema field names that may appear as mapping KEYS inside
# ``ModuleRunResult.extra`` and its nested ``model_dump`` structures. This is a strict, exhaustive
# ALLOW-LIST derived from the fixed keys the modules write (grep ``extra=`` under ``src/modules/*``)
# plus the schema field names of every model those modules ``model_dump`` INTO ``extra``
# (``DriftReport`` / ``Finding`` / ``SourceReference`` / ``AgentResponse``). A key survives egress
# ONLY when it is an exact member here: default-DENY. A "structurally valid" token proves NOTHING —
# an SSN ``123-45-6789`` is structurally valid — so a customer-/workload-DERIVED key (e.g. the
# per-scope ``extra.drift.<scope>`` workload id, an ``emittedByStream`` stream name) is NOT in this
# set and is redacted to a positional placeholder. VALUES are still redacted by
# :func:`redact_tree`'s leaf rules regardless of whether the key survives.
PLATFORM_SAFE_STRUCTURAL_KEYS: frozenset[str] = frozenset(
    {
        # reassessments.module — extra + its nested ``summary`` dict
        "summary", "drift", "cadence", "workloads",
        "newFailures", "recovered", "stillFailing", "addedNodes", "removedNodes",
        # dependency_graph.module
        "topSpofs", "unresolvedMembers",
        # quality_checks.module / aiops.module
        "surfacedNotes",
        # telemetry_export.module
        "configured", "emittedByStream", "emitted", "errors",
        # discovery.module
        "nodeCount", "classifiedCount", "skippedRows",
        # aiops.module
        "rca", "sourcesAvailable", "sourcesUnavailable", "sourcesPartial", "packSources",
        # alerts.module
        "notifications",
        # DriftReport schema fields (``extra.drift.<scope>`` = DriftReport.model_dump)
        "workload",
        # Finding schema fields (nested in newFailures/recovered/stillFailing + rca sourceRefs)
        "id", "module", "title", "passed", "severity", "nodeId", "blastRadius", "evidence",
        "packId", "packVersion", "detail", "createdAt",
        # SourceReference schema fields
        "kind",
        # AgentResponse schema fields (aiops ``rca`` = list of AgentResponse.model_dump)
        "agentName", "taskType", "inputSummary", "findings", "risks", "recommendations",
        "sourceReferences", "confidence", "nextActions", "generatedAt",
    }
)

# Tag KEYS the PLATFORM itself writes and whose VALUES are therefore platform-controlled (not
# customer free-form) and may egress verbatim. This is an explicit ALLOW-LIST: the default is to
# redact every customer tag value. The platform does not currently stamp any resource tag of its
# own (discovered ``ResourceNode.tags`` are ALL customer-authored Azure tags), so this is
# intentionally EMPTY — every tag value is redacted. Add a key here ONLY when the platform is the
# proven writer of that tag; do not invent entries to let customer values through.
PLATFORM_SAFE_TAG_KEYS: frozenset[str] = frozenset()

# Prefix for the opaque, cardinality-preserving placeholder a redacted mapping KEY is replaced with.
# The suffix is the key's POSITIONAL index within its mapping — derived from POSITION, never from
# the key's value/content — so distinct customer keys keep distinct placeholders (they never
# collide) while the placeholder text itself carries none of the original (possibly-PII) key.
_REDACTED_KEY_PREFIX = "redacted_key_"

# Fail-closed recursion bound for :func:`redact_tree` — a structure deeper than this (or a cycle)
# yields the sentinel rather than recursing without limit.
_MAX_REDACT_DEPTH = 64


def _redact_key(key: Any, index: int, allow: frozenset[str]) -> str:
    """Return ``key`` iff it is an EXACT member of the platform-owned ``allow`` list, else a
    positional opaque placeholder.

    Default-DENY: a mapping key is customer-controlled/-derived and can itself carry PII (an email,
    an MRN, an SSN, a patient name), and being *structurally valid* proves nothing. A key therefore
    survives ONLY when it is — by RAW, EXACT equality (no Unicode/NFKC folding) — a member of
    ``allow`` (a set of fixed, platform/module-defined schema field names); otherwise it becomes
    ``f"{_REDACTED_KEY_PREFIX}{index}"``. Matching the raw key exactly is deliberate: a
    customer-crafted Unicode variant (e.g. a fullwidth ``ｄｅｔａｉｌ``) must NOT be folded into an
    ASCII platform key ``detail`` — folding would let it impersonate a platform key AND collide with
    a real ``detail`` in the same mapping, silently overwriting a value. The placeholder is derived
    from the key's POSITION (never its content), so distinct keys stay distinct and no PII key text
    egresses. Idempotent: a placeholder is not in ``allow`` and re-redacts to the same positional
    placeholder.
    """
    if isinstance(key, str) and key in allow:
        return key
    return f"{_REDACTED_KEY_PREFIX}{index}"


def redact_tree(value: Any, _depth: int = 0, _seen: frozenset[int] | None = None) -> Any:
    """Recursively DEFAULT-REDACT the free-form surface of a nested structure for egress.

    Default-DENY: in a PHI context any leaf could be a patient name/MRN/SSN and any customer-derived
    mapping KEY (or unknown object) could carry PII, so a leaf is preserved ONLY when it is
    *provably* one of the explicitly-safe scalar types, and a mapping KEY survives ONLY when it is
    an exact member of :data:`PLATFORM_SAFE_STRUCTURAL_KEYS`:

    * **Safe scalar leaves (preserved):** :class:`enum.Enum` members (incl. ``StrEnum`` — checked
      BEFORE ``str`` so a ``str``-subclass Enum is kept while a plain ``str`` is redacted),
      ``bool``, ``int``, ``float`` and ``None``.
    * **Containers (recursed):** ``dict``/``Mapping`` (keys sanitized via :func:`_redact_key`; a
      value is recursed/preserved ONLY beneath an exact allow-listed platform key — under any
      untrusted/redacted key the value is redacted wholesale, since default-DENY grants no schema
      knowledge of it), ``list``/``tuple`` (→ list), and ``set``/``frozenset`` (ELEMENTS redacted
      too — a set of redaction sentinels legitimately collapses; a redacted element that is no
      longer hashable collapses to :data:`REDACTED`).
    * **Anything else (redacted):** ``str``, ``bytes``, a Pydantic ``BaseModel``, a dataclass, or
      any other object → :data:`REDACTED`. Unknown objects are NEVER introspected/serialized (their
      ``__str__``/``model_dump`` could leak PHI).

    Deterministic and I/O-free so it can run at the serialization boundary; idempotent because
    :data:`REDACTED` re-redacts to itself and positional placeholder keys are stable. Fail-closed
    against deep/cyclic input: past :data:`_MAX_REDACT_DEPTH` levels, or on a container already on
    the current path, it returns :data:`REDACTED` rather than recursing unbounded.
    """
    seen = _seen if _seen is not None else frozenset()
    if _depth > _MAX_REDACT_DEPTH:
        return REDACTED
    # An Enum member (StrEnum IS a str) is a bounded, platform-defined value — preserve it before
    # the ``str`` leaf rule redacts it.
    if isinstance(value, Enum):
        return value
    # Explicitly-safe scalar leaves. bool is an int subclass so covered here; None by identity.
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, Mapping):
        if id(value) in seen:
            return REDACTED
        branch = seen | {id(value)}
        result: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            safe_key = _redact_key(key, index, PLATFORM_SAFE_STRUCTURAL_KEYS)
            # Default-DENY: a value is recursed/preserved ONLY beneath an exact allow-listed
            # platform key. Under an untrusted/redacted key we have NO schema knowledge of the
            # value, so even a safe scalar (a numeric SSN ``123456789``) must be redacted
            # wholesale — never recursed. Test allow-list membership directly (not
            # ``safe_key == key``) so a crafted key equal to ``redacted_key_<index>`` cannot spoof.
            if isinstance(key, str) and key in PLATFORM_SAFE_STRUCTURAL_KEYS:
                result[safe_key] = redact_tree(item, _depth + 1, branch)
            else:
                result[safe_key] = REDACTED
        return result
    if isinstance(value, (list, tuple)):
        if id(value) in seen:
            return REDACTED
        branch = seen | {id(value)}
        return [redact_tree(item, _depth + 1, branch) for item in value]
    if isinstance(value, (set, frozenset)):
        if id(value) in seen:
            return REDACTED
        branch = seen | {id(value)}
        elements: list[Any] = []
        for item in value:
            redacted_item = redact_tree(item, _depth + 1, branch)
            # A set element must stay hashable; a redacted container (dict/list) is not, so it
            # collapses to the sentinel (default-deny, safe).
            try:
                hash(redacted_item)
            except TypeError:
                redacted_item = REDACTED
            elements.append(redacted_item)
        return set(elements) if isinstance(value, set) else frozenset(elements)
    # Default-DENY: str/bytes/BaseModel/dataclass/arbitrary object — never introspected — is
    # coerced to the sentinel rather than serialized.
    return REDACTED


def redact_node_tags(node: ResourceNode) -> ResourceNode:
    """Return an egress COPY of ``node`` with its customer-controlled tags DEFAULT-REDACTED.

    Azure tags are customer-authored, so both keys and values can carry PII — redaction is
    default-DENY, keyed on the explicit :data:`PLATFORM_SAFE_TAG_KEYS` allow-list:

    * Every tag KEY is sanitized via :func:`_redact_key`: it survives ONLY when it is an exact
      member of :data:`PLATFORM_SAFE_TAG_KEYS` (keys the PLATFORM proves it writes); otherwise it
      is replaced by a positional opaque placeholder so a PII key (e.g. ``alice@contoso.com``, or a
      "structurally valid" ``123-45-6789``) can never egress verbatim.
    * Every tag VALUE is redacted to :data:`REDACTED` unless its key is in the same allow-list. The
      allow-list is currently EMPTY, so in practice every customer tag key becomes a placeholder and
      every value is redacted.

    Applied to a COPY at the API response boundary only — the stored/ingested estate and the copy
    used for internal impact/graph analysis keep the raw keys and values.
    """
    if not node.tags:
        return node
    redacted: dict[str, str] = {}
    for index, (key, value) in enumerate(node.tags.items()):
        safe_key = _redact_key(key, index, PLATFORM_SAFE_TAG_KEYS)
        # Preserve the value ONLY when the raw key is an exact allow-listed platform-owned key.
        # Otherwise redact. Test the raw key directly (not ``safe_key``) so a crafted key equal to
        # ``redacted_key_<index>`` cannot spoof preservation. Positional placeholders stay distinct.
        preserve = isinstance(key, str) and key in PLATFORM_SAFE_TAG_KEYS
        redacted[safe_key] = value if preserve else REDACTED
    return node.model_copy(update={"tags": redacted})


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


# --------------------------------------------------------------------------------------
# Bounded egress projections of the metrics snapshot (issue #91).
#
# The in-process :class:`MetricsRegistry` is a *generic* counter/duration store: its
# ``increment``/``observe_duration`` accept arbitrary label maps, so the raw :class:`MetricSample`/
# :class:`DurationSample` contracts keep a free-form ``dict[str, str]`` label type. That free-form
# key type is statically UNBOUNDED, so exposing the raw snapshot on ``/api/metrics`` is a tracked
# no-PII-egress gap. These VIEW models are the bounded projection the API serialises instead: the
# label KEY type is the closed :class:`MetricLabelKey` allow-list (so emitted keys are statically
# enumerable) and every label VALUE is coerced through :func:`redact_value`. In production only the
# sanctioned ``module``/``outcome`` labels are ever emitted, so this projection is loss-free for
# real traffic while dropping any unexpected (potentially unbounded/PII-bearing) label on egress.
# --------------------------------------------------------------------------------------
class MetricLabelKey(StrEnum):
    """Allow-list of metric label KEYS permitted to cross the egress boundary (bounded, non-PII).

    These are exactly the sanctioned, low-cardinality labels the domain helpers emit
    (``record_module_run`` → ``{module, outcome}``; ``record_connector_fail_closed`` →
    ``{module}``). A closed enum makes the emitted key set statically enumerable, so the audited
    egress surface is bounded; any other label key is dropped on egress (fail closed).
    """

    module = "module"
    outcome = "outcome"


_METRIC_LABEL_KEYS: frozenset[str] = frozenset(k.value for k in MetricLabelKey)


def bound_labels(raw: Any) -> dict[str, str]:
    """PURE: project a free-form label map onto the bounded egress shape (drop + redact).

    Keys not on the :class:`MetricLabelKey` allow-list are DROPPED; each surviving value is coerced
    through :func:`redact_value` so no free-form label value can egress unredacted. Non-mapping
    input yields an empty map (fail closed). Deterministic and I/O-free (runs in a validator).
    """
    if not isinstance(raw, Mapping):
        return {}
    return {
        str(key): redact_value(value)
        for key, value in raw.items()
        if str(key) in _METRIC_LABEL_KEYS
    }


class MetricSampleView(BaseModel):
    """Bounded egress projection of :class:`MetricSample` (allow-listed keys, redacted values)."""

    name: str
    labels: dict[MetricLabelKey, str] = Field(default_factory=dict)
    value: int = Field(ge=0)

    @field_validator("labels", mode="before")
    @classmethod
    def _bound_labels(cls, value: Any) -> dict[str, str]:
        return bound_labels(value)

    @classmethod
    def from_sample(cls, sample: MetricSample) -> MetricSampleView:
        return cls.model_validate(
            {"name": sample.name, "labels": sample.labels, "value": sample.value}
        )


class DurationSampleView(BaseModel):
    """Bounded egress projection of :class:`DurationSample` (allow-listed keys, redacted values)."""

    name: str
    labels: dict[MetricLabelKey, str] = Field(default_factory=dict)
    count: int = Field(ge=0)
    totalMs: float = Field(ge=0.0)
    minMs: float = Field(ge=0.0)
    maxMs: float = Field(ge=0.0)

    @field_validator("labels", mode="before")
    @classmethod
    def _bound_labels(cls, value: Any) -> dict[str, str]:
        return bound_labels(value)

    @classmethod
    def from_sample(cls, sample: DurationSample) -> DurationSampleView:
        return cls.model_validate(
            {
                "name": sample.name,
                "labels": sample.labels,
                "count": sample.count,
                "totalMs": sample.totalMs,
                "minMs": sample.minMs,
                "maxMs": sample.maxMs,
            }
        )


class MetricsSnapshotView(BaseModel):
    """Bounded egress projection of :class:`MetricsSnapshot` served at ``/api/metrics``.

    Identical wire shape to :class:`MetricsSnapshot` (``counters``/``durations`` lists) but every
    sample's labels are projected onto the bounded :class:`MetricLabelKey` allow-list with redacted
    values, so the serialized egress surface is statically bounded and PII-free.
    """

    counters: list[MetricSampleView] = Field(default_factory=list)
    durations: list[DurationSampleView] = Field(default_factory=list)

    @classmethod
    def from_snapshot(cls, snapshot: MetricsSnapshot) -> MetricsSnapshotView:
        return cls(
            counters=[MetricSampleView.from_sample(s) for s in snapshot.counters],
            durations=[DurationSampleView.from_sample(s) for s in snapshot.durations],
        )
