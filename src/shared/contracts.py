"""Shared domain contracts for the Workloads Platform.

Every analytical/agent output and every cross-boundary payload is a Pydantic model defined here.
Do not fork these shapes in modules — import them. See `.github/copilot-instructions.md`.
"""
from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


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
    signature: str | None = Field(default=None, description="HMAC signature over sha256")
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
