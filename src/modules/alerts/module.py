"""Alerts & Notifications module — route findings/incidents with blast-radius-weighted severity.

Always-on ACA **service** (1→10). Consumes **Ops Packs** (who to tell, how, and the runbook link)
and escalates severity by blast radius, so a failure that downs the whole workload pages, while an
isolated, redundant-node issue is a low-priority ticket.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Protocol, cast, runtime_checkable

from shared.contracts import (
    AgentResponse,
    Finding,
    ModuleKind,
    ModuleManifest,
    ModuleRunResult,
    PackType,
    ScaleProfile,
    ScaleTrigger,
    Severity,
)
from shared.module_base import Module, ModuleContext
from shared.state import ReadableState

from .channels import DeliveryResult, NotificationChannel

_MANIFEST = ModuleManifest(
    name="alerts",
    displayName="Alerts & Notifications",
    kind=ModuleKind.service,
    consumes=[PackType.ops],
    produces=["notifications"],
    scaleProfile=ScaleProfile(
        kind=ModuleKind.service,
        minReplicas=1,
        maxReplicas=10,
        triggers=[ScaleTrigger(type="azure-queue", metadata={"queueName": "findings"})],
        cpu=0.5,
        memoryGi=1.0,
    ),
)

_ESCALATION_ORDER = [Severity.info, Severity.low, Severity.medium, Severity.high, Severity.critical]

# Channels that mean "silence this notification": an Ops Pack maps a severity here (e.g.
# ``info`` -> ``"none"``) to suppress delivery. Empty/whitespace channels are treated the same.
_SUPPRESSED_CHANNELS = frozenset({"none"})


def is_suppressed(channel: str | None) -> bool:
    """True if a routed ``channel`` means "do not deliver" (suppression sentinel or empty)."""
    normalized = (channel or "").strip().casefold()
    return normalized == "" or normalized in _SUPPRESSED_CHANNELS


def weight_by_blast_radius(finding: Finding) -> Severity:
    """Pure severity escalation: bump severity up by blast radius bands.

    radius 0 -> unchanged; 1-4 -> +1 band; 5+ -> critical. Never downgrades.
    """
    idx = _ESCALATION_ORDER.index(finding.severity) if finding.severity in _ESCALATION_ORDER else 2
    if finding.blastRadius >= 5:
        return Severity.critical
    if finding.blastRadius >= 1:
        idx = min(idx + 1, len(_ESCALATION_ORDER) - 1)
    return _ESCALATION_ORDER[idx]


def route(finding: Finding, ops: dict) -> dict:
    """Pure routing decision: map an (escalated) finding to a channel per the Ops Pack."""
    severity = weight_by_blast_radius(finding)
    routes = ops.get("routes", {})
    channel = routes.get(severity.value, ops.get("default", "ticket"))
    return {
        "findingId": finding.id,
        "severity": severity.value,
        "channel": channel,
        "runbook": ops.get("runbook"),
    }


@runtime_checkable
class _OpsPack(Protocol):
    """Local view of a verified pack — just the parsed body the routing table lives in."""

    @property
    def body(self) -> Mapping[str, Any]: ...


@runtime_checkable
class _OpsPacksSource(Protocol):
    """Local view of the packs engine: hand back verified Ops Packs for a workload."""

    def load_for_workload(self, workload: str, pack_type: PackType) -> Sequence[_OpsPack]: ...


def load_ops_routing(packs: object | None, workload: str) -> dict[str, Any]:
    """Merge verified **Ops Pack** bodies into a single routing table for :func:`route`.

    Ops Pack body shape (content, not code): ``{"routes": {<severity>: <channel>}, "default":
    <channel>, "runbook": <url>}``. Fail closed: if the packs engine is absent or a pack fails
    verification, return ``{}`` so routing falls back to the safe default channel instead of acting
    on an unverified pack.
    """
    if packs is None:
        return {}
    source = cast(_OpsPacksSource, packs)
    routes: dict[str, str] = {}
    ops: dict[str, Any] = {"routes": routes}
    try:
        loaded = source.load_for_workload(workload, PackType.ops)
    except Exception:  # unverifiable/unavailable ops packs -> fail closed, no routing table
        return {}
    for pack in loaded:
        body = pack.body
        pack_routes = body.get("routes")
        if isinstance(pack_routes, Mapping):
            routes.update({str(k): str(v) for k, v in pack_routes.items()})
        if body.get("default") is not None:
            ops["default"] = body["default"]
        if body.get("runbook"):
            ops["runbook"] = body["runbook"]
    return ops


def _notification_payload(finding: Finding, decision: Mapping[str, Any]) -> dict[str, Any]:
    """Build the outbound payload as an EXPLICIT allowlist — this data leaves the boundary.

    Only ``findingId``, ``severity``, ``channel`` and ``runbook`` are ever egressed. This is a
    deliberate allowlist, NOT a pass-through of ``Finding`` fields: ``nodeId``, ``title``,
    ``detail``, ``evidence`` and the raw finding are excluded so no unconstrained,
    customer-derived data crosses the process boundary.

    TODO(human): even ``findingId`` can encode a customer resource id. If the delivery endpoint is
    EXTERNAL to the customer boundary, add a redaction/hashing option for ``findingId`` — a policy
    decision (in-boundary vs. egress), so keep it a deliberate hook rather than a silent default.
    """
    return {
        "findingId": finding.id,
        "severity": decision["severity"],
        "channel": decision["channel"],
        "runbook": decision.get("runbook"),
    }


def _deliver(notifier: NotificationChannel | None, payload: Mapping[str, Any]) -> DeliveryResult:
    """Deliver via the injected channel, failing closed if it is missing or errors."""
    channel = str(payload.get("channel", ""))
    if notifier is None:
        return DeliveryResult(
            channel=channel, delivered=False, detail="no notifier client injected"
        )
    try:
        return notifier.send(payload)
    except Exception as exc:  # never crash a run on a delivery error — surface undelivered
        return DeliveryResult(channel=channel, delivered=False, detail=f"send error: {exc!s}")


def _resolve_workloads(state: ReadableState | None, scope: Mapping[str, str]) -> list[str]:
    """Scope wins; otherwise every workload the read-only store knows (empty if no state)."""
    if scope.get("workload"):
        return [scope["workload"]]
    if state is None:
        return []
    return state.list_workloads()


class AlertsModule(Module):
    @property
    def manifest(self) -> ModuleManifest:
        return _MANIFEST

    def run(self, ctx: ModuleContext, *, scope: dict[str, str] | None = None) -> ModuleRunResult:
        scope = scope or {}
        state = ctx.state
        notifier = cast(NotificationChannel | None, ctx.clients.get("notifier"))
        workloads = _resolve_workloads(state, scope)

        audit: list[dict[str, Any]] = []
        routed = 0
        for workload in workloads:
            findings = state.get_findings(workload) if state is not None else []
            failing = [f for f in findings if f.passed is False]
            ops = load_ops_routing(ctx.packs, workload)
            for finding in failing:
                decision = route(finding, ops)
                channel = str(decision["channel"])
                routed += 1
                if is_suppressed(channel):
                    # Ops Pack silenced this severity — record it, but never call the notifier.
                    audit.append({
                        "workload": workload,
                        "findingId": finding.id,
                        "severity": decision["severity"],
                        "channel": channel,
                        "delivered": False,
                        "suppressed": True,
                        "runbook": decision.get("runbook"),
                    })
                    continue
                result = _deliver(notifier, _notification_payload(finding, decision))
                audit.append({
                    "workload": workload,
                    "findingId": finding.id,
                    "severity": decision["severity"],
                    "channel": channel,
                    "delivered": result.delivered,
                    "suppressed": False,
                    "runbook": decision.get("runbook"),
                })

        delivered = sum(1 for a in audit if a["delivered"])
        risks = (
            [] if notifier is not None
            else ["no notifier channel injected — routes computed, undelivered"]
        )
        response = AgentResponse(
            agentName="alerts",
            taskType="route-notifications",
            inputSummary=f"scope={scope or 'all'}; workloads={len(workloads)}; routed={routed}",
            findings=[f"{routed} notification(s) routed, {delivered} delivered"],
            risks=risks,
            confidence=1.0,
        )
        return ModuleRunResult(module=self.name, ok=True, response=response,
                               extra={"notifications": audit})
