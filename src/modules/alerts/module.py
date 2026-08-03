"""Alerts & Notifications module — route findings/incidents with blast-radius-weighted severity.

Always-on ACA **service** (1→10). Consumes **Ops Packs** (who to tell, how, and the runbook link)
and escalates severity by blast radius, so a failure that downs the whole workload pages, while an
isolated, redundant-node issue is a low-priority ticket.
"""
from __future__ import annotations

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


class AlertsModule(Module):
    @property
    def manifest(self) -> ModuleManifest:
        return _MANIFEST

    def run(self, ctx: ModuleContext, *, scope: dict[str, str] | None = None) -> ModuleRunResult:
        scope = scope or {}
        findings: list[Finding] = []
        ops: dict = {}
        notifications = [route(f, ops) for f in findings if f.passed is False]
        response = AgentResponse(
            agentName="alerts",
            taskType="route-notifications",
            inputSummary=f"scope={scope or 'all'}; findings={len(findings)}",
            findings=[f"{len(notifications)} notification(s) routed"],
            confidence=1.0,
        )
        return ModuleRunResult(module=self.name, ok=True, response=response,
                               extra={"notifications": notifications})
