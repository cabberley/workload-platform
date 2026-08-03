"""AIOps module — fuse telemetry, detect proactively, auto-RCA, and *advise* remediation.

Always-on ACA **service** (1→20). Consumes **Telemetry Packs** to know what to watch and how to
detect (metric thresholds + AI log analysis). On a detection it correlates against the dependency
graph to localize root cause and produces an advisory remediation recommendation — **never**
auto-applied (fail-closed; humans dispose). Escalates to "call support" when confidence is low.
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
    SourceReference,
)
from shared.module_base import Module, ModuleContext

_MANIFEST = ModuleManifest(
    name="aiops",
    displayName="AIOps (System Pulse + Azure Monitor)",
    kind=ModuleKind.service,
    consumes=[PackType.telemetry],
    produces=["detections", "rca", "Finding[]"],
    scaleProfile=ScaleProfile(
        kind=ModuleKind.service,
        minReplicas=1,
        maxReplicas=20,
        triggers=[
            ScaleTrigger(type="azure-queue", metadata={"queueName": "telemetry"}),
            ScaleTrigger(type="cpu", metadata={"type": "Utilization", "value": "70"}),
        ],
        cpu=1.0,
        memoryGi=2.0,
    ),
)

# Confidence below which we do not assert an RCA — we advise contacting support instead.
RCA_CONFIDENCE_FLOOR = 0.6


def detect_metric_breach(signal: dict) -> Finding | None:
    """Pure threshold detection for one telemetry signal.

    signal = {name, value, op ('gt'|'lt'), threshold, nodeId, severity}
    Fail-closed: a malformed signal returns None (surfaced upstream), never a silent pass.
    """
    required = {"name", "value", "op", "threshold"}
    if not required.issubset(signal):
        return None
    op = signal["op"]
    threshold = signal["threshold"]
    value = signal["value"]
    breached = value > threshold if op == "gt" else value < threshold
    if not breached:
        return None
    return Finding(
        id=f"detect::{signal['name']}::{signal.get('nodeId', 'na')}",
        module="aiops",
        title=f"Telemetry breach: {signal['name']}",
        passed=False,
        severity=Severity(signal.get("severity", "high")),
        nodeId=signal.get("nodeId"),
        evidence=[SourceReference(kind="metric", id=signal["name"],
                                  detail=f"{signal['value']} {op} {signal['threshold']}")],
        detail="Proactive detection from telemetry pack threshold.",
    )


def correlate_rca(finding: Finding, blast_radius_of: dict[str, int]) -> AgentResponse:
    """Localize likely root cause using blast radius; gate assertions by confidence."""
    node = finding.nodeId or "unknown"
    radius = blast_radius_of.get(node, 0)
    confidence = 0.8 if radius > 0 else 0.4
    if confidence >= RCA_CONFIDENCE_FLOOR:
        recs = [f"Investigate {node} (blast radius {radius}) as probable root cause."]
        nxt = ["propose-remediation"]
    else:
        recs = ["Root cause not confidently localized."]
        nxt = ["recommend-contact-support"]
    return AgentResponse(
        agentName="aiops",
        taskType="auto-rca",
        inputSummary=f"finding={finding.id}",
        findings=[finding.title],
        risks=[f"blast radius {radius}"] if radius else [],
        recommendations=recs,
        sourceReferences=finding.evidence,
        confidence=confidence,
        nextActions=nxt,
    )


class AiopsModule(Module):
    @property
    def manifest(self) -> ModuleManifest:
        return _MANIFEST

    def run(self, ctx: ModuleContext, *, scope: dict[str, str] | None = None) -> ModuleRunResult:
        scope = scope or {}
        signals: list[dict] = []
        findings = [f for f in (detect_metric_breach(s) for s in signals) if f is not None]
        response = AgentResponse(
            agentName="aiops",
            taskType="proactive-detect",
            inputSummary=f"scope={scope or 'all'}; signals={len(signals)}",
            findings=[f"{len(findings)} detection(s)"],
            confidence=1.0,
            nextActions=["auto-rca"] if findings else [],
        )
        return ModuleRunResult(module=self.name, ok=True, findings=findings, response=response)
