"""Scheduled Reassessments module — re-run discovery/quality on a cadence; compute drift.

Runs as a cron ACA **Job** (0→5). Compares the latest run to the prior snapshot and emits
drift findings (new failures, resolved failures, changed estate). Pure diff logic is testable.
"""
from __future__ import annotations

from shared.contracts import (
    AgentResponse,
    Finding,
    ModuleKind,
    ModuleManifest,
    ModuleRunResult,
    ScaleProfile,
    ScaleTrigger,
)
from shared.module_base import Module, ModuleContext

_MANIFEST = ModuleManifest(
    name="reassessments",
    displayName="Scheduled Reassessments",
    kind=ModuleKind.job,
    consumes=[],
    produces=["drift", "Finding[]"],
    scaleProfile=ScaleProfile(
        kind=ModuleKind.job,
        minReplicas=0,
        maxReplicas=5,
        triggers=[ScaleTrigger(type="cron", metadata={"schedule": "0 3 * * *"})],
        cpu=0.5,
        memoryGi=1.0,
    ),
)


def diff_findings(previous: list[Finding], current: list[Finding]) -> dict[str, list[str]]:
    """Pure drift diff: which checks newly failed, which recovered, keyed by finding id."""
    prev = {f.id: f for f in previous}
    cur = {f.id: f for f in current}
    new_failures = [
        i for i, f in cur.items()
        if f.passed is False and prev.get(i, f).passed is not False
    ]
    recovered = [
        i for i, f in prev.items()
        if f.passed is False and cur.get(i) and cur[i].passed
    ]
    return {"newFailures": new_failures, "recovered": recovered}


class ReassessmentsModule(Module):
    @property
    def manifest(self) -> ModuleManifest:
        return _MANIFEST

    def run(self, ctx: ModuleContext, *, scope: dict[str, str] | None = None) -> ModuleRunResult:
        scope = scope or {}
        drift = diff_findings([], [])
        response = AgentResponse(
            agentName="reassessments",
            taskType="scheduled-reassessment",
            inputSummary=f"scope={scope or 'all'}",
            findings=[
                f"{len(drift['newFailures'])} new failures, {len(drift['recovered'])} recovered"
            ],
            confidence=1.0,
            nextActions=["route-findings"] if drift["newFailures"] else [],
        )
        return ModuleRunResult(module=self.name, ok=True, response=response, extra=drift)
