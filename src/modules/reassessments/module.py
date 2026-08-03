"""Scheduled Reassessments module — re-run discovery/quality on a cadence; compute drift.

Runs as a cron ACA **Job** (0→5). Compares the latest run to the prior snapshot and emits
drift findings (new failures, resolved failures, changed estate). Pure diff logic is testable.
"""
from __future__ import annotations

from shared.contracts import (
    AgentResponse,
    DriftReport,
    Finding,
    ModuleKind,
    ModuleManifest,
    ModuleRunResult,
    ScaleProfile,
    ScaleTrigger,
)
from shared.module_base import Module, ModuleContext
from shared.state import ReadableState, compute_drift

# Scheduled re-run cadence this module models (mirrors the manifest cron trigger).
_CADENCE_CRON = "0 3 * * *"

_MANIFEST = ModuleManifest(
    name="reassessments",
    displayName="Scheduled Reassessments",
    kind=ModuleKind.job,
    consumes=[],
    produces=["drift", "Finding[]"],
    scaleProfile=ScaleProfile(
        kind=ModuleKind.job,
        # Schedule job: minReplicas is N/A (schedule jobs scale to zero between runs); maxReplicas
        # maps to the ACA job `parallelism` (replicas launched per scheduled run). See infra/bicep.
        minReplicas=0,
        maxReplicas=5,
        triggers=[ScaleTrigger(type="cron", metadata={"schedule": "0 3 * * *"})],
        cpu=0.5,
        memoryGi=1.0,
    ),
)


def diff_findings(previous: list[Finding], current: list[Finding]) -> dict[str, list[str]]:
    """Pure drift diff: which checks newly failed, which recovered, keyed by finding id.

    Delegates to the shared pure :func:`compute_drift` so the module and the API core agree on
    one canonical "failing means ``passed is False``" (fail-closed) diff, then projects it down to
    the finding-id lists this helper has always returned. No I/O, deterministic, unit-tested.
    """
    report = compute_drift(previous, current, workload="")
    return {
        "newFailures": [f.id for f in report.newFailures],
        "recovered": [f.id for f in report.recovered],
    }


def _resolve_workloads(state: ReadableState | None, scope: dict[str, str]) -> list[str]:
    """Resolve the workload(s) to reassess. Fail closed to ``[]`` when there is no state.

    An explicit ``scope["workload"]`` wins; otherwise reassess every workload the read-only state
    knows about. With no state view we cannot read prior/current snapshots, so we surface nothing
    rather than guess (guardrail 4).
    """
    if scoped := scope.get("workload"):
        return [scoped]
    if state is None:
        return []
    return list(state.list_workloads())


def _drift_for_workload(state: ReadableState, workload: str) -> DriftReport:
    """Compute drift for one workload from the read-only state.

    Mirrors the API ``/api/workloads/{workload}/drift`` endpoint: prior snapshot findings/nodes vs
    current findings/estate, fed to the shared pure :func:`compute_drift`. State reads sit at the
    edge here; the diff itself stays pure.
    """
    return compute_drift(
        state.get_previous_findings(workload),
        state.get_findings(workload),
        workload=workload,
        previous_nodes=state.get_previous_node_ids(workload),
        current_nodes=[node.id for node in state.get_estate(workload)],
    )


class ReassessmentsModule(Module):
    @property
    def manifest(self) -> ModuleManifest:
        return _MANIFEST

    def run(self, ctx: ModuleContext, *, scope: dict[str, str] | None = None) -> ModuleRunResult:
        scope = scope or {}
        state = ctx.state
        workloads = _resolve_workloads(state, scope)

        # TODO(human): wire the actual re-trigger of discovery/quality jobs here. This module runs
        # on the cron cadence (0 3 * * *) and computes drift over the *latest vs previous* snapshot
        # already in state; it does NOT itself re-invoke discovery/quality across the process
        # boundary in MVP. Re-running those modules is an orchestration/control-plane concern —
        # enqueue their ACA Jobs (e.g. Storage Queue / KEDA) from the worker before this drift
        # pass, so "current" reflects a fresh scan. Advisory only: no auto-action is taken here.

        reports: dict[str, DriftReport] = {}
        new_failures: list[Finding] = []
        if state is not None:
            for workload in workloads:
                report = _drift_for_workload(state, workload)
                reports[workload] = report
                new_failures.extend(report.newFailures)

        total_new = sum(len(r.newFailures) for r in reports.values())
        total_recovered = sum(len(r.recovered) for r in reports.values())
        total_still = sum(len(r.stillFailing) for r in reports.values())
        added_nodes = sum(len(r.addedNodes) for r in reports.values())
        removed_nodes = sum(len(r.removedNodes) for r in reports.values())

        response = AgentResponse(
            agentName="reassessments",
            taskType="scheduled-reassessment",
            inputSummary=f"cadence={_CADENCE_CRON} scope={scope or 'all'} workloads={len(reports)}",
            findings=[
                f"{workload}: {len(r.newFailures)} new failures, {len(r.recovered)} recovered, "
                f"{len(r.stillFailing)} still failing"
                for workload, r in reports.items()
            ]
            or ["no workloads in scope"],
            risks=[
                f"{f.title} newly failing ({f.severity})" for f in new_failures
            ],
            # Drift is advisory/routable: a human (or alerts) disposes; we never remediate.
            recommendations=["route new-failure findings to alerts"] if new_failures else [],
            confidence=1.0,
            nextActions=["route-findings"] if new_failures else [],
        )

        summary: dict[str, object] = {
            "cadence": _CADENCE_CRON,
            "workloads": len(reports),
            "newFailures": total_new,
            "recovered": total_recovered,
            "stillFailing": total_still,
            "addedNodes": added_nodes,
            "removedNodes": removed_nodes,
        }
        extra: dict[str, object] = {
            "summary": summary,
            "drift": {w: r.model_dump(mode="json") for w, r in reports.items()},
        }
        return ModuleRunResult(
            module=self.name,
            ok=True,
            findings=new_failures,
            response=response,
            extra=extra,
        )
