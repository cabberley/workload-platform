"""Telemetry Export module — emit the platform's PII-free app-signals to Log Analytics (issue #86).

This module closes the gap the #58 baseline Grafana boards left open: the boards read four custom
Log Analytics tables (``WpNodeState_CL``, ``WpSpof_CL``, ``WpFinding_CL``, ``WpConnectorFetch_CL``)
that nothing emitted, so three of them failed at query time. This module is the opt-in, in-boundary,
keyless emit path.

Architecture (respects every house rule):

* **Independently scalable.** It is its OWN ``kind: job`` module — a scheduled ACA Job (scale-to-
  zero between fires, like reassessments) that periodically reads shared state, shapes rows, and
  publishes them. It does not ride the aiops hot-detection path, so it scales on its own cadence.
* **Module isolation.** The signals originate across several modules (node states from discovery /
  quality findings, SPOFs from dependency_graph, blast radius from findings). This module NEVER
  imports a sibling module — it reads them through the shared read-only ``ReadableState`` view (the
  API-core/state channel) and shapes them with pure functions in
  :mod:`modules.telemetry_export.shaping`.
* **Pure logic ⟂ I/O.** All signal-shaping is pure + unit-tested; the only I/O is the injected,
  keyless, fail-closed :class:`~modules.telemetry_export.exporter.LogsIngestionClient` looked up by
  name in ``ctx.clients``.
* **Opt-in / fail closed.** With no state view, no exporter wired, or the exporter unconfigured, the
  run is an inert no-op that still returns ``ok=True`` — a telemetry failure never breaks anything.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import cast

from modules.telemetry_export.exporter import (
    ExportResult,
    LogsIngestionClient,
    TelemetryBatch,
)
from modules.telemetry_export.shaping import (
    WpConnectorFetchRow,
    WpFindingRow,
    WpNodeStateRow,
    WpSpofRow,
    shape_findings,
    shape_node_states,
    shape_spofs,
)
from shared.contracts import (
    AgentResponse,
    ModuleKind,
    ModuleManifest,
    ModuleRunResult,
    ScaleProfile,
    ScaleTrigger,
)
from shared.module_base import Module, ModuleContext
from shared.state import ReadableState

# Well-known name the composition root (cli.wiring) registers the keyless export edge client under.
CLIENT_KEY = "telemetry_exporter"

# Export cadence this module models (mirrors the manifest cron trigger). Five minutes matches the
# 5-minute bins the freshness/health boards summarize over.
_CADENCE_CRON = "*/5 * * * *"

_MANIFEST = ModuleManifest(
    name="telemetry_export",
    displayName="Telemetry Export (Azure Monitor)",
    kind=ModuleKind.job,
    consumes=[],
    produces=["WpNodeState_CL", "WpSpof_CL", "WpFinding_CL", "WpConnectorFetch_CL"],
    scaleProfile=ScaleProfile(
        kind=ModuleKind.job,
        # Schedule job: scale-to-zero between fires; one replica per scheduled run (parallelism=1
        # in infra/bicep). minReplicas is N/A to schedule cadence; kept for schema consistency.
        minReplicas=0,
        maxReplicas=1,
        triggers=[ScaleTrigger(type="cron", metadata={"schedule": _CADENCE_CRON})],
        cpu=0.25,
        memoryGi=0.5,
    ),
)


def _resolve_workloads(state: ReadableState | None, scope: dict[str, str]) -> list[str]:
    """Resolve the workload(s) to export. Fail closed to ``[]`` when there is no state view.

    An explicit ``scope["workload"]`` wins; otherwise export every workload the read-only state
    knows about. With no state we cannot read signals, so we surface nothing rather than guess.
    """
    if scoped := scope.get("workload"):
        return [scoped]
    if state is None:
        return []
    return list(state.list_workloads())


def _shape_for_workload(
    state: ReadableState, workload: str, *, at: datetime
) -> tuple[list[WpNodeStateRow], list[WpSpofRow], list[WpFindingRow]]:
    """Read one workload's in-boundary signals from state and shape them (pure) into PII-free rows.

    State reads sit at this edge; the shaping is pure. Node state derives from ALL of the workload's
    findings; SPOF + blast-radius rows derive from the failing findings that carry a node + radius
    (the dependency_graph output). No raw ids leave — SPOF node ids are opaqued in shaping.
    """
    findings = state.get_findings(workload)
    nodes = state.get_estate(workload)
    node_states = shape_node_states(workload, nodes, findings, at=at)
    spofs = shape_spofs(workload, findings, at=at)
    finding_rows = shape_findings(workload, findings)
    return node_states, spofs, finding_rows


class TelemetryExportModule(Module):
    @property
    def manifest(self) -> ModuleManifest:
        return _MANIFEST

    def run(self, ctx: ModuleContext, *, scope: dict[str, str] | None = None) -> ModuleRunResult:
        scope = scope or {}
        state = ctx.state
        workloads = _resolve_workloads(state, scope)
        at = datetime.now(UTC)

        node_states: list[WpNodeStateRow] = []
        spofs: list[WpSpofRow] = []
        findings: list[WpFindingRow] = []
        if state is not None:
            for workload in workloads:
                ns, sp, fr = _shape_for_workload(state, workload, at=at)
                node_states.extend(ns)
                spofs.extend(sp)
                findings.extend(fr)

        # WpConnectorFetch_CL: there is no shared, persisted connector-fetch freshness read model
        # today (each connector's `FetchResult` is ephemeral at that module's edge, and module
        # isolation forbids importing sibling connectors). The pure `shape_connector_fetch` +
        # `WpConnectorFetchRow` contract are ready; we emit NOTHING for connectors here (fail
        # closed → the freshness board treats a missing connector row as "unverified, not fresh",
        # which it documents), rather than fabricate data.
        #
        # TODO(human): source connector-fetch freshness without a cross-module import. The clean
        # options are (a) the API core persists a small PII-free `{connector, success, ts}` read
        # model each connector run writes through the single writer, exposed on `ReadableState`; or
        # (b) each read connector reports its `FetchResult` to this export seam via the composition
        # root. Both are contract/boundary changes → route via the Architect + an ADR, then feed the
        # results through `shape_connector_fetches` here. Do NOT import a sibling connector.
        connector_fetches: list[WpConnectorFetchRow] = []

        batch = TelemetryBatch(
            node_states=node_states,
            spofs=spofs,
            findings=findings,
            connector_fetches=connector_fetches,
        )

        result = self._export(ctx, batch)
        response = _build_response(scope, workloads, batch, result)
        # ok stays True: export outcomes are advisory and surfaced in the response (fail-closed —
        # a telemetry emit failure must never fail the platform). The boards themselves surface a
        # missing/stale table.
        return ModuleRunResult(
            module=self.name,
            ok=True,
            response=response,
            extra={
                "configured": result.configured,
                "emittedByStream": result.emitted_by_stream,
                "emitted": result.emitted,
                "errors": result.errors,
                "workloads": len(workloads),
            },
        )

    @staticmethod
    def _export(ctx: ModuleContext, batch: TelemetryBatch) -> ExportResult:
        """Look the keyless exporter up by name and publish. Absent client ⇒ inert (fail closed)."""
        client = ctx.clients.get(CLIENT_KEY)
        if client is None:
            return ExportResult(configured=False)
        exporter = cast(LogsIngestionClient, client)
        return exporter.export(batch)


def _build_response(
    scope: dict[str, str],
    workloads: list[str],
    batch: TelemetryBatch,
    result: ExportResult,
) -> AgentResponse:
    """Build the PII-free run summary. Only counts, the configured flag, and error classes."""
    status = (
        "inert (exporter unconfigured)"
        if not result.configured
        else f"emitted {result.emitted} row(s)"
    )
    return AgentResponse(
        agentName="telemetry_export",
        taskType="emit-platform-telemetry",
        inputSummary=(
            f"cadence={_CADENCE_CRON} scope={scope or 'all'} workloads={len(workloads)} "
            f"rows={batch.total_rows()} status={status}"
        ),
        findings=[
            f"WpNodeState_CL={len(batch.node_states)}",
            f"WpSpof_CL={len(batch.spofs)}",
            f"WpFinding_CL={len(batch.findings)}",
            f"WpConnectorFetch_CL={len(batch.connector_fetches)}",
        ],
        risks=[f"export error: {name}" for name in result.errors],
        confidence=1.0,
        nextActions=[],
    )
