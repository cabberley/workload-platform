"""Discovery module — classify the estate into workload → tier → role.

Reads the estate (Azure Resource Graph at the edge; Kuiper assist optional) and applies
**Workload Definition Packs** to label nodes. Output feeds the dependency and quality modules.
Runs as an ACA **Job** (bursty, periodic) that scales 0→10.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Protocol, cast

from shared.contracts import (
    AgentResponse,
    ModuleKind,
    ModuleManifest,
    ModuleRunResult,
    PackType,
    ResourceNode,
    ScaleProfile,
    ScaleTrigger,
)
from shared.module_base import Module, ModuleContext

from .arg import ResourceGraphClient, rows_to_nodes
from .connectors.kuiper import (
    KuiperConnector,
    SupplementalResult,
    apply_supplemental,
    hints_from_result,
)

# Well-known name the worker/API uses to inject the ARG edge client into ``ctx.clients``.
RESOURCE_GRAPH_CLIENT = "resource_graph"

# Well-known name the worker/API uses to (optionally) inject the Kuiper discovery-assist connector
# into ``ctx.clients`` (issue #47). Absent ⇒ Discovery runs exactly as before (ARG only); present
# and available ⇒ its hints are merged as clearly-marked, non-authoritative SUPPLEMENTAL signals.
# Discovery never hard-depends on Kuiper — this is an optional DI seam, keyless and fail-closed.
KUIPER_CONNECTOR = "kuiper"


class _WorkloadPack(Protocol):
    """Structural view of a loaded pack: just the ``body`` dict Discovery flattens."""

    @property
    def body(self) -> Mapping[str, Any]: ...


class _PacksEngine(Protocol):
    """Structural view of the packs engine: load workload packs by type."""

    def load_all(self, *, pack_type: PackType) -> Sequence[_WorkloadPack]: ...


_MANIFEST = ModuleManifest(
    name="discovery",
    displayName="Discovery",
    kind=ModuleKind.job,
    consumes=[PackType.workload],
    produces=["estate", "ResourceNode[]"],
    scaleProfile=ScaleProfile(
        kind=ModuleKind.job,
        # Schedule job: minReplicas is N/A (schedule jobs scale to zero between runs); maxReplicas
        # maps to the ACA job `parallelism` (replicas launched per scheduled run). See infra/bicep.
        minReplicas=0,
        maxReplicas=10,
        triggers=[
            ScaleTrigger(type="cron", metadata={"schedule": "0 */6 * * *"}),
            # On-demand runs are API-invoked (control-plane `job start`), not a KEDA queue scaler.
            ScaleTrigger(type="api-invoked", metadata={}),
        ],
        cpu=0.5,
        memoryGi=1.0,
    ),
)


def classify(resources: list[ResourceNode], definitions: list[dict]) -> list[ResourceNode]:
    """Pure classification: tag each resource with workload/tier/role from pack definitions.

    A definition entry matches on resource `type` and/or tag rules and assigns tier/role.
    Kept pure so it is fully unit-testable without Azure.
    """
    out: list[ResourceNode] = []
    for node in resources:
        labelled = node.model_copy()
        node_type_cf = node.type.casefold()
        for d in definitions:
            resource_type = d.get("resourceType")
            # Azure Resource Graph returns resource types in inconsistent casing (e.g.
            # ``microsoft.compute/virtualmachines``) vs the pack's canonical casing, so match
            # case-insensitively on BOTH sides. The node's original ``type`` string is preserved
            # on the output — we only case-fold for the comparison.
            if resource_type and resource_type.casefold() != node_type_cf:
                continue
            tag_key = d.get("tagKey")
            if tag_key and node.tags.get(tag_key) != d.get("tagValue"):
                continue
            labelled.workload = d.get("workload", labelled.workload)
            labelled.tier = d.get("tier", labelled.tier)
            labelled.role = d.get("role", labelled.role)
            break
        out.append(labelled)
    return out


def definitions_from_packs(packs: Sequence[_WorkloadPack]) -> list[dict]:
    """Pure: flatten Workload Definition pack bodies into the definition dicts ``classify`` reads.

    Each workload pack ``body`` carries a ``definitions`` list of
    ``{resourceType, tagKey, tagValue, workload, tier, role}`` entries. We concatenate them in pack
    order and inherit the pack-level ``workload`` when an entry omits its own, so a pack can set the
    workload once. Non-dict entries are skipped (fail closed — a malformed pack cannot inject junk).
    """
    definitions: list[dict] = []
    for pack in packs:
        body = pack.body or {}
        default_workload = body.get("workload")
        for entry in body.get("definitions", []) or []:
            if not isinstance(entry, Mapping):
                continue
            definition = dict(entry)
            if default_workload and "workload" not in definition:
                definition["workload"] = default_workload
            definitions.append(definition)
    return definitions


class DiscoveryModule(Module):
    @property
    def manifest(self) -> ModuleManifest:
        return _MANIFEST

    def _load_definitions(self, packs: object | None) -> list[dict]:
        """Load + flatten Workload Definition packs from the injected packs engine (fail closed)."""
        if packs is None:
            return []
        engine = cast(_PacksEngine, packs)
        loaded = engine.load_all(pack_type=PackType.workload)
        return definitions_from_packs(loaded)

    def run(self, ctx: ModuleContext, *, scope: dict[str, str] | None = None) -> ModuleRunResult:
        scope = scope or {}
        notes: list[str] = []

        # Edge I/O lives entirely behind the injected ARG client (the DI seam). If none is wired
        # we fail closed: an explicit empty estate, ok=True, confidence 0.0, and a surfaced note —
        # never a crash. ``estate=[]`` deliberately CLEARS stale estate for this scope.
        client = ctx.clients.get(RESOURCE_GRAPH_CLIENT)
        if client is None:
            response = AgentResponse(
                agentName="discovery",
                taskType="classify-estate",
                inputSummary=f"scope={scope or 'subscription'}",
                findings=["No resource_graph client injected; estate not queried"],
                risks=["Discovery ran without an Azure Resource Graph client (fail-closed)"],
                confidence=0.0,
                nextActions=["inject-resource-graph-client"],
            )
            return ModuleRunResult(module=self.name, ok=True, response=response,
                                   estate=[], extra={"nodeCount": 0, "skippedRows": 0})

        arg = cast(ResourceGraphClient, client)
        try:
            rows = arg.query(scope)
        except Exception as exc:  # noqa: BLE001 - any edge failure must fail closed, not crash
            response = AgentResponse(
                agentName="discovery",
                taskType="classify-estate",
                inputSummary=f"scope={scope or 'subscription'}",
                findings=["Azure Resource Graph query failed; estate not updated"],
                risks=[f"ARG query error ({type(exc).__name__}); ran fail-closed"],
                confidence=0.0,
                nextActions=["retry-discovery"],
            )
            return ModuleRunResult(module=self.name, ok=True, response=response,
                                   estate=None, extra={"nodeCount": 0, "skippedRows": 0})

        resources, skipped = rows_to_nodes(list(rows))
        if skipped:
            notes.append(f"Skipped {len(skipped)} malformed row(s)")

        definitions = self._load_definitions(ctx.packs)
        if not definitions:
            notes.append("No Workload Definition packs available; nodes left unclassified")

        classified = classify(resources, definitions)
        classified_count = sum(1 for node in classified if node.workload is not None)
        # Confidence reflects how much of the AUTHORITATIVE ARG estate we could classify; an empty
        # or fully-unclassified estate stays at 0.0 (fail closed, do not over-claim). Kuiper is
        # supplemental only and never inflates this figure.
        confidence = (classified_count / len(classified)) if classified else 0.0

        # Optional Kuiper discovery-assist (issue #47): when a connector is injected AND returns
        # available hints, ANNOTATE matching ARG nodes with a bounded, non-authoritative
        # supplemental tag. It never adds/removes/overrides a node and never emits a graph.
        # Absent/failing-closed ⇒ Discovery behaves EXACTLY as ARG-only (estate + graph unchanged).
        supplemental, kuiper_note = self._kuiper_assist(ctx, classified)
        if kuiper_note:
            notes.append(kuiper_note)
        estate = supplemental.nodes if supplemental is not None else classified

        findings = [f"Classified {classified_count}/{len(classified)} discovered resources"]
        findings.extend(notes)
        response = AgentResponse(
            agentName="discovery",
            taskType="classify-estate",
            inputSummary=f"scope={scope or 'subscription'}",
            findings=findings,
            confidence=confidence,
            nextActions=["build-dependency-graph"],
        )
        extra: dict[str, Any] = {
            "nodeCount": len(estate),
            "classifiedCount": classified_count,
            "skippedRows": len(skipped),
        }
        if supplemental is not None:
            extra["supplementalSignals"] = len(supplemental.annotated_ids)
        # NB: Discovery deliberately does NOT emit a WorkloadGraph — the state writer
        # UPSERT-REPLACES a workload's graph, so a Kuiper-derived graph here would wipe
        # dependency_graph's authoritative edges. Kuiper contributes supplemental estate-node
        # annotations only; a future non-destructive edge integration is owned by dependency_graph.
        return ModuleRunResult(module=self.name, ok=True, response=response,
                               estate=estate, extra=extra)

    def _kuiper_assist(
        self, ctx: ModuleContext, authoritative: list[ResourceNode]
    ) -> tuple[SupplementalResult | None, str | None]:
        """Fetch + apply optional Kuiper supplemental annotations — fail closed to a no-op.

        Returns ``(supplemental, note)`` where ``supplemental`` is a :class:`SupplementalResult`
        only when a Kuiper connector is injected AND returns available hints that annotate at least
        one ARG node; otherwise ``None`` (Discovery then behaves exactly as ARG-only). ``note`` is a
        human-readable surface line, or ``None`` when no connector is wired (so ARG-only output is
        byte-for-byte unchanged). This never raises across the boundary and never lets a Kuiper
        failure break Discovery. Kuiper only ANNOTATES existing ARG nodes — it never adds, removes,
        or overrides a node, and never emits a graph.
        """
        connector = ctx.clients.get(KUIPER_CONNECTOR)
        if connector is None:
            return None, None
        kuiper = cast(KuiperConnector, connector)
        try:
            result = kuiper.fetch_raw()
            hints = hints_from_result(result)
            applied = apply_supplemental(authoritative, hints)
        except Exception as exc:  # noqa: BLE001 - Kuiper is optional assist; never break Discovery
            return None, f"Kuiper assist unavailable ({type(exc).__name__}); estate from ARG only"
        if not result.available:
            return None, "Kuiper assist unavailable (fail-closed); estate from ARG only"
        if not applied.annotated_ids:
            return None, "Kuiper assist returned no usable supplemental hints"
        note = (
            f"Kuiper assist corroborated {len(applied.annotated_ids)} ARG node(s) with "
            "supplemental signals (non-authoritative; ARG authoritative)"
        )
        return applied, note
