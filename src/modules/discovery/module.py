"""Discovery module — classify the estate into workload → tier → role.

Reads the estate (Azure Resource Graph at the edge; Kuiper assist optional) and applies
**Workload Definition Packs** to label nodes. Output feeds the dependency and quality modules.
Runs as an ACA **Job** (bursty, periodic) that scales 0→10.
"""
from __future__ import annotations

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
        for d in definitions:
            if d.get("resourceType") and d["resourceType"] != node.type:
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


class DiscoveryModule(Module):
    @property
    def manifest(self) -> ModuleManifest:
        return _MANIFEST

    def run(self, ctx: ModuleContext, *, scope: dict[str, str] | None = None) -> ModuleRunResult:
        scope = scope or {}
        # Edge I/O (ARG/Kuiper) is injected via ctx in real runs; skeleton returns an empty estate.
        resources: list[ResourceNode] = []
        definitions: list[dict] = []
        classified = classify(resources, definitions)
        response = AgentResponse(
            agentName="discovery",
            taskType="classify-estate",
            inputSummary=f"scope={scope or 'subscription'}",
            findings=[f"Classified {len(classified)} resources"],
            confidence=1.0 if classified else 0.0,
            nextActions=["build-dependency-graph"],
        )
        return ModuleRunResult(module=self.name, ok=True, response=response,
                               extra={"nodeCount": len(classified)})
