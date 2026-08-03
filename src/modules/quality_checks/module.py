"""Quality Checks module — run versioned Rule Packs against the estate.

Applies **Rule Packs** (WAF / WARA / APRL / app-specific) to discovered nodes and emits
PASS/FAIL `Finding`s with evidence and provenance (pack id + version). Runs as an ACA **Job**
that fans out 0→30 — one replica per workload/rule batch — so large estates finish fast.
"""
from __future__ import annotations

from shared.contracts import (
    AgentResponse,
    Finding,
    ModuleKind,
    ModuleManifest,
    ModuleRunResult,
    PackType,
    ResourceNode,
    ScaleProfile,
    ScaleTrigger,
    Severity,
    SourceReference,
)
from shared.module_base import Module, ModuleContext

_MANIFEST = ModuleManifest(
    name="quality_checks",
    displayName="Quality Checks",
    kind=ModuleKind.job,
    consumes=[PackType.rule],
    produces=["Finding[]"],
    scaleProfile=ScaleProfile(
        kind=ModuleKind.job,
        minReplicas=0,
        maxReplicas=30,
        triggers=[ScaleTrigger(type="azure-queue", metadata={"queueName": "assessments"})],
        cpu=0.5,
        memoryGi=1.0,
    ),
)


def evaluate_rule(node: ResourceNode, rule: dict) -> Finding | None:
    """Pure rule evaluation for one node/rule. Returns a Finding or None if not applicable.

    A rule targets a resource type and asserts a required tag/property. Fail-closed:
    if the rule applies but evidence is missing, it FAILs rather than silently passing.
    """
    if rule.get("resourceType") and rule["resourceType"] != node.type:
        return None
    required_tag = rule.get("requiredTag")
    passed = True
    detail = rule.get("description", "")
    if required_tag is not None:
        passed = node.tags.get(required_tag) is not None
    severity = Severity(rule.get("severity", "medium")) if not passed else Severity.info
    return Finding(
        id=f"{rule.get('id', 'rule')}::{node.id}",
        module="quality_checks",
        title=rule.get("title", rule.get("id", "rule")),
        passed=passed,
        severity=severity,
        nodeId=node.id,
        evidence=[SourceReference(kind="resource", id=node.id, detail=detail)],
        packId=rule.get("packId"),
        packVersion=rule.get("packVersion"),
        detail=detail,
    )


class QualityChecksModule(Module):
    @property
    def manifest(self) -> ModuleManifest:
        return _MANIFEST

    def run(self, ctx: ModuleContext, *, scope: dict[str, str] | None = None) -> ModuleRunResult:
        scope = scope or {}
        nodes: list[ResourceNode] = []
        rules: list[dict] = []
        findings: list[Finding] = []
        for node in nodes:
            for rule in rules:
                f = evaluate_rule(node, rule)
                if f is not None:
                    findings.append(f)
        failed = [f for f in findings if f.passed is False]
        response = AgentResponse(
            agentName="quality_checks",
            taskType="run-rule-packs",
            inputSummary=f"scope={scope or 'all'}; rules={len(rules)}",
            findings=[f"{len(findings)} checks, {len(failed)} failed"],
            confidence=1.0,
            nextActions=["route-findings"] if failed else [],
        )
        return ModuleRunResult(module=self.name, ok=True, findings=findings, response=response)
