"""Contract round-trips and validation."""
import pytest
from pydantic import ValidationError

from shared.contracts import (
    AgentResponse,
    ModuleKind,
    ModuleManifest,
    ScaleProfile,
    SourceReference,
)


def test_agent_response_roundtrip():
    r = AgentResponse(
        agentName="aiops",
        taskType="auto-rca",
        inputSummary="finding=x",
        findings=["latency breach"],
        sourceReferences=[SourceReference(kind="metric", id="odb_latency_ms")],
        confidence=0.8,
        nextActions=["propose-remediation"],
    )
    dumped = r.model_dump()
    again = AgentResponse(**dumped)
    assert again.agentName == "aiops"
    assert again.confidence == 0.8
    assert again.sourceReferences[0].kind == "metric"


def test_confidence_bounds_enforced():
    with pytest.raises(ValidationError):
        AgentResponse(agentName="a", taskType="t", inputSummary="s", confidence=1.5)


def test_module_manifest_scale_profile():
    m = ModuleManifest(
        name="quality_checks",
        displayName="Quality Checks",
        kind=ModuleKind.job,
        scaleProfile=ScaleProfile(kind=ModuleKind.job, minReplicas=0, maxReplicas=30),
    )
    assert m.scaleProfile.maxReplicas == 30
    assert m.enabled is True
