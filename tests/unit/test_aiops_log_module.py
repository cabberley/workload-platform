"""AIOps module wiring tests for log-anomaly detection + enrichment (issue #53, deliverable 3+4).

All fixtures are clearly-fake synthetic data (guardrail 2). These exercise the module ``run`` flow:
log-anomaly findings are fused into the SAME detection→RCA path as metric detections, advisory LLM
enrichment lands in the redact-on-egress ``extra`` surface, and the whole path fails closed (no
log-sample client, or a short baseline) with NO fabricated detection.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from modules.aiops.connectors.log_sample import LogFeatureFetchResult
from modules.aiops.connectors.openai_enrichment import LogAnomalyEnrichment
from modules.aiops.connectors.rca_explanation import RcaExplanation
from modules.aiops.module import AiopsModule
from shared.contracts import (
    AgentResponse,
    DependencyEdge,
    LogFeatures,
    PackType,
    ResourceNode,
    WorkloadGraph,
)
from shared.module_base import ModuleContext

_ODB_NODE = "/subscriptions/00000000/rg/epic/odb-01"
_WEB_NODE = "/subscriptions/00000000/rg/epic/web-01"


class _FakeManifest:
    def __init__(self, pack_id: str, version: str, targets: list[str]) -> None:
        self.id = pack_id
        self.version = version
        self.targets = targets


class _FakePack:
    def __init__(self, manifest: _FakeManifest, body: dict[str, Any]) -> None:
        self.manifest = manifest
        self.body = body


class FakePacks:
    def __init__(self, packs: list[tuple[_FakeManifest, dict[str, Any], PackType]]) -> None:
        self._packs = packs

    def load_for_workload(self, workload: str, pack_type: PackType) -> list[_FakePack]:
        return [
            _FakePack(m, b)
            for m, b, t in self._packs
            if t == pack_type and (not m.targets or workload in m.targets)
        ]


class FakeState:
    def __init__(self, *, estate: list[ResourceNode], graph: WorkloadGraph | None) -> None:
        self._estate = estate
        self._graph = graph

    def list_workloads(self) -> list[str]:
        return ["epic"]

    def get_estate(self, workload: str) -> list[ResourceNode]:
        return self._estate

    def get_graph(self, workload: str) -> WorkloadGraph | None:
        return self._graph


class _FakeLogSample:
    def __init__(self, windows_by_resource: dict[str, list[LogFeatures]]) -> None:
        self._w = windows_by_resource
        self.calls: list[tuple[str, ...]] = []

    def fetch_features(
        self, *, resource_ids: Sequence[str] | None = None
    ) -> LogFeatureFetchResult:
        self.calls.append(tuple(resource_ids or ()))
        return LogFeatureFetchResult(available=True, windowsByResource=self._w)


class _UnavailableLogSample:
    def fetch_features(
        self, *, resource_ids: Sequence[str] | None = None
    ) -> LogFeatureFetchResult:
        return LogFeatureFetchResult(available=False, error="NoCredential")


class _FakeEnrich:
    def __init__(self) -> None:
        self.seen: list[LogFeatures] = []

    def enrich(self, features: LogFeatures) -> LogAnomalyEnrichment:
        self.seen.append(features)
        return LogAnomalyEnrichment(available=True, advisory="synthetic advisory")


def _estate() -> list[ResourceNode]:
    return [
        ResourceNode(id=_ODB_NODE, name="odb-01", type="epic/odb", workload="epic", role="odb"),
        ResourceNode(id=_WEB_NODE, name="web-01", type="epic/web", workload="epic", role="web"),
    ]


def _graph() -> WorkloadGraph:
    return WorkloadGraph(
        nodes=_estate(), edges=[DependencyEdge(source=_WEB_NODE, target=_ODB_NODE)]
    )


def _feat(error_rate: float) -> LogFeatures:
    return LogFeatures(
        totalCount=100, countsByLevel={}, errorRate=error_rate, warnRate=0.0,
        distinctTemplateCount=5, topTemplates=[], durationSampleCount=0,
    )


def _anomaly_pack() -> tuple[_FakeManifest, dict[str, Any], PackType]:
    body = {
        "signals": [],
        "logAnalysis": {
            "anomaly": {
                "nodeId": "role:odb",
                "minBaseline": 5,
                "method": "mad",
                "features": [
                    {
                        "feature": "errorRate",
                        "direction": "up",
                        "bands": [
                            {"z": 3.5, "severity": "medium"},
                            {"z": 6.0, "severity": "high"},
                        ],
                        "advisoryZScore": 2.0,
                    }
                ],
            }
        },
    }
    return (_FakeManifest("synthetic-log-anomaly", "0.1.0", ["epic"]), body, PackType.telemetry)


def _baseline_and_spike() -> dict[str, list[LogFeatures]]:
    windows = [_feat(0.010 + 0.001 * i) for i in range(8)]
    windows.append(_feat(0.5))  # current window — massively elevated
    return {_ODB_NODE: windows}


def test_log_anomaly_finding_fused_into_detection_path() -> None:
    packs = FakePacks([_anomaly_pack()])
    state = FakeState(estate=_estate(), graph=_graph())
    log_sample = _FakeLogSample(_baseline_and_spike())
    ctx = ModuleContext(
        packs=packs, state=state, clients={"log_sample": log_sample}
    )
    result = AiopsModule().run(ctx, scope={"workload": "epic"})

    assert result.ok is True
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.id.startswith("detect::log::synthetic-log-anomaly::errorRate::")
    assert f.nodeId == _ODB_NODE
    assert f.blastRadius == 1  # web depends on odb → blast radius applied
    assert f.packId == "synthetic-log-anomaly"
    # The detection drives the auto-RCA path.
    assert result.response is not None
    assert result.response.nextActions == ["auto-rca"]
    # Only the watched node's id was requested from the edge (role→node resolution).
    assert log_sample.calls == [(_ODB_NODE,)]


def test_enrichment_lands_in_extra_and_receives_only_aggregate_features() -> None:
    packs = FakePacks([_anomaly_pack()])
    state = FakeState(estate=_estate(), graph=_graph())
    log_sample = _FakeLogSample(_baseline_and_spike())
    enrich = _FakeEnrich()
    ctx = ModuleContext(
        packs=packs,
        state=state,
        clients={"log_sample": log_sample, "llm_enrichment": enrich},
    )
    result = AiopsModule().run(ctx, scope={"workload": "epic"})

    entries = result.extra["logAnomalyEnrichment"]
    assert entries == [{"nodeId": _ODB_NODE, "advisory": "synthetic advisory"}]
    # The enrichment client only ever received the aggregate LogFeatures contract.
    assert len(enrich.seen) == 1
    assert isinstance(enrich.seen[0], LogFeatures)


def test_no_log_sample_client_fails_closed_with_note_and_no_detection() -> None:
    packs = FakePacks([_anomaly_pack()])
    state = FakeState(estate=_estate(), graph=_graph())
    ctx = ModuleContext(packs=packs, state=state, clients={})
    result = AiopsModule().run(ctx, scope={"workload": "epic"})

    assert result.findings == []
    notes = result.extra["surfacedNotes"]
    assert any("log-sample source unavailable" in n for n in notes)


def test_unavailable_edge_fails_closed() -> None:
    packs = FakePacks([_anomaly_pack()])
    state = FakeState(estate=_estate(), graph=_graph())
    ctx = ModuleContext(
        packs=packs, state=state, clients={"log_sample": _UnavailableLogSample()}
    )
    result = AiopsModule().run(ctx, scope={"workload": "epic"})
    assert result.findings == []
    assert any("log-sample edge unavailable" in n for n in result.extra["surfacedNotes"])


def test_short_baseline_yields_no_detection_in_module() -> None:
    packs = FakePacks([_anomaly_pack()])
    state = FakeState(estate=_estate(), graph=_graph())
    # Only 2 windows total → baseline of 1 < minBaseline 5.
    log_sample = _FakeLogSample({_ODB_NODE: [_feat(0.01), _feat(0.5)]})
    ctx = ModuleContext(
        packs=packs, state=state, clients={"log_sample": log_sample}
    )
    result = AiopsModule().run(ctx, scope={"workload": "epic"})
    assert result.findings == []
    assert any("minBaseline" in n for n in result.extra["surfacedNotes"])


def test_unconfigured_enrichment_does_not_break_pure_result() -> None:
    """With enrichment UNCONFIGURED (None config), the pure statistical finding still stands."""
    packs = FakePacks([_anomaly_pack()])
    state = FakeState(estate=_estate(), graph=_graph())
    log_sample = _FakeLogSample(_baseline_and_spike())
    unconfigured = OpenAIEnrichmentClientUnconfigured()
    ctx = ModuleContext(
        packs=packs,
        state=state,
        clients={"log_sample": log_sample, "llm_enrichment": unconfigured},
    )
    result = AiopsModule().run(ctx, scope={"workload": "epic"})
    assert len(result.findings) == 1  # pure result unaffected
    assert result.extra["logAnomalyEnrichment"] == []  # no-op enrichment contributes nothing


class OpenAIEnrichmentClientUnconfigured:
    """A stand-in for an UNCONFIGURED enrichment client (always no-ops)."""

    def enrich(self, features: LogFeatures) -> LogAnomalyEnrichment:
        return LogAnomalyEnrichment(available=False, error="Unconfigured")


class _FakeRcaExplain:
    """A stand-in grounded RCA-explanation client — returns a fixed advisory (issue #54)."""

    def __init__(self, *, available: bool = True) -> None:
        self._available = available
        self.seen: list[Any] = []

    def explain(self, response: Any) -> Any:
        self.seen.append(response)
        return RcaExplanation(
            available=self._available,
            advisory="synthetic grounded advisory" if self._available else None,
            grounded=self._available,
        )


def test_rca_explanation_lands_in_extra_aligned_with_rca() -> None:
    packs = FakePacks([_anomaly_pack()])
    state = FakeState(estate=_estate(), graph=_graph())
    log_sample = _FakeLogSample(_baseline_and_spike())
    explain = _FakeRcaExplain()
    ctx = ModuleContext(
        packs=packs,
        state=state,
        clients={"log_sample": log_sample, "rca_explanation": explain},
    )
    result = AiopsModule().run(ctx, scope={"workload": "epic"})

    rca = result.extra["rca"]
    entries = result.extra["rcaExplanation"]
    assert len(rca) >= 1
    # One advisory per RCA response, index-aligned with extra["rca"].
    assert len(entries) == len(rca)
    assert all(e == {"advisory": "synthetic grounded advisory"} for e in entries)
    # The edge only ever received the analytical AgentResponse (never raw estate/log data).
    assert len(explain.seen) == len(rca)
    assert all(isinstance(r, AgentResponse) for r in explain.seen)


def test_rca_explanation_absent_leaves_pure_result() -> None:
    packs = FakePacks([_anomaly_pack()])
    state = FakeState(estate=_estate(), graph=_graph())
    log_sample = _FakeLogSample(_baseline_and_spike())
    ctx = ModuleContext(packs=packs, state=state, clients={"log_sample": log_sample})
    result = AiopsModule().run(ctx, scope={"workload": "epic"})
    # No edge configured ⇒ empty advisory list (the no-op IS the off state of the flag).
    assert result.extra["rcaExplanation"] == []
    assert len(result.extra["rca"]) >= 1


def test_rca_explanation_no_op_client_yields_empty_advisories() -> None:
    packs = FakePacks([_anomaly_pack()])
    state = FakeState(estate=_estate(), graph=_graph())
    log_sample = _FakeLogSample(_baseline_and_spike())
    explain = _FakeRcaExplain(available=False)
    ctx = ModuleContext(
        packs=packs,
        state=state,
        clients={"log_sample": log_sample, "rca_explanation": explain},
    )
    result = AiopsModule().run(ctx, scope={"workload": "epic"})
    entries = result.extra["rcaExplanation"]
    assert len(entries) == len(result.extra["rca"])
    assert all(e == {"advisory": ""} for e in entries)
