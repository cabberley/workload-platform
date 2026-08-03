"""AIOps module tests — pure fusion, RCA gating, and the fail-closed Azure Monitor edge.

All fixtures are clearly-fake synthetic data (guardrail 2). The module reads a read-only
``ReadableState`` view and telemetry via injected edge clients; these tests inject fakes so they
stay Azure- and network-free. Detection is advisory only — no state is ever written.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import pytest

from modules.aiops.connectors.azure_monitor import (
    AzureMonitorClient,
    AzureMonitorConfig,
    AzureMonitorSdkNotWired,
    map_metrics_response,
)
from modules.aiops.connectors.azure_monitor import to_signals as azure_monitor_to_signals
from modules.aiops.connectors.system_pulse import FetchResult, Signal
from modules.aiops.module import (
    RCA_CONFIDENCE_FLOOR,
    AiopsModule,
    correlate_rca,
    detect_metric_breach,
    fuse_detections,
    load_telemetry_rules,
)
from shared.contracts import (
    DependencyEdge,
    Finding,
    PackType,
    ResourceNode,
    WorkloadGraph,
)
from shared.module_base import ModuleContext

_ODB_NODE = "/subscriptions/00000000/rg/epic/odb-01"
_WEB_NODE = "/subscriptions/00000000/rg/epic/web-01"


# --------------------------------------------------------------------------------------
# Synthetic fakes — packs, state, telemetry source
# --------------------------------------------------------------------------------------
class _FakeManifest:
    def __init__(self, pack_id: str, version: str, targets: list[str]) -> None:
        self.id = pack_id
        self.version = version
        self.targets = targets


class _FakePack:
    def __init__(self, manifest: _FakeManifest, body: dict[str, Any]) -> None:
        self.manifest = manifest
        self.body = body


class FakePacksTargetAware:
    """Packs engine that honours ``manifest.targets`` (mirrors the real engine's filtering)."""

    def __init__(self, packs: list[tuple[_FakeManifest, dict[str, Any], PackType]]) -> None:
        self._packs = packs

    def load_for_workload(self, workload: str, pack_type: PackType) -> list[_FakePack]:
        out: list[_FakePack] = []
        for manifest, body, ptype in self._packs:
            if ptype != pack_type:
                continue
            if manifest.targets and workload not in manifest.targets:
                continue
            out.append(_FakePack(manifest, body))
        return out


def _telemetry_pack(
    *,
    pack_id: str = "system-pulse-core",
    version: str = "1.0.0",
    targets: list[str] | None = None,
    signals: list[dict[str, Any]],
) -> tuple[_FakeManifest, dict[str, Any], PackType]:
    return (
        _FakeManifest(pack_id, version, targets if targets is not None else ["epic"]),
        {"signals": signals},
        PackType.telemetry,
    )


class FakeState:
    """Read-only ``ReadableState`` over one synthetic workload. Records any write attempt."""

    def __init__(
        self,
        *,
        workload: str,
        estate: list[ResourceNode],
        graph: WorkloadGraph | None,
    ) -> None:
        self._workload = workload
        self._estate = estate
        self._graph = graph
        self.writes: list[str] = []

    def list_workloads(self) -> list[str]:
        return [self._workload]

    def get_estate(self, workload: str) -> list[ResourceNode]:
        return self._estate if workload == self._workload else []

    def get_graph(self, workload: str) -> WorkloadGraph | None:
        return self._graph if workload == self._workload else None

    # Any accidental write surface is recorded so the single-writer test can assert none happened.
    def __getattr__(self, name: str) -> Any:
        if name.startswith(("put_", "commit_", "add_", "set_", "write_", "save_", "delete_")):
            def _recorder(*args: Any, **kwargs: Any) -> None:
                self.writes.append(name)

            return _recorder
        raise AttributeError(name)


class FakeSignalSource:
    """A telemetry edge client returning a fixed ``FetchResult`` (System-Pulse-shaped raw)."""

    def __init__(self, result: FetchResult) -> None:
        self._result = result
        self.calls: list[tuple[str, ...]] = []

    def fetch_raw(self, *, metric_names: Sequence[str] | None = None) -> FetchResult:
        self.calls.append(tuple(metric_names or ()))
        return self._result


def _sp_raw(metric: str, value: float, resource_id: str) -> dict[str, Any]:
    return {
        "metric": metric,
        "value": value,
        "unit": "ms",
        "timestamp": "2026-08-03T04:00:00Z",
        "resourceId": resource_id,
    }


def _odb_estate() -> list[ResourceNode]:
    return [
        ResourceNode(id=_ODB_NODE, name="odb-01", type="epic/odb", workload="epic", role="odb"),
        ResourceNode(id=_WEB_NODE, name="web-01", type="epic/web", workload="epic", role="web"),
    ]


def _pulse_source(*raws: dict[str, Any]) -> FakeSignalSource:
    return FakeSignalSource(FetchResult(available=True, raw=list(raws)))


# --------------------------------------------------------------------------------------
# load_telemetry_rules — parsing + fail-closed validation
# --------------------------------------------------------------------------------------
def test_load_telemetry_rules_parses_valid_signal() -> None:
    packs = FakePacksTargetAware(
        [_telemetry_pack(signals=[
            {"name": "odb_latency_ms", "op": "gt", "threshold": 500,
             "severity": "high", "nodeId": "role:odb"},
        ])]
    )
    rules, notes = load_telemetry_rules(packs, "epic")
    assert notes == []
    assert len(rules) == 1
    rule = rules[0]
    assert rule["name"] == "odb_latency_ms"
    assert rule["op"] == "gt"
    assert rule["threshold"] == pytest.approx(500.0)
    assert rule["role"] == "odb"
    assert rule["packId"] == "system-pulse-core"
    assert rule["packVersion"] == "1.0.0"


@pytest.mark.parametrize(
    "bad_signal",
    [
        {"name": "m", "op": "between", "threshold": 1, "severity": "high", "nodeId": "role:odb"},
        {"name": "m", "op": "gt", "threshold": "high", "severity": "high", "nodeId": "role:odb"},
        {"name": "m", "op": "gt", "threshold": True, "severity": "high", "nodeId": "role:odb"},
        {"name": "m", "op": "gt", "threshold": 1, "severity": "apocalyptic", "nodeId": "role:odb"},
        {"name": "m", "op": "gt", "threshold": [1, 2], "severity": "high", "nodeId": "role:odb"},
        {"name": "m", "op": "gt", "threshold": 1, "severity": "high", "nodeId": "odb"},
        "not-a-mapping",
    ],
)
def test_load_telemetry_rules_skips_and_surfaces_malformed(bad_signal: Any) -> None:
    packs = FakePacksTargetAware([_telemetry_pack(signals=[bad_signal])])
    rules, notes = load_telemetry_rules(packs, "epic")
    assert rules == []  # never a silent detection from a malformed entry
    assert len(notes) == 1  # surfaced, not swallowed


def test_load_telemetry_rules_none_packs_is_empty() -> None:
    assert load_telemetry_rules(None, "epic") == ([], [])


def test_load_telemetry_rules_non_list_signals_surfaced() -> None:
    manifest = _FakeManifest("bad-pack", "1.0.0", ["epic"])
    packs = FakePacksTargetAware([(manifest, {"signals": {"not": "a list"}}, PackType.telemetry)])
    rules, notes = load_telemetry_rules(packs, "epic")
    assert rules == []
    assert notes and "not a list" in notes[0]


# --------------------------------------------------------------------------------------
# fuse_detections — pure fusion of rules × observed signals
# --------------------------------------------------------------------------------------
def _rule(**over: Any) -> dict[str, Any]:
    base = {
        "name": "odb_latency_ms", "op": "gt", "threshold": 500.0,
        "severity": "high", "role": "odb", "packId": "system-pulse-core", "packVersion": "1.0.0",
    }
    base.update(over)
    return base


def _signal(
    metric: str, value: float, resource_id: str, *, timestamp: str = "2026-08-03T04:00:00Z"
) -> Signal:
    return Signal(
        metric=metric, value=value, unit="ms",
        timestamp=timestamp, resourceId=resource_id,  # type: ignore[arg-type]
    )


def test_fuse_happy_path_one_detection_on_resolved_node() -> None:
    findings = fuse_detections(
        [_rule()],
        [_signal("odb_latency_ms", 512.0, _ODB_NODE)],
        _odb_estate(),
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.passed is False
    assert finding.nodeId == _ODB_NODE  # resolved from role:odb to the estate node id
    assert finding.packId == "system-pulse-core"
    assert finding.packVersion == "1.0.0"
    assert finding.evidence and finding.evidence[0].id == "odb_latency_ms"


def test_fuse_no_breach_no_detection() -> None:
    findings = fuse_detections(
        [_rule()],
        [_signal("odb_latency_ms", 142.0, _ODB_NODE)],  # below 500 threshold
        _odb_estate(),
    )
    assert findings == []


def test_fuse_signal_on_unselected_node_is_ignored() -> None:
    # Signal exceeds threshold but sits on the web node, which the role:odb rule doesn't select.
    findings = fuse_detections(
        [_rule()],
        [_signal("odb_latency_ms", 999.0, _WEB_NODE)],
        _odb_estate(),
    )
    assert findings == []


def test_fuse_unknown_role_selects_nothing() -> None:
    findings = fuse_detections(
        [_rule(role="does-not-exist")],
        [_signal("odb_latency_ms", 999.0, _ODB_NODE)],
        _odb_estate(),
    )
    assert findings == []


# --------------------------------------------------------------------------------------
# correlate_rca — confidence gating (advisory only)
# --------------------------------------------------------------------------------------
def _detection(node_id: str) -> Finding:
    return detect_metric_breach(
        {"name": "odb_latency_ms", "value": 512.0, "op": "gt",
         "threshold": 500.0, "nodeId": node_id, "severity": "high"}
    )  # type: ignore[return-value]


def test_rca_high_confidence_when_blast_radius_positive() -> None:
    rca = correlate_rca(_detection(_ODB_NODE), {_ODB_NODE: 3})
    assert rca.confidence >= RCA_CONFIDENCE_FLOOR
    assert rca.nextActions == ["propose-remediation"]
    assert "root cause" in rca.recommendations[0].lower()


def test_rca_low_confidence_recommends_support_when_no_graph() -> None:
    rca = correlate_rca(_detection(_ODB_NODE), {})  # empty/None graph ⇒ radius 0
    assert rca.confidence < RCA_CONFIDENCE_FLOOR
    assert rca.nextActions == ["recommend-contact-support"]
    # Advisory only — never proposes an auto-applied remediation.
    assert "propose-remediation" not in rca.nextActions


# --------------------------------------------------------------------------------------
# AiopsModule.run — end-to-end fusion over injected fakes
# --------------------------------------------------------------------------------------
def _graph_with_dependent() -> WorkloadGraph:
    return WorkloadGraph(
        nodes=_odb_estate(),
        edges=[DependencyEdge(source=_WEB_NODE, target=_ODB_NODE)],  # web depends on odb
    )


def test_run_fusion_happy_path_detection_and_rca() -> None:
    packs = FakePacksTargetAware(
        [_telemetry_pack(signals=[
            {"name": "odb_latency_ms", "op": "gt", "threshold": 500,
             "severity": "high", "nodeId": "role:odb"},
        ])]
    )
    state = FakeState(workload="epic", estate=_odb_estate(), graph=_graph_with_dependent())
    clients = {"system_pulse": _pulse_source(_sp_raw("odb_latency_ms", 512.0, _ODB_NODE))}
    ctx = ModuleContext(packs=packs, state=state, clients=clients)

    result = AiopsModule().run(ctx, scope={"workload": "epic"})

    assert result.ok is True
    assert len(result.findings) == 1
    detection = result.findings[0]
    assert detection.nodeId == _ODB_NODE
    assert detection.blastRadius == 1  # web depends on odb
    assert result.response is not None
    assert result.response.taskType == "proactive-detect"
    assert result.response.nextActions == ["auto-rca"]
    # RCA is high-confidence because odb has a positive blast radius.
    rca = result.extra["rca"]
    assert len(rca) == 1
    assert rca[0]["confidence"] >= RCA_CONFIDENCE_FLOOR
    assert rca[0]["nextActions"] == ["propose-remediation"]
    assert result.extra["sourcesUnavailable"] == ["azure_monitor"]
    assert result.extra["packSources"][0]["id"] == "system-pulse-core"


def test_run_no_breach_yields_no_detection() -> None:
    packs = FakePacksTargetAware(
        [_telemetry_pack(signals=[
            {"name": "odb_latency_ms", "op": "gt", "threshold": 500,
             "severity": "high", "nodeId": "role:odb"},
        ])]
    )
    state = FakeState(workload="epic", estate=_odb_estate(), graph=None)
    clients = {"system_pulse": _pulse_source(_sp_raw("odb_latency_ms", 100.0, _ODB_NODE))}
    result = AiopsModule().run(ModuleContext(packs=packs, state=state, clients=clients))
    assert result.findings == []
    assert result.response is not None
    assert result.response.nextActions == []
    assert result.extra["rca"] == []


def test_run_source_absent_is_surfaced_no_fabrication() -> None:
    packs = FakePacksTargetAware(
        [_telemetry_pack(signals=[
            {"name": "odb_latency_ms", "op": "gt", "threshold": 500,
             "severity": "high", "nodeId": "role:odb"},
        ])]
    )
    state = FakeState(workload="epic", estate=_odb_estate(), graph=None)
    # No telemetry clients at all — both well-known sources are unavailable.
    result = AiopsModule().run(ModuleContext(packs=packs, state=state, clients={}))
    assert result.findings == []
    assert sorted(result.extra["sourcesUnavailable"]) == ["azure_monitor", "system_pulse"]
    assert any("no telemetry observed" in n for n in result.extra["surfacedNotes"])


def test_run_source_unavailable_fetch_is_surfaced() -> None:
    packs = FakePacksTargetAware(
        [_telemetry_pack(signals=[
            {"name": "odb_latency_ms", "op": "gt", "threshold": 500,
             "severity": "high", "nodeId": "role:odb"},
        ])]
    )
    state = FakeState(workload="epic", estate=_odb_estate(), graph=None)
    down = FakeSignalSource(FetchResult(available=False, error="ConnectError"))
    result = AiopsModule().run(
        ModuleContext(packs=packs, state=state, clients={"system_pulse": down})
    )
    assert result.findings == []
    assert "system_pulse" in result.extra["sourcesUnavailable"]


def test_run_target_aware_epic_pack_does_not_detect_for_sap() -> None:
    # An epic-targeted telemetry pack must not produce detections for a sap workload.
    packs = FakePacksTargetAware(
        [_telemetry_pack(targets=["epic"], signals=[
            {"name": "odb_latency_ms", "op": "gt", "threshold": 500,
             "severity": "high", "nodeId": "role:odb"},
        ])]
    )
    sap_estate = [
        ResourceNode(id="/sub/rg/sap/hana-01", name="hana-01", type="sap/hana",
                     workload="sap", role="odb"),
    ]
    state = FakeState(workload="sap", estate=sap_estate, graph=None)
    clients = {
        "system_pulse": _pulse_source(_sp_raw("odb_latency_ms", 999.0, "/sub/rg/sap/hana-01"))
    }
    result = AiopsModule().run(ModuleContext(packs=packs, state=state, clients=clients))
    assert result.findings == []  # epic pack filtered out for the sap workload


def test_run_fails_closed_with_no_state() -> None:
    result = AiopsModule().run(ModuleContext(packs=None, state=None, clients={}))
    assert result.ok is True
    assert result.findings == []
    assert result.response is not None
    assert result.response.nextActions == []
    assert any("state unavailable" in n for n in result.extra["surfacedNotes"])


def test_run_packs_unavailable_is_surfaced() -> None:
    state = FakeState(workload="epic", estate=_odb_estate(), graph=None)
    result = AiopsModule().run(ModuleContext(packs=None, state=state, clients={}))
    assert result.findings == []
    assert any("packs engine unavailable" in n for n in result.extra["surfacedNotes"])


def test_run_low_confidence_rca_when_graph_missing() -> None:
    packs = FakePacksTargetAware(
        [_telemetry_pack(signals=[
            {"name": "odb_latency_ms", "op": "gt", "threshold": 500,
             "severity": "high", "nodeId": "role:odb"},
        ])]
    )
    state = FakeState(workload="epic", estate=_odb_estate(), graph=None)  # no graph ⇒ radius 0
    clients = {"system_pulse": _pulse_source(_sp_raw("odb_latency_ms", 512.0, _ODB_NODE))}
    result = AiopsModule().run(ModuleContext(packs=packs, state=state, clients=clients))
    assert len(result.findings) == 1
    rca = result.extra["rca"][0]
    assert rca["confidence"] < RCA_CONFIDENCE_FLOOR
    assert rca["nextActions"] == ["recommend-contact-support"]


def test_run_performs_no_state_writes() -> None:
    packs = FakePacksTargetAware(
        [_telemetry_pack(signals=[
            {"name": "odb_latency_ms", "op": "gt", "threshold": 500,
             "severity": "high", "nodeId": "role:odb"},
        ])]
    )
    state = FakeState(workload="epic", estate=_odb_estate(), graph=_graph_with_dependent())
    clients = {"system_pulse": _pulse_source(_sp_raw("odb_latency_ms", 512.0, _ODB_NODE))}
    AiopsModule().run(ModuleContext(packs=packs, state=state, clients=clients))
    assert state.writes == []  # single-writer: the module never writes shared state


# --------------------------------------------------------------------------------------
# Azure Monitor edge — pure mapper + fail-closed client (no real SDK / network)
# --------------------------------------------------------------------------------------
def _am_payload(resource_id: str, metric: str, values: list[float]) -> dict[str, Any]:
    return {
        "resourceId": resource_id,
        "metrics": [
            {
                "name": metric,
                "unit": "Milliseconds",
                "timeseries": [
                    {"data": [
                        {"timeStamp": "2026-08-03T04:00:00Z", "average": v} for v in values
                    ]}
                ],
            }
        ],
    }


def test_azure_monitor_mapper_flattens_payload_to_signals() -> None:
    signals = map_metrics_response(_am_payload(_ODB_NODE, "odb_latency_ms", [512.0, 540.0]))
    assert [s.value for s in signals] == [pytest.approx(512.0), pytest.approx(540.0)]
    assert all(s.metric == "odb_latency_ms" for s in signals)
    assert all(s.resourceId == _ODB_NODE for s in signals)


def test_azure_monitor_mapper_prefers_available_aggregation_and_skips_null() -> None:
    payload = {
        "resourceId": _ODB_NODE,
        "metrics": [{
            "name": "odb_latency_ms", "unit": "ms",
            "timeseries": [{"data": [
                {"timeStamp": "2026-08-03T04:00:00Z", "average": None, "maximum": 700.0},
                {"timeStamp": "2026-08-03T04:01:00Z", "average": None, "total": None},  # dropped
            ]}],
        }],
    }
    signals = map_metrics_response(payload)
    assert len(signals) == 1
    assert signals[0].value == pytest.approx(700.0)


@pytest.mark.parametrize("payload", [None, {}, {"metrics": "nope"}, {"metrics": [1, 2]}, 42])
def test_azure_monitor_mapper_is_total_on_bad_shapes(payload: Any) -> None:
    assert map_metrics_response(payload) == []  # never raises, never fabricates


class FakeMetricsBackend:
    """Injected backend returning synthetic normalized payloads (no SDK)."""

    def __init__(self, payloads: list[dict[str, Any]]) -> None:
        self._payloads = payloads

    def query_metrics(
        self, *, resource_ids: Sequence[str], metric_names: Sequence[str],
        credential: Any, timeout_s: float,
    ) -> list[dict[str, Any]]:
        return self._payloads


class RaisingBackend:
    def query_metrics(self, **_: Any) -> list[dict[str, Any]]:
        raise RuntimeError("super-secret-token-value")


def test_azure_monitor_client_success_returns_signals() -> None:
    backend = FakeMetricsBackend([_am_payload(_ODB_NODE, "odb_latency_ms", [512.0])])
    client = AzureMonitorClient(
        AzureMonitorConfig(resource_ids=[_ODB_NODE], metric_names=["odb_latency_ms"]),
        credential_provider=lambda: object(),  # keyless credential stand-in
        backend=backend,
    )
    result = client.fetch_raw()
    assert result.available is True
    signals = azure_monitor_to_signals(result)
    assert len(signals) == 1
    assert signals[0].value == pytest.approx(512.0)


def test_azure_monitor_client_no_credential_fails_closed_without_query() -> None:
    called = {"n": 0}

    class _Guard:
        def query_metrics(self, **_: Any) -> list[dict[str, Any]]:
            called["n"] += 1
            return []

    client = AzureMonitorClient(
        AzureMonitorConfig(resource_ids=[_ODB_NODE]),
        credential_provider=lambda: None,  # no credential resolves
        backend=_Guard(),
    )
    result = client.fetch_raw()
    assert result.available is False
    assert result.error == "NoCredential"
    assert called["n"] == 0  # no query attempted


def test_azure_monitor_client_backend_error_fails_closed_class_name_only() -> None:
    client = AzureMonitorClient(
        AzureMonitorConfig(resource_ids=[_ODB_NODE]),
        credential_provider=lambda: object(),
        backend=RaisingBackend(),
    )
    result = client.fetch_raw()
    assert result.available is False
    assert result.error == "RuntimeError"  # class name only — no message, no token


def test_azure_monitor_client_failing_credential_provider_fails_closed() -> None:
    def boom() -> object | None:
        raise ValueError("super-secret-token-value")

    client = AzureMonitorClient(
        AzureMonitorConfig(resource_ids=[_ODB_NODE]),
        credential_provider=boom,
    )
    result = client.fetch_raw()
    assert result.available is False
    assert result.error == "ValueError"


def test_azure_monitor_client_fuses_into_module_detection() -> None:
    # Azure Monitor as the sole telemetry source still drives a detection through run().
    packs = FakePacksTargetAware(
        [_telemetry_pack(signals=[
            {"name": "odb_latency_ms", "op": "gt", "threshold": 500,
             "severity": "high", "nodeId": "role:odb"},
        ])]
    )
    state = FakeState(workload="epic", estate=_odb_estate(), graph=_graph_with_dependent())
    am_client = AzureMonitorClient(
        AzureMonitorConfig(resource_ids=[_ODB_NODE], metric_names=["odb_latency_ms"]),
        credential_provider=lambda: object(),
        backend=FakeMetricsBackend([_am_payload(_ODB_NODE, "odb_latency_ms", [777.0])]),
    )
    ctx = ModuleContext(packs=packs, state=state, clients={"azure_monitor": am_client})
    result = AiopsModule().run(ctx, scope={"workload": "epic"})
    assert len(result.findings) == 1
    assert result.findings[0].nodeId == _ODB_NODE
    assert result.extra["sourcesUnavailable"] == ["system_pulse"]


# --------------------------------------------------------------------------------------
# FIX 1 — real SDK backend is an explicit fail-closed stub (not a misleading AttributeError)
# --------------------------------------------------------------------------------------
def test_default_sdk_backend_fails_closed_with_descriptive_error() -> None:
    # The default (real) backend is not wired to the installed SDK; it must fail closed with a
    # descriptive error class name — never a misleading AttributeError against a missing client.
    client = AzureMonitorClient(
        AzureMonitorConfig(resource_ids=[_ODB_NODE], metric_names=["odb_latency_ms"]),
        credential_provider=lambda: object(),  # credential resolves, so the backend is invoked
    )
    result = client.fetch_raw()
    assert result.available is False
    assert result.error == "AzureMonitorSdkNotWired"
    assert azure_monitor_to_signals(result) == []


def test_sdk_path_via_mocked_sdk_object_drives_pure_mapper() -> None:
    # Prove the *real* code path (a backend querying an SDK-shaped client) through to the pure
    # mapper, using a mocked SDK object — no network, no real azure-monitor-query metrics client.
    class _FakePoint:
        def __init__(self, average: float) -> None:
            self.timestamp = "2026-08-03T04:00:00Z"
            self.average = average
            self.total = self.maximum = self.minimum = self.count = None

    class _FakeSeries:
        def __init__(self, averages: list[float]) -> None:
            self.data = [_FakePoint(a) for a in averages]

    class _FakeMetric:
        def __init__(self) -> None:
            self.name = "odb_latency_ms"
            self.unit = "Milliseconds"
            self.timeseries = [_FakeSeries([512.0, 540.0])]

    class _FakeMetricsResult:
        def __init__(self) -> None:
            self.metrics = [_FakeMetric()]

    class _SdkShapedBackend:
        """A backend that calls an injected SDK-shaped client and normalizes via the real helper."""

        def query_metrics(
            self, *, resource_ids: Sequence[str], metric_names: Sequence[str],
            credential: Any, timeout_s: float,
        ) -> list[dict[str, Any]]:
            from modules.aiops.connectors.azure_monitor import _normalize_sdk_response

            sdk_client = _FakeMetricsResult()  # stands in for a real SDK query response
            return [_normalize_sdk_response(rid, sdk_client) for rid in resource_ids]

    client = AzureMonitorClient(
        AzureMonitorConfig(resource_ids=[_ODB_NODE], metric_names=["odb_latency_ms"]),
        credential_provider=lambda: object(),
        backend=_SdkShapedBackend(),
    )
    result = client.fetch_raw()
    assert result.available is True
    signals = azure_monitor_to_signals(result)
    assert [s.value for s in signals] == [pytest.approx(512.0), pytest.approx(540.0)]
    assert all(s.resourceId == _ODB_NODE for s in signals)


def test_sdk_not_wired_error_carries_no_secret_upstream() -> None:
    # The descriptive exception may carry context, but only its CLASS NAME reaches the FetchResult.
    assert issubclass(AzureMonitorSdkNotWired, RuntimeError)
    client = AzureMonitorClient(
        AzureMonitorConfig(resource_ids=[_ODB_NODE]),
        credential_provider=lambda: object(),
    )
    assert client.fetch_raw().error == "AzureMonitorSdkNotWired"


# --------------------------------------------------------------------------------------
# FIX 2 — non-finite thresholds are malformed (skipped + surfaced), never a detection
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize("threshold", [float("nan"), float("inf"), float("-inf")])
def test_load_telemetry_rules_rejects_non_finite_threshold(threshold: float) -> None:
    packs = FakePacksTargetAware(
        [_telemetry_pack(signals=[
            {"name": "m", "op": "lt", "threshold": threshold,
             "severity": "high", "nodeId": "role:odb"},
        ])]
    )
    rules, notes = load_telemetry_rules(packs, "epic")
    assert rules == []  # non-finite threshold cannot define a breach → skipped
    assert len(notes) == 1  # surfaced


@pytest.mark.parametrize("threshold", [float("nan"), float("inf"), float("-inf")])
def test_run_non_finite_threshold_fabricates_no_detection(threshold: float) -> None:
    # Regression: threshold=inf, op="lt", value=1.0 must NOT fabricate detect::m::<node>.
    packs = FakePacksTargetAware(
        [_telemetry_pack(signals=[
            {"name": "m", "op": "lt", "threshold": threshold,
             "severity": "high", "nodeId": "role:odb"},
        ])]
    )
    state = FakeState(workload="epic", estate=_odb_estate(), graph=None)
    clients = {"system_pulse": _pulse_source(_sp_raw("m", 1.0, _ODB_NODE))}
    result = AiopsModule().run(ModuleContext(packs=packs, state=state, clients=clients))
    assert result.findings == []
    # The malformed (non-finite) signal is surfaced, not silently swallowed.
    assert any("skipped" in n for n in result.extra["surfacedNotes"])


# --------------------------------------------------------------------------------------
# FIX 3 — case-insensitive resourceId matching; emit the canonical estate id
# --------------------------------------------------------------------------------------
def test_fuse_matches_resource_id_case_insensitively_and_emits_canonical_id() -> None:
    # Estate holds the canonical (mixed-case) id; the signal arrives lowercased.
    canonical = "/subscriptions/00000000/rg/EPIC/ODB-01"
    estate = [
        ResourceNode(id=canonical, name="odb-01", type="epic/odb", workload="epic", role="odb"),
    ]
    findings = fuse_detections(
        [_rule()],
        [_signal("odb_latency_ms", 512.0, canonical.lower())],
        estate,
    )
    assert len(findings) == 1
    assert findings[0].nodeId == canonical  # canonical estate id, not the raw signal casing


def test_run_case_insensitive_resource_id_fuses_with_canonical_id() -> None:
    canonical = "/subscriptions/00000000/rg/EPIC/ODB-01"
    packs = FakePacksTargetAware(
        [_telemetry_pack(signals=[
            {"name": "odb_latency_ms", "op": "gt", "threshold": 500,
             "severity": "high", "nodeId": "role:odb"},
        ])]
    )
    estate = [
        ResourceNode(id=canonical, name="odb-01", type="epic/odb", workload="epic", role="odb"),
    ]
    state = FakeState(workload="epic", estate=estate, graph=None)
    clients = {"system_pulse": _pulse_source(_sp_raw("odb_latency_ms", 512.0, canonical.upper()))}
    result = AiopsModule().run(ModuleContext(packs=packs, state=state, clients=clients))
    assert len(result.findings) == 1
    assert result.findings[0].nodeId == canonical


# --------------------------------------------------------------------------------------
# FIX 4 — colliding (metric, node) across packs merge into ONE detection, all sources cited
# --------------------------------------------------------------------------------------
def test_fuse_merges_colliding_packs_into_one_detection_citing_all() -> None:
    rule_a = _rule(threshold=500.0, severity="medium", packId="pack-a", packVersion="1.0.0")
    rule_b = _rule(threshold=400.0, severity="critical", packId="pack-b", packVersion="2.0.0")
    findings = fuse_detections(
        [rule_a, rule_b],
        [_signal("odb_latency_ms", 512.0, _ODB_NODE)],
        _odb_estate(),
    )
    # Exactly one detection for the shared (metric, node) — no clobbering duplicate ids.
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == f"detect::odb_latency_ms::{_ODB_NODE}"
    # Highest-severity rule wins the emitted severity + provenance.
    assert finding.severity.value == "critical"
    assert finding.packId == "pack-b"
    assert finding.packVersion == "2.0.0"
    # BOTH contributing packs are cited in evidence (provenance never lost).
    pack_ids = {e.id for e in finding.evidence if e.kind == "pack"}
    assert pack_ids == {"pack-a", "pack-b"}


def _metric_evidence_detail(finding: Finding) -> str:
    ref = next(e for e in finding.evidence if e.kind == "metric")
    assert ref.detail is not None
    return ref.detail


def _dump(findings: list[Finding]) -> list[tuple[Any, ...]]:
    """Stable projection of the full findings list, incl. the cited evidence VALUE + order."""
    return [
        (
            f.id,
            f.nodeId,
            f.severity.value,
            f.packId,
            f.packVersion,
            _metric_evidence_detail(f),
            tuple(sorted(e.id for e in f.evidence if e.kind == "pack")),
        )
        for f in findings
    ]


def test_fuse_merge_is_deterministic_regardless_of_rule_order() -> None:
    rule_a = _rule(threshold=500.0, severity="medium", packId="pack-a", packVersion="1.0.0")
    rule_b = _rule(threshold=400.0, severity="critical", packId="pack-b", packVersion="2.0.0")
    signal = [_signal("odb_latency_ms", 512.0, _ODB_NODE)]
    forward = fuse_detections([rule_a, rule_b], signal, _odb_estate())
    reverse = fuse_detections([rule_b, rule_a], signal, _odb_estate())
    # FULL output identical (severity, provenance, AND cited evidence value + order).
    assert _dump(forward) == _dump(reverse)
    assert forward[0].packId == "pack-b"


def test_fuse_cited_observation_is_order_independent_2_3_vs_3_2() -> None:
    # Reviewer's regression: observations [2,3] vs [3,2] must cite the SAME (most-extreme) value.
    rule = _rule(threshold=1.0)  # odb_latency_ms gt 1.0
    obs_23 = [
        _signal("odb_latency_ms", 2.0, _ODB_NODE, timestamp="2026-08-03T04:00:00Z"),
        _signal("odb_latency_ms", 3.0, _ODB_NODE, timestamp="2026-08-03T04:01:00Z"),
    ]
    obs_32 = list(reversed(obs_23))
    f23 = fuse_detections([rule], obs_23, _odb_estate())
    f32 = fuse_detections([rule], obs_32, _odb_estate())
    assert _dump(f23) == _dump(f32)
    # The most-extreme breach (3.0) is cited regardless of input order (not 2.0).
    assert _metric_evidence_detail(f23[0]) == "3.0 gt 1.0"
    assert _metric_evidence_detail(f32[0]) == "3.0 gt 1.0"


def test_fuse_cited_observation_lt_picks_lowest_value() -> None:
    # For lt, the most-extreme breach is the LOWEST value; order must not change the citation.
    rule = _rule(op="lt", threshold=100.0)
    obs = [
        _signal("odb_latency_ms", 40.0, _ODB_NODE),
        _signal("odb_latency_ms", 10.0, _ODB_NODE),
    ]
    forward = fuse_detections([rule], obs, _odb_estate())
    reverse = fuse_detections([rule], list(reversed(obs)), _odb_estate())
    assert _dump(forward) == _dump(reverse)
    assert _metric_evidence_detail(forward[0]) == "10.0 lt 100.0"


def test_fuse_winner_tiebreak_gt_vs_lt_same_pack_is_order_independent() -> None:
    # Same severity + same pack/version, differing only by op/threshold: the residual tie must be
    # broken by the total-ordering rule identity (op, threshold, name), not by input order.
    gt_rule = _rule(op="gt", threshold=0.0, severity="high")
    lt_rule = _rule(op="lt", threshold=0.0, severity="high")
    obs = [
        _signal("odb_latency_ms", 1.0, _ODB_NODE),
        _signal("odb_latency_ms", -1.0, _ODB_NODE),
    ]
    forward = fuse_detections([gt_rule, lt_rule], obs, _odb_estate())
    reverse = fuse_detections([lt_rule, gt_rule], list(reversed(obs)), _odb_estate())
    assert _dump(forward) == _dump(reverse)
    # "gt" sorts before "lt", so the gt rule wins and its breaching observation (1.0) is cited.
    assert _metric_evidence_detail(forward[0]) == "1.0 gt 0.0"


def test_fuse_finding_order_is_input_order_independent() -> None:
    estate = _odb_estate()  # odb + web nodes
    rule_odb = _rule(name="odb_latency_ms", role="odb", threshold=500.0, severity="high")
    rule_web = _rule(name="web_5xx_rate", role="web", threshold=0.05, severity="critical")
    sig_odb = _signal("odb_latency_ms", 512.0, _ODB_NODE)
    sig_web = _signal("web_5xx_rate", 0.9, _WEB_NODE)
    forward = fuse_detections([rule_odb, rule_web], [sig_odb, sig_web], estate)
    reverse = fuse_detections([rule_web, rule_odb], [sig_web, sig_odb], estate)
    assert _dump(forward) == _dump(reverse)
    # Emitted order is deterministic (sorted by finding id), not input order.
    assert [f.id for f in forward] == sorted(f.id for f in forward)


def test_run_colliding_packs_emit_single_detection() -> None:
    packs = FakePacksTargetAware(
        [
            _telemetry_pack(pack_id="pack-a", version="1.0.0", signals=[
                {"name": "odb_latency_ms", "op": "gt", "threshold": 500,
                 "severity": "medium", "nodeId": "role:odb"},
            ]),
            _telemetry_pack(pack_id="pack-b", version="2.0.0", signals=[
                {"name": "odb_latency_ms", "op": "gt", "threshold": 400,
                 "severity": "critical", "nodeId": "role:odb"},
            ]),
        ]
    )
    state = FakeState(workload="epic", estate=_odb_estate(), graph=_graph_with_dependent())
    clients = {"system_pulse": _pulse_source(_sp_raw("odb_latency_ms", 512.0, _ODB_NODE))}
    result = AiopsModule().run(ModuleContext(packs=packs, state=state, clients=clients))
    assert len(result.findings) == 1
    assert result.findings[0].severity.value == "critical"
    cited = {e.id for e in result.findings[0].evidence if e.kind == "pack"}
    assert cited == {"pack-a", "pack-b"}
    assert len(result.extra["rca"]) == 1  # one detection ⇒ one RCA


# --------------------------------------------------------------------------------------
# FIX 5 — accurate source-availability accounting
# --------------------------------------------------------------------------------------
def test_run_no_clients_reports_both_sources_unavailable_and_zero_available() -> None:
    packs = FakePacksTargetAware(
        [_telemetry_pack(signals=[
            {"name": "odb_latency_ms", "op": "gt", "threshold": 500,
             "severity": "high", "nodeId": "role:odb"},
        ])]
    )
    state = FakeState(workload="epic", estate=_odb_estate(), graph=None)
    result = AiopsModule().run(ModuleContext(packs=packs, state=state, clients={}))
    assert sorted(result.extra["sourcesUnavailable"]) == ["azure_monitor", "system_pulse"]
    assert result.extra["sourcesAvailable"] == []
    # The summary must not claim available sources when there were none.
    assert result.response is not None
    assert "sources=0" in result.response.inputSummary


def test_run_no_state_no_rules_reports_all_sources_unavailable() -> None:
    # No state and no clients at all: nothing was observed, so both well-known sources are
    # unavailable and none are claimed available (the earlier inaccuracy).
    result = AiopsModule().run(ModuleContext(packs=None, state=None, clients={}))
    assert sorted(result.extra["sourcesUnavailable"]) == ["azure_monitor", "system_pulse"]
    assert result.extra["sourcesAvailable"] == []
    assert result.response is not None
    assert "sources=0" in result.response.inputSummary


def test_run_available_source_not_listed_unavailable() -> None:
    packs = FakePacksTargetAware(
        [_telemetry_pack(signals=[
            {"name": "odb_latency_ms", "op": "gt", "threshold": 500,
             "severity": "high", "nodeId": "role:odb"},
        ])]
    )
    state = FakeState(workload="epic", estate=_odb_estate(), graph=None)
    clients = {"system_pulse": _pulse_source(_sp_raw("odb_latency_ms", 100.0, _ODB_NODE))}
    result = AiopsModule().run(ModuleContext(packs=packs, state=state, clients=clients))
    assert result.extra["sourcesAvailable"] == ["system_pulse"]
    assert result.extra["sourcesUnavailable"] == ["azure_monitor"]
    assert result.response is not None
    assert "sources=1" in result.response.inputSummary


# --------------------------------------------------------------------------------------
# FIX B — partial source outages must not be erased across workloads
# --------------------------------------------------------------------------------------
class _TwoWorkloadState:
    """Read-only state exposing two workloads that share one estate."""

    def __init__(self, estate: list[ResourceNode]) -> None:
        self._estate = estate

    def list_workloads(self) -> list[str]:
        return ["w1", "w2"]

    def get_estate(self, workload: str) -> list[ResourceNode]:
        return self._estate

    def get_graph(self, workload: str) -> WorkloadGraph | None:
        return None


class _FlakySource:
    """Available on the first fetch, unavailable thereafter (an intermittent/partial outage)."""

    def __init__(self, ok: FetchResult) -> None:
        self._results = [ok, FetchResult(available=False, error="ConnectError")]
        self._i = 0

    def fetch_raw(self, *, metric_names: Sequence[str] | None = None) -> FetchResult:
        result = self._results[min(self._i, len(self._results) - 1)]
        self._i += 1
        return result


def test_run_partial_source_outage_across_workloads_is_not_erased() -> None:
    packs = FakePacksTargetAware(
        [_telemetry_pack(targets=[], signals=[
            {"name": "odb_latency_ms", "op": "gt", "threshold": 500,
             "severity": "high", "nodeId": "role:odb"},
        ])]
    )
    state = _TwoWorkloadState(_odb_estate())
    ok = FetchResult(available=True, raw=[_sp_raw("odb_latency_ms", 100.0, _ODB_NODE)])
    clients = {"system_pulse": _FlakySource(ok)}  # ok for w1, fails for w2
    result = AiopsModule().run(ModuleContext(packs=packs, state=state, clients=clients))

    # The w2 outage is preserved, not subtracted away by w1's success.
    assert "system_pulse" in result.extra["sourcesUnavailable"]
    assert result.extra["sourcesPartial"] == ["system_pulse"]
    # It still succeeded somewhere, so it is also reported available.
    assert "system_pulse" in result.extra["sourcesAvailable"]
    # azure_monitor was never configured ⇒ unavailable, never partial.
    assert "azure_monitor" in result.extra["sourcesUnavailable"]
    assert "azure_monitor" not in result.extra["sourcesPartial"]
