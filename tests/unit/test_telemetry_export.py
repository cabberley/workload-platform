"""Azure-free unit tests for the telemetry_export module (issue #86).

Covers the pure shaping functions (each of the 4 tables), the fail-closed ``State_s`` domain +
``unknown`` default, the opaque/deterministic ``NodeRef_s``, and the keyless edge client's
inert-when-unconfigured + swallow-on-failure behaviour. All fixtures are clearly-fake synthetic data
(guardrail 2); the exporter is exercised with an injected fake backend so tests never touch Azure.
"""
from __future__ import annotations

from datetime import UTC, datetime

from modules.telemetry_export.exporter import (
    ExportResult,
    IngestionSdkNotWired,
    LogsIngestionClient,
    LogsIngestionConfig,
    TelemetryBatch,
    build_batch,
)
from modules.telemetry_export.module import CLIENT_KEY, TelemetryExportModule
from modules.telemetry_export.shaping import (
    WpConnectorFetchRow,
    opaque_node_ref,
    shape_connector_fetch,
    shape_connector_fetches,
    shape_findings,
    shape_node_states,
    shape_spofs,
)
from shared.connectors import FetchResult
from shared.contracts import Finding, HealthState, ResourceNode, Severity
from shared.module_base import ModuleContext

_AT = datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC)

# Clearly-fake synthetic node id — NEVER a real Azure resource id.
_FAKE_NODE_ID = "synthetic-node://atlas/web-0"


def _node(node_id: str) -> ResourceNode:
    return ResourceNode(id=node_id, name="fake", type="Synthetic/thing")


def _finding(
    *,
    node_id: str,
    passed: bool | None,
    severity: Severity = Severity.info,
    blast_radius: int = 0,
) -> Finding:
    return Finding(
        id=f"fake::{node_id}",
        module="dependency_graph",
        title="synthetic",
        passed=passed,
        severity=severity,
        nodeId=node_id,
        blastRadius=blast_radius,
        createdAt=_AT,
    )


# --------------------------------------------------------------------------------------
# WpNodeState_CL — shaping + State_s domain + fail-closed unknown.
# --------------------------------------------------------------------------------------
def test_node_state_maps_failing_high_to_down() -> None:
    nodes = [_node("n1")]
    findings = [_finding(node_id="n1", passed=False, severity=Severity.high)]
    rows = shape_node_states("atlas", nodes, findings, at=_AT)
    assert len(rows) == 1
    assert rows[0].to_la_columns() == {
        "Workload_s": "atlas",
        "State_s": "down",
        "TimeGenerated": _AT.isoformat(),
    }


def test_node_state_maps_failing_medium_to_degraded() -> None:
    rows = shape_node_states(
        "atlas", [_node("n1")], [_finding(node_id="n1", passed=False, severity=Severity.medium)]
    )
    assert rows[0].state == HealthState.degraded


def test_node_state_positive_evidence_is_up() -> None:
    rows = shape_node_states("atlas", [_node("n1")], [_finding(node_id="n1", passed=True)])
    assert rows[0].state == HealthState.up


def test_node_state_fails_closed_to_unknown_without_evidence() -> None:
    # No findings at all → unknown (never guessed up).
    rows = shape_node_states("atlas", [_node("n1")], [])
    assert rows[0].state == HealthState.unknown


def test_node_state_unknown_finding_does_not_promote_to_up() -> None:
    # A finding with passed is None (observation/unknown) is NOT positive evidence → unknown.
    rows = shape_node_states("atlas", [_node("n1")], [_finding(node_id="n1", passed=None)])
    assert rows[0].state == HealthState.unknown


def test_node_state_worst_severity_wins() -> None:
    findings = [
        _finding(node_id="n1", passed=False, severity=Severity.low),
        _finding(node_id="n1", passed=False, severity=Severity.critical),
        _finding(node_id="n1", passed=True),
    ]
    rows = shape_node_states("atlas", [_node("n1")], findings)
    assert rows[0].state == HealthState.down


def test_node_state_domain_is_enforced() -> None:
    # Every emitted State_s is one of the 4 allowed values.
    allowed = {"up", "degraded", "down", "unknown"}
    nodes = [_node("a"), _node("b"), _node("c"), _node("d")]
    findings = [
        _finding(node_id="a", passed=False, severity=Severity.critical),
        _finding(node_id="b", passed=False, severity=Severity.low),
        _finding(node_id="c", passed=True),
    ]
    rows = shape_node_states("atlas", nodes, findings)
    assert {r.state.value for r in rows} <= allowed


def test_node_state_row_never_contains_node_id() -> None:
    rows = shape_node_states("atlas", [_node(_FAKE_NODE_ID)], [])
    cols = rows[0].to_la_columns()
    assert _FAKE_NODE_ID not in cols.values()
    assert set(cols) == {"Workload_s", "State_s", "TimeGenerated"}


# --------------------------------------------------------------------------------------
# WpSpof_CL — opaque, deterministic NodeRef_s.
# --------------------------------------------------------------------------------------
def test_spof_opaques_node_id() -> None:
    findings = [
        _finding(node_id=_FAKE_NODE_ID, passed=False, severity=Severity.high, blast_radius=3)
    ]
    rows = shape_spofs("atlas", findings, at=_AT)
    assert len(rows) == 1
    cols = rows[0].to_la_columns()
    # NodeRef_s is the opaque digest — never the raw node id.
    assert cols["NodeRef_s"] == opaque_node_ref(_FAKE_NODE_ID)
    assert cols["NodeRef_s"] != _FAKE_NODE_ID
    assert _FAKE_NODE_ID not in cols["NodeRef_s"]
    assert set(cols) == {"Workload_s", "NodeRef_s", "TimeGenerated"}


def test_opaque_node_ref_is_deterministic_and_bounded() -> None:
    a = opaque_node_ref(_FAKE_NODE_ID)
    b = opaque_node_ref(_FAKE_NODE_ID)
    assert a == b
    assert len(a) == 64 and all(c in "0123456789abcdef" for c in a)
    assert opaque_node_ref("other-node") != a


def test_spof_excludes_non_failing_or_zero_radius() -> None:
    findings = [
        _finding(node_id="n1", passed=False, severity=Severity.high, blast_radius=0),  # no radius
        _finding(node_id="n2", passed=None, severity=Severity.high, blast_radius=5),   # not failing
        _finding(node_id="n3", passed=False, severity=Severity.high, blast_radius=2),  # SPOF
    ]
    rows = shape_spofs("atlas", findings)
    assert {r.node_ref for r in rows} == {opaque_node_ref("n3")}


def test_spof_dedupes_by_opaque_ref() -> None:
    findings = [
        _finding(node_id="n1", passed=False, severity=Severity.high, blast_radius=3),
        _finding(node_id="n1", passed=False, severity=Severity.critical, blast_radius=9),
    ]
    rows = shape_spofs("atlas", findings)
    assert len(rows) == 1


# --------------------------------------------------------------------------------------
# WpFinding_CL — blast radius of failing findings only.
# --------------------------------------------------------------------------------------
def test_finding_row_shapes_blast_radius() -> None:
    findings = [_finding(node_id="n1", passed=False, severity=Severity.high, blast_radius=4)]
    rows = shape_findings("atlas", findings)
    assert len(rows) == 1
    assert rows[0].to_la_columns() == {
        "Workload_s": "atlas",
        "BlastRadius_d": 4.0,
        "TimeGenerated": _AT.isoformat(),
    }


def test_finding_row_excludes_passing_and_unknown() -> None:
    findings = [
        _finding(node_id="n1", passed=True, blast_radius=3),
        _finding(node_id="n2", passed=None, blast_radius=3),
        _finding(node_id="n3", passed=False, blast_radius=1),
    ]
    rows = shape_findings("atlas", findings)
    assert [r.blast_radius for r in rows] == [1.0]


# --------------------------------------------------------------------------------------
# WpConnectorFetch_CL — success flag only, no payload/error leak.
# --------------------------------------------------------------------------------------
def test_connector_fetch_shapes_success_flag() -> None:
    row = shape_connector_fetch("system_pulse", FetchResult(available=True), at=_AT)
    assert row.to_la_columns() == {
        "Connector_s": "system_pulse",
        "Success_b": True,
        "TimeGenerated": _AT.isoformat(),
    }


def test_connector_fetch_failure_is_false_and_error_not_leaked() -> None:
    result = FetchResult(available=False, error="TimeoutError", raw=[{"secret": "leak"}])
    row = shape_connector_fetch("azure_monitor", result, at=_AT)
    cols = row.to_la_columns()
    assert cols["Success_b"] is False
    assert "leak" not in str(cols) and "TimeoutError" not in str(cols.values())


def test_connector_fetches_batch() -> None:
    rows = shape_connector_fetches(
        {"a": FetchResult(available=True), "b": FetchResult(available=False)}, at=_AT
    )
    assert {(r.connector, r.success) for r in rows} == {("a", True), ("b", False)}


# --------------------------------------------------------------------------------------
# Exporter edge client — inert when unconfigured, fail-closed on error.
# --------------------------------------------------------------------------------------
class _RecordingBackend:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    def upload(self, *, rule_id, stream_name, records, credential, endpoint, timeout_s):  # noqa: ANN001,ANN002
        self.calls.append((stream_name, len(records)))


class _FailingBackend:
    def upload(self, *, rule_id, stream_name, records, credential, endpoint, timeout_s):  # noqa: ANN001,ANN002
        raise RuntimeError("synthetic backend failure")


def _one_row_batch() -> TelemetryBatch:
    return build_batch(connector_fetches=[WpConnectorFetchRow(connector="a", success=True)])


def test_exporter_inert_when_unconfigured() -> None:
    # No endpoint/rule_id → inert no-op, no throw, no backend call.
    backend = _RecordingBackend()
    client = LogsIngestionClient(
        LogsIngestionConfig(), credential_provider=lambda: object(), backend=backend
    )
    assert client.configured is False
    result = client.export(_one_row_batch())
    assert result == ExportResult(configured=False)
    assert result.ok is True
    assert backend.calls == []


def test_exporter_no_credential_fails_closed() -> None:
    backend = _RecordingBackend()
    client = LogsIngestionClient(
        LogsIngestionConfig(endpoint="https://dce.example", rule_id="dcr-abc"),
        credential_provider=lambda: None,
        backend=backend,
    )
    assert client.configured is True
    result = client.export(_one_row_batch())
    assert result.errors == ["NoCredential"]
    assert result.emitted == 0
    assert backend.calls == []


def test_exporter_publishes_only_non_empty_streams() -> None:
    backend = _RecordingBackend()
    client = LogsIngestionClient(
        LogsIngestionConfig(endpoint="https://dce.example", rule_id="dcr-abc"),
        credential_provider=lambda: object(),
        backend=backend,
    )
    result = client.export(_one_row_batch())
    assert result.ok is True
    assert result.emitted == 1
    assert backend.calls == [("Custom-WpConnectorFetch_CL", 1)]


def test_exporter_swallows_backend_failure() -> None:
    observed: list[int] = []
    client = LogsIngestionClient(
        LogsIngestionConfig(endpoint="https://dce.example", rule_id="dcr-abc", retries=1),
        credential_provider=lambda: object(),
        backend=_FailingBackend(),
        fail_closed_observer=lambda: observed.append(1),
        sleep=lambda _s: None,
    )
    result = client.export(_one_row_batch())  # must NOT raise
    assert result.errors == ["RuntimeError"]
    assert result.ok is False
    assert observed == [1]  # keyless observer counted the fail-closed event


def test_exporter_swallows_raising_credential_provider() -> None:
    def _boom() -> object:
        raise ValueError("provider blew up")

    client = LogsIngestionClient(
        LogsIngestionConfig(endpoint="https://dce.example", rule_id="dcr-abc"),
        credential_provider=_boom,
    )
    result = client.export(_one_row_batch())  # must NOT raise
    assert result.errors == ["NoCredential"]


def test_is_transient_never_retries_missing_sdk() -> None:
    from modules.telemetry_export.exporter import _is_transient

    assert _is_transient(IngestionSdkNotWired("x")) is False
    assert _is_transient(RuntimeError("x")) is True


# --------------------------------------------------------------------------------------
# Module integration — reads a fake ReadableState, shapes, and exports through a fake client.
# --------------------------------------------------------------------------------------
class _FakeState:
    def __init__(
        self, *, workload: str, nodes: list[ResourceNode], findings: list[Finding]
    ) -> None:
        self._workload = workload
        self._nodes = nodes
        self._findings = findings

    def list_workloads(self) -> list[str]:
        return [self._workload]

    def get_estate(self, workload: str) -> list[ResourceNode]:
        return self._nodes if workload == self._workload else []

    def get_findings(self, workload: str, module: str | None = None) -> list[Finding]:
        return self._findings if workload == self._workload else []


class _CapturingExporter:
    def __init__(self) -> None:
        self.batch: TelemetryBatch | None = None

    def export(self, batch: TelemetryBatch) -> ExportResult:
        self.batch = batch
        return ExportResult(configured=True, emitted_by_stream={"Custom-WpNodeState_CL": 1})


def test_module_runs_inert_with_empty_context() -> None:
    # No state, no exporter → inert, still ok (fail-closed; never breaks the platform).
    result = TelemetryExportModule().run(ModuleContext(), scope={})
    assert result.ok is True
    assert result.module == "telemetry_export"
    assert result.extra["configured"] is False


def test_module_shapes_and_exports_from_state() -> None:
    nodes = [_node("n1"), _node("n2")]
    findings = [
        _finding(node_id="n1", passed=False, severity=Severity.high, blast_radius=3),
        _finding(node_id="n2", passed=True),
    ]
    state = _FakeState(workload="atlas", nodes=nodes, findings=findings)
    exporter = _CapturingExporter()
    ctx = ModuleContext(state=state, clients={CLIENT_KEY: exporter})

    result = TelemetryExportModule().run(ctx, scope={})

    assert result.ok is True
    assert exporter.batch is not None
    batch = exporter.batch
    # 2 nodes → 2 node-state rows; 1 SPOF (n1, radius 3); 1 failing finding row.
    assert len(batch.node_states) == 2
    assert {r.state for r in batch.node_states} == {HealthState.down, HealthState.up}
    assert len(batch.spofs) == 1
    assert batch.spofs[0].node_ref == opaque_node_ref("n1")
    assert len(batch.findings) == 1
    # No connector rows yet (no PII-free source — see TODO(human)).
    assert batch.connector_fetches == []
    # PII-free: no raw node id anywhere in the emitted column dicts.
    dumped = str(
        [r.to_la_columns() for r in batch.node_states]
        + [r.to_la_columns() for r in batch.spofs]
        + [r.to_la_columns() for r in batch.findings]
    )
    assert "n1" not in dumped and "n2" not in dumped


def test_module_scope_targets_single_workload() -> None:
    state = _FakeState(workload="atlas", nodes=[_node("n1")], findings=[])
    exporter = _CapturingExporter()
    ctx = ModuleContext(state=state, clients={CLIENT_KEY: exporter})
    result = TelemetryExportModule().run(ctx, scope={"workload": "atlas"})
    assert result.extra["workloads"] == 1
    assert exporter.batch is not None
    assert len(exporter.batch.node_states) == 1
    assert exporter.batch.node_states[0].state == HealthState.unknown  # no findings → unknown
