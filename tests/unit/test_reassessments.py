"""Reassessments module tests — deterministic drift over synthetic snapshot state.

All fixtures are clearly-fake synthetic data (guardrail 2). The module reads a read-only
``ReadableState`` view and delegates the diff to the shared pure ``compute_drift`` — these tests
inject a fake state so they stay Azure-free.
"""
from __future__ import annotations

from modules.reassessments.module import ReassessmentsModule, diff_findings
from shared.contracts import Finding, ResourceNode, Severity
from shared.module_base import ModuleContext


class FakeState:
    """Minimal in-memory ``ReadableState`` for one synthetic workload.

    Returns synthetic previous vs current findings and estate node ids; unknown workloads read
    empty (fail-closed). Only the read methods the module uses are meaningful.
    """

    def __init__(
        self,
        *,
        workload: str,
        previous_findings: list[Finding],
        current_findings: list[Finding],
        previous_node_ids: list[str],
        current_nodes: list[ResourceNode],
    ) -> None:
        self._workload = workload
        self._previous_findings = previous_findings
        self._current_findings = current_findings
        self._previous_node_ids = previous_node_ids
        self._current_nodes = current_nodes

    def list_workloads(self) -> list[str]:
        return [self._workload]

    def get_estate(self, workload: str) -> list[ResourceNode]:
        return self._current_nodes if workload == self._workload else []

    def get_graph(self, workload: str):  # noqa: ANN201 - unused by reassessments
        return None

    def get_findings(self, workload: str, module: str | None = None) -> list[Finding]:
        return self._current_findings if workload == self._workload else []

    def get_previous_findings(self, workload: str) -> list[Finding]:
        return self._previous_findings if workload == self._workload else []

    def get_previous_node_ids(self, workload: str) -> list[str]:
        return self._previous_node_ids if workload == self._workload else []


def _finding(fid: str, passed: bool | None, *, severity: Severity = Severity.medium) -> Finding:
    return Finding(
        id=fid,
        module="quality_checks",
        title=f"synthetic check {fid}",
        passed=passed,
        severity=severity,
        packId="waf-reliability-baseline",
        packVersion="1.2.0",
    )


def _fake_state() -> FakeState:
    # Synthetic snapshot: one still-failing, one recovering, one newly failing check.
    return FakeState(
        workload="fake-epic",
        previous_findings=[
            _finding("chk-still", False),
            _finding("chk-recovered", False),
        ],
        current_findings=[
            _finding("chk-still", False),
            _finding("chk-recovered", True),
            _finding("chk-new", False, severity=Severity.high),
        ],
        previous_node_ids=["node-a", "node-b"],
        current_nodes=[
            ResourceNode(id="node-b", name="node-b", type="fake/type"),
            ResourceNode(id="node-c", name="node-c", type="fake/type"),
        ],
    )


def test_run_computes_deterministic_drift_and_surfaces_new_failures():
    module = ReassessmentsModule()
    result = module.run(ModuleContext(state=_fake_state()), scope={})

    assert result.ok is True
    summary = result.extra["summary"]
    assert summary["newFailures"] == 1
    assert summary["recovered"] == 1
    assert summary["stillFailing"] == 1
    assert summary["addedNodes"] == 1
    assert summary["removedNodes"] == 1
    assert summary["cadence"] == "0 3 * * *"

    # New-failure findings are surfaced on the result for the alerts module to route.
    assert [f.id for f in result.findings] == ["chk-new"]
    assert result.findings[0].passed is False
    assert result.findings[0].module == "quality_checks"  # provenance carried through
    assert result.response is not None
    assert result.response.nextActions == ["route-findings"]

    drift = result.extra["drift"]["fake-epic"]
    assert [f["id"] for f in drift["newFailures"]] == ["chk-new"]
    assert [f["id"] for f in drift["recovered"]] == ["chk-recovered"]
    assert [f["id"] for f in drift["stillFailing"]] == ["chk-still"]
    assert drift["addedNodes"] == ["node-c"]
    assert drift["removedNodes"] == ["node-a"]


def test_run_scopes_to_a_single_workload():
    module = ReassessmentsModule()
    result = module.run(ModuleContext(state=_fake_state()), scope={"workload": "fake-epic"})
    assert result.extra["summary"]["workloads"] == 1
    assert [f.id for f in result.findings] == ["chk-new"]


def test_run_fails_closed_with_no_state():
    module = ReassessmentsModule()
    result = module.run(ModuleContext(state=None), scope={})
    assert result.ok is True
    assert result.findings == []
    assert result.extra["summary"]["workloads"] == 0
    assert result.extra["drift"] == {}
    assert result.response is not None
    assert result.response.nextActions == []


def test_run_unknown_workload_yields_empty_drift():
    module = ReassessmentsModule()
    result = module.run(ModuleContext(state=_fake_state()), scope={"workload": "no-such-workload"})
    assert result.ok is True
    assert result.findings == []
    assert result.extra["summary"]["newFailures"] == 0
    assert result.extra["drift"]["no-such-workload"]["newFailures"] == []


def test_diff_findings_pure_new_failure_and_recovered_paths():
    previous = [_finding("chk-recovered", False), _finding("chk-stable", True)]
    current = [
        _finding("chk-recovered", True),
        _finding("chk-stable", True),
        _finding("chk-new", False),
    ]
    drift = diff_findings(previous, current)
    assert drift["newFailures"] == ["chk-new"]
    assert drift["recovered"] == ["chk-recovered"]


def test_diff_findings_empty_inputs():
    assert diff_findings([], []) == {"newFailures": [], "recovered": []}
