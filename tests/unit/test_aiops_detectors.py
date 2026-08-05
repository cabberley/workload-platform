"""Tests for the telemetry detector compiler + pure windowing (issue #51).

Covers: pack -> detector compilation (mixed threshold/window/expression, fail-closed on malformed),
pure window selection/aggregation, threshold-over-window (aggregate/all/any), rate/count, empty
windows, provenance, and end-to-end wiring into ``AiopsModule.run`` (detections flow to
``correlate_root_cause``; simple-threshold behavior is unchanged). All fixtures are clearly-fake.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from modules.aiops.connectors.system_pulse import FetchResult, Signal
from modules.aiops.detectors import (
    Detector,
    classify_signal,
    compile_detectors,
    compute_aggregates,
    select_window_samples,
)
from modules.aiops.module import (
    AiopsModule,
    _is_windowed_signal,
    load_telemetry_rules,
    load_windowed_detectors,
    run_windowed_detectors,
)
from shared.contracts import (
    DependencyEdge,
    PackType,
    ResourceNode,
    WorkloadGraph,
)
from shared.module_base import ModuleContext

_NODE = "/subscriptions/00000000/rg/demo/widget-01"
_ROLE = "fake-widget"
_METRIC = "fake_widget_latency_ms"
_BASE = datetime(2026, 8, 3, 4, 0, 0, tzinfo=UTC)


def _sig(
    value: float, *, offset_s: float = 0.0, metric: str = _METRIC, node: str = _NODE
) -> Signal:
    return Signal(
        metric=metric,
        value=value,
        unit="ms",
        timestamp=_BASE + timedelta(seconds=offset_s),
        resourceId=node,
    )


def _estate() -> list[ResourceNode]:
    return [
        ResourceNode(id=_NODE, name="widget-01", type="demo/widget", workload="demo", role=_ROLE)
    ]


# --------------------------------------------------------------------------------------
# classify_signal + threshold-path routing stay in sync
# --------------------------------------------------------------------------------------
def test_classify_signal_precedence() -> None:
    assert classify_signal({"window": {"samples": 3}}) == "window"
    assert classify_signal({"expression": "value > threshold"}) == "expression"
    # expression wins when both are present (it may reference the window aggregates).
    assert classify_signal({"window": {"samples": 3}, "expression": "avg > 1"}) == "expression"
    assert classify_signal({"op": "gt"}) == "threshold"
    assert classify_signal("not-a-dict") == "threshold"


def test_is_windowed_signal_matches_classify() -> None:
    for raw in ({"window": {}}, {"expression": "x"}, {"op": "gt"}, "x", 3):
        assert _is_windowed_signal(raw) == (classify_signal(raw) != "threshold")


# --------------------------------------------------------------------------------------
# compile_detectors — mixed compile + fail-closed
# --------------------------------------------------------------------------------------
def _signal(**over: Any) -> dict[str, Any]:
    base = {
        "name": _METRIC, "op": "gt", "threshold": 500,
        "severity": "high", "nodeId": "role:fake-widget",
    }
    base.update(over)
    return base


def test_compile_mixed_pack_yields_three_kinds() -> None:
    body = {
        "signals": [
            _signal(),
            _signal(window={"samples": 5, "aggregate": "avg"}),
            _signal(expression="avg > threshold", window={"samples": 3}),
        ]
    }
    detectors, notes = compile_detectors(body, "demo-pack", "1.0.0")
    assert notes == []
    kinds = sorted(d.kind for d in detectors)
    assert kinds == ["expression", "threshold", "window"]
    assert all(isinstance(d, Detector) for d in detectors)
    assert {d.pack_id for d in detectors} == {"demo-pack"}


@pytest.mark.parametrize(
    "bad_window",
    [
        {"samples": 5, "durationSeconds": 10},  # both selectors
        {},                                      # neither selector
        {"samples": 0},                          # samples < 1
        {"samples": 3, "aggregate": "median"},   # unknown aggregate
        {"samples": 3, "mode": "sometimes"},     # unknown mode
        {"durationSeconds": -5},                 # non-positive duration
        "not-an-object",                         # non-object window
        {"samples": 3, "aggregate": []},         # MED3: non-string aggregate (unhashable)
        {"samples": 3, "mode": []},              # MED3: non-string mode (unhashable)
        {"durationSeconds": 1e308},              # MED3: duration overflows timedelta => rejected
    ],
)
def test_compile_malformed_window_surfaced_not_compiled(bad_window: Any) -> None:
    body = {"signals": [_signal(window=bad_window)]}
    detectors, notes = compile_detectors(body, "demo-pack", "1.0.0")
    assert detectors == []
    assert len(notes) == 1 and "skipped" in notes[0]


def test_compile_malformed_window_never_crashes_run() -> None:
    # MED3: unhashable aggregate/mode and huge duration must not raise during compile OR eval.
    for bad in ({"samples": 3, "aggregate": []}, {"mode": []}, {"durationSeconds": 1e308}):
        detectors, notes = compile_detectors(
            {"signals": [_signal(window=bad)]}, "p", "1.0.0"
        )
        assert detectors == [] and notes


def test_compile_unsafe_expression_surfaced_not_compiled() -> None:
    body = {"signals": [_signal(expression="__import__('os')")]}
    detectors, notes = compile_detectors(body, "demo-pack", "1.0.0")
    assert detectors == []
    assert len(notes) == 1 and "unsafe/invalid expression" in notes[0]


def test_compile_bad_base_fields_surfaced() -> None:
    # A windowed signal whose base fields are malformed (non-role selector) still fails closed.
    body = {"signals": [_signal(nodeId="widget", window={"samples": 3})]}
    detectors, notes = compile_detectors(body, "demo-pack", "1.0.0")
    assert detectors == []
    assert len(notes) == 1


def test_compile_signals_not_a_list_yields_no_detectors() -> None:
    detectors, notes = compile_detectors({"signals": {"not": "a list"}}, "p", "1.0.0")
    assert detectors == []
    assert notes and "not a list" in notes[0]


@pytest.mark.parametrize("body", [{}, [], "nope", 3, {"other": 1}])
def test_compile_malformed_body_always_surfaced(body: Any) -> None:
    # MED8: a non-object body or a body missing `signals` is never silently ignored.
    detectors, notes = compile_detectors(body, "p", "1.0.0")
    assert detectors == []
    assert len(notes) == 1 and "no detectors compiled" in notes[0]


def test_expression_explicit_null_window_rejected_not_defaulted() -> None:
    # MED-B: an explicit "window": null must NOT silently default to a 1-sample window.
    body = {"signals": [_signal(expression="value > threshold", window=None)]}
    detectors, notes = compile_detectors(body, "p", "1.0.0")
    assert detectors == []
    assert len(notes) == 1 and "window must be an object" in notes[0]


def test_window_signal_explicit_null_window_rejected() -> None:
    body = {"signals": [_signal(window=None)]}
    detectors, notes = compile_detectors(body, "p", "1.0.0")
    assert detectors == []
    assert len(notes) == 1 and "window must be an object" in notes[0]


def test_expression_absent_window_defaults_no_regression() -> None:
    # window key genuinely absent ⇒ still compiles with the documented one-sample default.
    body = {"signals": [_signal(expression="value > threshold")]}
    detectors, notes = compile_detectors(body, "p", "1.0.0")
    assert notes == [] and len(detectors) == 1 and detectors[0].kind == "expression"


def test_expression_valid_explicit_window_compiles_unchanged() -> None:
    body = {"signals": [_signal(expression="avg > threshold", window={"samples": 3})]}
    detectors, notes = compile_detectors(body, "p", "1.0.0")
    assert notes == [] and len(detectors) == 1 and detectors[0].kind == "expression"


def test_compile_kinds_filter_excludes_threshold() -> None:
    body = {"signals": [_signal(), _signal(window={"samples": 3})]}
    detectors, _ = compile_detectors(body, "p", "1.0.0", kinds={"window", "expression"})
    assert [d.kind for d in detectors] == ["window"]


# --------------------------------------------------------------------------------------
# Pure window selection + aggregation
# --------------------------------------------------------------------------------------
def test_select_window_samples_by_count() -> None:
    samples = [_sig(i, offset_s=i) for i in range(6)]
    sel = select_window_samples(samples, ("samples", 3))
    assert [s.value for s in sel] == [3, 4, 5]


def test_select_window_samples_by_duration() -> None:
    samples = [
        _sig(1, offset_s=0), _sig(2, offset_s=60), _sig(3, offset_s=120), _sig(4, offset_s=180)
    ]
    sel = select_window_samples(samples, ("durationSeconds", 100))
    assert [s.value for s in sel] == [3, 4]  # within 100s of latest (t=180) => t=120,180


def test_compute_aggregates_full() -> None:
    aggs = compute_aggregates([_sig(10, offset_s=0), _sig(20, offset_s=10), _sig(30, offset_s=20)])
    assert aggs is not None
    assert aggs["avg"] == pytest.approx(20)
    assert aggs["max"] == 30 and aggs["min"] == 10 and aggs["sum"] == 60
    assert aggs["count"] == 3 and aggs["last"] == 30
    assert aggs["rate"] == pytest.approx((30 - 10) / 20)  # 1.0 per second


def test_compute_aggregates_empty_is_none() -> None:
    assert compute_aggregates([]) is None


def test_compute_aggregates_single_sample_has_no_rate() -> None:
    aggs = compute_aggregates([_sig(5)])
    assert aggs is not None and "rate" not in aggs and aggs["avg"] == 5


# --------------------------------------------------------------------------------------
# Windowed detector evaluation (aggregate / all / any / rate / count)
# --------------------------------------------------------------------------------------
def _one_detector(signal: dict[str, Any]) -> Detector:
    detectors, notes = compile_detectors({"signals": [signal]}, "demo-pack", "1.0.0")
    assert notes == [] and len(detectors) == 1
    return detectors[0]


def test_window_aggregate_avg_breach() -> None:
    det = _one_detector(_signal(threshold=15, window={"samples": 3, "aggregate": "avg"}))
    signals = [_sig(10, offset_s=0), _sig(20, offset_s=10), _sig(30, offset_s=20)]  # avg=20>15
    findings = det(signals, _estate())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == f"detect::win::{_METRIC}::{_NODE}"
    assert finding.nodeId == _NODE and finding.passed is False
    assert finding.packId == "demo-pack" and finding.packVersion == "1.0.0"
    assert any(ref.kind == "pack" for ref in finding.evidence)
    assert any(ref.kind == "metric" and ref.id == _METRIC for ref in finding.evidence)


def test_window_aggregate_no_breach() -> None:
    det = _one_detector(_signal(threshold=100, window={"samples": 3, "aggregate": "avg"}))
    signals = [_sig(10, offset_s=0), _sig(20, offset_s=10), _sig(30, offset_s=20)]  # avg=20<100
    assert det(signals, _estate()) == []


def test_window_mode_all() -> None:
    det = _one_detector(_signal(threshold=5, window={"samples": 3, "mode": "all"}))
    assert det([_sig(6, offset_s=i) for i in range(3)], _estate())  # all > 5
    assert det([_sig(6, offset_s=0), _sig(1, offset_s=1), _sig(9, offset_s=2)], _estate()) == []


def test_window_mode_any() -> None:
    det = _one_detector(_signal(threshold=5, window={"samples": 3, "mode": "any"}))
    assert det([_sig(1, offset_s=0), _sig(1, offset_s=1), _sig(9, offset_s=2)], _estate())  # one>5
    assert det([_sig(1, offset_s=i) for i in range(3)], _estate()) == []


def test_window_aggregate_rate() -> None:
    det = _one_detector(_signal(op="gt", threshold=0.5, window={"samples": 3, "aggregate": "rate"}))
    signals = [_sig(10, offset_s=0), _sig(20, offset_s=10), _sig(30, offset_s=20)]  # rate=1.0/s
    assert det(signals, _estate())


def test_window_aggregate_count() -> None:
    det = _one_detector(_signal(op="gt", threshold=2, window={"samples": 3, "aggregate": "count"}))
    assert det([_sig(1, offset_s=i) for i in range(3)], _estate())  # full window: count 3 > 2
    det2 = _one_detector(_signal(op="gt", threshold=2, window={"samples": 2, "aggregate": "count"}))
    assert det2([_sig(1, offset_s=i) for i in range(2)], _estate()) == []  # count 2, not > 2


def test_window_samples_requires_full_window() -> None:
    # MED4: a samples:N window must be full before it decides — no early/partial fire.
    det = _one_detector(_signal(op="gt", threshold=5, window={"samples": 5, "mode": "all"}))
    assert det([_sig(9, offset_s=0)], _estate()) == []           # 1 breaching sample, window short
    assert det([_sig(9, offset_s=i) for i in range(4)], _estate()) == []  # still < 5
    assert det([_sig(9, offset_s=i) for i in range(5)], _estate())       # 5 all-breaching => fires


def test_select_window_samples_short_count_is_empty() -> None:
    samples = [_sig(1, offset_s=0), _sig(2, offset_s=1)]
    assert select_window_samples(samples, ("samples", 5)) == []


def test_window_non_finite_samples_no_detection() -> None:
    # MED5: non-finite / overflowing telemetry never crashes and never drives a breach.
    det = _one_detector(_signal(op="gt", threshold=0, window={"samples": 2, "aggregate": "max"}))
    assert det([_sig(float("inf"), offset_s=0), _sig(float("-inf"), offset_s=1)], _estate()) == []
    assert det([_sig(1e308, offset_s=0), _sig(1e308, offset_s=1)], _estate()) == []
    det_all = _one_detector(_signal(op="gt", threshold=0, window={"samples": 1, "mode": "all"}))
    assert det_all([_sig(float("inf"))], _estate()) == []  # single inf: count/all must not fire


def test_compute_aggregates_non_finite_is_none() -> None:
    assert compute_aggregates([_sig(float("inf")), _sig(1.0, offset_s=1)]) is None
    assert compute_aggregates([_sig(1e308), _sig(1e308, offset_s=1)]) is None


def test_window_rate_single_sample_no_detection() -> None:
    det = _one_detector(_signal(op="gt", threshold=0, window={"samples": 3, "aggregate": "rate"}))
    assert det([_sig(10)], _estate()) == []  # rate undefined for 1 sample => no detection


def test_window_empty_no_detection() -> None:
    det = _one_detector(_signal(window={"samples": 3, "aggregate": "avg"}))
    assert det([], _estate()) == []
    # signal on an unselected node is ignored too
    other = Signal(metric=_METRIC, value=9999, unit="ms", timestamp=_BASE, resourceId="/other")
    assert det([other], _estate()) == []


def test_finding_id_namespaces_provably_disjoint() -> None:
    # MED6: a legacy metric literally named "win::cpu" cannot collide with a windowed "cpu".
    from modules.aiops.module import detect_metric_breach

    legacy = detect_metric_breach(
        {"name": "win::cpu", "value": 10, "op": "gt", "threshold": 1,
         "nodeId": _NODE, "severity": "high",
         "packId": "demo-pack", "packVersion": "1.0.0"}
    )
    assert legacy is not None
    det = _one_detector(_signal(name="cpu", op="gt", threshold=1, window={"samples": 1}))
    win = det([_sig(10, metric="cpu")], _estate())
    assert len(win) == 1
    assert legacy.id != win[0].id
    assert legacy.id == f"detect::win%3A%3Acpu::{_NODE}"   # colons escaped in the metric component
    assert win[0].id == f"detect::win::cpu::{_NODE}"       # distinct windowed namespace marker


def test_equal_timestamp_samples_order_independent() -> None:
    # MED7: reversing two same-timestamp/same-resource samples yields the SAME detection.
    det = _one_detector(_signal(op="gt", threshold=0, window={"samples": 1, "aggregate": "last"}))
    a, b = _sig(1, offset_s=0), _sig(9, offset_s=0)  # identical timestamp + resourceId
    f1 = det([a, b], _estate())
    f2 = det([b, a], _estate())
    assert f1 and f2
    assert f1[0].id == f2[0].id
    assert [e.detail for e in f1[0].evidence] == [e.detail for e in f2[0].evidence]


# --------------------------------------------------------------------------------------
# Expression detector evaluation
# --------------------------------------------------------------------------------------
def test_expression_detector_breach_and_provenance() -> None:
    det = _one_detector(
        _signal(threshold=15, expression="avg > threshold and max < 100", window={"samples": 3})
    )
    signals = [_sig(10, offset_s=0), _sig(20, offset_s=10), _sig(30, offset_s=20)]  # avg=20, max=30
    findings = det(signals, _estate())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == f"detect::expr::{_METRIC}::{_NODE}"
    assert finding.packId == "demo-pack"
    assert any("expression[" in (ref.detail or "") for ref in finding.evidence)


def test_expression_detector_false_no_detection() -> None:
    det = _one_detector(_signal(threshold=100, expression="avg > threshold", window={"samples": 3}))
    signals = [_sig(10, offset_s=0), _sig(20, offset_s=10)]  # avg=15 < 100
    assert det(signals, _estate()) == []


def test_expression_without_window_uses_last_sample() -> None:
    det = _one_detector(_signal(threshold=50, expression="value > threshold"))
    # default one-sample window => value = last sample.
    assert det([_sig(10, offset_s=0), _sig(80, offset_s=10)], _estate())
    assert det([_sig(80, offset_s=0), _sig(10, offset_s=10)], _estate()) == []


def test_expression_div_by_zero_no_crash_no_detection() -> None:
    det = _one_detector(
        _signal(expression="sum / (count - 3) > threshold", window={"samples": 3}, threshold=0)
    )
    # count == 3 => division by zero => None => no detection, no crash.
    assert det([_sig(1, offset_s=i) for i in range(3)], _estate()) == []


# --------------------------------------------------------------------------------------
# run_windowed_detectors — deterministic dedup across packs
# --------------------------------------------------------------------------------------
def test_run_windowed_dedup_keeps_highest_severity_and_cites_all() -> None:
    low = _one_detector_pack(
        "pack-a", "1.0.0", _signal(severity="low", window={"samples": 3}, threshold=5)
    )
    high = _one_detector_pack(
        "pack-b", "2.0.0", _signal(severity="critical", window={"samples": 3}, threshold=5)
    )
    signals = [_sig(9, offset_s=i) for i in range(3)]
    findings = run_windowed_detectors([low, high], signals, _estate())
    assert len(findings) == 1  # same id => one deterministic finding
    assert findings[0].severity.value == "critical"
    pack_ids = {ref.id for ref in findings[0].evidence if ref.kind == "pack"}
    assert pack_ids == {"pack-a", "pack-b"}  # provenance from both packs retained


def _one_detector_pack(pack_id: str, version: str, signal: dict[str, Any]) -> Detector:
    detectors, notes = compile_detectors({"signals": [signal]}, pack_id, version)
    assert notes == [] and len(detectors) == 1
    return detectors[0]


# --------------------------------------------------------------------------------------
# Integration through AiopsModule.run
# --------------------------------------------------------------------------------------
class _FakeManifest:
    def __init__(self, pack_id: str, version: str, targets: list[str]) -> None:
        self.id, self.version, self.targets = pack_id, version, targets


class _FakePack:
    def __init__(self, manifest: _FakeManifest, body: dict[str, Any]) -> None:
        self.manifest, self.body = manifest, body


class _FakePacks:
    def __init__(self, packs: list[tuple[_FakeManifest, dict[str, Any]]]) -> None:
        self._packs = packs

    def load_for_workload(self, workload: str, pack_type: PackType) -> list[_FakePack]:
        if pack_type != PackType.telemetry:
            return []
        return [
            _FakePack(m, b)
            for m, b in self._packs
            if not m.targets or workload in m.targets
        ]


class _FakeState:
    def __init__(self, estate: list[ResourceNode], graph: WorkloadGraph | None) -> None:
        self._estate, self._graph = estate, graph

    def list_workloads(self) -> list[str]:
        return ["demo"]

    def get_estate(self, workload: str) -> list[ResourceNode]:
        return self._estate

    def get_graph(self, workload: str) -> WorkloadGraph | None:
        return self._graph


class _PulseSource:
    def __init__(self, raws: list[dict[str, Any]]) -> None:
        self._raws = raws

    def fetch_raw(self, *, metric_names: Any = None) -> FetchResult:
        return FetchResult(available=True, raw=self._raws)


def _raw(metric: str, value: float, offset_s: float) -> dict[str, Any]:
    return {
        "metric": metric,
        "value": value,
        "unit": "ms",
        "timestamp": (_BASE + timedelta(seconds=offset_s)).isoformat(),
        "resourceId": _NODE,
    }


def _graph() -> WorkloadGraph:
    dependent = ResourceNode(
        id="/dep-01", name="dep-01", type="demo/dep", workload="demo", role="dep"
    )
    return WorkloadGraph(
        nodes=_estate() + [dependent],
        edges=[DependencyEdge(source="/dep-01", target=_NODE)],
    )


def test_run_windowed_detection_flows_to_rca() -> None:
    body = {
        "signals": [
            _signal(threshold=15, window={"samples": 3, "aggregate": "avg"}),
        ]
    }
    packs = _FakePacks([(_FakeManifest("demo-pack", "1.0.0", ["demo"]), body)])
    state = _FakeState(_estate(), _graph())
    raws = [_raw(_METRIC, v, off) for v, off in [(10, 0), (20, 10), (30, 20)]]  # avg=20>15
    ctx = ModuleContext(packs=packs, state=state, clients={"system_pulse": _PulseSource(raws)})

    result = AiopsModule().run(ctx, scope={"workload": "demo"})

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.id == f"detect::win::{_METRIC}::{_NODE}"
    assert finding.blastRadius == 1  # dep depends on the widget node
    # Detection flowed into RCA and pack provenance is surfaced.
    assert len(result.extra["rca"]) == 1
    assert result.extra["packSources"][0]["id"] == "demo-pack"


def test_run_windowed_metric_not_in_any_threshold_is_still_fetched() -> None:
    # A windowed detector over a metric that no threshold rule names must still get observations.
    body = {
        "signals": [
            _signal(name="lonely_metric", threshold=1, window={"samples": 2, "aggregate": "avg"})
        ]
    }
    packs = _FakePacks([(_FakeManifest("demo-pack", "1.0.0", ["demo"]), body)])
    state = _FakeState(_estate(), None)
    raws = [_raw("lonely_metric", 5, 0), _raw("lonely_metric", 7, 10)]  # avg=6>1
    ctx = ModuleContext(packs=packs, state=state, clients={"system_pulse": _PulseSource(raws)})

    result = AiopsModule().run(ctx, scope={"workload": "demo"})
    assert len(result.findings) == 1
    assert result.findings[0].id == f"detect::win::lonely_metric::{_NODE}"


def test_run_windowed_signal_does_not_double_fire_as_threshold() -> None:
    # Regression: a windowed signal must be routed ONLY to the compiled-detector path, never also
    # counted as a legacy single-sample threshold. Latest sample (30) alone would breach 15.
    body = {"signals": [_signal(threshold=15, window={"samples": 3, "aggregate": "avg"})]}
    packs = _FakePacks([(_FakeManifest("demo-pack", "1.0.0", ["demo"]), body)])

    rules, _ = load_telemetry_rules(packs, "demo")
    assert rules == []  # threshold path ignores the windowed signal
    detectors, _ = load_windowed_detectors(packs, "demo")
    assert [d.kind for d in detectors] == ["window"]

    state = _FakeState(_estate(), None)
    raws = [_raw(_METRIC, v, off) for v, off in [(10, 0), (20, 10), (30, 20)]]
    ctx = ModuleContext(packs=packs, state=state, clients={"system_pulse": _PulseSource(raws)})
    result = AiopsModule().run(ctx, scope={"workload": "demo"})
    # Exactly one finding (windowed avg), NOT an extra threshold on the latest sample.
    assert len(result.findings) == 1
    assert result.findings[0].id.startswith("detect::win::")
