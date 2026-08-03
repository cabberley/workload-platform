"""Unit tests for platform self-observability (issue #60).

Covers the PURE logic — readiness aggregation (fail-closed), the metrics registry math + snapshot
serialization, and the tracing hook's no-op-by-default behavior — plus the one thin I/O edge, the
fail-closed store-reachability probe. All Azure-free and deterministic; no secrets, no PII.
"""
from __future__ import annotations

from shared.contracts import MetricsSnapshot, ReadinessReport
from shared.observability import (
    DEP_STATE_STORE,
    METRIC_CONNECTOR_FAIL_CLOSED,
    METRIC_MODULE_RUN_DURATION,
    METRIC_MODULE_RUNS,
    MetricsRegistry,
    ProbeResult,
    SpanData,
    Tracer,
    aggregate_readiness,
    build_metrics_snapshot,
    connector_fail_closed_observer,
    process_metrics,
    store_reachable_probe,
)


# --------------------------------------------------------------------------------------
# Readiness aggregation — PURE, fail-closed.
# --------------------------------------------------------------------------------------
def test_aggregate_readiness_all_ready() -> None:
    probes = [
        ProbeResult("state_store", ok=True, detail="reachable"),
        ProbeResult("packs_engine", ok=True, detail="absent"),
        ProbeResult("edge_clients", ok=True, detail="constructed (0 clients)"),
    ]
    report = aggregate_readiness(probes)
    assert isinstance(report, ReadinessReport)
    assert report.ready is True
    assert [d.name for d in report.dependencies] == ["state_store", "packs_engine", "edge_clients"]
    assert all(d.ok for d in report.dependencies)


def test_aggregate_readiness_one_down_is_not_ready() -> None:
    probes = [
        ProbeResult("state_store", ok=True),
        ProbeResult("packs_engine", ok=False, detail="probe error"),
        ProbeResult("edge_clients", ok=True),
    ]
    report = aggregate_readiness(probes)
    assert report.ready is False
    down = {d.name: d.ok for d in report.dependencies}
    assert down == {"state_store": True, "packs_engine": False, "edge_clients": True}


def test_aggregate_readiness_unknown_probe_fails_closed() -> None:
    # ok=None means "unknown": it must be reported not-ok and force overall not-ready.
    probes = [ProbeResult("state_store", ok=True), ProbeResult("edge_clients", ok=None)]
    report = aggregate_readiness(probes)
    assert report.ready is False
    unknown = next(d for d in report.dependencies if d.name == "edge_clients")
    assert unknown.ok is False


def test_aggregate_readiness_empty_is_not_ready() -> None:
    # No probes = nothing positively verified ⇒ fail closed.
    report = aggregate_readiness([])
    assert report.ready is False
    assert report.dependencies == []


# --------------------------------------------------------------------------------------
# Store-reachability probe — thin I/O edge, fail-closed on ANY exception.
# --------------------------------------------------------------------------------------
class _OkReader:
    def list_workloads(self) -> list[str]:
        return ["epic"]


class _BoomReader:
    def list_workloads(self) -> list[str]:
        raise RuntimeError("secret://connection-string-should-never-surface")


def test_store_reachable_probe_ok() -> None:
    probe = store_reachable_probe(_OkReader())  # type: ignore[arg-type]
    assert probe.name == DEP_STATE_STORE
    assert probe.ok is True
    assert probe.detail == "reachable"


def test_store_reachable_probe_exception_is_not_ready_and_hides_detail() -> None:
    probe = store_reachable_probe(_BoomReader())  # type: ignore[arg-type]
    assert probe.ok is False
    # The exception text (which could carry a connection string) must NOT leak into detail.
    assert probe.detail == "probe error"
    assert "connection-string" not in (probe.detail or "")


# --------------------------------------------------------------------------------------
# Metrics registry + snapshot — PURE math, thread-safe registry.
# --------------------------------------------------------------------------------------
def test_counter_increment_and_snapshot() -> None:
    reg = MetricsRegistry()
    reg.increment("things_total", labels={"kind": "a"})
    reg.increment("things_total", labels={"kind": "a"}, amount=2)
    reg.increment("things_total", labels={"kind": "b"})

    snap = reg.snapshot()
    assert isinstance(snap, MetricsSnapshot)
    by_kind = {tuple(sorted(s.labels.items())): s.value for s in snap.counters}
    assert by_kind[(("kind", "a"),)] == 3
    assert by_kind[(("kind", "b"),)] == 1


def test_observe_duration_aggregates() -> None:
    reg = MetricsRegistry()
    for ms in (10.0, 30.0, 20.0):
        reg.observe_duration("op_ms", ms, labels={"op": "x"})

    snap = reg.snapshot()
    assert len(snap.durations) == 1
    d = snap.durations[0]
    assert d.count == 3
    assert d.totalMs == 60.0
    assert d.minMs == 10.0
    assert d.maxMs == 30.0


def test_record_module_run_uses_bounded_labels() -> None:
    reg = MetricsRegistry()
    reg.record_module_run("quality_checks", ok=True, duration_ms=12.5)
    reg.record_module_run("quality_checks", ok=False, duration_ms=4.0)

    snap = reg.snapshot()
    run_counter = {
        tuple(sorted(s.labels.items())): s.value
        for s in snap.counters
        if s.name == METRIC_MODULE_RUNS
    }
    assert run_counter[(("module", "quality_checks"), ("outcome", "ok"))] == 1
    assert run_counter[(("module", "quality_checks"), ("outcome", "error"))] == 1
    # Labels are strictly bounded to module + outcome (no PII / high-cardinality free text).
    for sample in snap.counters:
        assert set(sample.labels) <= {"module", "outcome"}
    assert any(d.name == METRIC_MODULE_RUN_DURATION for d in snap.durations)


def test_record_connector_fail_closed_counter() -> None:
    reg = MetricsRegistry()
    reg.record_connector_fail_closed("aiops")
    reg.record_connector_fail_closed("aiops")

    snap = reg.snapshot()
    fc = next(s for s in snap.counters if s.name == METRIC_CONNECTOR_FAIL_CLOSED)
    assert fc.labels == {"module": "aiops"}
    assert fc.value == 2


def test_record_module_run_counter_and_duration_in_lockstep() -> None:
    # MED 2: the counter bump + duration observation are one atomic critical section, so a snapshot
    # always sees the counter and its matching duration count in lockstep (never a torn read).
    reg = MetricsRegistry()
    for _ in range(50):
        reg.record_module_run("discovery", ok=True, duration_ms=1.0)

    snap = reg.snapshot()
    counter = next(s for s in snap.counters if s.name == METRIC_MODULE_RUNS)
    duration = next(d for d in snap.durations if d.name == METRIC_MODULE_RUN_DURATION)
    assert counter.value == duration.count == 50


def test_record_module_run_no_torn_read_under_concurrency() -> None:
    import threading

    reg = MetricsRegistry()
    writers = 4
    per_writer = 1500
    stop = threading.Event()
    torn: list[tuple[int, int]] = []

    def write() -> None:
        for _ in range(per_writer):
            reg.record_module_run("discovery", ok=True, duration_ms=1.0)

    def read() -> None:
        while not stop.is_set():
            snap = reg.snapshot()
            cval = next(
                (s.value for s in snap.counters if s.name == METRIC_MODULE_RUNS), 0
            )
            dcount = next(
                (d.count for d in snap.durations if d.name == METRIC_MODULE_RUN_DURATION), 0
            )
            if cval != dcount:  # a torn read: counter without its matching duration
                torn.append((cval, dcount))

    readers = [threading.Thread(target=read) for _ in range(2)]
    writer_threads = [threading.Thread(target=write) for _ in range(writers)]
    for r in readers:
        r.start()
    for w in writer_threads:
        w.start()
    for w in writer_threads:
        w.join()
    stop.set()
    for r in readers:
        r.join()

    assert torn == []  # every observed snapshot was consistent
    final = reg.snapshot()
    counter = next(s for s in final.counters if s.name == METRIC_MODULE_RUNS)
    duration = next(d for d in final.durations if d.name == METRIC_MODULE_RUN_DURATION)
    assert counter.value == duration.count == writers * per_writer


def test_connector_fail_closed_observer_targets_injected_registry() -> None:
    # MED 3: the observer helper builds a keyless, zero-arg callback bound to a bounded label.
    reg = MetricsRegistry()
    observer = connector_fail_closed_observer("aiops", reg)
    observer()
    observer()

    fc = next(s for s in reg.snapshot().counters if s.name == METRIC_CONNECTOR_FAIL_CLOSED)
    assert fc.labels == {"module": "aiops"}
    assert fc.value == 2


def test_connector_fail_closed_observer_defaults_to_process_registry() -> None:
    # With no explicit registry the observer targets the process-wide singleton the API exposes.
    proc = process_metrics()
    assert process_metrics() is proc  # stable singleton
    before = next(
        (s.value for s in proc.snapshot().counters if s.name == METRIC_CONNECTOR_FAIL_CLOSED),
        0,
    )
    connector_fail_closed_observer("aiops")()
    after = next(
        s.value for s in proc.snapshot().counters if s.name == METRIC_CONNECTOR_FAIL_CLOSED
    )
    assert after == before + 1


def test_build_metrics_snapshot_is_deterministically_sorted() -> None:
    counters = {("b_total", (("k", "2"),)): 5, ("a_total", (("k", "1"),)): 1}
    snap = build_metrics_snapshot(counters, {})
    assert [s.name for s in snap.counters] == ["a_total", "b_total"]


def test_empty_snapshot() -> None:
    snap = MetricsRegistry().snapshot()
    assert snap.counters == []
    assert snap.durations == []


# --------------------------------------------------------------------------------------
# Tracing — OTel-style seam; NO-OP by default, guarded export.
# --------------------------------------------------------------------------------------
class _RecordingExporter:
    def __init__(self) -> None:
        self.spans: list[SpanData] = []

    def export(self, span: SpanData) -> None:
        self.spans.append(span)


class _BrokenExporter:
    def export(self, span: SpanData) -> None:
        raise RuntimeError("exporter down")


def test_tracer_noop_by_default_exports_nothing() -> None:
    tracer = Tracer()
    assert tracer.enabled is False
    with tracer.start_span("module.run", attributes={"module": "discovery"}) as span:
        span.set_attribute("outcome", "ok")
    # Nothing to assert on export (there is none); reaching here proves no crash / no I/O needed.
    assert span.attributes == {"module": "discovery", "outcome": "ok"}


def test_tracer_exports_span_when_exporter_wired() -> None:
    exporter = _RecordingExporter()
    tracer = Tracer(exporter)
    assert tracer.enabled is True
    with tracer.start_span("http.request", attributes={"http.method": "GET"}) as span:
        span.set_attribute("http.status_code", "200")

    assert len(exporter.spans) == 1
    exported = exporter.spans[0]
    assert exported.name == "http.request"
    assert exported.attributes == {"http.method": "GET", "http.status_code": "200"}
    assert exported.duration_ms >= 0.0


def test_tracer_swallows_exporter_errors() -> None:
    tracer = Tracer(_BrokenExporter())
    # A broken exporter must never break the traced path.
    with tracer.start_span("module.run"):
        pass
