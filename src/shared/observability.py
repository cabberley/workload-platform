"""Platform self-observability — readiness aggregation, internal metrics, tracing seams (#60).

The platform must observe **itself**: liveness/readiness, in-process metrics, and tracing hooks
across the API core, modules and workers. This module is the cross-cutting home for that logic so
the API core and service entrypoints can use it without any module importing another module.

Design follows the house rules:

* **Pure logic ⟂ I/O.** :func:`aggregate_readiness`, the :class:`MetricsRegistry` math, and
  :func:`build_metrics_snapshot` are pure and unit-tested. The only I/O edge here is the thin
  :func:`store_reachable_probe` wrapper, which turns a cheap store read into a fail-closed
  :class:`ProbeResult` (any exception ⇒ not ready, never a crash).
* **Fail closed.** Readiness is True only when every probed dependency is positively verified;
  an unknown/errored probe forces NOT ready.
* **Keyless / no PII.** Nothing here reads a secret or exports anything by default. Metric labels
  and span attributes must be bounded, low-cardinality names + numeric measures only — never a
  connection string, resource id, or PII.
* **No vendor lock.** Tracing is an OpenTelemetry-*style* seam: a no-op by default with a guarded,
  keyless export hook that can be wired to a real exporter later (``TODO(human)`` below).
"""
from __future__ import annotations

import threading
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from time import perf_counter
from typing import Protocol

from shared.connectors.base import FailClosedObserver
from shared.contracts import (
    DependencyStatus,
    DurationSample,
    MetricSample,
    MetricsSnapshot,
    ReadinessReport,
)
from shared.state import ReadableState

# Well-known dependency names surfaced by readiness (low-cardinality, stable, non-sensitive).
DEP_STATE_STORE = "state_store"
DEP_PACKS_ENGINE = "packs_engine"
DEP_EDGE_CLIENTS = "edge_clients"

# Bounded metric names + label keys/values. Keeping these as constants keeps cardinality low and
# labels PII-free by construction (only a module name + a fixed outcome vocabulary are ever used).
METRIC_MODULE_RUNS = "module_runs_total"
METRIC_MODULE_RUN_DURATION = "module_run_duration_ms"
METRIC_CONNECTOR_FAIL_CLOSED = "connector_fail_closed_total"
LABEL_MODULE = "module"
LABEL_OUTCOME = "outcome"
OUTCOME_OK = "ok"
OUTCOME_ERROR = "error"


# --------------------------------------------------------------------------------------
# Readiness — PURE aggregation + one thin, fail-closed I/O probe.
# --------------------------------------------------------------------------------------
@dataclass(frozen=True)
class ProbeResult:
    """Outcome of probing a single dependency (the input to :func:`aggregate_readiness`).

    ``ok`` is tri-state: ``True`` = positively verified ready, ``False`` = verified not ready,
    ``None`` = unknown (probe could not determine). Aggregation treats anything other than ``True``
    as not-ready, so unknown fails closed.
    """

    name: str
    ok: bool | None
    detail: str | None = None


def aggregate_readiness(probes: Sequence[ProbeResult]) -> ReadinessReport:
    """Fold per-dependency :class:`ProbeResult` s into an overall :class:`ReadinessReport`.

    PURE and fail-closed: overall ``ready`` is True only when there is at least one probe AND every
    probe is positively ``ok is True``. An empty probe set (nothing known) or any ``False``/``None``
    (unknown) probe yields NOT ready. Each probe becomes a :class:`DependencyStatus` whose ``ok`` is
    ``probe.ok is True`` so an unknown probe is reported as not-ok.
    """
    dependencies = [
        DependencyStatus(name=p.name, ok=(p.ok is True), detail=p.detail) for p in probes
    ]
    ready = bool(dependencies) and all(dep.ok for dep in dependencies)
    return ReadinessReport(ready=ready, dependencies=dependencies)


def store_reachable_probe(
    reader: ReadableState, *, name: str = DEP_STATE_STORE
) -> ProbeResult:
    """Thin I/O edge: probe state-store reachability backend-agnostically, failing closed.

    Performs a single cheap read through the backend-agnostic :class:`~shared.state.ReadableState`
    interface (``list_workloads``) so it works for BOTH the local and Azure backends without
    coupling to either. ANY exception is swallowed into a not-ready :class:`ProbeResult` (``ok`` =
    False) — the readiness endpoint must never crash. The ``detail`` is a fixed, non-sensitive
    string; the exception (which could carry a connection string) is deliberately NOT included.
    """
    try:
        reader.list_workloads()
    except Exception:  # noqa: BLE001 - fail closed: any store error ⇒ not ready, never crash
        return ProbeResult(name=name, ok=False, detail="probe error")
    return ProbeResult(name=name, ok=True, detail="reachable")


# --------------------------------------------------------------------------------------
# Metrics — a lightweight, keyless, thread-safe in-process registry.
# --------------------------------------------------------------------------------------
def _freeze_labels(labels: Mapping[str, str] | None) -> tuple[tuple[str, str], ...]:
    """Return a deterministic, hashable key for ``labels`` (sorted; empty when None)."""
    if not labels:
        return ()
    return tuple(sorted(labels.items()))


def _labels_dict(key: tuple[tuple[str, str], ...]) -> dict[str, str]:
    return dict(key)


@dataclass
class _DurationAcc:
    """Streaming aggregate for a labelled duration measure (milliseconds)."""

    count: int = 0
    total_ms: float = 0.0
    min_ms: float = 0.0
    max_ms: float = 0.0

    def observe(self, value_ms: float) -> None:
        if self.count == 0:
            self.min_ms = value_ms
            self.max_ms = value_ms
        else:
            self.min_ms = min(self.min_ms, value_ms)
            self.max_ms = max(self.max_ms, value_ms)
        self.count += 1
        self.total_ms += value_ms


def build_metrics_snapshot(
    counters: Mapping[tuple[str, tuple[tuple[str, str], ...]], int],
    durations: Mapping[tuple[str, tuple[tuple[str, str], ...]], _DurationAcc],
) -> MetricsSnapshot:
    """PURE: serialize raw counter/duration maps into a deterministic :class:`MetricsSnapshot`.

    Sorted by (name, labels) so the JSON snapshot is stable and diffable. Kept separate from the
    registry so the serialization math is unit-testable without any threading or timing.
    """
    counter_samples = [
        MetricSample(name=name, labels=_labels_dict(labels), value=value)
        for (name, labels), value in sorted(counters.items())
    ]
    duration_samples = [
        DurationSample(
            name=name,
            labels=_labels_dict(labels),
            count=acc.count,
            totalMs=acc.total_ms,
            minMs=acc.min_ms,
            maxMs=acc.max_ms,
        )
        for (name, labels), acc in sorted(durations.items())
    ]
    return MetricsSnapshot(counters=counter_samples, durations=duration_samples)


class MetricsRegistry:
    """In-process, keyless counters + duration aggregates, safe for the API's threaded model.

    A single lock guards all mutation and snapshotting — the API is a low-replica single-writer
    service, so a coarse lock is more than enough and keeps the math obviously correct. Labels are
    the caller's responsibility to keep bounded and PII-free; the domain helpers
    (:meth:`record_module_run`, :meth:`record_connector_fail_closed`) only ever emit a module name
    + a fixed outcome, which is the sanctioned low-cardinality shape.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], int] = {}
        self._durations: dict[tuple[str, tuple[tuple[str, str], ...]], _DurationAcc] = {}

    def _increment_locked(
        self, name: str, labels_key: tuple[tuple[str, str], ...], amount: int
    ) -> None:
        """Mutate the counter map. Caller MUST hold ``self._lock``."""
        key = (name, labels_key)
        self._counters[key] = self._counters.get(key, 0) + amount

    def _observe_duration_locked(
        self, name: str, labels_key: tuple[tuple[str, str], ...], value_ms: float
    ) -> None:
        """Mutate the duration map. Caller MUST hold ``self._lock``."""
        key = (name, labels_key)
        acc = self._durations.get(key)
        if acc is None:
            acc = _DurationAcc()
            self._durations[key] = acc
        acc.observe(value_ms)

    def increment(
        self, name: str, *, labels: Mapping[str, str] | None = None, amount: int = 1
    ) -> None:
        """Add ``amount`` (default 1) to the counter identified by ``name`` + ``labels``."""
        labels_key = _freeze_labels(labels)
        with self._lock:
            self._increment_locked(name, labels_key, amount)

    def observe_duration(
        self, name: str, value_ms: float, *, labels: Mapping[str, str] | None = None
    ) -> None:
        """Record one duration observation (milliseconds) for ``name`` + ``labels``."""
        labels_key = _freeze_labels(labels)
        with self._lock:
            self._observe_duration_locked(name, labels_key, value_ms)

    def record_module_run(self, module: str, *, ok: bool, duration_ms: float) -> None:
        """Domain helper: count a module run and record its duration, labelled name+outcome.

        Labels are strictly ``{module: <name>, outcome: ok|error}`` — bounded and PII-free. This is
        the seam the API's run endpoint calls at the edge (never reaching into a module's guts).

        The counter bump and the duration observation happen in a **single** critical section, so a
        concurrent :meth:`snapshot` can never see the count without its matching duration (no torn
        read between the two measures for one run).
        """
        outcome = OUTCOME_OK if ok else OUTCOME_ERROR
        labels_key = _freeze_labels({LABEL_MODULE: module, LABEL_OUTCOME: outcome})
        with self._lock:
            self._increment_locked(METRIC_MODULE_RUNS, labels_key, 1)
            self._observe_duration_locked(METRIC_MODULE_RUN_DURATION, labels_key, duration_ms)

    def record_connector_fail_closed(self, module: str) -> None:
        """Domain helper: increment the fail-closed counter for ``module`` (low-cardinality).

        Exposed as an injectable seam so a module edge can report a connector failing closed
        WITHOUT another module importing this registry directly — the API/composition root passes
        this bound method (or a callback wrapping it) into the edge.
        """
        self.increment(METRIC_CONNECTOR_FAIL_CLOSED, labels={LABEL_MODULE: module})

    def snapshot(self) -> MetricsSnapshot:
        """Return a deterministic, point-in-time :class:`MetricsSnapshot` (copied under lock)."""
        with self._lock:
            counters = dict(self._counters)
            durations = {k: _DurationAcc(v.count, v.total_ms, v.min_ms, v.max_ms)
                         for k, v in self._durations.items()}
        return build_metrics_snapshot(counters, durations)


# The one process-wide metrics registry. The API exposes THIS instance at ``/api/metrics`` and the
# composition root (``cli.wiring``) wires connector fail-closed observers into THIS instance, so a
# real fail-closed event in a connector shows up in the same snapshot operators read. Kept as a
# lazily-built singleton so importing this module has no side effects; ``build`` is guarded by a
# lock so concurrent first-use cannot create two registries.
_process_metrics: MetricsRegistry | None = None
_process_metrics_lock = threading.Lock()


def process_metrics() -> MetricsRegistry:
    """Return the process-wide :class:`MetricsRegistry` singleton (built once, thread-safe)."""
    global _process_metrics
    if _process_metrics is None:
        with _process_metrics_lock:
            if _process_metrics is None:
                _process_metrics = MetricsRegistry()
    return _process_metrics


def connector_fail_closed_observer(
    module: str, registry: MetricsRegistry | None = None
) -> FailClosedObserver:
    """Build a keyless, zero-arg observer that counts one connector fail-closed for ``module``.

    Wired by the composition root into a connector so a real fail-closed event increments
    ``connector_fail_closed_total{module=...}`` on the process registry (or an injected ``registry``
    in tests). The label is bounded to the module name only — no PII/high-cardinality. The returned
    callable takes no data, so nothing request-identifying can ride along.
    """
    target = registry if registry is not None else process_metrics()
    return lambda: target.record_connector_fail_closed(module)


# --------------------------------------------------------------------------------------
# Tracing — OpenTelemetry-STYLE seam. No-op by default, keyless, no network export.
# --------------------------------------------------------------------------------------
@dataclass
class SpanData:
    """Immutable-ish record handed to an exporter when a span ends (name + bounded attributes).

    ``attributes`` must be low-cardinality and PII-free (e.g. module name, outcome, HTTP method) —
    never a raw path with ids, a connection string, or PII. ``duration_ms`` is wall-clock.
    """

    name: str
    attributes: dict[str, str] = field(default_factory=dict)
    duration_ms: float = 0.0


class SpanExporter(Protocol):
    """Keyless export seam. A concrete exporter is a downstream choice (see ``TODO(human)``)."""

    def export(self, span: SpanData) -> None:
        """Persist/forward a finished span. MUST NOT require secrets or block the request path."""
        ...


class Span:
    """A minimal active span: collects bounded attributes; exported (if at all) on close."""

    def __init__(self, name: str, attributes: Mapping[str, str] | None = None) -> None:
        self.name = name
        self.attributes: dict[str, str] = dict(attributes or {})
        self._start = perf_counter()

    def set_attribute(self, key: str, value: str) -> None:
        """Attach a bounded, PII-free attribute (e.g. outcome=ok). No secrets/ids."""
        self.attributes[key] = value

    def _finish(self) -> SpanData:
        return SpanData(
            name=self.name,
            attributes=dict(self.attributes),
            duration_ms=(perf_counter() - self._start) * 1000.0,
        )


class Tracer:
    """OTel-style tracer seam. Default is a **no-op**: no exporter ⇒ nothing is ever exported.

    Wiring a real exporter is a deliberate, downstream decision — the default never touches the
    network and never needs a secret, honouring keyless + fail-closed. The export call is guarded
    so a broken exporter can never break the request path.

    TODO(human): choose the concrete, keyless exporter (e.g. an OTLP exporter over Managed Identity
    to an in-boundary collector, or an Azure Monitor exporter). Wire it as the ``exporter`` here at
    the composition root; keep it off by default and never read a key/connection string in code.
    """

    def __init__(self, exporter: SpanExporter | None = None) -> None:
        self._exporter = exporter

    @property
    def enabled(self) -> bool:
        """True only when a concrete exporter is wired (default no-op tracer is False)."""
        return self._exporter is not None

    @contextmanager
    def start_span(
        self, name: str, *, attributes: Mapping[str, str] | None = None
    ) -> Iterator[Span]:
        """Start a span around a boundary; on exit, export it IFF an exporter is wired.

        No-op-safe: with no exporter the only work is creating the :class:`Span` object and reading
        a monotonic clock — no allocation of exporters, no I/O. Export errors are swallowed so the
        traced code path is never affected by observability.
        """
        span = Span(name, attributes)
        try:
            yield span
        finally:
            if self._exporter is not None:
                data = span._finish()
                # Guarded: a broken exporter must never break the traced request path.
                with suppress(Exception):
                    self._exporter.export(data)
