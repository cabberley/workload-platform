"""Synthetic-payload harness for driving read-only connectors — no PII/PHI, secrets or network.

Everything here is **obviously fake**: fictional resource ids, metric names and values, and a
zeroed subscription guid. There are no real endpoints, no credentials and no clinical/free-text
fields. Connector tests import these builders to exercise the edges with clearly-synthetic data.
"""
from __future__ import annotations

from typing import Any

import httpx

from shared.connectors import FetchResult

# Clearly-fake identifiers — never a real subscription, resource or metric.
FAKE_RESOURCE_ID = "/subscriptions/00000000-0000-0000-0000-000000000000/rg/fake/widget-01"
FAKE_METRIC = "fake_latency_ms"


def make_fetch_result(
    *,
    available: bool = True,
    raw: list[dict[str, Any]] | None = None,
    error: str | None = None,
) -> FetchResult:
    """Build a synthetic :class:`FetchResult` for tests."""
    return FetchResult(available=available, raw=list(raw or []), error=error)


def synthetic_signal_raw(
    *,
    metric: str = FAKE_METRIC,
    value: float = 12.5,
    unit: str = "ms",
    timestamp: str = "2026-01-01T00:00:00Z",
    resource_id: str = FAKE_RESOURCE_ID,
) -> dict[str, Any]:
    """A System-Pulse-shaped raw record — synthetic and PII-free."""
    return {
        "metric": metric,
        "value": value,
        "unit": unit,
        "timestamp": timestamp,
        "resourceId": resource_id,
    }


def synthetic_metrics_payload(
    *,
    resource_id: str = FAKE_RESOURCE_ID,
    metric: str = FAKE_METRIC,
    values: tuple[float, ...] = (12.5,),
    unit: str = "ms",
) -> dict[str, Any]:
    """An Azure-Monitor-shaped normalized payload (resource→metrics→timeseries→data)."""
    data = [
        {"timeStamp": f"2026-01-01T00:0{i}:00Z", "average": value}
        for i, value in enumerate(values)
    ]
    return {
        "resourceId": resource_id,
        "metrics": [{"name": metric, "unit": unit, "timeseries": [{"data": data}]}],
    }


def json_transport(payload: Any, *, status_code: int = 200) -> httpx.MockTransport:
    """A fake httpx transport that always returns ``payload`` as JSON — no real network."""

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json=payload)

    return httpx.MockTransport(handle)


def raising_transport(exc: Exception) -> httpx.MockTransport:
    """A fake httpx transport that always raises ``exc`` (drives fail-closed / retry paths)."""

    def handle(request: httpx.Request) -> httpx.Response:
        raise exc

    return httpx.MockTransport(handle)


def flaky_transport(exc: Exception, *, fail_times: int, then_payload: Any) -> httpx.MockTransport:
    """Raise ``exc`` for the first ``fail_times`` calls, then return ``then_payload`` as JSON."""
    state = {"n": 0}

    def handle(request: httpx.Request) -> httpx.Response:
        if state["n"] < fail_times:
            state["n"] += 1
            raise exc
        return httpx.Response(200, json=then_payload)

    return httpx.MockTransport(handle)


class FakeMetricsBackend:
    """A synthetic ``MetricsBackend`` returning fixed payloads — no Azure SDK, no network."""

    def __init__(self, payloads: list[dict[str, Any]]) -> None:
        self._payloads = payloads
        self.calls = 0

    def query_metrics(self, **_: Any) -> list[dict[str, Any]]:
        self.calls += 1
        return list(self._payloads)


class FlakyMetricsBackend:
    """Raise ``exc`` for the first ``fail_times`` queries, then return ``payloads``."""

    def __init__(
        self, exc: Exception, *, fail_times: int, payloads: list[dict[str, Any]]
    ) -> None:
        self._exc = exc
        self._fail_times = fail_times
        self._payloads = payloads
        self.calls = 0

    def query_metrics(self, **_: Any) -> list[dict[str, Any]]:
        self.calls += 1
        if self.calls <= self._fail_times:
            raise self._exc
        return list(self._payloads)


class RecordingSleep:
    """A ``sleep`` stand-in that records durations instead of sleeping — tests never wait."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)
