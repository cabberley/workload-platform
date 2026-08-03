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


def synthetic_logs_payload(
    *,
    resource_id: str = FAKE_RESOURCE_ID,
    metric: str = FAKE_METRIC,
    values: tuple[float, ...] = (12.5,),
    unit: str = "aggregated",
) -> dict[str, Any]:
    """An Azure-Monitor-shaped **aggregated logs** payload (``{"logRecords": [...]}``).

    Every record is an aggregated numeric datapoint — never a raw log body/message/row.
    """
    return {
        "logRecords": [
            {
                "metric": metric,
                "value": value,
                "unit": unit,
                "timestamp": f"2026-01-01T00:0{i}:00Z",
                "resourceId": resource_id,
            }
            for i, value in enumerate(values)
        ]
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
        self.last_kwargs: dict[str, Any] = {}

    def query_metrics(self, **kwargs: Any) -> list[dict[str, Any]]:
        self.calls += 1
        self.last_kwargs = kwargs
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


class FakeLogsBackend:
    """A synthetic ``LogsBackend`` returning fixed aggregated payloads — no Azure SDK/network."""

    def __init__(self, payloads: list[dict[str, Any]]) -> None:
        self._payloads = payloads
        self.calls = 0
        self.last_kwargs: dict[str, Any] = {}

    def query_logs(self, **kwargs: Any) -> list[dict[str, Any]]:
        self.calls += 1
        self.last_kwargs = kwargs
        return list(self._payloads)


class RaisingLogsBackend:
    """A ``LogsBackend`` that always raises ``exc`` — drives the logs fail-closed path."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc
        self.calls = 0

    def query_logs(self, **_: Any) -> list[dict[str, Any]]:
        self.calls += 1
        raise self._exc


class RecordingSleep:
    """A ``sleep`` stand-in that records durations instead of sleeping — tests never wait."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


class FakeMetricsSdkClient:
    """A fake ``MetricsClient`` for the ``_SdkMetricsBackend`` ``client_factory`` seam.

    Records the endpoint/credential it was built with and the ``query_resources`` kwargs (so a test
    can assert the configured timeout is forwarded), and returns an empty result set — no SDK,
    no network, no token actually sent.
    """

    def __init__(self, endpoint: str, credential: Any) -> None:
        self.endpoint = endpoint
        self.credential = credential
        self.query_kwargs: dict[str, Any] = {}
        self.closed = False

    def query_resources(self, **kwargs: Any) -> list[Any]:
        self.query_kwargs = kwargs
        return []

    def close(self) -> None:
        self.closed = True


class FakeLogsSdkColumnTable:
    """A fake logs result table (``.columns`` / ``.rows``)."""

    def __init__(self, columns: list[str], rows: list[list[Any]]) -> None:
        self.columns = columns
        self.rows = rows


class FakeLogsSdkResult:
    """A fake ``LogsQueryResult`` (``.status`` + ``.tables``)."""

    def __init__(self, status: Any, tables: list[FakeLogsSdkColumnTable]) -> None:
        self.status = status
        self.tables = tables


class FakeLogsSdkClient:
    """A fake ``LogsQueryClient`` for the ``_SdkLogsBackend`` ``client_factory`` seam.

    Records the ``query_workspace`` kwargs (so a test can assert ``server_timeout`` is forwarded)
    and returns a fixed, successful, aggregated result — no SDK, no network.
    """

    def __init__(
        self, credential: Any, *, status: Any, tables: list[FakeLogsSdkColumnTable]
    ) -> None:
        self.credential = credential
        self._status = status
        self._tables = tables
        self.query_kwargs: dict[str, Any] = {}
        self.closed = False

    def query_workspace(self, workspace_id: str, query: str, **kwargs: Any) -> FakeLogsSdkResult:
        self.query_kwargs = {"workspace_id": workspace_id, "query": query, **kwargs}
        return FakeLogsSdkResult(self._status, self._tables)

    def close(self) -> None:
        self.closed = True


class FakeLogsPartialResult:
    """A real-shaped ``LogsQueryPartialResult``: a PARTIAL status with ``.partial_data`` and NO
    ``.tables`` — used to prove a partial result is NOT reported as a successful empty (MED 3)."""

    def __init__(self, status: Any, partial_data: list[Any] | None = None) -> None:
        self.status = status
        self.partial_data = partial_data or []
