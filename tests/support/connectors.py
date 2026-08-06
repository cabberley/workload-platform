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

# A clearly-fake second resource id for Kuiper supplemental-hint fixtures (never a real id).
FAKE_KUIPER_RESOURCE_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/rg/fake/kuiper-widget-99"
)

# A clearly-fake second resource id for Citrix dependency-signal fixtures (never a real id).
FAKE_CITRIX_TARGET_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/rg/fake/citrix-vda-02"
)


class MockCitrixTokenProvider:
    """A synthetic, keyless :class:`~shared.connectors.TokenProvider` — no real Citrix, no secret.

    Returns an obviously-fake bearer token so the whole keyless resolve→auth-header→fetch path is
    exercised WITHOUT any Citrix-side facts or real credential. Records how many times it was
    consulted so a test can assert an invalid endpoint never resolves a credential. Construct with
    ``token=None`` to model a provider that cannot mint a token (⇒ the connector fails closed).
    """

    def __init__(self, token: str | None = "fake-citrix-read-token") -> None:  # noqa: S107 - fake
        self.calls = 0
        self._token = token

    def __call__(self) -> str | None:
        self.calls += 1
        return self._token


def synthetic_citrix_health(
    *,
    resource_id: str = FAKE_RESOURCE_ID,
    health: str = "degraded",
) -> dict[str, Any]:
    """A synthetic Citrix *host-health* control-plane signal — obviously fake, PII/PHI-free.

    The closed schema is ``{kind, resourceId, health}``: a resource id to annotate (matched against
    an existing estate node id — never used to create a node) plus a closed-vocabulary ``health``
    token. There is deliberately no free-form field to carry PII.
    """
    return {"kind": "host-health", "resourceId": resource_id, "health": health}


def synthetic_citrix_dependency(
    *,
    resource_id: str = FAKE_RESOURCE_ID,
    depends_on: str = FAKE_CITRIX_TARGET_ID,
) -> dict[str, Any]:
    """A synthetic Citrix *session-dependency* control-plane signal — obviously fake, PII/PHI-free.

    The closed schema is ``{kind, resourceId, dependsOn}``: both endpoints are matched against
    existing estate node ids. Maps to a (deferred, un-persisted) dependency edge.
    """
    return {"kind": "session-dependency", "resourceId": resource_id, "dependsOn": depends_on}


def synthetic_kuiper_hint(
    *,
    resource_id: str = FAKE_RESOURCE_ID,
    signal: str | None = "corroborated",
) -> dict[str, Any]:
    """A synthetic Kuiper *entity-signal* discovery hint — obviously fake, PII/PHI-free.

    The closed hint schema is ``{kind, resourceId, signal}``: a resource id to CORROBORATE
    (matched against an existing ARG node id — never used to create a node) plus an optional
    closed-vocabulary ``signal``. There is deliberately no free-form field to carry PII.
    """
    hint: dict[str, Any] = {"kind": "entity-signal", "resourceId": resource_id}
    if signal is not None:
        hint["signal"] = signal
    return hint


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
