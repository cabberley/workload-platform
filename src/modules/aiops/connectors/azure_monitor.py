"""Azure Monitor connector — read-only, keyless, fail-closed metrics client.

Azure Monitor is a second **read-only** telemetry source for the AIOps module (alongside System
Pulse). This connector mirrors the System Pulse edge contract exactly so the module can fuse both
sources uniformly:

* it emits the **same** :class:`~modules.aiops.connectors.system_pulse.Signal` shape and reuses
  System Pulse's PII-safe, fail-closed :func:`~modules.aiops.connectors.system_pulse.map_signal`
  and :class:`~modules.aiops.connectors.system_pulse.FetchResult` — there is **no** divergent
  signal contract;
* it isolates **all** SDK/network I/O in one edge method — :meth:`AzureMonitorClient.fetch_raw`.
  The ``azure-monitor-query`` SDK is imported **lazily inside that method** so importing this
  module never needs the SDK, keeping unit tests (and ``mypy``) Azure-free;
* it is **keyless** — Managed Identity via an *injected* credential provider (a callable returning
  an ``azure.core.credentials.TokenCredential`` or ``None``). No secret, key, or connection string
  is ever read, embedded, or logged;
* it **fails closed** — if no credential resolves, or the backend raises, it returns
  ``available=False`` with the error **class name only** (never a body, token, or message) and
  makes **no** unauthenticated call;
* the flatten/normalize step (Azure Monitor's nested metrics→timeseries→data payload → flat
  ``Signal[]``) is a **pure** function unit-tested with synthetic payloads.

This connector exposes **two** read-only edges, both keyless, lazy, guarded and fail-closed:

* **Metrics** — a real ``MetricsClient`` query from the ``azure-monitor-querymetrics`` package
  (the metrics client moved *out* of ``azure-monitor-query`` 2.0.0 into that split package). The
  SDK is imported **lazily inside the backend edge**; if the optional package is not importable at
  runtime the edge fails closed with the descriptive ``AzureMonitorSdkNotWired`` class name (never a
  misleading ``AttributeError``).
* **Logs** — a real ``LogsQueryClient`` query from ``azure-monitor-query`` (already installed),
  running **only bounded, aggregated KQL** (counts / averages / percentiles per resource+metric).
  The KQL is produced by the **pure** :func:`build_logs_kql` transform and never selects a log
  body / message / free-text column, so **no raw log row ever crosses the boundary** — the logs
  edge emits only aggregated numeric :class:`Signal`\\ s.

Both flatten steps (Azure Monitor's nested metrics→timeseries→data payload, and the aggregated
logs table) are **pure** functions unit-tested with synthetic payloads. Every emitted signal is
stamped ``source = SignalSource.azure_monitor`` so fused signals self-describe their origin.
"""
from __future__ import annotations

import random
import time
from collections.abc import Callable, Sequence
from datetime import timedelta
from typing import Any, Protocol, cast, runtime_checkable
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from modules.aiops.connectors.system_pulse import (
    Signal,
    SignalMappingError,
    SignalSource,
    map_signal,
)
from shared.connectors import (
    CredentialProvider,
    FetchResult,
    fail_closed,
    run_with_retries,
)

# ``CredentialProvider`` and ``FetchResult`` now live in the shared connector base (issue #45).
# ``CredentialProvider`` is re-exported here (see ``__all__``) for backward compatibility. A
# credential provider mints a keyless ``TokenCredential`` (e.g. a closure over
# ``DefaultAzureCredential(...)``) or returns ``None`` if it cannot; kept as an injected callable
# so ``azure-identity`` stays an edge-only, non-top-level concern and tests stay Azure-free.

# Aggregation columns Azure Monitor returns per data point, in the order we prefer to read them.
_AGGREGATIONS: tuple[str, ...] = ("average", "total", "maximum", "minimum", "count")


class AzureMonitorConfig(BaseModel):
    """Connector configuration. Holds no secrets — only resource ids and query parameters."""

    model_config = ConfigDict(extra="forbid")

    resource_ids: list[str] = Field(
        default_factory=list, description="Azure resource ids to query metrics for"
    )
    metric_names: list[str] = Field(
        default_factory=list, description="Default metric names to fetch when none are supplied"
    )
    timeout_s: float = Field(default=30.0, gt=0.0)
    credential_scope: str = Field(default="https://management.azure.com/.default")
    # --- Metrics edge (azure-monitor-querymetrics MetricsClient) ---------------------------
    # A *regional* metrics data-plane endpoint is required by MetricsClient (queried resources must
    # live in the same region + subscription). Absent ⇒ the metrics edge fails closed; no secret.
    metrics_endpoint: str | None = Field(
        default=None, description="Regional metrics endpoint, e.g. https://westus3.metrics.monitor.azure.com"
    )
    metric_namespace: str | None = Field(
        default=None, description="Metric namespace containing the requested metric names"
    )
    metric_granularity_minutes: int = Field(
        default=5, ge=1, description="Metrics granularity (bin size) in minutes"
    )
    metric_lookback_minutes: int = Field(
        default=15, ge=1, description="Metrics timespan window (lookback) in minutes"
    )
    # --- Logs edge (azure-monitor-query LogsQueryClient) -----------------------------------
    # A Log Analytics *workspace id* (the GUID from the workspace Properties blade — not a secret).
    # Absent ⇒ the logs edge is disabled and fails closed. The KQL table + every projected column
    # are FIXED, audited constants (see ``build_logs_kql``) — deliberately NOT config-driven — so no
    # caller can alias a raw log-body column into an emitted field. Only the query window/bin are
    # tunable here.
    workspace_id: str | None = Field(
        default=None, description="Log Analytics workspace id (GUID) for the logs edge"
    )
    log_bin_minutes: int = Field(default=5, ge=1, description="KQL summarize bin size in minutes")
    log_lookback_hours: float = Field(
        default=1.0, gt=0.0, description="Logs query timespan window (lookback) in hours"
    )
    # Bounded retry-with-jitter for transient backend/transport errors (issue #45). Defaults are
    # conservative and never change fail-closed behaviour: after ``retries`` attempts the edge
    # still fails closed. Only transient errors are retried (see ``_is_transient_backend``); a
    # guarded-import failure, credential errors and malformed payloads fail closed at once.
    retries: int = Field(default=3, ge=1, description="Max query attempts (>=1)")
    base_delay_s: float = Field(default=0.2, gt=0.0, description="Base backoff delay in seconds")
    max_delay_s: float = Field(default=2.0, gt=0.0, description="Backoff cap in seconds")


# --------------------------------------------------------------------------------------
# Pure mapping — no I/O, fully unit-testable with synthetic Azure Monitor payloads.
# --------------------------------------------------------------------------------------
def _stamp_azure_monitor(signal: Signal) -> Signal:
    """Re-stamp a mapped signal with Azure Monitor provenance.

    ``map_signal`` (owned by System Pulse) defaults ``source = SignalSource.system_pulse``; every
    signal this connector emits is re-stamped ``SignalSource.azure_monitor`` so a fused signal
    self-describes its origin. ``model_copy`` keeps the validated, PII-safe field set intact.
    """
    return signal.model_copy(update={"source": SignalSource.azure_monitor})


def _pick_aggregation(point: Any) -> Any:
    """Return the first present, non-bool aggregation value on a data point, else ``None``."""
    if not isinstance(point, dict):
        return None
    for agg in _AGGREGATIONS:
        value = point.get(agg)
        if value is not None and not isinstance(value, bool):
            return value
    return None


def map_metrics_response(payload: Any) -> list[Signal]:
    """Flatten one Azure Monitor metrics payload into ``Signal[]`` — **pure** and **PII-safe**.

    Expects the normalized shape the edge produces from the SDK response::

        {"resourceId": "...",
         "metrics": [{"name": "odb_latency_ms", "unit": "Milliseconds",
                      "timeseries": [{"data": [{"timeStamp": "...", "average": 512.0}]}]}]}

    Every data point is mapped through System Pulse's ``map_signal`` (which validates the value,
    normalizes the timestamp to UTC, and drops all non-allowlisted fields) and then re-stamped with
    ``SignalSource.azure_monitor``, so a malformed point is dropped — never fabricated over — and
    this function never raises on bad structure.
    """
    if not isinstance(payload, dict):
        return []
    resource_id = payload.get("resourceId")
    metrics = payload.get("metrics")
    if not isinstance(metrics, list):
        return []
    signals: list[Signal] = []
    for metric in metrics:
        if not isinstance(metric, dict):
            continue
        name = metric.get("name")
        unit = metric.get("unit", "")
        timeseries = metric.get("timeseries")
        if not isinstance(timeseries, list):
            continue
        for series in timeseries:
            if not isinstance(series, dict):
                continue
            data = series.get("data")
            if not isinstance(data, list):
                continue
            for point in data:
                value = _pick_aggregation(point)
                if value is None:
                    continue
                raw = {
                    "metric": name,
                    "value": value,
                    "unit": unit,
                    "timestamp": point.get("timeStamp") if isinstance(point, dict) else None,
                    "resourceId": resource_id,
                }
                try:
                    signals.append(_stamp_azure_monitor(map_signal(raw)))
                except SignalMappingError:
                    continue
    return signals


# The ONLY columns the logs edge lifts out of an aggregated KQL row. Anything else a table might
# carry (a message / body / free-text column) is ignored by construction — this allowlist, plus the
# body-free ``build_logs_kql`` transform, is what makes the logs path provably raw-log-free.
_LOG_RECORD_FIELDS: tuple[str, ...] = ("metric", "value", "unit", "timestamp", "resourceId")


def map_logs_response(payload: Any) -> list[Signal]:
    """Flatten one **aggregated** Azure Monitor logs payload into ``Signal[]`` — pure & PII-safe.

    Expects the normalized shape the logs edge produces from the aggregated KQL result::

        {"logRecords": [
            {"metric": "odb_latency_ms", "value": 512.0, "unit": "aggregated",
             "timestamp": "2026-01-01T00:00:00Z", "resourceId": "/subscriptions/.../odb-01"}]}

    Only :data:`_LOG_RECORD_FIELDS` are read from each record — any extra column is dropped by
    construction — then each record is mapped via ``map_signal`` and re-stamped
    ``SignalSource.azure_monitor``. Because the aggregation (:func:`build_logs_kql`) never projects
    a body/message column *and* this mapper only reads numeric-aggregate + identifier fields, **no
    raw log row can ever be emitted**. Malformed records are dropped, never fabricated over.
    """
    if not isinstance(payload, dict):
        return []
    records = payload.get("logRecords")
    if not isinstance(records, list):
        return []
    signals: list[Signal] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        raw = {
            "metric": record.get("metric"),
            "value": record.get("value"),
            "unit": record.get("unit", "aggregated"),
            "timestamp": record.get("timestamp"),
            "resourceId": record.get("resourceId"),
        }
        try:
            signals.append(_stamp_azure_monitor(map_signal(raw)))
        except SignalMappingError:
            continue
    return signals


def _kql_verbatim_literal(value: object) -> str:
    """Render one value as a KQL **verbatim** string literal (``@'...'``) — fail-closed on garbage.

    KQL verbatim literals treat backslash as a **literal** character (unlike ordinary ``'...'``
    literals, where ``\\`` is an escape). Doubling the single quote (``'`` → ``''``) is then the
    *only* escape, so a value can never terminate the literal early to break out and inject KQL —
    closing the ``\\'`` break-out an ordinary literal would allow. Non-``str`` values and values
    carrying a C0 control char / ``DEL`` (which could still split a single-line literal) are
    rejected — never silently stripped — so bad config fails closed and is surfaced.
    """
    if not isinstance(value, str):
        raise SignalMappingError(f"kql filter value must be a string: {value!r}")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise SignalMappingError("kql filter value contains a control character")
    return "@'" + value.replace("'", "''") + "'"


def _kql_str_list(values: Sequence[str]) -> str:
    """Render a KQL string list ``(@'a', @'b')`` of **verbatim** literals — bounds the ``in`` set.

    ``values`` are only ever interpolated as **verbatim quoted string literals** (filter *values*,
    never identifiers) via :func:`_kql_verbatim_literal`: backslash is literal and the single quote
    is doubled, so a configured resource id / metric name cannot break out of the literal to inject
    KQL or select a different column. Malformed values fail closed rather than corrupt the query.
    """
    return "(" + ", ".join(_kql_verbatim_literal(v) for v in values) + ")"


# --------------------------------------------------------------------------------------
# Fixed, audited KQL shape. The table and EVERY projected column are hard-coded constants — NEVER
# taken from config — so no caller can alias a raw log-body/message column into an emitted field or
# inject an arbitrary KQL identifier. The only config-driven inputs are filter *values*
# (resource ids / metric names, quote-escaped) and numeric window/bin sizes.
_LOG_TABLE = "AzureMetrics"  # a numeric platform-metrics table — never a raw-log/body table
_LOG_VALUE_COLUMN = "Average"  # numeric aggregate source column
_LOG_METRIC_COLUMN = "MetricName"  # identifier column (a metric name, not free text)
_LOG_RESOURCE_COLUMN = "_ResourceId"  # identifier column (an Azure resource id)
_LOG_TIME_COLUMN = "TimeGenerated"  # timestamp column


def build_logs_kql(
    *,
    resource_ids: Sequence[str],
    metric_names: Sequence[str],
    lookback_hours: float,
    bin_minutes: int,
) -> str:
    """Build a **bounded, aggregated** KQL query — a small, pure, reviewable transform.

    The table and every projected column are **fixed, audited constants** (never config-driven), so
    a reviewer can confirm **no raw log body / message / row ever leaves the boundary**:

    * it filters to the configured ``resource_ids`` (and ``metric_names`` when supplied) — passed
      only as **verbatim** quote-escaped string *values* — and a bounded ``lookback_hours`` window;
    * it ``summarize``\\ s **only numeric aggregates** — ``avg`` / ``percentile(95)`` / ``count`` —
      grouped by resource id, metric name and a ``bin(TimeGenerated, <n>m)`` bucket;
    * its final ``project`` is a hard-coded allowlist of identifier + numeric-aggregate columns
      (``resourceId``, ``metric``, ``value``, ``count``, ``timestamp``). It can never select a
      free-text / body / message column, so the result carries no raw log content.

    The output columns are aliased to match :data:`_LOG_RECORD_FIELDS`, so
    :func:`_normalize_logs_response` + :func:`map_logs_response` can map rows straight into signals.
    """
    lines = [
        _LOG_TABLE,
        f"| where {_LOG_TIME_COLUMN} > ago({lookback_hours}h)",
    ]
    if resource_ids:
        lines.append(f"| where {_LOG_RESOURCE_COLUMN} in~ {_kql_str_list(resource_ids)}")
    if metric_names:
        lines.append(f"| where {_LOG_METRIC_COLUMN} in~ {_kql_str_list(metric_names)}")
    lines.extend(
        [
            (
                f"| summarize value = avg({_LOG_VALUE_COLUMN}), "
                f"p95 = percentile({_LOG_VALUE_COLUMN}, 95), count = count() "
                f"by resourceId = {_LOG_RESOURCE_COLUMN}, metric = {_LOG_METRIC_COLUMN}, "
                f"timestamp = bin({_LOG_TIME_COLUMN}, {bin_minutes}m)"
            ),
            "| project resourceId, metric, value, count, timestamp",
        ]
    )
    return "\n".join(lines)


def to_signals(result: FetchResult) -> list[Signal]:
    """Flatten a fetch result into signals — pure. Unavailable ⇒ ``[]`` (fail closed).

    ``result.raw`` is a list of Azure Monitor payloads — metrics payloads (``{"metrics": [...]}``)
    and/or aggregated logs payloads (``{"logRecords": [...]}``). Each is dispatched to the matching
    pure mapper and the results concatenated. Records that fail mapping are dropped, not guessed at.
    """
    if not result.available:
        return []
    signals: list[Signal] = []
    for payload in result.raw:
        if isinstance(payload, dict) and "logRecords" in payload:
            signals.extend(map_logs_response(payload))
        else:
            signals.extend(map_metrics_response(payload))
    return signals


def _coerce_backend_raw(payload: Any) -> list[dict[str, Any]]:
    """Strictly require the backend to return a list of dict payloads. Raise otherwise.

    A broken backend surfaces as ``available=False`` rather than masquerading as empty-but-healthy.
    """
    if not isinstance(payload, list):
        raise ValueError("azure monitor backend must return a list of payloads")
    if not all(isinstance(item, dict) for item in payload):
        raise ValueError("azure monitor backend returned a non-dict payload")
    return [item for item in payload if isinstance(item, dict)]


# --------------------------------------------------------------------------------------
# Backend seam — the ONLY place that touches the Azure SDK. Injectable for tests.
# --------------------------------------------------------------------------------------
@runtime_checkable
class MetricsBackend(Protocol):
    """Narrow query seam. The real implementation wraps ``azure-monitor-querymetrics``'s
    ``MetricsClient``; tests inject a fake that returns synthetic normalized payloads (or raises to
    exercise fail-closed)."""

    def query_metrics(
        self,
        *,
        resource_ids: Sequence[str],
        metric_names: Sequence[str],
        credential: Any,
        timeout_s: float,
    ) -> list[dict[str, Any]]:
        ...


def _normalize_sdk_response(resource_id: str, response: Any) -> dict[str, Any]:
    """Convert an ``azure-monitor-query`` ``MetricsQueryResult`` into our normalized payload.

    Reads attributes defensively (``getattr``) so the pure mapper — not this edge — owns validation.
    """
    metrics_out: list[dict[str, Any]] = []
    for metric in getattr(response, "metrics", None) or []:
        series_out: list[dict[str, Any]] = []
        for series in getattr(metric, "timeseries", None) or []:
            data_out: list[dict[str, Any]] = []
            for point in getattr(series, "data", None) or []:
                data_out.append(
                    {
                        "timeStamp": getattr(point, "timestamp", None),
                        "average": getattr(point, "average", None),
                        "total": getattr(point, "total", None),
                        "maximum": getattr(point, "maximum", None),
                        "minimum": getattr(point, "minimum", None),
                        "count": getattr(point, "count", None),
                    }
                )
            series_out.append({"data": data_out})
        metrics_out.append(
            {
                "name": getattr(metric, "name", None),
                "unit": str(getattr(metric, "unit", "") or ""),
                "timeseries": series_out,
            }
        )
    return {"resourceId": resource_id, "metrics": metrics_out}


class AzureMonitorSdkNotWired(RuntimeError):
    """Raised when the optional metrics SDK package cannot be imported at query time.

    The metrics edge lazily imports :class:`MetricsClient` from ``azure-monitor-querymetrics`` (the
    split package that owns the metrics client since ``azure-monitor-query`` 2.0.0 shipped Logs
    clients only). When that optional package is **not importable** at runtime, the guarded import
    raises this descriptive error, which surfaces (via :meth:`AzureMonitorClient.fetch_raw`) as
    ``error='AzureMonitorSdkNotWired'`` — a clear, fail-closed signal — instead of a misleading
    ``ImportError``/``AttributeError``. Everything else (endpoint/namespace config, the query
    itself) still fails closed with its own error class name.
    """


class UntrustedMetricsEndpoint(ValueError):
    """Raised when a configured ``metrics_endpoint`` is not a trusted Azure Monitor host.

    ``azure-monitor-querymetrics``'s ``MetricsClient`` sends a **bearer Managed-Identity token**
    (scope ``https://metrics.monitor.azure.com/.default``) to whatever HTTPS host it is constructed
    with. An attacker-influenced endpoint could therefore harvest a *replayable* Azure token
    (SSRF / token replay). To prevent that, :func:`_validate_metrics_endpoint` validates the
    endpoint **before** any SDK import / client construction; a non-trusted endpoint raises this
    class and **no token is ever minted or sent** — the edge fails closed with the class name only.
    """


# Trusted regional Azure Monitor **metrics** data-plane host suffixes, per cloud. The token scope is
# ``https://metrics.monitor.azure.com/.default`` (and sovereign equivalents), so we only ever hand
# the credential-bearing client a host under one of these suffixes.
_TRUSTED_METRICS_HOST_SUFFIXES: tuple[str, ...] = (
    ".metrics.monitor.azure.com",  # Azure public cloud
    ".metrics.monitor.azure.us",  # Azure US Government
    ".metrics.monitor.azure.cn",  # Azure China (21Vianet)
)


def _validate_metrics_endpoint(endpoint: str) -> str:
    """Validate a metrics endpoint against the trusted Azure Monitor hosts — **pure**, fail-closed.

    Rejects anything that could exfiltrate the Managed-Identity token (SSRF / token replay):
    requires ``https://``, forbids userinfo and explicit ports, forbids any path/query/fragment,
    and requires the host to be a real subdomain under a trusted ``*.metrics.monitor.azure.*``
    suffix. Returns the normalized endpoint on success; raises :class:`UntrustedMetricsEndpoint`
    otherwise (before any token is minted). Never logs the endpoint value.
    """
    parts = urlsplit(endpoint.strip())
    if parts.scheme != "https":
        raise UntrustedMetricsEndpoint("metrics endpoint must use https")
    if parts.username or parts.password:
        raise UntrustedMetricsEndpoint("metrics endpoint must not carry userinfo")
    if parts.query or parts.fragment:
        raise UntrustedMetricsEndpoint("metrics endpoint must not carry a query or fragment")
    if parts.path not in ("", "/"):
        raise UntrustedMetricsEndpoint("metrics endpoint must not carry a path")
    try:
        # ``parts.port`` raises ValueError on a malformed port; both cases are untrusted.
        port = parts.port
    except ValueError as exc:
        raise UntrustedMetricsEndpoint("metrics endpoint has an invalid port") from exc
    if port is not None:
        raise UntrustedMetricsEndpoint("metrics endpoint must not specify a port")
    host = (parts.hostname or "").lower()
    for suffix in _TRUSTED_METRICS_HOST_SUFFIXES:
        # Require at least one real label before the suffix (reject the bare suffix / look-alikes).
        if host.endswith(suffix) and len(host) > len(suffix):
            return f"https://{host}"
    raise UntrustedMetricsEndpoint("metrics endpoint host is not a trusted Azure Monitor host")


class _SdkMetricsBackend:
    """Real metrics backend — lazily wraps ``azure-monitor-querymetrics``'s ``MetricsClient``.

    Read-only, keyless (the injected credential is handed straight to the SDK), and bounded to the
    configured resource ids. The SDK import is **lazy inside** :meth:`query_metrics` so importing
    this module never needs the package and ``mypy src`` stays Azure-free. A missing package fails
    closed via :class:`AzureMonitorSdkNotWired`; missing endpoint/namespace config fails closed too.
    """

    def __init__(
        self,
        config: AzureMonitorConfig,
        *,
        client_factory: Callable[[str, Any], Any] | None = None,
    ) -> None:
        self._config = config
        # Test seam: inject a fake ``(endpoint, credential) -> client`` so timeout/SSRF behaviour is
        # exercised without the real SDK. ``None`` ⇒ lazily import the real ``MetricsClient``.
        self._client_factory = client_factory

    def _build_client(self, endpoint: str, credential: Any) -> Any:
        if self._client_factory is not None:
            return self._client_factory(endpoint, credential)
        try:
            from azure.monitor.querymetrics import MetricsClient  # noqa: PLC0415 - lazy edge import
        except ImportError as exc:  # optional package absent → fail closed, descriptive class name
            raise AzureMonitorSdkNotWired(
                "azure-monitor-querymetrics is not installed; the metrics edge is unavailable"
            ) from exc
        return MetricsClient(endpoint, credential)

    def query_metrics(
        self,
        *,
        resource_ids: Sequence[str],
        metric_names: Sequence[str],
        credential: Any,
        timeout_s: float,
    ) -> list[dict[str, Any]]:
        if not self._config.metrics_endpoint or not self._config.metric_namespace:
            raise ValueError("azure monitor metrics edge needs a regional endpoint + namespace")
        # Validate the endpoint BEFORE minting/handing over any token (SSRF / token-replay guard).
        endpoint = _validate_metrics_endpoint(self._config.metrics_endpoint)
        client = self._build_client(endpoint, credential)
        try:
            results = client.query_resources(
                resource_ids=list(resource_ids),
                metric_namespace=self._config.metric_namespace,
                metric_names=list(metric_names),
                timespan=timedelta(minutes=self._config.metric_lookback_minutes),
                granularity=timedelta(minutes=self._config.metric_granularity_minutes),
                aggregations=list(_AGGREGATIONS),
                timeout=timeout_s,
            )
            # Each MetricsQueryResult maps positionally to the resource id we queried it for.
            return [
                _normalize_sdk_response(resource_id, result)
                for resource_id, result in zip(resource_ids, results, strict=False)
            ]
        finally:
            close = getattr(client, "close", None)
            if callable(close):
                close()


@runtime_checkable
class LogsBackend(Protocol):
    """Narrow logs query seam. The real implementation wraps ``azure-monitor-query``'s
    ``LogsQueryClient``; tests inject a fake that returns synthetic aggregated payloads (or raises
    to exercise fail-closed)."""

    def query_logs(
        self,
        *,
        workspace_id: str,
        resource_ids: Sequence[str],
        metric_names: Sequence[str],
        credential: Any,
        timeout_s: float,
    ) -> list[dict[str, Any]]:
        ...


def _normalize_logs_response(response: Any, *, allowed: Sequence[str]) -> dict[str, Any]:
    """Convert a ``LogsQueryClient`` result into our normalized ``{"logRecords": [...]}`` payload.

    Reads ``response.tables[*].columns`` / ``rows`` defensively and keeps **only** columns in
    ``allowed`` (the aggregated identifier + numeric columns the KQL projected) — any other column
    is dropped here, so no raw log content is normalized in. The pure mapper owns final validation.
    """
    allow = set(allowed)
    records: list[dict[str, Any]] = []
    for table in getattr(response, "tables", None) or []:
        columns = [str(c) for c in (getattr(table, "columns", None) or [])]
        for row in getattr(table, "rows", None) or []:
            record = {
                name: value
                for name, value in zip(columns, row, strict=False)
                if name in allow
            }
            records.append(record)
    return {"logRecords": records}


def _logs_result_to_payload(response: Any, *, success_status: Any) -> dict[str, Any]:
    """Gate a logs query result on SUCCESS, then normalize — **pure**, fail-closed on anything else.

    ``LogsQueryClient`` can return a ``LogsQueryResult`` (status ``SUCCESS`` with ``.tables``) or a
    ``LogsQueryPartialResult`` (status ``PARTIAL`` with ``.partial_data`` and **no** ``.tables``).
    A partial/missing/unexpected status is a **false all-clear** if normalized as empty, so we
    accept **only** ``success_status``; anything else raises ``ValueError`` (fails the edge closed
    with the class name only). On success the aggregated table is normalized via
    :func:`_normalize_logs_response`.
    """
    status = getattr(response, "status", None)
    if status != success_status:
        raise ValueError("azure monitor logs query did not return a successful status")
    return _normalize_logs_response(response, allowed=_LOG_RECORD_FIELDS)


class _SdkLogsBackend:
    """Real logs backend — lazily wraps ``azure-monitor-query``'s ``LogsQueryClient``.

    Read-only, keyless, and PII-safe: it runs **only** the bounded, aggregated KQL from
    :func:`build_logs_kql` (never a raw-row/body projection) against the configured Log Analytics
    workspace, then normalizes the aggregated table into ``{"logRecords": [...]}``. The SDK import
    is lazy inside :meth:`query_logs` so this module stays Azure-free at import time.
    """

    def __init__(
        self,
        config: AzureMonitorConfig,
        *,
        client_factory: Callable[[Any], Any] | None = None,
        status_success: Any | None = None,
    ) -> None:
        self._config = config
        # Test seams: inject a fake ``(credential) -> client`` and the SUCCESS sentinel so the
        # timeout/status-gating behaviour is exercised without the real SDK. ``None`` ⇒ real SDK.
        self._client_factory = client_factory
        self._status_success = status_success

    def _build_client(self, credential: Any) -> tuple[Any, Any]:
        """Return ``(client, success_status)`` from the injected factory or the lazy SDK import."""
        if self._client_factory is not None:
            return self._client_factory(credential), self._status_success
        try:
            from azure.monitor.query import (  # noqa: PLC0415 - lazy edge import
                LogsQueryClient,
                LogsQueryStatus,
            )
        except ImportError as exc:  # azure-monitor-query is a base dep, but stay defensive
            raise AzureMonitorSdkNotWired(
                "azure-monitor-query is not installed; the logs edge is unavailable"
            ) from exc
        return LogsQueryClient(credential), LogsQueryStatus.SUCCESS

    def query_logs(
        self,
        *,
        workspace_id: str,
        resource_ids: Sequence[str],
        metric_names: Sequence[str],
        credential: Any,
        timeout_s: float,
    ) -> list[dict[str, Any]]:
        kql = build_logs_kql(
            resource_ids=resource_ids,
            metric_names=metric_names,
            lookback_hours=self._config.log_lookback_hours,
            bin_minutes=self._config.log_bin_minutes,
        )
        client, success_status = self._build_client(credential)
        try:
            response = client.query_workspace(
                workspace_id,
                kql,
                timespan=timedelta(hours=self._config.log_lookback_hours),
                server_timeout=max(1, int(timeout_s)),
            )
            # Accept ONLY a successful status; PARTIAL/missing/unexpected ⇒ fail closed (MED 3).
            return [_logs_result_to_payload(response, success_status=success_status)]
        finally:
            close = getattr(client, "close", None)
            if callable(close):
                close()


# --------------------------------------------------------------------------------------
# Network edge — the ONLY place that performs I/O.
# --------------------------------------------------------------------------------------
# Transient error *class names* worth a bounded retry. Matched by name (not import) so no vendor
# SDK is pulled in at module import time; azure-core's ``ServiceRequestError``/``ServiceResponse
# Error`` and the builtin connection/timeout errors qualify. A guarded-import failure
# (``AzureMonitorSdkNotWired``), credential-provider errors and malformed payloads do **not**.
_TRANSIENT_ERROR_NAMES: frozenset[str] = frozenset(
    {
        "ServiceRequestError",
        "ServiceResponseError",
        "ServiceRequestTimeoutError",
        "ConnectionError",
        "ConnectionResetError",
        "TimeoutError",
    }
)


def _is_transient_backend(exc: BaseException) -> bool:
    """Retry only transient backend/transport failures, matched by exception class name.

    The match walks the exception's MRO so a *subclass* of an allowlisted transient error is also
    retried — e.g. azure-core's ``ServiceResponseTimeoutError`` (a subclass of ``ServiceResponse
    Error``). Kept name-based so no vendor SDK is imported at module import time.
    """
    return any(klass.__name__ in _TRANSIENT_ERROR_NAMES for klass in type(exc).__mro__)


class AzureMonitorClient:
    """Thin, read-only Azure Monitor client (metrics + logs). Fail-closed; never queries unauth'd.

    Inject a ``credential_provider`` (Managed Identity, keyless) and — in tests — a ``backend``
    (metrics) and/or ``logs_backend`` so everything is exercised without the SDK or network. If no
    credential resolves, :meth:`fetch_raw` fails closed with ``error="NoCredential"`` and performs
    **no** query.

    Which edges run is driven by config/injection: the **metrics** edge runs when a ``backend`` is
    injected or ``config.resource_ids`` is non-empty; the **logs** edge runs when a ``logs_backend``
    is injected or ``config.workspace_id`` is set. Any edge error fails the whole fetch closed.
    """

    def __init__(
        self,
        config: AzureMonitorConfig,
        *,
        credential_provider: CredentialProvider | None = None,
        backend: MetricsBackend | None = None,
        logs_backend: LogsBackend | None = None,
        sleep: Callable[[float], None] = time.sleep,
        rng: random.Random | None = None,
    ) -> None:
        self._config = config
        self._credential_provider = credential_provider
        self._backend = backend
        self._logs_backend = logs_backend
        # Injected so bounded-retry backoff is deterministic and instant in tests; real by default.
        self._sleep = sleep
        self._rng = rng if rng is not None else random.Random()  # noqa: S311 - backoff jitter, not crypto

    def _resolve_credential(self) -> object | None:
        """Resolve a keyless credential from the injected provider, or ``None``.

        May raise if the injected provider raises; :meth:`fetch_raw` guards this and fails closed.
        The credential object is only ever handed to the SDK backend — never logged or returned.
        """
        if self._credential_provider is not None:
            return self._credential_provider()
        return None

    def fetch_raw(self, *, metric_names: Sequence[str] | None = None) -> FetchResult:
        """The single I/O edge. Read-only metrics + logs query; returns payloads or fails closed.

        Fails closed (``available=False``, error *class* name only — no body, token, or message) on
        an unresolvable/raising credential, or any backend/SDK error. Transient backend/transport
        errors are retried (bounded, with jitter) before failing closed. When no credential
        resolves, **no** query is made.
        """
        return fail_closed(lambda: self._fetch(metric_names=metric_names))

    def _fetch(self, *, metric_names: Sequence[str] | None) -> FetchResult:
        """Resolve the credential, then run each enabled edge under bounded retry. Guarded above."""
        credential = self._resolve_credential()
        if credential is None:
            return FetchResult(available=False, error="NoCredential")
        names = list(metric_names) if metric_names else list(self._config.metric_names)
        raw: list[dict[str, Any]] = []
        if self._metrics_enabled():
            raw.extend(self._run_edge(self._metrics_attempt(credential, names)))
        if self._logs_enabled():
            raw.extend(self._run_edge(self._logs_attempt(credential, names)))
        return FetchResult(available=True, raw=raw)

    def _metrics_enabled(self) -> bool:
        """Whether to run the metrics edge.

        With an injected ``backend`` (tests) it always runs. Otherwise the **real** metrics edge
        requires the *complete* metrics config — ``resource_ids`` **and** ``metrics_endpoint``
        **and** ``metric_namespace`` — so a logs-only deployment that sets ``resource_ids`` merely
        to bound its KQL does **not** trip the metrics edge (and fail) before logs can run (MED 4).
        """
        if self._backend is not None:
            return True
        return bool(
            self._config.resource_ids
            and self._config.metrics_endpoint
            and self._config.metric_namespace
        )

    def _logs_enabled(self) -> bool:
        """Logs edge runs when a logs backend is injected (tests) or a workspace id is set."""
        return self._logs_backend is not None or bool(self._config.workspace_id)

    def _metrics_attempt(
        self, credential: object, names: list[str]
    ) -> Callable[[], list[dict[str, Any]]]:
        backend: MetricsBackend = self._backend or cast(
            MetricsBackend, _SdkMetricsBackend(self._config)
        )

        def _attempt() -> list[dict[str, Any]]:
            raw = backend.query_metrics(
                resource_ids=list(self._config.resource_ids),
                metric_names=names,
                credential=credential,
                timeout_s=self._config.timeout_s,
            )
            return _coerce_backend_raw(raw)

        return _attempt

    def _logs_attempt(
        self, credential: object, names: list[str]
    ) -> Callable[[], list[dict[str, Any]]]:
        backend: LogsBackend = self._logs_backend or cast(
            LogsBackend, _SdkLogsBackend(self._config)
        )
        workspace_id = self._config.workspace_id or ""

        def _attempt() -> list[dict[str, Any]]:
            raw = backend.query_logs(
                workspace_id=workspace_id,
                resource_ids=list(self._config.resource_ids),
                metric_names=names,
                credential=credential,
                timeout_s=self._config.timeout_s,
            )
            return _coerce_backend_raw(raw)

        return _attempt

    def _run_edge(self, attempt: Callable[[], list[dict[str, Any]]]) -> list[dict[str, Any]]:
        """Run one edge attempt under the shared bounded retry-with-jitter policy. May raise."""
        return run_with_retries(
            attempt,
            attempts=self._config.retries,
            base_delay_s=self._config.base_delay_s,
            max_delay_s=self._config.max_delay_s,
            sleep=self._sleep,
            rng=self._rng,
            retry_on=_is_transient_backend,
        )


__all__ = [
    "AzureMonitorClient",
    "AzureMonitorConfig",
    "AzureMonitorSdkNotWired",
    "CredentialProvider",
    "LogsBackend",
    "MetricsBackend",
    "UntrustedMetricsEndpoint",
    "build_logs_kql",
    "map_logs_response",
    "map_metrics_response",
    "to_signals",
]
