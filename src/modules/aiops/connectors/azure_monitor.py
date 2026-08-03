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

The real SDK metrics query is **not** wired: the installed ``azure-monitor-query`` (2.0.0) ships
Logs clients only — the metrics client moved to the separate ``azure-monitor-querymetrics`` package
which is not an install requirement. The real backend therefore fails closed with a descriptive
``AzureMonitorSdkNotWired`` error (never a misleading ``AttributeError``); it is marked
``TODO(human)`` but the client is structurally complete, guarded, fail-closed, and unit-testable via
an injected fake backend.

.. note::
   Emitted signals carry ``source = SignalSource.system_pulse`` because the shared ``SignalSource``
   enum (owned by ``system_pulse``) has no ``azure_monitor`` member and must not be forked here.
   Source provenance is tracked by the module via the injected client key (``"azure_monitor"``).
   TODO(human): add an ``azure_monitor`` ``SignalSource`` member via the Architect (a shared
   contract change) so signals self-describe their origin.
"""
from __future__ import annotations

import random
import time
from collections.abc import Callable, Sequence
from typing import Any, Protocol, cast, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from modules.aiops.connectors.system_pulse import (
    Signal,
    SignalMappingError,
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
    # Bounded retry-with-jitter for transient backend/transport errors (issue #45). Defaults are
    # conservative and never change fail-closed behaviour: after ``retries`` attempts the edge
    # still fails closed. Only transient errors are retried (see ``_is_transient_backend``); the
    # not-wired stub, credential errors and malformed payloads fail closed at once.
    retries: int = Field(default=3, ge=1, description="Max query attempts (>=1)")
    base_delay_s: float = Field(default=0.2, gt=0.0, description="Base backoff delay in seconds")
    max_delay_s: float = Field(default=2.0, gt=0.0, description="Backoff cap in seconds")


# --------------------------------------------------------------------------------------
# Pure mapping — no I/O, fully unit-testable with synthetic Azure Monitor payloads.
# --------------------------------------------------------------------------------------
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
    normalizes the timestamp to UTC, and drops all non-allowlisted fields), so a malformed point is
    dropped — never fabricated over — and this function never raises on bad structure.
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
                    signals.append(map_signal(raw))
                except SignalMappingError:
                    continue
    return signals


def to_signals(result: FetchResult) -> list[Signal]:
    """Flatten a fetch result into signals — pure. Unavailable ⇒ ``[]`` (fail closed).

    ``result.raw`` is a list of per-resource Azure Monitor payloads; each is flattened and the
    results are concatenated. Records that fail mapping are dropped, never guessed at.
    """
    if not result.available:
        return []
    signals: list[Signal] = []
    for payload in result.raw:
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
    """Narrow query seam. The real implementation wraps ``azure-monitor-query``; tests inject a
    fake that returns synthetic normalized payloads (or raises to exercise fail-closed)."""

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
    """Raised by the real backend until a metrics query is wired to the installed SDK.

    Surfaces (via :meth:`AzureMonitorClient.fetch_raw`) as ``error='AzureMonitorSdkNotWired'`` —
    a descriptive, fail-closed signal — instead of a misleading ``AttributeError`` against a client
    class that does not exist in the installed ``azure-monitor-query`` release.
    """


def query_metrics_via_sdk(
    *,
    resource_ids: Sequence[str],
    metric_names: Sequence[str],
    credential: Any,
    timeout_s: float,
    normalize: Any = None,
) -> list[dict[str, Any]]:
    """Wire this to the current Azure Monitor metrics SDK (a ``TODO(human)`` stub for now).

    The installed ``azure-monitor-query`` (2.0.0) ships **Logs** clients only
    (``LogsQueryClient`` / ``MonitorQueryLogsClient``); the metrics client + query API were moved
    out into the separate ``azure-monitor-querymetrics`` package, which is **not** an install
    requirement here. Rather than importing a ``MetricsQueryClient`` that does not exist — which
    would raise a misleading ``AttributeError`` and hide the real cause — this backend fails closed
    with a descriptive error.

    TODO(human): once the AIOps/SRE team confirm the metrics package + client and its keyless query
    method (timespan window, granularity, aggregations), perform a bounded, read-only query per
    resource id inside a lazy, guarded import and hand each SDK response to
    :func:`_normalize_sdk_response` (already structured for the metrics→timeseries→data shape the
    pure mapper consumes). Never widen scope beyond the configured resource ids; keep it keyless.
    """
    del resource_ids, metric_names, credential, timeout_s, normalize
    raise AzureMonitorSdkNotWired(
        "Azure Monitor metrics backend is not wired: the installed azure-monitor-query ships "
        "Logs clients only (metrics moved to azure-monitor-querymetrics, not an install "
        "requirement). Inject a MetricsBackend to run metrics queries."
    )


class _SdkMetricsBackend:
    """Real backend seam. Currently a fail-closed stub — see :func:`query_metrics_via_sdk`."""

    def query_metrics(
        self,
        *,
        resource_ids: Sequence[str],
        metric_names: Sequence[str],
        credential: Any,
        timeout_s: float,
    ) -> list[dict[str, Any]]:
        return query_metrics_via_sdk(
            resource_ids=resource_ids,
            metric_names=metric_names,
            credential=credential,
            timeout_s=timeout_s,
            normalize=_normalize_sdk_response,
        )


# --------------------------------------------------------------------------------------
# Network edge — the ONLY place that performs I/O.
# --------------------------------------------------------------------------------------
# Transient error *class names* worth a bounded retry. Matched by name (not import) so no vendor
# SDK is pulled in at module import time; azure-core's ``ServiceRequestError``/``ServiceResponse
# Error`` and the builtin connection/timeout errors qualify. The not-wired stub
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
    """Thin, read-only Azure Monitor metrics client. Fail-closed; never queries unauthenticated.

    Inject a ``credential_provider`` (Managed Identity, keyless) and — in tests — a ``backend`` so
    everything is exercised without the SDK or network. If no credential resolves, :meth:`fetch_raw`
    fails closed with ``error="NoCredential"`` and performs **no** query.
    """

    def __init__(
        self,
        config: AzureMonitorConfig,
        *,
        credential_provider: CredentialProvider | None = None,
        backend: MetricsBackend | None = None,
        sleep: Callable[[float], None] = time.sleep,
        rng: random.Random | None = None,
    ) -> None:
        self._config = config
        self._credential_provider = credential_provider
        self._backend = backend
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
        """The single I/O edge. Read-only metrics query; returns raw payloads or fails closed.

        Fails closed (``available=False``, error *class* name only — no body, token, or message) on
        an unresolvable/raising credential, or any backend/SDK error. Transient backend/transport
        errors are retried (bounded, with jitter) before failing closed. When no credential
        resolves, **no** query is made.
        """
        return fail_closed(lambda: self._fetch(metric_names=metric_names))

    def _fetch(self, *, metric_names: Sequence[str] | None) -> FetchResult:
        """Resolve the credential, then run the bounded, retried query. May raise; guarded above."""
        credential = self._resolve_credential()
        if credential is None:
            return FetchResult(available=False, error="NoCredential")
        backend: MetricsBackend = self._backend or cast(MetricsBackend, _SdkMetricsBackend())
        names = list(metric_names) if metric_names else list(self._config.metric_names)

        def _attempt() -> list[dict[str, Any]]:
            raw = backend.query_metrics(
                resource_ids=list(self._config.resource_ids),
                metric_names=names,
                credential=credential,
                timeout_s=self._config.timeout_s,
            )
            return _coerce_backend_raw(raw)

        raw = run_with_retries(
            _attempt,
            attempts=self._config.retries,
            base_delay_s=self._config.base_delay_s,
            max_delay_s=self._config.max_delay_s,
            sleep=self._sleep,
            rng=self._rng,
            retry_on=_is_transient_backend,
        )
        return FetchResult(available=True, raw=raw)


__all__ = [
    "AzureMonitorClient",
    "AzureMonitorConfig",
    "AzureMonitorSdkNotWired",
    "CredentialProvider",
    "MetricsBackend",
    "map_metrics_response",
    "query_metrics_via_sdk",
    "to_signals",
]
