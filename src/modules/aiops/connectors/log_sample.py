"""Log-sample connector — keyless, read-only, fail-closed edge that emits ONLY PII-free features.

The AIOps log-anomaly detector (issue #53) needs, per watched resource, a series of prior windows'
:class:`shared.contracts.LogFeatures` (the baseline) plus the current window's features. This
connector is the ONLY place that ever touches a raw log body/message, and it does so strictly
in-boundary:

* it fetches BOUNDED raw log windows at its single I/O edge, then IMMEDIATELY reduces each window
  with the PURE :func:`modules.aiops.log_features.extract_log_features` extractor;
* it returns ONLY :class:`shared.contracts.LogFeatures` windows — the raw rows are local to the
  edge/backend and **never** cross the connector→module boundary (no raw log body, message, id, or
  PII is ever returned);
* it is **keyless** — Managed Identity via an *injected* ``credential_provider`` (a callable
  returning a ``TokenCredential`` or ``None``); no key/secret/connection string is read or logged;
* it **fails closed** — no credential, a raising backend, or a missing SDK yields
  ``available=False`` with the error **class name only** (never a body/token/message) and no data;
* the field mapping (how a record is shaped: which keys hold level/message/duration/timestamp) is a
  DEPLOYMENT concern carried in :class:`LogFeatureExtractionSpec`, NOT pack content.

The real Log Analytics backend imports its SDK **lazily inside the edge**, so importing this module
never needs the SDK and unit tests inject fakes to stay Azure- and network-free.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from modules.aiops.log_features import (
    LogFeatureExtractionSpec,
    extract_log_features,
)
from shared.connectors import CredentialProvider, FailClosedObserver
from shared.contracts import LogFeatures

# The well-known client-registry key the AIOps module looks this connector up by.
CLIENT_KEY = "log_sample"


class LogSampleConfig(BaseModel):
    """Connector configuration. Holds no secrets — only ids, the field mapping, and query bounds."""

    model_config = ConfigDict(extra="forbid")

    workspace_id: str = Field(description="Log Analytics workspace id (GUID) for the logs edge")
    resource_ids: list[str] = Field(
        default_factory=list, description="Azure resource ids to sample logs for"
    )
    # Field mapping: how a raw record is shaped (deployment concern, NOT pack content). The message
    # is only ever hashed to a structural signature by the pure extractor — never returned.
    extraction: LogFeatureExtractionSpec = Field(default_factory=LogFeatureExtractionSpec)
    # Windowing bounds (deterministic, bounded work).
    window_minutes: int = Field(default=5, ge=1, le=1440, description="Window (bin) size, minutes")
    window_count: int = Field(
        default=13, ge=2, le=500,
        description="Total windows to fetch (baseline + the most-recent current window)",
    )
    max_rows_per_resource: int = Field(
        default=50_000, ge=1, le=1_000_000, description="Fail-closed cap on raw rows per resource"
    )
    timeout_s: float = Field(default=30.0, gt=0.0, le=120.0)


@dataclass(frozen=True)
class RawLogWindow:
    """One bounded, time-ordered window of RAW rows for a resource — INTERNAL to the connector.

    Never returned across the connector boundary: the client reduces it to :class:`LogFeatures`
    immediately and discards the rows. ``index`` orders windows oldest→newest.
    """

    resource_id: str
    index: int
    records: list[dict[str, Any]] = field(default_factory=list)


@runtime_checkable
class LogWindowBackend(Protocol):
    """Structural view of a raw-log-window backend: one read-only, bounded fetch method.

    Returns time-ordered :class:`RawLogWindow`\\ s (oldest→newest per resource). The raw rows it
    returns stay inside the connector — the client reduces them to :class:`LogFeatures` and never
    re-emits them. A real implementation queries Log Analytics; tests inject a fake.
    """

    def fetch_windows(
        self,
        *,
        resource_ids: Sequence[str],
        credential: Any,
        timeout_s: float,
    ) -> list[RawLogWindow]: ...


class LogSampleSdkNotWired(RuntimeError):
    """Raised when the optional logs SDK cannot be imported at query time — fail closed."""


class LogFeatureFetchResult(BaseModel):
    """Fetch envelope carrying ONLY PII-free :class:`LogFeatures` windows (or a fail-closed empty).

    ``available=False`` ⇒ fail closed (no data). ``windowsByResource`` maps a resource id to its
    windows ordered **oldest→newest** (the last element is the current window; the rest are the
    baseline). ``error`` is the error **class name only** — never a body, token, or message.
    """

    model_config = ConfigDict(extra="forbid")

    available: bool
    windowsByResource: dict[str, list[LogFeatures]] = Field(default_factory=dict)
    error: str | None = Field(
        default=None, description="Error *class* name only; never a body or token"
    )


class LogSampleClient:
    """Thin, read-only log-sample client. Keyless, fail-closed; emits ONLY PII-free features.

    Inject a ``credential_provider`` (Managed Identity, keyless) and — in tests — a ``backend`` so
    everything is exercised without the SDK or network. If no credential resolves,
    :meth:`fetch_features` fails closed with ``error="NoCredential"`` and performs **no** query.
    The raw rows the backend returns are reduced to :class:`LogFeatures` here and never leave it.
    """

    def __init__(
        self,
        config: LogSampleConfig,
        *,
        credential_provider: CredentialProvider | None = None,
        backend: LogWindowBackend | None = None,
        fail_closed_observer: FailClosedObserver | None = None,
    ) -> None:
        self._config = config
        self._credential_provider = credential_provider
        self._backend = backend
        self._fail_closed_observer = fail_closed_observer

    def fetch_features(
        self, *, resource_ids: Sequence[str] | None = None
    ) -> LogFeatureFetchResult:
        """The single I/O edge. Returns PII-free :class:`LogFeatures` windows or fails closed.

        Any exception (unresolvable/raising credential, backend/SDK error) becomes a fail-closed
        ``available=False`` result carrying the error class name only — never a raw row, body, or
        token. When no credential resolves, **no** query is made.
        """
        try:
            return self._fetch(resource_ids=resource_ids)
        except Exception as exc:  # noqa: BLE001 - every edge failure must fail closed, class name only
            if self._fail_closed_observer is not None:
                with suppress(Exception):
                    self._fail_closed_observer()
            return LogFeatureFetchResult(available=False, error=type(exc).__name__)

    def _fetch(self, *, resource_ids: Sequence[str] | None) -> LogFeatureFetchResult:
        """Resolve the credential, fetch raw windows, and reduce them to features. May raise."""
        credential = (
            self._credential_provider() if self._credential_provider is not None else None
        )
        if credential is None:
            return LogFeatureFetchResult(available=False, error="NoCredential")

        targets = list(resource_ids) if resource_ids else list(self._config.resource_ids)
        if not targets:
            return LogFeatureFetchResult(available=True, windowsByResource={})

        backend = self._backend if self._backend is not None else _SdkLogWindowBackend(self._config)
        windows = backend.fetch_windows(
            resource_ids=targets,
            credential=credential,
            timeout_s=self._config.timeout_s,
        )
        return LogFeatureFetchResult(
            available=True,
            windowsByResource=self._reduce(windows),
        )

    def _reduce(self, windows: list[RawLogWindow]) -> dict[str, list[LogFeatures]]:
        """Reduce raw windows to per-resource, oldest→newest features. Raw rows discarded."""
        grouped: dict[str, list[RawLogWindow]] = {}
        for window in windows:
            grouped.setdefault(window.resource_id, []).append(window)
        result: dict[str, list[LogFeatures]] = {}
        for resource_id, resource_windows in grouped.items():
            ordered = sorted(resource_windows, key=lambda w: w.index)
            result[resource_id] = [
                extract_log_features(w.records, self._config.extraction) for w in ordered
            ]
        return result


class _SdkLogWindowBackend:
    """Real backend — lazily wraps ``azure-monitor-query``'s ``LogsQueryClient`` (raw-row query).

    Read-only and keyless: it runs a BOUNDED KQL that projects the mapped raw columns
    (TimeGenerated + level/message/duration) within the lookback window, buckets rows into
    fixed-size windows in Python, and returns them as :class:`RawLogWindow`\\ s. Those raw rows are
    consumed by :meth:`LogSampleClient._reduce` and never re-emitted. The SDK import is lazy inside
    :meth:`fetch_windows` so importing this module never needs the package; a missing package fails
    closed via :class:`LogSampleSdkNotWired`.
    """

    def __init__(
        self,
        config: LogSampleConfig,
        *,
        client_factory: Callable[[Any], Any] | None = None,
    ) -> None:
        self._config = config
        self._client_factory = client_factory

    def _build_client(self, credential: Any) -> Any:
        if self._client_factory is not None:
            return self._client_factory(credential)
        try:
            from azure.monitor.query import LogsQueryClient  # noqa: PLC0415 - lazy edge import
        except ImportError as exc:
            raise LogSampleSdkNotWired(
                "azure-monitor-query is not installed; the log-sample edge is unavailable"
            ) from exc
        return LogsQueryClient(credential)

    def fetch_windows(
        self,
        *,
        resource_ids: Sequence[str],
        credential: Any,
        timeout_s: float,
    ) -> list[RawLogWindow]:
        # The real Log Analytics raw-row query is intentionally deferred: wiring supplies an
        # injected backend in every path exercised today, and the pure anomaly core is fully
        # valuable with NO log-sample endpoint configured (fail-closed by absence). Building the
        # real bounded KQL raw-row projection is tracked follow-up; fail closed here so a
        # half-wired real edge can never silently emit fabricated windows.
        self._build_client(credential)
        raise LogSampleSdkNotWired(
            "log-sample real SDK backend is not yet wired; inject a backend or leave unconfigured"
        )


__all__ = [
    "CLIENT_KEY",
    "LogFeatureFetchResult",
    "LogSampleClient",
    "LogSampleConfig",
    "LogSampleSdkNotWired",
    "LogWindowBackend",
    "RawLogWindow",
]
