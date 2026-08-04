"""Keyless, fail-closed **write** edge for platform telemetry export (issue #86).

This is the ONE place that performs I/O for the export path. It publishes the PII-free rows shaped
by :mod:`modules.telemetry_export.shaping` into the customer's OWN in-boundary Log Analytics
workspace via the Azure Monitor **Logs Ingestion API** — a Data Collection Endpoint (DCE) + a Data
Collection Rule (DCR) immutable id + per-table stream names — authenticated with Managed Identity
(``DefaultAzureCredential``). This is an in-boundary export to the customer's own workspace, not an
external boundary crossing; even so, only the aggregate/opaque schema fields ever leave the shaping
layer.

It deliberately mirrors the read-connector edge pattern (``modules.aiops.connectors.azure_monitor``
+ ``shared.connectors.base``) — lazy/guarded SDK import, injected keyless credential, bounded
retry-with-jitter, class-name-only errors — but is built as its OWN thin **write** client because
this is an *export* edge, not a read connector on the ``FetchResult`` base.

Guardrails:

* **Keyless.** The credential is an *injected* :data:`~shared.connectors.CredentialProvider`
  (Managed Identity). No key, SAS token, or connection string is ever read, embedded, or logged.
* **Opt-in / inert when unconfigured.** With no DCE endpoint or DCR immutable id configured, the
  client is a **no-op**: :meth:`LogsIngestionClient.export` returns an inert result and makes NO
  call and surfaces nothing (fail-closed). The exporter is thus opt-in — it does nothing until the
  keyless DCE/DCR config is present.
* **Fail closed, isolated failures.** A missing SDK, unresolved credential, or any backend error is
  swallowed per-stream and recorded as the error **class name only** (never a body, token, or row
  content). A failed emit NEVER raises to the caller, so a telemetry failure can never break the
  platform. An optional keyless observer lets the event be *counted* without importing any registry.
"""
from __future__ import annotations

import random
import time
from collections.abc import Callable, Sequence
from typing import Any, Protocol, cast, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from modules.telemetry_export.shaping import (
    WpConnectorFetchRow,
    WpFindingRow,
    WpNodeStateRow,
    WpSpofRow,
)
from shared.connectors import (
    CredentialProvider,
    FailClosedObserver,
    run_with_retries,
)

# Default DCR stream names, one per custom table. The Logs Ingestion convention is
# ``Custom-<TableName>``; the DCR's ``streamDeclarations`` (see infra/bicep/modules/
# telemetry-export.bicep) MUST declare exactly these, mapping each to its ``*_CL`` table.
_DEFAULT_STREAM_NODE_STATE = "Custom-WpNodeState_CL"
_DEFAULT_STREAM_SPOF = "Custom-WpSpof_CL"
_DEFAULT_STREAM_FINDING = "Custom-WpFinding_CL"
_DEFAULT_STREAM_CONNECTOR_FETCH = "Custom-WpConnectorFetch_CL"


class LogsIngestionConfig(BaseModel):
    """Configuration for the Logs Ingestion write edge. Holds NO secrets — only ids + stream names.

    ``endpoint`` (the DCE logs-ingestion URI) and ``rule_id`` (the DCR *immutable* id, e.g.
    ``dcr-xxxxxxxx``) are BOTH required to be non-empty for the client to be considered configured;
    absent either, the client is inert (a no-op export). Both are non-secret Azure resource
    identifiers supplied at deploy time (Bicep outputs), never keys.
    """

    model_config = ConfigDict(extra="forbid")

    endpoint: str | None = Field(
        default=None, description="Data Collection Endpoint logs-ingestion URI (no secret)"
    )
    rule_id: str | None = Field(
        default=None, description="Data Collection Rule immutable id, e.g. dcr-xxxx (no secret)"
    )
    stream_node_state: str = Field(default=_DEFAULT_STREAM_NODE_STATE)
    stream_spof: str = Field(default=_DEFAULT_STREAM_SPOF)
    stream_finding: str = Field(default=_DEFAULT_STREAM_FINDING)
    stream_connector_fetch: str = Field(default=_DEFAULT_STREAM_CONNECTOR_FETCH)
    credential_scope: str = Field(default="https://monitor.azure.com/.default")
    timeout_s: float = Field(default=30.0, gt=0.0)
    retries: int = Field(default=3, ge=1, description="Max upload attempts per stream (>=1)")
    base_delay_s: float = Field(default=0.2, gt=0.0, description="Base backoff delay in seconds")
    max_delay_s: float = Field(default=2.0, gt=0.0, description="Backoff cap in seconds")


class TelemetryBatch(BaseModel):
    """The PII-free rows to publish in one export pass, grouped by destination table."""

    model_config = ConfigDict(extra="forbid")

    node_states: list[WpNodeStateRow] = Field(default_factory=list)
    spofs: list[WpSpofRow] = Field(default_factory=list)
    findings: list[WpFindingRow] = Field(default_factory=list)
    connector_fetches: list[WpConnectorFetchRow] = Field(default_factory=list)

    def total_rows(self) -> int:
        return (
            len(self.node_states)
            + len(self.spofs)
            + len(self.findings)
            + len(self.connector_fetches)
        )


class ExportResult(BaseModel):
    """Outcome of an export pass. PII-free: only counts + error **class names** (never row content).

    ``configured`` is False when the client was inert (no DCE/DCR) — the export was a deliberate
    no-op, not a failure. ``ok`` is True when the pass raised no errors (an inert pass is ``ok``).
    """

    model_config = ConfigDict(extra="forbid")

    configured: bool
    emitted_by_stream: dict[str, int] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list, description="Error class names only")

    @property
    def emitted(self) -> int:
        return sum(self.emitted_by_stream.values())

    @property
    def ok(self) -> bool:
        return not self.errors


@runtime_checkable
class IngestionBackend(Protocol):
    """The single network edge: upload already-shaped records to one DCR stream. May raise."""

    def upload(
        self,
        *,
        rule_id: str,
        stream_name: str,
        records: list[dict[str, object]],
        credential: object,
        endpoint: str,
        timeout_s: float,
    ) -> None: ...


class IngestionSdkNotWired(RuntimeError):
    """Raised when the ``azure-monitor-ingestion`` SDK is not importable at runtime.

    A descriptive class name (never a bare ``ImportError`` from deep in the SDK) so the fail-closed
    result says exactly why the edge did nothing.
    """


class _SdkIngestionBackend:
    """Real backend — lazily imports ``azure-monitor-ingestion`` INSIDE :meth:`upload`.

    Keeping the import lazy means importing this module (and hence the worker/registry) never needs
    the SDK, so unit tests and ``mypy`` stay Azure-free. A missing package fails closed with the
    descriptive :class:`IngestionSdkNotWired` name.
    """

    def upload(
        self,
        *,
        rule_id: str,
        stream_name: str,
        records: list[dict[str, object]],
        credential: object,
        endpoint: str,
        timeout_s: float,
    ) -> None:
        try:
            from azure.monitor.ingestion import LogsIngestionClient as _SdkClient
        except ImportError as exc:  # fail closed with a descriptive name, not a raw ImportError
            raise IngestionSdkNotWired("azure-monitor-ingestion is not installed") from exc
        client = _SdkClient(endpoint=endpoint, credential=cast(Any, credential))
        # ``records`` is List[Dict[str, object]]; the SDK's ``upload`` declares
        # ``List[MutableMapping[str, Any]]``. ``list`` is invariant, so cast at this thin SDK
        # boundary (as with ``credential`` above) — the rows are already the PII-free shaped dicts.
        client.upload(rule_id=rule_id, stream_name=stream_name, logs=cast(Any, records))


def _is_transient(exc: BaseException) -> bool:
    """Retry only transient transport/backends; never retry a missing-SDK or config error.

    Conservative by design: an :class:`IngestionSdkNotWired` (permanent) is NOT retried, so a
    misconfigured deployment fails closed immediately instead of spinning through the backoff.
    """
    return not isinstance(exc, IngestionSdkNotWired)


class LogsIngestionClient:
    """Thin, keyless, fail-closed write client for the Azure Monitor Logs Ingestion API.

    Inject a ``credential_provider`` (Managed Identity, keyless) and — in tests — a ``backend`` so
    the whole path is exercised with no SDK or network. When unconfigured (no DCE endpoint / DCR id)
    the client is INERT: :meth:`export` returns ``configured=False`` and makes no call.
    """

    def __init__(
        self,
        config: LogsIngestionConfig,
        *,
        credential_provider: CredentialProvider | None = None,
        backend: IngestionBackend | None = None,
        fail_closed_observer: FailClosedObserver | None = None,
        sleep: Callable[[float], None] = time.sleep,
        rng: random.Random | None = None,
    ) -> None:
        self._config = config
        self._credential_provider = credential_provider
        self._backend = backend
        self._fail_closed_observer = fail_closed_observer
        self._sleep = sleep
        # Jitter only — never used for anything cryptographic.
        self._rng = rng if rng is not None else random.Random()  # noqa: S311 - backoff jitter

    @property
    def configured(self) -> bool:
        """True only when BOTH the DCE endpoint and the DCR immutable id are present (opt-in)."""
        return bool(self._config.endpoint) and bool(self._config.rule_id)

    def _resolve_credential(self) -> object | None:
        if self._credential_provider is not None:
            return self._credential_provider()
        return None

    def export(self, batch: TelemetryBatch) -> ExportResult:
        """Publish ``batch`` to Log Analytics. Inert if unconfigured; never raises (fail closed).

        Every failure mode returns an :class:`ExportResult` rather than raising: unconfigured →
        inert no-op; no credential → a single ``NoCredential`` error and no call; a per-stream
        backend error → that stream's error **class name** recorded while other streams still
        publish. A telemetry failure can therefore never break the calling module.
        """
        if not self.configured:
            return ExportResult(configured=False)

        credential = self._safe_resolve_credential()
        if credential is None:
            self._observe_fail_closed()
            return ExportResult(configured=True, errors=["NoCredential"])

        streams: list[tuple[str, list[dict[str, object]]]] = [
            (self._config.stream_node_state, [r.to_la_columns() for r in batch.node_states]),
            (self._config.stream_spof, [r.to_la_columns() for r in batch.spofs]),
            (self._config.stream_finding, [r.to_la_columns() for r in batch.findings]),
            (
                self._config.stream_connector_fetch,
                [r.to_la_columns() for r in batch.connector_fetches],
            ),
        ]

        emitted: dict[str, int] = {}
        errors: list[str] = []
        rule_id = cast(str, self._config.rule_id)
        endpoint = cast(str, self._config.endpoint)
        backend = self._backend or cast(IngestionBackend, _SdkIngestionBackend())

        for stream_name, records in streams:
            if not records:
                continue
            try:
                self._upload_with_retries(backend, rule_id, stream_name, records, credential,
                                          endpoint)
                emitted[stream_name] = len(records)
            except Exception as exc:  # noqa: BLE001 - isolate + fail closed, class name only
                self._observe_fail_closed()
                errors.append(type(exc).__name__)

        return ExportResult(configured=True, emitted_by_stream=emitted, errors=errors)

    def _safe_resolve_credential(self) -> object | None:
        """Resolve the injected credential; a raising provider becomes ``None`` (fail closed)."""
        try:
            return self._resolve_credential()
        except Exception:  # noqa: BLE001 - a broken provider must not crash export
            return None

    def _upload_with_retries(
        self,
        backend: IngestionBackend,
        rule_id: str,
        stream_name: str,
        records: list[dict[str, object]],
        credential: object,
        endpoint: str,
    ) -> None:
        run_with_retries(
            lambda: backend.upload(
                rule_id=rule_id,
                stream_name=stream_name,
                records=records,
                credential=credential,
                endpoint=endpoint,
                timeout_s=self._config.timeout_s,
            ),
            attempts=self._config.retries,
            base_delay_s=self._config.base_delay_s,
            max_delay_s=self._config.max_delay_s,
            sleep=self._sleep,
            rng=self._rng,
            retry_on=_is_transient,
        )

    def _observe_fail_closed(self) -> None:
        """Invoke the optional keyless observer, guarded so observing never breaks fail-closed."""
        if self._fail_closed_observer is None:
            return
        try:
            self._fail_closed_observer()
        except Exception:  # noqa: BLE001 - observing must never turn fail-closed into a crash
            return


def build_batch(
    *,
    node_states: Sequence[WpNodeStateRow] = (),
    spofs: Sequence[WpSpofRow] = (),
    findings: Sequence[WpFindingRow] = (),
    connector_fetches: Sequence[WpConnectorFetchRow] = (),
) -> TelemetryBatch:
    """Small helper to assemble a :class:`TelemetryBatch` from shaped row sequences."""
    return TelemetryBatch(
        node_states=list(node_states),
        spofs=list(spofs),
        findings=list(findings),
        connector_fetches=list(connector_fetches),
    )


__all__ = [
    "ExportResult",
    "IngestionBackend",
    "IngestionSdkNotWired",
    "LogsIngestionClient",
    "LogsIngestionConfig",
    "TelemetryBatch",
    "build_batch",
]
