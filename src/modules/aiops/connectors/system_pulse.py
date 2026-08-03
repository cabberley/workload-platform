"""System Pulse connector — read-only, keyless, fail-closed telemetry client.

Epic *System Pulse* is a **read-only** telemetry source for the AIOps module. This connector:

* isolates **all** network I/O in one edge method — :meth:`SystemPulseClient.fetch_raw`;
* **fails closed** — on any unavailability/error it returns ``available=False`` with **no**
  signals; it never fabricates data and never swallows a failure into a silent success. It also
  **never sends an unauthenticated request**: if no credential resolves it fails closed and makes
  no network call;
* is **keyless-capable** — Managed Identity via an *injected* credential provider, or a
  customer-supplied *read* token sourced from an environment variable that is **Key Vault
  backed**. The token is never hardcoded and never logged;
* exposes a **pure** mapping :func:`map_signal` that keeps only the fields needed for detection
  and **drops** every free-text / body / patient / user / message field (no PII egress).

The pure :class:`Signal` shape here is what AIOps ``detect_metric_breach`` consumes. That detector
lives in ``modules.aiops.module`` (a different issue); we do **not** import it, to avoid an import
cycle — we only define and export a clean signal shape + mapping.
"""
from __future__ import annotations

import math
import os
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field

from shared.contracts import SourceReference

# The environment variable that (Key Vault backed) holds a customer-supplied read token.
# We read the *name* here — never a literal secret.
DEFAULT_TOKEN_ENV = "SYSTEM_PULSE_READ_TOKEN"  # noqa: S105 - env var name, not a secret

# The ONLY raw fields we lift into a Signal. Anything else in the payload is ignored by
# construction — this allowlist is what makes the mapping provably PII-safe.
REQUIRED_RAW_FIELDS: tuple[str, ...] = ("metric", "value", "unit", "timestamp", "resourceId")

# A credential/token provider: returns a bearer token string, or ``None`` if it cannot mint one.
# Managed Identity is supported as an *injected* provider (e.g. a closure over
# DefaultAzureCredential(...).get_token(...).token) so azure-identity stays an optional,
# non-top-level dependency.
# TODO(human): confirm System Pulse's real auth scheme with the System Pulse team — Epic-issued
# read token vs Azure AD bearer. Until confirmed we keep auth pluggable via this provider.
TokenProvider = Callable[[], str | None]

# Defensible epoch-unit ranges (absolute magnitude). Seconds up to ~year 5138 stay below
# 1e11; millisecond timestamps land in [1e11, 1e14); anything larger is treated as microseconds
# and, if out of range for the platform clock, is rejected (never crashes).
_EPOCH_SECONDS_MAX = 1e11
_EPOCH_MILLIS_MAX = 1e14

# HTTP auth scheme for the resolved token. Kept as a bare constant (not a full credential
# literal) so the token is interpolated at runtime and never embedded in source.
_AUTH_SCHEME = "Bearer"


class SignalSource(StrEnum):
    """Provenance tag for signals emitted by this connector."""

    system_pulse = "system-pulse"


class Signal(BaseModel):
    """Compact, PII-safe telemetry record consumed by AIOps detection.

    Only detection-relevant fields are carried. ``extra="forbid"`` guarantees no arbitrary
    passthrough of the raw payload can ever attach to a signal.
    """

    model_config = ConfigDict(extra="forbid")

    metric: str = Field(description="Metric name, e.g. odb_latency_ms")
    value: float
    unit: str = Field(description="Unit of the value, e.g. ms | percent | count")
    timestamp: datetime = Field(description="Observation time, normalized to UTC")
    resourceId: str = Field(description="Azure resource id the metric belongs to")
    source: SignalSource = SignalSource.system_pulse


class FetchResult(BaseModel):
    """Result of the network edge. ``available=False`` ⇒ fail closed (no signals)."""

    model_config = ConfigDict(extra="forbid")

    available: bool
    raw: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = Field(
        default=None, description="Error *class* name only; never a body or token"
    )


class SignalMappingError(ValueError):
    """Raised when a raw payload cannot be mapped — surfaced, never fabricated over."""


class SystemPulseConfig(BaseModel):
    """Connector configuration. Holds no secrets — only a Key Vault-backed env var *name*."""

    model_config = ConfigDict(extra="forbid")

    base_url: str = Field(description="System Pulse base URL, e.g. https://pulse.internal")
    metrics_path: str = "/v1/metrics"
    timeout_s: float = Field(default=10.0, gt=0.0)
    token_env: str = DEFAULT_TOKEN_ENV


# --------------------------------------------------------------------------------------
# Pure mapping — no I/O, fully unit-testable with synthetic payloads.
# --------------------------------------------------------------------------------------
def _epoch_to_utc(value: float) -> datetime:
    """Convert an epoch number (s / ms / µs, by magnitude) to aware UTC — or raise, never crash."""
    if not math.isfinite(value):
        raise SignalMappingError(f"non-finite epoch timestamp: {value!r}")
    magnitude = abs(value)
    if magnitude < _EPOCH_SECONDS_MAX:
        seconds = value
    elif magnitude < _EPOCH_MILLIS_MAX:
        seconds = value / 1000.0
    else:
        seconds = value / 1_000_000.0
    try:
        return datetime.fromtimestamp(seconds, tz=UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise SignalMappingError(f"epoch timestamp out of range: {value!r}") from exc


def _parse_timestamp(value: Any) -> datetime:
    """Normalize an ISO-8601 string, epoch number, or datetime to an aware UTC datetime.

    Any conversion failure raises :class:`SignalMappingError` (which ``to_signals`` drops) — the
    connector never crashes on a malformed timestamp.
    """
    if isinstance(value, bool):  # bool is a subclass of int — reject explicitly.
        raise SignalMappingError("timestamp must not be a bool")
    try:
        if isinstance(value, datetime):
            dt = value
        elif isinstance(value, (int, float)):
            dt = _epoch_to_utc(float(value))
        elif isinstance(value, str):
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            raise SignalMappingError(f"unsupported timestamp type: {type(value).__name__}")
    except SignalMappingError:
        raise
    except (ValueError, TypeError, OverflowError, OSError) as exc:
        raise SignalMappingError(f"unparseable timestamp: {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def map_signal(raw: dict[str, Any]) -> Signal:
    """Map a raw System Pulse payload to a :class:`Signal` — **pure** and **PII-safe**.

    Only :data:`REQUIRED_RAW_FIELDS` are read; any free-text / body / patient / user / message
    field present in ``raw`` is dropped by construction. Missing or malformed required fields
    raise :class:`SignalMappingError` (fail closed) — a signal is never fabricated.
    """
    try:
        metric = raw["metric"]
        value = raw["value"]
        unit = raw["unit"]
        resource_id = raw["resourceId"]
        timestamp = raw["timestamp"]
    except KeyError as exc:
        raise SignalMappingError(f"missing required field: {exc.args[0]}") from exc

    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise SignalMappingError(f"invalid metric value: {value!r}")
    try:
        value_f = float(value)
    except ValueError as exc:
        raise SignalMappingError(f"non-numeric metric value: {value!r}") from exc

    return Signal(
        metric=str(metric),
        value=value_f,
        unit=str(unit),
        timestamp=_parse_timestamp(timestamp),
        resourceId=str(resource_id),
    )


def to_signals(result: FetchResult) -> list[Signal]:
    """Map a fetch result to signals — pure. Unavailable ⇒ ``[]`` (fail closed).

    Records that fail mapping are dropped (surfaced by their absence), never guessed at.
    """
    if not result.available:
        return []
    signals: list[Signal] = []
    for raw in result.raw:
        try:
            signals.append(map_signal(raw))
        except SignalMappingError:
            continue
    return signals


def to_source_reference(signal: Signal) -> SourceReference:
    """Provenance for a signal — cites metric + resource, reusing the shared contract."""
    return SourceReference(kind="metric", id=signal.metric, detail=signal.resourceId)


def _coerce_raw_list(payload: Any) -> list[dict[str, Any]]:
    """Strictly extract a list of record dicts from the response payload.

    Accepts a bare list, or exactly one of a ``{signals|value|data: [...]}`` envelope. Ambiguous
    (multi-key) or unrecognized envelopes, and any non-dict entry, **raise** — so a broken feed
    surfaces as ``available=False`` rather than masquerading as healthy-but-empty. A genuinely
    empty valid list is returned as ``[]`` (available, no signals).
    """
    if isinstance(payload, list):
        items: list[Any] = payload
    elif isinstance(payload, dict):
        envelopes = [k for k in ("signals", "value", "data") if isinstance(payload.get(k), list)]
        if len(envelopes) != 1:
            raise ValueError("ambiguous or unrecognized System Pulse payload shape")
        items = payload[envelopes[0]]
    else:
        raise ValueError("unrecognized System Pulse payload shape")
    if not all(isinstance(item, dict) for item in items):
        raise ValueError("System Pulse payload contains non-dict entries")
    return [item for item in items if isinstance(item, dict)]


# --------------------------------------------------------------------------------------
# Network edge — the ONLY place that performs I/O.
# --------------------------------------------------------------------------------------
class SystemPulseClient:
    """Thin, read-only System Pulse client. Fail-closed; never sends an unauthenticated request.

    Auth resolution order: (a) an injected ``credential_provider`` (e.g. Managed Identity) wins;
    (b) else a Key Vault-backed read token from ``config.token_env``; (c) if neither yields a
    token, :meth:`fetch_raw` fails closed with ``error="NoCredential"`` and performs **no**
    network call. Inject ``client`` (an ``httpx.Client`` on ``httpx.MockTransport``) and/or
    ``credential_provider`` to keep everything testable without touching the network.
    """

    def __init__(
        self,
        config: SystemPulseConfig,
        *,
        client: httpx.Client | None = None,
        credential_provider: TokenProvider | None = None,
    ) -> None:
        self._config = config
        self._client = client
        self._credential_provider = credential_provider

    def _resolve_token(self) -> str | None:
        """Resolve a bearer token: injected provider wins, else Key Vault-backed env, else None.

        May raise if an injected provider raises; the caller guards this and fails closed. The
        token value is only ever used to build the auth header — never logged or returned in a
        :class:`FetchResult`.
        """
        if self._credential_provider is not None:
            token = self._credential_provider()
            if token:
                return token
        env_token = os.environ.get(self._config.token_env)
        if env_token:
            return env_token
        return None

    def _endpoint(self) -> str:
        return f"{self._config.base_url.rstrip('/')}/{self._config.metrics_path.lstrip('/')}"

    def fetch_raw(self, *, metric_names: Sequence[str] | None = None) -> FetchResult:
        """The single network edge. Read-only GET; returns raw payloads or fails closed.

        Fails closed (``available=False``, error *class* name only — no body, no token) on: an
        unresolvable/raising credential, any transport/decoding error, or a malformed payload.
        When no credential resolves, **no** HTTP request is made.
        """
        client = self._client
        owns_client = client is None
        try:
            token = self._resolve_token()
            if not token:
                return FetchResult(available=False, error="NoCredential")
            if client is None:
                # TLS verification on, bounded timeout — never an insecure request.
                client = httpx.Client(timeout=self._config.timeout_s, verify=True)
            params = {"metric": list(metric_names)} if metric_names else None
            auth_value = f"{_AUTH_SCHEME} {token}"
            response = client.get(
                self._endpoint(),
                headers={"Authorization": auth_value},
                params=params,
            )
            response.raise_for_status()
            raw = _coerce_raw_list(response.json())
            return FetchResult(available=True, raw=raw)
        except Exception as exc:  # noqa: BLE001 - every failure (incl. provider) must fail closed
            return FetchResult(available=False, error=type(exc).__name__)
        finally:
            if owns_client and client is not None:
                client.close()
