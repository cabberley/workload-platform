"""Citrix **NetScaler** connector (NITRO REST) — read-only, keyless, fail-closed-by-default.

NetScaler is a read-only load-balancer signal source (issue #49). Like the sibling Citrix (#48) and
Kuiper (#47) connectors it is written **defensively**: the real NetScaler NITRO base URL, object
model, health vocabulary, and auth scheme are an **external dependency owned by the network team**,
so until a human wires an **approved https endpoint** (and adds its host to ``approved_hosts``) the
connector does **nothing** — it stays unavailable, resolves **no** credential, builds **no**
``Authorization`` header, and makes **no** network call.

It builds ON the shared machinery — it does **not** re-derive it:

* the fail-closed fetch loop, endpoint validation, keyless credential resolution, bounded
  retry-with-jitter, and the streamed size/time-bounded reader all come from
  :class:`shared.connectors.edge.HttpEdgeClient`;
* the PII-safe transform (membership → dependency edges, aggregate health, filtered-log signals)
  is the pure, vendor-neutral layer in :mod:`shared.connectors.lb`.

The only NetScaler-specific code is :func:`parse_nitro` — a **pure** function mapping a synthetic
NITRO response envelope to the common signal records the shared transform validates atomically. No
Azure/vendor SDK is imported at module top; ``httpx`` is imported lazily inside the shared edge.

**Keyless.** The bearer is resolved (keyless order) via an injected Managed-Identity provider → a
Key Vault ``SecretProvider`` → a documented local-dev env-var fallback whose **name** (never a
secret literal) is :data:`DEFAULT_TOKEN_ENV`.

TODO(human): the real NITRO base URL, ``signals_path`` (membership vs stat vs log-summary may be
multiple NITRO endpoints), response envelope, object model, and health vocabulary are EXTERNAL
(issue #49). The synthetic shape parsed here is a conservative placeholder exercised only by
synthetic fixtures; confirm and replace it (with an ADR) once the NITRO contract is published. There
is intentionally NO default ``base_url`` or approved host, so the connector is inert until a human
wires an approved endpoint.
"""
from __future__ import annotations

import random
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from shared.connectors.base import (
    FailClosedObserver,
    FetchResult,
    SecretProvider,
    TokenProvider,
)
from shared.connectors.edge import HttpEdgeClient, HttpEdgeConfig
from shared.connectors.lb import (
    BACKEND_MEMBER_KIND,
    LOG_SIGNAL_KIND,
    LbSignalError,
    parse_signals_atomic,
    signals_to_raw,
)

if TYPE_CHECKING:  # httpx is imported lazily inside the shared edge so importing this module is
    import httpx  # SDK-free.

__all__ = [
    "DEFAULT_TOKEN_ENV",
    "EDGE_ORIGIN",
    "NITRO_LOGSUMMARY_KEY",
    "NITRO_MEMBERSHIP_KEY",
    "SUPPLEMENTAL_SOURCE",
    "NetScalerClient",
    "NetScalerConfig",
    "NetScalerConnector",
    "parse_nitro",
]

# The env var *name* (Key Vault backed) that holds a customer-supplied read token — never a literal.
DEFAULT_TOKEN_ENV = "NETSCALER_READ_TOKEN"  # noqa: S105 - env var name, not a secret

# Provenance markers stamped by the shared transform when this connector contributes a signal.
SUPPLEMENTAL_SOURCE = "netscaler"
EDGE_ORIGIN = "connector:netscaler"

# The two NITRO envelope sections this connector reads. TODO(human): confirm the real NITRO object
# names / endpoints; these are synthetic placeholders.
NITRO_MEMBERSHIP_KEY = "lbvserver_binding"
NITRO_LOGSUMMARY_KEY = "logsummary"

# Map a NITRO service/member state to the common closed health vocabulary. An unrecognized state
# maps to ``unknown`` (fail-safe) rather than being dropped, so a monitoring gap surfaces as
# ``unknown`` instead of silently vanishing. TODO(human): confirm the real NITRO state vocabulary.
_NITRO_STATE_MAP: dict[str, str] = {
    "UP": "up",
    "DOWN": "down",
    "OUT OF SERVICE": "degraded",
    "OUT_OF_SERVICE": "degraded",
    "TRANSITION TO OUT OF SERVICE": "degraded",
    "UNKNOWN": "unknown",
}


class NetScalerConfig(HttpEdgeConfig):
    """NetScaler connector config — inherits the shared bounded/keyless fields, sets NITRO defaults.

    No secrets: ``token_env`` holds only a Key Vault-backed env var *name*. No default host, so the
    connector is inert until an operator wires an approved ``https`` endpoint.
    """

    signals_path: str = "/nitro/v1/config/lbvserver_binding"
    token_env: str = DEFAULT_TOKEN_ENV


def _map_state(value: Any) -> str:
    """Map a raw NITRO state to a common closed health token; unknown/garbage ⇒ ``unknown``."""
    if isinstance(value, str):
        return _NITRO_STATE_MAP.get(value.strip().upper(), "unknown")
    return "unknown"


def parse_nitro(payload: Any) -> list[dict[str, Any]]:
    """Map a synthetic NITRO response envelope → common signal records — PURE, fail closed.

    The membership envelope is REQUIRED (fail closed): the top-level ``lbvserver_binding`` key MUST
    be present and be a list, each binding MUST carry a non-empty ``name`` identifier (validated
    UNCONDITIONALLY, even when its member list is empty, so an unnamed binding never silently
    suppresses topology), and each binding MUST carry a ``members`` list. If the membership envelope
    is ABSENT or wrong-typed, or a binding is unnamed, the fetch **raises**
    :class:`~shared.connectors.lb.LbSignalError` — a malformed/error payload can never be silently
    read as "zero members" and suppress topology (fail-OPEN). Only an explicitly-present but EMPTY
    ``members`` list of a NAMED binding is a legitimate zero-members success. The ``logsummary``
    section stays OPTIONAL (it may legitimately be absent).

    Other structural problems (a non-dict envelope, a NITRO ``errorcode`` other than 0, a non-list
    section, or a non-dict entry) also **raise**. The emitted records are still validated atomically
    by :func:`~shared.connectors.lb.parse_signals_atomic` — this function only *shapes* the vendor
    envelope and maps member state to the common health vocabulary; it never copies a free-form
    field.

    TODO(human): confirm the real NITRO envelope, section keys, and per-object field names; this is
    a conservative synthetic placeholder.
    """
    if not isinstance(payload, dict):
        raise LbSignalError("NITRO payload is not an object")
    errorcode = payload.get("errorcode")
    if errorcode not in (None, 0):
        raise LbSignalError("NITRO response reports a non-zero errorcode")

    records: list[dict[str, Any]] = []

    if NITRO_MEMBERSHIP_KEY not in payload:
        raise LbSignalError("NITRO response is missing the required lbvserver_binding envelope")
    bindings = payload.get(NITRO_MEMBERSHIP_KEY)
    if not isinstance(bindings, list):
        raise LbSignalError("NITRO lbvserver_binding is not a list")
    for binding in bindings:
        if not isinstance(binding, dict):
            raise LbSignalError("NITRO lbvserver_binding entry is not an object")
        lb_id = binding.get("name")
        if not isinstance(lb_id, str) or not lb_id:
            raise LbSignalError("NITRO binding is missing a name identifier")
        members = binding.get("members")
        if not isinstance(members, list):
            raise LbSignalError("NITRO binding members is not a list")
        for member in members:
            if not isinstance(member, dict):
                raise LbSignalError("NITRO member entry is not an object")
            records.append(
                {
                    "kind": BACKEND_MEMBER_KIND,
                    "lbId": lb_id,
                    "memberId": member.get("resourceId"),
                    "health": _map_state(member.get("state")),
                }
            )

    logs = payload.get(NITRO_LOGSUMMARY_KEY)
    if logs is not None:
        if not isinstance(logs, list):
            raise LbSignalError("NITRO logsummary is not a list")
        for entry in logs:
            if not isinstance(entry, dict):
                raise LbSignalError("NITRO logsummary entry is not an object")
            records.append(
                {
                    "kind": LOG_SIGNAL_KIND,
                    "lbId": entry.get("resourceId"),
                    "metric": entry.get("metric"),
                    "value": entry.get("value"),
                }
            )
    return records


@runtime_checkable
class NetScalerConnector(Protocol):
    """Narrow read-only seam a consuming module casts its injected NetScaler client to.

    The concrete :class:`NetScalerClient` is injected at the process boundary; unit tests inject a
    fake returning a synthetic :class:`~shared.connectors.FetchResult`. Keeping the surface this
    small lets a module treat "no connector" and "a connector that failed closed" identically, and
    keeps the module SDK-free.
    """

    def fetch_raw(self) -> FetchResult:
        """Return validated LB signals, or a fail-closed ``available=False`` result."""
        ...


class NetScalerClient:
    """Thin, read-only NetScaler NITRO client. Fail-closed by default; validates the endpoint FIRST.

    Delegates the whole fail-closed fetch loop to :class:`~shared.connectors.edge.HttpEdgeClient`
    (endpoint validation before any credential resolution, keyless bearer resolution, bounded
    retry-with-jitter, streamed size/time-bounded read) and supplies the NITRO-specific pure
    transform (:func:`parse_nitro` → atomic validation → normalized records). Inject ``client`` (an
    ``httpx.Client`` on ``httpx.MockTransport``), ``credential_provider`` and/or ``secret_provider``
    to keep everything testable without touching the network or a vault.
    """

    def __init__(
        self,
        config: NetScalerConfig,
        *,
        client: httpx.Client | None = None,
        credential_provider: TokenProvider | None = None,
        secret_provider: SecretProvider | None = None,
        fail_closed_observer: FailClosedObserver | None = None,
        sleep: Callable[[float], None] = time.sleep,
        rng: random.Random | None = None,
    ) -> None:
        self._config = config

        def _transform(payload: Any) -> list[dict[str, Any]]:
            signals = parse_signals_atomic(
                parse_nitro(payload),
                max_records=config.max_records,
                max_field_len=config.max_field_len,
            )
            return signals_to_raw(signals)

        self._edge = HttpEdgeClient(
            config,
            _transform,
            client=client,
            credential_provider=credential_provider,
            secret_provider=secret_provider,
            fail_closed_observer=fail_closed_observer,
            sleep=sleep,
            rng=rng,
        )

    def fetch_raw(self) -> FetchResult:
        """Return validated NITRO-derived signals, or a fail-closed ``available=False`` result."""
        return self._edge.fetch_raw()
