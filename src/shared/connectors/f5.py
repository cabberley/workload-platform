"""**F5 BIG-IP** connector (iControl REST) — read-only, keyless, fail-closed-by-default.

F5 BIG-IP is a read-only load-balancer signal source (issue #49). Like its NetScaler sibling it is
written **defensively**: the real iControl REST base URL, object model, member-state vocabulary, and
auth scheme are an **external dependency owned by the network team**, so until a human wires an
**approved https endpoint** (and adds its host to ``approved_hosts``) the connector does **nothing**
— it stays unavailable, resolves **no** credential, and makes **no** network call.

It builds ON the shared machinery — it does **not** re-derive it:

* the fail-closed fetch loop, endpoint validation, keyless credential resolution, bounded
  retry-with-jitter, and the streamed size/time-bounded reader all come from
  :class:`shared.connectors.edge.HttpEdgeClient`;
* the PII-safe transform (membership → dependency edges, aggregate health, filtered-log signals)
  is the pure, vendor-neutral layer in :mod:`shared.connectors.lb`.

The only F5-specific code is :func:`parse_icontrol` — a **pure** function mapping a synthetic
iControl ``{"items": [...]}`` pool response to the common signal records the shared transform
validates atomically. No Azure/vendor SDK is imported at module top; ``httpx`` is imported lazily
inside the shared edge.

**Keyless.** The bearer is resolved (keyless order) via an injected Managed-Identity provider → a
Key Vault ``SecretProvider`` → a documented local-dev env-var fallback whose **name** (never a
secret literal) is :data:`DEFAULT_TOKEN_ENV`.

TODO(human): the real iControl base URL, ``signals_path`` (pools vs virtuals vs stats may be several
endpoints), response envelope, object model, and member-state/session vocabulary are EXTERNAL (issue
#49). The synthetic shape parsed here is a conservative placeholder exercised only by synthetic
fixtures; confirm and replace it (with an ADR) once the iControl contract is published. There is
intentionally NO default ``base_url`` or approved host, so the connector is inert until a human
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
    "ICONTROL_ITEMS_KEY",
    "ICONTROL_LOGSUMMARY_KEY",
    "SUPPLEMENTAL_SOURCE",
    "F5Client",
    "F5Config",
    "F5Connector",
    "parse_icontrol",
]

# The env var *name* (Key Vault backed) that holds a customer-supplied read token — never a literal.
DEFAULT_TOKEN_ENV = "F5_READ_TOKEN"  # noqa: S105 - env var name, not a secret

# Provenance markers stamped by the shared transform when this connector contributes a signal.
SUPPLEMENTAL_SOURCE = "f5"
EDGE_ORIGIN = "connector:f5"

# The iControl envelope sections this connector reads. TODO(human): confirm the real iControl object
# names / endpoints; these are synthetic placeholders.
ICONTROL_ITEMS_KEY = "items"
ICONTROL_LOGSUMMARY_KEY = "logSummary"

# Map an iControl member ``state`` to the common closed health vocabulary. An unrecognized state
# maps to ``unknown`` (fail-safe). TODO(human): confirm the real iControl state vocabulary.
_F5_STATE_MAP: dict[str, str] = {
    "up": "up",
    "down": "down",
    "unchecked": "unknown",
    "enabled": "up",
    "disabled": "degraded",
}

# iControl ``session`` values that force a member to ``degraded`` regardless of monitor ``state`` —
# an administratively disabled member is reachable-but-not-serving. TODO(human): confirm.
_F5_DEGRADED_SESSIONS: frozenset[str] = frozenset(
    {"user-disabled", "monitor-disabled"}
)


class F5Config(HttpEdgeConfig):
    """F5 connector config — inherits the shared bounded/keyless fields, sets iControl defaults.

    No secrets: ``token_env`` holds only a Key Vault-backed env var *name*. No default host, so the
    connector is inert until an operator wires an approved ``https`` endpoint.
    """

    signals_path: str = "/mgmt/tm/ltm/pool"
    token_env: str = DEFAULT_TOKEN_ENV


def _map_member_health(member: dict[str, Any]) -> str:
    """Map an iControl member's ``session``/``state`` to a common closed health token."""
    session = member.get("session")
    if isinstance(session, str) and session.strip().lower() in _F5_DEGRADED_SESSIONS:
        return "degraded"
    state = member.get("state")
    if isinstance(state, str):
        return _F5_STATE_MAP.get(state.strip().lower(), "unknown")
    return "unknown"


def parse_icontrol(payload: Any) -> list[dict[str, Any]]:
    """Map a synthetic iControl REST pool response → common signal records — PURE, fail closed.

    The membership envelope is REQUIRED (fail closed): the top-level ``items`` key MUST be present
    and be a list, each pool MUST carry a non-empty ``fullPath`` identifier (validated
    UNCONDITIONALLY, even when its member list is empty, so an unnamed pool never silently
    suppresses topology), and each pool MUST carry a ``membersReference`` object whose ``items`` is
    a list. If the membership envelope is ABSENT or wrong-typed, or a pool is unnamed, the fetch
    **raises** :class:`~shared.connectors.lb.LbSignalError` — a malformed/error payload can never be
    silently read as "zero members" and suppress topology (fail-OPEN). Only an explicitly-present
    but EMPTY ``items`` list of a NAMED pool is a legitimate zero-members success. The
    ``logSummary`` section stays OPTIONAL (it may legitimately be absent).

    Other structural problems (a non-dict envelope, a non-list section, or a non-dict entry) also
    **raise**. The emitted records are still validated atomically by
    :func:`~shared.connectors.lb.parse_signals_atomic` — this function only *shapes* the vendor
    envelope and maps member state/session to the common health vocabulary; it never copies a
    free-form field.

    TODO(human): confirm the real iControl envelope, ``membersReference`` shape, and per-object
    field names; this is a conservative synthetic placeholder.
    """
    if not isinstance(payload, dict):
        raise LbSignalError("iControl payload is not an object")

    records: list[dict[str, Any]] = []

    if ICONTROL_ITEMS_KEY not in payload:
        raise LbSignalError("iControl response is missing the required items membership envelope")
    pools = payload.get(ICONTROL_ITEMS_KEY)
    if not isinstance(pools, list):
        raise LbSignalError("iControl items is not a list")
    for pool in pools:
        if not isinstance(pool, dict):
            raise LbSignalError("iControl pool entry is not an object")
        lb_id = pool.get("fullPath")
        if not isinstance(lb_id, str) or not lb_id:
            raise LbSignalError("iControl pool is missing a fullPath identifier")
        members_ref = pool.get("membersReference")
        if not isinstance(members_ref, dict):
            raise LbSignalError("iControl membersReference is not an object")
        members = members_ref.get("items")
        if not isinstance(members, list):
            raise LbSignalError("iControl membersReference items is not a list")
        for member in members:
            if not isinstance(member, dict):
                raise LbSignalError("iControl member entry is not an object")
            records.append(
                {
                    "kind": BACKEND_MEMBER_KIND,
                    "lbId": lb_id,
                    "memberId": member.get("fullPath"),
                    "health": _map_member_health(member),
                }
            )

    logs = payload.get(ICONTROL_LOGSUMMARY_KEY)
    if logs is not None:
        if not isinstance(logs, list):
            raise LbSignalError("iControl logSummary is not a list")
        for entry in logs:
            if not isinstance(entry, dict):
                raise LbSignalError("iControl logSummary entry is not an object")
            records.append(
                {
                    "kind": LOG_SIGNAL_KIND,
                    "lbId": entry.get("fullPath"),
                    "metric": entry.get("metric"),
                    "value": entry.get("value"),
                }
            )
    return records


@runtime_checkable
class F5Connector(Protocol):
    """Narrow read-only seam a consuming module casts its injected F5 client to.

    The concrete :class:`F5Client` is injected at the process boundary; unit tests inject a fake
    returning a synthetic :class:`~shared.connectors.FetchResult`. Keeping the surface this small
    lets a module treat "no connector" and "a connector that failed closed" identically, and keeps
    the module SDK-free.
    """

    def fetch_raw(self) -> FetchResult:
        """Return validated LB signals, or a fail-closed ``available=False`` result."""
        ...


class F5Client:
    """Thin, read-only F5 iControl REST client. Fail-closed by default; validates endpoint FIRST.

    Delegates the whole fail-closed fetch loop to :class:`~shared.connectors.edge.HttpEdgeClient`
    and supplies the iControl-specific pure transform (:func:`parse_icontrol` → atomic validation →
    normalized records). Inject ``client`` (an ``httpx.Client`` on ``httpx.MockTransport``),
    ``credential_provider`` and/or ``secret_provider`` to keep everything testable without touching
    the network or a vault.
    """

    def __init__(
        self,
        config: F5Config,
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
                parse_icontrol(payload),
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
        """Return validated iControl-derived signals, or a fail-closed unavailable result."""
        return self._edge.fetch_raw()
