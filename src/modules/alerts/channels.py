"""Notification delivery — the thin I/O edge for the Alerts module.

Pure routing (`weight_by_blast_radius`, `route` in ``module.py``) decides *what* to send and
*where*; this file is the only place that actually *delivers*. Delivery sits behind a narrow
:class:`NotificationChannel` Protocol so the module logic stays Azure/network-free and unit
testable — tests inject a fake channel via ``ctx.clients={"notifier": fake}`` and never touch the
network.

Guardrails honoured here:
  * **Keyless.** The webhook URL is *never* embedded in code, config literals, or tests. It is a
    plain config value or a Key Vault reference resolved **by identity** at the process edge, so no
    secret/URL-with-token ever lands in the repo.
  * **In-boundary / no PHI-PII.** A notification payload carries only ids, severity, channel and a
    runbook link — never log bodies or customer data.
  * **Fail closed.** A missing URL or a delivery error surfaces as an *undelivered*
    :class:`DeliveryResult`; it never raises through the module or silently claims success.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

import httpx

# Config key (or Key Vault reference name) the edge reads the webhook URL from. The *value* is
# supplied at runtime by identity — only the key name lives in code (keyless).
WEBHOOK_URL_CONFIG_KEY = "alerts.webhook.url"


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    """Outcome of one delivery attempt. ``delivered`` is the fail-closed truth signal."""

    channel: str
    delivered: bool
    statusCode: int | None = None
    detail: str | None = None


@runtime_checkable
class NotificationChannel(Protocol):
    """Narrow delivery seam. A channel takes a routed notification and reports the outcome.

    Implementations live at the edge and are injected via ``ctx.clients["notifier"]``. The
    ``notification`` mapping is the routed decision (id/severity/channel/runbook) — never customer
    data. Implementations must **fail closed**: return an undelivered :class:`DeliveryResult` rather
    than raising for an expected delivery error.
    """

    def send(self, notification: Mapping[str, Any]) -> DeliveryResult:
        """Deliver ``notification`` and return a :class:`DeliveryResult`."""
        ...


class WebhookChannel:
    """Real channel: HTTP POST the routed notification to a webhook URL (keyless).

    The ``url`` is resolved at the edge from config or a Key Vault reference (by identity) — it is
    **never** hard-coded. An ``httpx.Client`` is injected so transport/auth is configured once at
    the boundary; unit tests never construct this class (they inject a fake channel instead), so no
    test hits the network.

    TODO(human): authenticate the webhook with Entra (bearer token from ``DefaultAzureCredential``)
    or an HMAC signature whose key is fetched from Key Vault by identity. Wire it on the injected
    ``httpx.Client`` (e.g. an auth hook / default header) at the edge — keep the secret out of this
    file, out of ``ctx.config`` literals, and out of tests.
    """

    def __init__(self, url: str, client: httpx.Client, *, timeout: float = 10.0) -> None:
        self._url = url
        self._client = client
        self._timeout = timeout

    def send(self, notification: Mapping[str, Any]) -> DeliveryResult:
        channel = str(notification.get("channel", "webhook"))
        if not self._url:
            # Fail closed: nothing to POST to — surface undelivered, do not act/raise.
            return DeliveryResult(
                channel=channel, delivered=False, detail="no webhook url configured"
            )
        try:
            resp = self._client.post(self._url, json=dict(notification), timeout=self._timeout)
        except httpx.HTTPError as exc:  # network/timeout — fail closed, never crash the run
            return DeliveryResult(
                channel=channel, delivered=False, detail=f"transport error: {exc!s}"
            )
        delivered = 200 <= resp.status_code < 300
        return DeliveryResult(channel=channel, delivered=delivered, statusCode=resp.status_code)


def build_webhook_channel(config: Mapping[str, str], client: httpx.Client) -> WebhookChannel | None:
    """Edge factory: construct a :class:`WebhookChannel` from config, or ``None`` if unconfigured.

    Reads the URL from ``config[WEBHOOK_URL_CONFIG_KEY]`` (a plain URL or a Key Vault reference the
    edge has already resolved by identity). Returns ``None`` when absent so the module fails closed
    (routes computed, marked undelivered) instead of guessing an endpoint. Called by the worker/API
    at the process boundary — not by the pure module logic.
    """
    url = config.get(WEBHOOK_URL_CONFIG_KEY, "").strip()
    if not url:
        return None
    return WebhookChannel(url, client)


# TODO(human): add an email / Microsoft Teams / ACS channel implementing ``NotificationChannel``
# (e.g. ``class TeamsChannel``) that posts an Adaptive Card via an ACS/Graph client authenticated
# with Managed Identity (keyless). Keep it behind this same Protocol and inject it at the edge as
# ``ctx.clients["notifier"]`` (or a composite fan-out channel) so the module stays delivery-agnostic
# and tests keep injecting a fake. No connection strings/secrets in code, config literals, or tests.
