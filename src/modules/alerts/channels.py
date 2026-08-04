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
  * **HTTPS-only egress.** Outbound webhook URLs MUST be ``https://`` — cleartext ``http://`` is
    rejected fail-closed by :func:`require_https_webhook` (shared with the composition root) so
    findings can never egress over the wire in the clear. A documented, loopback-ONLY opt-out
    exists for a local test sink.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

import httpx

# Config key (or Key Vault reference name) the edge reads the webhook URL from. The *value* is
# supplied at runtime by identity — only the key name lives in code (keyless).
WEBHOOK_URL_CONFIG_KEY = "alerts.webhook.url"
# Config key gating the documented, loopback-ONLY cleartext opt-out (see ``require_https_webhook``).
# A truthy value permits ``http://`` *only* to a loopback host (127.0.0.0/8, ::1, localhost) — for
# a local test sink. Cleartext to any non-loopback host is ALWAYS rejected, even when this is set.
WEBHOOK_ALLOW_INSECURE_LOOPBACK_CONFIG_KEY = "alerts.webhook.allowInsecureLoopback"

# Truthy spellings accepted for boolean opt-out flags (case-insensitive).
_TRUTHY = frozenset({"1", "true", "yes", "on"})


def _is_truthy(value: str | None) -> bool:
    """Return whether ``value`` is a truthy flag spelling (``1/true/yes/on``, case-insensitive)."""
    return (value or "").strip().lower() in _TRUTHY


class InsecureWebhookError(ValueError):
    """Raised (fail closed) when a webhook URL is not HTTPS and not an allowed loopback opt-out.

    Carries only scheme/host-level detail — never the full URL — so a token embedded in the
    path/query of a misconfigured webhook can never leak into an error message or log (no-PII).
    """


# Constant, URL-free message for a URL that cannot even be parsed (or whose host/port is invalid).
# Kept constant so a leaking ``urlparse``/``.port`` ``ValueError`` (which can echo the raw netloc,
# including ``user:token@host`` userinfo) is never surfaced or logged — we ``raise ... from None``.
_MALFORMED_WEBHOOK_MSG = (
    "webhook URL is blank, scheme-less, malformed, or has an invalid host/port; a full https:// "
    "URL is required (URL content withheld to avoid leaking an embedded credential)"
)

# Constant, host-free detail for a delivery-time failure that could otherwise leak the hostname.
# A resolver-stage ``UnicodeError`` (e.g. the stdlib ``idna`` codec's "label too long") carries the
# COMPLETE canonical host in ``exc.object`` / ``exc.args``; we surface only this constant so no
# attacker-chosen host/token content ever reaches a message or log.
_SANITIZED_DELIVERY_DETAIL = (
    "transport error: webhook host could not be resolved (details withheld)"
)

# Constant, host-free detail for a general delivery/transport failure. httpx exception messages are
# NOT host/URL-free by contract — ``str(exc)`` for a connect/cert error can echo the configured
# webhook hostname (and a URL in the path/query could carry a token). We surface only this constant
# so neither the host nor any secret ever reaches the DeliveryResult detail or a log.
_TRANSPORT_ERROR_DETAIL = "webhook delivery failed"


def _is_loopback_host(hostname: str | None) -> bool:
    """Precisely decide whether ``hostname`` is a loopback host — spoof-proof.

    Matches only ``localhost`` (case-insensitive), an IPv4 literal in ``127.0.0.0/8``, or the IPv6
    literal EXACTLY ``::1``. A crafted host like ``127.0.0.1.evil.com`` or ``localhost.evil.com`` is
    NOT a valid IP literal and is not the literal string ``localhost``, so it is correctly rejected
    (no naive substring match). An ipv4-mapped IPv6 form such as ``::ffff:127.0.0.1`` — which
    ``ipaddress``'s ``.is_loopback`` would otherwise treat as loopback — is explicitly REJECTED, so
    the documented "exactly ``::1``" IPv6 loopback policy (ADR 0003) holds and a disguised loopback
    cannot slip through the opt-in. ``hostname`` is the canonical host from :class:`httpx.URL`
    (already IDNA-normalised, brackets stripped for IPv6, userinfo/port removed), so it is the true
    host httpx will dial.
    """
    if not hostname:
        return False
    host = hostname.lower()
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        # IPv6 loopback sink is EXACTLY ``::1``. Reject ipv4-mapped forms (``::ffff:127.0.0.1``),
        # which ``.is_loopback`` would smuggle through as a disguised loopback, and any other IPv6.
        return ip.ipv4_mapped is None and ip == ipaddress.IPv6Address("::1")
    # IPv4: unchanged — any address in 127.0.0.0/8 is a loopback sink.
    return ip.is_loopback


# A clean IPv6 zone id (the ``%eth0`` scope after an IPv6 literal): letters/digits/._- only. Used to
# reject a malformed authority like ``[fd00::abcd%]:x]`` whose ``.host`` httpx yields as
# ``fd00::abcd%]:x`` — the zone token ``]:x`` fails this pattern (``ipaddress`` alone would ignore
# such trailing junk). The ``{1,63}`` bound also caps the zone length: a real interface/zone id is
# short, and an over-long ASCII zone otherwise slips past validation and raises an UNCAUGHT
# ``UnicodeError`` ("label too long") in the idna codec during ``getaddrinfo`` at send(), leaking
# the full zone/host.
_IPV6_ZONE = re.compile(r"^[A-Za-z0-9._-]{1,63}$")

# Characters that must NEVER appear in a canonical IPv4/DNS host. These are the delimiters/controls
# that let a malformed authority slip past one httpx parser and blow up (leaking the raw host) in
# another (e.g. the response cookie-jar parse). ``:`` routes to the IPv6 branch, so it is excluded
# here on purpose.
_FORBIDDEN_HOST_CHARS = frozenset("[]%/\\?#@ \t\r\n\x0b\x0c")


def _canonical_host_ok(host: str) -> bool:
    """Strict allowlist: the canonical host must be EXACTLY one well-formed shape, else reject.

    CLASS-CLOSING control (issue #84 R4): :class:`httpx.URL` strips the surrounding brackets from an
    IPv6 authority but does NOT validate its contents — for ``https://[fd00::abcd%]:x]/p`` it yields
    ``.host == 'fd00::abcd%]:x'`` (junk retained), which passes ``httpx.URL`` and the
    ``httpx.Request`` preflight yet later raises inside httpx's cookie-jar URL parse at delivery,
    leaking the raw host (and any token in the URL). Rather than chase each httpx parser
    (whack-a-mole), we require the canonical host to be one of exactly three well-formed shapes:

      1. **IPv6 literal** — brackets already stripped by ``.host``; split off an optional ``%zone``
         and require BOTH ``ipaddress.IPv6Address`` to accept the address AND the zone token to be
         clean. This rejects trailing junk after the address (``...%]:x``), malformed zones, and
         non-hex groups that ``ipaddress`` alone would mis-handle.
      2. **IPv4 literal** — ``ipaddress.IPv4Address`` accepts the dotted-quad. (The spoof-guard's
         decimal/octal/hex rejection still applies separately for the loopback opt-out.)
      3. **DNS hostname** — non-empty dot-separated labels with no delimiter/control characters,
         within the DNS length bounds (total ≤ 253, each label 1..63). Those are the exact bounds
         the idna codec enforces, so a host that passes here can never raise an UNCAUGHT
         ``UnicodeError`` ("label too long") deep in ``getaddrinfo`` at send() (which would leak the
         full host from ``exc.object``). IDNA-cleanliness is ALREADY guaranteed by the
         ``httpx.URL`` + ``httpx.Request`` preflight in :func:`require_https_webhook`; we
         deliberately do NOT re-run a different IDNA codec here (that would reintroduce the
         parser-disagreement class we are closing) and we accept the unicode host form ``.host``
         returns for internationalised domains.

    Anything that is not exactly one of these three shapes is rejected → constant sanitized error.
    """
    if not host:
        return False
    if ":" in host:  # IPv6 literal (httpx already stripped the surrounding [ ])
        addr, sep, zone = host.partition("%")
        if sep and not _IPV6_ZONE.match(zone):  # bounded charset AND length (guards long-zone leak)
            return False
        try:
            ip6 = ipaddress.IPv6Address(addr)
        except ValueError:
            return False
        # Reject ipv4-mapped/-embedded forms (``::ffff:127.0.0.1``, ``::ffff:7f00:1``): they are a
        # disguised, ambiguous encoding of an IPv4 address (a known spoof vector — e.g. a mapped
        # loopback that ``.is_loopback`` treats as loopback) and must never be dialled. Rejecting
        # the SHAPE closes this everywhere (https, default-off, AND the loopback opt-in) with the
        # constant sanitized error — no host leak.
        return ip6.ipv4_mapped is None
    # No colon → IPv4 literal or DNS name. Reject any delimiter/control character outright so a
    # malformed authority cannot masquerade as a hostname.
    if any(ch in _FORBIDDEN_HOST_CHARS or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in host):
        return False
    try:
        ipaddress.IPv4Address(host)
        return True
    except ValueError:
        pass
    # DNS hostname: enforce the DNS length bounds (total ≤ 253 after a single trailing dot, every
    # label 1..63). An empty label (``..``/leading/trailing dot) or an over-long label/host is
    # rejected — this is what stops an over-long label passing validation and then raising an
    # UNCAUGHT idna "label too long" ``UnicodeError`` in ``getaddrinfo`` at send() (leaks the host).
    stripped = host.rstrip(".")
    if not stripped or len(stripped) > 253:
        return False
    return all(1 <= len(label) <= 63 for label in stripped.split("."))


def require_https_webhook(url: str, *, allow_insecure_loopback: bool = False) -> httpx.URL:
    """Validate an outbound webhook URL is HTTPS (fail closed); return the canonical URL or raise.

    This is the ONE shared validator used by both the composition root (``cli.wiring``) and the
    channel itself (defense in depth), so the policy can never drift between call sites.

    Policy:
      * ``https://`` with a nonempty host → accepted.
      * ``http://`` → accepted ONLY when ``allow_insecure_loopback`` is set AND the host is a
        loopback host (127.0.0.0/8, ::1, localhost). Cleartext to any non-loopback host is ALWAYS
        rejected, even with the opt-out enabled.
      * anything else — blank, scheme-less, malformed, a missing host, or an invalid port — is
        rejected fail-closed AT VALIDATION TIME (not late inside httpx at delivery).

    The URL is preflighted through httpx's OWN parser (:class:`httpx.URL`) **and** its request
    builder (:class:`httpx.Request`), which apply the SAME IDNA/host/port and Host-header encoding
    rules httpx uses at ``send()``. Validating with the delivery path eliminates the
    validate-vs-deliver mismatch class: a URL accepted here can never raise a late, uncaught
    ``httpx.InvalidURL`` / ``idna.IDNAError`` / ``UnicodeEncodeError`` (whose message would leak
    attacker-controlled host data) at delivery. Every parse/IDNA/port/unicode failure becomes the
    CONSTANT sanitized :class:`InsecureWebhookError` (``idna.IDNAError`` and ``UnicodeEncodeError``
    both subclass ``UnicodeError``, so they are covered) raised ``from None`` so no URL/host content
    reaches the message or the cause chain. The preflight builds the ``Request`` only — never any
    network I/O.

    On rejection raises :class:`InsecureWebhookError` with a scheme/host-level message only (never
    the full URL, which may carry a token) so no secret/PII leaks into errors or logs.

    Returns the CANONICAL :class:`httpx.URL` object (not the raw string) so the channel stores and
    POSTs byte-identically to the validated URL — ``send()`` never re-parses a different string, so
    validation and delivery can never disagree. (``httpx.URL == str`` is true and round-trips, so
    existing ``== url`` callers/tests are unaffected.)
    """
    candidate = (url or "").strip()
    try:
        parsed = httpx.URL(candidate)
        scheme = parsed.scheme.lower()
        host = parsed.host  # canonical host httpx will dial (IDNA-normalised, no userinfo/port)
        port = parsed.port  # int or None; httpx does NOT range-check it, so we do below
        # Preflight the SAME request-construction path delivery uses (``send()`` POSTs to this URL).
        # A successful ``httpx.URL()`` does NOT guarantee httpx can build the actual Request: e.g.
        # ``https://[::1%zone<non-ascii>]/hook`` parses fine but raises ``UnicodeEncodeError`` while
        # encoding the Host header at send(), leaking the netloc. Building the Request HERE (no
        # network I/O — no ``client.send``) surfaces that failure at VALIDATION so it is converted
        # to the constant sanitized error below, never a late uncaught leak.
        httpx.Request("POST", parsed)
        # Strict host allowlist (IPv6 / IPv4 / DNS): closes the class of malformed authorities that
        # slip past one httpx parser and leak the raw host in another (e.g. the cookie-jar parse) at
        # delivery. A pure bool over the canonical host — it never raises, so no host content leaks.
        host_shape_ok = _canonical_host_ok(host)
    except (httpx.InvalidURL, ValueError, UnicodeError):
        # idna.IDNAError and UnicodeEncodeError both subclass UnicodeError, so IDNA and Host-header
        # encoding failures are covered. Suppress the cause (``from None``) so the raw netloc / host
        # in the underlying message can never be logged.
        raise InsecureWebhookError(_MALFORMED_WEBHOOK_MSG) from None
    # A missing host, a host that is not one of the three well-formed shapes, or an out-of-range TCP
    # port (httpx.URL accepts e.g. :70000) fails closed HERE at validation — never late in the
    # transport at send(), where a leaking parser error could echo the raw host.
    if not host or not host_shape_ok or (port is not None and not 0 <= port <= 65535):
        raise InsecureWebhookError(_MALFORMED_WEBHOOK_MSG)
    if scheme == "https":
        return parsed
    if scheme == "http" and allow_insecure_loopback and _is_loopback_host(host):
        return parsed
    # PII-free: report scheme + host only — never the path/query (which may carry a token/secret).
    raise InsecureWebhookError(
        f"webhook URL must use https:// (got scheme {scheme or '(none)'!r} for host {host!r}); "
        "cleartext http:// is permitted only to a loopback host with the loopback opt-out enabled"
    )


def build_webhook_http_client(
    timeout: float = 10.0, *, transport: httpx.BaseTransport | None = None
) -> httpx.Client:
    """Build the hardened ``httpx.Client`` used for webhook delivery (keyless, TLS-preserving).

    Security posture (issue #84 — the loopback cleartext exception must stay strictly local):
      * ``trust_env=False`` — environment proxies (``HTTP_PROXY`` / ``HTTPS_PROXY`` / ``ALL_PROXY``)
        and env CA overrides are IGNORED, so a cleartext loopback POST can never be routed off-box
        through a proxy (which would exfiltrate the full URL + payload).
      * ``follow_redirects=False`` — an ``https://`` endpoint cannot ``307``→``http`` *downgrade*
        delivery onto an untrusted/cleartext transport; a redirect surfaces as a non-2xx response
        (undelivered) instead of being silently followed. Fail closed.
      * ``verify=True`` — TLS certificate verification stays on.

    ``transport`` is an injection seam for unit tests (a ``MockTransport``); it is never set in
    production, where the default verifying transport is used.
    """
    return httpx.Client(
        timeout=timeout,
        verify=True,
        trust_env=False,
        follow_redirects=False,
        transport=transport,
    )


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
    **never** hard-coded. The channel **owns** its hardened :class:`httpx.Client` (built via
    :func:`build_webhook_http_client`: env proxies ignored, redirects not followed, TLS verified) —
    a caller CANNOT inject a client with those protections disabled. Only a ``transport`` seam is
    exposed for unit tests (a ``MockTransport``); production passes none. Unit tests never hit the
    network (they inject a fake channel, or a MockTransport that raises if dialled).

    TODO(human): authenticate the webhook with Entra (bearer token from ``DefaultAzureCredential``)
    or an HMAC signature whose key is fetched from Key Vault by identity. Wire it on the owned
    ``httpx.Client`` (e.g. an auth hook / default header) at the edge — keep the secret out of this
    file, out of ``ctx.config`` literals, and out of tests.
    """

    def __init__(
        self,
        url: str,
        *,
        timeout: float = 10.0,
        allow_insecure_loopback: bool = False,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        # Defense in depth (belt-and-braces): validate the scheme HERE too, sharing the ONE
        # validator with the composition root. Even if a WebhookChannel is constructed directly
        # (bypassing wiring), a non-HTTPS URL is refused fail-closed so findings can never egress
        # over cleartext. Cleartext is tolerated only for an explicit loopback test sink.
        self._url = require_https_webhook(url, allow_insecure_loopback=allow_insecure_loopback)
        # The channel OWNS its hardened client so no caller can re-enable env proxies (which would
        # exfiltrate the cleartext loopback POST off-box) or redirect-following (a 307→http TLS
        # downgrade). Only a transport SEAM is exposed for tests; it is passed INTO the hardened
        # builder, so trust_env=False / follow_redirects=False always apply (issue #84).
        self._client = build_webhook_http_client(timeout, transport=transport)
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
        except httpx.HTTPError:  # network/timeout/cert — fail closed; msg NOT host/URL-free
            # ``str(exc)`` for a connect/cert error can echo the configured webhook host (and a URL
            # could carry a token in its path/query), so we NEVER surface ``exc``/``exc.args``/
            # ``exc.request``/``.url`` — only a CONSTANT host-free detail.
            return DeliveryResult(
                channel=channel, delivered=False, detail=_TRANSPORT_ERROR_DETAIL
            )
        except UnicodeError:
            # Defense in depth (belt-and-suspenders): even though validation now bounds host/label
            # lengths, a future parser corner could let a hostname reach here and raise a
            # ``UnicodeError`` (superclass of ``UnicodeEncodeError``/``UnicodeDecodeError``) deep in
            # ``getaddrinfo`` — e.g. the stdlib idna codec's "label too long". Its ``.object`` /
            # ``.args`` carry the FULL canonical host (attacker-chosen, possibly secret-looking),
            # so we NEVER surface ``exc`` content: return a CONSTANT sanitized detail, no cause.
            return DeliveryResult(
                channel=channel, delivered=False, detail=_SANITIZED_DELIVERY_DETAIL
            )
        delivered = 200 <= resp.status_code < 300
        return DeliveryResult(channel=channel, delivered=delivered, statusCode=resp.status_code)


def build_webhook_channel(
    config: Mapping[str, str], *, transport: httpx.BaseTransport | None = None
) -> WebhookChannel | None:
    """Edge factory: construct a :class:`WebhookChannel` from config, or ``None`` if unconfigured.

    Reads the URL from ``config[WEBHOOK_URL_CONFIG_KEY]`` (a plain URL or a Key Vault reference the
    edge has already resolved by identity). Returns ``None`` when absent so the module fails closed
    (routes computed, marked undelivered) instead of guessing an endpoint. Called by the worker/API
    at the process boundary — not by the pure module logic.

    The returned channel OWNS a hardened client — no client is injected, so a caller can never
    supply one with env proxies / redirect-following enabled. ``transport`` is a test-only seam
    (a ``MockTransport``) forwarded into :func:`build_webhook_http_client`.

    Fails closed on a non-HTTPS URL: a cleartext ``http://`` endpoint is rejected via
    :class:`InsecureWebhookError` unless it is a loopback host AND
    ``config[WEBHOOK_ALLOW_INSECURE_LOOPBACK_CONFIG_KEY]`` is truthy (documented loopback opt-out).
    """
    url = config.get(WEBHOOK_URL_CONFIG_KEY, "").strip()
    if not url:
        return None
    allow_insecure_loopback = _is_truthy(config.get(WEBHOOK_ALLOW_INSECURE_LOOPBACK_CONFIG_KEY))
    return WebhookChannel(
        url, allow_insecure_loopback=allow_insecure_loopback, transport=transport
    )


# TODO(human): add an email / Microsoft Teams / ACS channel implementing ``NotificationChannel``
# (e.g. ``class TeamsChannel``) that posts an Adaptive Card via an ACS/Graph client authenticated
# with Managed Identity (keyless). Keep it behind this same Protocol and inject it at the edge as
# ``ctx.clients["notifier"]`` (or a composite fan-out channel) so the module stays delivery-agnostic
# and tests keep injecting a fake. No connection strings/secrets in code, config literals, or tests.
