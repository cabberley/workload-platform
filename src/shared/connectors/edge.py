"""Shared HTTPS **edge** helpers for read-only connectors — endpoint safety + a bounded reader.

Historically each connector (Kuiper #47, Citrix #48) re-derived the same two pieces of transport
machinery around the primitives in :mod:`shared.connectors.base`:

* a **credential-exfil-safe endpoint validator** — proves an operator-configured URL is an
  ``https`` host on an explicit approved-host allowlist (no IP literals, no userinfo/query/fragment/
  port, no placeholder, IDNA-canonicalized *exactly* as HTTPX encodes it) BEFORE any credential is
  resolved or any request is made; and
* a **streamed, size- AND time-bounded JSON reader** — measures the byte ceiling on the raw wire
  body (decompression-bomb safe), aborts a slow-drip body on the overall deadline, and refuses a
  non-``identity`` content coding.

This module unifies both so the two load-balancer connectors added for issue #49 (NetScaler NITRO,
F5 iControl REST) **build on** the machinery instead of re-deriving it, and a generic
:class:`HttpEdgeClient` runs the whole fail-closed fetch loop given only a connector's config and a
pure ``transform`` from decoded payload → PII-safe ``FetchResult.raw`` records.

**SDK-free at import.** ``httpx`` is imported **lazily inside** :meth:`HttpEdgeClient._fetch`;
importing this module (or a connector built on it) never imports ``httpx``. Only ``idna`` (already a
transitive dependency of HTTPX, and *not* HTTPX) is imported at module top so the host is
canonicalized with the exact library HTTPX uses.
"""
from __future__ import annotations

import ipaddress
import json
import random
import re
import time
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit, urlunsplit

import idna
from pydantic import BaseModel, ConfigDict, Field

from shared.connectors.base import (
    FailClosedObserver,
    FetchResult,
    SecretProvider,
    TokenProvider,
    fail_closed,
    resolve_bearer_token,
    run_with_retries,
)

if TYPE_CHECKING:  # httpx is imported lazily inside the edge so importing this module is SDK-free.
    import httpx

__all__ = [
    "DeadlineExceeded",
    "EdgeEndpointError",
    "EndpointNotApproved",
    "HttpEdgeClient",
    "HttpEdgeConfig",
    "InvalidEndpoint",
    "InvalidResponse",
    "ResponseTooLarge",
    "coerce_dict_list",
    "read_bounded_json",
    "validate_https_endpoint",
]

# HTTP auth scheme for the resolved token — kept as a bare constant so the token is interpolated at
# runtime and never embedded in source.
_AUTH_SCHEME = "Bearer"

# Slice size for bounding an already-buffered (non-streaming) response body — keeps the size check
# operating on fixed-size chunks. The live edge streams network-sized ``iter_raw()`` chunks instead.
_WIRE_CHUNK_BYTES = 65536

# A legacy/alternate IPv4-literal label: a bare decimal integer, a 0x-hex form, or a leading-zero
# octal form. ``ipaddress.ip_address`` only rejects the canonical dotted-quad, so hosts whose labels
# are ALL numeric/hex (e.g. ``2130706433``, ``0x7f.0.0.1``, ``0177.0.0.1``, ``127.1``) would slip
# through as "hostnames" and may resolve to loopback — they are rejected as IP literals.
_NUMERIC_LABEL_RE = re.compile(r"(?i)^(0x[0-9a-f]+|\d+)$")

# Hosts that are obvious non-production placeholders — rejected even if mistakenly allow-listed.
_PLACEHOLDER_HOSTS: frozenset[str] = frozenset(
    {
        "",
        "localhost",
        "example.com",
        "example.org",
        "example.net",
        "changeme",
        "placeholder",
        "todo",
        "invalid",
        "netscaler.local",
        "bigip.local",
        "f5.local",
    }
)


class EdgeEndpointError(ValueError):
    """Base: the configured endpoint is not safe to send a credential to — fail closed."""


class InvalidEndpoint(EdgeEndpointError):
    """Endpoint is structurally unsafe (not https / userinfo / query / fragment / port / IP /
    placeholder / unsafe path) — fail closed BEFORE resolving a credential."""


class EndpointNotApproved(EdgeEndpointError):
    """The endpoint host is not on the operator-configured approved-host allowlist — fail closed."""


class ResponseTooLarge(ValueError):
    """Raised when a response exceeds the configured byte ceiling — fail closed."""


class InvalidResponse(ValueError):
    """Raised when a response cannot be safely/bounded-ly read (e.g. an unbounded content coding we
    refused to decode) — fail closed."""


class DeadlineExceeded(ValueError):
    """Raised when the overall fetch deadline is exhausted before/within an attempt."""


class HttpEdgeConfig(BaseModel):
    """Shared connector config. Holds **no secrets** — only a Key Vault-backed env var *name*.

    There is intentionally **no default host**: ``base_url`` and ``approved_hosts`` both default to
    empty, so a connector built on this config is inert (``available=False``) until a human wires an
    approved ``https`` endpoint AND adds its host to ``approved_hosts``. Vendor connectors subclass
    this to set their own ``signals_path`` / ``token_env`` defaults.
    """

    model_config = ConfigDict(extra="forbid")

    base_url: str = Field(default="", description="Approved https base URL (none by default)")
    signals_path: str = Field(default="/", description="Read-only path fetched at the edge")
    approved_hosts: tuple[str, ...] = Field(
        default_factory=tuple, description="Explicit approved endpoint hosts (no default)"
    )
    timeout_s: float = Field(default=10.0, gt=0.0, le=60.0)
    token_env: str = Field(default="", description="Key Vault-backed env var *name* (not a secret)")
    token_secret_name: str | None = None
    # Bounded work: capped retries/delays + an overall elapsed-time deadline across retries, a max
    # response-body size, a max record count, and a max per-field length. Any exceeded bound fails
    # closed. Only transient transport errors are retried; else fail at once.
    retries: int = Field(default=3, ge=1, le=8, description="Max fetch attempts (bounded)")
    base_delay_s: float = Field(default=0.2, gt=0.0, le=5.0)
    max_delay_s: float = Field(default=2.0, gt=0.0, le=30.0)
    max_elapsed_s: float = Field(default=15.0, gt=0.0, le=120.0, description="Total retry deadline")
    max_response_bytes: int = Field(default=1_048_576, ge=1, le=10_485_760)
    max_records: int = Field(default=1000, ge=1, le=10_000)
    max_field_len: int = Field(default=512, ge=1, le=4096)


def _is_numeric_ipv4_literal(host: str) -> bool:
    """True iff every label of ``host`` is numeric/hex — i.e. a legacy/alternate IPv4 literal."""
    labels = host.split(".")
    return any(labels) and all(_NUMERIC_LABEL_RE.match(label) for label in labels if label != "")


def _canonicalize_host(host: str) -> str:
    """Canonicalize a hostname EXACTLY as HTTPX will encode it — fail closed on any IDNA error.

    Mirrors ``httpx._urlparse.encode_host``: an ASCII host is lower-cased and used as-is (already
    the punycode/``xn--`` form for an internationalized name); a non-ASCII host is encoded with the
    SAME ``idna`` library HTTPX uses (``idna.encode``, IDNA2008 — NOT the legacy stdlib ``idna``
    codec, which would map e.g. ``ß`` → ``ss`` and validate a DIFFERENT host than HTTPX requests).
    A single trailing FQDN dot is stripped. Any IDNA failure raises :class:`InvalidEndpoint` (fail
    closed) — never a lossy fallback. The returned value is the byte-for-byte host HTTPX will put on
    the wire, so the allowlist check and the actual request target can never diverge.
    """
    normalized = host.strip().rstrip(".").lower()
    if not normalized:
        raise InvalidEndpoint("endpoint host is empty")
    if normalized.isascii():
        return normalized
    try:
        return idna.encode(normalized).decode("ascii")
    except idna.IDNAError as exc:
        raise InvalidEndpoint("endpoint host is not IDNA-encodable") from exc


def validate_https_endpoint(
    base_url: str, signals_path: str, approved_hosts: Iterable[str]
) -> str:
    """Validate the endpoint BEFORE any credential is resolved — or raise (credential-exfil safe).

    Returns the full endpoint URL only when ALL hold: scheme is ``https``; there is no userinfo,
    query, or fragment; **no explicit port**; the host is non-empty, not an IP literal (canonical
    dotted-quad/IPv6 OR a legacy numeric/hex/octal/short form), not a known placeholder (after
    canonicalization), and — compared on its canonical (lower-cased, trailing-dot-stripped,
    HTTPX-identical IDNA-encoded) form — present in ``approved_hosts`` (there is no default host);
    and ``signals_path`` is a simple, safe path. Any failure raises :class:`InvalidEndpoint` /
    :class:`EndpointNotApproved` so the caller fails closed and NEVER resolves a credential or sends
    a request.

    The returned URL is rebuilt from the VALIDATED scheme + canonical host + validated path — the
    raw ``base_url`` host is never handed to HTTPX downstream, so the allowlist-checked host is
    byte-for-byte the host that is requested. ``http://`` is rejected so it can never be used even
    with ``verify=True``.
    """
    parts = urlsplit(base_url)
    if parts.scheme != "https":
        raise InvalidEndpoint("endpoint scheme must be https")
    if parts.username or parts.password:
        raise InvalidEndpoint("endpoint must not contain userinfo")
    if parts.query or parts.fragment:
        raise InvalidEndpoint("endpoint must not contain a query or fragment")
    # An explicit port is part of the endpoint identity but is not covered by a host-only allowlist,
    # so reject it outright rather than let ``host:port`` slip through on host alone.
    if parts.port is not None:
        raise InvalidEndpoint("endpoint must not specify an explicit port")
    raw_host = parts.hostname
    if not raw_host:
        raise InvalidEndpoint("endpoint host is empty")
    normalized_host = raw_host.strip().rstrip(".").lower()
    # Reject IP literals — the canonical dotted-quad/IPv6 forms AND legacy numeric/hex/octal/short
    # forms that ``ipaddress`` would treat as a hostname. A load balancer must be a named host.
    try:
        ipaddress.ip_address(normalized_host)
    except ValueError:
        if _is_numeric_ipv4_literal(normalized_host):
            raise InvalidEndpoint("endpoint host must not be a numeric IP literal") from None
    else:
        raise InvalidEndpoint("endpoint host must not be an IP literal")
    host = _canonicalize_host(raw_host)
    if host in _PLACEHOLDER_HOSTS:
        raise InvalidEndpoint("endpoint host is a placeholder")
    approved = {_canonicalize_host(h) for h in approved_hosts}
    if host not in approved:
        raise EndpointNotApproved("endpoint host is not on the approved-host allowlist")
    if not signals_path.startswith("/") or any(c in signals_path for c in "?#@ "):
        raise InvalidEndpoint("signals_path is not a simple path")
    # Rebuild from the VALIDATED components only — canonical host + validated scheme/path — so HTTPX
    # is never handed the raw host and requests exactly the host we allowlist-checked.
    base_path = parts.path.rstrip("/")
    full_path = f"{base_path}/{signals_path.lstrip('/')}"
    return urlunsplit((parts.scheme, host, full_path, "", ""))


def coerce_dict_list(payload: Any, key_candidates: Iterable[str]) -> list[dict[str, Any]]:
    """Strictly extract a list of dicts from a bare list or a single-key ``{key: [...]}`` envelope.

    Accepts a bare list, or an envelope with **exactly one** recognized key from ``key_candidates``.
    Ambiguous, unrecognized, a non-list value, or any non-dict entry all **raise** — so a broken
    feed surfaces as ``available=False`` rather than masquerading as healthy-but-empty.
    """
    if isinstance(payload, list):
        items: list[Any] = payload
    elif isinstance(payload, dict):
        present = [k for k in key_candidates if k in payload]
        if len(present) != 1:
            raise InvalidResponse("ambiguous or unrecognized payload shape")
        candidate = payload[present[0]]
        if not isinstance(candidate, list):
            raise InvalidResponse("envelope value is not a list")
        items = candidate
    else:
        raise InvalidResponse("unrecognized payload shape")
    if not all(isinstance(item, dict) for item in items):
        raise InvalidResponse("payload contains non-dict entries")
    return [item for item in items if isinstance(item, dict)]


def _iter_wire_bytes(response: httpx.Response) -> Iterable[bytes]:
    """Yield RAW, undecoded wire chunks — the correct (compressed) side of any content coding.

    The live streaming edge (``client.stream(...)``) exposes an un-consumed stream, so
    ``iter_raw()`` yields network-sized chunks with NO implicit decompression — the size ceiling is
    enforced on the wire (decompression-bomb safe). If the response body was already buffered
    (``is_stream_consumed`` — e.g. a non-streaming transport), fall back to slicing that in-memory
    body into fixed-size chunks so the same bounded check applies; a non-identity coding was already
    refused by the caller, so the buffered bytes are the literal body.
    """
    if response.is_stream_consumed:
        body = response.content
        for start in range(0, len(body), _WIRE_CHUNK_BYTES):
            yield body[start : start + _WIRE_CHUNK_BYTES]
        return
    yield from response.iter_raw()


def read_bounded_json(response: httpx.Response, max_bytes: int, deadline: float) -> Any:
    """Stream + size- AND time-bound a response body on the WIRE, then JSON-decode it — fail closed.

    Defends against a decompression bomb from a compromised/malfunctioning APPROVED endpoint: the
    byte ceiling MUST be measured on the on-the-wire body, never on the far-larger decoded side of a
    content coding. So this:

    * rejects an over-limit declared ``Content-Length`` BEFORE reading;
    * refuses any non-``identity`` ``Content-Encoding`` (we request ``Accept-Encoding: identity``; a
      server that compresses anyway is refused, not decoded) — :class:`InvalidResponse`;
    * streams RAW wire bytes via ``iter_raw()`` (NO implicit decompression) and rejects the moment
      the ceiling WOULD be exceeded — ``len(buffer) + len(chunk) > max_bytes`` is checked BEFORE the
      chunk is appended, so an over-limit buffer is never materialized;
    * checks the remaining overall deadline on EVERY chunk so a slow-drip body is aborted mid-stream
      rather than drained.

    Byte-ceiling breach ⇒ :class:`ResponseTooLarge`; deadline breach ⇒ :class:`DeadlineExceeded`;
    unbounded/refused coding ⇒ :class:`InvalidResponse`.
    """
    declared = response.headers.get("content-length")
    if declared is not None:
        try:
            declared_n = int(declared)
        except ValueError as exc:
            raise ResponseTooLarge("invalid Content-Length header") from exc
        if declared_n > max_bytes:
            raise ResponseTooLarge("declared response exceeds byte ceiling")
    encoding = response.headers.get("content-encoding", "").strip().lower()
    if encoding and encoding != "identity":
        raise InvalidResponse("response carries a non-identity content-encoding")
    buffer = bytearray()
    for chunk in _iter_wire_bytes(response):
        if time.monotonic() >= deadline:
            raise DeadlineExceeded("fetch deadline exhausted while streaming")
        if len(buffer) + len(chunk) > max_bytes:
            raise ResponseTooLarge("streamed response exceeds byte ceiling")
        buffer.extend(chunk)
    return json.loads(bytes(buffer))


# Pure ``decoded payload -> PII-safe FetchResult.raw records``. Any exception ⇒ the whole fetch
# fails closed (guarded by :func:`fail_closed`). Malformed payloads are NOT transient, so they are
# not retried; a bad payload surfaces as ``available=False`` at once.
PayloadTransform = Callable[[Any], list[dict[str, Any]]]


class HttpEdgeClient:
    """Generic, read-only HTTPS edge. Fail-closed by default; validates the endpoint FIRST.

    Given a :class:`HttpEdgeConfig` and a pure ``transform`` (decoded JSON → PII-safe
    ``FetchResult.raw`` records), :meth:`fetch_raw` runs the whole fail-closed loop: validate the
    endpoint **before** any credential is resolved, resolve a keyless bearer (injected provider →
    Key Vault by identity → local-dev env fallback), stream a size/time-bounded body, decode, and
    hand the payload to ``transform``. Any failure fails closed (``available=False``, error **class
    name only** — never a body, message, or token). Inject ``client`` (an ``httpx.Client`` on
    ``httpx.MockTransport``), ``credential_provider`` and/or ``secret_provider`` to keep everything
    testable without touching the network or a vault.
    """

    def __init__(
        self,
        config: HttpEdgeConfig,
        transform: PayloadTransform,
        *,
        envelope_keys: Iterable[str] = (),
        client: httpx.Client | None = None,
        credential_provider: TokenProvider | None = None,
        secret_provider: SecretProvider | None = None,
        fail_closed_observer: FailClosedObserver | None = None,
        sleep: Callable[[float], None] = time.sleep,
        rng: random.Random | None = None,
    ) -> None:
        self._config = config
        self._transform = transform
        self._envelope_keys = tuple(envelope_keys)
        self._client = client
        self._credential_provider = credential_provider
        self._secret_provider = secret_provider
        self._fail_closed_observer = fail_closed_observer
        self._sleep = sleep
        self._rng = rng if rng is not None else random.Random()  # noqa: S311 - backoff jitter

    def fetch_raw(self) -> FetchResult:
        """The single network edge. Read-only GET; returns validated records or fails closed.

        Fails closed (``available=False``, error *class* name only) on: an unapproved/invalid
        endpoint (BEFORE resolving any credential), an unresolvable credential, any transport/
        decoding error, an oversized (streamed) response, a malformed payload, or the overall time
        deadline being exhausted. Transient transport errors are retried only while the deadline has
        time left; everything else fails closed at once. When the endpoint is invalid or no
        credential resolves, **no** request runs.
        """
        return fail_closed(self._fetch, observer=self._fail_closed_observer)

    def _fetch(self) -> FetchResult:
        """Validate endpoint, resolve credential, then bounded read + pure transform. May raise."""
        # Validate BEFORE touching any credential. Raises ⇒ fail closed, no credential read.
        endpoint = validate_https_endpoint(
            self._config.base_url, self._config.signals_path, self._config.approved_hosts
        )
        token = resolve_bearer_token(
            self._credential_provider,
            self._config.token_env,
            secret_provider=self._secret_provider,
            secret_name=self._config.token_secret_name,
        )
        if not token:
            return FetchResult(available=False, error="NoCredential")

        import httpx  # lazy: keeps importing this module (and any connector on it) SDK-free.

        active_client = self._client or httpx.Client(verify=True)
        owns_client = self._client is None
        deadline = time.monotonic() + self._config.max_elapsed_s

        def _remaining() -> float:
            return deadline - time.monotonic()

        def _bounded_sleep(seconds: float) -> None:
            self._sleep(max(0.0, min(seconds, _remaining())))

        def _retry_on(exc: BaseException) -> bool:
            transient = isinstance(exc, httpx.TransportError)
            return transient and _remaining() > 0.0

        try:
            def _attempt() -> Any:
                remaining = _remaining()
                if remaining <= 0.0:
                    raise DeadlineExceeded("fetch deadline exhausted")
                per_attempt_timeout = min(self._config.timeout_s, remaining)
                with active_client.stream(
                    "GET",
                    endpoint,
                    headers={
                        "Authorization": f"{_AUTH_SCHEME} {token}",
                        "Accept-Encoding": "identity",
                    },
                    timeout=per_attempt_timeout,
                ) as response:
                    response.raise_for_status()
                    return read_bounded_json(
                        response, self._config.max_response_bytes, deadline
                    )

            payload = run_with_retries(
                _attempt,
                attempts=self._config.retries,
                base_delay_s=self._config.base_delay_s,
                max_delay_s=self._config.max_delay_s,
                sleep=_bounded_sleep,
                rng=self._rng,
                retry_on=_retry_on,
            )
            # A successful attempt that overran the deadline is still rejected (fail closed): a
            # single slow attempt must never smuggle late data past the overall time ceiling.
            if _remaining() <= 0.0:
                raise DeadlineExceeded("fetch overran the deadline")
            # Pure transform runs OUTSIDE the retry loop — a malformed payload is not transient and
            # must fail closed at once, never be retried.
            raw = self._transform(payload)
            return FetchResult(available=True, raw=raw)
        finally:
            if owns_client:
                active_client.close()
