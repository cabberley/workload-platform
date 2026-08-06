"""The injectable JWKS edge: fetch the tenant's PUBLIC signing keys and resolve them by ``kid``.

This is the ONE place that does JWKS HTTP and RSA public-key construction — the network- and
crypto-heavy edge the validator depends on only through the small :class:`PublicKeyProvider`
Protocol (mirroring how connectors inject a ``TokenProvider``). Tests inject a fake provider (or a
fake fetcher) so :class:`~shared.auth.validator.TokenValidator` runs keyless and network-free.

**Keyless by construction:** only PUBLIC keys are ever handled here. A JWK carries the RSA modulus
(``n``) and exponent (``e``) of a public key; there is no private key or client secret anywhere.
The cache is bounded by a TTL and refreshes on an unknown ``kid`` (Entra rotates signing keys), so a
freshly-rotated key is picked up without a process restart, while a bogus ``kid`` triggers at most
one refresh and then fails closed.
"""
from __future__ import annotations

import base64
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Protocol, runtime_checkable

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPublicNumbers

from shared.auth.errors import AuthenticationError

__all__ = [
    "DEFAULT_JWKS_TTL_SECONDS",
    "JwksFetcher",
    "JwksKeyProvider",
    "PublicKeyProvider",
    "httpx_jwks_fetcher",
    "jwk_to_public_key",
]

# A JWKS fetcher returns the ``keys`` array (a list of JWK dicts) from a JWKS endpoint. Injected so
# the HTTP transport stays at the edge and tests never touch the network.
JwksFetcher = Callable[[str], Sequence[Mapping[str, object]]]

# Default bounded cache lifetime. Signing keys rotate slowly; an unknown ``kid`` forces an early
# refresh regardless, so a short-ish TTL bounds staleness without hammering the endpoint.
DEFAULT_JWKS_TTL_SECONDS = 3600.0


@runtime_checkable
class PublicKeyProvider(Protocol):
    """Resolve an RSA PUBLIC signing key by its ``kid``. The validator's only JWKS dependency.

    Raises :class:`~shared.auth.errors.AuthenticationError` (fail closed) when the ``kid`` cannot be
    resolved even after a refresh — never returns ``None``.
    """

    def get_key(self, kid: str) -> RSAPublicKey: ...


def _b64url_uint(value: str) -> int:
    """Decode a base64url-encoded big-endian unsigned integer (a JWK ``n``/``e`` field)."""
    padding = "=" * (-len(value) % 4)
    raw = base64.urlsafe_b64decode(value + padding)
    return int.from_bytes(raw, "big")


def jwk_to_public_key(jwk: Mapping[str, object]) -> RSAPublicKey:
    """Construct an RSA public key from a JWK's ``n``/``e``. Fail closed on a malformed/non-RSA JWK.

    Only RSA keys (``kty == "RSA"``) are supported (Entra signs ID/access tokens with RS256). Any
    missing/invalid field raises :class:`~shared.auth.errors.AuthenticationError` with a generic,
    PII-free reason.
    """
    if jwk.get("kty") != "RSA":
        raise AuthenticationError("unsupported_key_type")
    modulus = jwk.get("n")
    exponent = jwk.get("e")
    if not isinstance(modulus, str) or not isinstance(exponent, str):
        raise AuthenticationError("malformed_jwk")
    try:
        numbers = RSAPublicNumbers(e=_b64url_uint(exponent), n=_b64url_uint(modulus))
        return numbers.public_key()
    except Exception as exc:  # noqa: BLE001 - any construction failure fails closed, no leak
        raise AuthenticationError("malformed_jwk") from exc


def httpx_jwks_fetcher(uri: str) -> Sequence[Mapping[str, object]]:
    """Default JWKS fetcher: GET the JWKS document with ``httpx`` and return its ``keys`` array.

    ``httpx`` is a base platform dependency; the import is local so importing this module needs no
    HTTP stack and unit tests (which inject a fake fetcher) stay network-free. Any transport/parse
    failure raises :class:`~shared.auth.errors.AuthenticationError` (class-name-only, no leak).
    """
    import httpx

    try:
        response = httpx.get(uri, timeout=5.0)
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:  # noqa: BLE001 - edge failure fails closed, class name only
        raise AuthenticationError(f"jwks_fetch_failed:{type(exc).__name__}") from exc
    keys = payload.get("keys") if isinstance(payload, Mapping) else None
    if not isinstance(keys, list):
        raise AuthenticationError("jwks_malformed")
    return keys


class JwksKeyProvider:
    """A TTL-cached, refresh-on-unknown-``kid`` :class:`PublicKeyProvider` over a JWKS endpoint.

    Fetches the JWKS document through an injected :data:`JwksFetcher` (default
    :func:`httpx_jwks_fetcher`) and caches the parsed public keys by ``kid``. On a cache miss it
    refreshes ONCE (Entra rotates keys) before failing closed for an unknown ``kid``. The cache is
    also refreshed when older than ``ttl_seconds``. Thread-safe (a lock guards the cache) so the
    single-process API can share one provider across worker threads. ``clock`` is injectable so
    TTL-expiry is deterministic in tests.
    """

    def __init__(
        self,
        jwks_uri: str,
        *,
        fetcher: JwksFetcher | None = None,
        ttl_seconds: float = DEFAULT_JWKS_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._jwks_uri = jwks_uri
        self._fetcher: JwksFetcher = fetcher if fetcher is not None else httpx_jwks_fetcher
        self._ttl = ttl_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._keys: dict[str, RSAPublicKey] = {}
        self._fetched_at: float | None = None

    def get_key(self, kid: str) -> RSAPublicKey:
        """Return the public key for ``kid``, refreshing on staleness or an unknown ``kid``.

        Fails closed (:class:`~shared.auth.errors.AuthenticationError`) if the ``kid`` is still
        unknown after a refresh.
        """
        with self._lock:
            if self._is_stale():
                self._refresh_locked()
            key = self._keys.get(kid)
            if key is None:
                # Unknown kid: force a single refresh (keys may have just rotated), then re-check.
                self._refresh_locked()
                key = self._keys.get(kid)
            if key is None:
                raise AuthenticationError("unknown_kid")
            return key

    def _is_stale(self) -> bool:
        if self._fetched_at is None:
            return True
        return (self._clock() - self._fetched_at) >= self._ttl

    def _refresh_locked(self) -> None:
        """Re-fetch and re-parse the JWKS document (caller holds the lock)."""
        jwks = self._fetcher(self._jwks_uri)
        parsed: dict[str, RSAPublicKey] = {}
        for jwk in jwks:
            kid = jwk.get("kid")
            if not isinstance(kid, str):
                continue
            if jwk.get("kty") != "RSA":
                continue
            parsed[kid] = jwk_to_public_key(jwk)
        self._keys = parsed
        self._fetched_at = self._clock()
