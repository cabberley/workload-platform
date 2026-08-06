"""Keyless Entra (Azure AD) bearer-token validator — public-key (JWKS) signature verification only.

Validates a JWT access token's **signature** against the tenant's PUBLIC JWKS keys and its
**issuer / audience / expiry (``exp``) / not-before (``nbf``)** claims, then extracts a non-PII
:class:`~shared.auth.principal.Principal` (the ``oid`` object id + recognized ``roles``). It is:

* **Keyless.** RS256 signatures are verified with the tenant's public key (RSASSA-PKCS1-v1_5 +
  SHA-256) obtained from the injectable :class:`~shared.auth.jwks.PublicKeyProvider`. There is NO
  client secret / private key anywhere — signature verification is a public-key operation.
* **Fail closed.** Any problem — malformed token, wrong ``alg`` (an ``alg=none``/``HS256`` downgrade
  is rejected), unknown ``kid``, bad signature, wrong issuer/audience, expired / not-yet-valid,
  missing ``oid`` — raises :class:`~shared.auth.errors.AuthenticationError`. The raised message is a
  short generic reason code ONLY; it never contains the token, any claim value, or PII.
* **Injectable / network-free to test.** The JWKS/crypto edge is behind ``key_provider`` and the
  wall-clock behind ``clock``, so unit tests sign with a locally-generated key, inject its public
  half, and validate with no network and no real Entra.
"""
from __future__ import annotations

import base64
import binascii
import json
import time
from collections.abc import Callable, Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from shared.auth.config import AuthConfig
from shared.auth.errors import AuthenticationError
from shared.auth.jwks import PublicKeyProvider
from shared.auth.principal import Principal
from shared.auth.roles import roles_from_app_roles

__all__ = ["DEFAULT_LEEWAY_SECONDS", "TokenValidator"]

# Small clock-skew tolerance applied to exp/nbf, mirroring standard JWT validators.
DEFAULT_LEEWAY_SECONDS = 60.0

# The ONLY signature algorithm accepted. Pinning this rejects the classic ``alg=none`` bypass and an
# HS256 "confusion" downgrade (which would try to verify an RSA-signed token with a symmetric key).
_ALLOWED_ALG = "RS256"


def _b64url_decode(segment: str) -> bytes:
    """Decode one base64url JWT segment (no padding). Fail closed on invalid base64url."""
    padding_str = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + padding_str)
    except (binascii.Error, ValueError) as exc:
        raise AuthenticationError("malformed_token") from exc


def _decode_json_segment(segment: str) -> dict[str, Any]:
    """Decode a base64url JSON object segment (JWT header/payload). Fail closed if not an object."""
    try:
        obj = json.loads(_b64url_decode(segment))
    except (ValueError, UnicodeDecodeError) as exc:
        raise AuthenticationError("malformed_token") from exc
    if not isinstance(obj, dict):
        raise AuthenticationError("malformed_token")
    return obj


class TokenValidator:
    """Validate an Entra bearer token and return a non-PII :class:`Principal`, or fail closed.

    Construct with the keyless :class:`~shared.auth.config.AuthConfig` and an injectable
    :class:`~shared.auth.jwks.PublicKeyProvider`. ``clock`` (default :func:`time.time`) and
    ``leeway_seconds`` are injectable so ``exp``/``nbf`` checks are deterministic in tests.
    """

    def __init__(
        self,
        config: AuthConfig,
        key_provider: PublicKeyProvider,
        *,
        clock: Callable[[], float] = time.time,
        leeway_seconds: float = DEFAULT_LEEWAY_SECONDS,
    ) -> None:
        self._config = config
        self._key_provider = key_provider
        self._clock = clock
        self._leeway = leeway_seconds

    def validate(self, token: str) -> Principal:
        """Verify signature + claims of ``token`` and return the non-PII principal (fail closed).

        Raises :class:`~shared.auth.errors.AuthenticationError` (mapped to HTTP 401 by the API) on
        ANY failure, with a generic reason code that never leaks the token, claims, or PII.
        """
        header_seg, payload_seg = self._split(token)
        header = _decode_json_segment(header_seg)
        self._require_rs256(header)
        key = self._resolve_key(header)
        self._verify_signature(token, key)
        claims = _decode_json_segment(payload_seg)
        self._check_issuer(claims)
        self._check_audience(claims)
        self._check_time(claims)
        return self._principal_from_claims(claims)

    @staticmethod
    def _split(token: str) -> tuple[str, str]:
        """Split a compact JWS into (header_seg, payload_seg); the signature stays on the token."""
        parts = token.split(".")
        if len(parts) != 3 or not all(parts):
            raise AuthenticationError("malformed_token")
        return parts[0], parts[1]

    @staticmethod
    def _require_rs256(header: Mapping[str, Any]) -> None:
        if header.get("alg") != _ALLOWED_ALG:
            # Reject alg=none / HS256 downgrade and any non-RS256 algorithm outright.
            raise AuthenticationError("unsupported_alg")

    def _resolve_key(self, header: Mapping[str, Any]) -> Any:
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise AuthenticationError("missing_kid")
        # The provider fails closed (raises AuthenticationError) on an unknown kid.
        return self._key_provider.get_key(kid)

    @staticmethod
    def _verify_signature(token: str, key: Any) -> None:
        """Verify the RS256 signature over ``header.payload`` with the public key. Fail closed."""
        signing_input, _, signature_seg = token.rpartition(".")
        signature = _b64url_decode(signature_seg)
        try:
            key.verify(
                signature,
                signing_input.encode("ascii"),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except InvalidSignature as exc:
            raise AuthenticationError("bad_signature") from exc

    def _check_issuer(self, claims: Mapping[str, Any]) -> None:
        issuer = claims.get("iss")
        if not isinstance(issuer, str) or issuer not in self._config.allowed_issuers:
            raise AuthenticationError("bad_issuer")

    def _check_audience(self, claims: Mapping[str, Any]) -> None:
        aud = claims.get("aud")
        audiences: tuple[str, ...]
        if isinstance(aud, str):
            audiences = (aud,)
        elif isinstance(aud, list):
            audiences = tuple(a for a in aud if isinstance(a, str))
        else:
            raise AuthenticationError("bad_audience")
        if self._config.audience not in audiences:
            raise AuthenticationError("bad_audience")

    def _check_time(self, claims: Mapping[str, Any]) -> None:
        now = self._clock()
        exp = self._numeric_claim(claims, "exp")
        if exp is None or now > exp + self._leeway:
            raise AuthenticationError("expired")
        nbf = self._numeric_claim(claims, "nbf")
        if nbf is not None and now < nbf - self._leeway:
            raise AuthenticationError("not_yet_valid")

    @staticmethod
    def _numeric_claim(claims: Mapping[str, Any], name: str) -> float | None:
        value = claims.get(name)
        if isinstance(value, bool):  # bool is an int subclass — never a valid time claim
            return None
        if isinstance(value, (int, float)):
            return float(value)
        return None

    @staticmethod
    def _principal_from_claims(claims: Mapping[str, Any]) -> Principal:
        """Extract the non-PII oid + recognized roles. Fail closed if no usable object id."""
        oid = claims.get("oid")
        if not isinstance(oid, str) or not oid:
            # No object id ⇒ we cannot record a non-PII actor; refuse rather than fall back to PII.
            raise AuthenticationError("missing_oid")
        raw_roles = claims.get("roles")
        app_roles = (
            [r for r in raw_roles if isinstance(r, str)] if isinstance(raw_roles, list) else []
        )
        return Principal(oid=oid, roles=roles_from_app_roles(app_roles))
