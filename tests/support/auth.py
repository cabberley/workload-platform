"""Synthetic JWT/JWKS harness for the Entra auth tests — no network, no real Entra, keyless.

Everything here is **obviously fake**: a locally-generated RSA keypair, a zeroed tenant guid, and a
fabricated object id. Tokens are signed with the local private key and validated with its PUBLIC
half through an injected :class:`~shared.auth.jwks.PublicKeyProvider`, so the whole flow is offline
and keyless (the private key never leaves the test process; validation uses only the public key).
"""
from __future__ import annotations

import base64
import json
import time
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from shared.auth.config import AuthConfig
from shared.auth.errors import AuthenticationError
from shared.auth.jwks import PublicKeyProvider
from shared.auth.validator import TokenValidator

# Clearly-fake identifiers — never a real tenant, app, or directory object.
FAKE_TENANT = "00000000-0000-0000-0000-000000000000"
FAKE_AUDIENCE = "api://fake-workloads-platform"
FAKE_ISSUER = f"https://login.microsoftonline.com/{FAKE_TENANT}/v2.0"
FAKE_OID = "11111111-1111-1111-1111-111111111111"
TEST_KID = "test-key-1"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class StaticKeyProvider:
    """A :class:`PublicKeyProvider` returning one public key for a fixed ``kid`` (network-free).

    Any other ``kid`` fails closed with :class:`AuthenticationError`, mirroring the real provider's
    unknown-``kid`` behaviour without any HTTP.
    """

    def __init__(self, public_key: RSAPublicKey, *, kid: str = TEST_KID) -> None:
        self._public_key = public_key
        self._kid = kid

    def get_key(self, kid: str) -> RSAPublicKey:
        if kid != self._kid:
            raise AuthenticationError("unknown_kid")
        return self._public_key


class TokenFactory:
    """Mints RS256 JWTs signed with a locally-generated private key (synthetic, offline)."""

    def __init__(self, *, kid: str = TEST_KID) -> None:
        self._private: RSAPrivateKey = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self._kid = kid

    @property
    def public_key(self) -> RSAPublicKey:
        return self._private.public_key()

    def key_provider(self) -> StaticKeyProvider:
        return StaticKeyProvider(self.public_key, kid=self._kid)

    def public_jwk(self) -> dict[str, str]:
        """Return the public key as a JWKS-style JWK dict (for :func:`jwk_to_public_key` tests)."""
        numbers = self.public_key.public_numbers()
        n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
        e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
        return {"kty": "RSA", "kid": self._kid, "use": "sig", "alg": "RS256",
                "n": _b64url(n), "e": _b64url(e)}

    def mint(
        self,
        *,
        oid: str | None = FAKE_OID,
        roles: list[str] | None = None,
        tid: str | None = None,
        audience: str | list[str] = FAKE_AUDIENCE,
        issuer: str = FAKE_ISSUER,
        expires_in: float = 3600.0,
        not_before: float | None = None,
        now: float | None = None,
        alg: str = "RS256",
        kid: str | None = None,
        sign: bool = True,
        header_overrides: dict[str, Any] | None = None,
    ) -> str:
        """Build a compact JWS. Knobs let a test forge a specifically-invalid token.

        ``tid`` mints the Entra tenant-id claim (issue #65); omitted (``None``) ⇒ no ``tid`` claim,
        exercising the tenant-absent path.
        """
        issued = now if now is not None else time.time()
        header: dict[str, Any] = {"alg": alg, "typ": "JWT", "kid": kid or self._kid}
        if header_overrides:
            header.update(header_overrides)
        claims: dict[str, Any] = {
            "iss": issuer,
            "aud": audience,
            "exp": issued + expires_in,
            "iat": issued,
        }
        if not_before is not None:
            claims["nbf"] = not_before
        if oid is not None:
            claims["oid"] = oid
        if roles is not None:
            claims["roles"] = roles
        if tid is not None:
            claims["tid"] = tid
        header_seg = _b64url(json.dumps(header).encode("utf-8"))
        payload_seg = _b64url(json.dumps(claims).encode("utf-8"))
        signing_input = f"{header_seg}.{payload_seg}".encode("ascii")
        if sign and alg == "RS256":
            signature = self._private.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
            sig_seg = _b64url(signature)
        elif sign:
            # A deliberately-bogus signature for a non-RS256 alg (should be rejected before verify).
            sig_seg = _b64url(b"not-a-real-signature")
        else:
            sig_seg = _b64url(b"")
        return f"{header_seg}.{payload_seg}.{sig_seg}"

    def tamper(self, token: str) -> str:
        """Return ``token`` with its payload mutated so the signature no longer matches."""
        header_seg, payload_seg, sig_seg = token.split(".")
        claims = json.loads(
            base64.urlsafe_b64decode(payload_seg + "=" * (-len(payload_seg) % 4))
        )
        claims["oid"] = "22222222-2222-2222-2222-222222222222"
        forged = _b64url(json.dumps(claims).encode("utf-8"))
        return f"{header_seg}.{forged}.{sig_seg}"


def fake_auth_config(
    *, audience: str = FAKE_AUDIENCE, issuer: str = FAKE_ISSUER
) -> AuthConfig:
    return AuthConfig(
        tenant_id=FAKE_TENANT,
        audience=audience,
        allowed_issuers=(issuer,),
        jwks_uri=f"https://login.microsoftonline.com/{FAKE_TENANT}/discovery/v2.0/keys",
    )


def build_test_validator(
    factory: TokenFactory,
    *,
    config: AuthConfig | None = None,
    key_provider: PublicKeyProvider | None = None,
    clock: Any = None,
) -> TokenValidator:
    cfg = config if config is not None else fake_auth_config()
    provider = key_provider if key_provider is not None else factory.key_provider()
    if clock is None:
        return TokenValidator(cfg, provider)
    return TokenValidator(cfg, provider, clock=clock)


# Public, non-secret DER of the private key is never exported — only the public key/JWK is exposed,
# reinforcing that validation is keyless.
def public_key_pem(factory: TokenFactory) -> bytes:
    return factory.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
