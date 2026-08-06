"""Unit tests for keyless auth config, the role model, and the JWKS key provider (network-free)."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from shared.auth import build_token_validator
from shared.auth.config import (
    ENV_ALLOWED_ISSUERS,
    ENV_AUDIENCE,
    ENV_JWKS_URI,
    ENV_MODE,
    ENV_TENANT_ID,
    AuthMode,
    build_auth_config,
    resolve_auth_mode,
)
from shared.auth.errors import AuthConfigError, AuthenticationError
from shared.auth.jwks import JwksKeyProvider, jwk_to_public_key
from shared.auth.principal import Principal
from shared.auth.roles import Role, roles_from_app_roles
from support.auth import TokenFactory

FAKE_TENANT = "00000000-0000-0000-0000-000000000000"


# --------------------------------------------------------------------------------------
# Config — fail-closed by default; None ONLY when fully unconfigured, raise on partial.
# --------------------------------------------------------------------------------------
def test_config_is_none_when_not_configured() -> None:
    # Both absent ⇒ "not configured" ⇒ None (the caller decides via mode).
    assert build_auth_config({}) is None


def test_config_raises_on_partial_config() -> None:
    # Tenant without audience (or vice-versa) is a misconfiguration ⇒ fail closed, never a None.
    with pytest.raises(AuthConfigError):
        build_auth_config({ENV_TENANT_ID: FAKE_TENANT})
    with pytest.raises(AuthConfigError):
        build_auth_config({ENV_AUDIENCE: "api://app"})
    # Blank values count as absent for the present half ⇒ still partial.
    with pytest.raises(AuthConfigError):
        build_auth_config({ENV_TENANT_ID: FAKE_TENANT, ENV_AUDIENCE: "  "})


def test_config_populated_with_canonical_defaults() -> None:
    config = build_auth_config({ENV_TENANT_ID: FAKE_TENANT, ENV_AUDIENCE: "api://app"})
    assert config is not None
    assert config.tenant_id == FAKE_TENANT
    assert config.audience == "api://app"
    assert config.allowed_issuers == (
        f"https://login.microsoftonline.com/{FAKE_TENANT}/v2.0",
    )
    assert config.jwks_uri == (
        f"https://login.microsoftonline.com/{FAKE_TENANT}/discovery/v2.0/keys"
    )


def test_config_honours_issuer_and_jwks_overrides() -> None:
    config = build_auth_config(
        {
            ENV_TENANT_ID: FAKE_TENANT,
            ENV_AUDIENCE: "api://app",
            ENV_ALLOWED_ISSUERS: "https://iss/a, https://iss/b",
            ENV_JWKS_URI: "https://keys.example/jwks",
        }
    )
    assert config is not None
    assert config.allowed_issuers == ("https://iss/a", "https://iss/b")
    assert config.jwks_uri == "https://keys.example/jwks"


def test_resolve_auth_mode_defaults_required() -> None:
    assert resolve_auth_mode({}) is AuthMode.required
    assert resolve_auth_mode({ENV_MODE: "required"}) is AuthMode.required
    assert resolve_auth_mode({ENV_MODE: "REQUIRED"}) is AuthMode.required
    assert resolve_auth_mode({ENV_MODE: "disabled"}) is AuthMode.disabled


def test_resolve_auth_mode_rejects_unknown() -> None:
    with pytest.raises(AuthConfigError):
        resolve_auth_mode({ENV_MODE: "off"})


def test_build_token_validator_none_only_when_explicitly_disabled() -> None:
    # Explicit opt-out is the ONLY way to get None (the documented no-auth local/dev path).
    assert build_token_validator(config={ENV_MODE: "disabled"}) is None
    # Disabled with stray config is still disabled (deliberate opt-out wins).
    assert (
        build_token_validator(
            config={ENV_MODE: "disabled", ENV_TENANT_ID: FAKE_TENANT, ENV_AUDIENCE: "api://app"},
            key_provider=TokenFactory().key_provider(),
        )
        is None
    )


def test_build_token_validator_required_but_unconfigured_fails_closed() -> None:
    # Default mode is required; absence of config must refuse to serve, never permit-all.
    with pytest.raises(AuthConfigError):
        build_token_validator(config={})
    with pytest.raises(AuthConfigError):
        build_token_validator(config={ENV_MODE: "required"})


def test_build_token_validator_required_but_partial_fails_closed() -> None:
    with pytest.raises(AuthConfigError):
        build_token_validator(config={ENV_MODE: "required", ENV_TENANT_ID: FAKE_TENANT})


def test_build_token_validator_disabled_logs_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    with caplog.at_level(logging.WARNING, logger="shared.auth"):
        assert build_token_validator(config={ENV_MODE: "disabled"}) is None
    assert any("DISABLED" in rec.message for rec in caplog.records)


def test_build_token_validator_when_configured() -> None:
    factory = TokenFactory()
    validator = build_token_validator(
        config={ENV_TENANT_ID: FAKE_TENANT, ENV_AUDIENCE: "api://app"},
        key_provider=factory.key_provider(),
    )
    assert validator is not None


# --------------------------------------------------------------------------------------
# Role model — deny-by-default grant closure.
# --------------------------------------------------------------------------------------
def test_reader_grants_only_reader() -> None:
    principal = Principal(oid="o", roles=frozenset({Role.reader}))
    assert principal.grants(Role.reader)
    assert not principal.grants(Role.operator)
    assert not principal.grants(Role.admin)


def test_operator_grants_reader_and_operator() -> None:
    principal = Principal(oid="o", roles=frozenset({Role.operator}))
    assert principal.grants(Role.reader)
    assert principal.grants(Role.operator)
    assert not principal.grants(Role.admin)


def test_admin_grants_everything() -> None:
    principal = Principal(oid="o", roles=frozenset({Role.admin}))
    assert principal.grants(Role.reader)
    assert principal.grants(Role.operator)
    assert principal.grants(Role.admin)


def test_no_roles_grants_nothing() -> None:
    principal = Principal(oid="o", roles=frozenset())
    assert not principal.grants(Role.reader)
    assert not principal.grants(Role.operator)
    assert not principal.grants(Role.admin)


def test_roles_from_app_roles_ignores_unknown() -> None:
    assert roles_from_app_roles(["Workloads.Admin", "Nope"]) == frozenset({Role.admin})
    assert roles_from_app_roles([]) == frozenset()


def test_principal_is_frozen_and_closed() -> None:
    principal = Principal(oid="o", roles=frozenset({Role.reader}))
    with pytest.raises(ValidationError):  # frozen model — cannot mutate
        principal.oid = "other"  # type: ignore[misc]
    with pytest.raises(ValidationError):  # extra="forbid" — cannot smuggle a PII field
        Principal(oid="o", roles=frozenset(), email="x@y.z")  # type: ignore[call-arg]


# --------------------------------------------------------------------------------------
# JWKS provider — public-key construction, TTL cache, refresh-on-unknown-kid (no network).
# --------------------------------------------------------------------------------------
def test_jwk_to_public_key_roundtrips() -> None:
    factory = TokenFactory()
    jwk = factory.public_jwk()
    key = jwk_to_public_key(jwk)
    assert key.public_numbers() == factory.public_key.public_numbers()


def test_jwk_to_public_key_rejects_non_rsa() -> None:
    with pytest.raises(AuthenticationError):
        jwk_to_public_key({"kty": "EC", "kid": "x"})


def test_provider_resolves_key_via_injected_fetcher() -> None:
    factory = TokenFactory()
    jwk = factory.public_jwk()
    calls: list[str] = []

    def fetcher(uri: str) -> list[dict]:
        calls.append(uri)
        return [jwk]

    provider = JwksKeyProvider("https://keys/jwks", fetcher=fetcher)
    key = provider.get_key(jwk["kid"])
    assert key.public_numbers() == factory.public_key.public_numbers()
    assert calls == ["https://keys/jwks"]


def test_provider_refreshes_once_on_unknown_kid_then_fails_closed() -> None:
    factory = TokenFactory()
    jwk = factory.public_jwk()
    calls: list[str] = []

    def fetcher(uri: str) -> list[dict]:
        calls.append(uri)
        return [jwk]

    provider = JwksKeyProvider("https://keys/jwks", fetcher=fetcher)
    with pytest.raises(AuthenticationError) as exc:
        provider.get_key("kid-that-will-never-exist")
    assert str(exc.value) == "unknown_kid"
    # One initial fetch (stale cache) + one refresh forced by the unknown kid.
    assert len(calls) == 2


def test_provider_uses_ttl_cache_until_expiry() -> None:
    factory = TokenFactory()
    jwk = factory.public_jwk()
    calls: list[str] = []
    fake_time = [0.0]

    def fetcher(uri: str) -> list[dict]:
        calls.append(uri)
        return [jwk]

    provider = JwksKeyProvider(
        "https://keys/jwks", fetcher=fetcher, ttl_seconds=100.0, clock=lambda: fake_time[0]
    )
    provider.get_key(jwk["kid"])
    provider.get_key(jwk["kid"])  # within TTL — served from cache, no refetch
    assert len(calls) == 1
    fake_time[0] = 200.0  # advance past TTL
    provider.get_key(jwk["kid"])  # stale — refetch
    assert len(calls) == 2
