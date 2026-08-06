"""Unit tests for the keyless Entra token validator (network-free, synthetic keys/tokens).

Every test signs a JWT with a locally-generated key and validates it through an injected public-key
provider — no real Entra, no HTTP, no secret. Covers the fail-closed matrix required by issue #64.
"""
from __future__ import annotations

import pytest

from shared.auth.errors import AuthenticationError
from shared.auth.roles import Role
from support.auth import (
    FAKE_AUDIENCE,
    FAKE_OID,
    TokenFactory,
    build_test_validator,
    fake_auth_config,
)


@pytest.fixture
def factory() -> TokenFactory:
    return TokenFactory()


def test_valid_token_is_accepted_and_yields_non_pii_principal(factory: TokenFactory) -> None:
    validator = build_test_validator(factory)
    token = factory.mint(roles=["Workloads.Operator"])
    principal = validator.validate(token)
    assert principal.oid == FAKE_OID
    assert principal.roles == frozenset({Role.operator})
    # A token without a `tid` claim yields a None tenant_id (resolved downstream — issue #65).
    assert principal.tenant_id is None
    # Non-PII by construction: the model only carries oid + roles + the non-PII tenant id
    # (no name/email/upn field).
    assert set(principal.model_dump().keys()) == {"oid", "roles", "tenant_id"}


def test_expired_token_is_rejected(factory: TokenFactory) -> None:
    validator = build_test_validator(factory)
    # Expired well beyond the leeway window.
    token = factory.mint(expires_in=-3600.0)
    with pytest.raises(AuthenticationError) as exc:
        validator.validate(token)
    assert str(exc.value) == "expired"


def test_not_yet_valid_token_is_rejected(factory: TokenFactory) -> None:
    validator = build_test_validator(factory)
    import time

    token = factory.mint(not_before=time.time() + 3600.0)
    with pytest.raises(AuthenticationError) as exc:
        validator.validate(token)
    assert str(exc.value) == "not_yet_valid"


def test_wrong_audience_is_rejected(factory: TokenFactory) -> None:
    validator = build_test_validator(factory)
    token = factory.mint(audience="api://some-other-app")
    with pytest.raises(AuthenticationError) as exc:
        validator.validate(token)
    assert str(exc.value) == "bad_audience"


def test_audience_list_containing_expected_is_accepted(factory: TokenFactory) -> None:
    validator = build_test_validator(factory)
    token = factory.mint(audience=["api://other", FAKE_AUDIENCE])
    principal = validator.validate(token)
    assert principal.oid == FAKE_OID


def test_wrong_issuer_is_rejected(factory: TokenFactory) -> None:
    validator = build_test_validator(factory)
    token = factory.mint(issuer="https://login.microsoftonline.com/evil/v2.0")
    with pytest.raises(AuthenticationError) as exc:
        validator.validate(token)
    assert str(exc.value) == "bad_issuer"


def test_bad_signature_is_rejected(factory: TokenFactory) -> None:
    validator = build_test_validator(factory)
    token = factory.mint(roles=["Workloads.Reader"])
    tampered = factory.tamper(token)
    with pytest.raises(AuthenticationError) as exc:
        validator.validate(tampered)
    assert str(exc.value) == "bad_signature"


def test_unknown_kid_is_rejected(factory: TokenFactory) -> None:
    validator = build_test_validator(factory)
    token = factory.mint(kid="some-rotated-away-kid")
    with pytest.raises(AuthenticationError) as exc:
        validator.validate(token)
    assert str(exc.value) == "unknown_kid"


def test_alg_none_downgrade_is_rejected(factory: TokenFactory) -> None:
    validator = build_test_validator(factory)
    # A non-empty (bogus) signature segment so the token survives structural parsing and the
    # explicit RS256 pin is what rejects the alg=none downgrade.
    token = factory.mint(alg="none")
    with pytest.raises(AuthenticationError) as exc:
        validator.validate(token)
    assert str(exc.value) == "unsupported_alg"


def test_alg_none_with_empty_signature_is_rejected(factory: TokenFactory) -> None:
    validator = build_test_validator(factory)
    token = factory.mint(alg="none", sign=False)
    with pytest.raises(AuthenticationError):
        validator.validate(token)


def test_hs256_confusion_is_rejected(factory: TokenFactory) -> None:
    validator = build_test_validator(factory)
    token = factory.mint(alg="HS256")
    with pytest.raises(AuthenticationError) as exc:
        validator.validate(token)
    assert str(exc.value) == "unsupported_alg"


def test_malformed_token_is_rejected(factory: TokenFactory) -> None:
    validator = build_test_validator(factory)
    with pytest.raises(AuthenticationError) as exc:
        validator.validate("not.a.jwt")
    assert str(exc.value) == "malformed_token"


def test_missing_oid_is_rejected(factory: TokenFactory) -> None:
    validator = build_test_validator(factory)
    token = factory.mint(oid=None, roles=["Workloads.Reader"])
    with pytest.raises(AuthenticationError) as exc:
        validator.validate(token)
    assert str(exc.value) == "missing_oid"


def test_unknown_app_roles_grant_nothing(factory: TokenFactory) -> None:
    validator = build_test_validator(factory)
    token = factory.mint(roles=["Some.Unmapped.Role"])
    principal = validator.validate(token)
    assert principal.roles == frozenset()
    # Deny-by-default: no recognized role satisfies even Reader.
    assert not principal.grants(Role.reader)


def test_no_roles_claim_yields_empty_roles(factory: TokenFactory) -> None:
    validator = build_test_validator(factory)
    token = factory.mint(roles=None)
    principal = validator.validate(token)
    assert principal.roles == frozenset()


def test_error_message_never_leaks_token_or_pii(factory: TokenFactory) -> None:
    """A validation failure must surface a short reason code — never the token or any claim."""
    validator = build_test_validator(factory)
    token = factory.mint(audience="api://leak-me", oid="secret-oid-should-not-appear")
    with pytest.raises(AuthenticationError) as exc:
        validator.validate(token)
    message = str(exc.value)
    assert token not in message
    assert "secret-oid-should-not-appear" not in message
    assert "leak-me" not in message
    assert message == "bad_audience"


def test_clock_skew_leeway_allows_recently_expired(factory: TokenFactory) -> None:
    # exp 30s in the past is within the default 60s leeway → still valid.
    validator = build_test_validator(factory)
    token = factory.mint(expires_in=-30.0)
    principal = validator.validate(token)
    assert principal.oid == FAKE_OID


def test_injected_clock_makes_time_checks_deterministic(factory: TokenFactory) -> None:
    fixed_now = 1_000_000.0
    config = fake_auth_config()
    validator = build_test_validator(factory, config=config, clock=lambda: fixed_now)
    # Token expires at fixed_now + 100, minted "at" fixed_now → valid under the frozen clock.
    token = factory.mint(now=fixed_now, expires_in=100.0)
    assert validator.validate(token).oid == FAKE_OID
    # And a token that already expired under the frozen clock is rejected.
    stale = factory.mint(now=fixed_now - 10_000.0, expires_in=100.0)
    with pytest.raises(AuthenticationError):
        validator.validate(stale)
