"""Unit tests for the keyless Key Vault secret provider (issue #85).

Azure-free by construction: the Azure SDK is mocked (a fake ``SecretClient``) — no network, no
real vault, no credentials. Proves: resolve-via-provider, **fail closed** on a
missing/inaccessible/empty secret, and the **env-var fallback used ONLY when no vault is
configured**. No secret literals — only clearly-fake placeholder values and non-secret placeholder
URIs.
"""
from __future__ import annotations

import pytest

from shared.secret_provider import (
    ENV_KEY_VAULT_URI,
    KeyVaultSecretProvider,
    SecretProvider,
    SecretResolutionError,
    build_secret_provider,
    resolve_secret,
)

# A clearly-fake, non-secret placeholder vault URI (never a real endpoint or credential).
FAKE_VAULT_URI = "https://wp-vault.vault.azure.net"
# A clearly-fake placeholder secret VALUE — not a real credential (synthetic test fixture).
FAKE_TOKEN_VALUE = "fake-kv-resolved-token"  # noqa: S105 - synthetic test placeholder, not a secret


class _FakeSecret:
    def __init__(self, value: str | None) -> None:
        self.value = value


class _FakeSecretClient:
    """A ``SecretClient``-shaped stub — returns preconfigured values or raises like the real SDK."""

    def __init__(
        self, secrets: dict[str, str | None], *, raise_for: set[str] | None = None
    ) -> None:
        self._secrets = secrets
        self._raise_for = raise_for or set()
        self.calls: list[str] = []

    def get_secret(self, name: str) -> _FakeSecret:
        self.calls.append(name)
        if name in self._raise_for:
            raise RuntimeError("super-secret-error-message-must-not-leak")
        if name not in self._secrets:
            raise KeyError(name)  # stand-in for azure ResourceNotFoundError
        return _FakeSecret(self._secrets[name])


# --------------------------------------------------------------------------------------
# KeyVaultSecretProvider.get_secret — resolves, and fails closed on every bad path.
# --------------------------------------------------------------------------------------
def test_provider_resolves_secret_via_mocked_client() -> None:
    client = _FakeSecretClient({"system-pulse-read-token": FAKE_TOKEN_VALUE})
    provider = KeyVaultSecretProvider(FAKE_VAULT_URI, client=client)
    assert provider.get_secret("system-pulse-read-token") == FAKE_TOKEN_VALUE
    assert client.calls == ["system-pulse-read-token"]


def test_provider_is_structural_secret_provider() -> None:
    provider = KeyVaultSecretProvider(FAKE_VAULT_URI, client=_FakeSecretClient({}))
    assert isinstance(provider, SecretProvider)


def test_provider_fail_closed_on_missing_secret() -> None:
    provider = KeyVaultSecretProvider(FAKE_VAULT_URI, client=_FakeSecretClient({}))
    with pytest.raises(SecretResolutionError) as exc:
        provider.get_secret("system-pulse-read-token")
    # The secret NAME may appear (not sensitive); the fail must never return None/empty.
    assert "system-pulse-read-token" in str(exc.value)


def test_provider_fail_closed_on_empty_value() -> None:
    provider = KeyVaultSecretProvider(FAKE_VAULT_URI, client=_FakeSecretClient({"t": ""}))
    with pytest.raises(SecretResolutionError):
        provider.get_secret("t")


def test_provider_fail_closed_hides_sdk_error_message() -> None:
    # A raising SDK must fail closed WITHOUT leaking the underlying message (only the class name).
    client = _FakeSecretClient({}, raise_for={"t"})
    provider = KeyVaultSecretProvider(FAKE_VAULT_URI, client=client)
    with pytest.raises(SecretResolutionError) as exc:
        provider.get_secret("t")
    assert "super-secret-error-message-must-not-leak" not in str(exc.value)
    assert "RuntimeError" in str(exc.value)


def test_provider_requires_non_empty_uri() -> None:
    with pytest.raises(ValueError, match="vault URI"):
        KeyVaultSecretProvider("   ", client=_FakeSecretClient({}))


# --------------------------------------------------------------------------------------
# build_secret_provider — present only when a vault URI is configured.
# --------------------------------------------------------------------------------------
def test_build_secret_provider_none_without_uri() -> None:
    assert build_secret_provider(config={}) is None


def test_build_secret_provider_present_with_uri() -> None:
    provider = build_secret_provider(config={ENV_KEY_VAULT_URI: FAKE_VAULT_URI})
    assert isinstance(provider, KeyVaultSecretProvider)
    assert provider.vault_uri == FAKE_VAULT_URI


# --------------------------------------------------------------------------------------
# resolve_secret — Key Vault first (fail closed), env fallback ONLY when no vault configured.
# --------------------------------------------------------------------------------------
def test_resolve_secret_uses_key_vault_when_configured() -> None:
    provider = KeyVaultSecretProvider(
        FAKE_VAULT_URI, client=_FakeSecretClient({"the-name": FAKE_TOKEN_VALUE})
    )
    # The env value is present but MUST be ignored — a configured vault is authoritative.
    out = resolve_secret(
        provider, "the-name", "THE_ENV", config={"THE_ENV": "env-value-should-be-ignored"}
    )
    assert out == FAKE_TOKEN_VALUE


def test_resolve_secret_key_vault_configured_but_missing_fails_closed() -> None:
    provider = KeyVaultSecretProvider(FAKE_VAULT_URI, client=_FakeSecretClient({}))
    with pytest.raises(SecretResolutionError):
        resolve_secret(provider, "absent", "THE_ENV", config={"THE_ENV": "ignored"}, required=True)


def test_resolve_secret_env_fallback_only_when_no_vault() -> None:
    out = resolve_secret(None, "the-name", "THE_ENV", config={"THE_ENV": "env-value"})
    assert out == "env-value"


def test_resolve_secret_no_vault_optional_missing_returns_none() -> None:
    assert resolve_secret(None, "the-name", "THE_ENV", config={}) is None


def test_resolve_secret_no_vault_required_missing_fails_closed() -> None:
    with pytest.raises(SecretResolutionError):
        resolve_secret(None, "the-name", "THE_ENV", config={}, required=True)
