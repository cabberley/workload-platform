"""Keyless runtime-secret resolution — Key Vault by Managed Identity, with a local-dev fallback.

Runtime configuration and connector bearer tokens (e.g. the System Pulse read token) must never be
embedded in code/config/packs. In Azure they live in **Azure Key Vault** and are read BY the
platform's Managed Identity at composition time — keyless from the operator's perspective
(guardrail #3). This module is the ONE place that talks to Key Vault:

* :class:`KeyVaultSecretProvider` resolves a named secret from a vault using
  ``DefaultAzureCredential`` (Managed Identity in Azure; the standard credential chain locally). The
  ``azure-keyvault-secrets`` / ``azure-identity`` imports are **guarded and lazy** (inside a
  method), so importing this module never requires an Azure SDK and ``mypy src`` stays clean.
* :func:`build_secret_provider` returns a provider **only** when a vault URI is configured
  (``$WP_KEY_VAULT_URI``); otherwise it returns ``None`` so the caller uses the documented
  local-development env-var fallback.
* :func:`resolve_secret` implements the resolution policy: **Key Vault by identity when a vault is
  configured, else the env-var fallback** — and **fails closed** (raises
  :class:`SecretResolutionError`) when a *required* secret cannot be resolved.

**Fail closed (guardrail #4).** When a vault IS configured, a required secret that is
missing/inaccessible raises rather than silently degrading to ``None`` — the composition root then
refuses to start. The env-var fallback path applies **only** when no vault URI is configured
(local dev / existing tests). No secret value is ever logged or placed in an exception message:
errors carry the secret **name** and the failing error **class name** only.
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:  # pragma: no cover - typing-only import, never needed at runtime
    from azure.keyvault.secrets import SecretClient

__all__ = [
    "ENV_KEY_VAULT_URI",
    "KeyVaultSecretProvider",
    "SecretProvider",
    "SecretResolutionError",
    "build_secret_provider",
    "resolve_secret",
]

# The env var *name* holding the Key Vault URI (a non-secret resource URL, e.g.
# ``https://my-vault.vault.azure.net``). Only the name lives in code (keyless); the value is
# supplied at runtime by the deploy (a non-secret env var) or the operator locally. When unset, the
# provider is absent and callers use the documented local-dev env-var fallback.
ENV_KEY_VAULT_URI = "WP_KEY_VAULT_URI"


class SecretResolutionError(RuntimeError):
    """Raised (fail closed) when a REQUIRED runtime secret cannot be resolved.

    Carries the secret **name** and, when relevant, the failing error **class name** only — never a
    secret value or an SDK error message — so a resolution failure surfaces without leaking
    anything.
    """


@runtime_checkable
class SecretProvider(Protocol):
    """Structural seam for a keyless runtime-secret resolver.

    ``get_secret`` returns the secret string, or raises :class:`SecretResolutionError` to **fail
    closed** when a configured vault cannot supply the named secret. Modelled as a Protocol so
    ``shared.connectors`` and the connectors stay free of any Azure SDK — they depend only on this
    shape, not on :class:`KeyVaultSecretProvider`.
    """

    def get_secret(self, name: str) -> str: ...


class KeyVaultSecretProvider:
    """Resolve secrets from Azure Key Vault, keyless via ``DefaultAzureCredential`` (guardrail #3).

    The ``azure-keyvault-secrets`` + ``azure-identity`` imports happen lazily inside
    :meth:`_client_or_build`, so constructing/importing this module never requires an Azure SDK. A
    ``SecretClient``-shaped ``client`` can be injected for tests (mock the SDK — never hit a real
    vault). :meth:`get_secret` **fails closed**: a missing/inaccessible secret raises
    :class:`SecretResolutionError` (secret name + error class only), never returns ``None``/empty.
    """

    def __init__(self, vault_uri: str, *, client: SecretClient | None = None) -> None:
        self._vault_uri = vault_uri.strip()
        if not self._vault_uri:
            # A provider must never be constructed without a vault URI — that ambiguity would blur
            # the "configured vs not configured" decision the fallback policy depends on.
            raise ValueError("KeyVaultSecretProvider requires a non-empty vault URI")
        self._client = client

    @property
    def vault_uri(self) -> str:
        return self._vault_uri

    def _client_or_build(self) -> SecretClient:
        """Return the injected client, or lazily build a keyless ``SecretClient`` (guarded import).

        The Azure SDK imports live here, inside the method, so importing this module needs no Azure
        package. Any construction failure raises :class:`SecretResolutionError` (class name only).
        """
        if self._client is not None:
            return self._client
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient
        except ImportError as exc:  # pragma: no cover - azure SDK is a base dep in prod
            raise SecretResolutionError(
                f"Key Vault SDK unavailable ({type(exc).__name__})"
            ) from exc
        try:
            credential = DefaultAzureCredential()
            self._client = SecretClient(vault_url=self._vault_uri, credential=credential)
        except Exception as exc:  # noqa: BLE001 - construction failure fails closed, class only
            raise SecretResolutionError(
                f"could not build Key Vault client ({type(exc).__name__})"
            ) from exc
        return self._client

    def get_secret(self, name: str) -> str:
        """Fetch ``name`` from Key Vault by identity, or fail closed.

        Raises :class:`SecretResolutionError` when the secret is missing, inaccessible, or has an
        empty value — never returns ``None``/empty. The raised error carries the secret **name** and
        the failing error **class name** only; the secret value and any SDK message are never
        surfaced or logged.
        """
        client = self._client_or_build()
        try:
            secret = client.get_secret(name)
        except Exception as exc:  # noqa: BLE001 - any KV failure fails closed, class name only
            raise SecretResolutionError(
                f"required secret {name!r} could not be read from Key Vault "
                f"({type(exc).__name__})"
            ) from exc
        value = getattr(secret, "value", None)
        if not value:
            raise SecretResolutionError(
                f"required secret {name!r} is empty or absent in Key Vault"
            )
        return value


def build_secret_provider(
    *, config: Mapping[str, str] | None = None
) -> KeyVaultSecretProvider | None:
    """Build the Key Vault secret provider, or ``None`` when no vault is configured.

    Returns a :class:`KeyVaultSecretProvider` when ``$WP_KEY_VAULT_URI`` is set (Azure/production),
    else ``None`` so callers use the documented **local-development** env-var fallback. ``config``
    defaults to ``os.environ``; tests pass an explicit mapping. Only the vault URI (a non-secret
    URL) is read here — no secret value.
    """
    cfg: Mapping[str, str] = config if config is not None else os.environ
    uri = (cfg.get(ENV_KEY_VAULT_URI) or "").strip()
    if not uri:
        return None
    return KeyVaultSecretProvider(uri)


def resolve_secret(
    provider: SecretProvider | None,
    secret_name: str,
    env_var: str,
    *,
    config: Mapping[str, str] | None = None,
    required: bool = False,
) -> str | None:
    """Resolve a runtime secret under the keyless policy — Key Vault first, env fallback second.

    Resolution order:

    * **Key Vault by identity** when ``provider`` is present (a vault IS configured):
      :meth:`SecretProvider.get_secret` returns the value or **fails closed** (raises
      :class:`SecretResolutionError`) on a missing/inaccessible secret. The env-var fallback is
      **not** consulted in this path — in Azure, secrets come from Key Vault.
    * **Local-development env-var fallback** when ``provider`` is ``None`` (no vault configured):
      read ``env_var`` from ``config`` (default ``os.environ``). This preserves existing local/CI
      workflows unchanged.

    When ``required`` is ``True`` and nothing resolves, raises :class:`SecretResolutionError` (fail
    closed). When ``required`` is ``False``, an unresolved secret returns ``None`` and the caller
    fails closed on its own (e.g. a connector makes no network call).
    """
    if provider is not None:
        # A configured vault is authoritative. get_secret already fails closed on missing.
        return provider.get_secret(secret_name)
    cfg: Mapping[str, str] = config if config is not None else os.environ
    env_value = cfg.get(env_var)
    if env_value:
        return env_value
    if required:
        raise SecretResolutionError(
            f"required secret is not available: no Key Vault configured "
            f"(${ENV_KEY_VAULT_URI} unset) and local-dev fallback ${env_var} is unset"
        )
    return None
