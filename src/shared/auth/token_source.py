"""Keyless client-side seam for authenticating a first-party caller (the worker) TO the API.

The validator half of ``shared.auth`` proves an *incoming* token; this half lets a first-party
component *acquire* one to call the API, **keylessly**, using its own per-component Managed Identity
(issue #79) — never a shared secret. It mirrors the ``shared.connectors`` ``TokenProvider`` idiom:
an injected, callable seam so ``azure-identity`` / HTTP stay edge-only and unit tests are keyless
and network-free.

Resolution is driven by the SAME explicit auth mode as the server (:class:`AuthMode`): under
``disabled`` no token is attached (matching a server that is not enforcing); under ``required`` a
bearer for the API audience MUST be minted, and inability to mint **fails closed** (the caller must
not fall back to an unauthenticated request).
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Protocol, runtime_checkable

from shared.auth.config import AuthMode, build_auth_config, resolve_auth_mode
from shared.auth.errors import AuthConfigError

__all__ = [
    "AccessTokenLike",
    "ApiTokenProvider",
    "TokenCredentialLike",
    "build_api_token_provider",
    "default_api_scope",
    "managed_identity_token_provider",
]

# Returns a bearer token string, or raises to FAIL CLOSED — the worker must never send an
# unauthenticated request when auth is enabled, so this seam never returns an empty/None token.
ApiTokenProvider = Callable[[], str]


class AccessTokenLike(Protocol):
    """Structural shape of an ``azure.core.credentials.AccessToken`` — only ``.token`` is read."""

    token: str


@runtime_checkable
class TokenCredentialLike(Protocol):
    """Structural shape of an ``azure.core.credentials.TokenCredential`` (keyless).

    Modelled as a Protocol so this module needs no ``azure-identity`` import to be typed/tested — a
    fake credential is injected in tests; the real ``DefaultAzureCredential`` is constructed only in
    the composition path.
    """

    def get_token(self, *scopes: str) -> AccessTokenLike: ...


def default_api_scope(audience: str) -> str:
    """Build the OAuth2 client-credentials scope for the API audience (``<audience>/.default``).

    The audience is the API app registration's Application ID URI / client id (non-secret); the
    ``/.default`` scope requests the app roles assigned to the caller's identity.
    """
    return f"{audience.rstrip('/')}/.default"


def managed_identity_token_provider(
    scope: str, *, credential: TokenCredentialLike | None = None
) -> ApiTokenProvider:
    """Return a keyless :data:`ApiTokenProvider` minting a token for ``scope`` via Managed Identity.

    ``credential`` is injectable for tests; when omitted, ``azure.identity.DefaultAzureCredential``
    is imported **lazily** and constructed at call time (Managed Identity in Azure; the standard
    credential chain locally) — so importing this module never needs the Azure SDK and unit tests
    stay Azure-free. Fails closed: any failure to mint raises :class:`AuthConfigError` (class name
    only — never a token or SDK detail), so the caller aborts rather than sending an unauthenticated
    request.
    """

    def _acquire() -> str:
        active: TokenCredentialLike
        if credential is not None:
            active = credential
        else:
            try:
                from azure.identity import DefaultAzureCredential
            except ImportError as exc:  # pragma: no cover - azure-identity is a base dep in prod
                raise AuthConfigError("azure_identity_unavailable") from exc
            # DefaultAzureCredential.get_token has a broader (kwargs) signature but is structurally
            # compatible with our minimal read-only Protocol at runtime.
            active = DefaultAzureCredential()  # type: ignore[assignment]
        try:
            token = active.get_token(scope)
        except Exception as exc:  # noqa: BLE001 - fail closed, class name only (never a token/PII)
            raise AuthConfigError(f"token_acquisition_failed ({type(exc).__name__})") from exc
        return token.token

    return _acquire


def build_api_token_provider(
    config: Mapping[str, str] | None = None,
    *,
    credential: TokenCredentialLike | None = None,
) -> ApiTokenProvider | None:
    """Resolve the worker→API :data:`ApiTokenProvider` from env, or ``None`` when auth is disabled.

    Fail-closed, mode-driven (issue #64) — mirrors the server's
    :func:`shared.auth.build_token_validator`:

    * A **partial** config (one of tenant id / audience present, the other blank) ⇒
      :class:`AuthConfigError` in any mode (a misconfiguration must not silently disable auth).
    * :attr:`AuthMode.disabled` ⇒ ``None`` — the caller sends NO token, matching a server that is
      not enforcing (the deliberate local-dev / CI / test path).
    * :attr:`AuthMode.required` (the default) ⇒ a provider for ``<audience>/.default``. If the
      audience is unconfigured the worker cannot know who to authenticate to, so this raises
      :class:`AuthConfigError` (fail closed) rather than sending an unauthenticated request.

    ``credential`` is injected in tests to keep the flow keyless and network-free.
    """
    mode = resolve_auth_mode(config)
    auth_config = build_auth_config(config)  # raises on a partial config (fail closed)
    if mode is AuthMode.disabled:
        return None
    if auth_config is None:
        raise AuthConfigError("auth_required_but_unconfigured")
    scope = default_api_scope(auth_config.audience)
    return managed_identity_token_provider(scope, credential=credential)
