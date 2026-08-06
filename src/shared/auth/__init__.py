"""Keyless Entra (Azure AD) bearer-token validation + least-privilege RBAC for the API/console.

This package is a small, SDK-light, **keyless, fail-closed** auth seam:

* :mod:`shared.auth.config` — env-driven :class:`AuthConfig` + explicit :class:`AuthMode`. Auth is
  **fail-closed by default** (``WP_AUTH_MODE`` defaults to ``required``): a missing/blank config no
  longer means "no auth". :func:`build_auth_config` returns ``None`` only when fully unconfigured
  and raises :class:`~shared.auth.errors.AuthConfigError` on a partial config.
* :mod:`shared.auth.jwks` — the injectable JWKS edge (public keys only), TTL-cached, refresh-on-
  unknown-``kid``.
* :mod:`shared.auth.validator` — :class:`TokenValidator`: verifies the RS256 signature against the
  tenant's PUBLIC keys and the issuer/audience/exp/nbf claims, then extracts a non-PII
  :class:`Principal`.
* :mod:`shared.auth.roles` / :mod:`shared.auth.principal` — the Reader ⊂ Operator ⊂ Admin role model
  and deny-by-default grant closure.

:func:`build_token_validator` composes these into a ready validator, returns ``None`` ONLY when auth
is **explicitly disabled** (``WP_AUTH_MODE=disabled``), and raises
:class:`~shared.auth.errors.AuthConfigError` when ``required`` but unconfigured (or on any partial
config) so a misconfigured deployment refuses to serve rather than running wide-open.
"""
from __future__ import annotations

import logging
from collections.abc import Mapping

from shared.auth.config import (
    ENV_ALLOWED_ISSUERS,
    ENV_AUDIENCE,
    ENV_JWKS_URI,
    ENV_MODE,
    ENV_TENANT_ID,
    AuthConfig,
    AuthMode,
    build_auth_config,
    resolve_auth_mode,
)
from shared.auth.errors import (
    AuthConfigError,
    AuthenticationError,
    AuthError,
    AuthorizationError,
)
from shared.auth.jwks import (
    JwksFetcher,
    JwksKeyProvider,
    PublicKeyProvider,
    jwk_to_public_key,
)
from shared.auth.principal import Principal
from shared.auth.roles import (
    APP_ROLE_ADMIN,
    APP_ROLE_OPERATOR,
    APP_ROLE_READER,
    APP_ROLE_TO_ROLE,
    ROLE_GRANTS,
    Role,
    roles_from_app_roles,
)
from shared.auth.token_source import (
    ApiTokenProvider,
    TokenCredentialLike,
    build_api_token_provider,
    default_api_scope,
    managed_identity_token_provider,
)
from shared.auth.validator import TokenValidator

logger = logging.getLogger(__name__)

__all__ = [
    "APP_ROLE_ADMIN",
    "APP_ROLE_OPERATOR",
    "APP_ROLE_READER",
    "APP_ROLE_TO_ROLE",
    "ENV_ALLOWED_ISSUERS",
    "ENV_AUDIENCE",
    "ENV_JWKS_URI",
    "ENV_MODE",
    "ENV_TENANT_ID",
    "ROLE_GRANTS",
    "ApiTokenProvider",
    "AuthConfig",
    "AuthConfigError",
    "AuthError",
    "AuthMode",
    "AuthenticationError",
    "AuthorizationError",
    "JwksFetcher",
    "JwksKeyProvider",
    "Principal",
    "PublicKeyProvider",
    "Role",
    "TokenCredentialLike",
    "TokenValidator",
    "build_api_token_provider",
    "build_auth_config",
    "build_token_validator",
    "default_api_scope",
    "jwk_to_public_key",
    "managed_identity_token_provider",
    "resolve_auth_mode",
    "roles_from_app_roles",
]


def build_token_validator(
    *,
    config: Mapping[str, str] | None = None,
    key_provider: PublicKeyProvider | None = None,
) -> TokenValidator | None:
    """Build the keyless :class:`TokenValidator`, or ``None`` ONLY when auth is explicitly disabled.

    Fail-closed by default (issue #64) — the resolution is driven by the EXPLICIT
    :class:`~shared.auth.config.AuthMode`, not by mere presence/absence of config:

    * A **partial** config (one of tenant id / audience present, the other blank) ⇒
      :class:`~shared.auth.errors.AuthConfigError` in **any** mode (checked first) — a
      half-configured deployment must never silently disable auth.
    * :attr:`AuthMode.disabled` ⇒ ``None`` (the caller runs the documented no-auth local/dev/CI/test
      path). This is the ONLY way to get ``None``, and it emits a prominent startup warning.
    * :attr:`AuthMode.required` (the default when :data:`ENV_MODE` is unset) ⇒ a ready validator
      when configured, else :class:`~shared.auth.errors.AuthConfigError` (the API must refuse to
      serve rather than run wide-open).

    ``key_provider`` may be injected (tests); by default a TTL-cached :class:`JwksKeyProvider` over
    the tenant's public JWKS endpoint is built — public keys only, no secret.
    """
    mode = resolve_auth_mode(config)
    # Validate config shape FIRST so a partial config fails closed regardless of mode.
    auth_config = build_auth_config(config)
    if mode is AuthMode.disabled:
        logger.warning(
            "Entra auth is DISABLED via %s=disabled - the API is serving WITHOUT authentication; "
            "this is intended for local development / CI / tests only, never production.",
            ENV_MODE,
        )
        return None
    if auth_config is None:
        # mode=required but tenant id / audience are not configured: refuse to serve (fail closed).
        raise AuthConfigError("auth_required_but_unconfigured")
    provider = key_provider if key_provider is not None else JwksKeyProvider(auth_config.jwks_uri)
    return TokenValidator(auth_config, provider)
