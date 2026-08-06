"""Config-driven Entra (Azure AD) auth settings — keyless, resolved from env like the rest of src.

Auth is **fail-closed by default** (issue #64). An EXPLICIT mode governs behaviour:
:func:`resolve_auth_mode` reads :data:`ENV_MODE` (``WP_AUTH_MODE``) and defaults to
:attr:`AuthMode.required` when unset — so a forgotten/blank deploy var can NEVER silently disable
authentication. Under ``required`` the tenant id + audience must be configured or the API refuses to
serve; ``disabled`` is the ONLY (deliberate, logged) way to run without auth for local dev / CI /
tests. :func:`build_auth_config` returns a populated :class:`AuthConfig` when configured, ``None``
when fully unconfigured, and raises :class:`~shared.auth.errors.AuthConfigError` on a *partial*
config (one of tenant/audience present, the other blank) in ANY mode. No new config mechanism is
introduced — only env-var *names* live in code (keyless); every value (all non-secret resource
identifiers / URLs — a tenant guid, an app-registration client id / Application ID URI, an issuer
URL, a JWKS URL) is supplied at runtime by the deploy or the operator locally. There is NO client
secret anywhere here: token *signature* verification uses the tenant's PUBLIC JWKS keys only.
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from shared.auth.errors import AuthConfigError

__all__ = [
    "ENV_ALLOWED_ISSUERS",
    "ENV_AUDIENCE",
    "ENV_JWKS_URI",
    "ENV_MODE",
    "ENV_TENANT_ID",
    "AuthConfig",
    "AuthMode",
    "build_auth_config",
    "resolve_auth_mode",
]

# Env var *names* only (keyless). The values are non-secret resource identifiers set at runtime.
ENV_TENANT_ID = "WP_AUTH_TENANT_ID"
# The expected token audience — the API app registration's Application ID URI or client id.
ENV_AUDIENCE = "WP_AUTH_AUDIENCE"
# Optional comma-separated override of the allowed issuer(s). When unset the canonical Entra v2.0
# issuer for the tenant is used. Never a secret — an issuer is a public URL.
ENV_ALLOWED_ISSUERS = "WP_AUTH_ALLOWED_ISSUERS"
# Optional override of the JWKS (public signing keys) endpoint. When unset the canonical Entra v2.0
# discovery keys URL for the tenant is used. Public keys only — no secret.
ENV_JWKS_URI = "WP_AUTH_JWKS_URI"
# The EXPLICIT auth mode (issue #64, fail-closed by default). `required` (the default when unset)
# means the API MUST authenticate every request and refuses to serve if unconfigured; `disabled`
# is the ONLY way to run without auth and is a deliberate local-dev / CI / test opt-out. A missing
# var therefore never means "no auth" — absence defaults to fail-closed `required`.
ENV_MODE = "WP_AUTH_MODE"

# Canonical Entra (Azure AD) v2.0 endpoints, templated on the tenant id. Public, non-secret.
_ISSUER_TEMPLATE = "https://login.microsoftonline.com/{tenant}/v2.0"
_JWKS_TEMPLATE = "https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"


class AuthMode(StrEnum):
    """How the API treats authentication. Fail-closed by default (``required``).

    * ``required`` — every request is authenticated (deny-by-default RBAC). The tenant id + audience
      MUST be configured or the API **refuses to serve** (fail closed). This is the default when
      :data:`ENV_MODE` is unset, so a forgotten deploy var can never silently disable auth.
    * ``disabled`` — the **only** way to run without auth: a deliberate, explicit opt-out for local
      development / CI / tests. Selecting it logs a prominent startup warning.
    """

    required = "required"
    disabled = "disabled"


@dataclass(frozen=True)
class AuthConfig:
    """Immutable, keyless Entra auth configuration (all fields are non-secret identifiers/URLs).

    * ``tenant_id`` — the Entra tenant (directory) guid.
    * ``audience`` — the expected ``aud`` claim: the API app registration's Application ID URI or
      client id. A token minted for any other audience is rejected (fail closed).
    * ``allowed_issuers`` — the accepted ``iss`` claim value(s). Defaults to the tenant's canonical
      v2.0 issuer; an operator may pin additional/alternate issuers via env.
    * ``jwks_uri`` — where the tenant's PUBLIC signing keys are published. Signature verification
      fetches these; there is no private key / client secret anywhere.
    """

    tenant_id: str
    audience: str
    allowed_issuers: tuple[str, ...]
    jwks_uri: str


def resolve_auth_mode(config: Mapping[str, str] | None = None) -> AuthMode:
    """Resolve the explicit :class:`AuthMode`, defaulting to fail-closed ``required``.

    An unset/blank :data:`ENV_MODE` defaults to :attr:`AuthMode.required` — absence of config never
    means "no auth". An unrecognized value fails closed with :class:`AuthConfigError` (a
    typo like ``WP_AUTH_MODE=off`` must not silently disable auth). ``config`` defaults to
    ``os.environ``; tests pass an explicit mapping.
    """
    cfg: Mapping[str, str] = config if config is not None else os.environ
    raw = (cfg.get(ENV_MODE) or "").strip().lower()
    if not raw:
        return AuthMode.required
    try:
        return AuthMode(raw)
    except ValueError as exc:
        # Reason code only — never echo arbitrary env content into the error.
        raise AuthConfigError("invalid_auth_mode") from exc


def build_auth_config(config: Mapping[str, str] | None = None) -> AuthConfig | None:
    """Build the Entra :class:`AuthConfig` from env, or ``None`` when auth is unconfigured.

    Fail-closed semantics (issue #64):

    * Both :data:`ENV_TENANT_ID` and :data:`ENV_AUDIENCE` present ⇒ a populated config.
    * Both absent ⇒ ``None`` (unconfigured — the caller decides what to do based on the mode; under
      the default ``required`` mode this is a startup error, under ``disabled`` it is the no-auth
      local path).
    * Exactly one present (a **partial/blank** config) ⇒ **always** :class:`AuthConfigError`,
      regardless of mode — a half-configured deployment is a misconfiguration that must never
      silently disable auth.

    ``config`` defaults to ``os.environ``; tests pass an explicit mapping. Only non-secret
    identifiers/URLs are read here. The issuer(s) and JWKS URL default to the tenant's canonical
    Entra v2.0 endpoints and may be overridden via :data:`ENV_ALLOWED_ISSUERS` /
    :data:`ENV_JWKS_URI`.
    """
    cfg: Mapping[str, str] = config if config is not None else os.environ
    tenant_id = (cfg.get(ENV_TENANT_ID) or "").strip()
    audience = (cfg.get(ENV_AUDIENCE) or "").strip()
    if bool(tenant_id) != bool(audience):
        # Reason code only — never echo the configured values.
        raise AuthConfigError("partial_auth_config")
    if not tenant_id:
        return None
    issuers_raw = (cfg.get(ENV_ALLOWED_ISSUERS) or "").strip()
    if issuers_raw:
        allowed_issuers = tuple(part.strip() for part in issuers_raw.split(",") if part.strip())
    else:
        allowed_issuers = (_ISSUER_TEMPLATE.format(tenant=tenant_id),)
    jwks_uri = (cfg.get(ENV_JWKS_URI) or "").strip() or _JWKS_TEMPLATE.format(tenant=tenant_id)
    return AuthConfig(
        tenant_id=tenant_id,
        audience=audience,
        allowed_issuers=allowed_issuers,
        jwks_uri=jwks_uri,
    )
