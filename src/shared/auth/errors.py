"""Typed, PII-free auth errors — fail closed without ever leaking a token, claim, or PII.

Every failure in token validation or authorization raises one of these. Their messages carry ONLY
a generic, bounded reason (a short code) — NEVER the raw token, decoded claims, a principal name/
email, or any SDK/exception text — mirroring the connector ``FetchResult.error`` "class-name-only"
discipline (see ``shared.connectors.base``). The API translates :class:`AuthenticationError` to HTTP
401 and :class:`AuthorizationError` to HTTP 403; in neither case is the exception message widened
into a client body beyond a fixed, non-sensitive string.
"""
from __future__ import annotations

__all__ = [
    "AuthConfigError",
    "AuthError",
    "AuthenticationError",
    "AuthorizationError",
]


class AuthConfigError(Exception):
    """Raised (fail closed) when the API's auth configuration is missing or self-contradictory.

    This is a **startup / composition** error, deliberately NOT a subclass of :class:`AuthError` so
    it can never be caught by the per-request 401 handler and silently downgraded — a misconfigured
    deployment must **refuse to serve**, not run wide-open. Examples: ``WP_AUTH_MODE=required`` (the
    fail-closed default) with no tenant/audience configured; or a *partial* config (one of tenant
    id / audience present, the other blank) in any mode. Its message is a short, bounded reason code
    only — never a token, claim, secret, or PII.
    """


class AuthError(Exception):
    """Base class for every auth failure. Its ``str`` is a bounded, PII-free reason code only."""


class AuthenticationError(AuthError):
    """The bearer token is missing, malformed, expired, or fails signature/issuer/audience checks.

    Maps to HTTP 401. The message is a short, fixed reason (e.g. ``"expired"``, ``"bad_signature"``)
    — it never echoes the token, its claims, or principal PII, so a 401 surfaces without leaking.
    """


class AuthorizationError(AuthError):
    """A validly-authenticated principal lacks the role the requested action requires.

    Maps to HTTP 403. The message names only the required/most-privileged role code, never the
    principal id, name, or its actual roles.
    """
