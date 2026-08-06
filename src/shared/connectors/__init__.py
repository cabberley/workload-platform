"""Shared, reusable base for read-only edge connectors.

Every edge connector (System Pulse, Azure Monitor, and future Kuiper/Citrix/F5 integrations) is
**read-only**, **keyless**, **fail-closed**, **bounded**, and free of any third-party/Azure SDK at
import time. Historically each connector duplicated the same edge machinery — a fetch envelope,
credential resolution, and a ``try/except`` that converts every failure into an unavailable result.

This package unifies that machinery into small, composable, fully-typed helpers so connectors stay
consistent and the only per-connector code is the actual transport at the edge:

* :class:`FetchResult` — the single shared fetch envelope (``available``/``raw``/``error``).
* :data:`TokenProvider` / :data:`CredentialProvider` — the keyless seams (injected Managed-Identity
  provider, or a Key Vault-backed env var **name**).
* :func:`resolve_bearer_token` — the exact credential-resolution order the connectors use.
* :func:`run_with_retries` — bounded retry with jitter, fully deterministic via injected
  ``sleep``/``rng`` (the one genuinely new capability).
* :func:`fail_closed` — converts *any* exception from an edge callable into an unavailable
  :class:`FetchResult` carrying the error **class name only**.

No Azure or vendor SDK is imported here; any SDK stays lazy inside a connector's edge method.
"""
from __future__ import annotations

from shared.connectors.base import (
    CredentialProvider,
    FailClosedObserver,
    FetchResult,
    SecretProvider,
    TokenProvider,
    fail_closed,
    resolve_bearer_token,
    run_with_retries,
)

__all__ = [
    "CredentialProvider",
    "FailClosedObserver",
    "FetchResult",
    "SecretProvider",
    "TokenProvider",
    "fail_closed",
    "resolve_bearer_token",
    "run_with_retries",
]
