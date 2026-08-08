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

The :mod:`shared.connectors.edge` helpers add the two other pieces of edge machinery that
connectors used to re-derive — a credential-exfil-safe HTTPS endpoint validator
(:func:`validate_https_endpoint`), a streamed size/time-bounded JSON reader
(:func:`read_bounded_json`), and a generic fail-closed :class:`HttpEdgeClient` that runs the whole
fetch loop given a config and a pure payload transform. The load-balancer connectors added for
issue #49 (:mod:`shared.connectors.netscaler`, :mod:`shared.connectors.f5`) build on these plus the
pure, vendor-neutral transform layer in :mod:`shared.connectors.lb`.

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
from shared.connectors.edge import (
    DeadlineExceeded,
    EdgeEndpointError,
    EndpointNotApproved,
    HttpEdgeClient,
    HttpEdgeConfig,
    InvalidEndpoint,
    InvalidResponse,
    ResponseTooLarge,
    coerce_dict_list,
    read_bounded_json,
    validate_https_endpoint,
)

__all__ = [
    "CredentialProvider",
    "DeadlineExceeded",
    "EdgeEndpointError",
    "EndpointNotApproved",
    "FailClosedObserver",
    "FetchResult",
    "HttpEdgeClient",
    "HttpEdgeConfig",
    "InvalidEndpoint",
    "InvalidResponse",
    "ResponseTooLarge",
    "SecretProvider",
    "TokenProvider",
    "coerce_dict_list",
    "fail_closed",
    "read_bounded_json",
    "resolve_bearer_token",
    "run_with_retries",
    "validate_https_endpoint",
]
