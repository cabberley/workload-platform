"""Composable primitives shared by every read-only edge connector.

Kept deliberately small and connector-agnostic: no HTTP client, no Azure/vendor SDK, no connector
specifics. Connectors compose these helpers around their own transport at the edge.
"""
from __future__ import annotations

import os
import random
import time
from collections.abc import Callable
from contextlib import suppress
from typing import Any, TypeVar

from pydantic import BaseModel, ConfigDict, Field

_T = TypeVar("_T")

# The keyless credential seams. A ``TokenProvider`` mints a bearer *token string* (e.g. a closure
# over ``DefaultAzureCredential(...).get_token(...).token``); a ``CredentialProvider`` mints a
# keyless credential *object* (e.g. a ``TokenCredential``) handed straight to a vendor SDK. Both
# are injected callables so ``azure-identity`` / vendor SDKs stay edge-only and tests stay Azure-
# free. Either returns ``None`` when it cannot mint a credential — the connector then fails closed.
TokenProvider = Callable[[], str | None]
CredentialProvider = Callable[[], object | None]

# An injectable, keyless observer seam for connector fail-closed events (issue #60). A zero-arg
# callback the composition root/API can wire (e.g. ``lambda: metrics.record_connector_fail_closed(
# "aiops")``) so a connector failing closed can be *counted* WITHOUT the connector importing the
# metrics registry or any module reaching into another. Default ``None`` ⇒ no-op (nothing observed,
# no dependency added). It carries NO data — only the fact that a fail-closed conversion happened —
# so no body, token, or PII can ride along.
FailClosedObserver = Callable[[], None]


class FetchResult(BaseModel):
    """Result of a connector's network edge. ``available=False`` ⇒ fail closed (no data).

    This is the single shared fetch envelope for every connector. ``error`` carries the error
    **class** name only — never a response body, message, or token — so a failure surfaces without
    leaking anything across the boundary.
    """

    model_config = ConfigDict(extra="forbid")

    available: bool
    raw: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = Field(
        default=None, description="Error *class* name only; never a body or token"
    )


def resolve_bearer_token(provider: TokenProvider | None, token_env: str) -> str | None:
    """Resolve a bearer token in the connectors' canonical order — pure but for one env read.

    Order: (a) an injected ``provider`` (e.g. Managed Identity) wins if it returns a truthy token;
    (b) else a Key Vault-backed token from ``os.environ[token_env]`` (the env holds the *name*, the
    value is the secret injected at runtime); (c) else ``None`` → the caller fails closed and makes
    no network call. The token is only ever returned to the immediate caller — never logged.

    A raising ``provider`` propagates; callers guard it (via :func:`fail_closed`) and fail closed.
    """
    if provider is not None:
        token = provider()
        if token:
            return token
    env_token = os.environ.get(token_env)
    if env_token:
        return env_token
    return None


def run_with_retries(
    fn: Callable[[], _T],
    *,
    attempts: int,
    base_delay_s: float,
    max_delay_s: float,
    sleep: Callable[[float], None] = time.sleep,
    rng: random.Random | None = None,
    retry_on: Callable[[BaseException], bool] = lambda _exc: True,
) -> _T:
    """Run ``fn`` up to ``attempts`` times, retrying only on ``retry_on`` exceptions.

    Between attempts it sleeps a **full-jitter** backoff uniformly in
    ``[0, min(max_delay_s, base_delay_s * 2 ** (n - 1)))`` — i.e.
    ``min(max_delay_s, base_delay_s * 2 ** (n - 1)) * rng.random()`` where ``n`` is the 1-based
    attempt just completed and ``rng.random()`` ∈ ``[0, 1)``. This is exponential backoff capped at
    ``max_delay_s``; because the jitter multiplier is strictly ``< 1`` the sleep never exceeds the
    cap. It re-raises immediately if ``retry_on`` returns ``False`` for a raised exception, and
    re-raises the last exception once ``attempts`` is exhausted.

    ``sleep`` and ``rng`` are injected so the schedule is fully deterministic and tests never sleep
    for real; both default to the real ``time.sleep`` / a fresh ``random.Random`` in production.
    """
    if attempts < 1:
        raise ValueError("attempts must be >= 1")
    # Jitter only — never used for anything cryptographic, so the default PRNG is fine.
    active_rng = rng if rng is not None else random.Random()  # noqa: S311 - backoff jitter, not crypto
    # Grow the delay iteratively and saturate at ``max_delay_s`` so a large ``attempts`` never
    # computes an unbounded ``2 ** (n - 1)`` power (which would raise OverflowError and mask the
    # real exception). This yields the same capped-exponential schedule as
    # ``min(max_delay_s, base_delay_s * 2 ** (n - 1))``.
    delay = base_delay_s
    for n in range(1, attempts + 1):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - bounded retry decides via retry_on, then re-raises
            if n >= attempts or not retry_on(exc):
                raise
            capped = min(max_delay_s, delay)
            sleep(capped * active_rng.random())
            delay = min(max_delay_s, delay * 2)
    raise AssertionError("unreachable: run_with_retries exited without return or raise")


def fail_closed(
    fn: Callable[[], FetchResult], *, observer: FailClosedObserver | None = None
) -> FetchResult:
    """Run an edge callable, converting **any** exception into a fail-closed :class:`FetchResult`.

    A successful call is passed through unchanged (including a deliberate ``available=False``
    result, e.g. the no-credential case). Any raised exception becomes
    ``FetchResult(available=False, error=type(exc).__name__)`` — the error **class name only**, so
    no body, message, or token ever crosses the boundary. This is the single home for the
    ``except Exception`` block both connectors used to duplicate.

    ``observer`` is an optional, injectable seam (issue #60): when a fail-closed conversion happens
    it is invoked so the event can be *counted* (e.g. a metrics counter) without this shared base
    importing any registry or module. It is guarded so a broken observer never turns a fail-closed
    edge into a crash. Default ``None`` ⇒ no-op.
    """
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - every edge failure must fail closed, class name only
        if observer is not None:
            with suppress(Exception):  # observing must never break the fail-closed path
                observer()
        return FetchResult(available=False, error=type(exc).__name__)
