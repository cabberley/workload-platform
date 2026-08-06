"""Shared pytest configuration.

Fail-closed auth is the platform default (issue #64): with ``WP_AUTH_MODE`` unset the API's startup
guard would refuse to serve unless a tenant/audience is configured. The test suite has no real
Entra, so it **explicitly** selects the deliberate ``disabled`` auth mode here (the documented
local-dev / CI / test opt-out) — set before any app import/startup so the guard permits the
no-auth path. Tests that exercise enabled auth override the ``get_auth_validator`` dependency with
an injected, network-free validator; tests that assert the fail-closed startup behaviour opt into
``required`` mode via ``monkeypatch``.
"""
from __future__ import annotations

import os
import sys
from collections.abc import Iterator

import pytest

# Set before collection / any FastAPI startup. `setdefault` so an outer environment can override.
os.environ.setdefault("WP_AUTH_MODE", "disabled")


@pytest.fixture(autouse=True)
def _reset_auth_validator_cache() -> Iterator[None]:
    """Reset the API's process-wide auth-validator cache around each test.

    The validator is built once per process and memoised on ``api.app.main``; resetting it before
    and after each test keeps a test that opts into ``required`` mode from leaking a built (or
    refused) validator into unrelated tests. Only touches the module when it is already imported,
    so pure unit tests that never load the API are unaffected.
    """
    def _clear() -> None:
        module = sys.modules.get("api.app.main")
        if module is not None:
            module._auth_validator = None
            module._auth_validator_built = False

    _clear()
    yield
    _clear()
