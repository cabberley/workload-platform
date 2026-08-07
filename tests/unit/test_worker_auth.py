"""Unit tests for the keyless worker→API bearer seam (issue #64 FIX 2) — network-free, Azure-free.

Proves the worker mints a bearer for the API audience via an INJECTED credential (mirroring the
``azure-identity`` edge) under ``WP_AUTH_MODE=required``, attaches NO header under ``disabled``, and
fails closed on a partial / unconfigured required config. No real Entra, no HTTP.
"""
from __future__ import annotations

import pytest

from cli import worker
from shared.auth.config import ENV_AUDIENCE, ENV_MODE, ENV_TENANT_ID
from shared.auth.errors import AuthConfigError
from shared.auth.token_source import (
    build_api_token_provider,
    default_api_scope,
    managed_identity_token_provider,
)

FAKE_TENANT = "00000000-0000-0000-0000-000000000000"
AUDIENCE = "api://aegis"


class _FakeAccessToken:
    def __init__(self, token: str) -> None:
        self.token = token


class _FakeCredential:
    """Structural stand-in for ``azure.identity.DefaultAzureCredential`` — keyless."""

    def __init__(self, token: str = "minted-token") -> None:
        self._token = token
        self.scopes: list[str] = []

    def get_token(self, *scopes: str) -> _FakeAccessToken:
        self.scopes.extend(scopes)
        return _FakeAccessToken(self._token)


class _FailingCredential:
    def get_token(self, *scopes: str) -> _FakeAccessToken:
        raise RuntimeError("imds unreachable")


class _CapturingResponse:
    def __init__(self, payload: object = None) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:  # pragma: no cover - trivial
        return None

    def json(self) -> object:
        return self._payload


class _CapturingClient:
    """Injected httpx-like client capturing the outgoing request without any network."""

    def __init__(self, get_payload: object = None) -> None:
        self.calls: list[dict[str, object]] = []
        self._get_payload = get_payload if get_payload is not None else []

    def post(self, url, *, json, headers, timeout) -> _CapturingResponse:  # noqa: A002
        self.calls.append({"url": url, "json": json, "headers": dict(headers), "timeout": timeout})
        return _CapturingResponse()

    def get(self, url, *, headers, timeout) -> _CapturingResponse:
        self.calls.append({"url": url, "headers": dict(headers), "timeout": timeout})
        return _CapturingResponse(self._get_payload)


# --------------------------------------------------------------------------------------
# default_api_scope
# --------------------------------------------------------------------------------------
def test_default_api_scope_appends_default() -> None:
    assert default_api_scope("api://aegis") == "api://aegis/.default"
    # Trailing slash is normalised so we never emit a double slash.
    assert default_api_scope("api://aegis/") == "api://aegis/.default"


# --------------------------------------------------------------------------------------
# managed_identity_token_provider — injected credential, fail closed.
# --------------------------------------------------------------------------------------
def test_managed_identity_provider_mints_via_injected_credential() -> None:
    cred = _FakeCredential(token="abc123")
    provider = managed_identity_token_provider("api://aegis/.default", credential=cred)
    assert provider() == "abc123"
    assert cred.scopes == ["api://aegis/.default"]


def test_managed_identity_provider_fails_closed_on_error() -> None:
    cred = _FailingCredential()
    provider = managed_identity_token_provider("api://aegis/.default", credential=cred)
    with pytest.raises(AuthConfigError):
        provider()


# --------------------------------------------------------------------------------------
# build_api_token_provider — same fail-closed mode semantics as the server.
# --------------------------------------------------------------------------------------
def test_provider_is_none_when_disabled() -> None:
    assert build_api_token_provider({ENV_MODE: "disabled"}) is None


def test_provider_built_when_required_and_configured() -> None:
    cred = _FakeCredential(token="tok")
    provider = build_api_token_provider(
        {ENV_MODE: "required", ENV_TENANT_ID: FAKE_TENANT, ENV_AUDIENCE: AUDIENCE},
        credential=cred,
    )
    assert provider is not None
    assert provider() == "tok"
    assert cred.scopes == [f"{AUDIENCE}/.default"]


def test_provider_required_but_unconfigured_fails_closed() -> None:
    with pytest.raises(AuthConfigError):
        build_api_token_provider({ENV_MODE: "required"})
    # Default mode is required, so an empty config also fails closed.
    with pytest.raises(AuthConfigError):
        build_api_token_provider({})


def test_provider_partial_config_fails_closed() -> None:
    with pytest.raises(AuthConfigError):
        build_api_token_provider({ENV_MODE: "required", ENV_TENANT_ID: FAKE_TENANT})


# --------------------------------------------------------------------------------------
# worker._submit_result — attaches Bearer only when a provider is present.
# --------------------------------------------------------------------------------------
def test_submit_attaches_bearer_when_provider_present() -> None:
    client = _CapturingClient()
    worker._submit_result(
        "http://api",
        "epic",
        {"module": "quality_checks", "ok": True},
        token_provider=lambda: "minted-token",
        client=client,
    )
    assert len(client.calls) == 1
    headers = client.calls[0]["headers"]
    assert headers["Authorization"] == "Bearer minted-token"
    assert client.calls[0]["url"] == "http://api/api/workloads/epic/results"


def test_submit_sends_no_auth_header_when_disabled() -> None:
    client = _CapturingClient()
    worker._submit_result(
        "http://api",
        "epic",
        {"module": "quality_checks", "ok": True},
        token_provider=None,
        client=client,
    )
    assert len(client.calls) == 1
    assert "Authorization" not in client.calls[0]["headers"]


# --------------------------------------------------------------------------------------
# worker._fetch_assigned_versions — the reader-protected assignment read is authenticated
# with the SAME keyless bearer (issue #64 FIX 2), so it is not denied under WP_AUTH_MODE=required.
# --------------------------------------------------------------------------------------
def test_fetch_attaches_bearer_when_provider_present() -> None:
    client = _CapturingClient(get_payload=[])
    result = worker._fetch_assigned_versions(
        "http://api",
        "epic",
        token_provider=lambda: "minted-token",
        client=client,
    )
    assert result == {}
    assert len(client.calls) == 1
    headers = client.calls[0]["headers"]
    assert headers["Authorization"] == "Bearer minted-token"
    assert client.calls[0]["url"] == "http://api/api/workloads/epic/pack-assignments"


def test_fetch_sends_no_auth_header_when_disabled() -> None:
    client = _CapturingClient(get_payload=[])
    result = worker._fetch_assigned_versions(
        "http://api",
        "epic",
        token_provider=None,
        client=client,
    )
    assert result == {}
    assert len(client.calls) == 1
    assert "Authorization" not in client.calls[0]["headers"]
