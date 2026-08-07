"""Shared HTTPS edge — endpoint credential-exfil safety + the generic fail-closed fetch loop.

All fixtures are obviously synthetic (fake hosts, zeroed ids, no PII). The network edge is driven
via ``httpx.MockTransport`` — never a real socket. This is the single canonical test of
:mod:`shared.connectors.edge`; the vendor connector tests only add their own pure ``parse_*`` and a
thin integration smoke test on top of this machinery.
"""
from __future__ import annotations

import gzip
import importlib
import sys
from typing import Any

import httpx
import pytest

from shared.connectors import TokenProvider
from shared.connectors.edge import (
    EndpointNotApproved,
    HttpEdgeClient,
    HttpEdgeConfig,
    InvalidEndpoint,
    coerce_dict_list,
    validate_https_endpoint,
)
from support.connectors import (
    MockLbTokenProvider,
    RecordingSleep,
    flaky_transport,
    raising_transport,
)

APPROVED_HOST = "lb.approved.test"
APPROVED_BASE_URL = f"https://{APPROVED_HOST}"
_PATH = "/mgmt/tm/ltm/pool"


def _config(**overrides: object) -> HttpEdgeConfig:
    base: dict[str, object] = {
        "base_url": APPROVED_BASE_URL,
        "signals_path": _PATH,
        "approved_hosts": (APPROVED_HOST,),
        "token_env": "LB_READ_TOKEN",
    }
    base.update(overrides)
    return HttpEdgeConfig(**base)  # type: ignore[arg-type]


def _echo(payload: Any) -> list[dict[str, Any]]:
    """Trivial transform: expect a JSON list of dicts and pass it through (for the edge tests)."""
    return [dict(item) for item in payload]


def _raise_if_called(request: httpx.Request) -> httpx.Response:
    raise AssertionError("no HTTP request should have been made")


def _client_with(
    transport: httpx.MockTransport,
    *,
    config: HttpEdgeConfig | None = None,
    credential_provider: TokenProvider | None = None,
    transform: Any = _echo,
    **kwargs: object,
) -> HttpEdgeClient:
    cfg = config or _config()
    provider = credential_provider if credential_provider is not None else MockLbTokenProvider()
    http_client = httpx.Client(transport=transport)
    return HttpEdgeClient(
        cfg, transform, client=http_client, credential_provider=provider, **kwargs  # type: ignore[arg-type]
    )


# --------------------------------------------------------------------------------------
# validate_https_endpoint — credential-exfil safety
# --------------------------------------------------------------------------------------
def test_validate_endpoint_accepts_approved_https() -> None:
    assert validate_https_endpoint(APPROVED_BASE_URL, _PATH, (APPROVED_HOST,)) == (
        f"{APPROVED_BASE_URL}{_PATH}"
    )


@pytest.mark.parametrize("url", [f"http://{APPROVED_HOST}", f"ftp://{APPROVED_HOST}", ""])
def test_validate_endpoint_rejects_non_https(url: str) -> None:
    with pytest.raises(InvalidEndpoint):
        validate_https_endpoint(url, "/x", (APPROVED_HOST,))


def test_validate_endpoint_rejects_userinfo() -> None:
    with pytest.raises(InvalidEndpoint, match="userinfo"):
        validate_https_endpoint(f"https://u:p@{APPROVED_HOST}", "/x", (APPROVED_HOST,))


@pytest.mark.parametrize("url", [f"{APPROVED_BASE_URL}?a=1", f"{APPROVED_BASE_URL}#frag"])
def test_validate_endpoint_rejects_query_or_fragment(url: str) -> None:
    with pytest.raises(InvalidEndpoint):
        validate_https_endpoint(url, "/x", (APPROVED_HOST,))


def test_validate_endpoint_rejects_explicit_port() -> None:
    with pytest.raises(InvalidEndpoint, match="port"):
        validate_https_endpoint(f"https://{APPROVED_HOST}:8443", "/x", (f"{APPROVED_HOST}:8443",))


@pytest.mark.parametrize(
    "host", ["127.0.0.1", "[::1]", "2130706433", "0x7f.0.0.1", "0177.0.0.1", "127.1"]
)
def test_validate_endpoint_rejects_ip_literal_hosts(host: str) -> None:
    with pytest.raises(InvalidEndpoint):
        validate_https_endpoint(f"https://{host}", "/x", (host,))


@pytest.mark.parametrize("host", ["localhost", "example.com", "placeholder", "bigip.local"])
def test_validate_endpoint_rejects_placeholder_host_even_if_allowlisted(host: str) -> None:
    with pytest.raises(InvalidEndpoint):
        validate_https_endpoint(f"https://{host}", "/x", (host,))


def test_validate_endpoint_rejects_host_not_on_allowlist() -> None:
    with pytest.raises(EndpointNotApproved):
        validate_https_endpoint(APPROVED_BASE_URL, "/x", ())


def test_validate_endpoint_trailing_dot_matches_approved_host() -> None:
    assert validate_https_endpoint(f"https://{APPROVED_HOST}.", _PATH, (APPROVED_HOST,)).startswith(
        APPROVED_BASE_URL
    )


def test_validate_endpoint_idn_host_returns_punycode_target() -> None:
    import idna

    idn = "bücher.example-lb.test"
    punycode = idna.encode(idn).decode("ascii")
    url = validate_https_endpoint(f"https://{idn}", _PATH, (punycode,))
    assert punycode in url


@pytest.mark.parametrize("bad_path", ["no-leading-slash", "/has space", "/has?query", "/has#frag"])
def test_validate_endpoint_rejects_unsafe_path(bad_path: str) -> None:
    with pytest.raises(InvalidEndpoint):
        validate_https_endpoint(APPROVED_BASE_URL, bad_path, (APPROVED_HOST,))


# --------------------------------------------------------------------------------------
# coerce_dict_list
# --------------------------------------------------------------------------------------
def test_coerce_dict_list_accepts_bare_list() -> None:
    assert coerce_dict_list([{"a": 1}], ("items",)) == [{"a": 1}]


def test_coerce_dict_list_accepts_single_key_envelope() -> None:
    assert coerce_dict_list({"items": [{"a": 1}]}, ("items", "value")) == [{"a": 1}]


@pytest.mark.parametrize(
    "payload",
    [{"items": [1, 2]}, {"items": "x"}, {"a": [], "b": []}, 42, {"unknown": []}],
)
def test_coerce_dict_list_rejects_bad_shapes(payload: object) -> None:
    with pytest.raises(Exception):  # noqa: B017 - InvalidResponse subclasses ValueError
        coerce_dict_list(payload, ("items", "value"))


# --------------------------------------------------------------------------------------
# HttpEdgeClient — the generic fail-closed fetch loop
# --------------------------------------------------------------------------------------
def test_fetch_raw_success_returns_transformed_records() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        assert request.url.path == _PATH
        return httpx.Response(200, json=[{"a": 1}])

    result = _client_with(httpx.MockTransport(handle)).fetch_raw()
    assert result.available is True
    assert result.raw == [{"a": 1}]


def test_fetch_raw_invalid_endpoint_fails_closed_without_resolving_credential() -> None:
    spy = MockLbTokenProvider()
    client = _client_with(
        httpx.MockTransport(_raise_if_called),
        config=_config(base_url="", approved_hosts=()),
        credential_provider=spy,
    )
    result = client.fetch_raw()
    assert result.available is False
    assert result.error == "InvalidEndpoint"
    assert spy.calls == 0


def test_fetch_raw_unapproved_host_fails_closed_without_credential() -> None:
    spy = MockLbTokenProvider()
    client = _client_with(
        httpx.MockTransport(_raise_if_called),
        config=_config(base_url="https://lb.evil.test", approved_hosts=(APPROVED_HOST,)),
        credential_provider=spy,
    )
    result = client.fetch_raw()
    assert result.available is False
    assert result.error == "EndpointNotApproved"
    assert spy.calls == 0


def test_fetch_raw_no_token_fails_closed_without_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LB_READ_TOKEN", raising=False)
    result = _client_with(
        httpx.MockTransport(_raise_if_called),
        credential_provider=MockLbTokenProvider(token=None),
    ).fetch_raw()
    assert result.available is False
    assert result.error == "NoCredential"


def test_fetch_raw_uses_env_fallback_when_no_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LB_READ_TOKEN", "fake-env-token")
    seen: dict[str, str] = {}

    def handle(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, json=[])

    http_client = httpx.Client(transport=httpx.MockTransport(handle))
    client = HttpEdgeClient(_config(), _echo, client=http_client)  # no provider ⇒ env fallback
    assert client.fetch_raw().available is True
    assert seen.get("authorization") == "Bearer fake-env-token"


def test_fetch_raw_sends_bearer_only_to_validated_endpoint() -> None:
    token = "fake-lb-read-token"
    seen: dict[str, str] = {}

    def handle(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, json=[])

    _client_with(
        httpx.MockTransport(handle), credential_provider=MockLbTokenProvider(token=token)
    ).fetch_raw()
    assert seen.get("authorization") == "Bearer" + " " + token


def test_fetch_raw_requests_identity_encoding() -> None:
    seen: dict[str, str] = {}

    def handle(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, json=[])

    _client_with(httpx.MockTransport(handle)).fetch_raw()
    assert seen.get("accept-encoding") == "identity"


def test_fetch_raw_fails_closed_on_http_error() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="unavailable")

    result = _client_with(httpx.MockTransport(handle)).fetch_raw()
    assert result.available is False
    assert result.raw == []
    assert result.error is not None


def test_fetch_raw_retries_transient_then_succeeds() -> None:
    transport = flaky_transport(httpx.ConnectError("boom"), fail_times=1, then_payload=[{"a": 1}])
    result = _client_with(transport, sleep=RecordingSleep()).fetch_raw()
    assert result.available is True
    assert result.raw == [{"a": 1}]


def test_fetch_raw_fails_closed_when_retries_exhausted() -> None:
    transport = raising_transport(httpx.ConnectError("boom"))
    result = _client_with(transport, config=_config(retries=2), sleep=RecordingSleep()).fetch_raw()
    assert result.available is False
    assert result.error == "ConnectError"


def test_fetch_raw_fails_closed_on_oversized_response() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[{"a": 1}])

    result = _client_with(
        httpx.MockTransport(handle), config=_config(max_response_bytes=1)
    ).fetch_raw()
    assert result.available is False
    assert result.error == "ResponseTooLarge"


def test_fetch_raw_aborts_oversized_streamed_body_without_buffering() -> None:
    yielded = {"chunks": 0}

    def handle(request: httpx.Request) -> httpx.Response:
        def gen() -> object:
            for _ in range(1000):
                yielded["chunks"] += 1
                yield b"x" * 1024

        return httpx.Response(200, content=gen())

    result = _client_with(
        httpx.MockTransport(handle), config=_config(max_response_bytes=4096)
    ).fetch_raw()
    assert result.available is False
    assert result.error == "ResponseTooLarge"
    assert yielded["chunks"] < 1000


def test_fetch_raw_rejects_compressed_body_without_decoding() -> None:
    huge_json = b'[{"a": "' + b"A" * (1024 * 1024) + b'"}]'
    compressed = gzip.compress(huge_json)
    assert len(compressed) < 4096

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Encoding": "gzip"}, content=compressed)

    result = _client_with(
        httpx.MockTransport(handle), config=_config(max_response_bytes=65_536)
    ).fetch_raw()
    assert result.available is False
    assert result.error == "InvalidResponse"


def test_fetch_raw_deadline_rejects_slow_but_successful_attempt() -> None:
    import time

    def handle(request: httpx.Request) -> httpx.Response:
        time.sleep(0.05)  # overrun the tiny deadline so the post-success check fails closed
        return httpx.Response(200, json=[{"a": 1}])

    result = _client_with(
        httpx.MockTransport(handle), config=_config(retries=1, max_elapsed_s=0.01)
    ).fetch_raw()
    assert result.available is False
    assert result.error == "DeadlineExceeded"


def test_fetch_raw_malformed_payload_fails_closed_not_retried() -> None:
    calls = {"n": 0}

    def handle(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={"not": "a list"})

    def _transform(payload: Any) -> list[dict[str, Any]]:
        return [dict(item) for item in payload]  # raises on a dict payload

    result = _client_with(
        httpx.MockTransport(handle), transform=_transform, config=_config(retries=3),
        sleep=RecordingSleep(),
    ).fetch_raw()
    assert result.available is False
    assert calls["n"] == 1  # a malformed payload is NOT transient — never retried


def test_failing_provider_fails_closed_without_leaking() -> None:
    def boom() -> str | None:
        raise RuntimeError("super-secret-token-value")

    result = _client_with(
        httpx.MockTransport(_raise_if_called), credential_provider=boom
    ).fetch_raw()
    assert result.available is False
    assert result.error == "RuntimeError"


def test_fetch_raw_fail_closed_fires_injected_observer() -> None:
    from shared.observability import (
        METRIC_CONNECTOR_FAIL_CLOSED,
        MetricsRegistry,
        connector_fail_closed_observer,
    )

    reg = MetricsRegistry()

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="unavailable")

    client = _client_with(
        httpx.MockTransport(handle),
        fail_closed_observer=connector_fail_closed_observer("aiops", reg),
    )
    assert client.fetch_raw().available is False
    fc = next(s for s in reg.snapshot().counters if s.name == METRIC_CONNECTOR_FAIL_CLOSED)
    assert fc.labels == {"module": "aiops"}
    assert fc.value == 1


def test_fetch_raw_success_does_not_fire_observer() -> None:
    from shared.observability import MetricsRegistry, connector_fail_closed_observer

    reg = MetricsRegistry()

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[])

    client = _client_with(
        httpx.MockTransport(handle),
        fail_closed_observer=connector_fail_closed_observer("aiops", reg),
    )
    assert client.fetch_raw().available is True
    assert reg.snapshot().counters == []


def test_importing_edge_does_not_import_httpx(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "httpx", None)
    for mod in ("shared.connectors.edge", "shared.connectors"):
        monkeypatch.delitem(sys.modules, mod, raising=False)
    reloaded = importlib.import_module("shared.connectors.edge")
    assert reloaded is not None
