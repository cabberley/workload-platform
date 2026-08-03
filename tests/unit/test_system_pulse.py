"""System Pulse connector — pure mapping + fail-closed/keyless edge (Azure- and network-free)."""
from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest

from modules.aiops.connectors.system_pulse import (
    REQUIRED_RAW_FIELDS,
    FetchResult,
    Signal,
    SignalMappingError,
    SignalSource,
    SystemPulseClient,
    SystemPulseConfig,
    TokenProvider,
    map_signal,
    to_signals,
    to_source_reference,
)


def _synthetic_raw(**overrides: object) -> dict[str, object]:
    """A clearly-fake System Pulse payload laden with PII-looking fields that must be dropped."""
    raw: dict[str, object] = {
        "metric": "odb_latency_ms",
        "value": 142.5,
        "unit": "ms",
        "timestamp": "2026-08-03T04:00:00Z",
        "resourceId": "/subscriptions/00000000/rg/epic/odb-01",
        # --- everything below is PII / free-text / body and must never survive the mapping ---
        "patient": "Jane Doe",
        "patientId": "MRN-123456",
        "user": "dr.smith",
        "userId": "u-42",
        "message": "chest pain, prescribed X",
        "body": {"note": "free text clinical note"},
        "freeText": "do not leak me",
        "note": "secret",
    }
    raw.update(overrides)
    return raw


# --------------------------------------------------------------------------------------
# Pure mapping + PII safety
# --------------------------------------------------------------------------------------
def test_map_signal_keeps_only_detection_fields() -> None:
    signal = map_signal(_synthetic_raw())
    assert signal.metric == "odb_latency_ms"
    assert signal.value == pytest.approx(142.5)
    assert signal.unit == "ms"
    assert signal.resourceId.endswith("odb-01")
    assert signal.source is SignalSource.system_pulse


def test_map_signal_drops_all_pii_and_free_text_fields() -> None:
    signal = map_signal(_synthetic_raw())
    dumped = signal.model_dump()
    assert set(dumped) == {"metric", "value", "unit", "timestamp", "resourceId", "source"}
    leaked = {"patient", "patientId", "user", "userId", "message", "body", "freeText", "note"}
    # No PII key survives, and no PII *value* is smuggled into any retained field.
    assert leaked.isdisjoint(dumped)
    haystack = " ".join(str(v) for v in dumped.values())
    for needle in ("Jane Doe", "MRN-123456", "dr.smith", "chest pain", "clinical note"):
        assert needle not in haystack


def test_signal_forbids_arbitrary_passthrough() -> None:
    with pytest.raises(ValueError):
        Signal(  # type: ignore[call-arg]
            metric="m",
            value=1.0,
            unit="ms",
            timestamp=datetime.now(UTC),
            resourceId="r",
            patient="leak",
        )


@pytest.mark.parametrize("missing", REQUIRED_RAW_FIELDS)
def test_map_signal_fails_closed_on_missing_field(missing: str) -> None:
    raw = _synthetic_raw()
    del raw[missing]
    with pytest.raises(SignalMappingError):
        map_signal(raw)


def test_map_signal_rejects_non_numeric_value() -> None:
    with pytest.raises(SignalMappingError):
        map_signal(_synthetic_raw(value="not-a-number"))


def test_map_signal_rejects_bool_value() -> None:
    with pytest.raises(SignalMappingError):
        map_signal(_synthetic_raw(value=True))


@pytest.mark.parametrize(
    "ts",
    [
        "2026-08-03T04:00:00Z",
        "2026-08-03T04:00:00+00:00",
        "2026-08-03T04:00:00",  # naive → assumed UTC
        1_754_193_600,  # epoch seconds
        1_754_193_600_000,  # epoch millis
        1_000_000_000_000,  # ms at the old 1e12 boundary (2001) — must not be read as seconds
    ],
)
def test_map_signal_normalizes_timestamp_to_utc(ts: object) -> None:
    signal = map_signal(_synthetic_raw(timestamp=ts))
    assert signal.timestamp.tzinfo is not None
    assert signal.timestamp.utcoffset() == UTC.utcoffset(None)


def test_epoch_seconds_and_millis_agree() -> None:
    secs = map_signal(_synthetic_raw(timestamp=1_754_193_600)).timestamp
    millis = map_signal(_synthetic_raw(timestamp=1_754_193_600_000)).timestamp
    assert secs == millis


def test_ms_boundary_value_maps_to_year_2001() -> None:
    signal = map_signal(_synthetic_raw(timestamp=1_000_000_000_000))
    assert signal.timestamp.year == 2001


@pytest.mark.parametrize("ts", [float("inf"), float("nan"), 1e30, -1e30])
def test_map_signal_drops_out_of_range_or_nonfinite_epoch(ts: float) -> None:
    # These must fail closed (raise SignalMappingError → dropped by to_signals), never crash.
    with pytest.raises(SignalMappingError):
        map_signal(_synthetic_raw(timestamp=ts))


def test_to_signals_drops_crashing_timestamp_without_raising() -> None:
    good = _synthetic_raw()
    bad = _synthetic_raw(timestamp=1e30)  # would crash datetime.fromtimestamp if unguarded
    signals = to_signals(FetchResult(available=True, raw=[good, bad]))
    assert len(signals) == 1


def test_map_signal_rejects_unparseable_timestamp() -> None:
    with pytest.raises(SignalMappingError):
        map_signal(_synthetic_raw(timestamp="yesterday"))


def test_to_source_reference_cites_metric_and_resource() -> None:
    ref = to_source_reference(map_signal(_synthetic_raw()))
    assert ref.kind == "metric"
    assert ref.id == "odb_latency_ms"
    assert ref.detail is not None and ref.detail.endswith("odb-01")


# --------------------------------------------------------------------------------------
# to_signals — fail-closed aggregation
# --------------------------------------------------------------------------------------
def test_to_signals_unavailable_yields_no_signals() -> None:
    assert to_signals(FetchResult(available=False)) == []


def test_to_signals_skips_unmappable_records() -> None:
    good = _synthetic_raw()
    bad = {"metric": "x"}  # missing required fields
    result = FetchResult(available=True, raw=[good, bad])
    signals = to_signals(result)
    assert len(signals) == 1
    assert signals[0].metric == "odb_latency_ms"


# --------------------------------------------------------------------------------------
# Network edge — httpx.MockTransport (no real network)
# --------------------------------------------------------------------------------------
def _raise_if_called(request: httpx.Request) -> httpx.Response:
    raise AssertionError("no HTTP request should have been made")


def _client_with(
    handler: httpx.MockTransport,
    *,
    credential_provider: TokenProvider | None = lambda: "fake-read-token",
) -> SystemPulseClient:
    config = SystemPulseConfig(base_url="https://pulse.internal")
    http_client = httpx.Client(transport=handler)
    return SystemPulseClient(config, client=http_client, credential_provider=credential_provider)


def test_fetch_raw_success_returns_available_result() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/metrics"
        return httpx.Response(200, json={"signals": [_synthetic_raw()]})

    client = _client_with(httpx.MockTransport(handle))
    result = client.fetch_raw()
    assert result.available is True
    assert len(result.raw) == 1
    assert to_signals(result)[0].metric == "odb_latency_ms"


def test_fetch_raw_fails_closed_on_http_error() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="unavailable")

    result = _client_with(httpx.MockTransport(handle)).fetch_raw()
    assert result.available is False
    assert result.raw == []
    assert result.error is not None


def test_fetch_raw_fails_closed_on_transport_error() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    result = _client_with(httpx.MockTransport(handle)).fetch_raw()
    assert result.available is False
    assert result.raw == []


# --------------------------------------------------------------------------------------
# Fail-closed observer seam (issue #60) — counts a real fail-closed fetch, keyless, module label
# --------------------------------------------------------------------------------------
def test_fetch_raw_fail_closed_fires_injected_observer() -> None:
    from shared.observability import (
        METRIC_CONNECTOR_FAIL_CLOSED,
        MetricsRegistry,
        connector_fail_closed_observer,
    )

    reg = MetricsRegistry()

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="unavailable")  # → raises → fail-closed conversion

    client = SystemPulseClient(
        SystemPulseConfig(base_url="https://pulse.internal"),
        client=httpx.Client(transport=httpx.MockTransport(handle)),
        credential_provider=lambda: "fake-read-token",
        fail_closed_observer=connector_fail_closed_observer("aiops", reg),
    )
    result = client.fetch_raw()
    assert result.available is False  # still fails closed
    fc = next(
        s for s in reg.snapshot().counters if s.name == METRIC_CONNECTOR_FAIL_CLOSED
    )
    assert fc.labels == {"module": "aiops"}  # bounded, low-cardinality label
    assert fc.value == 1


def test_fetch_raw_success_does_not_fire_observer() -> None:
    from shared.observability import MetricsRegistry, connector_fail_closed_observer

    reg = MetricsRegistry()

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"signals": [_synthetic_raw()]})

    client = SystemPulseClient(
        SystemPulseConfig(base_url="https://pulse.internal"),
        client=httpx.Client(transport=httpx.MockTransport(handle)),
        credential_provider=lambda: "fake-read-token",
        fail_closed_observer=connector_fail_closed_observer("aiops", reg),
    )
    assert client.fetch_raw().available is True
    assert reg.snapshot().counters == []  # observer fires ONLY on a fail-closed conversion


def test_fetch_raw_without_observer_still_fails_closed() -> None:
    # Default (no observer) must be a no-op that never breaks the connector's fail-closed behavior.
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="unavailable")

    result = _client_with(httpx.MockTransport(handle)).fetch_raw()
    assert result.available is False
    assert result.error is not None
@pytest.mark.parametrize(
    "payload",
    [
        {"unexpected": "shape"},
        [1, "bad"],
        {"signals": [1]},
        {"signals": [], "value": []},  # ambiguous multi-key envelope
        "not-json-shape",
    ],
)
def test_fetch_raw_fails_closed_on_malformed_payload(payload: object) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    result = _client_with(httpx.MockTransport(handle)).fetch_raw()
    assert result.available is False
    assert result.raw == []


@pytest.mark.parametrize("payload", [[], {"signals": []}])
def test_fetch_raw_legit_empty_is_available_with_no_signals(payload: object) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    result = _client_with(httpx.MockTransport(handle)).fetch_raw()
    assert result.available is True
    assert result.raw == []
    assert to_signals(result) == []


# --------------------------------------------------------------------------------------
# Auth resolution — never sends an unauthenticated request
# --------------------------------------------------------------------------------------
def test_no_credential_fails_closed_without_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SYSTEM_PULSE_READ_TOKEN", raising=False)
    # Transport would raise if any HTTP call were attempted.
    result = _client_with(
        httpx.MockTransport(_raise_if_called), credential_provider=None
    ).fetch_raw()
    assert result.available is False
    assert result.error == "NoCredential"


def test_injected_provider_becomes_bearer_header() -> None:
    token = "fake-read-token"
    seen: dict[str, str] = {}

    def handle(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, json=[])

    # Assert the REAL outgoing header, built at runtime (no literal that a masker could rewrite).
    _client_with(httpx.MockTransport(handle), credential_provider=lambda: token).fetch_raw()
    assert seen.get("authorization") == "Bearer" + " " + token
    assert token in seen.get("authorization", "")


def test_env_token_used_as_bearer_when_no_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    token = "env-read-token"
    monkeypatch.setenv("SYSTEM_PULSE_READ_TOKEN", token)
    seen: dict[str, str] = {}

    def handle(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, json=[])

    _client_with(httpx.MockTransport(handle), credential_provider=None).fetch_raw()
    assert seen.get("authorization") == "Bearer" + " " + token
    assert token in seen.get("authorization", "")


def test_provider_wins_over_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYSTEM_PULSE_READ_TOKEN", "env-read-token")
    token = "provider-token"
    seen: dict[str, str] = {}

    def handle(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, json=[])

    _client_with(httpx.MockTransport(handle), credential_provider=lambda: token).fetch_raw()
    assert seen.get("authorization") == "Bearer" + " " + token
    assert token in seen.get("authorization", "")


def test_failing_provider_fails_closed_without_leaking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SYSTEM_PULSE_READ_TOKEN", raising=False)

    def boom() -> str | None:
        raise RuntimeError("super-secret-token-value")

    result = _client_with(
        httpx.MockTransport(_raise_if_called), credential_provider=boom
    ).fetch_raw()
    assert result.available is False
    assert result.error == "RuntimeError"  # class name only — no message, no token

