"""Unit tests for the shared connector base (issue #45).

Covers the credential resolver, the bounded retry-with-jitter helper (fully deterministic — it
never sleeps for real), the fail-closed wrapper, and confirmation that both existing connectors now
retry transient failures while still failing closed. Uses the synthetic-payload harness in
``tests/support/connectors.py`` — no PII/PHI, no secrets, no network.
"""
from __future__ import annotations

import random

import httpx
import pytest

from modules.aiops.connectors.azure_monitor import AzureMonitorClient, AzureMonitorConfig
from modules.aiops.connectors.azure_monitor import to_signals as am_to_signals
from modules.aiops.connectors.system_pulse import (
    SystemPulseClient,
    SystemPulseConfig,
    _coerce_raw_list,
)
from modules.aiops.connectors.system_pulse import (
    to_signals as sp_to_signals,
)
from shared.connectors import (
    FetchResult,
    fail_closed,
    resolve_bearer_token,
    run_with_retries,
)
from support.connectors import (
    FAKE_METRIC,
    FAKE_RESOURCE_ID,
    FakeMetricsBackend,
    FlakyMetricsBackend,
    RecordingSleep,
    flaky_transport,
    make_fetch_result,
    synthetic_metrics_payload,
    synthetic_signal_raw,
)

_TOKEN_ENV = "CONNECTOR_BASE_TEST_TOKEN"


# --------------------------------------------------------------------------------------
# resolve_bearer_token — all three branches
# --------------------------------------------------------------------------------------
def test_resolve_bearer_token_injected_provider_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_TOKEN_ENV, "env-token")
    assert resolve_bearer_token(lambda: "provider-token", _TOKEN_ENV) == "provider-token"


def test_resolve_bearer_token_falls_back_to_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_TOKEN_ENV, "env-token")
    assert resolve_bearer_token(None, _TOKEN_ENV) == "env-token"
    # A provider that returns falsy also falls back to the Key Vault-backed env var.
    assert resolve_bearer_token(lambda: None, _TOKEN_ENV) == "env-token"
    assert resolve_bearer_token(lambda: "", _TOKEN_ENV) == "env-token"


def test_resolve_bearer_token_none_when_nothing_resolves(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(_TOKEN_ENV, raising=False)
    assert resolve_bearer_token(None, _TOKEN_ENV) is None
    assert resolve_bearer_token(lambda: None, _TOKEN_ENV) is None


# --------------------------------------------------------------------------------------
# run_with_retries — deterministic, never sleeps for real
# --------------------------------------------------------------------------------------
def test_run_with_retries_succeeds_first_try_without_sleeping() -> None:
    sleep = RecordingSleep()
    out = run_with_retries(
        lambda: 42, attempts=3, base_delay_s=1.0, max_delay_s=1.0,
        sleep=sleep, rng=random.Random(0),
    )
    assert out == 42
    assert sleep.calls == []


def test_run_with_retries_succeeds_after_n_failures() -> None:
    sleep = RecordingSleep()
    seen = {"n": 0}

    def fn() -> str:
        seen["n"] += 1
        if seen["n"] < 3:
            raise ConnectionError("transient")
        return "ok"

    out = run_with_retries(
        fn, attempts=5, base_delay_s=0.01, max_delay_s=0.1, sleep=sleep, rng=random.Random(0)
    )
    assert out == "ok"
    assert seen["n"] == 3
    assert len(sleep.calls) == 2  # two backoffs before the third attempt succeeds


def test_run_with_retries_exhausts_and_reraises_last() -> None:
    sleep = RecordingSleep()

    def fn() -> None:
        raise ConnectionError("last")

    with pytest.raises(ConnectionError, match="last"):
        run_with_retries(
            fn, attempts=3, base_delay_s=0.01, max_delay_s=0.1, sleep=sleep, rng=random.Random(0)
        )
    assert len(sleep.calls) == 2  # attempts - 1 backoffs


def test_run_with_retries_only_retries_configured_exceptions() -> None:
    sleep = RecordingSleep()
    seen = {"n": 0}

    def fn() -> None:
        seen["n"] += 1
        raise ValueError("not retryable")

    with pytest.raises(ValueError, match="not retryable"):
        run_with_retries(
            fn, attempts=3, base_delay_s=0.01, max_delay_s=0.1,
            sleep=sleep, rng=random.Random(0),
            retry_on=lambda exc: isinstance(exc, ConnectionError),
        )
    assert seen["n"] == 1  # not retried
    assert sleep.calls == []


def test_run_with_retries_deterministic_backoff_schedule() -> None:
    sleep = RecordingSleep()

    def fn() -> None:
        raise ConnectionError("boom")

    with pytest.raises(ConnectionError):
        run_with_retries(
            fn, attempts=4, base_delay_s=0.5, max_delay_s=100.0,
            sleep=sleep, rng=random.Random(1234),
        )
    # Recompute the exact full-jitter schedule with the same seed and formula.
    expected_rng = random.Random(1234)
    expected = [
        min(100.0, 0.5 * (2 ** (n - 1))) * expected_rng.random()
        for n in range(1, 4)  # 3 backoffs between 4 attempts
    ]
    assert sleep.calls == expected
    # Full jitter stays within the (uncapped, here) per-attempt cap.
    assert all(sleep.calls[i] < min(100.0, 0.5 * (2 ** i)) for i in range(3))


def test_run_with_retries_honors_max_delay_cap() -> None:
    sleep = RecordingSleep()

    def fn() -> None:
        raise TimeoutError()

    with pytest.raises(TimeoutError):
        run_with_retries(
            fn, attempts=5, base_delay_s=1000.0, max_delay_s=5.0,
            sleep=sleep, rng=random.Random(7),
        )
    # Uncapped backoff (1000 * 2**n) would explode; the cap keeps the pre-jitter value at 5.0, and
    # full jitter (multiplier in [0, 1)) means every recorded sleep is in [0.0, 5.0) — never above
    # the cap.
    assert len(sleep.calls) == 4
    assert all(0.0 <= s < 5.0 for s in sleep.calls)
    assert all(s <= 5.0 for s in sleep.calls)


def test_run_with_retries_large_attempts_no_overflow_reraises_original() -> None:
    # A large attempt count must not compute an unbounded 2**(n-1) power (OverflowError) and mask
    # the real exception — the iterative, saturating backoff attempts exactly `attempts` times and
    # re-raises the ORIGINAL error.
    sleep = RecordingSleep()
    seen = {"n": 0}
    sentinel = ConnectionError("original-transport-error")

    def fn() -> None:
        seen["n"] += 1
        raise sentinel

    with pytest.raises(ConnectionError) as excinfo:
        run_with_retries(
            fn, attempts=1100, base_delay_s=0.5, max_delay_s=2.0,
            sleep=sleep, rng=random.Random(0),
        )
    assert excinfo.value is sentinel  # the real error, not an OverflowError
    assert seen["n"] == 1100  # every attempt ran
    assert len(sleep.calls) == 1099  # attempts - 1 backoffs
    assert all(0.0 <= s <= 2.0 for s in sleep.calls)  # saturated at max_delay_s


def test_run_with_retries_rejects_non_positive_attempts() -> None:
    with pytest.raises(ValueError, match="attempts"):
        run_with_retries(lambda: 1, attempts=0, base_delay_s=0.1, max_delay_s=1.0)


# --------------------------------------------------------------------------------------
# fail_closed — passthrough success, convert exception to class-name error
# --------------------------------------------------------------------------------------
def test_fail_closed_passes_through_successful_result() -> None:
    good = make_fetch_result(available=True, raw=[synthetic_signal_raw()])
    assert fail_closed(lambda: good) is good


def test_fail_closed_passes_through_deliberate_unavailable() -> None:
    nocred = make_fetch_result(available=False, error="NoCredential")
    assert fail_closed(lambda: nocred) is nocred


def test_fail_closed_converts_exception_to_class_name_only() -> None:
    def boom() -> FetchResult:
        raise RuntimeError("super-secret-token-value")

    result = fail_closed(boom)
    assert result.available is False
    assert result.error == "RuntimeError"  # class name only — no message, no token
    assert result.raw == []


def test_fail_closed_observer_seam_counts_only_on_failure() -> None:
    # The injectable observer seam (#60) lets a fail-closed event be counted (e.g. a metrics
    # counter) without the shared base importing any registry. It fires ONLY on failure.
    calls: list[int] = []
    good = make_fetch_result(available=True, raw=[synthetic_signal_raw()])
    fail_closed(lambda: good, observer=lambda: calls.append(1))
    assert calls == []  # success ⇒ observer not invoked

    def boom() -> FetchResult:
        raise RuntimeError("boom")

    fail_closed(boom, observer=lambda: calls.append(1))
    assert calls == [1]  # failure ⇒ observed exactly once


def test_fail_closed_observer_error_never_breaks_fail_closed() -> None:
    def boom() -> FetchResult:
        raise RuntimeError("boom")

    def bad_observer() -> None:
        raise ValueError("observer blew up")

    # A broken observer must not turn a fail-closed edge into a crash.
    result = fail_closed(boom, observer=bad_observer)
    assert result.available is False
    assert result.error == "RuntimeError"


def test_fail_closed_observer_wires_to_metrics_registry() -> None:
    # End-to-end: the observer can bind the metrics helper for a bounded, PII-free counter.
    from shared.observability import METRIC_CONNECTOR_FAIL_CLOSED, MetricsRegistry

    reg = MetricsRegistry()

    def boom() -> FetchResult:
        raise RuntimeError("boom")

    fail_closed(boom, observer=lambda: reg.record_connector_fail_closed("aiops"))
    fc = next(
        s for s in reg.snapshot().counters if s.name == METRIC_CONNECTOR_FAIL_CLOSED
    )
    assert fc.labels == {"module": "aiops"}
    assert fc.value == 1


# --------------------------------------------------------------------------------------
# System Pulse — now retries transient transport errors, still fails closed
# --------------------------------------------------------------------------------------
def _sp_config(**overrides: object) -> SystemPulseConfig:
    base: dict[str, object] = {
        "base_url": "https://fake.internal",
        "retries": 3,
        "base_delay_s": 0.01,
        "max_delay_s": 0.1,
    }
    base.update(overrides)
    return SystemPulseConfig(**base)  # type: ignore[arg-type]


def test_system_pulse_retries_transient_then_succeeds() -> None:
    sleep = RecordingSleep()
    payload = {"signals": [synthetic_signal_raw()]}
    transport = flaky_transport(httpx.ConnectError("down"), fail_times=2, then_payload=payload)
    client = SystemPulseClient(
        _sp_config(),
        client=httpx.Client(transport=transport),
        credential_provider=lambda: "fake-token",
        sleep=sleep,
        rng=random.Random(0),
    )
    result = client.fetch_raw()
    assert result.available is True
    assert len(sp_to_signals(result)) == 1
    assert len(sleep.calls) == 2  # two retries before the third attempt succeeds


def test_system_pulse_always_transient_fails_closed_after_attempts() -> None:
    sleep = RecordingSleep()
    seen = {"n": 0}

    def handle(request: httpx.Request) -> httpx.Response:
        seen["n"] += 1
        raise httpx.ConnectError("down")

    client = SystemPulseClient(
        _sp_config(),
        client=httpx.Client(transport=httpx.MockTransport(handle)),
        credential_provider=lambda: "fake-token",
        sleep=sleep,
        rng=random.Random(0),
    )
    result = client.fetch_raw()
    assert result.available is False
    assert result.error == "ConnectError"
    assert seen["n"] == 3  # attempted exactly `retries` times
    assert len(sleep.calls) == 2


def test_system_pulse_http_status_error_is_not_retried() -> None:
    sleep = RecordingSleep()
    seen = {"n": 0}

    def handle(request: httpx.Request) -> httpx.Response:
        seen["n"] += 1
        return httpx.Response(503, text="unavailable")

    client = SystemPulseClient(
        _sp_config(),
        client=httpx.Client(transport=httpx.MockTransport(handle)),
        credential_provider=lambda: "fake-token",
        sleep=sleep,
        rng=random.Random(0),
    )
    result = client.fetch_raw()
    assert result.available is False
    assert seen["n"] == 1  # a 503 is not a transient transport error → no retry
    assert sleep.calls == []


# --------------------------------------------------------------------------------------
# System Pulse — envelope recognized by PRESENCE: ambiguous/malformed fails CLOSED
# --------------------------------------------------------------------------------------
def _sp_client_returning(payload: object) -> SystemPulseClient:
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    return SystemPulseClient(
        _sp_config(),
        client=httpx.Client(transport=httpx.MockTransport(handle)),
        credential_provider=lambda: "fake-token",
        sleep=RecordingSleep(),
        rng=random.Random(0),
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"signals": [], "value": "bad"},  # second recognized key present but not a list
        {"signals": [], "data": []},  # two recognized keys present → ambiguous
        {"value": "bad"},  # sole recognized key present but not a list
        {"unexpected": "shape"},  # no recognized key present
    ],
)
def test_system_pulse_ambiguous_or_malformed_payload_fails_closed(payload: object) -> None:
    result = _sp_client_returning(payload).fetch_raw()
    assert result.available is False
    assert result.raw == []


@pytest.mark.parametrize(
    "payload",
    [
        {"signals": [], "value": "bad"},
        {"signals": [], "data": []},
        {"value": "bad"},
        {"signals": [1]},  # recognized list, but a non-dict entry
    ],
)
def test_coerce_raw_list_raises_on_ambiguous_or_malformed(payload: object) -> None:
    with pytest.raises(ValueError):
        _coerce_raw_list(payload)


@pytest.mark.parametrize("payload", [{"signals": []}, {"value": []}, {"data": []}, []])
def test_coerce_raw_list_accepts_genuinely_empty_valid(payload: object) -> None:
    assert _coerce_raw_list(payload) == []


def test_system_pulse_genuinely_empty_envelope_is_available() -> None:
    result = _sp_client_returning({"signals": []}).fetch_raw()
    assert result.available is True
    assert result.raw == []
    assert sp_to_signals(result) == []


# --------------------------------------------------------------------------------------
# Azure Monitor — now retries transient backend errors, still fails closed
# --------------------------------------------------------------------------------------
def _am_config(**overrides: object) -> AzureMonitorConfig:
    base: dict[str, object] = {
        "resource_ids": [FAKE_RESOURCE_ID],
        "metric_names": [FAKE_METRIC],
        "retries": 3,
        "base_delay_s": 0.01,
        "max_delay_s": 0.1,
    }
    base.update(overrides)
    return AzureMonitorConfig(**base)  # type: ignore[arg-type]


def test_azure_monitor_retries_transient_then_succeeds() -> None:
    sleep = RecordingSleep()
    backend = FlakyMetricsBackend(
        ConnectionError("down"),
        fail_times=2,
        payloads=[synthetic_metrics_payload(values=(1.0,))],
    )
    client = AzureMonitorClient(
        _am_config(),
        credential_provider=lambda: object(),
        backend=backend,
        sleep=sleep,
        rng=random.Random(0),
    )
    result = client.fetch_raw()
    assert result.available is True
    assert len(am_to_signals(result)) == 1
    assert backend.calls == 3
    assert len(sleep.calls) == 2


def test_azure_monitor_always_transient_fails_closed_after_attempts() -> None:
    sleep = RecordingSleep()

    class AlwaysDown:
        def __init__(self) -> None:
            self.calls = 0

        def query_metrics(self, **_: object) -> list[dict[str, object]]:
            self.calls += 1
            raise ConnectionError("down")

    backend = AlwaysDown()
    client = AzureMonitorClient(
        _am_config(),
        credential_provider=lambda: object(),
        backend=backend,
        sleep=sleep,
        rng=random.Random(0),
    )
    result = client.fetch_raw()
    assert result.available is False
    assert result.error == "ConnectionError"
    assert backend.calls == 3
    assert len(sleep.calls) == 2


def test_azure_monitor_non_transient_error_is_not_retried() -> None:
    sleep = RecordingSleep()

    class Boom:
        def __init__(self) -> None:
            self.calls = 0

        def query_metrics(self, **_: object) -> list[dict[str, object]]:
            self.calls += 1
            raise RuntimeError("fatal")

    backend = Boom()
    client = AzureMonitorClient(
        _am_config(),
        credential_provider=lambda: object(),
        backend=backend,
        sleep=sleep,
        rng=random.Random(0),
    )
    result = client.fetch_raw()
    assert result.available is False
    assert result.error == "RuntimeError"
    assert backend.calls == 1  # RuntimeError is not transient → no retry
    assert sleep.calls == []


def test_azure_monitor_no_credential_makes_no_query_and_no_sleep() -> None:
    sleep = RecordingSleep()
    backend = FakeMetricsBackend([synthetic_metrics_payload()])
    client = AzureMonitorClient(
        _am_config(),
        credential_provider=lambda: None,  # no credential resolves
        backend=backend,
        sleep=sleep,
        rng=random.Random(0),
    )
    result = client.fetch_raw()
    assert result.available is False
    assert result.error == "NoCredential"
    assert backend.calls == 0  # no query attempted
    assert sleep.calls == []


# A fake azure-core-shaped hierarchy: an allowlisted transient base and a *subclass* whose own
# name is NOT in the allowlist. Retrying must key off the MRO, not the concrete class name.
class ServiceResponseError(Exception):
    """Stand-in for azure-core's allowlisted transient error (name matches the allowlist)."""


class ServiceResponseTimeoutError(ServiceResponseError):
    """A transient subclass whose own name is NOT in the allowlist — retryable via its MRO."""


def test_azure_monitor_retries_transient_error_subclass_via_mro() -> None:
    sleep = RecordingSleep()
    backend = FlakyMetricsBackend(
        ServiceResponseTimeoutError("transient timeout"),
        fail_times=2,
        payloads=[synthetic_metrics_payload(values=(1.0,))],
    )
    client = AzureMonitorClient(
        _am_config(),
        credential_provider=lambda: object(),
        backend=backend,
        sleep=sleep,
        rng=random.Random(0),
    )
    result = client.fetch_raw()
    assert result.available is True  # subclass of an allowlisted transient error → retried
    assert backend.calls == 3
    assert len(sleep.calls) == 2
