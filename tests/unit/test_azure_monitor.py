"""Azure Monitor connector tests — metrics + aggregated logs, keyless/fail-closed, Azure-free.

All fixtures are clearly-fake synthetic data (guardrail 2): obviously-fake resource ids, metric
names and payloads — no PII/PHI, no secrets, no network, no real Azure SDK. The logs path is
exercised end-to-end with injected fakes to prove it emits only aggregated numeric signals and
never a raw log body/row.
"""
from __future__ import annotations

import random
from typing import Any

import pytest

from cli.wiring import (
    ENV_AZURE_MONITOR_METRIC_NAMESPACE,
    ENV_AZURE_MONITOR_METRICS_ENDPOINT,
    ENV_AZURE_MONITOR_RESOURCE_IDS,
    ENV_AZURE_MONITOR_WORKSPACE_ID,
    build_client_registry,
)
from modules.aiops.connectors.azure_monitor import (
    _LOG_RECORD_FIELDS,
    AzureMonitorClient,
    AzureMonitorConfig,
    AzureMonitorSdkNotWired,
    UntrustedMetricsEndpoint,
    _kql_str_list,
    _kql_verbatim_literal,
    _logs_result_to_payload,
    _normalize_logs_response,
    _SdkLogsBackend,
    _SdkMetricsBackend,
    _validate_metrics_endpoint,
    build_logs_kql,
    map_logs_response,
    map_metrics_response,
)
from modules.aiops.connectors.azure_monitor import to_signals as am_to_signals
from modules.aiops.connectors.system_pulse import SignalMappingError, SignalSource
from support.connectors import (
    FAKE_METRIC,
    FAKE_RESOURCE_ID,
    FakeLogsBackend,
    FakeLogsPartialResult,
    FakeLogsSdkClient,
    FakeLogsSdkColumnTable,
    FakeLogsSdkResult,
    FakeMetricsBackend,
    FakeMetricsSdkClient,
    RaisingLogsBackend,
    RecordingSleep,
    make_fetch_result,
    synthetic_logs_payload,
    synthetic_metrics_payload,
)


def _cfg(**overrides: object) -> AzureMonitorConfig:
    base: dict[str, object] = {
        "resource_ids": [FAKE_RESOURCE_ID],
        "metric_names": [FAKE_METRIC],
        "retries": 3,
        "base_delay_s": 0.01,
        "max_delay_s": 0.1,
    }
    base.update(overrides)
    return AzureMonitorConfig(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------------------------
# Pure metrics mapping — provenance is Azure Monitor
# --------------------------------------------------------------------------------------
def test_map_metrics_response_stamps_azure_monitor_source() -> None:
    signals = map_metrics_response(synthetic_metrics_payload(values=(512.0, 540.0)))
    assert [s.value for s in signals] == [pytest.approx(512.0), pytest.approx(540.0)]
    assert all(s.source is SignalSource.azure_monitor for s in signals)


def test_map_metrics_response_drops_partial_points_without_fabricating() -> None:
    payload = {
        "resourceId": FAKE_RESOURCE_ID,
        "metrics": [
            {
                "name": FAKE_METRIC,
                "unit": "ms",
                "timeseries": [
                    {
                        "data": [
                            {"timeStamp": "2026-01-01T00:00:00Z", "average": 1.0},
                            {"timeStamp": "2026-01-01T00:01:00Z"},  # no aggregation → dropped
                            {"average": None},  # null aggregation → dropped
                        ]
                    }
                ],
            }
        ],
    }
    signals = map_metrics_response(payload)
    assert [s.value for s in signals] == [pytest.approx(1.0)]


@pytest.mark.parametrize("payload", [None, {}, {"metrics": "nope"}, {"metrics": [1, 2]}, 42])
def test_map_metrics_response_total_on_bad_shapes(payload: Any) -> None:
    assert map_metrics_response(payload) == []


# --------------------------------------------------------------------------------------
# Pure logs mapping — aggregated → Signal[], never a raw body
# --------------------------------------------------------------------------------------
def test_map_logs_response_maps_aggregated_records() -> None:
    signals = map_logs_response(synthetic_logs_payload(values=(12.5, 34.0)))
    assert [s.value for s in signals] == [pytest.approx(12.5), pytest.approx(34.0)]
    assert all(s.source is SignalSource.azure_monitor for s in signals)
    assert all(s.metric == FAKE_METRIC for s in signals)


def test_map_logs_response_never_emits_raw_body_fields() -> None:
    # A record that smuggles body/message/free-text columns: the mapper reads ONLY the allowlisted
    # aggregate/identifier fields, so no raw content can survive onto the Signal.
    payload = {
        "logRecords": [
            {
                "metric": FAKE_METRIC,
                "value": 7.0,
                "unit": "aggregated",
                "timestamp": "2026-01-01T00:00:00Z",
                "resourceId": FAKE_RESOURCE_ID,
                "Body": "raw clinical note — must never leak",
                "message": "chest pain",
                "RawData": {"note": "secret"},
            }
        ]
    }
    signals = map_logs_response(payload)
    assert len(signals) == 1
    dumped = signals[0].model_dump()
    assert set(dumped) == {"metric", "value", "unit", "timestamp", "resourceId", "source"}
    haystack = " ".join(str(v) for v in dumped.values())
    for needle in ("clinical note", "chest pain", "secret"):
        assert needle not in haystack


def test_map_logs_response_drops_malformed_records() -> None:
    payload = {
        "logRecords": [
            {"metric": FAKE_METRIC, "value": 1.0, "unit": "aggregated",
             "timestamp": "2026-01-01T00:00:00Z", "resourceId": FAKE_RESOURCE_ID},
            {"metric": FAKE_METRIC},  # missing required fields → dropped
            "not-a-dict",  # non-dict → dropped
            {"metric": FAKE_METRIC, "value": "NaNsense", "unit": "x",
             "timestamp": "2026-01-01T00:00:00Z", "resourceId": FAKE_RESOURCE_ID},  # bad value
        ]
    }
    signals = map_logs_response(payload)
    assert len(signals) == 1


@pytest.mark.parametrize("payload", [None, {}, {"logRecords": "nope"}, 42, []])
def test_map_logs_response_total_on_bad_shapes(payload: Any) -> None:
    assert map_logs_response(payload) == []


# --------------------------------------------------------------------------------------
# build_logs_kql — a bounded, aggregated, body-free transform
# --------------------------------------------------------------------------------------
def test_build_logs_kql_is_aggregated_and_bounded() -> None:
    kql = build_logs_kql(
        resource_ids=[FAKE_RESOURCE_ID],
        metric_names=[FAKE_METRIC],
        lookback_hours=1.0,
        bin_minutes=5,
    )
    # Aggregation only: summarize with numeric aggregates, grouped + binned.
    assert "summarize" in kql
    assert "avg(" in kql and "percentile(" in kql and "count()" in kql
    assert "bin(TimeGenerated, 5m)" in kql
    # Bounded to the configured resource id + metric + window.
    assert FAKE_RESOURCE_ID in kql
    assert FAKE_METRIC in kql
    assert "ago(1.0h)" in kql
    # The final projection selects ONLY identifier + numeric-aggregate columns — never a body.
    project = [line for line in kql.splitlines() if line.strip().startswith("| project")][0]
    for banned in ("Body", "Message", "RawData", "*"):
        assert banned not in project


def test_build_logs_kql_escapes_single_quotes() -> None:
    kql = build_logs_kql(
        resource_ids=["res'; drop"],
        metric_names=[],
        lookback_hours=1.0,
        bin_minutes=5,
    )
    assert "'res''; drop'" in kql  # single quote doubled, not left to break out of the literal


def test_build_logs_kql_omits_metric_filter_when_no_names() -> None:
    kql = build_logs_kql(
        resource_ids=[FAKE_RESOURCE_ID],
        metric_names=[],
        lookback_hours=2.0,
        bin_minutes=10,
    )
    assert "MetricName in~" not in kql


# --------------------------------------------------------------------------------------
# R2 HIGH — KQL injection via backslash: values render as VERBATIM literals, control chars rejected
# --------------------------------------------------------------------------------------
# The reviewer's working break-out payload: an ordinary literal would let `\'` escape the generated
# quote and the following `'` terminate the string, injecting an `| extend` that aliases raw
# Body/Message into the projected fields. A verbatim (@'...') literal makes backslash literal, so
# the only escape is `''` — the break-out is closed.
_INJECTION_RESOURCE_ID = (
    "safe\\') | extend Average=1.0, _ResourceId=tostring(Body), "
    "MetricName=tostring(Message), TimeGenerated=now() //"
)


def test_build_logs_kql_contains_injection_payload_only_inside_verbatim_literal() -> None:
    kql = build_logs_kql(
        resource_ids=[_INJECTION_RESOURCE_ID],
        metric_names=[],
        lookback_hours=1.0,
        bin_minutes=5,
    )
    lines = kql.splitlines()
    # The single-line payload adds NO extra pipeline lines: exactly the fixed 5-line shape.
    assert len(lines) == 5
    assert lines[0] == "AzureMetrics"
    assert lines[1] == "| where TimeGenerated > ago(1.0h)"
    # The whole payload sits inside ONE verbatim literal: starts with @', single quote doubled.
    assert lines[2].startswith("| where _ResourceId in~ (@'safe\\'')")
    assert "@'safe\\'') | extend" in kql  # the injected `| extend` is DATA inside the literal
    # The aggregation + projection are the fixed, uninjected shape.
    assert lines[3].startswith("| summarize value = avg(Average)")
    assert lines[4] == "| project resourceId, metric, value, count, timestamp"


def test_build_logs_kql_injection_via_metric_name_is_contained() -> None:
    kql = build_logs_kql(
        resource_ids=[],
        metric_names=[_INJECTION_RESOURCE_ID],
        lookback_hours=1.0,
        bin_minutes=5,
    )
    assert len(kql.splitlines()) == 5  # no injected pipeline lines
    assert "@'safe\\'') | extend" in kql
    assert kql.splitlines()[-1] == "| project resourceId, metric, value, count, timestamp"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("a'b", "@'a''b'"),  # single quote doubled
        ("a\\'b", "@'a\\''b'"),  # backslash stays literal, quote doubled — no break-out
        ("a\\\\'b", "@'a\\\\''b'"),  # double backslash + quote
        ("\\\\", "@'\\\\'"),  # bare backslashes, no quote
        ("a\\", "@'a\\'"),  # trailing backslash cannot terminate a verbatim literal
        (FAKE_RESOURCE_ID, f"@'{FAKE_RESOURCE_ID}'"),  # normal value renders unchanged
    ],
)
def test_kql_verbatim_literal_backslash_and_quote_combos(value: str, expected: str) -> None:
    assert _kql_verbatim_literal(value) == expected


def test_kql_str_list_renders_verbatim_list() -> None:
    assert _kql_str_list(["a", "b'c"]) == "(@'a', @'b''c')"


@pytest.mark.parametrize("bad", ["a\nb", "a\rb", "a\x00b", "tab\there", "\x1f"])
def test_kql_verbatim_literal_rejects_control_characters(bad: str) -> None:
    with pytest.raises(SignalMappingError):
        _kql_verbatim_literal(bad)


def test_build_logs_kql_fails_closed_on_control_char_value() -> None:
    # A newline in a value must fail closed (raise), never emit a broken multi-line literal.
    with pytest.raises(SignalMappingError):
        build_logs_kql(
            resource_ids=["good", "bad\nid | project Body"],
            metric_names=[],
            lookback_hours=1.0,
            bin_minutes=5,
        )


def test_kql_verbatim_literal_rejects_non_str() -> None:
    with pytest.raises(SignalMappingError):
        _kql_verbatim_literal(12345)  # type: ignore[arg-type]


# --------------------------------------------------------------------------------------
# _normalize_logs_response — keeps only allowlisted aggregate columns, drops body columns
# --------------------------------------------------------------------------------------
class _FakeTable:
    def __init__(self, columns: list[str], rows: list[list[Any]]) -> None:
        self.columns = columns
        self.rows = rows


class _FakeLogsResult:
    def __init__(self, tables: list[_FakeTable]) -> None:
        self.tables = tables


def test_normalize_logs_response_keeps_only_allowlisted_columns() -> None:
    # A table carrying an extra Body column — normalization must drop it, keeping only aggregates.
    table = _FakeTable(
        columns=["resourceId", "metric", "value", "count", "timestamp", "Body"],
        rows=[[FAKE_RESOURCE_ID, FAKE_METRIC, 3.0, 9, "2026-01-01T00:00:00Z", "raw log body"]],
    )
    payload = _normalize_logs_response(_FakeLogsResult([table]), allowed=_LOG_RECORD_FIELDS)
    assert list(payload) == ["logRecords"]
    record = payload["logRecords"][0]
    assert "Body" not in record
    assert record["resourceId"] == FAKE_RESOURCE_ID
    assert record["value"] == pytest.approx(3.0)
    # And the end-to-end mapping still yields exactly one clean signal with no body content.
    signals = map_logs_response(payload)
    assert len(signals) == 1
    assert "raw log body" not in " ".join(str(v) for v in signals[0].model_dump().values())


# --------------------------------------------------------------------------------------
# Logs edge — injected fake backend (no SDK, no network)
# --------------------------------------------------------------------------------------
def test_logs_edge_success_yields_azure_monitor_signals() -> None:
    backend = FakeLogsBackend([synthetic_logs_payload(values=(12.5,))])
    client = AzureMonitorClient(
        _cfg(resource_ids=[], workspace_id="ws-0000"),  # logs-only
        credential_provider=lambda: object(),
        logs_backend=backend,
    )
    result = client.fetch_raw()
    assert result.available is True
    signals = am_to_signals(result)
    assert len(signals) == 1
    assert signals[0].source is SignalSource.azure_monitor
    assert backend.calls == 1
    assert backend.last_kwargs["workspace_id"] == "ws-0000"


def test_logs_edge_no_credential_makes_no_query() -> None:
    backend = FakeLogsBackend([synthetic_logs_payload()])
    client = AzureMonitorClient(
        _cfg(resource_ids=[], workspace_id="ws-0000"),
        credential_provider=lambda: None,
        logs_backend=backend,
    )
    result = client.fetch_raw()
    assert result.available is False
    assert result.error == "NoCredential"
    assert backend.calls == 0


def test_logs_edge_backend_error_fails_closed_class_name_only() -> None:
    backend = RaisingLogsBackend(RuntimeError("super-secret-token-value"))
    client = AzureMonitorClient(
        _cfg(resource_ids=[], workspace_id="ws-0000"),
        credential_provider=lambda: object(),
        logs_backend=backend,
    )
    result = client.fetch_raw()
    assert result.available is False
    assert result.error == "RuntimeError"  # class name only — no message, no token


def test_logs_edge_malformed_backend_return_fails_closed() -> None:
    class _BadReturn:
        def query_logs(self, **_: Any) -> Any:
            return {"not": "a list"}  # violates the list-of-dicts contract

    client = AzureMonitorClient(
        _cfg(resource_ids=[], workspace_id="ws-0000"),
        credential_provider=lambda: object(),
        logs_backend=_BadReturn(),
    )
    result = client.fetch_raw()
    assert result.available is False
    assert result.error == "ValueError"


def test_logs_edge_transient_error_is_retried_then_fails_closed() -> None:
    sleep = RecordingSleep()

    class AlwaysDown:
        def __init__(self) -> None:
            self.calls = 0

        def query_logs(self, **_: Any) -> list[dict[str, Any]]:
            self.calls += 1
            raise ConnectionError("down")

    backend = AlwaysDown()
    client = AzureMonitorClient(
        _cfg(resource_ids=[], workspace_id="ws-0000"),
        credential_provider=lambda: object(),
        logs_backend=backend,
        sleep=sleep,
        rng=random.Random(0),
    )
    result = client.fetch_raw()
    assert result.available is False
    assert result.error == "ConnectionError"
    assert backend.calls == 3
    assert len(sleep.calls) == 2


# --------------------------------------------------------------------------------------
# Combined metrics + logs edges fuse into one fetch result
# --------------------------------------------------------------------------------------
def test_metrics_and_logs_edges_both_run_and_concatenate() -> None:
    metrics = FakeMetricsBackend([synthetic_metrics_payload(values=(1.0, 2.0))])
    logs = FakeLogsBackend([synthetic_logs_payload(values=(3.0,))])
    client = AzureMonitorClient(
        _cfg(resource_ids=[FAKE_RESOURCE_ID], workspace_id="ws-0000"),
        credential_provider=lambda: object(),
        backend=metrics,
        logs_backend=logs,
    )
    result = client.fetch_raw()
    assert result.available is True
    assert metrics.calls == 1
    assert logs.calls == 1
    signals = am_to_signals(result)
    assert [s.value for s in signals] == [
        pytest.approx(1.0),
        pytest.approx(2.0),
        pytest.approx(3.0),
    ]
    assert all(s.source is SignalSource.azure_monitor for s in signals)


# --------------------------------------------------------------------------------------
# to_signals dispatch
# --------------------------------------------------------------------------------------
def test_to_signals_dispatches_metrics_and_logs_payloads() -> None:
    result = make_fetch_result(
        raw=[synthetic_metrics_payload(values=(9.0,)), synthetic_logs_payload(values=(4.0,))]
    )
    signals = am_to_signals(result)
    assert [s.value for s in signals] == [pytest.approx(9.0), pytest.approx(4.0)]


def test_to_signals_unavailable_yields_nothing() -> None:
    assert am_to_signals(make_fetch_result(available=False)) == []


# --------------------------------------------------------------------------------------
# Default (real) metrics backend fails closed when the optional package is absent (MED 8)
# --------------------------------------------------------------------------------------
def test_default_metrics_backend_fails_closed_when_package_absent(monkeypatch) -> None:
    # MED 8: azure-monitor-querymetrics is now a mandatory dependency, so CI installs it. To
    # deterministically exercise the guarded-ImportError fail-closed path whether or not the
    # package is installed, SIMULATE its absence by pinning it to None in sys.modules (import →
    # ImportError). We give a fully-valid, TRUSTED metrics config so validation passes and the lazy
    # import is the thing that fails — proving the descriptive class name, not an AttributeError.
    import sys

    assert issubclass(AzureMonitorSdkNotWired, RuntimeError)
    monkeypatch.setitem(sys.modules, "azure.monitor.querymetrics", None)
    client = AzureMonitorClient(
        _cfg(
            resource_ids=[FAKE_RESOURCE_ID],
            metrics_endpoint="https://westus3.metrics.monitor.azure.com",
            metric_namespace="microsoft.insights/components",
        ),
        credential_provider=lambda: object(),
    )
    result = client.fetch_raw()
    assert result.available is False
    assert result.error == "AzureMonitorSdkNotWired"


# --------------------------------------------------------------------------------------
# Wiring — build_client_registry registers azure_monitor when workspace id + credential present
# --------------------------------------------------------------------------------------
def test_wiring_registers_azure_monitor_when_workspace_and_credential(monkeypatch) -> None:
    monkeypatch.setattr("cli.wiring._build_credential", lambda: object())
    registry = build_client_registry(
        config={
            ENV_AZURE_MONITOR_WORKSPACE_ID: "ws-0000",
            ENV_AZURE_MONITOR_RESOURCE_IDS: f"{FAKE_RESOURCE_ID}, {FAKE_RESOURCE_ID}",
            ENV_AZURE_MONITOR_METRICS_ENDPOINT: "https://westus3.metrics.monitor.azure.com",
            ENV_AZURE_MONITOR_METRIC_NAMESPACE: "microsoft.insights/components",
        }
    )
    assert "azure_monitor" in registry


def test_wiring_omits_azure_monitor_without_workspace(monkeypatch) -> None:
    monkeypatch.setattr("cli.wiring._build_credential", lambda: object())
    registry = build_client_registry(config={})
    assert "azure_monitor" not in registry


def test_wiring_omits_azure_monitor_without_credential(monkeypatch) -> None:
    monkeypatch.setattr("cli.wiring._build_credential", lambda: None)
    registry = build_client_registry(config={ENV_AZURE_MONITOR_WORKSPACE_ID: "ws-0000"})
    assert "azure_monitor" not in registry


def test_wiring_omits_azure_monitor_when_connector_import_fails(monkeypatch) -> None:
    # Simulate the connector module being unavailable: setting it to None in sys.modules makes the
    # guarded `from modules.aiops.connectors.azure_monitor import ...` raise → the key is omitted.
    import sys

    monkeypatch.setattr("cli.wiring._build_credential", lambda: object())
    monkeypatch.setitem(sys.modules, "modules.aiops.connectors.azure_monitor", None)
    registry = build_client_registry(config={ENV_AZURE_MONITOR_WORKSPACE_ID: "ws-0000"})
    assert "azure_monitor" not in registry


# --------------------------------------------------------------------------------------
# HIGH 1 — configured KQL columns/table can NEVER exfiltrate raw log text
# --------------------------------------------------------------------------------------
def test_high1_config_cannot_select_body_or_message_columns() -> None:
    # The log table/column names are fixed module constants (extra="forbid"), so a caller can no
    # longer set log_metric_column="Body" / log_resource_column="Message" to alias raw text into an
    # allowlisted field. Any such attempt is rejected at config validation.
    for smuggle in (
        {"log_metric_column": "Body"},
        {"log_resource_column": "Message"},
        {"log_value_column": "Body"},
        {"log_table": "SecurityEvent"},
        {"log_time_column": "Body"},
    ):
        with pytest.raises(Exception):  # noqa: B017,PT011 - pydantic ValidationError (extra=forbid)
            AzureMonitorConfig(**smuggle)  # type: ignore[arg-type]


def test_high1_fixed_kql_never_projects_free_text_columns() -> None:
    # Even with hostile resource/metric *values*, the query only ever projects fixed identifier +
    # numeric columns — Body/Message/RawData can never appear as a selected column.
    kql = build_logs_kql(
        resource_ids=["Body", "Message"],  # values, not identifiers — quoted, cannot select columns
        metric_names=["RawData"],
        lookback_hours=1.0,
        bin_minutes=5,
    )
    project = [line for line in kql.splitlines() if line.strip().startswith("| project")][0]
    assert project.strip() == "| project resourceId, metric, value, count, timestamp"
    # The hostile strings appear ONLY inside quoted filter literals, never as bare identifiers.
    assert "'Body'" in kql and "'Message'" in kql and "'RawData'" in kql


def test_high1_smuggled_body_column_cannot_emit_raw_text_end_to_end() -> None:
    # Repro of the reported defect: a backend row carrying raw "patient free text" / "secret
    # message" under Body/Message columns must never reach a Signal. The normalize allowlist +
    # body-free mapper drop them entirely.
    table = FakeLogsSdkColumnTable(
        columns=["resourceId", "metric", "value", "count", "timestamp", "Body", "Message"],
        rows=[[FAKE_RESOURCE_ID, FAKE_METRIC, 5.0, 3, "2026-01-01T00:00:00Z",
               "patient free text", "secret message"]],
    )
    payload = _normalize_logs_response(FakeLogsSdkResultShim([table]), allowed=_LOG_RECORD_FIELDS)
    signals = map_logs_response(payload)
    assert len(signals) == 1
    haystack = " ".join(str(v) for v in signals[0].model_dump().values())
    assert "patient free text" not in haystack
    assert "secret message" not in haystack


# --------------------------------------------------------------------------------------
# HIGH 2 — metrics endpoint validated before any token is minted/sent (SSRF / token replay)
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "endpoint",
    [
        "https://westus3.metrics.monitor.azure.com",
        "https://eastus.metrics.monitor.azure.us",
        "https://chinaeast2.metrics.monitor.azure.cn",
    ],
)
def test_high2_validate_metrics_endpoint_accepts_trusted_hosts(endpoint: str) -> None:
    assert _validate_metrics_endpoint(endpoint) == endpoint.lower()


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://westus3.metrics.monitor.azure.com",  # not https
        "https://attacker.example.com",  # untrusted host
        "https://westus3.metrics.monitor.azure.com.attacker.net",  # look-alike suffix
        "https://metrics.monitor.azure.com",  # bare suffix, no subdomain label
        "https://user:pass@westus3.metrics.monitor.azure.com",  # userinfo
        "https://westus3.metrics.monitor.azure.com:8443",  # explicit port
        "https://westus3.metrics.monitor.azure.com/redirect",  # path
        "https://westus3.metrics.monitor.azure.com/?x=1",  # query
        "https://westus3.metrics.monitor.azure.com/#frag",  # fragment
    ],
)
def test_high2_validate_metrics_endpoint_rejects_untrusted(endpoint: str) -> None:
    with pytest.raises(UntrustedMetricsEndpoint):
        _validate_metrics_endpoint(endpoint)


def test_high2_untrusted_endpoint_fails_closed_and_builds_no_client() -> None:
    # An attacker-influenced endpoint must fail closed BEFORE the credential-bearing client is even
    # built — so no bearer token is ever minted or sent.
    built: list[Any] = []

    def factory(endpoint: str, credential: Any) -> Any:  # pragma: no cover - must NOT be called
        built.append((endpoint, credential))
        return FakeMetricsSdkClient(endpoint, credential)

    backend = _SdkMetricsBackend(
        _cfg(
            metrics_endpoint="https://attacker.example.com",
            metric_namespace="microsoft.insights/components",
        ),
        client_factory=factory,
    )
    with pytest.raises(UntrustedMetricsEndpoint):
        backend.query_metrics(
            resource_ids=[FAKE_RESOURCE_ID],
            metric_names=[FAKE_METRIC],
            credential=object(),
            timeout_s=30.0,
        )
    assert built == []  # no client built ⇒ no token minted/sent


def test_high2_untrusted_endpoint_via_client_fails_closed_no_query() -> None:
    client = AzureMonitorClient(
        _cfg(
            resource_ids=[FAKE_RESOURCE_ID],
            metrics_endpoint="https://attacker.example.com",
            metric_namespace="microsoft.insights/components",
        ),
        credential_provider=lambda: object(),
    )
    result = client.fetch_raw()
    assert result.available is False
    assert result.error == "UntrustedMetricsEndpoint"  # class name only — no endpoint, no token


# --------------------------------------------------------------------------------------
# MED 3 — PARTIAL logs results are NOT reported as a successful empty
# --------------------------------------------------------------------------------------
def test_med3_partial_logs_result_fails_closed() -> None:
    # A LogsQueryPartialResult carries partial_data (not tables). Accepting only SUCCESS means a
    # PARTIAL status raises rather than silently returning {"logRecords": []} with available=True.
    partial = FakeLogsPartialResult(status="Partial", partial_data=[["ignored"]])
    with pytest.raises(ValueError):
        _logs_result_to_payload(partial, success_status="Success")


def test_med3_success_logs_result_is_normalized() -> None:
    table = FakeLogsSdkColumnTable(
        columns=["resourceId", "metric", "value", "count", "timestamp"],
        rows=[[FAKE_RESOURCE_ID, FAKE_METRIC, 4.0, 2, "2026-01-01T00:00:00Z"]],
    )
    result = FakeLogsSdkResult("Success", [table])
    payload = _logs_result_to_payload(result, success_status="Success")
    assert payload["logRecords"][0]["value"] == pytest.approx(4.0)


def test_med3_missing_status_fails_closed() -> None:
    class _NoStatus:
        tables: list[Any] = []

    with pytest.raises(ValueError):
        _logs_result_to_payload(_NoStatus(), success_status="Success")


# --------------------------------------------------------------------------------------
# MED 4 — resource_ids alone must NOT enable (and break) the metrics edge for logs-only deploys
# --------------------------------------------------------------------------------------
def test_med4_logs_only_with_resource_ids_still_runs_logs_no_metrics_failure() -> None:
    # resource_ids are set (to bound the KQL) but there is NO metrics endpoint/namespace, so the
    # real metrics edge must stay disabled and the logs edge must still run and succeed.
    logs = FakeLogsBackend([synthetic_logs_payload(values=(7.0,))])
    client = AzureMonitorClient(
        _cfg(resource_ids=[FAKE_RESOURCE_ID], workspace_id="ws-0000", metrics_endpoint=None),
        credential_provider=lambda: object(),
        logs_backend=logs,
    )
    result = client.fetch_raw()
    assert result.available is True
    assert logs.calls == 1
    signals = am_to_signals(result)
    assert [s.value for s in signals] == [pytest.approx(7.0)]


def test_med4_incomplete_metrics_config_disables_metrics_edge() -> None:
    # No injected backend, resource_ids set, endpoint present but namespace missing ⇒ metrics edge
    # stays disabled (would otherwise fail-closed the whole fetch).
    client = AzureMonitorClient(
        _cfg(
            resource_ids=[FAKE_RESOURCE_ID],
            metrics_endpoint="https://westus3.metrics.monitor.azure.com",
            metric_namespace=None,
            workspace_id=None,
        ),
        credential_provider=lambda: object(),
    )
    assert client._metrics_enabled() is False  # noqa: SLF001 - test asserts internal gate


# --------------------------------------------------------------------------------------
# MED 5 — non-finite values (NaN / inf) are dropped, never emitted as signals
# --------------------------------------------------------------------------------------
def test_med5_inf_from_metrics_is_dropped() -> None:
    payload = {
        "resourceId": FAKE_RESOURCE_ID,
        "metrics": [
            {
                "name": FAKE_METRIC,
                "unit": "ms",
                "timeseries": [
                    {
                        "data": [
                            {"timeStamp": "2026-01-01T00:00:00Z", "average": float("inf")},
                            {"timeStamp": "2026-01-01T00:01:00Z", "average": 3.0},
                        ]
                    }
                ],
            }
        ],
    }
    signals = map_metrics_response(payload)
    assert [s.value for s in signals] == [pytest.approx(3.0)]  # inf dropped, no fabricated breach


def test_med5_nan_from_logs_is_dropped() -> None:
    payload = {
        "logRecords": [
            {"metric": FAKE_METRIC, "value": "NaN", "unit": "aggregated",
             "timestamp": "2026-01-01T00:00:00Z", "resourceId": FAKE_RESOURCE_ID},
            {"metric": FAKE_METRIC, "value": 8.0, "unit": "aggregated",
             "timestamp": "2026-01-01T00:01:00Z", "resourceId": FAKE_RESOURCE_ID},
        ]
    }
    signals = map_logs_response(payload)
    assert [s.value for s in signals] == [pytest.approx(8.0)]  # NaN dropped


# --------------------------------------------------------------------------------------
# MED 7 — configured timeout_s is forwarded to both real SDK edges
# --------------------------------------------------------------------------------------
def test_med7_metrics_backend_forwards_timeout_to_sdk() -> None:
    captured: list[FakeMetricsSdkClient] = []

    def factory(endpoint: str, credential: Any) -> FakeMetricsSdkClient:
        client = FakeMetricsSdkClient(endpoint, credential)
        captured.append(client)
        return client

    backend = _SdkMetricsBackend(
        _cfg(
            metrics_endpoint="https://westus3.metrics.monitor.azure.com",
            metric_namespace="microsoft.insights/components",
        ),
        client_factory=factory,
    )
    backend.query_metrics(
        resource_ids=[FAKE_RESOURCE_ID],
        metric_names=[FAKE_METRIC],
        credential=object(),
        timeout_s=17.0,
    )
    assert captured[0].query_kwargs["timeout"] == pytest.approx(17.0)
    assert captured[0].closed is True


def test_med7_logs_backend_forwards_server_timeout_to_sdk() -> None:
    captured: list[FakeLogsSdkClient] = []
    table = FakeLogsSdkColumnTable(
        columns=["resourceId", "metric", "value", "count", "timestamp"],
        rows=[[FAKE_RESOURCE_ID, FAKE_METRIC, 1.0, 1, "2026-01-01T00:00:00Z"]],
    )

    def factory(credential: Any) -> FakeLogsSdkClient:
        client = FakeLogsSdkClient(credential, status="Success", tables=[table])
        captured.append(client)
        return client

    backend = _SdkLogsBackend(
        _cfg(resource_ids=[], workspace_id="ws-0000"),
        client_factory=factory,
        status_success="Success",
    )
    out = backend.query_logs(
        workspace_id="ws-0000",
        resource_ids=[FAKE_RESOURCE_ID],
        metric_names=[FAKE_METRIC],
        credential=object(),
        timeout_s=23.4,
    )
    assert captured[0].query_kwargs["server_timeout"] == 23  # max(1, int(23.4))
    assert out[0]["logRecords"][0]["value"] == pytest.approx(1.0)


def test_med7_client_forwards_configured_timeout_to_backend() -> None:
    # End-to-end: the client hands the configured timeout_s down to the backend edge.
    logs = FakeLogsBackend([synthetic_logs_payload(values=(2.0,))])
    client = AzureMonitorClient(
        _cfg(resource_ids=[], workspace_id="ws-0000", timeout_s=42.0),
        credential_provider=lambda: object(),
        logs_backend=logs,
    )
    client.fetch_raw()
    assert logs.last_kwargs["timeout_s"] == pytest.approx(42.0)


class FakeLogsSdkResultShim:
    """Minimal ``.tables`` container for ``_normalize_logs_response`` (no status gate)."""

    def __init__(self, tables: list[Any]) -> None:
        self.tables = tables
