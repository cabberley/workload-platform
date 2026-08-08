"""AIOps log-anomaly connector tests (issue #53) — keyless, fail-closed, no PII/log-body egress.

All fixtures are clearly-fake synthetic data (guardrail 2). Both connectors are exercised with
injected fakes so the tests stay Azure- and network-free. The properties proven here:

* the log-sample edge reduces raw rows to PII-free :class:`LogFeatures` and NEVER returns raw rows;
* it fails closed with no credential / a raising backend (error class name only);
* the enrichment edge no-ops when UNCONFIGURED, degrades on any error, region-pins, and sends ONLY
  the aggregate features JSON — never a raw log.
"""
from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from modules.aiops.connectors.log_sample import (
    LogSampleClient,
    LogSampleConfig,
    RawLogWindow,
)
from modules.aiops.connectors.openai_enrichment import (
    LogAnomalyEnrichment,
    OpenAIEnrichmentClient,
    OpenAIEnrichmentConfig,
)
from modules.aiops.log_features import (
    LogFeatureExtractionSpec,
    extract_log_features,
    structural_signature,
)
from shared.contracts import LogFeatures, TemplateFrequency

_RESOURCE = "/subscriptions/00000000/rg/synthetic/widget-01"

# A synthetic raw row containing things that WOULD be PII if ever returned.
_RAW_ROW = {
    "level": "error",
    "message": "user bob@contoso.example failed from 10.0.0.9 token deadbeefcafe1234",
    "dur": 42,
    "ts": "2026-08-03T04:00:00Z",
}


class _FakeBackend:
    """A fake raw-log-window backend returning a fixed set of windows (never touches network)."""

    def __init__(self, windows: list[RawLogWindow]) -> None:
        self._windows = windows
        self.calls = 0

    def fetch_windows(
        self, *, resource_ids: Sequence[str], credential: Any, timeout_s: float
    ) -> list[RawLogWindow]:
        self.calls += 1
        return list(self._windows)


class _RaisingBackend:
    def fetch_windows(
        self, *, resource_ids: Sequence[str], credential: Any, timeout_s: float
    ) -> list[RawLogWindow]:
        raise RuntimeError("boom-should-not-leak")


def _config() -> LogSampleConfig:
    return LogSampleConfig(
        workspace_id="00000000-0000-0000-0000-000000000000",
        resource_ids=[_RESOURCE],
        extraction=LogFeatureExtractionSpec(
            levelField="level", messageField="message", durationField="dur", timestampField="ts"
        ),
    )


# --------------------------------------------------------------------------------------
# log_sample — reduce to features, no raw rows cross the boundary
# --------------------------------------------------------------------------------------
def test_fetch_features_reduces_raw_windows_to_pii_free_features() -> None:
    windows = [
        RawLogWindow(resource_id=_RESOURCE, index=i, records=[dict(_RAW_ROW)])
        for i in range(3)
    ]
    client = LogSampleClient(
        _config(), credential_provider=lambda: object(), backend=_FakeBackend(windows)
    )
    result = client.fetch_features(resource_ids=[_RESOURCE])
    assert result.available is True
    features = result.windowsByResource[_RESOURCE]
    assert len(features) == 3
    assert all(isinstance(f, LogFeatures) for f in features)
    # The raw message/PII NEVER crosses the connector boundary.
    dumped = json.dumps(result.model_dump(mode="json"))
    for token in ("bob", "contoso", "10.0.0.9", "deadbeef", "failed"):
        assert token not in dumped


def test_fetch_features_windows_are_oldest_to_newest() -> None:
    windows = [
        RawLogWindow(resource_id=_RESOURCE, index=2, records=[dict(_RAW_ROW)]),
        RawLogWindow(resource_id=_RESOURCE, index=0, records=[dict(_RAW_ROW), dict(_RAW_ROW)]),
        RawLogWindow(resource_id=_RESOURCE, index=1, records=[dict(_RAW_ROW)]),
    ]
    client = LogSampleClient(
        _config(), credential_provider=lambda: object(), backend=_FakeBackend(windows)
    )
    result = client.fetch_features(resource_ids=[_RESOURCE])
    counts = [f.totalCount for f in result.windowsByResource[_RESOURCE]]
    assert counts == [2, 1, 1]  # ordered by index 0,1,2


def test_fetch_features_fails_closed_without_credential() -> None:
    client = LogSampleClient(
        _config(), credential_provider=lambda: None, backend=_FakeBackend([])
    )
    result = client.fetch_features(resource_ids=[_RESOURCE])
    assert result.available is False
    assert result.error == "NoCredential"
    assert result.windowsByResource == {}


def test_fetch_features_fails_closed_on_raising_backend() -> None:
    observed: list[int] = []
    client = LogSampleClient(
        _config(),
        credential_provider=lambda: object(),
        backend=_RaisingBackend(),
        fail_closed_observer=lambda: observed.append(1),
    )
    result = client.fetch_features(resource_ids=[_RESOURCE])
    assert result.available is False
    assert result.error == "RuntimeError"  # class name only — never the message body
    assert "boom" not in json.dumps(result.model_dump(mode="json"))
    assert observed == [1]


# --------------------------------------------------------------------------------------
# openai_enrichment — no-op unconfigured, degrade on error, send only aggregate features
# --------------------------------------------------------------------------------------
def _features() -> LogFeatures:
    return LogFeatures(
        totalCount=100, countsByLevel={}, errorRate=0.3, warnRate=0.1,
        distinctTemplateCount=7, topTemplates=[], durationSampleCount=0,
    )


def test_enrichment_no_ops_when_unconfigured() -> None:
    client = OpenAIEnrichmentClient(None, credential_provider=lambda: object())
    result = client.enrich(_features())
    assert isinstance(result, LogAnomalyEnrichment)
    assert result.available is False
    assert result.error == "Unconfigured"
    assert result.advisory is None


def _cfg(region: str = "westus3", platform_region: str = "westus3") -> OpenAIEnrichmentConfig:
    return OpenAIEnrichmentConfig(
        endpoint="https://synthetic-fake.openai.azure.com",
        deployment="fake-deployment",
        region=region,
        platform_region=platform_region,
    )


def test_enrichment_sends_only_aggregate_features_json() -> None:
    captured: dict[str, str] = {}

    def _transport(deployment: str, system_instruction: str, features_json: str) -> str:
        captured["deployment"] = deployment
        captured["payload"] = features_json
        return "advisory: error rate elevated vs baseline; investigate recent deploys."

    client = OpenAIEnrichmentClient(
        _cfg(), credential_provider=lambda: object(), transport=_transport
    )
    result = client.enrich(_features())
    assert result.available is True
    assert result.advisory is not None
    # The ONLY payload sent is the serialized aggregate LogFeatures — parseable + aggregate-only.
    parsed = json.loads(captured["payload"])
    assert parsed["totalCount"] == 100
    assert parsed["errorRate"] == 0.3
    assert set(parsed).issubset(set(_features().model_dump().keys()))


def test_enrichment_never_receives_raw_logs() -> None:
    seen: list[str] = []

    def _transport(deployment: str, system_instruction: str, features_json: str) -> str:
        seen.append(features_json)
        return "ok"

    client = OpenAIEnrichmentClient(
        _cfg(), credential_provider=lambda: object(), transport=_transport
    )
    client.enrich(_features())
    # No raw-log markers can appear — the payload is only the aggregate features contract.
    for payload in seen:
        for token in ("message", "bob", "contoso", "token", "path"):
            assert token not in payload


def test_enrichment_fails_closed_on_region_mismatch() -> None:
    calls: list[int] = []

    def _transport(deployment: str, system_instruction: str, features_json: str) -> str:
        calls.append(1)
        return "should-not-run"

    client = OpenAIEnrichmentClient(
        _cfg(region="westus3", platform_region="eastus2"),
        credential_provider=lambda: object(),
        transport=_transport,
    )
    result = client.enrich(_features())
    assert result.available is False
    assert result.error == "RegionPinMismatch"
    assert calls == []  # region pin fails BEFORE any transport call


def test_enrichment_fails_closed_without_credential() -> None:
    client = OpenAIEnrichmentClient(
        _cfg(), credential_provider=lambda: None, transport=lambda d, s, f: "x"
    )
    result = client.enrich(_features())
    assert result.available is False
    assert result.error == "NoCredential"


def test_enrichment_degrades_on_transport_error() -> None:
    def _transport(deployment: str, system_instruction: str, features_json: str) -> str:
        raise RuntimeError("model-unreachable-detail")

    observed: list[int] = []
    client = OpenAIEnrichmentClient(
        _cfg(),
        credential_provider=lambda: object(),
        transport=_transport,
        fail_closed_observer=lambda: observed.append(1),
    )
    result = client.enrich(_features())
    assert result.available is False
    assert result.error == "RuntimeError"  # class name only — no error body leaks
    assert observed == [1]


# --------------------------------------------------------------------------------------
# openai_enrichment — structural-template SIGNATURES must never egress (issue #53 HIGH fix)
# --------------------------------------------------------------------------------------
def test_enrichment_payload_drops_template_signatures() -> None:
    # The signature preimage may embed a residual lowercase keyword token, so the one-way hash is
    # an INTERNAL correlation key that must NOT leave the boundary. The enrichment projection drops
    # it entirely while keeping the aggregate template stats (count/fraction, distinct count).
    captured: dict[str, str] = {}

    def _transport(deployment: str, system_instruction: str, features_json: str) -> str:
        captured["payload"] = features_json
        return "advisory"

    sig = structural_signature("connection from prod host refused")
    feats = LogFeatures(
        totalCount=50, countsByLevel={}, errorRate=0.2, warnRate=0.0,
        distinctTemplateCount=2,
        topTemplates=[TemplateFrequency(signature=sig, count=10, fraction=0.2)],
        durationSampleCount=0,
    )
    client = OpenAIEnrichmentClient(
        _cfg(), credential_provider=lambda: object(), transport=_transport
    )
    result = client.enrich(feats)
    assert result.available is True
    payload = captured["payload"]
    parsed = json.loads(payload)
    # No signature key or hash string anywhere in the outbound payload.
    assert "signature" not in payload
    assert sig not in payload
    # Aggregate template stats DO survive — count + fraction only, no hash.
    assert parsed["distinctTemplateCount"] == 2
    assert parsed["topTemplates"] == [{"count": 10, "fraction": 0.2}]


def test_enrichment_from_extracted_features_emits_no_signature() -> None:
    # A log line with a bare identifier still yields enrichment, and its in-boundary signature
    # (which may embed a residual keyword token in its preimage) never reaches the transport.
    spec = LogFeatureExtractionSpec(levelField="level", messageField="message")
    sample = [
        {"level": "error", "message": "auth failed for user alice on host web"},
        {"level": "error", "message": "auth failed for user bob on host web"},
    ]
    feats = extract_log_features(sample, spec)
    assert feats.topTemplates  # a signature IS computed in-boundary

    captured: dict[str, str] = {}

    def _transport(deployment: str, system_instruction: str, features_json: str) -> str:
        captured["payload"] = features_json
        return "advisory"

    client = OpenAIEnrichmentClient(
        _cfg(), credential_provider=lambda: object(), transport=_transport
    )
    result = client.enrich(feats)
    assert result.available is True
    payload = captured["payload"]
    assert "signature" not in payload
    for tpl in feats.topTemplates:
        assert tpl.signature not in payload
