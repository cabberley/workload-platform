"""Grounded RCA-explanation edge tests (issue #54) — keyless, in-boundary, fail-closed.

All fixtures are clearly-fake synthetic data (guardrail 2). The edge is exercised with an injected
fake transport so nothing touches the Azure SDK or the network. Properties proven here:

* UNCONFIGURED ⇒ no-op (``available=False``) so the pure RCA result stands;
* the confidence floor, region-pin, endpoint-trust, and missing-credential gates all fail closed;
* the ONLY payload sent to the transport is the RCA's already-cited fields (no new/PII data);
* a faithful reply is accepted; an ungrounded (hallucinated) reply fails closed;
* any transport error degrades to a class-name-only error and pings the fail-closed observer.
"""
from __future__ import annotations

import json
from typing import Any

from modules.aiops.connectors.rca_explanation import (
    RcaExplanationClient,
    RcaExplanationConfig,
    grounding_payload,
)
from shared.contracts import AgentResponse, SourceReference

_CITED_NODE = "node-fake-01"
_CITED_RESOURCE = "/subscriptions/00000000/rg/synthetic/widget-01"
_CITED_METRIC = "cpu_saturation_ratio"


def _response(confidence: float = 0.9) -> AgentResponse:
    return AgentResponse(
        agentName="aiops",
        taskType="auto-rca",
        inputSummary="synthetic-input-summary-should-not-be-sent",
        findings=[f"{_CITED_NODE} shows {_CITED_METRIC} above threshold"],
        risks=["availability degraded for the widget workload"],
        recommendations=["investigate the cited node"],
        sourceReferences=[
            SourceReference(kind="resource", id=_CITED_RESOURCE, detail="observed"),
            SourceReference(kind="metric", id=_CITED_METRIC, detail=None),
        ],
        confidence=confidence,
        nextActions=["auto-rca"],
    )


def _cfg(region: str = "westus3", platform_region: str = "westus3") -> RcaExplanationConfig:
    return RcaExplanationConfig(
        endpoint="https://synthetic-fake.openai.azure.com",
        deployment="fake-deployment",
        region=region,
        platform_region=platform_region,
    )


def test_no_ops_when_unconfigured() -> None:
    client = RcaExplanationClient(None, credential_provider=lambda: object())
    result = client.explain(_response())
    assert result.available is False
    assert result.error == "Unconfigured"


def test_low_confidence_surfaces_support_path() -> None:
    client = RcaExplanationClient(
        _cfg(), credential_provider=lambda: object(), transport=lambda d, s, f: "x"
    )
    result = client.explain(_response(confidence=0.4))
    assert result.available is False
    assert result.error == "LowConfidence"


def test_fails_closed_on_region_mismatch_before_transport() -> None:
    calls: list[Any] = []

    def _transport(deployment: str, system: str, payload: str) -> str:
        calls.append(payload)
        return "ok"

    client = RcaExplanationClient(
        _cfg(region="westus3", platform_region="eastus2"),
        credential_provider=lambda: object(),
        transport=_transport,
    )
    result = client.explain(_response())
    assert result.available is False
    assert result.error == "RegionPinMismatch"
    assert calls == []  # region pin fails BEFORE any transport call


def test_fails_closed_on_untrusted_endpoint() -> None:
    cfg = RcaExplanationConfig(
        endpoint="https://evil.example.com",
        deployment="fake-deployment",
        region="westus3",
        platform_region="westus3",
    )
    client = RcaExplanationClient(
        cfg, credential_provider=lambda: object(), transport=lambda d, s, f: "ok"
    )
    result = client.explain(_response())
    assert result.available is False
    assert result.error == "UntrustedOpenAIEndpoint"


def test_fails_closed_without_credential() -> None:
    client = RcaExplanationClient(
        _cfg(), credential_provider=lambda: None, transport=lambda d, s, f: "ok"
    )
    result = client.explain(_response())
    assert result.available is False
    assert result.error == "NoCredential"


def test_sends_only_cited_fields_no_new_or_pii_data() -> None:
    captured: dict[str, str] = {}

    def _transport(deployment: str, system: str, payload: str) -> str:
        captured["payload"] = payload
        return f"{_CITED_NODE} breached {_CITED_METRIC}; review widget-01."

    client = RcaExplanationClient(
        _cfg(), credential_provider=lambda: object(), transport=_transport
    )
    result = client.explain(_response())
    assert result.available is True

    payload = captured["payload"]
    parsed = json.loads(payload)
    # Exactly the 5 cited fields — nothing else.
    assert set(parsed) == {
        "findings",
        "risks",
        "recommendations",
        "sourceReferences",
        "confidence",
    }
    # The non-evidence fields are NEVER sent.
    assert "inputSummary" not in payload
    assert "should-not-be-sent" not in payload
    assert "agentName" not in payload
    assert "generatedAt" not in payload
    # The payload equals the pure grounding payload of the same response.
    assert parsed == grounding_payload(_response())


def test_grounded_reply_is_accepted() -> None:
    client = RcaExplanationClient(
        _cfg(),
        credential_provider=lambda: object(),
        transport=lambda d, s, f: f"The evidence shows {_CITED_NODE} breached {_CITED_METRIC}.",
    )
    result = client.explain(_response())
    assert result.available is True
    assert result.grounded is True
    assert result.advisory is not None
    assert _CITED_NODE in result.advisory


def test_ungrounded_reply_fails_closed() -> None:
    client = RcaExplanationClient(
        _cfg(),
        credential_provider=lambda: object(),
        transport=lambda d, s, f: "The failure is in /subscriptions/99999999/rg/ghost/phantom-99.",
    )
    result = client.explain(_response())
    assert result.available is False
    assert result.error == "Ungrounded"


def test_non_text_reply_fails_closed() -> None:
    client = RcaExplanationClient(
        _cfg(),
        credential_provider=lambda: object(),
        transport=lambda d, s, f: None,  # type: ignore[arg-type,return-value]
    )
    result = client.explain(_response())
    assert result.available is False
    assert result.error == "NonTextResponse"


def test_transport_error_degrades_and_pings_observer() -> None:
    pings: list[int] = []

    def _boom(deployment: str, system: str, payload: str) -> str:
        raise RuntimeError("transport exploded")

    client = RcaExplanationClient(
        _cfg(),
        credential_provider=lambda: object(),
        transport=_boom,
        fail_closed_observer=lambda: pings.append(1),
    )
    result = client.explain(_response())
    assert result.available is False
    assert result.error == "RuntimeError"
    assert pings == [1]


def test_advisory_is_bounded() -> None:
    # Benign prose with no entity tokens, so truncation cannot create an ungrounded fragment.
    long_reply = (
        "the evidence indicates saturation and operators should review the cited node. " * 200
    )
    client = RcaExplanationClient(
        _cfg(), credential_provider=lambda: object(), transport=lambda d, s, f: long_reply
    )
    result = client.explain(_response())
    assert result.available is True
    assert result.advisory is not None
    assert len(result.advisory) <= 2000
