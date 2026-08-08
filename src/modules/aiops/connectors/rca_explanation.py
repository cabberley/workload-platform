"""Keyless in-boundary Azure OpenAI RCA-explanation edge (issue #54).

A THIN, OPTIONAL, fail-closed edge that (when configured AND enabled) turns an existing auto-RCA
:class:`shared.contracts.AgentResponse` into an ADVISORY natural-language EXPLANATION — grounded
STRICTLY on the evidence that RCA already cited. It is the productization of the in-boundary,
keyless LLM edge that issue #53 built and explicitly left reusable
(:mod:`modules.aiops.connectors.openai_enrichment`): it REUSES the same shared AOAI guardrail
machinery in :mod:`shared.connectors.aoai` (trusted-host validation, region-pin, lazy SDK transport,
Cognitive-Services scope) rather than re-deriving it.

Guardrails (keyless, in-boundary, grounded-only, advisory, fail-closed) — identical posture to #53:

* **Keyless.** Managed Identity via an *injected* ``credential_provider`` (a closure over
  ``DefaultAzureCredential``); no key, secret, or connection string is read, embedded, or logged.
* **Configured by env-var NAMES only.** The composition root passes endpoint / deployment / region
  VALUES it read from Key-Vault-backed env var *names*; none is a secret and none is hard-coded
  here. Absent any of them ⇒ the edge is UNCONFIGURED and no-ops (the pure RCA result stands).
* **Grounded-only, no new facts.** The ONLY payload sent is :func:`grounding_payload` — a projection
  of the AgentResponse's already-egress-classified CITED fields (``findings`` / ``risks`` /
  ``recommendations`` / ``sourceReferences`` / ``confidence``). A system instruction forbids the
  model from introducing any new resource id, metric, nodeId, or fact. After generation, the PURE
  grounding gate (:func:`modules.aiops.rca_grounding.ground_or_reject`) REJECTS an explanation that
  names any evidence-like entity not present in the cited fields — fail closed to the support path.
* **Confidence-gated.** When the RCA ``confidence`` is below ``rca.RCA_CONFIDENCE_FLOOR`` we do NOT
  assert an explanation; we surface the "review evidence / call support" path (mirrors #53's floor).
* **Region-pinned + endpoint-validated.** The AOAI region must equal the platform region and the
  endpoint host must be a trusted Azure OpenAI host — both checked BEFORE any token is minted.
* **Advisory only.** The returned explanation is a free-text advisory the module attaches to the
  redact-on-egress ``extra`` surface — never a finding/risk/recommendation/remediation/nextAction,
  never auto-applied. Low confidence / ungrounded / unconfigured / any error ⇒ the pure RCA stands.

**Module isolation** is preserved: this edge imports only ``shared.*`` and *same-module* helpers
(:mod:`modules.aiops.rca`, :mod:`modules.aiops.rca_grounding`) — never another ``src/modules/*``.

TODO(human): GO-LIVE of this in-boundary, no-Microsoft-processing pattern is gated on CELA/HiTrust
sign-off (external legal gate, NOT a code blocker). The grounded hook is built now and ships behind
config/flag; ship-enable it once signed off.
"""
from __future__ import annotations

import json
from contextlib import suppress
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from modules.aiops.rca import RCA_CONFIDENCE_FLOOR
from modules.aiops.rca_grounding import ground_or_reject
from shared.connectors import CredentialProvider, FailClosedObserver
from shared.connectors.aoai import (
    AoaiChatTransport,
    AoaiSdkNotWired,
    build_aoai_chat_transport,
    enforce_region_pin,
    validate_openai_endpoint,
)
from shared.contracts import AgentResponse

# The well-known client-registry key the AIOps module looks this connector up by.
CLIENT_KEY = "rca_explanation"

# A bounded advisory. The model is asked for a short, grounded explanation; we also cap the returned
# text so an over-long response cannot bloat the result envelope.
_MAX_ADVISORY_CHARS = 2000

# The system instruction constrains the model to EXPLAIN only the cited evidence and forbids it from
# introducing any new entity or fact. The pure grounding gate enforces this in code afterwards; the
# instruction is the first line of defense, the gate is the guarantee.
_SYSTEM_INSTRUCTION = (
    "You are an SRE assistant. You are given the ALREADY-CITED evidence of an automated "
    "root-cause analysis (its findings, risks, recommendations, cited source references, and a "
    "confidence score) as JSON. Explain, in a brief advisory paragraph, what this evidence "
    "indicates and what a human operator might investigate. Use ONLY the evidence provided: do NOT "
    "introduce any new resource id, metric name, node id, number, or fact that is not already in "
    "the cited evidence. Do not propose remediation or actions. This is advisory only; a human "
    "disposes."
)


class RcaExplanationSdkNotWired(AoaiSdkNotWired):
    """Raised when the optional Azure OpenAI SDK cannot be imported — fail closed (name only)."""


class RcaExplanationConfig(BaseModel):
    """Connector configuration. Holds no secrets — only non-secret ids + region VALUES.

    All values are supplied by the composition root from Key-Vault-backed env var *names*; the
    endpoint/deployment/region are non-secret. ``extra="forbid"`` so a bad config fails closed.
    """

    model_config = ConfigDict(extra="forbid")

    endpoint: str = Field(
        description="Azure OpenAI endpoint, e.g. https://<resource>.openai.azure.com"
    )
    deployment: str = Field(description="Azure OpenAI deployment name (non-secret)")
    region: str = Field(description="Azure OpenAI resource region (e.g. westus3)")
    platform_region: str = Field(description="The platform's region; must equal `region` (pinned)")
    timeout_s: float = Field(default=30.0, gt=0.0, le=120.0)
    max_advisory_chars: int = Field(default=_MAX_ADVISORY_CHARS, ge=1, le=8000)


class RcaExplanation(BaseModel):
    """Advisory-only grounded explanation result. ``available=False`` ⇒ no-op (the RCA stands).

    ``advisory`` is a free-text advisory the module attaches to the redact-on-egress ``extra``
    surface (never a finding/response field). ``grounded`` records that the pure grounding gate
    accepted it. ``error`` is the error **class name only** — never a body, token, or message.
    """

    model_config = ConfigDict(extra="forbid")

    available: bool
    advisory: str | None = None
    grounded: bool = False
    error: str | None = Field(
        default=None, description="Error *class* name only; never a body or token"
    )


def grounding_payload(response: AgentResponse) -> dict[str, Any]:
    """The ONLY payload sent to the model: the RCA's already-cited fields, nothing else.

    Sends the AgentResponse's ``findings`` / ``risks`` / ``recommendations`` / ``sourceReferences``
    (kind/id/detail only) / ``confidence`` — the fields the RCA already egress-classified. It
    deliberately OMITS ``agentName`` / ``taskType`` / ``inputSummary`` / ``nextActions`` /
    ``generatedAt`` so no non-evidence field can leak or seed a fabricated fact.
    """
    return {
        "findings": list(response.findings),
        "risks": list(response.risks),
        "recommendations": list(response.recommendations),
        "sourceReferences": [
            {"kind": ref.kind, "id": ref.id, "detail": ref.detail}
            for ref in response.sourceReferences
        ],
        "confidence": response.confidence,
    }


class RcaExplanationClient:
    """Thin, keyless, fail-closed Azure OpenAI RCA-explanation edge. Sends ONLY cited RCA fields.

    Inject a ``credential_provider`` (Managed Identity, keyless) and — in tests — a ``transport`` so
    everything is exercised without the SDK or network. UNCONFIGURED (no config) ⇒ every call
    no-ops with ``available=False`` so the pure RCA result stands. Region-pin and endpoint trust are
    validated BEFORE any credential is resolved; the confidence floor and the pure grounding gate
    are enforced so an ungrounded or low-confidence explanation is never asserted (fail closed).
    """

    def __init__(
        self,
        config: RcaExplanationConfig | None,
        *,
        credential_provider: CredentialProvider | None = None,
        transport: AoaiChatTransport | None = None,
        fail_closed_observer: FailClosedObserver | None = None,
    ) -> None:
        self._config = config
        self._credential_provider = credential_provider
        self._transport = transport
        self._fail_closed_observer = fail_closed_observer

    @property
    def configured(self) -> bool:
        """True iff a config is present. UNCONFIGURED clients always no-op (the RCA stands)."""
        return self._config is not None

    def explain(self, response: AgentResponse) -> RcaExplanation:
        """Return a grounded advisory explanation of ``response``, or no-op / fail closed.

        Fail-closed and advisory only. UNCONFIGURED ⇒ ``available=False`` (no-op). A non-response
        input, a below-floor confidence, a region-pin mismatch, an untrusted endpoint, an
        unresolvable/raising credential, a missing SDK, a non-text or UNGROUNDED model reply, or any
        transport error ⇒ ``available=False`` with the error class name only — the pure RCA result
        always stands. The ONLY payload sent is :func:`grounding_payload` (the RCA's cited fields).
        """
        try:
            return self._explain(response)
        except Exception as exc:  # noqa: BLE001 - every edge failure must fail closed, class name only
            if self._fail_closed_observer is not None:
                with suppress(Exception):
                    self._fail_closed_observer()
            return RcaExplanation(available=False, error=type(exc).__name__)

    def _explain(self, response: AgentResponse) -> RcaExplanation:
        """Validate input + confidence + region-pin + endpoint + credential, then ground reply."""
        if self._config is None:
            return RcaExplanation(available=False, error="Unconfigured")
        # Refuse anything that is not the canonical analytical contract (defense in depth): the only
        # thing this edge ever explains is an AgentResponse produced in-boundary by aiops.rca.
        if not isinstance(response, AgentResponse):
            return RcaExplanation(available=False, error="NonAgentResponseInput")

        # Confidence floor (mirrors #53): below the floor the RCA asserts no root cause, so we do
        # NOT assert an explanation — surface the support path instead of a confident narrative.
        if response.confidence < RCA_CONFIDENCE_FLOOR:
            return RcaExplanation(available=False, error="LowConfidence")

        # Region-pin BEFORE resolving any credential or validating the endpoint (fail closed early).
        enforce_region_pin(self._config.region, self._config.platform_region)
        # Validate the endpoint host BEFORE minting/handing over any token (SSRF/token guard).
        validate_openai_endpoint(self._config.endpoint)

        credential = (
            self._credential_provider() if self._credential_provider is not None else None
        )
        if credential is None:
            return RcaExplanation(available=False, error="NoCredential")

        # The ONLY payload sent: the RCA's already-cited fields. No new data is fetched/fabricated.
        payload_json = json.dumps(grounding_payload(response))
        transport = (
            self._transport if self._transport is not None else self._sdk_transport(credential)
        )
        advisory = transport(self._config.deployment, _SYSTEM_INSTRUCTION, payload_json)
        if not isinstance(advisory, str):
            return RcaExplanation(available=False, error="NonTextResponse")

        # PURE grounding gate on the FULL model text (BEFORE any truncation, so bounding can never
        # split a trailing token and spuriously fail — or pass — the gate). ``None`` ⇒ fail closed
        # (surface the review-evidence/support path).
        grounded = ground_or_reject(response, advisory)
        if grounded is None:
            return RcaExplanation(available=False, error="Ungrounded")
        # Only NOW bound the already-grounded text for the result envelope.
        bounded = grounded[: self._config.max_advisory_chars]
        return RcaExplanation(available=True, advisory=bounded, grounded=True)

    def _sdk_transport(self, credential: Any) -> AoaiChatTransport:
        """Build a real transport that lazily wraps the Azure OpenAI SDK (keyless, validated).

        Delegates to the shared :func:`~shared.connectors.aoai.build_aoai_chat_transport` so the SDK
        stays lazy (a missing package fails closed via :class:`RcaExplanationSdkNotWired`) and the
        keyless credential is handed straight to the SDK — never logged.
        """
        assert self._config is not None  # noqa: S101 - _explain guards None before calling
        return build_aoai_chat_transport(
            endpoint=self._config.endpoint,
            credential=credential,
            timeout_s=self._config.timeout_s,
            sdk_not_wired=RcaExplanationSdkNotWired,
        )


__all__ = [
    "CLIENT_KEY",
    "RcaExplanation",
    "RcaExplanationClient",
    "RcaExplanationConfig",
    "RcaExplanationSdkNotWired",
    "grounding_payload",
]
