"""Keyless in-boundary Azure OpenAI enrichment edge (issue #53, deliverable 4).

A THIN, OPTIONAL, fail-closed edge that (when configured) enriches the pure statistical
log-anomaly result with an ADVISORY natural-language explanation from an Azure OpenAI deployment
running IN the customer's own subscription. It is enrichment, NOT a dependency: the pure anomaly
core (deliverables 1-3) is fully valuable and correct with NO endpoint configured — this edge
simply no-ops and the statistical result stands alone.

Guardrails (keyless, in-boundary, no PII egress, region-pinned, advisory, fail-closed):

* **Keyless.** Managed Identity via an *injected* ``credential_provider`` (a closure over
  ``DefaultAzureCredential``); no key, secret, or connection string is read, embedded, or logged.
* **Configured by env-var NAMES only.** The composition root passes the endpoint / deployment /
  region VALUES it read from Key-Vault-backed env var *names*; none of them is a secret and none is
  hard-coded here. Absent any of them ⇒ the edge is UNCONFIGURED and no-ops.
* **PII-free by construction.** The ONLY thing sent is the PII-free ENRICHMENT PROJECTION of the
  already-computed aggregate :class:`shared.contracts.LogFeatures`
  (:meth:`~shared.contracts.LogFeatures.enrichment_payload`: counts, rates, level tallies, numeric
  percentiles, and per-template count/fraction — with the one-way structural-template *signatures
  dropped*, since their hash preimage may embed residual lowercase keyword tokens). A
  non-:class:`LogFeatures` input is refused (fail closed). No raw log body, message, id, template
  hash, or PII can reach the model — there is no code path that carries one here.
* **Region-pinned.** The Azure OpenAI region must equal the platform region (both supplied by the
  composition root); a mismatch fails closed with NO call. The endpoint host is additionally
  validated against the trusted Azure OpenAI hosts before any token is minted (SSRF/token-replay
  guard), mirroring the Azure Monitor metrics edge.
* **Advisory only.** The returned enrichment is a free-text advisory the module attaches to the
  redact-on-egress ``extra`` surface — never a finding/response field, never a remediation, never
  auto-applied. Low confidence / unconfigured / any error ⇒ the pure result stands.

Placed under ``modules.aiops.connectors`` so issue #54 (Copilot RCA explanation) can REUSE this
same keyless, region-pinned, fail-closed edge.
"""
from __future__ import annotations

import json
from contextlib import suppress
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from shared.connectors import CredentialProvider, FailClosedObserver
from shared.connectors.aoai import (
    TRUSTED_AOAI_HOST_SUFFIXES,
    AoaiChatTransport,
    AoaiSdkNotWired,
    RegionPinMismatch,
    UntrustedOpenAIEndpoint,
    build_aoai_chat_transport,
    enforce_region_pin,
    validate_openai_endpoint,
)
from shared.contracts import LogFeatures

# The well-known client-registry key the AIOps module looks this connector up by.
CLIENT_KEY = "llm_enrichment"

# Backwards-compatible aliases: the shared AOAI machinery (issue #54 refactor) is the single home
# for the trusted-host suffixes, scope, and endpoint validator so the RCA-explanation edge reuses
# EXACTLY the same guardrails. These names are kept so #53 imports/behavior are unchanged.
_TRUSTED_AOAI_HOST_SUFFIXES = TRUSTED_AOAI_HOST_SUFFIXES
_validate_openai_endpoint = validate_openai_endpoint

# A bounded advisory. The model is asked for a short, aggregate-only explanation; we also cap the
# returned text so an over-long response cannot bloat the result envelope.
_MAX_ADVISORY_CHARS = 2000

_SYSTEM_INSTRUCTION = (
    "You are an SRE assistant. You are given ONLY aggregate, PII-free log statistics for a single "
    "observation window (counts, rates, one-way structural-template hashes, numeric duration "
    "percentiles). Never ask for or infer raw log contents. Give a brief, advisory explanation of "
    "what the aggregate pattern may indicate and what a human operator might investigate. This is "
    "advisory only; a human disposes."
)

# An injected transport: given (deployment, system_instruction, features_json) return advisory text.
# The real backend lazily imports the Azure OpenAI SDK; tests inject a fake so nothing touches the
# network. The features_json is the serialized PII-free enrichment PROJECTION (signatures dropped) —
# the ONLY payload sent. Aliased to the shared AOAI transport type (issue #54 refactor).
LLMTransport = AoaiChatTransport


class OpenAIEnrichmentConfig(BaseModel):
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


class OpenAIEnrichmentSdkNotWired(AoaiSdkNotWired):
    """Raised when the optional Azure OpenAI SDK cannot be imported — fail closed.

    A subclass of the shared :class:`~shared.connectors.aoai.AoaiSdkNotWired` so the surfaced
    error **class name** stays ``OpenAIEnrichmentSdkNotWired`` (unchanged #53 behavior) while the
    transport machinery is shared.
    """


class LogAnomalyEnrichment(BaseModel):
    """Advisory-only enrichment result. ``available=False`` ⇒ no-op (the pure result stands).

    ``advisory`` is a free-text advisory the module attaches to the redact-on-egress ``extra``
    surface (never a finding/response field). ``error`` is the error **class name only** — never a
    body, token, or message.
    """

    model_config = ConfigDict(extra="forbid")

    available: bool
    advisory: str | None = None
    error: str | None = Field(
        default=None, description="Error *class* name only; never a body or token"
    )


class OpenAIEnrichmentClient:
    """Thin, keyless, fail-closed Azure OpenAI enrichment edge. Sends ONLY aggregate features.

    Inject a ``credential_provider`` (Managed Identity, keyless) and — in tests — a ``transport`` so
    everything is exercised without the SDK or network. UNCONFIGURED (no config) ⇒ every call
    no-ops with ``available=False`` so the pure statistical result stands alone. Region-pin and
    endpoint trust are validated BEFORE any credential is resolved.
    """

    def __init__(
        self,
        config: OpenAIEnrichmentConfig | None,
        *,
        credential_provider: CredentialProvider | None = None,
        transport: LLMTransport | None = None,
        fail_closed_observer: FailClosedObserver | None = None,
    ) -> None:
        self._config = config
        self._credential_provider = credential_provider
        self._transport = transport
        self._fail_closed_observer = fail_closed_observer

    @property
    def configured(self) -> bool:
        """True iff a config is present. UNCONFIGURED clients always no-op (pure result stands)."""
        return self._config is not None

    def enrich(self, features: LogFeatures) -> LogAnomalyEnrichment:
        """Return an advisory enrichment for the aggregate ``features``, or no-op/fail closed.

        Fail-closed and advisory only. UNCONFIGURED ⇒ ``available=False`` (no-op). A non-features
        input, a region-pin mismatch, an untrusted endpoint, an unresolvable/raising credential, a
        missing SDK, or any transport error ⇒ ``available=False`` with the error class name only —
        the pure statistical result always stands. The ONLY payload sent is the serialized PII-free
        enrichment projection (:meth:`~shared.contracts.LogFeatures.enrichment_payload`, structural
        signatures dropped); no raw log body/message/PII/template hash can reach the model.
        """
        try:
            return self._enrich(features)
        except Exception as exc:  # noqa: BLE001 - every edge failure must fail closed, class name only
            if self._fail_closed_observer is not None:
                with suppress(Exception):
                    self._fail_closed_observer()
            return LogAnomalyEnrichment(available=False, error=type(exc).__name__)

    def _enrich(self, features: LogFeatures) -> LogAnomalyEnrichment:
        """Validate region-pin + endpoint + credential, then send ONLY aggregate features."""
        if self._config is None:
            return LogAnomalyEnrichment(available=False, error="Unconfigured")
        # Refuse anything that is not the aggregate, PII-free features contract (defense in depth):
        # there is no path that carries a raw log here, and this makes that guarantee explicit.
        if not isinstance(features, LogFeatures):
            return LogAnomalyEnrichment(available=False, error="NonAggregateInput")

        # Region-pin BEFORE resolving any credential or validating the endpoint (fail closed early).
        enforce_region_pin(self._config.region, self._config.platform_region)
        # Validate the endpoint host BEFORE minting/handing over any token (SSRF/token guard).
        validate_openai_endpoint(self._config.endpoint)

        credential = (
            self._credential_provider() if self._credential_provider is not None else None
        )
        if credential is None:
            return LogAnomalyEnrichment(available=False, error="NoCredential")

        # The ONLY payload sent: the PII-free enrichment PROJECTION of the aggregate features.
        # ``enrichment_payload`` drops every structural-template signature (whose one-way-hash
        # preimage may embed residual lowercase keyword tokens) and keeps only counts/rates/level
        # tallies/percentiles/template count+fraction — never a raw log row or a template hash.
        features_json = json.dumps(features.enrichment_payload())
        transport = (
            self._transport if self._transport is not None else self._sdk_transport(credential)
        )
        advisory = transport(self._config.deployment, _SYSTEM_INSTRUCTION, features_json)
        if not isinstance(advisory, str):
            return LogAnomalyEnrichment(available=False, error="NonTextResponse")
        trimmed = advisory.strip()[: self._config.max_advisory_chars]
        return LogAnomalyEnrichment(available=True, advisory=trimmed or None)

    def _sdk_transport(self, credential: Any) -> LLMTransport:
        """Build a real transport that lazily wraps the Azure OpenAI SDK (keyless, validated).

        Delegates to the shared :func:`~shared.connectors.aoai.build_aoai_chat_transport` so the SDK
        stays lazy (a missing package fails closed via :class:`OpenAIEnrichmentSdkNotWired`) and the
        keyless credential is handed straight to the SDK — never logged. Unchanged #53 behavior.
        """
        assert self._config is not None  # noqa: S101 - _enrich guards None before calling
        return build_aoai_chat_transport(
            endpoint=self._config.endpoint,
            credential=credential,
            timeout_s=self._config.timeout_s,
            sdk_not_wired=OpenAIEnrichmentSdkNotWired,
        )


__all__ = [
    "CLIENT_KEY",
    "LogAnomalyEnrichment",
    "OpenAIEnrichmentClient",
    "OpenAIEnrichmentConfig",
    "OpenAIEnrichmentSdkNotWired",
    "RegionPinMismatch",
    "UntrustedOpenAIEndpoint",
]
