"""Shared, keyless in-boundary Azure OpenAI (AOAI) edge machinery.

Factored out of :mod:`modules.aiops.connectors.openai_enrichment` (issue #53) so that BOTH the
log-anomaly enrichment edge and the issue #54 grounded-RCA-explanation edge reuse the SAME guardrail
primitives instead of duplicating them:

* :data:`COGNITIVE_SCOPE` — the token scope minted for a validated, trusted AOAI host.
* :data:`TRUSTED_AOAI_HOST_SUFFIXES` — the per-cloud trusted data-plane host suffixes.
* :func:`validate_openai_endpoint` — a pure, fail-closed SSRF/token-replay endpoint validator.
* :func:`enforce_region_pin` — the region-pin check (deployment region must equal platform region).
* :func:`build_aoai_chat_transport` — the lazy Azure OpenAI SDK chat transport builder.
* :class:`RegionPinMismatch` / :class:`UntrustedOpenAIEndpoint` / :class:`AoaiSdkNotWired` — the
  fail-closed exception types. Their **class names** are what an edge surfaces as its error string,
  so they are stable and carry no body/token.

No Azure/vendor SDK is imported at module import time — the SDK stays lazy inside the transport
built by :func:`build_aoai_chat_transport`, so ``mypy src`` and unit tests remain Azure-free.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

# The token scope handed to the credential for Azure OpenAI (Cognitive Services). Only ever used to
# mint a bearer token for a validated, trusted endpoint host.
COGNITIVE_SCOPE = "https://cognitiveservices.azure.com/.default"

# Trusted Azure OpenAI / Cognitive Services data-plane host suffixes, per cloud. The credential is
# only ever handed to a client constructed with a host under one of these suffixes.
TRUSTED_AOAI_HOST_SUFFIXES: tuple[str, ...] = (
    ".openai.azure.com",  # Azure public cloud (Azure OpenAI)
    ".cognitiveservices.azure.com",  # Azure public cloud (Cognitive Services)
    ".openai.azure.us",  # Azure US Government
    ".cognitiveservices.azure.us",  # Azure US Government
    ".openai.azure.cn",  # Azure China (21Vianet)
    ".cognitiveservices.azure.cn",  # Azure China (21Vianet)
)

# An injected transport: given (deployment, system_instruction, user_payload_json) return advisory
# text. The real backend lazily imports the Azure OpenAI SDK; edges inject a fake so nothing touches
# the network.
AoaiChatTransport = Callable[[str, str, str], str]


class RegionPinMismatch(ValueError):
    """Raised when the Azure OpenAI region does not equal the platform region — fail closed."""


class UntrustedOpenAIEndpoint(ValueError):
    """Raised when the configured endpoint is not a trusted Azure OpenAI host — fail closed."""


class AoaiSdkNotWired(RuntimeError):
    """Raised when the optional Azure OpenAI SDK cannot be imported — fail closed."""


def validate_openai_endpoint(endpoint: str) -> str:
    """Validate an Azure OpenAI endpoint against the trusted hosts — pure, fail-closed.

    Rejects anything that could exfiltrate the Managed-Identity token (SSRF / token replay):
    requires ``https://``, forbids userinfo, explicit ports, and any query/fragment, and requires a
    real subdomain under a trusted ``*.openai.azure.*`` / ``*.cognitiveservices.azure.*`` suffix.
    Returns the normalized ``https://<host>`` on success; raises :class:`UntrustedOpenAIEndpoint`
    otherwise (before any token is minted). Never logs the endpoint value.
    """
    parts = urlsplit(endpoint.strip())
    if parts.scheme != "https":
        raise UntrustedOpenAIEndpoint("openai endpoint must use https")
    if parts.username or parts.password:
        raise UntrustedOpenAIEndpoint("openai endpoint must not carry userinfo")
    if parts.query or parts.fragment:
        raise UntrustedOpenAIEndpoint("openai endpoint must not carry a query or fragment")
    try:
        port = parts.port
    except ValueError as exc:
        raise UntrustedOpenAIEndpoint("openai endpoint has an invalid port") from exc
    if port is not None:
        raise UntrustedOpenAIEndpoint("openai endpoint must not specify a port")
    host = (parts.hostname or "").lower()
    for suffix in TRUSTED_AOAI_HOST_SUFFIXES:
        if host.endswith(suffix) and len(host) > len(suffix):
            return f"https://{host}"
    raise UntrustedOpenAIEndpoint("openai endpoint host is not a trusted Azure OpenAI host")


def enforce_region_pin(region: str, platform_region: str) -> None:
    """Fail closed unless the AOAI deployment region equals the platform region (region-pin).

    Both are supplied by the composition root. A mismatch raises :class:`RegionPinMismatch` with NO
    call made — the edge stays in-boundary (a deployment in another region is refused).
    """
    if region.strip().lower() != platform_region.strip().lower():
        raise RegionPinMismatch("azure openai region is not pinned to the platform region")


def build_aoai_chat_transport(
    *,
    endpoint: str,
    credential: Any,
    timeout_s: float,
    sdk_not_wired: type[Exception] = AoaiSdkNotWired,
) -> AoaiChatTransport:
    """Build a real transport that lazily wraps the Azure OpenAI SDK (keyless, validated).

    The SDK import is lazy so importing this module never needs the package; a missing package fails
    closed via ``sdk_not_wired`` (each edge passes its own so the surfaced error class name stays
    stable). The credential is handed straight to the keyless SDK — never logged. The endpoint is
    re-validated at call time (defense in depth) before any token is minted.
    """

    def _transport(deployment: str, system_instruction: str, user_payload_json: str) -> str:
        validated = validate_openai_endpoint(endpoint)
        try:
            from azure.ai.inference import (
                ChatCompletionsClient,  # noqa: PLC0415 - lazy edge import
            )
            from azure.ai.inference.models import (  # noqa: PLC0415 - lazy edge import
                SystemMessage,
                UserMessage,
            )
        except ImportError as exc:
            raise sdk_not_wired(
                "azure-ai-inference is not installed; the AOAI edge is unavailable"
            ) from exc
        client = ChatCompletionsClient(
            endpoint=f"{validated}/openai/deployments/{deployment}",
            credential=credential,
            credential_scopes=[COGNITIVE_SCOPE],
        )
        try:
            response = client.complete(
                messages=[
                    SystemMessage(content=system_instruction),
                    UserMessage(content=user_payload_json),
                ],
                timeout=timeout_s,
            )
            choice = response.choices[0]
            content = choice.message.content
            return content if isinstance(content, str) else ""
        finally:
            close = getattr(client, "close", None)
            if callable(close):
                close()

    return _transport


__all__ = [
    "COGNITIVE_SCOPE",
    "TRUSTED_AOAI_HOST_SUFFIXES",
    "AoaiChatTransport",
    "AoaiSdkNotWired",
    "RegionPinMismatch",
    "UntrustedOpenAIEndpoint",
    "build_aoai_chat_transport",
    "enforce_region_pin",
    "validate_openai_endpoint",
]
