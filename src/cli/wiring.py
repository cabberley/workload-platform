"""Composition root — the ONE place that knows concrete pack + edge-client types (issue #24).

The capability modules are pure by design: they look their dependencies up by well-known name in
``ModuleContext`` (``ctx.packs`` / ``ctx.clients[...]``) and never import a concrete Azure/edge
client. Something has to actually *build* those dependencies and inject them at the process
boundary — that is this file. It is deliberately the only module allowed to import the concrete
``AzureResourceGraphClient`` / ``AzureNetworkTopologyClient`` / ``WebhookChannel`` /
``SystemPulseClient`` classes and the packs engine, so ``shared`` and every module stay decoupled.

Guardrails honoured here:
  * **Keyless.** Every client authenticates with Managed Identity via ``DefaultAzureCredential``;
    no keys/secrets/connection strings are ever read or written. Only Key Vault-backed env var
    *names/values* (e.g. a webhook URL, a subscription id) are consumed.
  * **Guarded / lazy Azure imports.** Nothing Azure is imported at module import time. Every SDK
    import happens *inside* a function, so importing this composition root (and hence the API and
    worker) never requires an Azure SDK and ``mypy src`` stays clean without them installed.
  * **Fail closed.** A missing SDK, missing config, or missing content root leaves the pack/client
    simply **absent** — the module then fails closed on its own (packs=None / client lookup miss).
    These builders do not raise for absent/optional dependencies. The one deliberate exception is a
    security misconfiguration: a non-HTTPS outbound webhook URL is REJECTED at composition time
    (``InsecureWebhookError``) rather than silently accepted, so findings can never egress over
    cleartext.
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from packs_engine.content_store import PackContentStore, build_pack_content_store
from packs_engine.engine import PacksEngine
from packs_engine.registry import PackRegistry
from shared.observability import connector_fail_closed_observer

# Env var *names* the composition root reads. Values are supplied at runtime by identity / Key
# Vault — only the names live in code (keyless).
ENV_CONTENT_ROOT = "WP_CONTENT_ROOT"
ENV_SUBSCRIPTION_ID = "WP_SUBSCRIPTION_ID"
ENV_ALERT_WEBHOOK_URL = "WP_ALERT_WEBHOOK_URL"
# Documented opt-out gating a loopback-ONLY cleartext webhook (a local test sink). Truthy permits
# http:// only to 127.0.0.0/8 / ::1 / localhost; cleartext to any non-loopback host is ALWAYS
# rejected, even with this set. Keyless — only the env var name lives in code.
ENV_ALERT_WEBHOOK_ALLOW_INSECURE_LOOPBACK = "WP_ALERT_WEBHOOK_ALLOW_INSECURE_LOOPBACK"
ENV_SYSTEM_PULSE_BASE_URL = "SYSTEM_PULSE_BASE_URL"
SYSTEM_PULSE_TOKEN_ENV = "SYSTEM_PULSE_READ_TOKEN"  # noqa: S105 - env var *name*, not a secret
# Azure Monitor connector (aiops). A Log Analytics workspace id gates the logs edge; the metrics
# edge additionally needs a regional endpoint + namespace. All are Key Vault-backed *values*; only
# the env var names live in code (keyless — Managed Identity supplies the credential).
ENV_AZURE_MONITOR_WORKSPACE_ID = "AZURE_MONITOR_WORKSPACE_ID"
ENV_AZURE_MONITOR_RESOURCE_IDS = "AZURE_MONITOR_RESOURCE_IDS"
ENV_AZURE_MONITOR_METRICS_ENDPOINT = "AZURE_MONITOR_METRICS_ENDPOINT"
ENV_AZURE_MONITOR_METRIC_NAMESPACE = "AZURE_MONITOR_METRIC_NAMESPACE"

_DEFAULT_CONTENT_ROOT = "content"
_WEBHOOK_TIMEOUT_S = 10.0


def build_packs_engine() -> PacksEngine | None:
    """Construct the :class:`PacksEngine` rooted at ``$WP_CONTENT_ROOT`` (default ``content``).

    Returns ``None`` (fail closed) when the content root does not exist — modules already treat
    ``packs=None`` as "no content, assess nothing", so an absent pack directory degrades safely
    rather than crashing. Never raises.

    TODO(human): source the pack signing secret from Key Vault (by identity) and pass it as
    ``PacksEngine(root, signing_secret=...)`` so signatures — not just content hashes — are
    verified before execution. Keep the secret out of code/config literals.

    TODO(human): audit ``pack.import`` and ``pack.assign`` (issue #59). These are HELD behind the
    pack-import/admission decision (#37): there is no import/assign subsystem to emit from yet.
    When #37 lands, construct the engine (or the import service) with a store-backed
    ``AuditEmitter`` (as the API does via ``PacksEngine.attach_audit_emitter``) and emit
    ``AuditAction.pack_import`` on admission (with the success-path ``pack.verify``) and
    ``AuditAction.pack_assign`` when a pack is bound to a workload — actor = the importing
    principal id, subject/packId/packVersion = the admitted pack. Do NOT build the held subsystem
    here just to emit.
    """
    root = os.environ.get(ENV_CONTENT_ROOT, _DEFAULT_CONTENT_ROOT)
    try:
        if not Path(root).is_dir():
            return None
        # Issue #44: wire the metadata registry + the digest-addressed content store so the engine
        # can resolve IMPORTED packs (never shipped in the image) by their verified registry digest,
        # re-verifying ``canonical_digest == registry.digest`` before execution (fail closed). The
        # content-root filesystem stays the source for shipped packs; the store is additive. Both
        # are optional — if the store cannot be built from optional Azure deps, the engine still
        # serves shipped packs (fail closed for imports). An UNKNOWN backend still fails closed
        # (the selector raises) — a misconfiguration we refuse rather than silently downgrade.
        registry = PackRegistry(index_path=Path(root) / "registry" / "index.json")
        content_store = _build_pack_content_store_or_none()
        return PacksEngine(root, registry=registry, content_store=content_store)
    except OSError:
        return None


def _build_pack_content_store_or_none() -> PackContentStore | None:
    """Build the pack content store, or ``None`` when its optional Azure deps are unavailable.

    Mirrors the fail-closed-but-non-crashing contract of the other builders here: a missing Azure
    SDK / endpoint config leaves the store absent so the engine simply serves shipped packs and
    fails closed for imported ones. An UNKNOWN ``WORKLOADS_PACK_STORE_BACKEND`` is NOT swallowed —
    :func:`build_pack_content_store` raises ``ValueError`` and it propagates, so a misconfigured
    backend fails closed rather than silently degrading to the filesystem.
    """
    try:
        return build_pack_content_store()
    except (ImportError, RuntimeError, OSError):
        return None


def _build_credential() -> object | None:
    """Lazily build a keyless ``DefaultAzureCredential`` once, or ``None`` if unavailable.

    The ``azure-identity`` import is guarded and happens only here, inside the function, so this
    module imports with no Azure SDK present. On a missing SDK (or any construction error) we
    return ``None`` and the dependent clients are simply omitted (fail closed). No credential is
    ever constructed at import time.
    """
    try:
        from azure.identity import DefaultAzureCredential
    except ImportError:
        return None
    try:
        return DefaultAzureCredential()
    except Exception:  # noqa: BLE001 - never let credential construction crash wiring
        return None


def build_client_registry(*, config: Mapping[str, str] | None = None) -> dict[str, object]:
    """Build the keyless edge-client registry injected as ``ctx.clients`` at the boundary.

    Each client is constructed only when its config is present and its SDK imports; anything
    missing leaves that key **absent** so the consuming module fails closed on lookup. Does not
    raise for absent/optional dependencies — the one exception is a security misconfiguration: a
    non-HTTPS ``$WP_ALERT_WEBHOOK_URL`` is rejected fail-closed (``InsecureWebhookError``). Keys
    mirror what the modules read:

    * ``"resource_graph"`` (discovery) — needs ``azure-identity`` for a keyless credential.
    * ``"network"`` (dependency_graph) — needs ``$WP_SUBSCRIPTION_ID`` + ``azure-mgmt-network``.
    * ``"notifier"`` (alerts) — needs ``$WP_ALERT_WEBHOOK_URL`` (a Key Vault-backed value); the URL
      MUST be ``https://`` (cleartext rejected unless it is a loopback sink and
      ``$WP_ALERT_WEBHOOK_ALLOW_INSECURE_LOOPBACK`` is set).
    * ``"system_pulse"`` (aiops) — needs ``$SYSTEM_PULSE_BASE_URL``; the read token is resolved at
      the edge from the Key Vault-backed ``$SYSTEM_PULSE_READ_TOKEN`` (never embedded here).
    * ``"azure_monitor"`` (aiops) — needs ``$AZURE_MONITOR_WORKSPACE_ID`` (Log Analytics workspace,
      for the aggregated logs edge) **and** a keyless credential; optional
      ``$AZURE_MONITOR_RESOURCE_IDS`` / ``$AZURE_MONITOR_METRICS_ENDPOINT`` /
      ``$AZURE_MONITOR_METRIC_NAMESPACE`` enable the metrics edge. The SDK imports lazily at the
      edge, so a missing package leaves the key absent (fail closed) rather than crashing.

    ``config`` defaults to ``os.environ``; tests pass an explicit mapping.
    """
    cfg: Mapping[str, str] = config if config is not None else os.environ
    registry: dict[str, object] = {}
    credential = _build_credential()

    _add_resource_graph(registry, credential)
    _add_network(registry, cfg, credential)
    _add_notifier(registry, cfg)
    _add_system_pulse(registry, cfg)
    _add_azure_monitor(registry, cfg, credential)

    return registry


def _add_resource_graph(registry: dict[str, object], credential: object | None) -> None:
    """Discovery's keyless ARG client — omitted if no credential or the ARG SDK is absent.

    ``AzureResourceGraphClient`` defers its SDK import to query time, so constructing it can never
    signal a missing SDK on its own. We therefore PROBE ``azure.mgmt.resourcegraph`` here (guarded)
    before registering, so a missing SDK omits the key — consistent with this builder's documented
    fail-closed contract and with how the other builders behave.
    """
    if credential is None:
        return
    try:
        import azure.mgmt.resourcegraph  # noqa: F401 - probe SDK presence; fail closed if absent

        from modules.discovery.arg import AzureResourceGraphClient
    except ImportError:
        return
    registry["resource_graph"] = AzureResourceGraphClient(credential=credential)


def _add_network(
    registry: dict[str, object], cfg: Mapping[str, str], credential: object | None
) -> None:
    """dependency_graph's keyless network-topology client — needs a subscription id + SDK."""
    subscription_id = cfg.get(ENV_SUBSCRIPTION_ID)
    if not subscription_id or credential is None:
        return
    try:
        from modules.dependency_graph.topology import AzureNetworkTopologyClient

        # NOTE: this constructor imports azure-mgmt-network eagerly; a missing SDK raises
        # ImportError here and is caught below (fail closed → key absent).
        registry["network"] = AzureNetworkTopologyClient(
            subscription_id, credential=cast("Any", credential)
        )
    except Exception:  # noqa: BLE001 - missing azure-mgmt-network / any error → omit
        return


def _add_notifier(registry: dict[str, object], cfg: Mapping[str, str]) -> None:
    """alerts' webhook channel — the URL is a Key Vault-backed value, never a literal secret.

    Fails closed at composition time on a non-HTTPS webhook URL: a misconfigured cleartext
    ``http://`` endpoint is REJECTED (via :class:`InsecureWebhookError`) rather than silently
    accepted, so findings can never egress over the wire in the clear. Cleartext is tolerated only
    for an explicit loopback test sink gated behind
    ``$WP_ALERT_WEBHOOK_ALLOW_INSECURE_LOOPBACK``. The shared validator carries only scheme/host in
    its message, so no token in the URL path/query leaks (no-PII). An empty URL still leaves the
    key simply absent (module fails closed on lookup).
    """
    from modules.alerts.channels import WebhookChannel, require_https_webhook

    url = (cfg.get(ENV_ALERT_WEBHOOK_URL) or "").strip()
    if not url:
        return
    allow_insecure_loopback = (
        cfg.get(ENV_ALERT_WEBHOOK_ALLOW_INSECURE_LOOPBACK) or ""
    ).strip().lower() in {"1", "true", "yes", "on"}
    # Fail closed at composition time: a cleartext egress URL is a security misconfiguration we
    # refuse here (the channel re-validates as defense in depth).
    require_https_webhook(url, allow_insecure_loopback=allow_insecure_loopback)
    # The channel OWNS its hardened client (env proxies ignored + redirects not followed), so the
    # loopback cleartext exception cannot be routed off-box or TLS-downgraded via a 307 (issue #84).
    registry["notifier"] = WebhookChannel(
        url, timeout=_WEBHOOK_TIMEOUT_S, allow_insecure_loopback=allow_insecure_loopback
    )


def _add_system_pulse(registry: dict[str, object], cfg: Mapping[str, str]) -> None:
    """aiops' System Pulse connector — read token resolved at the edge from a Key Vault env."""
    base_url = (cfg.get(ENV_SYSTEM_PULSE_BASE_URL) or "").strip()
    if not base_url:
        return
    try:
        from modules.aiops.connectors.system_pulse import SystemPulseClient, SystemPulseConfig

        registry["system_pulse"] = SystemPulseClient(
            SystemPulseConfig(base_url=base_url, token_env=SYSTEM_PULSE_TOKEN_ENV),
            # Keyless observer (issue #60): a real fail-closed fetch increments
            # connector_fail_closed_total{module="aiops"} on the process registry the API exposes.
            fail_closed_observer=connector_fail_closed_observer("aiops"),
        )
    except Exception:  # noqa: BLE001 - fail closed: omit the connector, never crash wiring
        return


def _add_azure_monitor(
    registry: dict[str, object], cfg: Mapping[str, str], credential: object | None
) -> None:
    """aiops' Azure Monitor connector — keyless, read-only, guarded, fail-closed.

    Registered ONLY when a Log Analytics workspace id (``$AZURE_MONITOR_WORKSPACE_ID``, gating the
    aggregated logs edge) **and** a keyless credential are both present. A ``credential_provider``
    closure over the wiring credential keeps the connector keyless (Managed Identity via
    ``DefaultAzureCredential``) — no key/secret/connection string is ever read here. Optional
    ``$AZURE_MONITOR_RESOURCE_IDS`` (comma-separated) plus a regional metrics endpoint + namespace
    enable the metrics edge. The connector imports its Azure SDKs lazily at the edge, so a missing
    SDK simply fails closed at query time; this builder never raises — a missing workspace or
    credential leaves the key **absent** so the module fails closed on lookup.
    """
    workspace_id = (cfg.get(ENV_AZURE_MONITOR_WORKSPACE_ID) or "").strip()
    if not workspace_id or credential is None:
        return
    resource_ids = [
        rid.strip()
        for rid in (cfg.get(ENV_AZURE_MONITOR_RESOURCE_IDS) or "").split(",")
        if rid.strip()
    ]
    metrics_endpoint = (cfg.get(ENV_AZURE_MONITOR_METRICS_ENDPOINT) or "").strip() or None
    metric_namespace = (cfg.get(ENV_AZURE_MONITOR_METRIC_NAMESPACE) or "").strip() or None
    try:
        from modules.aiops.connectors.azure_monitor import (
            AzureMonitorClient,
            AzureMonitorConfig,
        )

        registry["azure_monitor"] = AzureMonitorClient(
            AzureMonitorConfig(
                workspace_id=workspace_id,
                resource_ids=resource_ids,
                metrics_endpoint=metrics_endpoint,
                metric_namespace=metric_namespace,
            ),
            credential_provider=lambda: credential,
            # Keyless observer (issue #60): a real fail-closed fetch increments
            # connector_fail_closed_total{module="aiops"} on the process registry the API exposes.
            fail_closed_observer=connector_fail_closed_observer("aiops"),
        )
    except Exception:  # noqa: BLE001 - fail closed: omit the connector, never crash wiring
        return
