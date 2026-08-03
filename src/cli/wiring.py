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
    None of these builders ever raise.
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

import httpx

from packs_engine.engine import PacksEngine

# Env var *names* the composition root reads. Values are supplied at runtime by identity / Key
# Vault — only the names live in code (keyless).
ENV_CONTENT_ROOT = "WP_CONTENT_ROOT"
ENV_SUBSCRIPTION_ID = "WP_SUBSCRIPTION_ID"
ENV_ALERT_WEBHOOK_URL = "WP_ALERT_WEBHOOK_URL"
ENV_SYSTEM_PULSE_BASE_URL = "SYSTEM_PULSE_BASE_URL"
SYSTEM_PULSE_TOKEN_ENV = "SYSTEM_PULSE_READ_TOKEN"  # noqa: S105 - env var *name*, not a secret

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
    """
    root = os.environ.get(ENV_CONTENT_ROOT, _DEFAULT_CONTENT_ROOT)
    try:
        if not Path(root).is_dir():
            return None
        return PacksEngine(root)
    except OSError:
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
    missing leaves that key **absent** so the consuming module fails closed on lookup. Never
    raises. Keys mirror what the modules read:

    * ``"resource_graph"`` (discovery) — needs ``azure-identity`` for a keyless credential.
    * ``"network"`` (dependency_graph) — needs ``$WP_SUBSCRIPTION_ID`` + ``azure-mgmt-network``.
    * ``"notifier"`` (alerts) — needs ``$WP_ALERT_WEBHOOK_URL`` (a Key Vault-backed value).
    * ``"system_pulse"`` (aiops) — needs ``$SYSTEM_PULSE_BASE_URL``; the read token is resolved at
      the edge from the Key Vault-backed ``$SYSTEM_PULSE_READ_TOKEN`` (never embedded here).

    ``config`` defaults to ``os.environ``; tests pass an explicit mapping.
    """
    cfg: Mapping[str, str] = config if config is not None else os.environ
    registry: dict[str, object] = {}
    credential = _build_credential()

    _add_resource_graph(registry, credential)
    _add_network(registry, cfg, credential)
    _add_notifier(registry, cfg)
    _add_system_pulse(registry, cfg)

    # TODO(human): azure_monitor extension point (issue #6). When #6 lands its keyless
    # AzureMonitorClient, wire it here in ~2 lines, guarded/fail-closed like the others, e.g.:
    #     if cfg.get("AZURE_MONITOR_WORKSPACE_ID") and credential is not None:
    #         from modules.aiops.connectors.azure_monitor import AzureMonitorClient
    #         registry["azure_monitor"] = AzureMonitorClient(credential=credential)
    # Do NOT import azure_monitor until #6 is on main.

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
    """alerts' webhook channel — the URL is a Key Vault-backed value, never a literal secret."""
    url = (cfg.get(ENV_ALERT_WEBHOOK_URL) or "").strip()
    if not url:
        return
    try:
        from modules.alerts.channels import WebhookChannel

        client = httpx.Client(timeout=_WEBHOOK_TIMEOUT_S, verify=True)
        registry["notifier"] = WebhookChannel(url, client)
    except Exception:  # noqa: BLE001 - fail closed: omit the channel, never crash wiring
        return


def _add_system_pulse(registry: dict[str, object], cfg: Mapping[str, str]) -> None:
    """aiops' System Pulse connector — read token resolved at the edge from a Key Vault env."""
    base_url = (cfg.get(ENV_SYSTEM_PULSE_BASE_URL) or "").strip()
    if not base_url:
        return
    try:
        from modules.aiops.connectors.system_pulse import SystemPulseClient, SystemPulseConfig

        registry["system_pulse"] = SystemPulseClient(
            SystemPulseConfig(base_url=base_url, token_env=SYSTEM_PULSE_TOKEN_ENV)
        )
    except Exception:  # noqa: BLE001 - fail closed: omit the connector, never crash wiring
        return
