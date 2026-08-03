"""Composition-root unit tests — keyless, fail-closed, guarded client/pack construction (#24).

These are Azure-free: with no Azure SDKs installed a client is simply *omitted*, never a crash.
No secret literals appear here — only Key Vault-backed env var names/values.
"""
from __future__ import annotations

from collections.abc import Mapping

from cli.wiring import (
    ENV_ALERT_WEBHOOK_URL,
    ENV_SUBSCRIPTION_ID,
    ENV_SYSTEM_PULSE_BASE_URL,
    build_client_registry,
    build_packs_engine,
)
from shared.module_base import Module, ModuleContext, build_default_registry, run_module

# A synthetic, clearly-fake webhook value (a Key Vault-backed URL in production) — not a secret.
FAKE_WEBHOOK_URL = "https://alerts.internal.invalid/hook"


# --------------------------------------------------------------------------------------
# build_client_registry — fail-closed: missing config/SDK omits the client, never raises.
# --------------------------------------------------------------------------------------
def test_build_client_registry_empty_config_never_raises_and_is_partial():
    registry = build_client_registry(config={})
    assert isinstance(registry, dict)
    # Config-gated clients are absent with no config (fail closed).
    assert "network" not in registry
    assert "notifier" not in registry
    assert "system_pulse" not in registry


def test_build_client_registry_includes_notifier_when_webhook_configured():
    registry = build_client_registry(config={ENV_ALERT_WEBHOOK_URL: FAKE_WEBHOOK_URL})
    assert "notifier" in registry


def test_build_client_registry_includes_system_pulse_when_base_url_configured():
    registry = build_client_registry(
        config={ENV_SYSTEM_PULSE_BASE_URL: "https://pulse.internal.invalid"}
    )
    assert "system_pulse" in registry


def test_build_client_registry_network_absent_without_sdk_even_if_subscription_set():
    # azure-mgmt-network is intentionally not an install requirement; a subscription id alone must
    # not produce a client — the guarded import fails closed and omits the key.
    registry = build_client_registry(config={ENV_SUBSCRIPTION_ID: "00000000-0000-0000-0000-0"})
    assert "network" not in registry


def test_build_client_registry_uses_os_environ_by_default(monkeypatch):
    monkeypatch.delenv(ENV_ALERT_WEBHOOK_URL, raising=False)
    monkeypatch.setenv(ENV_ALERT_WEBHOOK_URL, FAKE_WEBHOOK_URL)
    registry = build_client_registry()
    assert "notifier" in registry


def test_build_client_registry_omits_resource_graph_when_sdk_missing(monkeypatch):
    # Simulate azure.mgmt.resourcegraph being unavailable: setting the module to None makes
    # `import azure.mgmt.resourcegraph` raise ImportError. The guarded builder must then OMIT the
    # client (consistent with the documented fail-closed contract) rather than register an
    # unusable wrapper. Other config-gated clients still behave.
    import sys

    monkeypatch.setitem(sys.modules, "azure.mgmt.resourcegraph", None)
    registry = build_client_registry(config={ENV_ALERT_WEBHOOK_URL: FAKE_WEBHOOK_URL})
    assert "resource_graph" not in registry
    assert "notifier" in registry


# --------------------------------------------------------------------------------------
# build_packs_engine — missing content root returns None (fail closed), never raises.
# --------------------------------------------------------------------------------------
def test_build_packs_engine_missing_content_root_returns_none(monkeypatch, tmp_path):
    monkeypatch.setenv("WP_CONTENT_ROOT", str(tmp_path / "does-not-exist"))
    assert build_packs_engine() is None


def test_build_packs_engine_existing_content_root_returns_engine(monkeypatch, tmp_path):
    (tmp_path / "content").mkdir()
    monkeypatch.setenv("WP_CONTENT_ROOT", str(tmp_path / "content"))
    engine = build_packs_engine()
    assert engine is not None
    # It is rooted where we told it to be.
    assert str(engine.root).endswith("content")


# --------------------------------------------------------------------------------------
# run_module forwards packs AND clients verbatim into the ModuleContext (the #24 fix).
# --------------------------------------------------------------------------------------
class _CtxProbe(Module):
    """Captures the ModuleContext it is handed so a test can assert what was injected."""

    def __init__(self) -> None:
        self.seen: ModuleContext | None = None

    @property
    def manifest(self):  # type: ignore[override]
        return build_default_registry().get("discovery").manifest

    def run(self, ctx, *, scope=None):
        self.seen = ctx
        from shared.contracts import ModuleRunResult

        return ModuleRunResult(module=self.name, ok=True)


def test_run_module_forwards_packs_and_clients():
    probe = _CtxProbe()
    packs = object()
    clients: Mapping[str, object] = {"resource_graph": object()}
    run_module(probe, scope={}, packs=packs, clients=clients)
    assert probe.seen is not None
    assert probe.seen.packs is packs
    assert probe.seen.clients is clients


def test_run_module_defaults_leave_packs_none():
    probe = _CtxProbe()
    run_module(probe, scope={})
    assert probe.seen is not None
    assert probe.seen.packs is None
    assert probe.seen.clients == {}
