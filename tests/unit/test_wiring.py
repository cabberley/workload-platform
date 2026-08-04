"""Composition-root unit tests — keyless, fail-closed, guarded client/pack construction (#24).

These are Azure-free: with no Azure SDKs installed a client is simply *omitted*, never a crash.
No secret literals appear here — only Key Vault-backed env var names/values.
"""
from __future__ import annotations

from collections.abc import Mapping

from cli.wiring import (
    ENV_ALERT_WEBHOOK_ALLOW_INSECURE_LOOPBACK,
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


# --------------------------------------------------------------------------------------
# HTTPS enforcement (#84): a non-HTTPS webhook URL is REJECTED fail-closed at composition time.
# --------------------------------------------------------------------------------------
def test_build_client_registry_rejects_cleartext_http_webhook():
    import pytest

    from modules.alerts.channels import InsecureWebhookError

    with pytest.raises(InsecureWebhookError):
        build_client_registry(config={ENV_ALERT_WEBHOOK_URL: "http://alerts.evil.invalid/hook"})


def test_build_client_registry_rejects_scheme_less_webhook():
    import pytest

    from modules.alerts.channels import InsecureWebhookError

    with pytest.raises(InsecureWebhookError):
        build_client_registry(config={ENV_ALERT_WEBHOOK_URL: "alerts.internal.invalid/hook"})


def test_build_client_registry_rejects_invalid_port_at_composition():
    # R1 MED 3: a malformed port fails closed at composition time, not late inside httpx at send().
    import pytest

    from modules.alerts.channels import InsecureWebhookError

    with pytest.raises(InsecureWebhookError):
        build_client_registry(config={ENV_ALERT_WEBHOOK_URL: "https://alerts.internal.invalid:bad/hook"})


def test_build_client_registry_invalid_port_error_is_sanitized():
    # R1 MED 2: a leaking urlparse/.port ValueError (which can echo user:token@host) must not reach
    # the surfaced error — a constant, URL-free message is raised instead.
    import pytest

    from modules.alerts.channels import InsecureWebhookError

    with pytest.raises(InsecureWebhookError) as excinfo:
        build_client_registry(
            config={ENV_ALERT_WEBHOOK_URL: "https://user:SECRET123@alerts.evil.invalid:bad/hook"}
        )
    message = str(excinfo.value)
    for secret in ("SECRET123", "user", "alerts.evil.invalid", "bad", "/hook"):
        assert secret not in message
    assert excinfo.value.__cause__ is None


def test_build_client_registry_error_does_not_leak_url_path():
    # No-PII: the fail-closed error must not echo the path/query (which may carry a token).
    import pytest

    from modules.alerts.channels import InsecureWebhookError

    with pytest.raises(InsecureWebhookError) as excinfo:
        build_client_registry(
            config={ENV_ALERT_WEBHOOK_URL: "http://alerts.evil.invalid/hook?token=SECRET123"}
        )
    assert "SECRET123" not in str(excinfo.value)
    assert "/hook" not in str(excinfo.value)


def test_build_client_registry_loopback_http_rejected_without_flag():
    import pytest

    from modules.alerts.channels import InsecureWebhookError

    with pytest.raises(InsecureWebhookError):
        build_client_registry(config={ENV_ALERT_WEBHOOK_URL: "http://127.0.0.1:9000/hook"})


def test_build_client_registry_loopback_http_accepted_with_flag():
    registry = build_client_registry(
        config={
            ENV_ALERT_WEBHOOK_URL: "http://127.0.0.1:9000/hook",
            ENV_ALERT_WEBHOOK_ALLOW_INSECURE_LOOPBACK: "true",
        }
    )
    assert "notifier" in registry


def test_build_client_registry_localhost_http_accepted_with_flag():
    registry = build_client_registry(
        config={
            ENV_ALERT_WEBHOOK_URL: "http://localhost:9000/hook",
            ENV_ALERT_WEBHOOK_ALLOW_INSECURE_LOOPBACK: "1",
        }
    )
    assert "notifier" in registry


def test_build_client_registry_spoofed_loopback_rejected_even_with_flag():
    # Spoofed-loopback guard: an attacker host that merely *contains* a loopback token must NOT be
    # treated as loopback, even with the opt-out set — cleartext to it stays rejected.
    import pytest

    from modules.alerts.channels import InsecureWebhookError

    for spoofed in ("http://127.0.0.1.evil.com/hook", "http://localhost.evil.com/hook"):
        with pytest.raises(InsecureWebhookError):
            build_client_registry(
                config={
                    ENV_ALERT_WEBHOOK_URL: spoofed,
                    ENV_ALERT_WEBHOOK_ALLOW_INSECURE_LOOPBACK: "true",
                }
            )


def test_build_client_registry_includes_system_pulse_when_base_url_configured():
    registry = build_client_registry(
        config={ENV_SYSTEM_PULSE_BASE_URL: "https://pulse.internal.invalid"}
    )
    assert "system_pulse" in registry


def test_wired_system_pulse_fail_closed_increments_process_metric():
    """MED 3: the composition root wires a registry-backed fail-closed observer into System Pulse.

    A real fail-closed fetch (an HTTP error) increments ``connector_fail_closed_total{module=
    "aiops"}`` on the SAME process registry the API exposes at ``/api/metrics``. Azure-free: we
    drive the connector's edge with a fake httpx transport, no network, no secret.
    """
    import httpx

    from shared.observability import METRIC_CONNECTOR_FAIL_CLOSED, process_metrics

    registry = build_client_registry(
        config={ENV_SYSTEM_PULSE_BASE_URL: "https://pulse.internal.invalid"}
    )
    client = registry["system_pulse"]
    # Force the edge to fail closed: a fake transport that errors + a resolvable fake token.
    client._client = httpx.Client(
        transport=httpx.MockTransport(lambda _req: httpx.Response(503, text="unavailable"))
    )
    client._credential_provider = lambda: "fake-read-token"

    proc = process_metrics()
    before = next(
        (s.value for s in proc.snapshot().counters if s.name == METRIC_CONNECTOR_FAIL_CLOSED),
        0,
    )
    result = client.fetch_raw()
    assert result.available is False  # still fails closed

    after = next(
        s.value
        for s in proc.snapshot().counters
        if s.name == METRIC_CONNECTOR_FAIL_CLOSED and s.labels == {"module": "aiops"}
    )
    assert after == before + 1


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
