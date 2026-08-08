"""Composition-root unit tests — keyless, fail-closed, guarded client/pack construction (#24).

These are Azure-free: with no Azure SDKs installed a client is simply *omitted*, never a crash.
No secret literals appear here — only Key Vault-backed env var names/values.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Mapping

import pytest

from cli.wiring import (
    ENV_AIOPS_LLM_DEPLOYMENT,
    ENV_AIOPS_LLM_ENDPOINT,
    ENV_AIOPS_LLM_REGION,
    ENV_ALERT_WEBHOOK_ALLOW_INSECURE_LOOPBACK,
    ENV_ALERT_WEBHOOK_URL,
    ENV_LOG_SAMPLE_WORKSPACE_ID,
    ENV_PLATFORM_REGION,
    ENV_SUBSCRIPTION_ID,
    ENV_SYSTEM_PULSE_BASE_URL,
    build_client_registry,
    build_packs_engine,
    resolve_packs_for_workload,
)
from packs_engine.engine import Pack
from packs_engine.registry import PackRegistry
from shared.contracts import PackManifest, PackType
from shared.module_base import Module, ModuleContext, build_default_registry, run_module

# A synthetic, clearly-fake webhook value (a Key Vault-backed URL in production) — not a secret.
FAKE_WEBHOOK_URL = "https://alerts.internal.invalid/hook"


# Issue #95: require_https_webhook now resolves a webhook DNS name and range-blocks SSRF-sensitive
# targets, failing closed on an unresolvable host. FAKE_WEBHOOK_URL's synthetic ``.invalid`` host is
# deliberately unresolvable, so resolve every DNS name to a fixed PUBLIC address here to keep these
# composition-root tests hermetic/offline (patches only the validator's thin resolver wrapper).
@pytest.fixture(autouse=True)
def _stub_public_dns(monkeypatch):
    monkeypatch.setattr(
        "modules.alerts.channels._resolve_host_ips",
        lambda _host: [ipaddress.ip_address("93.184.216.34")],
    )


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


# --------------------------------------------------------------------------------------
# Key Vault secret injection (#85): composition resolves the connector token BY identity when a
# vault URI is configured, and FAILS CLOSED when the vault cannot supply a required secret.
# --------------------------------------------------------------------------------------
class _FakeKvSecret:
    def __init__(self, value: str) -> None:
        self.value = value


class _FakeKvClient:
    """A ``SecretClient``-shaped stub injected in place of the real Azure SDK (no network)."""

    def __init__(self, secrets: dict[str, str]) -> None:
        self._secrets = secrets

    def get_secret(self, name: str) -> _FakeKvSecret:
        if name not in self._secrets:
            raise KeyError(name)  # stands in for azure ResourceNotFoundError → fail closed
        return _FakeKvSecret(self._secrets[name])


def test_build_client_registry_system_pulse_uses_key_vault_when_configured(monkeypatch):
    from shared.secret_provider import ENV_KEY_VAULT_URI, KeyVaultSecretProvider

    fake = _FakeKvClient({"system-pulse-read-token": "kv-token"})
    monkeypatch.setattr(KeyVaultSecretProvider, "_client_or_build", lambda self: fake)
    registry = build_client_registry(
        config={
            ENV_SYSTEM_PULSE_BASE_URL: "https://pulse.internal.invalid",
            ENV_KEY_VAULT_URI: "https://wp-vault.vault.azure.net",
        }
    )
    assert "system_pulse" in registry
    client = registry["system_pulse"]
    # The connector is wired to resolve BY identity through the provider (keyless).
    assert client._secret_provider is not None
    assert client._config.token_secret_name == "system-pulse-read-token"


def test_build_client_registry_fail_closed_when_vault_missing_required_token(monkeypatch):
    from shared.secret_provider import (
        ENV_KEY_VAULT_URI,
        KeyVaultSecretProvider,
        SecretResolutionError,
    )

    fake = _FakeKvClient({})  # vault configured but the required token is absent
    monkeypatch.setattr(KeyVaultSecretProvider, "_client_or_build", lambda self: fake)
    # Composition must REFUSE to start rather than wire a silently-broken connector.
    with pytest.raises(SecretResolutionError):
        build_client_registry(
            config={
                ENV_SYSTEM_PULSE_BASE_URL: "https://pulse.internal.invalid",
                ENV_KEY_VAULT_URI: "https://wp-vault.vault.azure.net",
            }
        )


def test_build_client_registry_system_pulse_env_fallback_when_no_vault():
    # No $WP_KEY_VAULT_URI ⇒ no provider ⇒ the connector uses the documented local-dev env fallback
    # (no fail-closed), keeping existing local/CI workflows working unchanged.
    registry = build_client_registry(
        config={ENV_SYSTEM_PULSE_BASE_URL: "https://pulse.internal.invalid"}
    )
    client = registry["system_pulse"]
    assert client._secret_provider is None
    assert client._config.token_secret_name is None


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
# log-anomaly edges (issue #53) — keyless, fail-closed, opt-in.
# --------------------------------------------------------------------------------------
def test_build_client_registry_log_sample_absent_without_credential(monkeypatch):
    # No credential ⇒ the log-sample edge is omitted even with a workspace id configured
    # (fail-closed by absence).
    monkeypatch.setattr("cli.wiring._build_credential", lambda: None)
    registry = build_client_registry(
        config={ENV_LOG_SAMPLE_WORKSPACE_ID: "00000000-0000-0000-0000-000000000000"}
    )
    assert "log_sample" not in registry


def test_build_client_registry_log_sample_present_with_credential(monkeypatch):
    monkeypatch.setattr("cli.wiring._build_credential", lambda: object())
    registry = build_client_registry(
        config={ENV_LOG_SAMPLE_WORKSPACE_ID: "00000000-0000-0000-0000-000000000000"}
    )
    assert "log_sample" in registry


def test_build_client_registry_log_sample_absent_without_workspace(monkeypatch):
    monkeypatch.setattr("cli.wiring._build_credential", lambda: object())
    registry = build_client_registry(config={})
    assert "log_sample" not in registry


def test_build_client_registry_llm_enrichment_present_when_fully_configured(monkeypatch):
    monkeypatch.setattr("cli.wiring._build_credential", lambda: object())
    registry = build_client_registry(
        config={
            ENV_AIOPS_LLM_ENDPOINT: "https://synthetic-fake.openai.azure.com",
            ENV_AIOPS_LLM_DEPLOYMENT: "fake-deployment",
            ENV_AIOPS_LLM_REGION: "westus3",
            ENV_PLATFORM_REGION: "westus3",
        }
    )
    assert "llm_enrichment" in registry


def test_build_client_registry_llm_enrichment_absent_without_platform_region(monkeypatch):
    # Missing the platform region ⇒ the edge is UNCONFIGURED and omitted (the pure result stands).
    monkeypatch.setattr("cli.wiring._build_credential", lambda: object())
    registry = build_client_registry(
        config={
            ENV_AIOPS_LLM_ENDPOINT: "https://synthetic-fake.openai.azure.com",
            ENV_AIOPS_LLM_DEPLOYMENT: "fake-deployment",
            ENV_AIOPS_LLM_REGION: "westus3",
        }
    )
    assert "llm_enrichment" not in registry


def test_build_client_registry_llm_enrichment_absent_without_credential(monkeypatch):
    monkeypatch.setattr("cli.wiring._build_credential", lambda: None)
    registry = build_client_registry(
        config={
            ENV_AIOPS_LLM_ENDPOINT: "https://synthetic-fake.openai.azure.com",
            ENV_AIOPS_LLM_DEPLOYMENT: "fake-deployment",
            ENV_AIOPS_LLM_REGION: "westus3",
            ENV_PLATFORM_REGION: "westus3",
        }
    )
    assert "llm_enrichment" not in registry


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


# --------------------------------------------------------------------------------------
# resolve_packs_for_workload — single deterministic version per id; assigned execution is bound to
# the registry's VERIFIED digest; unassigned falls back to the highest *valid semver*.
# --------------------------------------------------------------------------------------
def _pack(pack_id: str, version: str, *, x: int = 0) -> Pack:
    """A real :class:`Pack` (so ``.source`` yields a canonical digest matching the registry)."""
    manifest = PackManifest(id=pack_id, type=PackType.rule, name=pack_id, version=version)
    return Pack(manifest=manifest, body={"x": x})


class _Engine:
    """A packs engine stand-in returning fixed packs so resolution is observable."""

    def __init__(self, packs: list[Pack]) -> None:
        self._packs = packs
        self.marker = "real-engine"

    def load_for_workload(self, workload: str, pack_type: object) -> list[Pack]:
        return list(self._packs)

    def load_all(self, *, pack_type: object = None, verify_sig: bool = True) -> list[Pack]:
        return list(self._packs)


def _registry(tmp_path, *verified: Pack) -> PackRegistry:
    """A tmp registry seeded with the VERIFIED digests of ``verified`` packs (via their source)."""
    reg = PackRegistry(str(tmp_path / "index.json"))
    for pack in verified:
        reg.publish(pack.source)
    return reg


def _refs(packs: list[Pack]) -> set[tuple[str, str]]:
    return {(p.manifest.id, p.manifest.version) for p in packs}


def test_resolve_packs_none_passthrough(tmp_path):
    reg = _registry(tmp_path)
    assert resolve_packs_for_workload(None, {"waf": "1.0.0"}, reg) is None


def test_resolve_packs_unassigned_collapses_each_id_to_latest_semver(tmp_path):
    engine = _Engine(
        [
            _pack("waf", "1.0.0"),
            _pack("waf", "2.0.0"),
            _pack("waf", "10.0.0"),
            _pack("other", "5.0.0"),
        ]
    )
    # Documented fallback: with NO assignments each id resolves to a SINGLE, highest-semver pack
    # (10.0.0 > 2.0.0 — semver, not lexicographic) — never every version.
    pinned = resolve_packs_for_workload(engine, {}, _registry(tmp_path))
    loaded = pinned.load_for_workload("epic", object())  # type: ignore[union-attr]
    assert _refs(loaded) == {("waf", "10.0.0"), ("other", "5.0.0")}
    # load_all resolves identically.
    assert _refs(pinned.load_all()) == {("waf", "10.0.0"), ("other", "5.0.0")}  # type: ignore[union-attr]


def test_resolve_packs_unassigned_all_invalid_semver_runs_nothing(tmp_path):
    # MED: an id whose ONLY versions are non-semver must run NOTHING — never a lexicographic pick.
    engine = _Engine([_pack("waf", "banana"), _pack("waf", "not-semver")])
    pinned = resolve_packs_for_workload(engine, {}, _registry(tmp_path))
    assert pinned.load_for_workload("epic", object()) == []  # type: ignore[union-attr]


def test_resolve_packs_assigned_runs_only_digest_verified_pack(tmp_path):
    # HIGH: an assigned id runs EXACTLY its version and only the pack whose canonical digest matches
    # the registry's verified digest; the unassigned id falls back to its latest valid semver.
    waf1 = _pack("waf", "1.0.0", x=1)
    waf2 = _pack("waf", "2.0.0", x=2)
    other = _pack("other", "5.0.0")
    engine = _Engine([waf1, waf2, other])
    reg = _registry(tmp_path, waf1)  # only waf@1.0.0 is verified
    pinned = resolve_packs_for_workload(engine, {"waf": "1.0.0"}, reg)
    assert _refs(pinned.load_for_workload("epic", object())) == {  # type: ignore[union-attr]
        ("waf", "1.0.0"),
        ("other", "5.0.0"),
    }


def test_resolve_packs_assigned_tampered_content_runs_nothing(tmp_path):
    # HIGH: content-root bytes carrying the assigned id@version but a DIFFERENT digest than the
    # registry's verified digest must NOT run — fail closed, no substitute of another version.
    verified = _pack("waf", "1.0.0", x=1)
    reg = _registry(tmp_path, verified)  # registry records the digest of the x=1 bytes
    tampered = _pack("waf", "1.0.0", x=999)  # same ref, tampered content ⇒ different digest
    engine = _Engine([tampered, _pack("waf", "2.0.0", x=2)])
    pinned = resolve_packs_for_workload(engine, {"waf": "1.0.0"}, reg)
    assert pinned.load_for_workload("epic", object()) == []  # type: ignore[union-attr]


def test_resolve_packs_assigned_dedupes_identical_digest_copies(tmp_path):
    # HIGH: two identical-digest copies of the assigned pack ⇒ EXACTLY ONE runs (not both).
    verified = _pack("waf", "1.0.0", x=7)
    reg = _registry(tmp_path, verified)
    engine = _Engine([_pack("waf", "1.0.0", x=7), _pack("waf", "1.0.0", x=7)])
    pinned = resolve_packs_for_workload(engine, {"waf": "1.0.0"}, reg)
    loaded = pinned.load_for_workload("epic", object())  # type: ignore[union-attr]
    assert len(loaded) == 1
    assert (loaded[0].manifest.id, loaded[0].manifest.version) == ("waf", "1.0.0")


def test_resolve_packs_assigned_without_registry_entry_runs_nothing(tmp_path):
    # Fail closed: an assigned ref with no registry entry (never imported) runs nothing.
    engine = _Engine([_pack("waf", "1.0.0")])
    pinned = resolve_packs_for_workload(engine, {"waf": "1.0.0"}, _registry(tmp_path))
    assert pinned.load_for_workload("epic", object()) == []  # type: ignore[union-attr]


def test_resolve_packs_assigned_older_plus_unassigned_latest(tmp_path):
    waf1, waf2 = _pack("waf", "1.0.0", x=1), _pack("waf", "2.0.0", x=2)
    other3, other4 = _pack("other", "3.0.0"), _pack("other", "4.0.0")
    engine = _Engine([waf1, waf2, other3, other4])
    reg = _registry(tmp_path, waf1)  # assigned waf@1.0.0 is verified
    # 'waf' assigned to the OLDER 1.0.0 pins exactly there (digest-verified); unassigned 'other'
    # resolves to its latest (4.0.0). Neither id ever runs multiple versions.
    pinned = resolve_packs_for_workload(engine, {"waf": "1.0.0"}, reg)
    assert _refs(pinned.load_for_workload("epic", object())) == {  # type: ignore[union-attr]
        ("waf", "1.0.0"),
        ("other", "4.0.0"),
    }


def test_resolve_packs_delegates_unknown_attrs_to_wrapped_engine(tmp_path):
    engine = _Engine([_pack("waf", "1.0.0")])
    pinned = resolve_packs_for_workload(engine, {}, _registry(tmp_path))
    # Attributes the wrapper does not override delegate to the wrapped engine.
    assert pinned.marker == "real-engine"  # type: ignore[union-attr]
