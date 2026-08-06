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
    resolve_packs_for_workload,
)
from packs_engine.engine import Pack
from packs_engine.registry import PackRegistry
from shared.contracts import PackManifest, PackType
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
