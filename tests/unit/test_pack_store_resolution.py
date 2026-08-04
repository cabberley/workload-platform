"""Runtime resolution of imported packs from the digest-addressed content store (issue #44).

Covers the end-to-end guarantee that a pack IMPORTED (registered) but never shipped in the
content-root image is resolved from the content store BY the registry's verified digest and
re-verified before execution — and that every fail-closed path (missing digest, tampered bytes,
mismatched type/ref, shipped-pack shadowing) resolves to NOTHING and never executes unverified or
shadowing bytes.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from packs_engine.canonical import canonical_bytes, canonical_digest
from packs_engine.content_store import LocalPackContentStore
from packs_engine.engine import PacksEngine
from packs_engine.registry import ImmutableVersionError, PackRegistry
from shared.contracts import Finding, PackType, ResourceNode, WorkloadGraph
from shared.module_base import run_module

WORKLOAD = "epic"


def _rule_pack(
    pack_id: str = "imported-rule", version: str = "1.0.0", *, tag: str = "backup"
) -> dict:
    return {
        "manifest": {
            "id": pack_id,
            "type": "rule",
            "name": "Imported rule pack",
            "version": version,
            "targets": [WORKLOAD],
            "author": "microsoft",
        },
        "body": {
            "rules": [
                {
                    "id": "imported-01",
                    "title": "VMs carry the required tag",
                    "resourceType": "Microsoft.Compute/virtualMachines",
                    "requiredTag": tag,
                    "severity": "high",
                    "description": "Imported pack rule.",
                }
            ]
        },
    }


class _SyntheticState:
    """Minimal read-only state exposing a single-workload estate for the module to assess."""

    def __init__(self, workload: str, estate: list[ResourceNode]) -> None:
        self._workload = workload
        self._estate = estate

    def list_workloads(self) -> list[str]:
        return [self._workload]

    def get_estate(self, workload: str) -> list[ResourceNode]:
        return self._estate if workload == self._workload else []

    def get_graph(self, workload: str) -> WorkloadGraph | None:
        return None

    def get_findings(self, workload: str, module: str | None = None) -> list[Finding]:
        return []

    def get_previous_findings(self, workload: str) -> list[Finding]:
        return []

    def get_previous_node_ids(self, workload: str) -> list[str]:
        return []


def _import(registry: PackRegistry, store: LocalPackContentStore, pack: dict) -> str:
    """Mirror the import single-writer: publish metadata, then store verified canonical bytes."""
    entry = registry.publish(pack)
    store.put(entry.digest, canonical_bytes(pack))
    return entry.digest


def _engine(tmp_path: Path) -> tuple[PacksEngine, PackRegistry, LocalPackContentStore]:
    """A PacksEngine over an EMPTY content root wired with a registry + content store."""
    root = tmp_path / "content"
    root.mkdir()
    registry = PackRegistry(index_path=root / "registry" / "index.json")
    store = LocalPackContentStore(tmp_path / "store")
    engine = PacksEngine(root, registry=registry, content_store=store)
    return engine, registry, store


# --------------------------------------------------------------------------------------
# Happy path: import -> assign -> run for a pack never shipped in the image.
# --------------------------------------------------------------------------------------
def test_imported_pack_resolves_from_store(tmp_path: Path) -> None:
    engine, registry, store = _engine(tmp_path)
    _import(registry, store, _rule_pack())

    packs = engine.load_for_workload(WORKLOAD, PackType.rule)
    assert [p.manifest.id for p in packs] == ["imported-rule"]
    assert packs[0].body["rules"][0]["requiredTag"] == "backup"


def test_imported_pack_runs_end_to_end_through_quality_checks(tmp_path: Path) -> None:
    from modules.quality_checks.module import QualityChecksModule

    engine, registry, store = _engine(tmp_path)
    _import(registry, store, _rule_pack(tag="backup-policy"))

    node = ResourceNode(id="vm-1", name="vm-1", type="Microsoft.Compute/virtualMachines", tags={})
    state = _SyntheticState(WORKLOAD, [node])

    result = run_module(
        QualityChecksModule(), scope={"workload": WORKLOAD}, state=state, packs=engine
    )
    # The imported pack's rule executed against the estate and produced a provenanced FAIL finding
    # (the node lacks the required tag) — proving the bytes resolved from the store and ran.
    assert result.ok is True
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.passed is False
    assert finding.packId == "imported-rule"
    assert finding.packVersion == "1.0.0"


# --------------------------------------------------------------------------------------
# Fail-closed paths — resolve to NOTHING, never execute unverified/tampered bytes.
# --------------------------------------------------------------------------------------
def test_missing_digest_in_store_fails_closed(tmp_path: Path) -> None:
    engine, registry, store = _engine(tmp_path)
    # Registry knows the pack (published) but its bytes were never stored.
    registry.publish(_rule_pack())

    assert engine.load_for_workload(WORKLOAD, PackType.rule) == []
    assert engine.load_all(pack_type=PackType.rule) == []


def test_tampered_store_bytes_fail_closed(tmp_path: Path) -> None:
    engine, registry, store = _engine(tmp_path)
    entry = registry.publish(_rule_pack())
    # Store bytes whose recomputed canonical digest does NOT match the registry digest.
    tampered = _rule_pack()
    tampered["body"]["rules"][0]["requiredTag"] = "attacker-controlled"
    assert canonical_digest(tampered) != entry.digest
    store.put(entry.digest, canonical_bytes(tampered))

    # The digest re-verification catches the mismatch → the pack resolves to nothing.
    assert engine.load_for_workload(WORKLOAD, PackType.rule) == []


def test_non_json_store_bytes_fail_closed(tmp_path: Path) -> None:
    engine, registry, store = _engine(tmp_path)
    entry = registry.publish(_rule_pack())
    store.put(entry.digest, b"\xff\xfenot json at all")

    assert engine.load_for_workload(WORKLOAD, PackType.rule) == []


def test_no_store_wired_serves_only_filesystem(tmp_path: Path) -> None:
    # Without a registry/store the engine is unchanged: an imported-but-unshipped pack is invisible.
    root = tmp_path / "content"
    root.mkdir()
    engine = PacksEngine(root)
    assert engine.load_all() == []


def test_shipped_pack_not_double_loaded_from_store(tmp_path: Path) -> None:
    root = tmp_path / "content"
    (root / "rules").mkdir(parents=True)
    pack = _rule_pack()

    (root / "rules" / "shipped.json").write_text(json.dumps(pack), encoding="utf-8")
    registry = PackRegistry(index_path=root / "registry" / "index.json")
    store = LocalPackContentStore(tmp_path / "store")
    # The SAME pack is both shipped on the filesystem AND imported into registry+store.
    _import(registry, store, pack)
    engine = PacksEngine(root, registry=registry, content_store=store)

    # It must appear exactly once (filesystem source), not twice.
    packs = engine.load_for_workload(WORKLOAD, PackType.rule)
    assert [p.manifest.id for p in packs] == ["imported-rule"]


# --------------------------------------------------------------------------------------
# Shipped packs are authoritative: an import of a MODIFIED same-``id@version`` pack (different
# digest ⇒ NOT digest-deduped) must NEVER shadow/override the shipped policy.
# --------------------------------------------------------------------------------------
def _ops_pack(*, critical_channel: str, default_channel: str, version: str = "1.0.0") -> dict:
    return {
        "manifest": {
            "id": "default-notify",
            "type": "ops",
            "name": "Default notify",
            "version": version,
            "targets": [],
            "author": "microsoft",
        },
        "body": {
            "routes": {"critical": critical_channel},
            "default": default_channel,
        },
    }


def test_imported_pack_cannot_shadow_shipped_pack_same_ref(tmp_path: Path) -> None:
    from modules.alerts.module import load_ops_routing

    root = tmp_path / "content"
    (root / "ops").mkdir(parents=True)
    # Shipped policy: critical findings page the on-call.
    shipped = _ops_pack(critical_channel="pager-critical", default_channel="pager-critical")
    (root / "ops" / "default-notify.json").write_text(json.dumps(shipped), encoding="utf-8")

    registry = PackRegistry(index_path=root / "registry" / "index.json")
    store = LocalPackContentStore(tmp_path / "store")
    # Attacker imports a MODIFIED default-notify@1.0.0 that routes critical to a black hole. It is a
    # different digest than the shipped pack, so digest de-dup does NOT catch it.
    attacker = _ops_pack(critical_channel="devnull", default_channel="devnull")
    assert canonical_digest(attacker) != canonical_digest(shipped)
    _import(registry, store, attacker)

    engine = PacksEngine(root, registry=registry, content_store=store)

    # Resolution yields ONLY the shipped pack for that ref — the import is skipped by ref.
    packs = engine.load_for_workload(WORKLOAD, PackType.ops)
    assert len(packs) == 1
    assert packs[0].body["routes"]["critical"] == "pager-critical"

    # And the downstream consumer that merges by reference (routes.update / default) is NOT
    # overridden: the shipped policy wins, so critical paging is not suppressed.
    routing = load_ops_routing(engine, WORKLOAD)
    assert routing["routes"]["critical"] == "pager-critical"
    assert routing["default"] == "pager-critical"


def test_imported_higher_version_cannot_override_shipped_pack_id(tmp_path: Path) -> None:
    from modules.alerts.module import load_ops_routing

    root = tmp_path / "content"
    (root / "ops").mkdir(parents=True)
    # Shipped policy at 1.0.0: critical findings page the on-call.
    shipped = _ops_pack(critical_channel="pager-critical", default_channel="pager-critical")
    (root / "ops" / "default-notify.json").write_text(json.dumps(shipped), encoding="utf-8")

    registry = PackRegistry(index_path=root / "registry" / "index.json")
    store = LocalPackContentStore(tmp_path / "store")
    # Attacker imports a signed, HIGHER-version default-notify@1.0.1 (a DIFFERENT ref than the
    # shipped @1.0.0, so the (id,version) gate alone would let it through) that routes critical to a
    # black hole. Merged last-wins by ``routes.update`` it would suppress paging — the fail-open.
    attacker = _ops_pack(critical_channel="devnull", default_channel="devnull", version="1.0.1")
    _import(registry, store, attacker)

    engine = PacksEngine(root, registry=registry, content_store=store)

    # Shipped packs win by ID at every version: only the shipped pack resolves for this id.
    packs = engine.load_for_workload(WORKLOAD, PackType.ops)
    assert [(p.manifest.id, p.manifest.version) for p in packs] == [("default-notify", "1.0.0")]

    # The shipped critical route is preserved — the higher-version import cannot override it.
    routing = load_ops_routing(engine, WORKLOAD)
    assert routing["routes"]["critical"] == "pager-critical"
    assert routing["default"] == "pager-critical"


def test_store_bytes_claiming_a_different_ref_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "content"
    root.mkdir()
    registry_dir = root / "registry"
    registry_dir.mkdir()
    store = LocalPackContentStore(tmp_path / "store")

    # Store a real, self-consistent pack (imported-rule@1.0.0) under ITS canonical digest.
    pack = _rule_pack()
    digest = canonical_digest(pack)
    store.put(digest, canonical_bytes(pack))

    # Hand-craft a registry index whose entry claims a DIFFERENT id@version than the stored bytes,
    # but carries the stored bytes' digest (so the digest re-verification would otherwise pass).
    index = {
        "version": 1,
        "entries": [
            {
                "id": "other-id",
                "version": "9.9.9",
                "type": "rule",
                "digest": digest,
                "createdAt": datetime.now(UTC).isoformat(),
                "signature": None,
            }
        ],
    }
    (registry_dir / "index.json").write_text(json.dumps(index), encoding="utf-8")

    engine = PacksEngine(
        root, registry=PackRegistry(index_path=registry_dir / "index.json"), content_store=store
    )
    # The manifest id/version (imported-rule@1.0.0) does not match the entry ref (other-id@9.9.9),
    # so the bytes are rejected even though the digest matched — fail closed, resolve nothing.
    assert engine.load_for_workload(WORKLOAD, PackType.rule) == []
    assert engine.load_all(pack_type=PackType.rule) == []


# --------------------------------------------------------------------------------------
# Shipped ops policy is AUTHORITATIVE PER KEY: a genuinely-new-id imported ops pack may only ADD
# routing keys the shipped policy does not define — it can NEVER override a shipped route/default/
# runbook (e.g. divert ``critical`` away from paging). Passes the shipped-ids gate (new id) yet
# must not suppress shipped critical paging in the last-wins merge.
# --------------------------------------------------------------------------------------
def _ops_pack_full(
    pack_id: str,
    *,
    routes: dict[str, str],
    default: str,
    runbook: str,
    version: str = "1.0.0",
) -> dict:
    return {
        "manifest": {
            "id": pack_id,
            "type": "ops",
            "name": pack_id,
            "version": version,
            "targets": [WORKLOAD],
            "author": "microsoft",
        },
        "body": {"routes": routes, "default": default, "runbook": runbook},
    }


def test_new_id_import_cannot_override_shipped_keys_but_can_add(tmp_path: Path) -> None:
    from modules.alerts.module import load_ops_routing

    root = tmp_path / "content"
    (root / "ops").mkdir(parents=True)
    # Shipped policy: critical pages the on-call; default pages; shipped runbook.
    shipped = _ops_pack_full(
        "default-notify",
        routes={"critical": "pager-critical", "high": "oncall"},
        default="pager-critical",
        runbook="kb/shipped-runbook",
    )
    (root / "ops" / "default-notify.json").write_text(json.dumps(shipped), encoding="utf-8")

    registry = PackRegistry(index_path=root / "registry" / "index.json")
    store = LocalPackContentStore(tmp_path / "store")
    # Attacker imports a genuinely NEW-ID ops pack (passes the shipped-ids gate). Its body redefines
    # the shipped ``critical`` route to a black hole AND redefines default/runbook, but also adds a
    # brand-new ``info`` route the shipped policy does not define.
    attacker = _ops_pack_full(
        "attacker-routing",
        routes={"critical": "devnull", "info": "slack"},
        default="devnull",
        runbook="kb/attacker-runbook",
    )
    _import(registry, store, attacker)

    engine = PacksEngine(root, registry=registry, content_store=store)

    # Both packs resolve (the new-id import is not shipped-shadowed): shipped + imported.
    packs = engine.load_for_workload(WORKLOAD, PackType.ops)
    assert {p.manifest.id for p in packs} == {"default-notify", "attacker-routing"}

    routing = load_ops_routing(engine, WORKLOAD)
    # Shipped keys WIN per key — the import cannot suppress critical paging or reroute default.
    assert routing["routes"]["critical"] == "pager-critical"
    assert routing["routes"]["high"] == "oncall"
    assert routing["default"] == "pager-critical"
    assert routing["runbook"] == "kb/shipped-runbook"
    # But the import CAN still augment the policy with a key shipped does not define.
    assert routing["routes"]["info"] == "slack"


def test_new_id_import_resolves_and_augments_when_no_shipped_collision(tmp_path: Path) -> None:
    from modules.alerts.module import load_ops_routing

    root = tmp_path / "content"
    (root / "ops").mkdir(parents=True)
    # Shipped policy defines only critical/default; no ``low`` route.
    shipped = _ops_pack_full(
        "default-notify",
        routes={"critical": "pager-critical"},
        default="pager-critical",
        runbook="kb/shipped-runbook",
    )
    (root / "ops" / "default-notify.json").write_text(json.dumps(shipped), encoding="utf-8")

    registry = PackRegistry(index_path=root / "registry" / "index.json")
    store = LocalPackContentStore(tmp_path / "store")
    # A well-behaved third-party import contributing only NEW keys (its own id namespace).
    addon = _ops_pack_full(
        "team-addon",
        routes={"low": "slack-low"},
        default="pager-critical",
        runbook="kb/shipped-runbook",
    )
    _import(registry, store, addon)

    engine = PacksEngine(root, registry=registry, content_store=store)
    routing = load_ops_routing(engine, WORKLOAD)
    # Genuinely-new keys from the import are applied; shipped keys remain intact.
    assert routing["routes"]["critical"] == "pager-critical"
    assert routing["routes"]["low"] == "slack-low"


def test_registry_forbids_two_digests_for_one_ref(tmp_path: Path) -> None:
    # Imported-vs-imported shadowing cannot arise: the registry rejects a re-publish of an existing
    # id@version under a different digest, so at most one store entry exists per ref.
    registry = PackRegistry(index_path=tmp_path / "registry" / "index.json")
    registry.publish(_rule_pack(tag="a"))
    with pytest.raises(ImmutableVersionError):
        registry.publish(_rule_pack(tag="b"))  # same ref, different content/digest

