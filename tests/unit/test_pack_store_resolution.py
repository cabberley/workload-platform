"""Runtime resolution of imported packs from the digest-addressed content store (issue #44).

Covers the end-to-end guarantee that a pack IMPORTED (registered) but never shipped in the
content-root image is resolved from the content store BY the registry's verified digest and
re-verified before execution — and that every fail-closed path (missing digest, tampered bytes,
mismatched type/ref, shipped-pack shadowing) resolves to NOTHING and never executes unverified or
shadowing bytes.
"""
from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from packs_engine.canonical import canonical_bytes, canonical_digest
from packs_engine.content_store import LocalPackContentStore
from packs_engine.engine import PacksEngine
from packs_engine.registry import ImmutableVersionError, PackRegistry
from shared.contracts import (
    Finding,
    PackSignature,
    PackType,
    ResourceNode,
    TrustBundle,
    TrustedPublicKey,
    WorkloadGraph,
)
from shared.module_base import run_module
from shared.signing import ED25519_ALG, Ed25519Signer, TrustBundleVerifier, sign_pack

WORKLOAD = "epic"

# A synthetic in-test Ed25519 signer stands in for Microsoft's OFFLINE signer. The matching PUBLIC
# key is pinned into the trust bundle the engine verifies against. NO private key is committed.
_SIGNER = Ed25519Signer.generate("test-ms-key")


def _pinned_verifier() -> TrustBundleVerifier:
    """A trust bundle pinning only ``_SIGNER``'s PUBLIC key (like a real pinned Microsoft key)."""
    pub = base64.b64encode(_SIGNER.verifier().public_bytes()).decode("ascii")
    bundle = TrustBundle(
        keys=[TrustedPublicKey(key_id="test-ms-key", algorithm=ED25519_ALG, public_key=pub)]
    )
    return TrustBundleVerifier.from_bundle(bundle)


def _sign(pack: dict) -> PackSignature:
    """Sign ``pack`` with the pinned synthetic key (as Microsoft's OFFLINE signer would)."""
    return sign_pack(pack, _SIGNER)


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
    """Mirror the import single-writer: publish metadata WITH the pinned-verified detached
    signature (issue #89, R2), then store verified canonical bytes so the runtime can re-verify."""
    entry = registry.publish(pack, signature=_sign(pack))
    store.put(entry.digest, canonical_bytes(pack))
    return entry.digest


def _engine(tmp_path: Path) -> tuple[PacksEngine, PackRegistry, LocalPackContentStore]:
    """A PacksEngine over an EMPTY content root wired with a registry + content store + the pinned
    trust root so the runtime re-verifies imported-pack signatures (issue #89, R2)."""
    root = tmp_path / "content"
    root.mkdir()
    registry = PackRegistry(index_path=root / "registry" / "index.json")
    store = LocalPackContentStore(tmp_path / "store")
    engine = PacksEngine(
        root, registry=registry, content_store=store, import_verifier=_pinned_verifier()
    )
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
    # Registry knows the pack (published, signed) but its bytes were never stored.
    pack = _rule_pack()
    registry.publish(pack, signature=_sign(pack))

    assert engine.load_for_workload(WORKLOAD, PackType.rule) == []
    assert engine.load_all(pack_type=PackType.rule) == []


def test_tampered_store_bytes_fail_closed(tmp_path: Path) -> None:
    engine, registry, store = _engine(tmp_path)
    pack = _rule_pack()
    entry = registry.publish(pack, signature=_sign(pack))
    # Store bytes whose recomputed canonical digest does NOT match the registry digest.
    tampered = _rule_pack()
    tampered["body"]["rules"][0]["requiredTag"] = "attacker-controlled"
    assert canonical_digest(tampered) != entry.digest
    store.put(entry.digest, canonical_bytes(tampered))

    # The digest re-verification catches the mismatch → the pack resolves to nothing.
    assert engine.load_for_workload(WORKLOAD, PackType.rule) == []


def test_non_json_store_bytes_fail_closed(tmp_path: Path) -> None:
    engine, registry, store = _engine(tmp_path)
    pack = _rule_pack()
    entry = registry.publish(pack, signature=_sign(pack))
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
    engine = PacksEngine(
        root, registry=registry, content_store=store, import_verifier=_pinned_verifier()
    )

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

    engine = PacksEngine(
        root, registry=registry, content_store=store, import_verifier=_pinned_verifier()
    )

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

    engine = PacksEngine(
        root, registry=registry, content_store=store, import_verifier=_pinned_verifier()
    )

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
        root,
        registry=PackRegistry(index_path=registry_dir / "index.json"),
        content_store=store,
        import_verifier=_pinned_verifier(),
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

    engine = PacksEngine(
        root, registry=registry, content_store=store, import_verifier=_pinned_verifier()
    )

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

    engine = PacksEngine(
        root, registry=registry, content_store=store, import_verifier=_pinned_verifier()
    )
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


# --------------------------------------------------------------------------------------
# Issue #89, R2 — the runtime resolver INDEPENDENTLY re-verifies each imported pack's persisted
# detached signature against the pinned trust bundle. A digest match is INTEGRITY, not trust: a
# legacy/pre-fix/attacker-crafted dist that recorded a digest WITHOUT a pinned-verified signature
# must be rejected fail-closed at runtime resolution (never activated).
# --------------------------------------------------------------------------------------
def _index_path(tmp_path: Path) -> Path:
    return tmp_path / "content" / "registry" / "index.json"


def _write_index(tmp_path: Path, document: dict) -> None:
    path = _index_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document), encoding="utf-8")


def test_pinned_signed_import_resolves_and_activates_at_runtime(tmp_path: Path) -> None:
    # (b) A pack admitted through the pinned gate (signature persisted, key pinned) STILL resolves
    # and activates at runtime — the re-verification passes for a genuinely-trusted import.
    engine, registry, store = _engine(tmp_path)
    _import(registry, store, _rule_pack(pack_id="trusted-import", tag="backup"))

    packs = engine.load_for_workload(WORKLOAD, PackType.rule)
    assert [p.manifest.id for p in packs] == ["trusted-import"]
    assert packs[0].imported is True


def test_legacy_v1_dist_rejected_at_runtime(tmp_path: Path) -> None:
    # (a) The reviewer's legacy-bypass PoC: a dist whose registry/store was written WITHOUT a
    # persisted pinned signature (a v1 index) is REJECTED at runtime resolution even though the
    # stored bytes' digest matches the recorded digest. The pre-fix 'evil-import' no longer loads.
    engine, registry, store = _engine(tmp_path)
    evil = _rule_pack(pack_id="evil-import", tag="attacker")
    digest = canonical_digest(evil)
    store.put(digest, canonical_bytes(evil))
    _write_index(
        tmp_path,
        {
            "version": 1,
            "entries": [
                {
                    "id": "evil-import",
                    "version": "1.0.0",
                    "type": "rule",
                    "digest": digest,
                    "createdAt": datetime.now(UTC).isoformat(),
                    "signature": None,
                }
            ],
        },
    )
    # Digest matches, but there is no pinned-verified signature → fail closed, resolve nothing.
    assert engine.load_for_workload(WORKLOAD, PackType.rule) == []
    assert [p.manifest.id for p in engine.load_all(pack_type=PackType.rule)] == []


def test_v2_signatureless_entry_rejected_at_runtime(tmp_path: Path) -> None:
    # (a/c) A v2 entry published WITHOUT a persisted detached signature (legacy-untrusted) is
    # skipped at runtime even though its bytes are present and digest-consistent.
    engine, registry, store = _engine(tmp_path)
    pack = _rule_pack(pack_id="unsigned-import")
    entry = registry.publish(pack)  # no signature persisted → legacy-untrusted v2 entry
    assert entry.signature is None and entry.key_id is None
    store.put(entry.digest, canonical_bytes(pack))

    assert engine.load_for_workload(WORKLOAD, PackType.rule) == []


def test_v1_index_parses_but_entries_are_legacy_skipped(tmp_path: Path) -> None:
    # (c) Schema bump: a v1 index still PARSES (no crash — registry.list works) but its entries are
    # treated as legacy-untrusted and skipped by the runtime resolver.
    engine, registry, store = _engine(tmp_path)
    pack = _rule_pack(pack_id="v1-legacy")
    digest = canonical_digest(pack)
    store.put(digest, canonical_bytes(pack))
    _write_index(
        tmp_path,
        {
            "version": 1,
            "entries": [
                {
                    "id": "v1-legacy",
                    "version": "1.0.0",
                    "type": "rule",
                    "digest": digest,
                    "createdAt": datetime.now(UTC).isoformat(),
                    "signature": None,
                }
            ],
        },
    )
    # The v1 index parses without raising (backward compatible) and the entry is present...
    listed = registry.list(PackType.rule)
    assert [e.ref.id for e in listed] == ["v1-legacy"]
    assert listed[0].signature is None and listed[0].key_id is None  # flagged legacy-untrusted
    # ...but it is fail-closed at runtime resolution.
    assert engine.load_for_workload(WORKLOAD, PackType.rule) == []


def test_tampered_persisted_signature_rejected_at_runtime(tmp_path: Path) -> None:
    # (d) A TAMPERED persisted signature (structure still self-consistent, crypto invalid) is
    # rejected at runtime — the pinned-key cryptographic check fails closed.
    engine, registry, store = _engine(tmp_path)
    _import(registry, store, _rule_pack(pack_id="tampered-sig"))

    # Corrupt only the base64 signature bytes of the persisted PackSignature (keep the covered
    # canonical_digest intact so the structural pre-check still passes but the crypto verify fails).
    path = _index_path(tmp_path)
    document = json.loads(path.read_text(encoding="utf-8"))
    stored = json.loads(document["entries"][0]["signature"])
    stored["signature"] = base64.b64encode(b"\x00" * 64).decode("ascii")
    document["entries"][0]["signature"] = json.dumps(stored)
    path.write_text(json.dumps(document), encoding="utf-8")

    assert engine.load_for_workload(WORKLOAD, PackType.rule) == []


def test_import_signed_by_unpinned_key_rejected_at_runtime(tmp_path: Path) -> None:
    # (d) A signature whose key_id is NOT pinned in the trust bundle is rejected at runtime, even
    # though the signature is internally valid for the (unpinned) rogue key.
    engine, registry, store = _engine(tmp_path)
    rogue = Ed25519Signer.generate("rogue-key")  # NOT pinned in _pinned_verifier()
    pack = _rule_pack(pack_id="rogue-import")
    entry = registry.publish(pack, signature=sign_pack(pack, rogue))
    assert entry.key_id == "rogue-key"
    store.put(entry.digest, canonical_bytes(pack))

    assert engine.load_for_workload(WORKLOAD, PackType.rule) == []


def test_no_trust_root_wired_imports_resolve_to_nothing(tmp_path: Path) -> None:
    # (e) With NO import verifier wired, imported entries resolve to nothing (fail closed) even for
    # a properly-signed pack — the runtime cannot verify imports, so it refuses to activate them.
    root = tmp_path / "content"
    root.mkdir()
    registry = PackRegistry(index_path=root / "registry" / "index.json")
    store = LocalPackContentStore(tmp_path / "store")
    engine = PacksEngine(root, registry=registry, content_store=store)  # import_verifier=None
    _import(registry, store, _rule_pack(pack_id="orphan-import"))

    assert engine.load_for_workload(WORKLOAD, PackType.rule) == []
    assert engine.load_all(pack_type=PackType.rule) == []

