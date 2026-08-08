"""Local ``StateStore`` tests for per-tenant imported packs + module config (issue #68).

Deterministic, Azure-free: the local sqlite ``LocalStateStore`` in an isolated ``tmp_path``. Each
test would fail without the corresponding put/get/list method on the backend. The ``scope`` field
is the tenant-namespace carrier the API's ``TenantScopedState`` threads (mirroring pack
assignments); at the raw store layer we drive it directly with disjoint scopes to prove the store
never crosses records between two scopes. All data is synthetic, clearly-fake — no PHI/PII.
"""
from __future__ import annotations

import pytest

from shared.contracts import ImportedPack, PackType, TenantModuleConfig
from shared.state import ImportConflictError, LocalStateStore, StateStore

SCOPE_A = "aaaaaaaa.__imports"
SCOPE_B = "bbbbbbbb.__imports"
MODULES_A = "aaaaaaaa.__modules"
MODULES_B = "bbbbbbbb.__modules"


@pytest.fixture()
def store(tmp_path) -> LocalStateStore:
    return LocalStateStore(str(tmp_path))


def _imported(
    scope: str,
    pack_id: str = "epic-core",
    version: str = "1.0.0",
    digest: str = "sha256:aaa",
    pack_type: PackType = PackType.workload,
    signature: str | None = None,
    key_id: str | None = None,
) -> ImportedPack:
    return ImportedPack(
        scope=scope,
        packId=pack_id,
        version=version,
        packType=pack_type,
        digest=digest,
        signature=signature,
        keyId=key_id,
        importedBy="tester",
    )


def test_local_store_still_satisfies_statestore_protocol(store: LocalStateStore) -> None:
    # The new imported-pack + module-config methods keep the local backend a structural StateStore.
    assert isinstance(store, StateStore)


# --------------------------------------------------------------------------------------
# Imported packs — put/get/list round-trips + scope isolation.
# --------------------------------------------------------------------------------------
def test_put_and_get_imported_pack_round_trips(store: LocalStateStore) -> None:
    assert store.get_imported_pack(SCOPE_A, "epic-core", "1.0.0") is None
    store.put_imported_pack(
        _imported(SCOPE_A, signature="sig-bytes", key_id="test-kid", pack_type=PackType.rule)
    )
    got = store.get_imported_pack(SCOPE_A, "epic-core", "1.0.0")
    assert got is not None
    assert got.packId == "epic-core"
    assert got.version == "1.0.0"
    assert got.packType is PackType.rule
    assert got.digest == "sha256:aaa"
    assert got.signature == "sig-bytes"
    assert got.keyId == "test-kid"
    assert got.importedBy == "tester"


def test_put_imported_pack_replaces_same_id_version(store: LocalStateStore) -> None:
    store.put_imported_pack(_imported(SCOPE_A, digest="sha256:aaa"))
    store.put_imported_pack(_imported(SCOPE_A, digest="sha256:bbb"))
    got = store.get_imported_pack(SCOPE_A, "epic-core", "1.0.0")
    assert got is not None and got.digest == "sha256:bbb"
    assert len(store.list_imported_packs(SCOPE_A)) == 1  # replaced, not duplicated


def test_imported_pack_get_is_scope_isolated(store: LocalStateStore) -> None:
    store.put_imported_pack(_imported(SCOPE_A, digest="sha256:aaa"))
    # Same id@version under a different scope is a DIFFERENT physical record.
    assert store.get_imported_pack(SCOPE_B, "epic-core", "1.0.0") is None
    store.put_imported_pack(_imported(SCOPE_B, digest="sha256:bbb"))
    a = store.get_imported_pack(SCOPE_A, "epic-core", "1.0.0")
    b = store.get_imported_pack(SCOPE_B, "epic-core", "1.0.0")
    assert a is not None and a.digest == "sha256:aaa"
    assert b is not None and b.digest == "sha256:bbb"


def test_list_imported_packs_is_scope_filtered_at_storage_layer(store: LocalStateStore) -> None:
    # FIX 4 (issue #68): the backend list is filtered BY SCOPE — a query for one tenant never
    # returns another tenant's rows even at the storage layer (no cross-tenant full-table scan).
    assert store.list_imported_packs(SCOPE_A) == []
    store.put_imported_pack(_imported(SCOPE_A, pack_id="a-pack"))
    store.put_imported_pack(_imported(SCOPE_B, pack_id="b-pack"))
    listed_a = store.list_imported_packs(SCOPE_A)
    listed_b = store.list_imported_packs(SCOPE_B)
    assert {(p.scope, p.packId) for p in listed_a} == {(SCOPE_A, "a-pack")}
    assert {(p.scope, p.packId) for p in listed_b} == {(SCOPE_B, "b-pack")}


# --------------------------------------------------------------------------------------
# Atomic per-tenant version immutability — try_record_imported_pack (FIX 2, issue #68).
# --------------------------------------------------------------------------------------
def test_try_record_imported_pack_inserts_when_absent(store: LocalStateStore) -> None:
    stored = store.try_record_imported_pack(_imported(SCOPE_A, digest="sha256:aaa"))
    assert stored.digest == "sha256:aaa"
    got = store.get_imported_pack(SCOPE_A, "epic-core", "1.0.0")
    assert got is not None and got.digest == "sha256:aaa"


def test_try_record_imported_pack_same_digest_is_idempotent(store: LocalStateStore) -> None:
    first = store.try_record_imported_pack(
        _imported(SCOPE_A, digest="sha256:aaa", key_id="kid-1")
    )
    # A second record of the SAME id@version + SAME digest returns the STORED record (no write),
    # preserving the first-writer's provenance.
    second = store.try_record_imported_pack(
        _imported(SCOPE_A, digest="sha256:aaa", key_id="kid-2")
    )
    assert second.keyId == first.keyId == "kid-1"
    assert len(store.list_imported_packs(SCOPE_A)) == 1


def test_try_record_imported_pack_different_digest_conflicts(store: LocalStateStore) -> None:
    store.try_record_imported_pack(_imported(SCOPE_A, digest="sha256:aaa"))
    # A different-digest re-import of the SAME id@version is an immutable-version conflict; the
    # FIRST content is preserved (never overwritten).
    with pytest.raises(ImportConflictError):
        store.try_record_imported_pack(_imported(SCOPE_A, digest="sha256:bbb"))
    got = store.get_imported_pack(SCOPE_A, "epic-core", "1.0.0")
    assert got is not None and got.digest == "sha256:aaa"


def test_try_record_imported_pack_is_scope_isolated(store: LocalStateStore) -> None:
    # The SAME id@version imported by two scopes with DIFFERENT content is not a conflict — the
    # records are physically disjoint per scope.
    store.try_record_imported_pack(_imported(SCOPE_A, digest="sha256:aaa"))
    store.try_record_imported_pack(_imported(SCOPE_B, digest="sha256:bbb"))
    a = store.get_imported_pack(SCOPE_A, "epic-core", "1.0.0")
    b = store.get_imported_pack(SCOPE_B, "epic-core", "1.0.0")
    assert a is not None and a.digest == "sha256:aaa"
    assert b is not None and b.digest == "sha256:bbb"


# --------------------------------------------------------------------------------------
# Module config — put/get round-trips + scope isolation + default-unset.
# --------------------------------------------------------------------------------------
def test_module_config_unset_is_none(store: LocalStateStore) -> None:
    assert store.get_module_config(MODULES_A) is None


def test_put_and_get_module_config_round_trips(store: LocalStateStore) -> None:
    store.put_module_config(TenantModuleConfig(scope=MODULES_A, disabled=["quality_checks"]))
    got = store.get_module_config(MODULES_A)
    assert got is not None
    assert got.scope == MODULES_A
    assert got.disabled == ["quality_checks"]


def test_put_module_config_replaces(store: LocalStateStore) -> None:
    store.put_module_config(TenantModuleConfig(scope=MODULES_A, disabled=["quality_checks"]))
    store.put_module_config(TenantModuleConfig(scope=MODULES_A, disabled=["drift"]))
    got = store.get_module_config(MODULES_A)
    assert got is not None and got.disabled == ["drift"]


def test_module_config_is_scope_isolated(store: LocalStateStore) -> None:
    store.put_module_config(TenantModuleConfig(scope=MODULES_A, disabled=["quality_checks"]))
    assert store.get_module_config(MODULES_B) is None
