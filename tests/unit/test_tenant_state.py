"""Unit tests for the TenantScopedState facade over the real LocalStateStore (issue #65).

Azure-free and hermetic: each test drives two TenantScopedState views (tenant A and tenant B) over
ONE isolated ``LocalStateStore`` in ``tmp_path`` and proves the isolation invariant end to end at
the state layer — a workload NAME shared by two tenants never leaks state or read models across
them, and ``list_workloads`` only ever returns the calling tenant's workloads. Synthetic fixtures
only (no PHI/PII).
"""
from __future__ import annotations

import pytest

from api.app.tenant_state import TenantScopedState
from shared.contracts import (
    Finding,
    ImportedPack,
    PackType,
    ResourceNode,
    Severity,
    SourceReference,
    TenancyMode,
    TenantContext,
    WorkloadGraph,
)
from shared.state import ImportConflictError, LocalStateStore

TENANT_A = "00000000-0000-0000-0000-00000000000a"
TENANT_B = "00000000-0000-0000-0000-00000000000b"


def _ctx(tenant_id: str) -> TenantContext:
    return TenantContext(tenant_id=tenant_id, mode=TenancyMode.multi)


def _node(node_id: str, workload: str) -> ResourceNode:
    return ResourceNode(
        id=node_id, name=node_id, type="Microsoft.Compute/virtualMachines", workload=workload
    )


def _finding(finding_id: str, node_id: str) -> Finding:
    return Finding(
        id=finding_id,
        module="quality_checks",
        title="synthetic finding",
        passed=False,
        severity=Severity.high,
        nodeId=node_id,
        packId="pack",
        packVersion="1.0.0",
        evidence=[SourceReference(kind="resource", id=node_id)],
    )


@pytest.fixture()
def inner(tmp_path) -> LocalStateStore:
    return LocalStateStore(str(tmp_path))


@pytest.fixture()
def scoped_a(inner: LocalStateStore) -> TenantScopedState:
    return TenantScopedState(inner, _ctx(TENANT_A))


@pytest.fixture()
def scoped_b(inner: LocalStateStore) -> TenantScopedState:
    return TenantScopedState(inner, _ctx(TENANT_B))


# --------------------------------------------------------------------------------------
# Estate read model — no cross-tenant read or overwrite.
# --------------------------------------------------------------------------------------
def test_estate_is_isolated_between_tenants(scoped_a, scoped_b) -> None:
    scoped_a.put_estate("epic", [_node("vm-a", "epic")])
    scoped_b.put_estate("epic", [_node("vm-b", "epic")])

    a_ids = [n.id for n in scoped_a.get_estate("epic")]
    b_ids = [n.id for n in scoped_b.get_estate("epic")]
    assert a_ids == ["vm-a"]
    assert b_ids == ["vm-b"]


def test_other_tenant_sees_nothing_for_unwritten_workload(scoped_a, scoped_b) -> None:
    scoped_a.put_estate("epic", [_node("vm-a", "epic")])
    assert scoped_b.get_estate("epic") == []


def test_graph_is_isolated_between_tenants(scoped_a, scoped_b) -> None:
    scoped_a.put_graph("epic", WorkloadGraph(nodes=[_node("vm-a", "epic")], edges=[]))
    assert scoped_a.get_graph("epic") is not None
    assert scoped_b.get_graph("epic") is None


def test_findings_are_isolated_between_tenants(scoped_a, scoped_b) -> None:
    scoped_a.add_findings("epic", [_finding("f-a", "vm-a")])
    scoped_b.add_findings("epic", [_finding("f-b", "vm-b")])
    assert [f.id for f in scoped_a.get_findings("epic")] == ["f-a"]
    assert [f.id for f in scoped_b.get_findings("epic")] == ["f-b"]


# --------------------------------------------------------------------------------------
# list_workloads — only the calling tenant's workloads surface (with logical names).
# --------------------------------------------------------------------------------------
def test_list_workloads_filters_by_tenant(scoped_a, scoped_b) -> None:
    scoped_a.put_estate("epic", [_node("vm-a", "epic")])
    scoped_a.put_estate("citrix", [_node("vm-a2", "citrix")])
    scoped_b.put_estate("epic", [_node("vm-b", "epic")])

    assert scoped_a.list_workloads() == ["citrix", "epic"]
    assert scoped_b.list_workloads() == ["epic"]


def test_list_workloads_returns_logical_names_not_composite(scoped_a) -> None:
    scoped_a.put_estate("epic", [_node("vm-a", "epic")])
    names = scoped_a.list_workloads()
    assert names == ["epic"]
    assert all("." not in n for n in names)


def test_inner_store_holds_composite_key_not_bare_workload(scoped_a, inner) -> None:
    """Defense-in-depth: the physical key in the underlying store is tenant-namespaced."""
    scoped_a.put_estate("epic", [_node("vm-a", "epic")])
    raw_keys = inner.list_workloads()
    assert raw_keys != ["epic"]  # never a bare workload name
    assert all(key != "epic" for key in raw_keys)


# --------------------------------------------------------------------------------------
# Snapshot / drift baseline stays per-tenant.
# --------------------------------------------------------------------------------------
def test_snapshot_is_scoped_per_tenant(scoped_a, scoped_b) -> None:
    scoped_a.put_estate("epic", [_node("vm-a", "epic")])
    scoped_b.put_estate("epic", [_node("vm-b", "epic")])
    snap_a = scoped_a.snapshot("epic")
    snap_b = scoped_b.snapshot("epic")
    assert snap_a != snap_b
    # After snapshot, each tenant's previous-node-ids reflect ONLY its own estate.
    assert scoped_a.get_previous_node_ids("epic") == ["vm-a"]
    assert scoped_b.get_previous_node_ids("epic") == ["vm-b"]


def test_tenant_property_exposes_context(scoped_a) -> None:
    assert scoped_a.tenant.tenant_id == TENANT_A


# --------------------------------------------------------------------------------------
# Per-tenant module enablement (issue #68) — disabled set is isolated between tenants.
# --------------------------------------------------------------------------------------
def test_module_config_unset_is_default_enabled(scoped_a) -> None:
    """No config set ⇒ nothing disabled (default-enabled — deny-by-default NOT applied)."""
    assert scoped_a.get_module_config() is None
    assert scoped_a.get_disabled_modules() == set()


def test_module_disable_is_isolated_between_tenants(scoped_a, scoped_b) -> None:
    scoped_a.set_disabled_modules(["quality_checks"])
    # Tenant A sees its own disable; tenant B is unaffected (still default-enabled).
    assert scoped_a.get_disabled_modules() == {"quality_checks"}
    assert scoped_b.get_disabled_modules() == set()
    assert scoped_b.get_module_config() is None


def test_module_disable_set_replaces_not_merges(scoped_a) -> None:
    scoped_a.set_disabled_modules(["quality_checks", "drift"])
    assert scoped_a.get_disabled_modules() == {"quality_checks", "drift"}
    scoped_a.set_disabled_modules(["drift"])  # replace semantics
    assert scoped_a.get_disabled_modules() == {"drift"}
    scoped_a.set_disabled_modules([])  # clear ⇒ back to default-enabled
    assert scoped_a.get_disabled_modules() == set()


def test_module_config_inner_key_is_tenant_namespaced(scoped_a, inner) -> None:
    """Defense-in-depth: the physical module-config key is the composite tenant key, never bare."""
    scoped_a.set_disabled_modules(["quality_checks"])
    config = inner.get_module_config(scoped_a._modules_scope())
    assert config is not None
    assert config.scope != "_modules"  # tenant-namespaced composite, never the bare logical name
    assert "." in config.scope


# --------------------------------------------------------------------------------------
# Per-tenant imported packs (issue #68) — an import is visible ONLY to the importing tenant.
# --------------------------------------------------------------------------------------
def _imported(pack_id: str, version: str, digest: str) -> ImportedPack:
    return ImportedPack(
        scope="",  # namespaced by record_imported_pack
        packId=pack_id,
        version=version,
        packType=PackType.workload,
        digest=digest,
        signature=None,
        keyId=None,
        importedBy="tester",
    )


def test_imported_pack_is_invisible_to_other_tenant(scoped_a, scoped_b) -> None:
    scoped_a.record_imported_pack(_imported("epic-core", "1.0.0", "sha256:aaa"))
    # Tenant A can see and address its own import; tenant B sees nothing (deny-by-default).
    assert scoped_a.get_imported_pack("epic-core", "1.0.0") is not None
    assert [p.packId for p in scoped_a.list_imported_packs()] == ["epic-core"]
    assert scoped_b.get_imported_pack("epic-core", "1.0.0") is None
    assert scoped_b.list_imported_packs() == []


def test_same_pack_id_version_imported_by_two_tenants_is_disjoint(scoped_a, scoped_b) -> None:
    scoped_a.record_imported_pack(_imported("epic-core", "1.0.0", "sha256:aaa"))
    scoped_b.record_imported_pack(_imported("epic-core", "1.0.0", "sha256:bbb"))
    # Each tenant sees ONLY its own record for the same id@version — no overwrite, no cross-read.
    got_a = scoped_a.get_imported_pack("epic-core", "1.0.0")
    got_b = scoped_b.get_imported_pack("epic-core", "1.0.0")
    assert got_a is not None and got_a.digest == "sha256:aaa"
    assert got_b is not None and got_b.digest == "sha256:bbb"


def test_imported_pack_inner_scope_is_tenant_namespaced(scoped_a, inner) -> None:
    scoped_a.record_imported_pack(_imported("epic-core", "1.0.0", "sha256:aaa"))
    raw = inner.list_imported_packs(scoped_a._imports_scope())
    assert len(raw) == 1
    assert raw[0].scope != "_imports"  # never the bare logical name
    assert "." in raw[0].scope


def test_try_record_imported_pack_is_atomic_and_per_tenant_immutable(scoped_a, scoped_b) -> None:
    # The facade's atomic guard (issue #68, FIX 2): same-digest re-import is idempotent, a
    # different-digest re-import conflicts, and another tenant importing the SAME id@version with
    # DIFFERENT content is NOT a conflict (physically disjoint per tenant).
    scoped_a.try_record_imported_pack(_imported("epic-core", "1.0.0", "sha256:aaa"))
    scoped_a.try_record_imported_pack(_imported("epic-core", "1.0.0", "sha256:aaa"))  # idempotent
    assert [p.packId for p in scoped_a.list_imported_packs()] == ["epic-core"]
    with pytest.raises(ImportConflictError):
        scoped_a.try_record_imported_pack(_imported("epic-core", "1.0.0", "sha256:bbb"))
    # Tenant B's disjoint import of the same id@version with different content succeeds.
    scoped_b.try_record_imported_pack(_imported("epic-core", "1.0.0", "sha256:ccc"))
    a = scoped_a.get_imported_pack("epic-core", "1.0.0")
    b = scoped_b.get_imported_pack("epic-core", "1.0.0")
    assert a is not None and a.digest == "sha256:aaa"  # first content preserved
    assert b is not None and b.digest == "sha256:ccc"
