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
    ResourceNode,
    Severity,
    SourceReference,
    TenancyMode,
    TenantContext,
    WorkloadGraph,
)
from shared.state import LocalStateStore

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
