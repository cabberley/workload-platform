"""Tenant-scoped state facade — namespaces every write and filters every read by tenant (#65).

:class:`TenantScopedState` wraps the process-wide single-writer :class:`~shared.state.StateStore`
(EITHER backend — local sqlite or Azure Table+Blob) and a resolved
:class:`~shared.contracts.TenantContext`. It threads the pure tenant PARTITION KEY (from
:mod:`api.app.tenancy`) into every workload-scoped call, so on BOTH backends:

* every write is stored under the tenant's composite partition — never a bare workload key;
* every read/query addresses only that tenant's partition; a workload NAME shared by two tenants
  maps to DISJOINT physical keys, so tenant A can never read or overwrite tenant B's state or read
  models;
* :meth:`list_workloads` returns only the CURRENT tenant's workloads — the composite keys of other
  tenants are filtered out and never surface.

Isolation is DENY-BY-DEFAULT: the tenant is bound at construction and there is no code path that
addresses another tenant's partition, so without a resolved context there is simply no scoped store,
and every method is physically confined to one tenant. It implements the full
:class:`~shared.state.StateStore` Protocol, so it is a drop-in the API core and its in-process
``ReadOnlyState`` view use transparently (the capability modules keep their unchanged read-only
surface — module isolation is preserved).

The append-only audit trail is instance-wide infrastructure (a single tamper-evident hash-chain,
ADR 0014) and is delegated UNCHANGED — tenant-scoping the audit log is out of scope for #65.
"""
from __future__ import annotations

from api.app.tenancy import tenant_partition_key, workload_of
from shared.contracts import (
    AuditEvent,
    Finding,
    ModuleRunResult,
    ResourceNode,
    TenantContext,
    WorkloadGraph,
)
from shared.state import StateStore

__all__ = ["TenantScopedState"]


class TenantScopedState:
    """A :class:`~shared.state.StateStore` view confined to one :class:`TenantContext` (issue #65).

    See the module docstring for the isolation contract; this class just threads the key.
    """

    def __init__(self, inner: StateStore, tenant: TenantContext) -> None:
        self._inner = inner
        self._tenant = tenant

    @property
    def tenant(self) -> TenantContext:
        """The tenant this view is confined to (read-only)."""
        return self._tenant

    def _key(self, workload: str) -> str:
        """Derive the tenant-namespaced physical partition key for ``workload`` (pure)."""
        return tenant_partition_key(self._tenant.tenant_id, workload)

    # -- reads (tenant-filtered) ---------------------------------------------------------
    def list_workloads(self) -> list[str]:
        """Return only THIS tenant's workloads (other tenants' partitions are filtered out)."""
        tenant_id = self._tenant.tenant_id
        workloads = {
            logical
            for scoped in self._inner.list_workloads()
            if (logical := workload_of(scoped, tenant_id)) is not None
        }
        return sorted(workloads)

    def get_estate(self, workload: str) -> list[ResourceNode]:
        return self._inner.get_estate(self._key(workload))

    def get_graph(self, workload: str) -> WorkloadGraph | None:
        return self._inner.get_graph(self._key(workload))

    def get_findings(self, workload: str, module: str | None = None) -> list[Finding]:
        return self._inner.get_findings(self._key(workload), module)

    def get_previous_findings(self, workload: str) -> list[Finding]:
        return self._inner.get_previous_findings(self._key(workload))

    def get_previous_node_ids(self, workload: str) -> list[str]:
        return self._inner.get_previous_node_ids(self._key(workload))

    # -- writes (tenant-namespaced; API core is the single writer) -----------------------
    def put_estate(self, workload: str, nodes: list[ResourceNode]) -> None:
        self._inner.put_estate(self._key(workload), nodes)

    def put_graph(self, workload: str, graph: WorkloadGraph) -> None:
        self._inner.put_graph(self._key(workload), graph)

    def add_findings(self, workload: str, findings: list[Finding]) -> None:
        self._inner.add_findings(self._key(workload), findings)

    def commit_run(self, workload: str, result: ModuleRunResult) -> dict[str, int]:
        return self._inner.commit_run(self._key(workload), result)

    def snapshot(self, workload: str) -> str:
        """Snapshot the tenant's ``workload``; return the id with the LOGICAL workload restored.

        The inner store embeds the physical key it is given into the returned id
        (``snap::<key>::<seq>``). We pass the composite tenant key, so we translate that key back to
        the caller's logical ``workload`` in the returned id — the API contract (and snapshot ids)
        stay stable across tenants and the tenant prefix never surfaces to the caller.
        """
        physical = self._key(workload)
        return self._inner.snapshot(physical).replace(physical, workload, 1)

    # -- audit trail (instance-wide infrastructure — delegated UNCHANGED) ----------------
    def append_audit(self, event: AuditEvent) -> None:
        self._inner.append_audit(event)

    def list_audit(self, *, limit: int | None = None) -> list[AuditEvent]:
        return self._inner.list_audit(limit=limit)

    def audit_head(self) -> str:
        return self._inner.audit_head()
