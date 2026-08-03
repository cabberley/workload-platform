"""Azure network-topology edge client for the Dependency & Blast Radius module.

This is the thin **I/O seam** that lets the pure edge-derivation logic in :mod:`module` turn
Azure Load Balancer / Application Gateway backend address pools into typed ``DependencyEdge``s.
Pure logic stays Azure-free and unit-tested; the concrete client below is injected at the process
boundary via ``ctx.clients["network"]``.

Guarded-import pattern (mirrors :mod:`shared.state`): the ``azure`` SDK is imported **lazily**
inside the constructor/methods and only under :data:`typing.TYPE_CHECKING` for annotations, so
*importing this module never requires* ``azure-mgmt-network`` and ``mypy src`` stays clean without
it installed. ``azure-mgmt-network`` is intentionally **not** an install requirement.

RBAC (least privilege): the real client only *reads* network topology. It needs the built-in
**Reader** role on the target subscription/resource group, or a narrower custom role granting just
``Microsoft.Network/loadBalancers/read``, ``Microsoft.Network/applicationGateways/read`` and
``Microsoft.Network/networkInterfaces/read`` — the last is required by the NIC-ipConfig→owning-VM
resolution (:meth:`AzureNetworkTopologyClient` calls ``network_interfaces.list_all()``). Keyless
only — auth is Managed Identity via ``DefaultAzureCredential``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:  # pragma: no cover - typing-only imports, never needed at runtime
    from azure.core.credentials import TokenCredential
    from azure.mgmt.network import NetworkManagementClient


@dataclass(frozen=True)
class BackendPool:
    """A load-balancing backend pool: the LB/App-Gateway resource id + its member references.

    ``member_ids`` are the balancer's backend members **already resolved to owning-VM ARM ids**
    for Load Balancer pools (a NIC IP-configuration is mapped to its NIC's ``virtualMachine.id``),
    or the **raw IP/FQDN** target for Application Gateway pools that do not map to a VM. Because
    discovery keys estate nodes by ARM resource id, LB members line up with estate node ids; the
    module still maps each id to an estate node, dedupes, and skips + surfaces any id absent from
    the estate — a phantom endpoint must never enter the graph. The optional ``private_link_ids`` /
    ``replica_ids`` carry richer relationships so private-link and replication topology can be
    auto-derived later without widening this seam (see the ``TODO(human)`` hooks in :mod:`module`).
    """

    load_balancer_id: str
    member_ids: list[str]
    kind: str = "load_balancer"  # load_balancer | application_gateway
    private_link_ids: list[str] = field(default_factory=list)
    replica_ids: list[str] = field(default_factory=list)


@runtime_checkable
class NetworkTopologyClient(Protocol):
    """Narrow, read-only surface a module needs: enumerate backend pools within a scope.

    Kept deliberately tiny so tests inject a ``FakeNetworkTopologyClient`` and the module never
    depends on the Azure SDK. ``scope`` is an opaque hint (subscription/resource-group id) the
    concrete client may use to bound its reads.
    """

    def backend_pools(self, scope: str) -> list[BackendPool]:
        """Return the LB/App-Gateway backend pools discoverable within ``scope``."""
        ...


class AzureNetworkTopologyClient:
    """Real keyless ``NetworkTopologyClient`` over ``azure-mgmt-network`` + Managed Identity.

    All Azure imports are guarded (lazy) so importing this module never needs the SDK. Construct
    one per subscription; ``DefaultAzureCredential`` provides keyless auth. Read-only — see the
    module docstring for the least-privilege RBAC this needs.
    """

    def __init__(self, subscription_id: str, *, credential: TokenCredential | None = None) -> None:
        # Guarded import: keep module import azure-free (see shared.state).
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.network import NetworkManagementClient

        cred = credential or DefaultAzureCredential()
        self._client: NetworkManagementClient = NetworkManagementClient(cred, subscription_id)

    @classmethod
    def from_management_client(cls, client: object) -> AzureNetworkTopologyClient:
        """Build a client around an already-constructed network management client.

        The Azure SDK is *not* imported here, so this is the unit-test seam: inject a fake exposing
        ``load_balancers`` / ``application_gateways`` / ``network_interfaces`` collections with a
        ``list_all()`` method and the standard ARM attribute shape.
        """
        self = cls.__new__(cls)
        self._client = client
        return self

    def backend_pools(self, scope: str) -> list[BackendPool]:
        """Read Load Balancer and Application Gateway backend address pools across the scope.

        Load Balancer pool members are NIC IP-configurations; each is **resolved to its owning VM's
        ARM resource id** (via the NIC's ``virtualMachine.id``) so the returned ids match discovery
        estate node ids. Application Gateway pool members are returned as their raw IP/FQDN targets
        (they do not map to a VM); the module skips + surfaces any id absent from the estate.
        """
        nic_to_vm = _nic_ipconfig_to_vm_index(self._client)
        pools: list[BackendPool] = []
        pools.extend(self._load_balancer_pools(nic_to_vm))
        pools.extend(self._app_gateway_pools())
        return pools

    def _load_balancer_pools(self, nic_to_vm: dict[str, str]) -> list[BackendPool]:
        pools: list[BackendPool] = []
        for lb in self._client.load_balancers.list_all():
            lb_id = str(getattr(lb, "id", "") or "")
            if not lb_id:
                continue
            for be in getattr(lb, "backend_address_pools", None) or []:
                members = _load_balancer_pool_members(be, nic_to_vm)
                pools.append(
                    BackendPool(load_balancer_id=lb_id, member_ids=members, kind="load_balancer")
                )
        return pools

    def _app_gateway_pools(self) -> list[BackendPool]:
        pools: list[BackendPool] = []
        for gw in self._client.application_gateways.list_all():
            gw_id = str(getattr(gw, "id", "") or "")
            if not gw_id:
                continue
            for be in getattr(gw, "backend_address_pools", None) or []:
                members = _app_gateway_pool_members(be)
                pools.append(
                    BackendPool(
                        load_balancer_id=gw_id, member_ids=members, kind="application_gateway"
                    )
                )
        return pools


def _nic_ipconfig_to_vm_index(client: object) -> dict[str, str]:
    """Map every NIC IP-configuration id to its owning VM ARM id via ``nic.virtual_machine.id``.

    One ``network_interfaces.list_all()`` read builds the whole index (keyless, read-only). A NIC
    with no attached VM contributes nothing.
    """
    index: dict[str, str] = {}
    interfaces = getattr(client, "network_interfaces", None)
    list_all = getattr(interfaces, "list_all", None)
    if list_all is None:
        return index
    for nic in list_all():
        vm = getattr(nic, "virtual_machine", None)
        vm_id = getattr(vm, "id", None) if vm is not None else None
        if not vm_id:
            continue
        for ipcfg in getattr(nic, "ip_configurations", None) or []:
            ipcfg_id = getattr(ipcfg, "id", None)
            if ipcfg_id:
                index[str(ipcfg_id)] = str(vm_id)
    return index


def _load_balancer_pool_members(pool: object, nic_to_vm: dict[str, str]) -> list[str]:
    """Owning-VM ARM ids for a Load Balancer backend pool (resolved from NIC ipConfig members).

    Each ``backend_ip_configurations[].id`` is a NIC IP-configuration id; it is resolved to the
    owning VM id through ``nic_to_vm``. An unresolvable member falls back to its raw id so the
    module can surface it (never silently dropped, never invented as a node).
    """
    members: list[str] = []
    for cfg in getattr(pool, "backend_ip_configurations", None) or []:
        cfg_id = getattr(cfg, "id", None)
        if not cfg_id:
            continue
        members.append(nic_to_vm.get(str(cfg_id), str(cfg_id)))
    return members


def _app_gateway_pool_members(pool: object) -> list[str]:  # pragma: no cover - needs Azure SDK
    """Members of an Application Gateway backend address pool (raw IP/FQDN references).

    App Gateway v2 pools reference backends by IP/FQDN (not NIC ipconfig ids). These raw values
    are surfaced as-is; the module resolves them to estate node ids (or skips + surfaces them),
    so no phantom node ever reaches the graph.

    TODO(human): map App Gateway IP/FQDN backends to estate node ids at the discovery layer (e.g.
    an estate index keyed by private IP / hostname) so they resolve instead of being skipped.
    """
    members: list[str] = []
    for addr in getattr(pool, "backend_addresses", None) or []:
        member = getattr(addr, "ip_address", None) or getattr(addr, "fqdn", None)
        if member:
            members.append(str(member))
    return members
