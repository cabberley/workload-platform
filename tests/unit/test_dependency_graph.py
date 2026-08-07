"""Dependency & Blast Radius module — auto edges, pack edges, SPOFs (pure, Azure-free).

Uses ONLY synthetic, clearly-fake fixtures: a ``FakeNetworkTopologyClient`` returning synthetic
backend pools, a ``FakeReadableState`` with a synthetic estate, and a ``FakePacks`` source. No
Azure SDK, no network, no real resource ids.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from modules.dependency_graph.module import (
    DependencyGraphModule,
    edges_from_backend_pool,
)
from modules.dependency_graph.topology import BackendPool
from shared.blast_radius import blast_radius, compute_impact
from shared.contracts import (
    EdgeType,
    HealthState,
    PackType,
    ResourceNode,
    WorkloadGraph,
)
from shared.module_base import ModuleContext


# --- synthetic fixtures --------------------------------------------------------------------
def _node(
    nid: str,
    *,
    role: str | None = None,
    ntype: str = "vm",
    workload: str = "fake-epic",
    tags: dict[str, str] | None = None,
) -> ResourceNode:
    return ResourceNode(
        id=nid, name=nid, type=ntype, workload=workload, role=role, tags=tags or {}
    )


def _estate() -> list[ResourceNode]:
    return [
        _node("lb", ntype="Microsoft.Network/loadBalancers"),
        _node("web1", role="web"),
        _node("web2", role="web"),
        _node("ecp1", role="ecp"),
        _node("odb", role="odb"),
    ]


class FakeReadableState:
    """Synthetic read-only state: a workload -> estate map. Satisfies ReadableState."""

    def __init__(self, estates: dict[str, list[ResourceNode]]) -> None:
        self._estates = estates

    def list_workloads(self) -> list[str]:
        return list(self._estates)

    def get_estate(self, workload: str) -> list[ResourceNode]:
        return list(self._estates.get(workload, []))

    def get_graph(self, workload: str) -> WorkloadGraph | None:
        return None

    def get_findings(self, workload: str, module: str | None = None) -> list:
        return []

    def get_previous_findings(self, workload: str) -> list:
        return []

    def get_previous_node_ids(self, workload: str) -> list[str]:
        return []


class FakeNetworkTopologyClient:
    """Synthetic NetworkTopologyClient returning canned backend pools."""

    def __init__(self, pools: list[BackendPool]) -> None:
        self._pools = pools

    def backend_pools(self, scope: str) -> list[BackendPool]:
        return list(self._pools)


class FakePacks:
    """Synthetic dependency-pack source. Returns the same packs for any workload."""

    def __init__(self, packs: list[object]) -> None:
        self._packs = packs

    def load_for_workload(self, workload: str, pack_type: PackType) -> list[object]:
        assert pack_type is PackType.dependency
        return list(self._packs)


def _fake_pack(pack_id: str, edges: list[dict]) -> object:
    return SimpleNamespace(manifest=SimpleNamespace(id=pack_id), body={"edges": edges})


def _run(*, state=None, clients=None, packs=None, scope=None):
    module = DependencyGraphModule()
    ctx = ModuleContext(state=state, clients=clients or {}, packs=packs)
    return module.run(ctx, scope=scope or {})


# --- edges_from_backend_pool redundancy semantics ------------------------------------------
def test_backend_pool_edges_have_correct_redundancy_semantics():
    edges = edges_from_backend_pool("lb", ["web1", "web2"])
    member_to_lb = {e.source: e for e in edges if e.target == "lb"}
    lb_to_member = {e.target: e for e in edges if e.source == "lb"}

    # member -> lb is non-redundant (losing the LB downs the member); origin auto, load_balances.
    assert member_to_lb["web1"].redundant is False
    assert member_to_lb["web1"].type is EdgeType.load_balances
    assert member_to_lb["web1"].origin == "auto"
    # lb -> member is redundant with >1 peer (losing one member only degrades the service).
    assert lb_to_member["web1"].redundant is True


def test_single_member_pool_is_not_redundant():
    edges = edges_from_backend_pool("lb", ["web1"])
    lb_to_member = [e for e in edges if e.source == "lb"]
    assert lb_to_member[0].redundant is False


def test_load_balancer_with_n_members_is_a_spof():
    edges = edges_from_backend_pool("lb", ["web1", "web2"])
    graph = WorkloadGraph(nodes=_estate(), edges=edges)

    # Losing the LB downs every member (SPOF); losing one redundant member downs nothing.
    assert blast_radius(graph, "lb") == 2
    impact = compute_impact(graph, "lb")
    assert impact["web1"] == HealthState.down
    assert impact["web2"] == HealthState.down

    assert blast_radius(graph, "web1") == 0
    member_impact = compute_impact(graph, "web1")
    assert member_impact["web2"] == HealthState.up
    # the balanced service degrades (redundant peer remains), it does not go down
    assert member_impact["lb"] == HealthState.degraded


# --- run(): auto edges + SPOF findings -----------------------------------------------------
def test_run_derives_auto_edges_and_ranks_lb_as_top_spof():
    state = FakeReadableState({"fake-epic": _estate()})
    net = FakeNetworkTopologyClient([BackendPool("lb", ["web1", "web2"])])
    result = _run(state=state, clients={"network": net}, scope={"workload": "fake-epic"})

    assert result.ok is True
    assert result.graph is not None
    # graph nodes are the estate; edges are auto-derived with provenance
    assert {n.id for n in result.graph.nodes} == {"lb", "web1", "web2", "ecp1", "odb"}
    assert result.graph.edges
    assert all(e.origin == "auto" for e in result.graph.edges)

    # LB is the ranked SPOF, and it is surfaced as a Finding with the right blast radius.
    top = result.extra["topSpofs"]
    assert top[0] == ("lb", 2)
    spof = next(f for f in result.findings if f.nodeId == "lb")
    assert spof.blastRadius == 2
    assert spof.passed is False


# --- run(): dependency-pack edges resolve to roles/nodes with provenance -------------------
def test_run_resolves_pack_edges_to_roles_with_origin_tag():
    state = FakeReadableState({"fake-epic": _estate()})
    pack = _fake_pack(
        "dep-epic-core",
        [
            # role -> role: every ecp depends (hard) on odb (canonical namespaced refs)
            {"source": "role:ecp", "target": "role:odb", "type": "depends_on", "redundant": False},
            # id -> role also resolves
            {"source": "id:web1", "target": "role:ecp"},
        ],
    )
    result = _run(state=state, packs=FakePacks([pack]), scope={"workload": "fake-epic"})

    assert result.graph is not None
    pack_edges = [e for e in result.graph.edges if e.origin == "pack:dep-epic-core"]
    assert ("ecp1", "odb", EdgeType.depends_on) in {
        (e.source, e.target, e.type) for e in pack_edges
    }
    assert ("web1", "ecp1", EdgeType.depends_on) in {
        (e.source, e.target, e.type) for e in pack_edges
    }
    # odb is now a SPOF: ecp1 -> odb is a hard edge, so losing odb downs ecp1.
    assert blast_radius(result.graph, "odb") >= 1


def test_run_drives_real_content_dependency_pack_end_to_end():
    # Load the ACTUAL shipped Dependency Pack (role:<name> reference format) via the real engine.
    from packs_engine.engine import PacksEngine

    content_root = Path(__file__).resolve().parents[2] / "content"
    engine = PacksEngine(content_root)
    # Estate matching the pack's target workload kind ("epic") with the pack's declared roles.
    estate = [
        _node("epic-lb", role="lb", ntype="Microsoft.Network/loadBalancers", workload="epic"),
        _node("epic-web1", role="web", workload="epic"),
        _node("epic-ecp1", role="ecp", workload="epic"),
        _node("epic-odb1", role="odb", workload="epic"),
    ]
    result = _run(
        state=FakeReadableState({"epic": estate}),
        packs=engine,
        scope={"workload": "epic"},
    )

    assert result.graph is not None
    pack_edges = [e for e in result.graph.edges if e.origin == "pack:epic-core-deps"]
    # The real pack declares ecp->odb, web->ecp, web->lb — all must resolve to real nodes.
    assert pack_edges, "real content pack produced zero edges — role: refs did not resolve"
    resolved = {(e.source, e.target) for e in pack_edges}
    assert ("epic-ecp1", "epic-odb1") in resolved
    assert ("epic-web1", "epic-ecp1") in resolved
    assert ("epic-web1", "epic-lb") in resolved
    # every pack-edge endpoint is a real estate node (no phantom nodes)
    node_ids = {n.id for n in result.graph.nodes}
    for edge in pack_edges:
        assert edge.source in node_ids and edge.target in node_ids


def test_run_skips_unresolvable_pack_references():
    state = FakeReadableState({"fake-epic": _estate()})
    pack = _fake_pack(
        "dep-bogus",
        [
            {"source": "role:ghost", "target": "role:phantom"},  # unknown roles
            {"source": "web1", "target": "ecp"},  # bare (un-namespaced) tokens are rejected
        ],
    )
    result = _run(state=state, packs=FakePacks([pack]), scope={"workload": "fake-epic"})

    assert result.graph is not None
    assert [e for e in result.graph.edges if e.origin == "pack:dep-bogus"] == []


def test_run_merges_auto_and_pack_edges():
    state = FakeReadableState({"fake-epic": _estate()})
    net = FakeNetworkTopologyClient([BackendPool("lb", ["web1", "web2"])])
    pack = _fake_pack("dep-epic-core", [{"source": "role:ecp", "target": "role:odb"}])
    result = _run(
        state=state,
        clients={"network": net},
        packs=FakePacks([pack]),
        scope={"workload": "fake-epic"},
    )

    assert result.graph is not None
    origins = {e.origin for e in result.graph.edges}
    assert "auto" in origins
    assert "pack:dep-epic-core" in origins


# --- FIX 2/A: module maps client member ids to estate nodes, dedupes, skips + surfaces ------
def test_auto_edges_map_members_to_estate_and_surface_unresolved():
    vm_id = "/subscriptions/S/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/vm1"
    lb_id = "/subscriptions/S/resourceGroups/RG/providers/Microsoft.Network/loadBalancers/lb1"
    ghost = "/subscriptions/S/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/ghost"
    estate = [
        _node(lb_id, role="lb", ntype="Microsoft.Network/loadBalancers", workload="epic"),
        _node(vm_id, role="web", workload="epic"),
    ]
    # The client already resolved members to owning-VM ARM ids; one is absent from the estate.
    net = FakeNetworkTopologyClient([BackendPool(lb_id, [vm_id, ghost])])
    result = _run(
        state=FakeReadableState({"epic": estate}),
        clients={"network": net},
        scope={"workload": "epic"},
    )

    assert result.graph is not None
    node_ids = {n.id for n in result.graph.nodes}
    # every auto edge endpoint is a real estate node — no phantom nodes
    for edge in result.graph.edges:
        assert edge.source in node_ids and edge.target in node_ids
    assert any(e.source == vm_id and e.target == lb_id for e in result.graph.edges)
    # the unresolvable member is skipped AND surfaced
    assert ghost in result.extra["unresolvedMembers"]
    assert not any(e.source == ghost or e.target == ghost for e in result.graph.edges)


def test_auto_edges_dedupe_same_vm_members_yield_sole_member_semantics():
    # FIX A: two IP-configs of ONE VM (client resolves both to the same VM id) must count as a
    # single, NON-redundant member — failing that VM downs the LB (not merely degrades it).
    vm_id = "/subscriptions/S/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/vm1"
    lb_id = "/subscriptions/S/resourceGroups/RG/providers/Microsoft.Network/loadBalancers/lb1"
    estate = [
        _node(lb_id, role="lb", ntype="Microsoft.Network/loadBalancers", workload="epic"),
        _node(vm_id, role="web", workload="epic"),
    ]
    net = FakeNetworkTopologyClient([BackendPool(lb_id, [vm_id, vm_id])])
    result = _run(
        state=FakeReadableState({"epic": estate}),
        clients={"network": net},
        scope={"workload": "epic"},
    )

    assert result.graph is not None
    # exactly one lb<->vm edge pair (member deduped), and both directions are non-redundant
    lb_to_vm = [e for e in result.graph.edges if e.source == lb_id and e.target == vm_id]
    vm_to_lb = [e for e in result.graph.edges if e.source == vm_id and e.target == lb_id]
    assert len(lb_to_vm) == 1 and lb_to_vm[0].redundant is False
    assert len(vm_to_lb) == 1 and vm_to_lb[0].redundant is False
    # sole member: failing the VM downs the LB (blast radius >= 1), not just degraded
    assert blast_radius(result.graph, vm_id) >= 1
    assert compute_impact(result.graph, vm_id)[lb_id] == HealthState.down


# --- FIX B: the real client resolves NIC ipConfig members to owning VM ids ------------------
def test_azure_client_resolves_nic_ipconfig_to_owning_vm_id():
    from modules.dependency_graph.topology import AzureNetworkTopologyClient

    vm_id = "/subscriptions/S/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/vm1"
    nic_ipcfg = (
        "/subscriptions/S/resourceGroups/RG/providers/Microsoft.Network/"
        "networkInterfaces/nic1/ipConfigurations/ipconfig1"
    )
    lb_id = "/subscriptions/S/resourceGroups/RG/providers/Microsoft.Network/loadBalancers/lb1"

    # Fake ARM management client: NICs carry virtual_machine.id; the LB pool refs the NIC ipConfig.
    nic = SimpleNamespace(
        id="/subscriptions/S/resourceGroups/RG/providers/Microsoft.Network/networkInterfaces/nic1",
        virtual_machine=SimpleNamespace(id=vm_id),
        ip_configurations=[SimpleNamespace(id=nic_ipcfg)],
    )
    lb = SimpleNamespace(
        id=lb_id,
        backend_address_pools=[
            SimpleNamespace(backend_ip_configurations=[SimpleNamespace(id=nic_ipcfg)])
        ],
    )
    fake_mgmt = SimpleNamespace(
        network_interfaces=SimpleNamespace(list_all=lambda: [nic]),
        load_balancers=SimpleNamespace(list_all=lambda: [lb]),
        application_gateways=SimpleNamespace(list_all=lambda: []),
    )

    client = AzureNetworkTopologyClient.from_management_client(fake_mgmt)
    pools = client.backend_pools("scope")

    assert len(pools) == 1
    # the client emits the owning VM id, NOT the raw NIC ipConfig id
    assert pools[0].member_ids == [vm_id]
    assert pools[0].load_balancer_id == lb_id


# --- FIX 3: pack role expansion is scoped per workload (no cross-workload edges) ------------
def test_pack_role_expansion_is_scoped_per_workload():
    w1 = [
        _node("w1-ecp", role="ecp", workload="w1"),
        _node("w1-odb", role="odb", workload="w1"),
    ]
    w2 = [
        _node("w2-ecp", role="ecp", workload="w2"),
        _node("w2-odb", role="odb", workload="w2"),
    ]
    pack = _fake_pack("dep-shared", [{"source": "role:ecp", "target": "role:odb"}])
    result = _run(
        state=FakeReadableState({"w1": w1, "w2": w2}),
        packs=FakePacks([pack]),
        scope={},  # resolve ALL workloads
    )

    assert result.graph is not None
    edges = {(e.source, e.target) for e in result.graph.edges}
    # exactly the intra-workload edges — no w2-ecp -> w1-odb cartesian bleed
    assert edges == {("w1-ecp", "w1-odb"), ("w2-ecp", "w2-odb")}
    # w1-odb only downs w1-ecp (radius 1), NOT anything in w2
    assert blast_radius(result.graph, "w1-odb") == 1
    assert blast_radius(result.graph, "w2-odb") == 1


# --- fail-closed behaviour -----------------------------------------------------------------
def test_run_fails_closed_without_network_client():
    state = FakeReadableState({"fake-epic": _estate()})
    pack = _fake_pack("dep-epic-core", [{"source": "role:ecp", "target": "role:odb"}])
    # No "network" client injected: graph still builds from estate + packs, no crash.
    result = _run(state=state, packs=FakePacks([pack]), scope={"workload": "fake-epic"})

    assert result.ok is True
    assert result.graph is not None
    assert {n.id for n in result.graph.nodes} == {"lb", "web1", "web2", "ecp1", "odb"}
    # only pack edges (no auto edges from a missing client)
    assert all(e.origin == "pack:dep-epic-core" for e in result.graph.edges)


def test_run_fails_closed_without_state_or_packs():
    # No state, no packs, no clients: empty graph, no findings, still ok.
    result = _run()
    assert result.ok is True
    assert result.graph is not None
    assert result.graph.nodes == []
    assert result.graph.edges == []
    assert result.findings == []


def test_run_resolves_all_workloads_when_scope_omitted():
    state = FakeReadableState({"fake-epic": _estate()})
    result = _run(state=state, scope={})
    assert result.graph is not None
    assert {n.id for n in result.graph.nodes} == {"lb", "web1", "web2", "ecp1", "odb"}


# --- Citrix control-plane assist (issue #48): optional, default-off, supplement-only -------
class _FakeCitrixConnector:
    """A synthetic Citrix connector returning a canned FetchResult — no network, no real Citrix."""

    def __init__(self, result):
        self._result = result

    def fetch_raw(self):
        return self._result


def _citrix_health(resource_id: str, health: str = "degraded") -> dict:
    return {"kind": "host-health", "resource_id": resource_id, "health": health}


def _citrix_dependency(source: str, target: str) -> dict:
    return {"kind": "session-dependency", "resource_id": source, "depends_on": target}


def test_run_is_identical_when_citrix_absent():
    from shared.connectors import FetchResult

    state = FakeReadableState({"fake-epic": _estate()})
    baseline = _run(state=state, scope={"workload": "fake-epic"})
    # A run WITHOUT any citrix client and one with an unavailable citrix client both leave the graph
    # nodes byte-for-byte identical (no supplemental tags), proving default-off + fail-closed.
    unavailable = _FakeCitrixConnector(FetchResult(available=False, error="NoCredential"))
    with_failclosed = _run(
        state=state, clients={"citrix": unavailable}, scope={"workload": "fake-epic"}
    )
    assert baseline.graph is not None and with_failclosed.graph is not None
    assert [n.model_dump() for n in baseline.graph.nodes] == [
        n.model_dump() for n in with_failclosed.graph.nodes
    ]
    assert all("aegis:source" not in n.tags for n in with_failclosed.graph.nodes)


def test_run_annotates_existing_node_with_citrix_health():
    from shared.connectors import FetchResult

    state = FakeReadableState({"fake-epic": _estate()})
    citrix = _FakeCitrixConnector(
        FetchResult(available=True, raw=[_citrix_health("odb", "unreachable")])
    )
    result = _run(state=state, clients={"citrix": citrix}, scope={"workload": "fake-epic"})
    assert result.graph is not None
    odb = next(n for n in result.graph.nodes if n.id == "odb")
    assert odb.tags["aegis:source"] == "citrix"
    assert odb.tags["aegis:citrix-health"] == "unreachable"
    # No node created/removed; only the matched node annotated.
    assert {n.id for n in result.graph.nodes} == {"lb", "web1", "web2", "ecp1", "odb"}
    other = next(n for n in result.graph.nodes if n.id == "web1")
    assert "aegis:source" not in other.tags
    # A human-readable note surfaces the supplemental annotation.
    assert any("Citrix assist annotated" in f for f in result.response.findings)


def test_run_does_not_persist_citrix_dependency_edges():
    from shared.connectors import FetchResult

    state = FakeReadableState({"fake-epic": _estate()})
    # A dependency signal between two real estate nodes must NOT become a persisted edge (graph-
    # replace hazard — deferred). The health signal is still applied.
    citrix = _FakeCitrixConnector(
        FetchResult(
            available=True,
            raw=[_citrix_health("odb", "degraded"), _citrix_dependency("ecp1", "odb")],
        )
    )
    result = _run(state=state, clients={"citrix": citrix}, scope={"workload": "fake-epic"})
    assert result.graph is not None
    # No edge carries the citrix connector origin — dependency edges are deferred, never persisted.
    assert all(e.origin != "connector:citrix" for e in result.graph.edges)
    # But the health annotation IS applied (supplement-only contribution).
    odb = next(n for n in result.graph.nodes if n.id == "odb")
    assert odb.tags["aegis:citrix-health"] == "degraded"


def test_run_citrix_signal_for_unknown_node_is_dropped():
    from shared.connectors import FetchResult

    state = FakeReadableState({"fake-epic": _estate()})
    citrix = _FakeCitrixConnector(
        FetchResult(available=True, raw=[_citrix_health("/does/not/exist", "healthy")])
    )
    result = _run(state=state, clients={"citrix": citrix}, scope={"workload": "fake-epic"})
    assert result.graph is not None
    assert all("aegis:source" not in n.tags for n in result.graph.nodes)
    assert any("no usable supplemental" in f for f in result.response.findings)


def test_run_survives_citrix_connector_that_raises():
    class _Boom:
        def fetch_raw(self):
            raise RuntimeError("super-secret")

    state = FakeReadableState({"fake-epic": _estate()})
    result = _run(state=state, clients={"citrix": _Boom()}, scope={"workload": "fake-epic"})
    # The module never breaks; graph builds from estate only, and no token/message leaks into notes.
    assert result.ok is True
    assert result.graph is not None
    assert all("aegis:source" not in n.tags for n in result.graph.nodes)
    assert any("Citrix assist unavailable (RuntimeError)" in f for f in result.response.findings)
    assert all("super-secret" not in f for f in result.response.findings)


# --- Load-balancer (NetScaler/F5) assist (issue #49): optional, default-off, supplement-only -----
class _FakeLbConnector:
    """A synthetic LB connector returning a canned FetchResult — no network, no real vendor."""

    def __init__(self, result):
        self._result = result

    def fetch_raw(self):
        return self._result


def _lb_member(lb_id: str, member_id: str = "web1", health: str = "down") -> dict:
    # A raw record in the shared LB wire shape (see shared.connectors.lb.signals_to_raw): the LB
    # aggregate health is reduced per lb_id, so this annotates the node whose id == lb_id.
    return {"kind": "backend-member", "lb_id": lb_id, "member_id": member_id, "health": health}


def test_run_is_identical_when_lb_absent():
    from shared.connectors import FetchResult

    state = FakeReadableState({"fake-epic": _estate()})
    baseline = _run(state=state, scope={"workload": "fake-epic"})
    # A run with an unavailable LB client leaves the graph nodes byte-for-byte identical to a run
    # with no LB client at all (no supplemental tags) — proving default-off + fail-closed.
    unavailable = _FakeLbConnector(FetchResult(available=False, error="InvalidEndpoint"))
    with_failclosed = _run(
        state=state, clients={"load_balancer": unavailable}, scope={"workload": "fake-epic"}
    )
    assert baseline.graph is not None and with_failclosed.graph is not None
    assert [n.model_dump() for n in baseline.graph.nodes] == [
        n.model_dump() for n in with_failclosed.graph.nodes
    ]
    assert all("aegis:source" not in n.tags for n in with_failclosed.graph.nodes)
    findings = with_failclosed.response.findings
    assert any("LB assist unavailable (fail-closed)" in f for f in findings)


def test_run_annotates_existing_node_with_lb_health():
    from shared.connectors import FetchResult

    state = FakeReadableState({"fake-epic": _estate()})
    # up + down members for the "lb" node ⇒ aggregate degraded health tag.
    lb = _FakeLbConnector(
        FetchResult(
            available=True,
            raw=[_lb_member("lb", "web1", "up"), _lb_member("lb", "web2", "down")],
        )
    )
    result = _run(state=state, clients={"load_balancer": lb}, scope={"workload": "fake-epic"})
    assert result.graph is not None
    lb_node = next(n for n in result.graph.nodes if n.id == "lb")
    assert lb_node.tags["aegis:source"] == "lb"
    assert lb_node.tags["aegis:lb-health"] == "degraded"
    # No node created/removed; only the matched node annotated.
    assert {n.id for n in result.graph.nodes} == {"lb", "web1", "web2", "ecp1", "odb"}
    other = next(n for n in result.graph.nodes if n.id == "web1")
    assert "aegis:source" not in other.tags
    assert any("LB assist annotated" in f for f in result.response.findings)


def test_run_lb_signal_for_unknown_node_is_dropped():
    from shared.connectors import FetchResult

    state = FakeReadableState({"fake-epic": _estate()})
    lb = _FakeLbConnector(
        FetchResult(available=True, raw=[_lb_member("/does/not/exist", "web1", "down")])
    )
    result = _run(state=state, clients={"load_balancer": lb}, scope={"workload": "fake-epic"})
    assert result.graph is not None
    assert all("aegis:source" not in n.tags for n in result.graph.nodes)
    assert any("no usable supplemental" in f for f in result.response.findings)


def test_run_does_not_persist_lb_dependency_edges():
    from shared.connectors import FetchResult

    state = FakeReadableState({"fake-epic": _estate()})
    lb = _FakeLbConnector(
        FetchResult(available=True, raw=[_lb_member("lb", "web1", "down")])
    )
    result = _run(state=state, clients={"load_balancer": lb}, scope={"workload": "fake-epic"})
    assert result.graph is not None
    # No LB dependency edges are ever merged into the persisted graph (deferred, ADR 0015). With no
    # network client injected, the only possible edges would be LB-derived — there are none.
    assert all(e.origin not in ("connector:netscaler", "connector:f5") for e in result.graph.edges)
    # The health annotation IS applied (supplement-only contribution).
    lb_node = next(n for n in result.graph.nodes if n.id == "lb")
    assert lb_node.tags["aegis:lb-health"] == "down"


def test_run_survives_lb_connector_that_raises():
    class _Boom:
        def fetch_raw(self):
            raise RuntimeError("super-secret-lb")

    state = FakeReadableState({"fake-epic": _estate()})
    result = _run(
        state=state, clients={"load_balancer": _Boom()}, scope={"workload": "fake-epic"}
    )
    assert result.ok is True
    assert result.graph is not None
    assert all("aegis:source" not in n.tags for n in result.graph.nodes)
    assert any("LB assist unavailable (RuntimeError)" in f for f in result.response.findings)
    assert all("super-secret-lb" not in f for f in result.response.findings)


def test_run_lb_and_citrix_assist_coexist_additively():
    from shared.connectors import FetchResult

    state = FakeReadableState({"fake-epic": _estate()})
    citrix = _FakeCitrixConnector(
        FetchResult(available=True, raw=[_citrix_health("odb", "degraded")])
    )
    lb = _FakeLbConnector(FetchResult(available=True, raw=[_lb_member("lb", "web1", "down")]))
    result = _run(
        state=state,
        clients={"citrix": citrix, "load_balancer": lb},
        scope={"workload": "fake-epic"},
    )
    assert result.graph is not None
    lb_node = next(n for n in result.graph.nodes if n.id == "lb")
    odb = next(n for n in result.graph.nodes if n.id == "odb")
    assert lb_node.tags["aegis:lb-health"] == "down"
    assert odb.tags["aegis:citrix-health"] == "degraded"

