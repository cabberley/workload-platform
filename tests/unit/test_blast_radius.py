"""Blast-radius math over the dependency graph — pure, Azure-free."""
from shared.blast_radius import blast_radius, compute_impact, rank_spofs
from shared.contracts import (
    DependencyEdge,
    EdgeType,
    HealthState,
    ResourceNode,
    WorkloadGraph,
)


def _node(nid: str) -> ResourceNode:
    return ResourceNode(id=nid, name=nid, type="vm")


def _epic_graph() -> WorkloadGraph:
    # web x2 -> lb (redundant to lb), web -> ecp (redundant peers), ecp -> odb (hard)
    return WorkloadGraph(
        nodes=[
            _node("odb"), _node("ecp1"), _node("ecp2"),
            _node("web1"), _node("web2"), _node("lb"),
        ],
        edges=[
            DependencyEdge(source="ecp1", target="odb", type=EdgeType.depends_on, redundant=False),
            DependencyEdge(source="ecp2", target="odb", type=EdgeType.depends_on, redundant=False),
            DependencyEdge(source="web1", target="lb", type=EdgeType.load_balances, redundant=True),
            DependencyEdge(source="web2", target="lb", type=EdgeType.load_balances, redundant=True),
        ],
    )


def test_odb_downs_both_ecp_nodes():
    g = _epic_graph()
    impact = compute_impact(g, "odb")
    assert impact["odb"] == HealthState.down
    assert impact["ecp1"] == HealthState.down
    assert impact["ecp2"] == HealthState.down
    # web nodes have no hard path to odb here, so they stay up
    assert impact["web1"] == HealthState.up


def test_lb_degrades_redundant_web_nodes():
    g = _epic_graph()
    impact = compute_impact(g, "lb")
    assert impact["lb"] == HealthState.down
    assert impact["web1"] == HealthState.degraded
    assert impact["web2"] == HealthState.degraded


def test_blast_radius_counts_only_down_nodes():
    g = _epic_graph()
    # odb downs ecp1 + ecp2 => 2
    assert blast_radius(g, "odb") == 2
    # lb only degrades web nodes => 0 down
    assert blast_radius(g, "lb") == 0


def test_rank_spofs_puts_odb_first():
    g = _epic_graph()
    ranked = rank_spofs(g)
    assert ranked[0][0] == "odb"
    assert ranked[0][1] == 2


def test_transitive_propagation():
    g = WorkloadGraph(
        nodes=[_node("a"), _node("b"), _node("c")],
        edges=[
            DependencyEdge(source="b", target="a", redundant=False),
            DependencyEdge(source="c", target="b", redundant=False),
        ],
    )
    # a fails -> b down -> c down => radius 2
    assert blast_radius(g, "a") == 2
