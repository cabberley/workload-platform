"""Workload-agnostic generalization proof (issue #62).

Demonstrates that a brand-new workload type is onboarded with **content only** — a Workload
Definition pack (``content/workloads/acme-bespoke-multitier.json``) plus a companion Dependency
pack (``content/dependencies/multi-tier-web-app.json``), both targeting the synthetic
``multi-tier-demo`` workload — and that NO platform code changes to support it.

The graph is built the SAME way the platform does, through the real module code paths:

1. **Workload pack → roles.** A synthetic, clearly-fake estate is classified through the real
   Discovery ``classify`` / ``definitions_from_packs`` using the ACTUAL shipped Workload
   Definition packs (loaded via ``PacksEngine``). The bespoke pack's tag selectors assign the
   presentation/application/database tiers and the ``web``/``app``/``db``/``lb`` roles.
2. **Dependency pack → edges.** Those classified nodes are fed to the real
   ``DependencyGraphModule.run``, which resolves the companion Dependency pack's ``role:`` edges
   into the typed ``WorkloadGraph``.
3. **Blast radius.** The SPOF story is asserted with the canonical pure ``shared.blast_radius``
   module (never a reimplementation): the single ``db`` data tier is the top single point of
   failure (its loss downs the whole application tier), while losing one redundant web/app node
   only degrades the workload.

Everything here is synthetic (``acme-`` / ``fake-`` ids and tags) — no Azure, no customer data,
no proprietary schema.
"""
from __future__ import annotations

from pathlib import Path

from modules.dependency_graph.module import DependencyGraphModule
from modules.discovery.module import classify, definitions_from_packs
from packs_engine.engine import PacksEngine
from shared.blast_radius import blast_radius, compute_impact, rank_spofs
from shared.contracts import HealthState, PackType, ResourceNode, WorkloadGraph
from shared.module_base import ModuleContext

REPO = Path(__file__).resolve().parents[2]
CONTENT = REPO / "content"

WORKLOAD = "multi-tier-demo"


class _FakeState:
    """Synthetic read-only state: a workload -> classified-estate map (satisfies ReadableState)."""

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


def _raw_node(nid: str, ntype: str, tags: dict[str, str]) -> ResourceNode:
    """An UNclassified discovered node — role/tier/workload are assigned by ``classify``."""
    return ResourceNode(id=nid, name=nid, type=ntype, tags=tags)


def _synthetic_estate() -> list[ResourceNode]:
    """A synthetic multi-tier estate tagged for the bespoke Workload Definition pack.

    Two web nodes (redundant presentation tier), two app nodes (redundant application tier), one
    db node (the single data tier = SPOF), and a shared load balancer.
    """
    vm = "Microsoft.Compute/virtualMachines"
    lb = "Microsoft.Network/loadBalancers"
    return [
        _raw_node("fake-lb", lb, {"acme-tier": "lb"}),
        _raw_node("fake-web1", vm, {"acme-tier": "web"}),
        _raw_node("fake-web2", vm, {"acme-tier": "web"}),
        _raw_node("fake-app1", vm, {"acme-tier": "app"}),
        _raw_node("fake-app2", vm, {"acme-tier": "app"}),
        _raw_node("fake-db1", vm, {"acme-tier": "db"}),
    ]


def _classified_estate(engine: PacksEngine) -> list[ResourceNode]:
    """Classify the synthetic estate through the REAL discovery path using the shipped packs."""
    definitions = definitions_from_packs(engine.load_all(pack_type=PackType.workload))
    return classify(_synthetic_estate(), definitions)


def _build_graph() -> WorkloadGraph:
    """Build the WorkloadGraph via the real module path: workload pack (roles) + dependency pack."""
    engine = PacksEngine(CONTENT)
    classified = _classified_estate(engine)
    result = DependencyGraphModule().run(
        ModuleContext(state=_FakeState({WORKLOAD: classified}), packs=engine),
        scope={"workload": WORKLOAD},
    )
    assert result.ok is True
    assert result.graph is not None
    return result.graph


# --------------------------------------------------------------------------------------
# 1) The Workload Definition pack alone classifies the estate into tiers/roles (content-only).
# --------------------------------------------------------------------------------------
def test_bespoke_workload_pack_classifies_estate_into_tiers_and_roles() -> None:
    engine = PacksEngine(CONTENT)
    by_id = {n.id: n for n in _classified_estate(engine)}

    # The bespoke pack (not Epic's) claimed every node into the multi-tier-demo workload.
    for node in by_id.values():
        assert node.workload == WORKLOAD

    assert (by_id["fake-web1"].tier, by_id["fake-web1"].role) == ("presentation", "web")
    assert (by_id["fake-app1"].tier, by_id["fake-app1"].role) == ("application", "app")
    assert (by_id["fake-db1"].tier, by_id["fake-db1"].role) == ("database", "db")
    assert (by_id["fake-lb"].tier, by_id["fake-lb"].role) == ("presentation", "lb")


# --------------------------------------------------------------------------------------
# 2) The companion Dependency pack resolves role: edges through the real module path.
# --------------------------------------------------------------------------------------
def test_bespoke_dependency_pack_resolves_role_edges_to_concrete_nodes() -> None:
    graph = _build_graph()
    pack_edges = [e for e in graph.edges if e.origin == "pack:multi-tier-web-app"]
    assert pack_edges, "multi-tier-web-app produced zero edges — role: refs did not resolve"

    resolved = {(e.source, e.target, e.redundant) for e in pack_edges}
    # app -> db is the NON-redundant SPOF edge (both app nodes depend hard on the single db).
    assert ("fake-app1", "fake-db1", False) in resolved
    assert ("fake-app2", "fake-db1", False) in resolved
    # web -> app is redundant across >= 2 app nodes; web -> lb is redundant.
    assert ("fake-web1", "fake-app1", True) in resolved
    assert ("fake-web1", "fake-lb", True) in resolved

    # No phantom endpoints: every pack-edge node is a real estate node.
    node_ids = {n.id for n in graph.nodes}
    for edge in pack_edges:
        assert edge.source in node_ids and edge.target in node_ids


# --------------------------------------------------------------------------------------
# 3) Blast radius (via shared.blast_radius): the single db tier is the SPOF; redundant nodes
#    only degrade. This is the smart-blast-radius story onboarded with content only.
# --------------------------------------------------------------------------------------
def test_bespoke_db_is_top_spof_and_downs_the_application_tier() -> None:
    graph = _build_graph()

    # (a) The single data tier is the top-ranked single point of failure.
    ranked = rank_spofs(graph)
    assert ranked[0][0] == "fake-db1"
    assert ranked[0][1] >= 2  # its failure downs at least the two app nodes

    # Losing the db takes the application tier DOWN (app tier down; web tier degraded).
    db_impact = compute_impact(graph, "fake-db1")
    assert db_impact["fake-db1"] == HealthState.down
    assert db_impact["fake-app1"] == HealthState.down
    assert db_impact["fake-app2"] == HealthState.down
    assert blast_radius(graph, "fake-db1") >= 2


def test_bespoke_single_redundant_node_failure_leaves_workload_functional() -> None:
    graph = _build_graph()

    # (b) A single redundant APP node failure keeps the workload up: the db is unaffected and the
    # web tier only degrades (its redundant peer app node remains).
    app_impact = compute_impact(graph, "fake-app1")
    assert app_impact["fake-app1"] == HealthState.down
    assert app_impact["fake-app2"] == HealthState.up
    assert app_impact["fake-db1"] == HealthState.up
    assert app_impact["fake-web1"] == HealthState.degraded
    assert blast_radius(graph, "fake-app1") == 0

    # A single redundant WEB node failure downs nothing else (nothing depends on the web tier).
    web_impact = compute_impact(graph, "fake-web1")
    assert web_impact["fake-web1"] == HealthState.down
    assert web_impact["fake-web2"] == HealthState.up
    assert blast_radius(graph, "fake-web1") == 0

    # Losing the shared (redundant) load balancer only degrades the web tier — not a SPOF.
    lb_impact = compute_impact(graph, "fake-lb")
    assert lb_impact["fake-web1"] == HealthState.degraded
    assert blast_radius(graph, "fake-lb") == 0

    # The non-redundant db SPOF has a strictly larger blast radius than the redundant lb.
    assert blast_radius(graph, "fake-db1") > blast_radius(graph, "fake-lb")


# --------------------------------------------------------------------------------------
# 4) Scope safety: the bespoke packs are assigned to multi-tier-demo only (manifest.targets),
#    so an unrelated workload reusing the same role names receives ZERO pack edges.
# --------------------------------------------------------------------------------------
def test_bespoke_packs_do_not_inject_into_unrelated_workload() -> None:
    engine = PacksEngine(CONTENT)
    # Classified nodes, but stored under an unrelated workload kind the packs never target.
    estate = [
        n.model_copy(update={"workload": "unrelated-prod"}) for n in _classified_estate(engine)
    ]
    result = DependencyGraphModule().run(
        ModuleContext(state=_FakeState({"unrelated-prod": estate}), packs=engine),
        scope={"workload": "unrelated-prod"},
    )
    assert result.graph is not None
    assert not any(e.origin == "pack:multi-tier-web-app" for e in result.graph.edges)
    assert not any(f.nodeId == "fake-db1" for f in result.findings)
