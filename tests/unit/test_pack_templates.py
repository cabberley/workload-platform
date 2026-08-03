"""Pack template + new example-pack tests (issue #38).

Two responsibilities, all Azure-free with synthetic, clearly-fake fixtures:

1. Every scaffold under ``content/templates`` schema-validates clean through the SAME
   ``packs_engine.schema.validate_pack`` path the CI gate (``scripts/validate_packs.py``) uses —
   this is the "validated in CI" requirement for the templates.
2. The two NEW real example packs actually produce output through their consuming modules:
   * ``content/rules/waf-security-baseline.json`` → Quality Checks yields the expected FAIL/PASS
     findings against a synthetic Azure estate.
   * ``content/dependencies/multi-tier-web-app.json`` → Dependency & Blast Radius yields SPOF
     findings, and a NON-redundant critical edge (app→db) produces a larger blast radius than a
     redundant one (web→lb).

Fixtures mirror the existing module tests (tests/unit/test_quality_checks.py,
tests/unit/test_dependency_graph.py): a fake ReadableState + fake packs source injected via
``ModuleContext``. No Azure calls, no real resource ids.
"""
from __future__ import annotations

import json
from pathlib import Path

from modules.aiops.connectors.system_pulse import FetchResult
from modules.aiops.module import AiopsModule
from modules.alerts.module import load_ops_routing
from modules.dependency_graph.module import DependencyGraphModule
from modules.quality_checks.module import QualityChecksModule
from packs_engine.engine import PacksEngine
from packs_engine.schema import validate_pack
from shared.blast_radius import blast_radius
from shared.contracts import PackType, ResourceNode, WorkloadGraph
from shared.module_base import ModuleContext

REPO = Path(__file__).resolve().parents[2]
CONTENT = REPO / "content"
TEMPLATES = CONTENT / "templates"

# The ids of the authoring scaffolds under content/templates — these must NEVER be loaded at
# runtime (see packs_engine.engine.RESERVED_NONRUNTIME_DIR).
_TEMPLATE_IDS = {
    "example-workload-pack",
    "example-rule-pack",
    "example-telemetry-pack",
    "example-dependency-pack",
    "example-ops-pack",
}


# --------------------------------------------------------------------------------------
# Synthetic fixtures (fake read-only state + fake packs source), mirroring the module tests.
# --------------------------------------------------------------------------------------
class FakeState:
    """Minimal read-only state stub returning a synthetic estate per workload."""

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


def _node(
    nid: str,
    *,
    ntype: str = "Microsoft.Compute/virtualMachines",
    role: str | None = None,
    workload: str = "example",
    tags: dict[str, str] | None = None,
) -> ResourceNode:
    return ResourceNode(
        id=nid, name=nid, type=ntype, workload=workload, role=role, tags=tags or {}
    )


def _template_files() -> list[Path]:
    return sorted(TEMPLATES.rglob("*.json"))


# --------------------------------------------------------------------------------------
# 1) Every template schema-validates clean (the CI "validated" requirement).
# --------------------------------------------------------------------------------------
def test_templates_exist_for_all_five_types() -> None:
    subdirs = {p.name for p in TEMPLATES.iterdir() if p.is_dir()}
    assert subdirs == {"workload", "rule", "telemetry", "dependency", "ops"}
    # Exactly one starter pack per type.
    assert len(_template_files()) == 5


def test_every_template_validates_clean() -> None:
    files = _template_files()
    assert files, "no template packs found under content/templates"
    for path in files:
        pack = json.loads(path.read_text(encoding="utf-8"))
        errors = validate_pack(pack)
        assert errors == [], f"{path.relative_to(REPO)} failed schema: {errors}"


def test_template_ids_are_distinct_across_all_content() -> None:
    # Templates must not collide with each other or with any released pack id under content/.
    ids: list[str] = []
    for path in CONTENT.rglob("*.json"):
        if path.parent.name == "registry":
            continue  # the registry index is not a pack
        raw = json.loads(path.read_text(encoding="utf-8"))
        manifest = raw.get("manifest")
        if isinstance(manifest, dict) and "id" in manifest:
            ids.append(manifest["id"])
    assert len(ids) == len(set(ids)), f"duplicate pack ids under content/: {ids}"


# --------------------------------------------------------------------------------------
# 2a) New WAF Security rule pack produces findings through Quality Checks.
# --------------------------------------------------------------------------------------
def test_waf_security_rule_pack_produces_findings() -> None:
    engine = PacksEngine(CONTENT)
    # Synthetic, clearly-fake estate: one node PER rule's resourceType, without the required tag
    # (FAIL, fail-closed) plus one storage account that DOES carry the tag (PASS).
    estate = {
        "example": [
            _node(
                "fake-storage-untagged",
                ntype="Microsoft.Storage/storageAccounts",
            ),  # sec-01 FAIL (no data-classification tag)
            _node(
                "fake-storage-tagged",
                ntype="Microsoft.Storage/storageAccounts",
                tags={"data-classification": "public"},
            ),  # sec-01 PASS
            _node(
                "fake-keyvault",
                ntype="Microsoft.KeyVault/vaults",
            ),  # sec-02 FAIL (no security-owner tag)
            _node(
                "fake-public-ip",
                ntype="Microsoft.Network/publicIPAddresses",
            ),  # sec-03 FAIL (no exposure-justification tag)
        ]
    }
    ctx = ModuleContext(state=FakeState(estate), packs=engine)
    result = QualityChecksModule().run(ctx, scope={"workload": "example"})

    assert result.ok is True
    security = [f for f in result.findings if f.packId == "waf-security-baseline"]
    assert security, "waf-security-baseline produced no findings"
    # Provenance on every finding (guardrail #8).
    for f in security:
        assert f.packVersion == "1.0.0"

    by_node = {(f.nodeId, f.packId): f for f in security}
    # The untagged storage account FAILS sec-01; the tagged one PASSES it.
    assert by_node[("fake-storage-untagged", "waf-security-baseline")].passed is False
    assert by_node[("fake-storage-tagged", "waf-security-baseline")].passed is True
    # Key Vault and public IP fail their respective tag rules (fail-closed).
    assert by_node[("fake-keyvault", "waf-security-baseline")].passed is False
    assert by_node[("fake-public-ip", "waf-security-baseline")].passed is False

    failed = [f for f in security if f.passed is False]
    assert len(failed) == 3


# --------------------------------------------------------------------------------------
# 2b) New multi-tier dependency pack produces blast radius through Dependency & Blast Radius.
# --------------------------------------------------------------------------------------
def _multi_tier_estate() -> list[ResourceNode]:
    # web (redundant behind app + lb) → app (redundant) → db (NON-redundant single point).
    return [
        _node("fake-lb", ntype="Microsoft.Network/loadBalancers", role="lb"),
        _node("fake-web1", role="web"),
        _node("fake-web2", role="web"),
        _node("fake-app1", role="app"),
        _node("fake-app2", role="app"),
        _node("fake-db1", role="db"),
    ]


def test_multi_tier_dependency_pack_produces_blast_radius() -> None:
    engine = PacksEngine(CONTENT)
    # The pack is scoped to the synthetic ``multi-tier-demo`` workload (manifest.targets), so it
    # only applies to an estate of that kind — never to unrelated real customer workloads.
    result = DependencyGraphModule().run(
        ModuleContext(state=FakeState({"multi-tier-demo": _multi_tier_estate()}), packs=engine),
        scope={"workload": "multi-tier-demo"},
    )

    assert result.ok is True
    assert result.graph is not None
    pack_edges = [e for e in result.graph.edges if e.origin == "pack:multi-tier-web-app"]
    assert pack_edges, "multi-tier-web-app produced zero edges — role: refs did not resolve"
    resolved = {(e.source, e.target) for e in pack_edges}
    # app→db (non-redundant) resolved to the concrete app/db nodes.
    assert ("fake-app1", "fake-db1") in resolved
    assert ("fake-app2", "fake-db1") in resolved

    # The non-redundant db is a single point of failure and is surfaced as a Finding.
    spofs = [f for f in result.findings if f.nodeId == "fake-db1"]
    assert spofs, "the non-redundant db tier was not surfaced as a SPOF"
    assert spofs[0].passed is False
    assert spofs[0].blastRadius >= 2  # downs both app nodes

    # A NON-redundant critical edge (app→db) yields a LARGER blast radius than a redundant one
    # (web→lb): losing the db downs both app nodes; losing the lb only degrades the web tier.
    db_radius = blast_radius(result.graph, "fake-db1")
    lb_radius = blast_radius(result.graph, "fake-lb")
    assert db_radius > lb_radius
    assert lb_radius == 0


def test_multi_tier_pack_injects_nothing_into_unrelated_workload() -> None:
    # REGRESSION (round-3 review): the pack is scoped to ``multi-tier-demo`` via manifest.targets,
    # so an UNRELATED workload whose nodes merely reuse the generic web/app/db role names must
    # receive ZERO pack edges and ZERO fabricated SPOF. A dependency pack inventing false topology
    # on an estate it was never assigned to would corrupt blast-radius/SPOF — this proves the
    # per-target scope prevents that global injection.
    engine = PacksEngine(CONTENT)
    estate = [
        _node(f"real-{n.id}", ntype=n.type, role=n.role, workload="unrelated-prod")
        for n in _multi_tier_estate()
    ]
    result = DependencyGraphModule().run(
        ModuleContext(state=FakeState({"unrelated-prod": estate}), packs=engine),
        scope={"workload": "unrelated-prod"},
    )
    assert result.graph is not None
    assert not any(
        e.origin == "pack:multi-tier-web-app" for e in result.graph.edges
    ), "multi-tier-web-app injected phantom edges into an unrelated workload"
    assert not any(
        f.id == "spof::real-fake-db1" for f in result.findings
    ), "multi-tier-web-app fabricated a DB SPOF for an unrelated workload"


def test_multi_tier_pack_loads_only_for_its_demo_target() -> None:
    # The engine returns the pack ONLY for the ``multi-tier-demo`` workload kind, never for an
    # arbitrary/unrelated one (contrast with a global ``targets: []`` pack).
    engine = PacksEngine(CONTENT)
    demo_ids = {
        p.manifest.id for p in engine.load_for_workload("multi-tier-demo", PackType.dependency)
    }
    assert "multi-tier-web-app" in demo_ids
    other_ids = {
        p.manifest.id for p in engine.load_for_workload("unrelated-prod", PackType.dependency)
    }
    assert "multi-tier-web-app" not in other_ids


# --------------------------------------------------------------------------------------
# 3) Reserved-directory fail-safe: templates have ZERO runtime effect (reviewer's repros).
#
# Each of these builds a REAL PacksEngine over the actual content root and drives the
# production loader / module the reviewer used. They FAIL before the engine exclusion of
# content/templates/ and PASS after (packs_engine.engine.RESERVED_NONRUNTIME_DIR).
# --------------------------------------------------------------------------------------
class _FakeSignalSource:
    """A telemetry edge client returning a fixed System-Pulse-shaped ``FetchResult``."""

    def __init__(self, metric: str, value: float, resource_id: str) -> None:
        self._result = FetchResult(
            available=True,
            raw=[{
                "metric": metric,
                "value": value,
                "unit": "ms",
                "timestamp": "2026-08-03T04:00:00Z",
                "resourceId": resource_id,
            }],
        )

    def fetch_raw(self, *, metric_names=None) -> FetchResult:
        return self._result


def test_templates_are_not_discovered_at_runtime() -> None:
    # The production loader must NOT return any template scaffold as an executable pack.
    engine = PacksEngine(CONTENT)
    loaded_ids = {p.manifest.id for p in engine.load_all(verify_sig=False)}
    assert loaded_ids.isdisjoint(_TEMPLATE_IDS), (
        f"template scaffolds leaked into runtime discovery: {loaded_ids & _TEMPLATE_IDS}"
    )
    # The real by-type packs are still discovered.
    assert {"epic-core", "waf-reliability-baseline", "default-notify"} <= loaded_ids


def test_ops_template_never_overrides_real_alert_routing() -> None:
    # Alert routing for an arbitrary workload must come ONLY from the real default-notify ops pack,
    # never the example-ops-pack placeholder runbook.
    engine = PacksEngine(CONTENT)
    ops = load_ops_routing(engine, "any-workload-kind")
    assert ops.get("runbook") == "https://aka.ms/workloads-platform/runbook"
    assert ops.get("runbook") != "https://example.invalid/REPLACE-ME/runbook"


def test_telemetry_template_produces_no_runtime_detection() -> None:
    # A customer node using the telemetry template's role/metric, with a breaching signal, must
    # yield NO detection originating from example-telemetry-pack (the pack is never loaded).
    engine = PacksEngine(CONTENT)
    node_id = "/sub/rg/example/replace-me-node-1"
    estate = {"example-workload": [_node(node_id, role="example-role")]}
    clients = {"system_pulse": _FakeSignalSource("example_latency_ms", 999.0, node_id)}
    result = AiopsModule().run(
        ModuleContext(state=FakeState(estate), packs=engine, clients=clients),
        scope={"workload": "example-workload"},
    )
    assert result.ok is True
    assert not any(f.packId == "example-telemetry-pack" for f in result.findings)
    assert result.findings == []  # no telemetry rules loaded ⇒ no detections at all


def test_dependency_template_injects_no_runtime_edges() -> None:
    # Synthetic nodes carrying the template's example-web/app/db roles must NOT gain any edge from
    # example-dependency-pack (the pack is never loaded at runtime).
    engine = PacksEngine(CONTENT)
    estate = [
        _node("real-web-1", role="example-web"),
        _node("real-app-1", role="example-app"),
        _node("real-db-1", role="example-db"),
    ]
    result = DependencyGraphModule().run(
        ModuleContext(state=FakeState({"example-workload": estate}), packs=engine),
        scope={"workload": "example-workload"},
    )
    assert result.graph is not None
    assert not any(
        e.origin == "pack:example-dependency-pack" for e in result.graph.edges
    ), "dependency template leaked edges into the runtime graph"
