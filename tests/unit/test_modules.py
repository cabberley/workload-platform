"""Module registry + per-module logic smoke tests (pure, Azure-free)."""
from modules.alerts.module import route, weight_by_blast_radius
from modules.discovery.module import classify
from modules.quality_checks.module import evaluate_rule
from shared.contracts import Finding, ResourceNode, Severity
from shared.module_base import Module, ModuleContext, build_default_registry, run_module


def test_registry_has_seven_modules():
    reg = build_default_registry()
    names = set(reg.names())
    assert names == {
        "discovery",
        "quality_checks",
        "reassessments",
        "dependency_graph",
        "aiops",
        "alerts",
        "telemetry_export",
    }


def test_every_module_runs_and_reports_ok():
    reg = build_default_registry()
    for module in reg.enabled_modules():
        result = module.run(ModuleContext(), scope={})
        assert result.module == module.name
        assert result.ok is True


def test_discovery_classify_assigns_role():
    nodes = [ResourceNode(id="vm1", name="vm1", type="Microsoft.Compute/virtualMachines",
                          tags={"epic-role": "odb"})]
    defs = [{"resourceType": "Microsoft.Compute/virtualMachines", "tagKey": "epic-role",
             "tagValue": "odb", "tier": "database", "role": "odb"}]
    out = classify(nodes, defs)
    assert out[0].role == "odb"
    assert out[0].tier == "database"


def test_quality_rule_fails_closed_on_missing_tag():
    node = ResourceNode(id="vm1", name="vm1", type="Microsoft.Compute/virtualMachines")
    rule = {"id": "r1", "title": "zone tag", "resourceType": "Microsoft.Compute/virtualMachines",
            "requiredTag": "availability-zone", "severity": "high"}
    finding = evaluate_rule(node, rule)
    assert finding is not None
    assert finding.passed is False
    assert finding.severity == Severity.high


def test_alerts_escalate_by_blast_radius():
    f = Finding(id="f", module="quality_checks", title="t", passed=False,
                severity=Severity.medium, blastRadius=6)
    assert weight_by_blast_radius(f) == Severity.critical
    decision = route(f, {"routes": {"critical": "page"}, "default": "ticket"})
    assert decision["channel"] == "page"
    assert decision["severity"] == "critical"


def test_context_clients_registry_defaults_empty_and_carries_injected():
    # Edge-client registry: empty by default, keyed lookup when injected (DI seam for #2/#4/#7).
    assert ModuleContext().clients == {}
    fake = object()
    ctx = ModuleContext(clients={"resource_graph": fake})
    assert ctx.clients["resource_graph"] is fake


def test_run_module_passes_clients_through_to_the_module():
    seen: dict[str, object] = {}

    class ClientProbe(Module):
        @property
        def manifest(self):  # type: ignore[override]
            return build_default_registry().get("discovery").manifest

        def run(self, ctx, *, scope=None):
            seen.update(ctx.clients)
            return build_default_registry().get("discovery").run(ctx, scope=scope)

    fake = object()
    run_module(ClientProbe(), scope={}, clients={"network": fake})
    assert seen["network"] is fake
