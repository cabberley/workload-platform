"""Quality Checks module tests — pure rule evaluation + estate/pack fan-out.

All fixtures are synthetic, clearly-fake resources (no PHI/PII, no customer data). The module
reads the already-discovered estate from a read-only ``ReadableState`` and verified Rule Packs
from the packs engine; both are injected as fakes so the tests stay Azure-free.
"""
from __future__ import annotations

from typing import Any

from modules.quality_checks.module import (
    QualityChecksModule,
    evaluate_rule,
    load_rules,
)
from packs_engine.engine import Pack
from shared.contracts import PackManifest, PackType, ResourceNode, Severity
from shared.module_base import ModuleContext

VM_TYPE = "Microsoft.Compute/virtualMachines"


# --------------------------------------------------------------------------------------
# Synthetic fixtures (fake ReadableState + fake packs engine).
# --------------------------------------------------------------------------------------
class FakeState:
    """Minimal read-only state stub returning a synthetic estate per workload."""

    def __init__(self, estates: dict[str, list[ResourceNode]]) -> None:
        self._estates = estates

    def list_workloads(self) -> list[str]:
        return list(self._estates)

    def get_estate(self, workload: str) -> list[ResourceNode]:
        return self._estates.get(workload, [])


class FakePacks:
    """Stand-in for the packs engine: returns pre-built, already-'verified' packs.

    Mirrors ``PacksEngine.load_for_workload`` — filters by ``PackManifest.targets`` so a workload
    only sees packs that target it (empty targets = applies to all).
    """

    def __init__(self, packs: list[Pack]) -> None:
        self._packs = packs

    def load_for_workload(self, workload: str, pack_type: PackType) -> list[Pack]:
        return [
            p for p in self._packs
            if p.manifest.type == pack_type
            and (not p.manifest.targets or workload in p.manifest.targets)
        ]


def _rule_pack(
    *,
    pack_id: str = "waf-reliability-baseline",
    version: str = "1.2.0",
    targets: list[str] | None = None,
    rules: Any = None,
) -> Pack:
    manifest = PackManifest(
        id=pack_id, type=PackType.rule, name="WAF Reliability", version=version,
        targets=targets or [],
    )
    if rules is None:
        rules = [
            {
                "id": "rel-01-zone",
                "title": "VMs carry an availability-zone tag",
                "resourceType": VM_TYPE,
                "requiredTag": "availability-zone",
                "severity": "high",
                "description": "WAF Reliability: critical tiers should be zone-aware.",
            }
        ]
    body: dict[str, Any] = {"rules": rules}
    return Pack(manifest=manifest, body=body)


def _zone_rule_pack() -> Pack:
    return _rule_pack()


def _vm(node_id: str, *, tags: dict[str, str] | None = None) -> ResourceNode:
    return ResourceNode(id=node_id, name=node_id, type=VM_TYPE, tags=tags or {})


# --------------------------------------------------------------------------------------
# Pure evaluate_rule coverage: pass / fail-on-missing-tag / not-applicable-by-type.
# --------------------------------------------------------------------------------------
def test_evaluate_rule_passes_when_required_tag_present():
    node = _vm("vm-pass", tags={"availability-zone": "1"})
    rule = {"id": "r1", "title": "zone", "resourceType": VM_TYPE,
            "requiredTag": "availability-zone", "severity": "high"}
    finding = evaluate_rule(node, rule)
    assert finding is not None
    assert finding.passed is True
    assert finding.severity == Severity.info


def test_evaluate_rule_fails_closed_on_missing_tag():
    node = _vm("vm-fail")
    rule = {"id": "r1", "title": "zone", "resourceType": VM_TYPE,
            "requiredTag": "availability-zone", "severity": "high"}
    finding = evaluate_rule(node, rule)
    assert finding is not None
    assert finding.passed is False
    assert finding.severity == Severity.high


def test_evaluate_rule_not_applicable_by_type_returns_none():
    node = ResourceNode(id="stg1", name="stg1", type="Microsoft.Storage/storageAccounts")
    rule = {"id": "r1", "title": "zone", "resourceType": VM_TYPE,
            "requiredTag": "availability-zone", "severity": "high"}
    assert evaluate_rule(node, rule) is None


def test_evaluate_rule_fails_closed_when_no_recognized_predicate():
    # Rule matches the node type but declares no supported predicate → must NOT silent-PASS.
    node = _vm("vm-x", tags={"availability-zone": "1"})
    rule = {"id": "r-nopred", "title": "no predicate", "resourceType": VM_TYPE, "severity": "low"}
    finding = evaluate_rule(node, rule)
    assert finding is not None
    assert finding.passed is False
    assert finding.severity == Severity.low
    assert "unsupported" in (finding.detail or "")


def test_evaluate_rule_invalid_severity_does_not_crash():
    node = _vm("vm-bad")
    rule = {"id": "r1", "resourceType": VM_TYPE, "requiredTag": "availability-zone",
            "severity": "not-a-severity"}
    finding = evaluate_rule(node, rule)
    assert finding is not None
    assert finding.passed is False
    assert finding.severity == Severity.medium  # safe default


def test_evaluate_rule_non_scalar_severity_does_not_crash():
    # A JSON-valid but non-scalar severity (list/dict) must not raise (unhashable) — fail closed.
    node = _vm("vm-bad")
    for bad in (["high"], {"x": 1}, 3, True):
        rule = {"id": "r1", "resourceType": VM_TYPE, "requiredTag": "availability-zone",
                "severity": bad}
        finding = evaluate_rule(node, rule)
        assert finding is not None
        assert finding.severity == Severity.medium  # safe default, no crash


# --------------------------------------------------------------------------------------
# load_rules: extracts rule dicts, stamps provenance, and hardens against malformed packs.
# --------------------------------------------------------------------------------------
def test_load_rules_stamps_pack_provenance():
    rules, notes = load_rules(FakePacks([_zone_rule_pack()]), "epic")
    assert len(rules) == 1
    assert rules[0]["packId"] == "waf-reliability-baseline"
    assert rules[0]["packVersion"] == "1.2.0"
    assert notes == []


def test_load_rules_with_no_packs_engine_is_empty():
    assert load_rules(None, "epic") == ([], [])


def test_load_rules_rules_none_does_not_crash_and_is_surfaced():
    pack = Pack(
        manifest=PackManifest(id="p", type=PackType.rule, name="p", version="1.0.0"),
        body={"rules": None},
    )
    rules, notes = load_rules(FakePacks([pack]), "epic")
    assert rules == []
    assert any("not a list" in n for n in notes)


def test_load_rules_non_list_rules_does_not_crash_and_is_surfaced():
    rules, notes = load_rules(FakePacks([_rule_pack(rules="oops-a-string")]), "epic")
    assert rules == []
    assert any("not a list" in n for n in notes)


def test_load_rules_non_dict_rule_entry_is_skipped_and_surfaced():
    rules, notes = load_rules(
        FakePacks([_rule_pack(rules=["not-a-mapping", {"id": "ok", "requiredTag": "t"}])]),
        "epic",
    )
    assert len(rules) == 1
    assert rules[0]["id"] == "ok"
    assert any("non-mapping" in n for n in notes)


def test_load_rules_invalid_severity_defaults_and_is_surfaced():
    rules, notes = load_rules(
        FakePacks([_rule_pack(rules=[{"id": "r", "requiredTag": "t", "severity": "megabad"}])]),
        "epic",
    )
    assert len(rules) == 1
    assert rules[0]["severity"] == Severity.medium
    assert any("invalid severity" in n for n in notes)


def test_load_rules_non_scalar_severity_defaults_and_is_surfaced():
    # List/dict severity must not crash rule loading (unhashable) — coerce + surface, keep rule.
    for bad in (["high"], {"x": 1}):
        rules, notes = load_rules(
            FakePacks([_rule_pack(rules=[{"id": "r", "requiredTag": "t", "severity": bad}])]),
            "epic",
        )
        assert len(rules) == 1
        assert rules[0]["severity"] == Severity.medium
        assert any("invalid severity" in n for n in notes)


# --------------------------------------------------------------------------------------
# Module.run: PASS / FAIL / NOT-APPLICABLE over a synthetic estate, provenance on findings.
# --------------------------------------------------------------------------------------
def test_run_emits_pass_fail_and_skips_not_applicable_with_provenance():
    estate = {
        "epic": [
            _vm("vm-ok", tags={"availability-zone": "2"}),  # PASS
            _vm("vm-bad"),                                    # FAIL (missing tag)
            ResourceNode(id="stg", name="stg",               # NOT-APPLICABLE (wrong type)
                         type="Microsoft.Storage/storageAccounts"),
        ]
    }
    ctx = ModuleContext(state=FakeState(estate), packs=FakePacks([_zone_rule_pack()]))
    result = QualityChecksModule().run(ctx)

    assert result.module == "quality_checks"
    assert result.ok is True
    # Two applicable node×rule checks (the storage account is skipped).
    assert len(result.findings) == 2
    by_node = {f.nodeId: f for f in result.findings}
    assert by_node["vm-ok"].passed is True
    assert by_node["vm-bad"].passed is False
    # Provenance on EVERY finding (guardrail #8).
    for f in result.findings:
        assert f.packId == "waf-reliability-baseline"
        assert f.packVersion == "1.2.0"
    assert result.response is not None
    assert "1 failed" in result.response.findings[0]


def test_run_scopes_to_a_single_workload():
    estate = {
        "epic": [_vm("vm-epic")],
        "sap": [_vm("vm-sap")],
    }
    ctx = ModuleContext(state=FakeState(estate), packs=FakePacks([_zone_rule_pack()]))
    result = QualityChecksModule().run(ctx, scope={"workload": "epic"})
    assert {f.nodeId for f in result.findings} == {"vm-epic"}


def test_run_unknown_workload_yields_no_findings():
    ctx = ModuleContext(state=FakeState({"epic": [_vm("vm-epic")]}),
                        packs=FakePacks([_zone_rule_pack()]))
    result = QualityChecksModule().run(ctx, scope={"workload": "does-not-exist"})
    assert result.findings == []
    assert result.ok is True


def test_run_fails_closed_with_no_state():
    # None state → no crash, empty findings (fail-closed).
    ctx = ModuleContext(state=None, packs=FakePacks([_zone_rule_pack()]))
    result = QualityChecksModule().run(ctx)
    assert result.findings == []
    assert result.ok is True


def test_run_with_no_packs_yields_no_findings():
    ctx = ModuleContext(state=FakeState({"epic": [_vm("vm-epic")]}), packs=None)
    result = QualityChecksModule().run(ctx)
    assert result.findings == []
    assert result.ok is True


# --------------------------------------------------------------------------------------
# FIX 2 — pack workload targeting: an epic-only pack must not run against a sap estate.
# --------------------------------------------------------------------------------------
def test_run_respects_pack_workload_targeting():
    epic_pack = _rule_pack(pack_id="epic-only", version="2.0.0", targets=["epic"])
    estate = {
        "epic": [_vm("vm-epic")],
        "sap": [_vm("vm-sap")],
    }
    packs = FakePacks([epic_pack])

    # DOES apply to the epic estate...
    epic_ctx = ModuleContext(state=FakeState(estate), packs=packs)
    epic_res = QualityChecksModule().run(epic_ctx, scope={"workload": "epic"})
    assert {f.nodeId for f in epic_res.findings} == {"vm-epic"}
    assert all(f.packId == "epic-only" for f in epic_res.findings)

    # ...and does NOT apply to the sap estate.
    sap_ctx = ModuleContext(state=FakeState(estate), packs=packs)
    sap_res = QualityChecksModule().run(sap_ctx, scope={"workload": "sap"})
    assert sap_res.findings == []


def test_run_surfaces_unsupported_rule_and_never_silent_passes():
    # A rule with no recognized predicate must fail-closed (surfaced, not passed).
    pack = _rule_pack(rules=[{"id": "no-pred", "resourceType": VM_TYPE, "severity": "medium"}])
    ctx = ModuleContext(state=FakeState({"epic": [_vm("vm-1")]}), packs=FakePacks([pack]))
    result = QualityChecksModule().run(ctx)
    assert len(result.findings) == 1
    assert result.findings[0].passed is False


def test_run_does_not_crash_on_malformed_pack_body_and_surfaces_notes():
    bad = Pack(
        manifest=PackManifest(id="bad", type=PackType.rule, name="bad", version="1.0.0"),
        body={"rules": None},
    )
    ctx = ModuleContext(state=FakeState({"epic": [_vm("vm-1")]}), packs=FakePacks([bad]))
    result = QualityChecksModule().run(ctx)
    assert result.ok is True
    assert result.findings == []
    assert result.extra["surfacedNotes"]  # malformed body surfaced, not raised


# --------------------------------------------------------------------------------------
# R4 — shipped rule ids are AUTHORITATIVE over imported rule ids. A Finding id is
# ``{rule_id}::{node_id}`` (not pack-namespaced) and findings persist last-wins on
# ``(workload, finding_id)``, so a NEW-pack-id imported rule REUSING a shipped rule id could
# overwrite (and suppress a FAIL from) the shipped rule. ``load_rules`` runs a two-pass, shipped-
# first merge keyed on ``pack.imported`` so an imported rule may ADD a new id but never shadow one.
# --------------------------------------------------------------------------------------
def _rule(rule_id: str, required_tag: str) -> dict[str, Any]:
    return {
        "id": rule_id,
        "title": rule_id,
        "resourceType": VM_TYPE,
        "requiredTag": required_tag,
        "severity": "high",
        "description": rule_id,
    }


def _shipped_pack(*, pack_id: str, rules: list[dict[str, Any]]) -> Pack:
    return Pack(
        manifest=PackManifest(id=pack_id, type=PackType.rule, name=pack_id, version="1.0.0"),
        body={"rules": rules},
        imported=False,
    )


def _imported_pack(*, pack_id: str, rules: list[dict[str, Any]]) -> Pack:
    return Pack(
        manifest=PackManifest(id=pack_id, type=PackType.rule, name=pack_id, version="1.0.0"),
        body={"rules": rules},
        imported=True,
    )


def test_load_rules_imported_rule_shadowing_shipped_id_is_skipped():
    # Shipped and a DIFFERENT-pack-id import both define rule id "rel-01" — the import is skipped.
    shipped = _shipped_pack(pack_id="waf-shipped", rules=[_rule("rel-01", "availability-zone")])
    attacker = _imported_pack(pack_id="attacker-rules", rules=[_rule("rel-01", "always-present")])
    rules, notes = load_rules(FakePacks([shipped, attacker]), "epic")

    # Exactly one rule for the shadowed id — the SHIPPED one (its requiredTag), not the import's.
    matching = [r for r in rules if r["id"] == "rel-01"]
    assert len(matching) == 1
    assert matching[0]["requiredTag"] == "availability-zone"
    assert matching[0]["packId"] == "waf-shipped"
    # The collision is surfaced as a fail-closed skip note (shipped wins).
    assert any(
        "attacker-rules" in n and "shadows shipped rule id" in n and "rel-01" in n for n in notes
    )


def test_load_rules_imported_rule_with_unique_id_still_loads():
    shipped = _shipped_pack(pack_id="waf-shipped", rules=[_rule("rel-01", "availability-zone")])
    addon = _imported_pack(pack_id="team-addon", rules=[_rule("addon-01", "cost-centre")])
    rules, notes = load_rules(FakePacks([shipped, addon]), "epic")

    ids = sorted(r["id"] for r in rules)
    assert ids == ["addon-01", "rel-01"]  # import AUGMENTS with its unique id
    assert not any("shadows shipped rule id" in n for n in notes)


def test_imported_pass_cannot_suppress_shipped_fail_in_persisted_state(tmp_path):
    from shared.state import LocalStateStore

    # Node HAS "env" (would PASS the attacker rule) but LACKS "availability-zone" (FAILs shipped).
    node = _vm("vm-1", tags={"env": "prod"})
    store = LocalStateStore(tmp_path)
    store.put_estate("epic", [node])

    shipped = _shipped_pack(pack_id="waf-shipped", rules=[_rule("rel-01", "availability-zone")])
    # Same rule id "rel-01" but a predicate the node satisfies → would emit a PASS for rel-01::vm-1.
    attacker = _imported_pack(pack_id="attacker-rules", rules=[_rule("rel-01", "env")])

    ctx = ModuleContext(state=store, packs=FakePacks([shipped, attacker]))
    result = QualityChecksModule().run(ctx, scope={"workload": "epic"})
    # Only the shipped rule ran → exactly one finding for the shadowed id, and it FAILS.
    assert len(result.findings) == 1
    assert result.findings[0].id == "rel-01::vm-1"
    assert result.findings[0].passed is False

    # Persist + read back: the shipped FAIL is what lands in durable state (no imported PASS to
    # last-wins-overwrite it).
    store.add_findings("epic", result.findings)
    persisted = store.get_findings("epic", module="quality_checks")
    assert [(f.id, f.passed) for f in persisted] == [("rel-01::vm-1", False)]
