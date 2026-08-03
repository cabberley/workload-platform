"""Pack schema validation — every shipped pack validates clean; malformed bodies fail closed.

These tests exercise the pure ``packs_engine.schema.validate_pack`` gate for all five pack types
(valid + malformed/negative), the round-2 loosen/tighten fixes (matching what each consumer module
actually reads), the unknown-type/missing-shape cases, and that the CI script
``scripts/validate_packs.py`` returns non-zero for a malformed body OR a missing/misspelled
manifest.
"""
from __future__ import annotations

import copy
import importlib.resources
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

from packs_engine.schema import PACK_TYPES, validate_pack

REPO = Path(__file__).resolve().parents[2]
CONTENT = REPO / "content"
SCRIPT = REPO / "scripts" / "validate_packs.py"

# One shipped pack per type — these MUST validate unchanged.
_SHIPPED = {
    "workload": CONTENT / "workloads" / "epic-core.json",
    "rule": CONTENT / "rules" / "waf-reliability-baseline.json",
    "telemetry": CONTENT / "telemetry" / "system-pulse-core.json",
    "dependency": CONTENT / "dependencies" / "epic-core-deps.json",
    "ops": CONTENT / "ops" / "default-notify.json",
}


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_all_five_types_have_shipped_fixtures() -> None:
    assert set(_SHIPPED) == set(PACK_TYPES)


@pytest.mark.parametrize("pack_type", PACK_TYPES)
def test_shipped_packs_validate_clean(pack_type: str) -> None:
    pack = _load(_SHIPPED[pack_type])
    assert validate_pack(pack) == []


# --- FIX 8: schemas ship as package data and load via importlib.resources ----------------------

@pytest.mark.parametrize("pack_type", PACK_TYPES)
def test_schema_is_packaged_and_loadable(pack_type: str) -> None:
    resource = (
        importlib.resources.files("packs_engine")
        .joinpath("schemas")
        .joinpath(f"{pack_type}.schema.json")
    )
    assert resource.is_file()
    schema = json.loads(resource.read_text(encoding="utf-8"))
    assert schema["$schema"].endswith("2020-12/schema")


# --- Workload: FIX 2 (optional pack workload, meaningful selector) + FIX 3 (tag pair) ----------

def test_workload_missing_definitions_rejected() -> None:
    pack = _load(_SHIPPED["workload"])
    pack["body"].pop("definitions")
    assert validate_pack(pack)


def test_workload_definition_extra_property_rejected() -> None:
    # Discovery has no forward-compat spec for workload definitions, so the object stays closed.
    pack = _load(_SHIPPED["workload"])
    pack["body"]["definitions"][0]["bogus"] = "x"
    assert validate_pack(pack)


def test_workload_pack_level_workload_is_optional() -> None:
    # discovery/module.py:106-112 only OPTIONALLY inherits a pack-level workload.
    pack = _load(_SHIPPED["workload"])
    pack["body"].pop("workload")
    assert validate_pack(pack) == []


def test_workload_tag_only_definition_is_valid() -> None:
    # discovery/module.py:77-85 treats resourceType and tag selectors independently.
    pack = _load(_SHIPPED["workload"])
    pack["body"]["definitions"] = [
        {"tagKey": "epic-role", "tagValue": "odb", "tier": "database", "role": "odb"}
    ]
    assert validate_pack(pack) == []


def test_workload_empty_selector_definition_rejected() -> None:
    # A definition with no resourceType and no tag pair matches everything — invalid.
    pack = _load(_SHIPPED["workload"])
    pack["body"]["definitions"] = [{"tier": "database", "role": "odb"}]
    assert validate_pack(pack)


def test_workload_tag_key_without_value_rejected() -> None:
    # discovery/module.py:84-85 compares against None and would misclassify — require the pair.
    pack = _load(_SHIPPED["workload"])
    pack["body"]["definitions"] = [
        {"resourceType": "Microsoft.Compute/virtualMachines", "tagKey": "epic-role"}
    ]
    assert validate_pack(pack)


def test_workload_no_pack_workload_selector_only_definition_rejected() -> None:
    # FINDING 3: without a pack-level workload, a selector-only definition assigns nothing (no-op
    # that can shadow later definitions — discovery/module.py:87-90,106-112).
    pack = _load(_SHIPPED["workload"])
    pack["body"].pop("workload")
    pack["body"]["definitions"] = [{"resourceType": "Microsoft.Compute/virtualMachines"}]
    assert validate_pack(pack)


def test_workload_no_pack_workload_labelled_definition_accepted() -> None:
    # FINDING 3: a definition that assigns a label (role/tier/workload) is valid without a
    # pack-level workload.
    pack = _load(_SHIPPED["workload"])
    pack["body"].pop("workload")
    pack["body"]["definitions"] = [
        {"resourceType": "Microsoft.Compute/virtualMachines", "role": "odb"}
    ]
    assert validate_pack(pack) == []


def test_workload_pack_workload_present_selector_only_definition_accepted() -> None:
    # FINDING 3: with a pack-level workload, definitions may be selector-only (they inherit it).
    pack = _load(_SHIPPED["workload"])
    pack["body"]["workload"] = "epic"
    pack["body"]["definitions"] = [{"resourceType": "Microsoft.Compute/virtualMachines"}]
    assert validate_pack(pack) == []


# --- Rule: FIX 4 (requiredTag optional) + FIX 7 (forward-compat extras) ------------------------

def test_rule_bad_severity_rejected() -> None:
    pack = _load(_SHIPPED["rule"])
    pack["body"]["rules"][0]["severity"] = "catastrophic"
    assert validate_pack(pack)


def test_rule_without_required_tag_is_valid() -> None:
    # quality_checks/module.py:146-155 yields a fail-closed unsupported-predicate FAILURE — valid
    # content (tests/unit/test_quality_checks.py:302-308), not an invalid pack.
    pack = _load(_SHIPPED["rule"])
    pack["body"]["rules"] = [
        {"id": "no-pred", "resourceType": "Microsoft.Compute/virtualMachines", "severity": "medium"}
    ]
    assert validate_pack(pack) == []


def test_rule_without_id_or_severity_is_valid() -> None:
    # RuleSpec defaults id->'rule' and severity->medium (quality_checks/module.py:108,112), so a
    # rule supplying neither is valid runtime content.
    pack = _load(_SHIPPED["rule"])
    pack["body"]["rules"] = [{"resourceType": "Microsoft.Compute/virtualMachines"}]
    assert validate_pack(pack) == []


def test_rule_unknown_field_allowed_forward_compat() -> None:
    # RuleSpec uses extra="ignore"; unknown fields must not fail CI.
    pack = _load(_SHIPPED["rule"])
    pack["body"]["rules"][0]["futurePredicate"] = {"sku": "Premium"}
    assert validate_pack(pack) == []


def test_rule_null_optional_fields_are_valid() -> None:
    # RuleSpec types title/resourceType/requiredTag/packId/packVersion as X|None and coerces a
    # null severity to medium (quality_checks/module.py:80-82), so explicit nulls on those fields
    # must be accepted at authoring time.
    pack = _load(_SHIPPED["rule"])
    pack["body"]["rules"] = [
        {
            "id": "nullable",
            "title": None,
            "resourceType": None,
            "requiredTag": None,
            "severity": None,
        }
    ]
    assert validate_pack(pack) == []


def test_rule_null_description_rejected() -> None:
    # RuleSpec.description:str='' is NON-nullable and _normalize_rule does not pre-coerce it, so a
    # null description raises ValidationError and the rule is dropped at runtime
    # (quality_checks/module.py:166-190). The schema must reject it to match the loader.
    pack = _load(_SHIPPED["rule"])
    pack["body"]["rules"][0]["description"] = None
    assert validate_pack(pack)


def test_rule_non_null_invalid_severity_still_rejected() -> None:
    pack = _load(_SHIPPED["rule"])
    pack["body"]["rules"][0]["severity"] = "bogus"
    assert validate_pack(pack)


def test_rule_non_null_wrong_typed_title_still_rejected() -> None:
    pack = _load(_SHIPPED["rule"])
    pack["body"]["rules"][0]["title"] = 123
    assert validate_pack(pack)


# --- Telemetry: FIX 5 (finite threshold, non-whitespace role) + FIX 7 (extras) -----------------

def test_telemetry_bad_op_rejected() -> None:
    pack = _load(_SHIPPED["telemetry"])
    pack["body"]["signals"][0]["op"] = "ge"
    assert validate_pack(pack)


def test_telemetry_boolean_threshold_rejected() -> None:
    pack = _load(_SHIPPED["telemetry"])
    pack["body"]["signals"][0]["threshold"] = True
    assert validate_pack(pack)


def test_telemetry_non_role_nodeid_rejected() -> None:
    pack = _load(_SHIPPED["telemetry"])
    pack["body"]["signals"][0]["nodeId"] = "odb"
    assert validate_pack(pack)


def test_telemetry_whitespace_only_role_rejected() -> None:
    # aiops/module.py:196-205 strips the role and requires it non-empty.
    pack = _load(_SHIPPED["telemetry"])
    pack["body"]["signals"][0]["nodeId"] = "role:   "
    assert validate_pack(pack)


def test_telemetry_non_finite_threshold_rejected() -> None:
    # JSON Schema "number" admits nan/inf; the programmatic finite check must reject them.
    pack = _load(_SHIPPED["telemetry"])
    pack["body"]["signals"][0]["threshold"] = float("inf")
    errors = validate_pack(pack)
    assert errors and any("finite" in e for e in errors)

    pack["body"]["signals"][0]["threshold"] = float("nan")
    assert validate_pack(pack)


def test_telemetry_unknown_field_allowed_forward_compat() -> None:
    pack = _load(_SHIPPED["telemetry"])
    pack["body"]["signals"][0]["window"] = "5m"
    assert validate_pack(pack) == []


# --- Dependency (unchanged shape) -------------------------------------------------------------

def test_dependency_unnamespaced_endpoint_rejected() -> None:
    pack = _load(_SHIPPED["dependency"])
    pack["body"]["edges"][0]["source"] = "odb"
    assert validate_pack(pack)


def test_dependency_bad_edge_type_rejected() -> None:
    pack = _load(_SHIPPED["dependency"])
    pack["body"]["edges"][0]["type"] = "calls"
    assert validate_pack(pack)


def test_dependency_null_type_and_redundant_are_valid() -> None:
    # _coerce_edge_type(None)->depends_on and bool(None)->False, so nulls are tolerated.
    pack = _load(_SHIPPED["dependency"])
    pack["body"]["edges"][0]["type"] = None
    pack["body"]["edges"][0]["redundant"] = None
    assert validate_pack(pack) == []


# --- Ops: FIX 6 (default-only, routes-only, or both all valid) ---------------------------------

def test_ops_bad_route_severity_key_rejected() -> None:
    pack = _load(_SHIPPED["ops"])
    pack["body"]["routes"]["apocalyptic"] = "page"
    assert validate_pack(pack)


def test_ops_default_only_is_valid() -> None:
    # alerts/module.py:117-123 falls back to default when a severity has no route.
    pack = _load(_SHIPPED["ops"])
    pack["body"] = {"default": "ticket", "runbook": pack["body"].get("runbook", "kb")}
    assert validate_pack(pack) == []


def test_ops_routes_only_is_valid() -> None:
    pack = _load(_SHIPPED["ops"])
    pack["body"] = {"routes": {"high": "email", "critical": "page"}}
    assert validate_pack(pack) == []


def test_ops_neither_default_nor_routes_rejected() -> None:
    pack = _load(_SHIPPED["ops"])
    pack["body"] = {"runbook": "kb"}
    assert validate_pack(pack)


def test_ops_null_runbook_is_valid() -> None:
    # alerts/module.py:157 uses a truthy check on runbook, so null/absent is tolerated.
    pack = _load(_SHIPPED["ops"])
    pack["body"]["runbook"] = None
    assert validate_pack(pack) == []


# --- Structural fail-closed cases -------------------------------------------------------------

def test_unknown_pack_type_rejected() -> None:
    errors = validate_pack({"manifest": {"id": "x", "type": "mystery"}, "body": {}})
    assert errors and "unknown pack type" in errors[0]


def test_missing_manifest_rejected() -> None:
    assert validate_pack({"body": {}})


def test_missing_body_rejected() -> None:
    errors = validate_pack({"manifest": {"id": "x", "type": "ops"}})
    assert errors and "body" in errors[0]


def test_errors_are_human_readable_strings() -> None:
    pack = _load(_SHIPPED["ops"])
    pack["body"] = {}  # neither default nor routes
    errors = validate_pack(pack)
    assert errors and all(isinstance(e, str) for e in errors)


def test_validate_pack_is_azure_free() -> None:
    """The pure validator must not import any Azure SDK (pure ⟂ I/O guardrail)."""
    source = (REPO / "src" / "packs_engine" / "schema.py").read_text(encoding="utf-8")
    assert "import azure" not in source and "from azure" not in source


# --- CI script fails closed on a bad body AND on a missing/misspelled manifest -----------------

def _load_script_main() -> Any:
    spec = importlib.util.spec_from_file_location("_validate_packs_cli", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.main


def test_script_passes_on_shipped_content() -> None:
    main = _load_script_main()
    assert main(["validate_packs.py", str(CONTENT)]) == 0


def test_script_fails_closed_on_malformed_body(tmp_path: Path) -> None:
    # A valid manifest (so Pydantic loads it) with a body that violates the ops schema (neither
    # default nor routes).
    bad = copy.deepcopy(_load(_SHIPPED["ops"]))
    bad["body"] = {"runbook": "kb"}
    (tmp_path / "bad-ops.json").write_text(json.dumps(bad), encoding="utf-8")

    main = _load_script_main()
    assert main(["validate_packs.py", str(tmp_path)]) == 1


def test_script_fails_closed_on_misspelled_manifest(tmp_path: Path) -> None:
    # FIX 1: a file whose top-level key is 'manifets' (typo) is skipped by the engine loader, but
    # the direct-enumeration schema gate must still FAIL closed.
    pack = copy.deepcopy(_load(_SHIPPED["ops"]))
    pack["manifets"] = pack.pop("manifest")  # introduce the typo
    (tmp_path / "typo.json").write_text(json.dumps(pack), encoding="utf-8")

    main = _load_script_main()
    assert main(["validate_packs.py", str(tmp_path)]) == 1


def test_script_fails_closed_on_invalid_body_in_schemas_subdir(tmp_path: Path) -> None:
    # FINDING 1: a valid-manifest/invalid-body pack placed under a 'schemas' subdir is still
    # discovered+executed by PacksEngine, so the validator must NOT exempt it — CI fails closed.
    bad = copy.deepcopy(_load(_SHIPPED["ops"]))
    bad["body"] = {"runbook": "kb"}  # neither default nor routes
    sub = tmp_path / "schemas"
    sub.mkdir()
    (sub / "bad-ops.json").write_text(json.dumps(bad), encoding="utf-8")

    main = _load_script_main()
    assert main(["validate_packs.py", str(tmp_path)]) == 1


def test_script_skips_registry_index(tmp_path: Path) -> None:
    # The pack registry index (#34) is infrastructure, not a pack: no manifest, {version, entries}.
    # It must be skipped by the pack-schema gate (the registry engine owns its integrity), so a
    # content root containing only the index passes.
    index = {"version": 1, "entries": []}
    reg = tmp_path / "registry"
    reg.mkdir()
    (reg / "index.json").write_text(json.dumps(index), encoding="utf-8")

    main = _load_script_main()
    assert main(["validate_packs.py", str(tmp_path)]) == 0


def test_valid_manifest_pack_under_registry_dir_is_still_validated(tmp_path: Path) -> None:
    # Anti-bypass: the registry-index skip is SHAPE-based, not PATH-based. A file carrying a
    # manifest (i.e. an executable pack) placed under a 'registry' subdir must STILL be schema
    # validated and fail closed on a bad body — otherwise the exemption would be a hiding spot.
    bad = copy.deepcopy(_load(_SHIPPED["ops"]))
    bad["body"] = {"runbook": "kb"}  # neither default nor routes
    reg = tmp_path / "registry"
    reg.mkdir()
    (reg / "sneaky.json").write_text(json.dumps(bad), encoding="utf-8")

    main = _load_script_main()
    assert main(["validate_packs.py", str(tmp_path)]) == 1


def test_non_pack_non_index_file_fails_closed(tmp_path: Path) -> None:
    # A stray file that is neither a pack (no manifest) nor the registry index shape must fail
    # closed — this is what catches a misspelled 'manifest' key or accidental junk under content/.
    (tmp_path / "junk.json").write_text(json.dumps({"foo": "bar"}), encoding="utf-8")

    main = _load_script_main()
    assert main(["validate_packs.py", str(tmp_path)]) == 1


def test_typo_manifest_with_index_keys_still_fails(tmp_path: Path) -> None:
    # The registry exemption is EXACT-shape: a mis-authored pack (misspelled 'manifest' + body)
    # that merely also carries version/entries keys must NOT be exempted — it fails closed.
    sneaky = {"manifets": {"id": "x", "type": "ops"}, "body": {}, "version": 1, "entries": []}
    (tmp_path / "sneaky.json").write_text(json.dumps(sneaky), encoding="utf-8")

    main = _load_script_main()
    assert main(["validate_packs.py", str(tmp_path)]) == 1


def test_registry_index_bool_version_fails(tmp_path: Path) -> None:
    # `type(version) is int` rejects bool (True is an int subclass) — not a valid index ⇒ fail.
    (tmp_path / "i.json").write_text(json.dumps({"version": True, "entries": []}), encoding="utf-8")

    main = _load_script_main()
    assert main(["validate_packs.py", str(tmp_path)]) == 1


def test_registry_index_wrong_version_fails(tmp_path: Path) -> None:
    # A version other than INDEX_SCHEMA_VERSION is not a recognized index ⇒ fail closed.
    (tmp_path / "i.json").write_text(json.dumps({"version": 999, "entries": []}), encoding="utf-8")

    main = _load_script_main()
    assert main(["validate_packs.py", str(tmp_path)]) == 1


def test_registry_index_with_malformed_entry_fails(tmp_path: Path) -> None:
    # An index whose entry does not parse via the registry's own RegistryEntry parser is not a
    # pristine index ⇒ not exempted ⇒ fails closed (the registry engine would also reject it).
    idx = {"version": 1, "entries": [{"not": "a valid entry"}]}
    (tmp_path / "i.json").write_text(json.dumps(idx), encoding="utf-8")

    main = _load_script_main()
    assert main(["validate_packs.py", str(tmp_path)]) == 1


def test_registry_index_with_duplicate_entries_fails(tmp_path: Path) -> None:
    # The shared parser rejects duplicate id@version refs (registry.py) — the CI gate must too, or
    # it would exempt an index that PackRegistry._load rejects.
    entry = {
        "id": "dup-pack",
        "version": "1.0.0",
        "type": "ops",
        "digest": "a" * 64,
        "createdAt": "2024-01-01T00:00:00+00:00",
    }
    idx = {"version": 1, "entries": [entry, dict(entry)]}
    (tmp_path / "i.json").write_text(json.dumps(idx), encoding="utf-8")

    main = _load_script_main()
    assert main(["validate_packs.py", str(tmp_path)]) == 1
