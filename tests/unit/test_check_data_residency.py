"""Tests for scripts/check_data_residency.py — the single-region data-residency gate (issue #63).

Guarantees under test (R1 + R2 + R3 hardening):
  1. The REAL infra/bicep on the current tree PASSES (every resource is co-located, defaultless
     child-module ``location`` params are validated by their parent call-site bindings).
  2. The gate FAILS CLOSED on every evasion probe — variable/param indirection to a foreign region,
     an object-spread foreign location, an unresolved/dynamic location, (R2) a **defaultless
     location param** used in isolation or a **module call site binding a foreign literal** to a
     child module's ``location``, and (R3) **whitespace/quoting/case variants** of the ``location``
     key plus a **compiled-ARM** foreign literal.
  3. The only trusted dynamic source is ``resourceGroup().location``; a param is trusted only when
     its default resolves to a permitted region, or every module call-site binding is permitted.

All fixtures are synthetic, secret-free bicep snippets.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "scripts" / "check_data_residency.py"
_INFRA = _REPO_ROOT / "infra" / "bicep"


def _load_cli():
    spec = importlib.util.spec_from_file_location("check_data_residency_cli", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Register before exec so dataclasses can resolve the module via __module__.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CHECK = _load_cli()

# A pinned permitted region for the "param with a permitted default" scenario.
_PERMITTED = frozenset({"australiaeast"})


def _kinds(text: str, **kw) -> list[str]:
    return [v.kind for v in CHECK.scan_bicep_text(text, "probe.bicep", **kw)]


# ---------------------------------------------------------------------------------------
# 1. The real infra passes (cross-file binding validation resolves child location params).
# ---------------------------------------------------------------------------------------
def test_real_infra_passes() -> None:
    violations = CHECK.run_check(_INFRA)
    assert violations == [], f"unexpected residency violations: {violations}"


def test_main_exit_zero_on_current_infra() -> None:
    assert CHECK.main([]) == 0


# ---------------------------------------------------------------------------------------
# 2. Accepted patterns produce no violation.
# ---------------------------------------------------------------------------------------
def test_parameterised_location_is_clean() -> None:
    text = (
        "param location string = resourceGroup().location\n"
        "resource a 'Microsoft.Storage/storageAccounts@2023-05-01' = {\n"
        "  name: 'wpst'\n"
        "  location: location\n"
        "}\n"
        "resource b 'Microsoft.KeyVault/vaults@2023-07-01' = {\n"
        "  name: 'wpkv'\n"
        "  location: resourceGroup().location\n"
        "}\n"
    )
    assert CHECK.scan_bicep_text(text, "clean.bicep") == []


def test_resource_group_location_is_clean() -> None:
    text = "resource a 'x@1' = {\n  location: resourceGroup().location\n}\n"
    assert CHECK.scan_bicep_text(text, "rg.bicep") == []


def test_location_with_trailing_comment_is_clean() -> None:
    text = (
        "param location string = resourceGroup().location\n"
        "resource a 'x@1' = {\n  location: location // in-boundary, single region\n}\n"
    )
    assert CHECK.scan_bicep_text(text, "commented.bicep") == []


def test_permitted_region_via_resolved_var_is_clean() -> None:
    # A var that resolves to resourceGroup().location must PASS (indirection to a permitted value).
    text = (
        "var regionSource = resourceGroup().location\n"
        "resource a 'x@1' = {\n  location: regionSource\n}\n"
    )
    assert CHECK.scan_bicep_text(text, "var-permitted.bicep") == []


def test_param_with_permitted_region_default_passes() -> None:
    # R2: a param whose DEFAULT is an explicitly permitted region literal is acceptable.
    text = (
        "param location string = 'australiaeast'\n"
        "resource a 'x@1' = {\n  location: location\n}\n"
    )
    assert CHECK.scan_bicep_text(text, "pinned.bicep", permitted_regions=_PERMITTED) == []


# ---------------------------------------------------------------------------------------
# 3. R2 evasion probes — defaultless params & module call-site bindings must FAIL closed.
# ---------------------------------------------------------------------------------------
def test_defaultless_location_param_in_isolation_is_violation() -> None:
    # R2 HIGH 2: a defaultless `param location string` is deploy-time controlled. Used with no
    # validated call-site binding it must FAIL CLOSED, not pass.
    text = "param location string\nresource a 'x@1' = {\n  location: location\n}\n"
    kinds = _kinds(text)
    assert "unresolved-location" in kinds


def test_defaultless_foreign_named_param_is_violation() -> None:
    # `param foreignRegion string` used as `location: foreignRegion` — deploy-time override bypass.
    text = "param foreignRegion string\nresource a 'x@1' = {\n  location: foreignRegion\n}\n"
    kinds = _kinds(text)
    assert "unresolved-location" in kinds


def test_param_with_foreign_default_is_violation() -> None:
    text = (
        "param location string = 'westeurope'\n"
        "resource a 'x@1' = {\n  location: location\n}\n"
    )
    kinds = _kinds(text)
    # param-default violation on the declaration, plus the resolved resource location.
    assert "param-default" in kinds
    assert "hardcoded-region" in kinds


def test_param_default_not_in_permitted_list_is_violation() -> None:
    # A region default that is NOT on the permitted allow-list is still a violation.
    text = (
        "param location string = 'japaneast'\n"
        "resource a 'x@1' = {\n  location: location\n}\n"
    )
    kinds = _kinds(text, permitted_regions=_PERMITTED)
    assert "param-default" in kinds


# ---------------------------------------------------------------------------------------
# 4. R1 evasion probes — variable/spread/unresolved indirection (regression coverage).
# ---------------------------------------------------------------------------------------
def test_probe_variable_indirected_foreign_region_is_caught() -> None:
    text = "var location = 'eastus'\nresource a 'x@1' = {\n  location: location\n}\n"
    assert "hardcoded-region" in _kinds(text)


def test_probe_spread_object_foreign_location_is_caught() -> None:
    text = (
        "resource a 'x@1' = {\n"
        "  properties: { ...base, location: 'westeurope' }\n"
        "}\n"
    )
    assert "hardcoded-region" in _kinds(text)


def test_probe_spread_source_object_foreign_location_is_caught() -> None:
    text = (
        "var base = {\n  location: 'westeurope'\n}\n"
        "resource a 'x@1' = {\n  location: resourceGroup().location\n}\n"
    )
    assert "hardcoded-region" in _kinds(text)


def test_probe_unresolved_dynamic_location_is_caught() -> None:
    text = "resource a 'x@1' = {\n  location: someDeploymentOverride\n}\n"
    assert _kinds(text) == ["unresolved-location"]


def test_probe_composed_object_var_location_is_caught() -> None:
    text = (
        "var loc = {\n  region: 'westeurope'\n}\n"
        "resource a 'x@1' = {\n  location: loc\n}\n"
    )
    assert "unresolved-location" in _kinds(text)


# ---------------------------------------------------------------------------------------
# 5. Direct violations (regression coverage retained).
# ---------------------------------------------------------------------------------------
def test_detects_hardcoded_region() -> None:
    text = (
        "resource a 'Microsoft.Storage/storageAccounts@2023-05-01' = {\n"
        "  name: 'wpst'\n"
        "  location: 'eastus'\n"
        "}\n"
    )
    violations = CHECK.scan_bicep_text(text, "bad.bicep")
    assert len(violations) == 1
    assert violations[0].kind == "hardcoded-region"
    assert violations[0].line == 3


def test_detects_cross_region_second_resource() -> None:
    text = (
        "param location string = resourceGroup().location\n"
        "resource a 'x@1' = {\n  location: location\n}\n"
        "resource b 'y@1' = {\n  location: 'westeurope'\n}\n"
    )
    violations = CHECK.scan_bicep_text(text, "mixed.bicep")
    assert [v.kind for v in violations] == ["hardcoded-region"]
    assert violations[0].detail.lower().find("westeurope") != -1


def test_detects_bad_param_default() -> None:
    text = "param location string = 'australiaeast'\n"
    violations = CHECK.scan_bicep_text(text, "param.bicep")
    assert len(violations) == 1
    assert violations[0].kind == "param-default"


# ---------------------------------------------------------------------------------------
# 6. Cross-file module call-site binding validation (R2).
# ---------------------------------------------------------------------------------------
def _write(dir_: Path, name: str, text: str) -> None:
    (dir_ / name).write_text(text, encoding="utf-8")


def test_module_permitted_binding_makes_child_pass(tmp_path: Path) -> None:
    # Parent binds child's defaultless `location` param to its own resourceGroup().location param.
    _write(
        tmp_path,
        "main.bicep",
        "param location string = resourceGroup().location\n"
        "module child 'child.bicep' = {\n"
        "  name: 'child'\n"
        "  params: {\n"
        "    location: location\n"
        "  }\n"
        "}\n",
    )
    _write(
        tmp_path,
        "child.bicep",
        "param location string\nresource a 'x@1' = {\n  location: location\n}\n",
    )
    assert CHECK.run_check(tmp_path) == []


def test_module_foreign_literal_binding_is_violation(tmp_path: Path) -> None:
    # Parent binds a FOREIGN literal into the child's location param — must fail closed.
    _write(
        tmp_path,
        "main.bicep",
        "param location string = resourceGroup().location\n"
        "module child 'child.bicep' = {\n"
        "  name: 'child'\n"
        "  params: {\n"
        "    location: 'westeurope'\n"
        "  }\n"
        "}\n",
    )
    _write(
        tmp_path,
        "child.bicep",
        "param location string\nresource a 'x@1' = {\n  location: location\n}\n",
    )
    violations = CHECK.run_check(tmp_path)
    kinds = [v.kind for v in violations]
    # Parent flags the foreign literal binding; child stays unresolved (binding not validated).
    assert "hardcoded-region" in kinds
    assert "unresolved-location" in kinds


def test_module_foreign_param_binding_is_violation(tmp_path: Path) -> None:
    # Parent binds a deploy-time param (no permitted default) — child must not be trusted.
    _write(
        tmp_path,
        "main.bicep",
        "param foreignRegion string\n"
        "module child 'child.bicep' = {\n"
        "  name: 'child'\n"
        "  params: {\n"
        "    location: foreignRegion\n"
        "  }\n"
        "}\n",
    )
    _write(
        tmp_path,
        "child.bicep",
        "param location string\nresource a 'x@1' = {\n  location: location\n}\n",
    )
    violations = CHECK.run_check(tmp_path)
    assert any(v.kind == "unresolved-location" for v in violations)


def test_run_check_end_to_end_flags_synthetic_dir(tmp_path: Path) -> None:
    _write(tmp_path, "bad.bicep", "resource a 'x@1' = {\n  location: 'japaneast'\n}\n")
    violations = CHECK.run_check(tmp_path)
    assert any(v.kind == "hardcoded-region" for v in violations)


def test_missing_infra_dir_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        CHECK.run_check(tmp_path / "does-not-exist")


# ---------------------------------------------------------------------------------------
# 7. R3 HIGH 3 — whitespace/quoting/case regex hardening + compiled-ARM structural check.
# ---------------------------------------------------------------------------------------
def test_probe_space_before_colon_foreign_is_caught() -> None:
    # `location :` (space before colon) must not slip past the tolerant key regex.
    text = "resource a 'x@1' = { location : 'westeurope' }\n"
    assert "hardcoded-region" in _kinds(text)


def test_probe_quoted_location_key_foreign_is_caught() -> None:
    text = "resource a 'x@1' = { 'location': 'westeurope' }\n"
    assert "hardcoded-region" in _kinds(text)


def test_probe_uppercased_location_key_foreign_is_caught() -> None:
    text = "resource a 'x@1' = { LOCATION: 'westeurope' }\n"
    assert "hardcoded-region" in _kinds(text)


def test_probe_quoted_and_spaced_location_key_foreign_is_caught() -> None:
    text = "resource a 'x@1' = { \"Location\" : 'westeurope' }\n"
    assert "hardcoded-region" in _kinds(text)


def test_similar_key_allocation_is_not_matched() -> None:
    # The negative lookbehind must avoid matching keys that merely END in `location`.
    text = (
        "resource a 'x@1' = {\n"
        "  allocation: 'westeurope'\n"
        "  location: resourceGroup().location\n"
        "}\n"
    )
    assert _kinds(text) == []


def test_scan_arm_template_flags_foreign_literal() -> None:
    template = {"resources": [{"type": "T", "name": "n", "location": "westeurope"}]}
    violations: list = []
    CHECK.scan_arm_template(template, {}, "arm.json", frozenset(), violations)
    assert [v.kind for v in violations] == ["hardcoded-region"]


def test_scan_arm_template_permits_resource_group_location() -> None:
    template = {
        "resources": [{"type": "T", "name": "n", "location": "[resourceGroup().location]"}]
    }
    violations: list = []
    CHECK.scan_arm_template(template, {}, "arm.json", frozenset(), violations)
    assert violations == []


def test_scan_arm_template_resolves_param_to_permitted() -> None:
    template = {
        "parameters": {"location": {"defaultValue": "[resourceGroup().location]"}},
        "resources": [{"type": "T", "name": "n", "location": "[parameters('location')]"}],
    }
    violations: list = []
    CHECK.scan_arm_template(template, {}, "arm.json", frozenset(), violations)
    assert violations == []


def test_scan_arm_template_resolves_param_to_foreign_literal() -> None:
    template = {
        "parameters": {"region": {"defaultValue": "westeurope"}},
        "resources": [{"type": "T", "name": "n", "location": "[parameters('region')]"}],
    }
    violations: list = []
    CHECK.scan_arm_template(template, {}, "arm.json", frozenset(), violations)
    assert any(v.kind == "hardcoded-region" for v in violations)


def test_scan_arm_template_nested_deployment_foreign_literal_is_caught() -> None:
    template = {
        "resources": [
            {
                "type": "Microsoft.Resources/deployments",
                "name": "child",
                "properties": {
                    "template": {
                        "resources": [
                            {"type": "T", "name": "n", "location": "westeurope"}
                        ]
                    }
                },
            }
        ]
    }
    violations: list = []
    CHECK.scan_arm_template(template, {}, "arm.json", frozenset(), violations)
    assert any(v.kind == "hardcoded-region" for v in violations)


@pytest.mark.skipif(CHECK._az_executable() is None, reason="az CLI not available")
def test_compiled_arm_foreign_literal_end_to_end(tmp_path: Path) -> None:
    # Compile a bicep whose formatting evades a naive regex; the compiled-ARM pass must catch it.
    _write(
        tmp_path,
        "main.bicep",
        "resource a 'Microsoft.Storage/storageAccounts@2023-05-01' = {\n"
        "  name: 'wpst'\n"
        "  location : 'westeurope'\n"
        "}\n",
    )
    violations = CHECK.run_check(tmp_path)
    assert any(v.kind == "hardcoded-region" for v in violations)


# ---------------------------------------------------------------------------------------
# 5. R4 MED — offline fallback: multiline + comment-interrupted `location` must be caught.
# ---------------------------------------------------------------------------------------
def test_probe_multiline_location_foreign_is_caught() -> None:
    # `location:` on its own line with the value on the next line must not slip past.
    text = "resource a 'x@1' = {\n  location:\n    'westeurope'\n}\n"
    assert "hardcoded-region" in _kinds(text)


def test_probe_block_comment_interrupted_location_is_caught() -> None:
    # A `/* ... */` gap between the key and colon must be stripped before matching.
    text = "resource a 'x@1' = {\n  location /* gap */ : 'westeurope'\n}\n"
    assert "hardcoded-region" in _kinds(text)


def test_probe_block_comment_hiding_value_is_stripped() -> None:
    # A block comment before the real value must not hide a foreign region.
    text = "resource a 'x@1' = {\n  location: /* note */ 'westeurope'\n}\n"
    assert "hardcoded-region" in _kinds(text)


def test_similar_key_allocation_multiline_is_not_matched() -> None:
    # `allocation:` must stay a non-match even across the multiline whole-text scan.
    text = "var allocation = 5\nresource a 'x@1' = {\n  allocation: 5\n}\n"
    assert _kinds(text) == []


def test_permitted_multiline_location_passes() -> None:
    text = "resource a 'x@1' = {\n  location:\n    resourceGroup().location\n}\n"
    assert _kinds(text) == []


def test_url_in_string_is_not_treated_as_comment() -> None:
    # A `//` inside a single-quoted string value must not be stripped as a line comment.
    text = (
        "param location string = resourceGroup().location\n"
        "resource a 'x@1' = {\n"
        "  endpoint: 'https://example.invalid/path'\n"
        "  location: location\n"
        "}\n"
    )
    assert CHECK.scan_bicep_text(text, "url.bicep") == []
