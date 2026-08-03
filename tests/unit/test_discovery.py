"""Discovery module — ARG edge, pack-driven classification, and fail-closed behaviour.

All fixtures are synthetic and clearly fake (GUID ``00000000...``); no customer data, no secrets,
no real network/Azure calls. The module and its pure helpers are exercised without the azure SDK.
"""
from __future__ import annotations

import importlib
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from modules.discovery.arg import (
    DEFAULT_ARG_QUERY,
    ResourceGraphClient,
    ResourceGraphPagingError,
    RowMappingError,
    collect_pages,
    row_to_node,
    rows_to_nodes,
)
from modules.discovery.module import (
    RESOURCE_GRAPH_CLIENT,
    DiscoveryModule,
    classify,
    definitions_from_packs,
)
from packs_engine.engine import PacksEngine
from shared.contracts import PackType, ResourceNode
from shared.module_base import ModuleContext

CONTENT = Path(__file__).resolve().parents[2] / "content"


# --------------------------------------------------------------------------------------
# Synthetic fixtures — clearly fake ids/tags. Never real customer data.
# --------------------------------------------------------------------------------------
def _synthetic_rows() -> list[dict[str, Any]]:
    sub = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-fake"
    return [
        {
            "id": f"{sub}/providers/Microsoft.Compute/virtualMachines/vm-odb-01",
            "name": "vm-odb-01",
            "type": "Microsoft.Compute/virtualMachines",
            "tags": {"epic-role": "odb"},
        },
        {
            "id": f"{sub}/providers/Microsoft.Compute/virtualMachines/vm-web-01",
            "name": "vm-web-01",
            "type": "Microsoft.Compute/virtualMachines",
            "tags": {"epic-role": "web"},
        },
        {
            # Unknown/unmodelled type: still becomes a node, but stays unclassified (fail closed).
            "id": f"{sub}/providers/Microsoft.Cache/redis/cache-fake",
            "name": "cache-fake",
            "type": "Microsoft.Cache/redis",
            "tags": None,
        },
    ]


class FakeResourceGraphClient:
    """Synthetic ARG client — returns canned rows, records the scope, does zero I/O."""

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows
        self.seen_scope: Mapping[str, str] | None = None

    def query(self, scope: Mapping[str, str]) -> list[Mapping[str, Any]]:
        self.seen_scope = scope
        return list(self._rows)


class BoomResourceGraphClient:
    """ARG client that always fails — used to prove the module fails closed, never crashes."""

    def query(self, scope: Mapping[str, str]) -> list[Mapping[str, Any]]:
        raise RuntimeError("synthetic ARG outage")


class PagingExhaustionResourceGraphClient:
    """ARG client whose paging never completes — query() raises via collect_pages (fail closed)."""

    def query(self, scope: Mapping[str, str]) -> list[Mapping[str, Any]]:
        def fetch_page(skip_token: str | None) -> tuple[list[Mapping[str, Any]], str | None]:
            return [{"id": "partial", "name": "n", "type": "t"}], "never-clears"

        return collect_pages(fetch_page)


def _workload_packs() -> list[Any]:
    return list(PacksEngine(CONTENT).load_all(pack_type=PackType.workload, verify_sig=False))


# --------------------------------------------------------------------------------------
# Protocol conformance + pure row mapping.
# --------------------------------------------------------------------------------------
def test_fake_client_satisfies_protocol():
    assert isinstance(FakeResourceGraphClient([]), ResourceGraphClient)


def test_row_to_node_maps_required_fields_and_stringifies_tags():
    node = row_to_node(
        {"id": "rid-1", "name": "n1", "type": "Microsoft.Compute/virtualMachines",
         "tags": {"epic-role": "odb", "num": 7, "skip": None}}
    )
    assert node.id == "rid-1"
    assert node.type == "Microsoft.Compute/virtualMachines"
    assert node.tags == {"epic-role": "odb", "num": "7"}
    # Freshly mapped nodes are unclassified — classification is a separate, pure step.
    assert node.workload is None and node.tier is None and node.role is None


@pytest.mark.parametrize(
    "row",
    [
        {"name": "n", "type": "t"},                       # missing id
        {"id": "x", "type": "t"},                         # missing name
        {"id": "x", "name": "n"},                         # missing type
        {"id": "  ", "name": "n", "type": "t"},           # blank id
        {"id": "x", "name": "n", "type": ""},             # blank type
        {"id": "x", "name": None, "type": "t"},           # null name
    ],
)
def test_row_to_node_fails_closed_on_malformed(row: dict[str, Any]):
    with pytest.raises(RowMappingError):
        row_to_node(row)


def test_rows_to_nodes_skips_and_reports_malformed():
    rows: list[Mapping[str, Any]] = [
        {"id": "ok", "name": "n", "type": "Microsoft.Compute/virtualMachines"},
        {"name": "bad"},  # malformed -> skipped
    ]
    nodes, skipped = rows_to_nodes(rows)
    assert [n.id for n in nodes] == ["ok"]
    assert len(skipped) == 1


# --------------------------------------------------------------------------------------
# Pack flattening + pure classify (tier/role/tag-miss).
# --------------------------------------------------------------------------------------
def test_definitions_from_packs_inherits_pack_workload():
    # Scope to the epic-core pack only: the platform ships multiple workload packs (Epic +
    # the synthetic bespoke multi-tier example), so this asserts epic-core's OWN definitions
    # inherit its pack-level ``workload`` rather than assuming a single workload pack exists.
    epic_packs = [p for p in _workload_packs() if p.manifest.id == "epic-core"]
    defs = definitions_from_packs(epic_packs)
    assert defs, "epic-core workload pack should yield definitions"
    assert all(d.get("workload") == "epic" for d in defs)
    assert any(d.get("role") == "odb" and d.get("tier") == "database" for d in defs)


def test_classify_assigns_tier_and_role_from_tag_rule():
    node = ResourceNode(id="vm", name="vm", type="Microsoft.Compute/virtualMachines",
                        tags={"epic-role": "odb"})
    out = classify([node], definitions_from_packs(_workload_packs()))
    assert out[0].workload == "epic"
    assert out[0].tier == "database"
    assert out[0].role == "odb"


def test_classify_leaves_node_unclassified_on_tag_miss():
    # Right resource type, wrong tag value -> no definition matches -> stays unclassified.
    node = ResourceNode(id="vm", name="vm", type="Microsoft.Compute/virtualMachines",
                        tags={"epic-role": "nope"})
    out = classify([node], definitions_from_packs(_workload_packs()))
    assert out[0].workload is None and out[0].tier is None and out[0].role is None


def test_classify_matches_type_only_definition():
    node = ResourceNode(id="lb", name="lb", type="Microsoft.Network/loadBalancers")
    out = classify([node], definitions_from_packs(_workload_packs()))
    assert out[0].role == "lb"
    assert out[0].tier == "presentation"


def test_classify_is_case_insensitive_on_resource_type():
    # ARG frequently returns fully-lowercased types; a lowercase type + valid tag must still
    # classify against the pack's canonically-cased definition. The stored ``type`` is preserved.
    lowercase_type = "microsoft.compute/virtualmachines"
    node = ResourceNode(id="vm", name="vm", type=lowercase_type, tags={"epic-role": "odb"})
    out = classify([node], definitions_from_packs(_workload_packs()))
    assert out[0].workload == "epic"
    assert out[0].tier == "database"
    assert out[0].role == "odb"
    assert out[0].type == lowercase_type  # original casing preserved, not normalized


# --------------------------------------------------------------------------------------
# ARG paging — the loop is driven by an injectable fetcher, no Azure SDK required.
# --------------------------------------------------------------------------------------
def test_collect_pages_aggregates_all_rows_across_two_pages():
    page1 = [{"id": f"r{i}", "name": f"n{i}", "type": "t"} for i in range(3)]
    page2 = [{"id": f"r{i}", "name": f"n{i}", "type": "t"} for i in range(3, 5)]
    pages: dict[str | None, tuple[list[Mapping[str, Any]], str | None]] = {
        None: (page1, "tok-2"),   # first page returns a skip_token -> more to fetch
        "tok-2": (page2, None),   # second (last) page clears the token
    }
    calls: list[str | None] = []

    def fetch_page(skip_token: str | None) -> tuple[list[Mapping[str, Any]], str | None]:
        calls.append(skip_token)
        return pages[skip_token]

    rows = collect_pages(fetch_page)
    assert [r["id"] for r in rows] == ["r0", "r1", "r2", "r3", "r4"]
    assert calls == [None, "tok-2"]  # paged exactly twice, driven by the skip_token


def test_collect_pages_single_page_stops_immediately():
    def fetch_page(skip_token: str | None) -> tuple[list[Mapping[str, Any]], str | None]:
        return [{"id": "only", "name": "n", "type": "t"}], None

    rows = collect_pages(fetch_page)
    assert [r["id"] for r in rows] == ["only"]


def test_collect_pages_fails_closed_when_token_never_clears():
    # A backend that always returns a token would exceed _MAX_PAGES; refuse the partial estate.
    def fetch_page(skip_token: str | None) -> tuple[list[Mapping[str, Any]], str | None]:
        # Distinct token each call so it's the page-limit (not repeat detection) that trips.
        nxt = f"tok-{(skip_token or 'tok-0').rsplit('-', 1)[-1]}x"
        return [{"id": "r", "name": "n", "type": "t"}], nxt

    with pytest.raises(ResourceGraphPagingError):
        collect_pages(fetch_page)


def test_collect_pages_fails_closed_on_repeating_token():
    # A non-advancing (stuck) loop: same token returned twice -> raise, never return partial rows.
    def fetch_page(skip_token: str | None) -> tuple[list[Mapping[str, Any]], str | None]:
        return [{"id": "r", "name": "n", "type": "t"}], "stuck"

    with pytest.raises(ResourceGraphPagingError):
        collect_pages(fetch_page)


# --------------------------------------------------------------------------------------
# DiscoveryModule.run — happy path, and fail-closed variants.
# --------------------------------------------------------------------------------------
def test_run_produces_and_classifies_estate_via_packs():
    fake = FakeResourceGraphClient(_synthetic_rows())
    ctx = ModuleContext(clients={RESOURCE_GRAPH_CLIENT: fake}, packs=PacksEngine(CONTENT))
    scope = {"subscription": "00000000-0000-0000-0000-000000000000"}
    result = DiscoveryModule().run(ctx, scope=scope)

    assert result.ok is True
    assert result.estate is not None
    assert result.extra["nodeCount"] == 3
    by_role = {n.id.split("/")[-1]: n for n in result.estate}
    assert by_role["vm-odb-01"].role == "odb"
    assert by_role["vm-web-01"].tier == "presentation"
    # Unknown type still became a node but stayed unclassified.
    assert by_role["cache-fake"].workload is None
    assert result.extra["classifiedCount"] == 2
    assert result.response is not None and 0.0 < result.response.confidence <= 1.0
    assert fake.seen_scope == scope


def test_run_fails_closed_without_client():
    # No resource_graph client injected -> empty estate, ok True, confidence 0.0, no crash.
    result = DiscoveryModule().run(ModuleContext(packs=PacksEngine(CONTENT)), scope={})
    assert result.ok is True
    assert result.estate == []
    assert result.extra["nodeCount"] == 0
    assert result.response is not None
    assert result.response.confidence == 0.0
    assert result.response.risks  # surfaced, not silent


def test_run_fails_closed_when_client_raises():
    ctx = ModuleContext(clients={RESOURCE_GRAPH_CLIENT: BoomResourceGraphClient()},
                        packs=PacksEngine(CONTENT))
    result = DiscoveryModule().run(ctx, scope={"subscription": "00000000"})
    assert result.ok is True
    # A failed query must NOT clear the estate (None = untouched), unlike the no-client case.
    assert result.estate is None
    assert result.response is not None and result.response.confidence == 0.0


def test_run_fails_closed_on_paging_exhaustion_does_not_clobber():
    # Incomplete paging raises inside query(); run() must return estate=None (don't clobber),
    # never a truncated/partial estate that could overwrite the complete persisted one.
    ctx = ModuleContext(clients={RESOURCE_GRAPH_CLIENT: PagingExhaustionResourceGraphClient()},
                        packs=PacksEngine(CONTENT))
    result = DiscoveryModule().run(ctx, scope={"subscription": "00000000"})
    assert result.ok is True
    assert result.estate is None
    assert result.extra["nodeCount"] == 0
    assert result.response is not None and result.response.confidence == 0.0


def test_run_leaves_nodes_unclassified_without_packs():
    fake = FakeResourceGraphClient(_synthetic_rows())
    result = DiscoveryModule().run(ModuleContext(clients={RESOURCE_GRAPH_CLIENT: fake}), scope={})
    assert result.ok is True
    assert result.estate is not None and len(result.estate) == 3
    assert all(n.workload is None for n in result.estate)
    assert result.extra["classifiedCount"] == 0


def test_run_skips_malformed_rows():
    rows = _synthetic_rows() + [{"name": "no-id-row"}]  # trailing malformed row
    fake = FakeResourceGraphClient(rows)
    ctx = ModuleContext(clients={RESOURCE_GRAPH_CLIENT: fake}, packs=PacksEngine(CONTENT))
    result = DiscoveryModule().run(ctx, scope={})
    assert result.extra["skippedRows"] == 1
    assert result.extra["nodeCount"] == 3


# --------------------------------------------------------------------------------------
# Guardrails: Azure-free import + no secrets.
# --------------------------------------------------------------------------------------
def test_importing_discovery_does_not_require_azure_sdk(monkeypatch: pytest.MonkeyPatch):
    # Simulate the azure SDK being absent; importing the module + arg edge must still succeed,
    # because every azure import is guarded lazily inside AzureResourceGraphClient methods.
    for name in list(sys.modules):
        if name == "azure" or name.startswith("azure."):
            monkeypatch.setitem(sys.modules, name, None)
    for mod in ("modules.discovery.arg", "modules.discovery.module"):
        monkeypatch.delitem(sys.modules, mod, raising=False)
        reloaded = importlib.import_module(mod)
        assert reloaded is not None


def test_source_contains_no_secrets():
    here = Path(__file__).resolve().parents[2] / "src" / "modules" / "discovery"
    banned = ("connectionstring=", "accountkey=", "password=", "sharedaccesskey")
    for path in here.glob("*.py"):
        text = path.read_text(encoding="utf-8").lower()
        assert not any(token in text for token in banned), f"possible secret in {path.name}"
    # The real client authenticates keyless via DefaultAzureCredential only.
    assert "defaultazurecredential" in (here / "arg.py").read_text(encoding="utf-8").lower()


def test_default_arg_query_is_read_only_projection():
    q = DEFAULT_ARG_QUERY.lower()
    assert q.startswith("resources")
    assert "project" in q
    # No mutation verbs — ARG is read-only by construction, but assert we never smuggle one in.
    assert not any(verb in q for verb in ("delete", "update", "insert", "set "))
