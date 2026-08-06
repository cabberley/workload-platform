"""Integration tests for the runtime composition root (issue #24).

Drives the FastAPI app with a ``TestClient`` to prove the wiring is REAL, not a no-op:
  * ``/api/modules/{name}/run`` injects packs + read-only state + edge clients and the module
    actually produces work end-to-end (quality_checks yields findings from injected packs+state);
  * ``ctx.packs``/``ctx.clients`` are TRULY the injected objects (no longer ``None``);
  * the API remains the single writer (a scoped run commits; an unscoped run commits nothing);
  * the worker-side ``ApiStateReader`` satisfies the full ``ReadableState`` over HTTP — including
    the two new previous-* endpoints — and exposes NO write methods.

All fixtures are synthetic, clearly-fake resources (no PHI/PII, no secrets).
"""
from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.app.main import app, get_clients, get_packs, get_store, registry
from cli.state_client import ApiStateReader
from cli.wiring import WorkloadPinnedPacks
from packs_engine.engine import Pack
from shared.contracts import (
    REDACTED,
    ModuleRunResult,
    PackManifest,
    PackType,
    ResourceNode,
    WorkloadGraph,
)
from shared.module_base import Module, ModuleContext
from shared.state import LocalStateStore, ReadableState

VM_TYPE = "Microsoft.Compute/virtualMachines"


# --------------------------------------------------------------------------------------
# Fakes injected via dependency_overrides (Azure-free, deterministic).
# --------------------------------------------------------------------------------------
class FakePacks:
    """Stand-in packs engine returning pre-built, already-'verified' Rule Packs."""

    def __init__(self, packs: list[Pack]) -> None:
        self._packs = packs

    def load_for_workload(self, workload: str, pack_type: PackType) -> list[Pack]:
        return [
            p for p in self._packs
            if p.manifest.type == pack_type
            and (not p.manifest.targets or workload in p.manifest.targets)
        ]


def _rule_pack() -> Pack:
    manifest = PackManifest(
        id="waf-reliability-baseline", type=PackType.rule, name="WAF Reliability", version="1.2.0",
    )
    body: dict[str, Any] = {
        "rules": [
            {
                "id": "rel-01-zone",
                "title": "VMs carry an availability-zone tag",
                "resourceType": VM_TYPE,
                "requiredTag": "availability-zone",
                "severity": "high",
                "description": "WAF Reliability: critical tiers should be zone-aware.",
            }
        ]
    }
    return Pack(manifest=manifest, body=body)


class _CtxProbe(Module):
    """A throwaway module that records the ModuleContext it was handed."""

    def __init__(self) -> None:
        self.seen: ModuleContext | None = None
        base = registry.get("aiops").manifest
        self._manifest = base.model_copy(update={"name": "ctx_probe", "displayName": "probe"})

    @property
    def manifest(self):  # type: ignore[override]
        return self._manifest

    def run(self, ctx: ModuleContext, *, scope=None) -> ModuleRunResult:
        self.seen = ctx
        return ModuleRunResult(module=self.name, ok=True)


@pytest.fixture
def wired(tmp_path):
    """TestClient with an isolated store + fake packs/clients injected as FastAPI deps."""
    store = LocalStateStore(str(tmp_path))
    packs = FakePacks([_rule_pack()])
    clients: dict[str, object] = {"resource_graph": object()}
    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_packs] = lambda: packs
    app.dependency_overrides[get_clients] = lambda: clients
    with TestClient(app) as client:
        yield client, packs, clients, store
    app.dependency_overrides.clear()


def _seed_estate(client: TestClient, workload: str, *, tagged: bool) -> None:
    nodes = [
        {"id": "vm-ok", "name": "vm-ok", "type": VM_TYPE, "tags": {"availability-zone": "1"}},
        {"id": "vm-bad", "name": "vm-bad", "type": VM_TYPE, "tags": {}},
    ]
    if not tagged:
        nodes = [nodes[1]]
    resp = client.post(f"/api/workloads/{workload}/estate", json=nodes)
    assert resp.status_code == 200


# --------------------------------------------------------------------------------------
# The run endpoint injects packs + state end-to-end AND the API remains the single writer.
# --------------------------------------------------------------------------------------
def test_run_endpoint_produces_work_from_injected_packs_and_state_and_commits(wired):
    client, _packs, _clients, _store = wired
    _seed_estate(client, "epic", tagged=True)

    resp = client.post("/api/modules/quality_checks/run", json={"scope": {"workload": "epic"}})
    assert resp.status_code == 200
    result = resp.json()
    # No longer a no-op: real findings computed from the injected Rule Pack + read-only estate.
    assert result["findings"], "expected findings from injected packs+state"
    assert any(f["passed"] is False for f in result["findings"])
    assert all(f["packId"] == "waf-reliability-baseline" for f in result["findings"])

    # The API (single writer) committed the run.
    committed = client.get("/api/workloads/epic/findings").json()
    assert len(committed) == len(result["findings"])


def test_run_without_workload_scope_commits_nothing(wired):
    client, _packs, _clients, _store = wired
    _seed_estate(client, "epic", tagged=False)

    resp = client.post("/api/modules/quality_checks/run", json={"scope": {}})
    assert resp.status_code == 200
    # It still COMPUTES across known workloads (proving state was injected)...
    assert resp.json()["findings"]
    # ...but with no workload in scope the API never calls commit_run — nothing is written.
    assert client.get("/api/workloads/epic/findings").json() == []


def test_run_endpoint_truly_injects_packs_and_clients_not_none(wired):
    client, packs, clients, _store = wired
    probe = _CtxProbe()
    registry.register(probe)
    try:
        resp = client.post(f"/api/modules/{probe.name}/run", json={"scope": {}})
        assert resp.status_code == 200
    finally:
        registry._modules.pop(probe.name, None)

    assert probe.seen is not None
    # The resolver is now ALWAYS applied (issue #37) so no run can execute multiple versions of an
    # id — even a workload-less run. ctx.packs is therefore the resolver view WRAPPING the injected
    # engine (not None, and not a different engine).
    assert isinstance(probe.seen.packs, WorkloadPinnedPacks)
    assert probe.seen.packs._engine is packs, "resolver must wrap the injected engine, not None"
    assert probe.seen.clients is clients, "ctx.clients must be the injected registry"


# --------------------------------------------------------------------------------------
# ApiStateReader — full ReadableState over HTTP, no write methods (single-writer preserved).
# --------------------------------------------------------------------------------------
def test_api_state_reader_roundtrips_full_readable_state(wired):
    client, _packs, _clients, _store = wired
    reader = ApiStateReader(base_url=str(client.base_url), client=client)

    nodes = [{"id": "vm1", "name": "vm1", "type": VM_TYPE, "tags": {"availability-zone": "1"}}]
    assert client.post("/api/workloads/epic/estate", json=nodes).status_code == 200
    graph = {"nodes": nodes, "edges": [{"source": "vm1", "target": "vm1"}]}
    assert client.post("/api/workloads/epic/graph", json=graph).status_code == 200
    findings = [
        {"id": "f1", "module": "quality_checks", "title": "t", "passed": False,
         "severity": "high", "nodeId": "vm1",
         "packId": "waf-reliability-baseline", "packVersion": "1.2.0",
         "evidence": [{"kind": "resource", "id": "vm1"}]}
    ]
    assert client.post("/api/workloads/epic/findings", json=findings).status_code == 200
    # Snapshot so the two NEW previous-* endpoints have data to serve.
    assert client.post("/api/workloads/epic/snapshot").status_code == 200

    assert reader.list_workloads() == ["epic"]
    assert [n.id for n in reader.get_estate("epic")] == ["vm1"]
    g = reader.get_graph("epic")
    assert g is not None and [n.id for n in g.nodes] == ["vm1"]
    assert [f.id for f in reader.get_findings("epic")] == ["f1"]
    assert [f.id for f in reader.get_findings("epic", module="quality_checks")] == ["f1"]
    assert [f.id for f in reader.get_previous_findings("epic")] == ["f1"]
    assert reader.get_previous_node_ids("epic") == ["vm1"]


def test_api_rejects_structural_finding_carrying_blank_pack_id(wired):
    # FIX A (issue #83): a structural finding must have NO pack identity at all. A blank
    # (whitespace) packId is still pack identity — the API must fail closed with 422, never persist.
    client, _packs, _clients, _store = wired
    findings = [
        {"id": "s1", "module": "dependency_graph", "title": "spof", "passed": False,
         "severity": "high", "nodeId": "vm1", "provenance": "structural",
         "structuralKind": "spof", "packId": "   ",
         "evidence": [{"kind": "resource", "id": "vm1"}]}
    ]
    assert client.post("/api/workloads/epic/findings", json=findings).status_code == 422
    # Nothing persisted — fail closed leaves storage untouched.
    assert client.get("/api/workloads/epic/findings").json() == []


def test_api_rejects_structural_finding_from_unauthorized_module(wired):
    # FIX C (issue #83, guardrail #8): a structural/spof finding may only be emitted by its
    # authorized module (dependency_graph). A caller declaring a different module must fail closed
    # with 422 — it cannot mint a packless "critical" finding to bypass pack citation.
    client, _packs, _clients, _store = wired
    findings = [
        {"id": "spof::vm1", "module": "quality_checks", "title": "spof", "passed": False,
         "severity": "critical", "nodeId": "vm1", "provenance": "structural",
         "structuralKind": "spof",
         "evidence": [{"kind": "resource", "id": "vm1"}]}
    ]
    assert client.post("/api/workloads/epic/findings", json=findings).status_code == 422
    assert client.get("/api/workloads/epic/findings").json() == []


def test_api_accepts_structural_finding_from_authorized_module(wired):
    # The same structural/spof finding from the authorized emitter module persists (200).
    client, _packs, _clients, _store = wired
    findings = [
        {"id": "spof::vm1", "module": "dependency_graph", "title": "spof", "passed": False,
         "severity": "critical", "nodeId": "vm1", "provenance": "structural",
         "structuralKind": "spof",
         "evidence": [{"kind": "resource", "id": "vm1"}]}
    ]
    assert client.post("/api/workloads/epic/findings", json=findings).status_code == 200
    assert [f["id"] for f in client.get("/api/workloads/epic/findings").json()] == ["spof::vm1"]


def test_api_state_reader_fails_closed_on_unknown_workload(wired):
    client, _packs, _clients, _store = wired
    reader = ApiStateReader(base_url=str(client.base_url), client=client)

    assert reader.get_estate("nope") == []
    assert reader.get_graph("nope") is None  # 404 → None, never a crash
    assert reader.get_findings("nope") == []
    assert reader.get_previous_findings("nope") == []
    assert reader.get_previous_node_ids("nope") == []


def test_api_state_reader_has_no_write_methods_and_is_readable_state():
    reader = ApiStateReader(base_url="http://api:8000")
    for attr in ("put_estate", "put_graph", "add_findings", "commit_run", "snapshot"):
        assert not hasattr(reader, attr), f"ApiStateReader must not expose {attr} (single writer)"
    # Structurally satisfies the read-only Protocol (all six read methods present).
    assert isinstance(reader, ReadableState)


# --------------------------------------------------------------------------------------
# Issue #91 — the write/index endpoints return BOUNDED typed response models (no raw dicts).
# --------------------------------------------------------------------------------------
def test_root_and_modules_are_bounded_typed_responses(wired):
    client, _packs, _clients, _store = wired
    root = client.get("/").json()
    assert set(root) == {"name", "docs", "health"}
    assert root == {"name": "workloads-platform", "docs": "/docs", "health": "/api/health"}

    modules = client.get("/api/modules").json()
    assert isinstance(modules, list) and modules
    # Each entry is a ModuleManifest schema (bounded fields), not a free-form dict.
    assert all({"name", "displayName", "kind", "scaleProfile"} <= set(m) for m in modules)


def test_write_endpoints_return_bounded_count_schemas(wired):
    client, _packs, _clients, _store = wired
    nodes = [{"id": "vm1", "name": "vm1", "type": VM_TYPE, "tags": {"availability-zone": "1"}}]
    estate = client.post("/api/workloads/epic/estate", json=nodes)
    assert estate.status_code == 200 and estate.json() == {"count": 1}

    graph = {"nodes": nodes, "edges": [{"source": "vm1", "target": "vm1"}]}
    graph_resp = client.post("/api/workloads/epic/graph", json=graph)
    assert graph_resp.status_code == 200 and graph_resp.json() == {"nodes": 1, "edges": 1}

    findings = [
        {"id": "f1", "module": "quality_checks", "title": "t", "passed": False,
         "severity": "high", "nodeId": "vm1",
         "packId": "waf-reliability-baseline", "packVersion": "1.2.0",
         "evidence": [{"kind": "resource", "id": "vm1"}]}
    ]
    findings_resp = client.post("/api/workloads/epic/findings", json=findings)
    assert findings_resp.status_code == 200 and findings_resp.json() == {"count": 1}

    snap = client.post("/api/workloads/epic/snapshot")
    assert snap.status_code == 200
    assert set(snap.json()) == {"snapshotId"} and isinstance(snap.json()["snapshotId"], str)


def test_results_endpoint_returns_bounded_persist_counts(wired):
    client, _packs, _clients, _store = wired
    result = {
        "module": "discovery",
        "ok": True,
        "estate": [{"id": "vm1", "name": "vm1", "type": VM_TYPE, "tags": {}}],
        "findings": [],
    }
    resp = client.post("/api/workloads/epic/results", json=result)
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {"workload", "persisted"}
    assert body["workload"] == "epic"
    # Bounded per-kind counts — exactly the three known keys, no free-form egress.
    assert set(body["persisted"]) == {"estate", "graph", "findings"}
    assert body["persisted"]["estate"] == 1


# --------------------------------------------------------------------------------------
# Issue #91 (review fixes) — customer-controlled/derived free-form egress is redacted at the
# API RESPONSE boundary (tags on estate/graph reads; the nested ``extra`` on module-run).
# --------------------------------------------------------------------------------------
def test_estate_egress_default_redacts_tag_values_and_pii_keys(wired):
    client, _packs, _clients, _store = wired
    nodes = [
        {
            "id": "vm1", "name": "vm1", "type": VM_TYPE,
            "tags": {
                "patientName": "AliceSmith", "patientSSN": "123-45-6789",
                "patientMRN": "MRN123456", "env": "prod",
                "alice@contoso.com": "x",  # PII KEY
            },
        }
    ]
    assert client.post("/api/workloads/epic/estate", json=nodes).status_code == 200

    tags = client.get("/api/workloads/epic/estate").json()[0]["tags"]
    # Default-DENY: EVERY customer tag KEY is redacted to a distinct positional placeholder and
    # EVERY value to the sentinel — no deny-list survivors, and a "structurally valid" SSN key or a
    # PII email key can never egress verbatim.
    assert tags == {
        "redacted_key_0": REDACTED,
        "redacted_key_1": REDACTED,
        "redacted_key_2": REDACTED,
        "redacted_key_3": REDACTED,
        "redacted_key_4": REDACTED,
    }
    assert not ({"patientName", "patientSSN", "patientMRN", "env", "alice@contoso.com"} & set(tags))


def test_graph_egress_default_redacts_tag_values_and_pii_keys(wired):
    client, _packs, _clients, _store = wired
    nodes = [
        {
            "id": "vm1", "name": "vm1", "type": VM_TYPE,
            "tags": {"patientName": "AliceSmith", "alice@contoso.com": "x"},
        }
    ]
    graph = {"nodes": nodes, "edges": [{"source": "vm1", "target": "vm1"}]}
    assert client.post("/api/workloads/epic/graph", json=graph).status_code == 200

    tags = client.get("/api/workloads/epic/graph").json()["nodes"][0]["tags"]
    assert tags == {"redacted_key_0": REDACTED, "redacted_key_1": REDACTED}
    assert not ({"patientName", "alice@contoso.com"} & set(tags))


class _PIIModule(Module):
    """Throwaway module whose result carries customer-derived PII in tags + nested ``extra``."""

    def __init__(self) -> None:
        base = registry.get("aiops").manifest
        self._manifest = base.model_copy(update={"name": "pii_probe", "displayName": "pii"})

    @property
    def manifest(self):  # type: ignore[override]
        return self._manifest

    def run(self, ctx: ModuleContext, *, scope=None) -> ModuleRunResult:
        node = ResourceNode(
            id="vm1", name="vm1", type=VM_TYPE,
            tags={"patientName": "AliceSmith", "alice@contoso.com": "x"},
        )
        return ModuleRunResult(
            module=self.name,
            ok=True,
            estate=[node],
            graph=WorkloadGraph(nodes=[node], edges=[]),
            extra={
                # ``drift.<scope>`` keys are workload-/customer-derived (not allow-listed), so each
                # whole subtree is redacted wholesale (Finding 1, R4) — no schema knowledge below.
                "drift": {
                    "epic": {"newFailures": [{"id": "f1", "detail": "alice@contoso.com"}]},
                    "john@contoso.com": {"newFailures": []},  # workload-derived PII KEY
                },
                # An allow-listed nested structure: structure survives, string leaves redacted.
                "summary": {
                    "newFailures": [
                        {"id": "f1", "detail": "alice@contoso.com", "severity": "high"},
                    ],
                },
                "nodeCount": 1,
                # Finding 1: nested UNSUPPORTED leaf types under ALLOW-LISTED keys must be redacted,
                # never serialized raw (container recursion redacts set elements).
                "recovered": {"alice@contoso.com", "bob@contoso.com"},  # set
                "stillFailing": b"123-45-6789",  # bytes
                "addedNodes": ResourceNode(id="n", name="AliceSmith", type=VM_TYPE),  # model
            },
        )


def test_module_run_egress_default_redacts_extra_leaves_keys_and_tags(wired):
    client, _packs, _clients, _store = wired
    module = _PIIModule()
    registry.register(module)
    try:
        resp = client.post(f"/api/modules/{module.name}/run", json={"scope": {}})
    finally:
        registry._modules.pop(module.name, None)
    assert resp.status_code == 200
    body = resp.json()

    extra = body["extra"]
    # Module-schema keys (drift/summary/nodeCount) survive; customer-derived keys are redacted.
    assert extra["nodeCount"] == 1
    # Finding 1 (R4): under the untrusted ``drift.<scope>`` keys the WHOLE subtree is redacted
    # wholesale — the keys become distinct positional placeholders, the values the scalar sentinel.
    assert extra["drift"] == {"redacted_key_0": REDACTED, "redacted_key_1": REDACTED}
    assert "epic" not in extra["drift"]
    assert "john@contoso.com" not in extra["drift"]
    # Under allow-listed keys the structure survives and every free-form string leaf is redacted.
    leaf = extra["summary"]["newFailures"][0]
    assert leaf == {"id": REDACTED, "detail": REDACTED, "severity": REDACTED}
    # Nested unsupported leaf types under allow-listed keys are redacted (set → list of the
    # sentinel, bytes and a nested Pydantic model → the scalar sentinel) — raw PHI never egresses.
    assert extra["recovered"] == [REDACTED]  # set of PII emails collapsed to one sentinel
    assert extra["stillFailing"] == REDACTED  # bytes
    assert extra["addedNodes"] == REDACTED  # nested Pydantic model carrying PHI

    # Tags on the estate + graph carriers: every key placeholdered, every value redacted.
    assert body["estate"][0]["tags"] == {"redacted_key_0": REDACTED, "redacted_key_1": REDACTED}
    assert body["graph"]["nodes"][0]["tags"] == {
        "redacted_key_0": REDACTED,
        "redacted_key_1": REDACTED,
    }

