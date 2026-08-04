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
from packs_engine.engine import Pack
from shared.contracts import ModuleRunResult, PackManifest, PackType
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
    assert probe.seen.packs is packs, "ctx.packs must be the injected engine, not None"
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
