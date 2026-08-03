"""Integration tests for the read-only blast-radius impact endpoint (issue #56).

Drives the FastAPI app with a ``TestClient`` against an isolated store and proves the endpoint
returns the CANONICAL :func:`shared.blast_radius.compute_impact` result (no duplicated math) and
fails **closed**: unknown node and missing graph both surface as errors, never a silent all-up map.

All fixtures are synthetic, clearly-fake resources (no PHI/PII, no secrets).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.app.main import app, get_store
from shared.state import LocalStateStore

VM = "vm"

# web x2 -> lb (redundant), ecp x2 -> odb (non-redundant). Mirrors the pure-math test fixture so
# the endpoint's numbers can be checked against the canonical `blast_radius.py` behaviour.
EPIC_GRAPH = {
    "nodes": [
        {"id": "odb", "name": "odb", "type": VM},
        {"id": "ecp1", "name": "ecp1", "type": VM},
        {"id": "ecp2", "name": "ecp2", "type": VM},
        {"id": "web1", "name": "web1", "type": VM},
        {"id": "web2", "name": "web2", "type": VM},
        {"id": "lb", "name": "lb", "type": VM},
    ],
    "edges": [
        {"source": "ecp1", "target": "odb", "type": "depends_on", "redundant": False},
        {"source": "ecp2", "target": "odb", "type": "depends_on", "redundant": False},
        {"source": "web1", "target": "lb", "type": "load_balances", "redundant": True},
        {"source": "web2", "target": "lb", "type": "load_balances", "redundant": True},
    ],
}


@pytest.fixture
def client(tmp_path):
    """TestClient backed by an isolated on-disk store injected via ``dependency_overrides``."""
    store = LocalStateStore(str(tmp_path))
    app.dependency_overrides[get_store] = lambda: store
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def _seed_graph(client: TestClient, workload: str = "epic") -> None:
    assert client.post(f"/api/workloads/{workload}/graph", json=EPIC_GRAPH).status_code == 200


def test_impact_non_redundant_downs_dependents(client):
    _seed_graph(client)
    resp = client.get("/api/workloads/epic/impact", params={"node": "odb"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["failedNode"] == "odb"
    # odb downs both ecp nodes (hard dependency), radius 2 — the canonical result.
    assert body["blastRadius"] == 2
    assert body["down"] == ["ecp1", "ecp2"]
    assert body["degraded"] == []
    assert body["states"]["odb"] == "down"
    assert body["states"]["ecp1"] == "down"
    assert body["states"]["web1"] == "up"


def test_impact_and_graph_endpoints_agree_on_graph_revision(client):
    _seed_graph(client)
    graph_rev = client.get("/api/workloads/epic/graph").json()["graphRevision"]
    impact_rev = client.get(
        "/api/workloads/epic/impact", params={"node": "odb"}
    ).json()["graphRevision"]
    # Both come from the SAME server-side `graph_revision` → the web can compare them opaquely.
    assert graph_rev and impact_rev == graph_rev


def test_graph_revision_tracks_edge_changes(client):
    _seed_graph(client)
    rev_before = client.get("/api/workloads/epic/graph").json()["graphRevision"]
    # Re-persist the SAME nodes but drop an edge — node ids unchanged, topology changed.
    fewer_edges = {"nodes": EPIC_GRAPH["nodes"], "edges": EPIC_GRAPH["edges"][1:]}
    assert client.post("/api/workloads/epic/graph", json=fewer_edges).status_code == 200
    rev_after = client.get("/api/workloads/epic/graph").json()["graphRevision"]
    assert rev_before != rev_after


def test_impact_redundant_edge_degrades_not_downs(client):
    _seed_graph(client)
    resp = client.get("/api/workloads/epic/impact", params={"node": "lb"})
    assert resp.status_code == 200
    body = resp.json()
    # Redundant load-balanced web tier degrades (not down); blast radius is 0.
    assert body["blastRadius"] == 0
    assert body["down"] == []
    assert body["degraded"] == ["web1", "web2"]
    assert body["states"]["web1"] == "degraded"
    assert body["states"]["lb"] == "down"


def test_impact_unknown_node_fails_closed(client):
    _seed_graph(client)
    resp = client.get("/api/workloads/epic/impact", params={"node": "ghost"})
    # Fail closed: unknown node is a 404, never a silent all-up map.
    assert resp.status_code == 404
    assert "ghost" in resp.json()["detail"]


def test_impact_missing_node_param_is_422(client):
    _seed_graph(client)
    # A missing required `node` query param is rejected before any math runs (fail closed).
    assert client.get("/api/workloads/epic/impact").status_code == 422


def test_impact_no_graph_is_404(client):
    resp = client.get("/api/workloads/nope/impact", params={"node": "odb"})
    assert resp.status_code == 404
    assert "nope" in resp.json()["detail"]


def test_impact_endpoint_does_not_mutate_state(client):
    _seed_graph(client)
    before = client.get("/api/workloads/epic/graph").json()
    client.get("/api/workloads/epic/impact", params={"node": "odb"})
    after = client.get("/api/workloads/epic/graph").json()
    assert before == after  # read-only: the graph is untouched by an impact query
