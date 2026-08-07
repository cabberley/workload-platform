"""Local ``StateStore`` tests for pack-version assignments (issue #37).

Deterministic, Azure-free: the local sqlite ``LocalStateStore`` in an isolated ``tmp_path``. Each
test would fail without the corresponding put/get/list assignment method. All data is synthetic,
clearly-fake — no PHI/PII, no secrets.
"""
from __future__ import annotations

import pytest

from shared.contracts import PackAssignment
from shared.state import LocalStateStore, StateStore


@pytest.fixture()
def store(tmp_path) -> LocalStateStore:
    return LocalStateStore(str(tmp_path))


def _assignment(
    workload: str = "epic",
    pack_id: str = "waf-reliability-baseline",
    version: str = "1.2.0",
    by: str = "customer@example.test",
) -> PackAssignment:
    return PackAssignment(workload=workload, packId=pack_id, version=version, assignedBy=by)


def test_local_store_satisfies_statestore_protocol(store: LocalStateStore) -> None:
    # The new assignment methods keep the local backend a structural ``StateStore``.
    assert isinstance(store, StateStore)


def test_put_and_get_assignment_round_trips(store: LocalStateStore) -> None:
    assert store.get_pack_assignments("epic") == []
    a = _assignment()
    store.put_pack_assignment(a)
    loaded = store.get_pack_assignments("epic")
    assert len(loaded) == 1
    assert loaded[0].workload == "epic"
    assert loaded[0].packId == "waf-reliability-baseline"
    assert loaded[0].version == "1.2.0"
    assert loaded[0].assignedBy == "customer@example.test"
    # Provenance timestamp round-trips as a datetime.
    assert loaded[0].assignedAt == a.assignedAt


def test_put_replaces_existing_version_single_active_per_pack(store: LocalStateStore) -> None:
    store.put_pack_assignment(_assignment(version="1.2.0", by="ms@example.test"))
    store.put_pack_assignment(_assignment(version="2.0.0", by="customer@example.test"))
    loaded = store.get_pack_assignments("epic")
    # Keyed by (workload, packId): the second assignment REPLACES the first — one active version.
    assert len(loaded) == 1
    assert loaded[0].version == "2.0.0"
    assert loaded[0].assignedBy == "customer@example.test"


def test_get_assignments_is_scoped_to_the_workload(store: LocalStateStore) -> None:
    store.put_pack_assignment(_assignment(workload="epic", version="1.0.0"))
    store.put_pack_assignment(_assignment(workload="sap", version="3.1.0"))
    epic = store.get_pack_assignments("epic")
    assert [(x.workload, x.version) for x in epic] == [("epic", "1.0.0")]
    assert store.get_pack_assignments("unknown") == []


def test_get_assignments_ordered_by_pack_id(store: LocalStateStore) -> None:
    store.put_pack_assignment(_assignment(pack_id="z-pack", version="1.0.0"))
    store.put_pack_assignment(_assignment(pack_id="a-pack", version="1.0.0"))
    assert [x.packId for x in store.get_pack_assignments("epic")] == ["a-pack", "z-pack"]


def test_list_assignments_spans_all_workloads(store: LocalStateStore) -> None:
    assert store.list_pack_assignments() == []
    store.put_pack_assignment(_assignment(workload="sap", pack_id="ops", version="1.0.0"))
    store.put_pack_assignment(_assignment(workload="epic", pack_id="rules", version="2.0.0"))
    listed = store.list_pack_assignments()
    # MS + customer visibility: every assignment, ordered by (workload, packId).
    assert [(x.workload, x.packId, x.version) for x in listed] == [
        ("epic", "rules", "2.0.0"),
        ("sap", "ops", "1.0.0"),
    ]
