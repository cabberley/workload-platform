"""Tests for scripts/cleanup_verify_state_writers.py (issue #79 brownfield fix).

Boundary under test: on an incremental/brownfield deploy the ONLY principals allowed to hold a
state-store WRITE role (Storage Blob Data Owner / Blob Data Contributor / Table Data Contributor) at
the storage-account scope are the api and worker user-assigned identities. The verify gate must FAIL
closed if any other principal (the legacy shared identity, the web reader identity, or anything
else) still holds one — whether assigned at the account or inherited from an ancestor scope — and
must PASS (no-op) when only the allowed writers do. All ids below are synthetic, secret-free
fixtures.
"""
from __future__ import annotations

import importlib.util
import json
import uuid as _uuid
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "cleanup_verify_state_writers.py"

_RA_NS = _uuid.UUID("00000000-0000-0000-0000-0000000000ff")


def _ra_guid(name: str) -> str:
    """Deterministic, valid role-assignment GUID from a readable test name.

    Real Azure role-assignment resource ids end in a GUID; the cleanup path now validates that, so
    fixtures must use canonical GUID-suffixed ids (not free-text names) for the happy path.
    """
    return str(_uuid.uuid5(_RA_NS, name))


def _load_cli():
    spec = importlib.util.spec_from_file_location("cleanup_verify_state_writers", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CLI = _load_cli()

SA_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg"
    "/providers/Microsoft.Storage/storageAccounts/wpst01234567890"
)
BLOB = "ba92f5b4-2d11-453d-a403-e96b0029c9fe"  # Storage Blob Data Contributor (WRITE)
TABLE = "0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3"  # Storage Table Data Contributor (WRITE)
OWNER = "b7e6dc6d-f1e8-4753-8033-0f276bb0955b"  # Storage Blob Data Owner (WRITE incl. delete)
BLOB_READER = "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"  # Storage Blob Data Reader (read-only)
TABLE_READER = "76199698-9eea-4c19-bc75-cec21354c6b6"  # Storage Table Data Reader (read-only)
QUEUE = "974c5e8b-45b9-4653-ba55-5f855dd0fb88"  # Storage Queue Data Contributor (NOT a state write)

RG_ID = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg"

API_PID = "11111111-1111-1111-1111-111111111111"
WORKER_PID = "22222222-2222-2222-2222-222222222222"
WEB_PID = "33333333-3333-3333-3333-333333333333"
LEGACY_PID = "99999999-9999-9999-9999-999999999999"
PROD_PID = "44444444-4444-4444-4444-444444444444"  # a bystander wp-id-production identity

RG_NAME = "rg"


def _assignment(
    principal: str,
    role_guid: str,
    scope: str = SA_ID,
    name: str = "ra",
    assignment_id: str | None = None,
) -> dict:
    ra_id = (
        assignment_id
        if assignment_id is not None
        else f"{scope}/providers/Microsoft.Authorization/roleAssignments/{_ra_guid(name)}"
    )
    return {
        "id": ra_id,
        "scope": scope,
        "principalId": principal,
        "roleDefinitionId": (
            f"/subscriptions/s/providers/Microsoft.Authorization/roleDefinitions/{role_guid}"
        ),
    }


def _identity(name: str, principal: str) -> dict:
    return {
        "name": name,
        "principalId": principal,
        "id": (
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg"
            f"/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{name}"
        ),
    }


# --- Synthetic CUSTOM role-definition fixtures (issue #98). Clearly-fake ids/names, no secrets. ---
# Canonical data-plane write/delete actions on the state store (what a custom role must NOT grant to
# a non-allowed principal without being caught).
BLOB_WRITE = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"
BLOB_DELETE = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"
BLOB_READ = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
TABLE_WRITE = "Microsoft.Storage/storageAccounts/tableServices/tables/entities/write"
TABLE_READ = "Microsoft.Storage/storageAccounts/tableServices/tables/entities/read"

# #98 HIGH-2: granular mutation verbs that also mutate state and must be classified as writers.
BLOB_ADD = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action"
BLOB_MOVE = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/move/action"
TABLE_ADD = "Microsoft.Storage/storageAccounts/tableServices/tables/entities/add/action"
TABLE_UPDATE = "Microsoft.Storage/storageAccounts/tableServices/tables/entities/update/action"

# Fake custom-role definition GUIDs (NOT any built-in) — deterministic + obviously synthetic.
CUSTOM_BLOB_WRITER = "aaaaaaaa-0000-4000-8000-000000000001"
CUSTOM_TABLE_WRITER = "aaaaaaaa-0000-4000-8000-000000000002"
CUSTOM_STORAGE_WILDCARD = "aaaaaaaa-0000-4000-8000-000000000003"
CUSTOM_BLOB_DELETER = "aaaaaaaa-0000-4000-8000-000000000004"
CUSTOM_READER = "aaaaaaaa-0000-4000-8000-000000000005"
CUSTOM_REVOKED_WILDCARD = "aaaaaaaa-0000-4000-8000-000000000006"
CUSTOM_MGMT_PLANE = "aaaaaaaa-0000-4000-8000-000000000007"
CUSTOM_TABLE_ADDUPD = "aaaaaaaa-0000-4000-8000-000000000008"
CUSTOM_BLOB_ADD = "aaaaaaaa-0000-4000-8000-000000000009"
CUSTOM_BLOB_MOVE = "aaaaaaaa-0000-4000-8000-00000000000a"
OPAQUE_ROLE = "aaaaaaaa-0000-4000-8000-00000000dead"  # never placed in the index -> unresolvable


def _role_def(
    guid: str,
    role_name: str,
    *,
    data_actions: list[str] | None = None,
    not_data_actions: list[str] | None = None,
    actions: list[str] | None = None,
) -> dict:
    """A synthetic custom role-definition dict shaped like `az role definition list` output."""
    return {
        "name": guid,
        "roleName": role_name,
        "roleType": "CustomRole",
        "id": f"/subscriptions/s/providers/Microsoft.Authorization/roleDefinitions/{guid}",
        "permissions": [
            {
                "actions": actions or [],
                "notActions": [],
                "dataActions": data_actions or [],
                "notDataActions": not_data_actions or [],
            }
        ],
    }


# Reusable synthetic custom role definitions.
RD_BLOB_WRITER = _role_def(CUSTOM_BLOB_WRITER, "wp-custom-blob-writer", data_actions=[BLOB_WRITE])
RD_TABLE_WRITER = _role_def(
    CUSTOM_TABLE_WRITER, "wp-custom-table-writer", data_actions=[TABLE_WRITE]
)
RD_STORAGE_WILDCARD = _role_def(
    CUSTOM_STORAGE_WILDCARD, "wp-custom-storage-star", data_actions=["Microsoft.Storage/*"]
)
RD_BLOB_DELETER = _role_def(
    CUSTOM_BLOB_DELETER, "wp-custom-blob-deleter", data_actions=[BLOB_DELETE]
)
RD_READER = _role_def(CUSTOM_READER, "wp-custom-reader", data_actions=[BLOB_READ, TABLE_READ])
RD_REVOKED_WILDCARD = _role_def(
    CUSTOM_REVOKED_WILDCARD,
    "wp-custom-revoked",
    data_actions=["Microsoft.Storage/*"],
    not_data_actions=["Microsoft.Storage/*"],
)
# A management-plane-only custom role: control-plane actions incl. a wildcard, but NO dataActions.
RD_MGMT_PLANE = _role_def(
    CUSTOM_MGMT_PLANE,
    "wp-custom-mgmt",
    actions=["Microsoft.Storage/storageAccounts/write", "Microsoft.Storage/storageAccounts/*"],
)

# #98 HIGH-2: custom roles granting ONLY granular mutation verbs (add/move/update/action) — each
# mutates state and must be caught.
RD_TABLE_ADDUPD = _role_def(
    CUSTOM_TABLE_ADDUPD, "wp-custom-table-addupd", data_actions=[TABLE_ADD, TABLE_UPDATE]
)
RD_BLOB_ADD = _role_def(CUSTOM_BLOB_ADD, "wp-custom-blob-add", data_actions=[BLOB_ADD])
RD_BLOB_MOVE = _role_def(CUSTOM_BLOB_MOVE, "wp-custom-blob-move", data_actions=[BLOB_MOVE])

ALL_CUSTOM_ROLE_DEFS = [
    RD_BLOB_WRITER,
    RD_TABLE_WRITER,
    RD_STORAGE_WILDCARD,
    RD_BLOB_DELETER,
    RD_READER,
    RD_REVOKED_WILDCARD,
    RD_MGMT_PLANE,
    RD_TABLE_ADDUPD,
    RD_BLOB_ADD,
    RD_BLOB_MOVE,
]


def _index(role_defs: list[dict]) -> dict:
    return CLI.build_role_definition_index(role_defs)


# --------------------------------------------------------------------------------------------------
# Pure logic: find_stray_state_writers
# --------------------------------------------------------------------------------------------------
def test_only_api_worker_writers_is_clean() -> None:
    assignments = [
        _assignment(API_PID, BLOB),
        _assignment(API_PID, TABLE),
        _assignment(WORKER_PID, BLOB),
        _assignment(WORKER_PID, TABLE),
        _assignment(WEB_PID, QUEUE),  # web has a NON-write role — not a stray
    ]
    strays = CLI.find_stray_state_writers(assignments, {API_PID, WORKER_PID}, SA_ID)
    assert strays == []


def test_legacy_shared_identity_writer_is_a_stray() -> None:
    assignments = [
        _assignment(API_PID, BLOB),
        _assignment(WORKER_PID, TABLE),
        _assignment(LEGACY_PID, BLOB, name="legacy-blob"),
        _assignment(LEGACY_PID, TABLE, name="legacy-table"),
    ]
    strays = CLI.find_stray_state_writers(assignments, {API_PID, WORKER_PID}, SA_ID)
    assert {s["principalId"] for s in strays} == {LEGACY_PID}
    assert len(strays) == 2


def test_web_reader_with_write_role_is_a_stray() -> None:
    # A regression where the reader identity gained a write role must be caught.
    strays = CLI.find_stray_state_writers(
        [_assignment(WEB_PID, BLOB)], {API_PID, WORKER_PID}, SA_ID
    )
    assert len(strays) == 1
    assert strays[0]["principalId"] == WEB_PID


def test_blob_data_owner_writer_is_a_stray() -> None:
    # Storage Blob Data Owner is WRITE-capable (read/write/DELETE) — a non-api/worker principal
    # holding it at the SA must be caught by cleanup and verify, not mistaken for a reader.
    strays = CLI.find_stray_state_writers(
        [_assignment(LEGACY_PID, OWNER, name="legacy-owner")], {API_PID, WORKER_PID}, SA_ID
    )
    assert len(strays) == 1
    assert strays[0]["principalId"] == LEGACY_PID
    assert OWNER in CLI.STATE_WRITE_ROLE_IDS


def test_reader_roles_are_not_writers() -> None:
    # Storage Blob/Table Data READER are read-only and must NOT be treated as state writers.
    assignments = [
        _assignment(WEB_PID, BLOB_READER),
        _assignment(WEB_PID, TABLE_READER),
    ]
    assert CLI.find_stray_state_writers(assignments, {API_PID, WORKER_PID}, SA_ID) == []
    assert CLI.find_effective_state_writers(assignments, {API_PID, WORKER_PID}) == []
    assert BLOB_READER not in CLI.STATE_WRITE_ROLE_IDS
    assert TABLE_READER not in CLI.STATE_WRITE_ROLE_IDS


def test_api_worker_owner_and_contributor_only_is_clean() -> None:
    # api + worker hold Contributor AND Owner only -> boundary holds.
    assignments = [
        _assignment(API_PID, OWNER),
        _assignment(API_PID, BLOB),
        _assignment(API_PID, TABLE),
        _assignment(WORKER_PID, OWNER),
        _assignment(WORKER_PID, BLOB),
        _assignment(WORKER_PID, TABLE),
    ]
    assert CLI.find_effective_state_writers(assignments, {API_PID, WORKER_PID}) == []


def test_find_effective_detects_inherited_writer() -> None:
    # A write role granted at the RESOURCE GROUP (inherited) is EFFECTIVE at the SA -> verify sees
    # it, but cleanup (SA-scope only) does not.
    inherited = _assignment(LEGACY_PID, BLOB, scope=RG_ID, name="rg-blob")
    assert CLI.find_effective_state_writers([inherited], {API_PID, WORKER_PID}) == [inherited]
    assert CLI.find_stray_state_writers([inherited], {API_PID, WORKER_PID}, SA_ID) == []


def test_case_insensitive_principal_and_role() -> None:
    strays = CLI.find_stray_state_writers(
        [_assignment(API_PID.upper(), BLOB.upper())], {API_PID}, SA_ID.upper()
    )
    assert strays == []


# --------------------------------------------------------------------------------------------------
# Pure logic: is_legacy_shared_identity_name
# --------------------------------------------------------------------------------------------------
def test_legacy_identity_name_matches_only_the_shared_identity() -> None:
    assert CLI.is_legacy_shared_identity_name("wp-id-abcd1234efgh5")
    for component in ("api", "worker", "web", "grafana"):
        assert not CLI.is_legacy_shared_identity_name(f"wp-id-{component}-abcd1234efgh5")
    assert not CLI.is_legacy_shared_identity_name("wp-log-abcd1234")
    assert not CLI.is_legacy_shared_identity_name("some-other-identity")


def test_per_component_identity_name_matcher() -> None:
    for component in ("api", "worker", "web", "grafana"):
        assert CLI.is_per_component_identity_name(f"wp-id-{component}-abcd1234")
    assert not CLI.is_per_component_identity_name("wp-id-abcd1234")  # legacy shared, not component
    assert not CLI.is_per_component_identity_name("wp-id-production")
    assert not CLI.is_per_component_identity_name("wp-id-monitoring")


# --------------------------------------------------------------------------------------------------
# Pure logic: correlate_deletable_legacy_identities — deletion requires EVIDENCE, not just the name.
# --------------------------------------------------------------------------------------------------
def test_correlate_deletes_only_evidenced_legacy_identity() -> None:
    # The genuine legacy shared identity WAS a stray writer (its principalId is in the removed set)
    # and matches the legacy name -> eligible for deletion.
    identities = [
        _identity("wp-id-abcd1234", LEGACY_PID),
        _identity("wp-id-production", PROD_PID),  # bystander, similar name
        _identity("wp-id-monitoring", "55555555-5555-5555-5555-555555555555"),
    ]
    to_delete, unresolved = CLI.correlate_deletable_legacy_identities(identities, {LEGACY_PID})
    assert [i["name"] for i in to_delete] == ["wp-id-abcd1234"]
    assert unresolved == []


def test_correlate_never_deletes_bystander_that_is_not_a_stray() -> None:
    # wp-id-production follows a similar naming convention but never held a state-write role at the
    # SA (its principalId is NOT in the removed stray set) -> must NOT be deleted, and is NOT a
    # stray we need to flag either (empty removed set).
    identities = [_identity("wp-id-production", PROD_PID)]
    to_delete, unresolved = CLI.correlate_deletable_legacy_identities(identities, set())
    assert to_delete == []
    assert unresolved == []


def test_correlate_unresolvable_stray_is_flagged_not_deleted() -> None:
    # A stray writer principal with no matching identity in the RG -> ambiguous -> fail closed:
    # nothing to delete, and the principal is surfaced as unresolved.
    identities = [_identity("wp-id-production", PROD_PID)]
    to_delete, unresolved = CLI.correlate_deletable_legacy_identities(identities, {LEGACY_PID})
    assert to_delete == []
    assert unresolved == [LEGACY_PID]


def test_correlate_per_component_stray_is_neither_deleted_nor_flagged() -> None:
    # If a per-component identity (e.g. web) wrongly held a write role it appears as a stray, but
    # its identity resource is legitimate: never delete it, and do not flag it as unresolved.
    identities = [_identity("wp-id-web-abcd1234", WEB_PID)]
    to_delete, unresolved = CLI.correlate_deletable_legacy_identities(identities, {WEB_PID})
    assert to_delete == []
    assert unresolved == []


def test_correlate_ambiguous_duplicate_principal_is_flagged() -> None:
    # Two identities sharing the stray principalId (defensive) -> ambiguous -> flag, delete nothing.
    identities = [
        _identity("wp-id-abcd1234", LEGACY_PID),
        _identity("wp-id-efgh5678", LEGACY_PID),
    ]
    to_delete, unresolved = CLI.correlate_deletable_legacy_identities(identities, {LEGACY_PID})
    assert to_delete == []
    assert unresolved == [LEGACY_PID]


# --------------------------------------------------------------------------------------------------
# _cleanup integration (live path, monkeypatched az): identity deletion is evidence-gated.
# --------------------------------------------------------------------------------------------------
def _patch_cleanup_io(monkeypatch, *, assignments: list[dict], identities: list[dict],
                      role_definitions: list[dict] | None = None):
    """Wire the live cleanup I/O to fixtures and record delete calls; returns the delete records."""
    role_deletes: list[str] = []
    identity_deletes: list[str] = []
    monkeypatch.setattr(CLI, "list_role_assignments", lambda *a, **k: list(assignments))
    monkeypatch.setattr(CLI, "list_user_assigned_identities", lambda *a, **k: list(identities))
    monkeypatch.setattr(
        CLI, "list_role_definitions", lambda *a, **k: list(role_definitions or [])
    )
    monkeypatch.setattr(CLI, "delete_role_assignment", lambda aid: role_deletes.append(aid))
    monkeypatch.setattr(CLI, "delete_identity", lambda iid: identity_deletes.append(iid))
    return role_deletes, identity_deletes


def test_cleanup_deletes_genuine_legacy_identity(monkeypatch) -> None:
    _roles, idents = _patch_cleanup_io(
        monkeypatch,
        assignments=[_assignment(LEGACY_PID, BLOB, name="legacy-blob")],
        identities=[_identity("wp-id-abcd1234", LEGACY_PID)],
    )
    rc = CLI._cleanup(SA_ID, {API_PID, WORKER_PID}, RG_NAME, None, dry_run=False)
    assert rc == 0
    assert idents == [_identity("wp-id-abcd1234", LEGACY_PID)["id"]]


def test_cleanup_never_deletes_bystander_identity(monkeypatch) -> None:
    # No stray writers at the SA -> a similarly-named bystander is NOT deleted (regression: the old
    # name-only matcher would have deleted wp-id-production).
    _roles, idents = _patch_cleanup_io(
        monkeypatch,
        assignments=[_assignment(API_PID, BLOB), _assignment(WORKER_PID, TABLE)],
        identities=[
            _identity("wp-id-production", PROD_PID),
            _identity("wp-id-monitoring", "5" * 8),
        ],
    )
    rc = CLI._cleanup(SA_ID, {API_PID, WORKER_PID}, RG_NAME, None, dry_run=False)
    assert rc == 0
    assert idents == []


def test_cleanup_unresolvable_stray_fails_closed_without_deleting_identity(monkeypatch) -> None:
    # Stray writer whose principal maps to no identity in the RG -> fail closed (rc != 0), and NO
    # identity delete is attempted.
    _roles, idents = _patch_cleanup_io(
        monkeypatch,
        assignments=[_assignment(LEGACY_PID, OWNER, name="legacy-owner")],
        identities=[_identity("wp-id-production", PROD_PID)],
    )
    rc = CLI._cleanup(SA_ID, {API_PID, WORKER_PID}, RG_NAME, None, dry_run=False)
    assert rc != 0
    assert idents == []


def test_cleanup_never_deletes_per_component_stray_identity(monkeypatch) -> None:
    # web wrongly held a write role -> its role assignment is removed but wp-id-web-* is NOT deleted
    # and does not fail the run.
    roles, idents = _patch_cleanup_io(
        monkeypatch,
        assignments=[_assignment(WEB_PID, BLOB, name="web-blob")],
        identities=[_identity("wp-id-web-abcd1234", WEB_PID)],
    )
    rc = CLI._cleanup(SA_ID, {API_PID, WORKER_PID}, RG_NAME, None, dry_run=False)
    assert rc == 0
    assert idents == []
    assert len(roles) == 1  # the stray role assignment WAS removed


def test_cleanup_greenfield_deletes_nothing(monkeypatch) -> None:
    roles, idents = _patch_cleanup_io(
        monkeypatch,
        assignments=[_assignment(API_PID, BLOB), _assignment(WORKER_PID, TABLE)],
        identities=[],
    )
    rc = CLI._cleanup(SA_ID, {API_PID, WORKER_PID}, RG_NAME, None, dry_run=False)
    assert rc == 0
    assert roles == []
    assert idents == []


# --------------------------------------------------------------------------------------------------
# Fail-closed accounting: a stray whose identity we cannot soundly correlate must not "pass".
# --------------------------------------------------------------------------------------------------
def _stray_without_principal(role_guid: str = BLOB, name: str = "bad") -> dict:
    a = _assignment("", role_guid, name=name)
    del a["principalId"]  # simulate az output missing the principalId entirely
    return a


def test_cleanup_missing_principal_fails_closed(monkeypatch) -> None:
    # A stray with NO principalId: its role assignment is still removed, but it cannot be correlated
    # to an identity, so cleanup must FAIL CLOSED (non-zero) rather than falsely report success.
    roles, idents = _patch_cleanup_io(
        monkeypatch,
        assignments=[_stray_without_principal(name="orphan-blob")],
        identities=[_identity("wp-id-abcd1234", LEGACY_PID)],
    )
    rc = CLI._cleanup(SA_ID, {API_PID, WORKER_PID}, RG_NAME, None, dry_run=False)
    assert rc != 0
    assert idents == []  # never deletes an identity for an uncorrelatable stray
    assert len(roles) == 1  # the destructive role assignment was still removed


@pytest.mark.parametrize("bad_pid", ["not-a-guid", "", None])
def test_cleanup_malformed_principal_fails_closed(monkeypatch, bad_pid) -> None:
    a = _assignment("x", OWNER, name="malformed")
    if bad_pid is None:
        del a["principalId"]
    else:
        a["principalId"] = bad_pid
    _roles, idents = _patch_cleanup_io(
        monkeypatch, assignments=[a], identities=[_identity("wp-id-abcd1234", LEGACY_PID)]
    )
    rc = CLI._cleanup(SA_ID, {API_PID, WORKER_PID}, RG_NAME, None, dry_run=False)
    assert rc != 0
    assert idents == []


def test_cleanup_missing_assignment_id_fails_closed(monkeypatch) -> None:
    # A stray with a valid principalId but NO assignment id cannot be deleted OR soundly handled.
    a = _assignment(LEGACY_PID, BLOB, name="noid")
    del a["id"]
    roles, idents = _patch_cleanup_io(
        monkeypatch, assignments=[a], identities=[_identity("wp-id-abcd1234", LEGACY_PID)]
    )
    rc = CLI._cleanup(SA_ID, {API_PID, WORKER_PID}, RG_NAME, None, dry_run=False)
    assert rc != 0
    assert roles == []  # no assignment id => no role delete attempted
    assert idents == []


def test_cleanup_mixed_valid_and_malformed_deletes_valid_but_fails_closed(monkeypatch) -> None:
    # One valid-correlating legacy stray + one missing-principalId stray: the valid legacy identity
    # IS deleted, yet cleanup still returns non-zero because the malformed stray is unaccounted for.
    legacy = _identity("wp-id-abcd1234", LEGACY_PID)
    roles, idents = _patch_cleanup_io(
        monkeypatch,
        assignments=[
            _assignment(LEGACY_PID, BLOB, name="legacy-blob"),
            _stray_without_principal(name="orphan-owner"),
        ],
        identities=[legacy],
    )
    rc = CLI._cleanup(SA_ID, {API_PID, WORKER_PID}, RG_NAME, None, dry_run=False)
    assert rc != 0
    assert idents == [legacy["id"]]  # the correlated legacy identity was deleted
    assert len(roles) == 2  # both role assignments removed


def test_cleanup_valid_principal_still_deletes_legacy(monkeypatch) -> None:
    # Regression guard: a well-formed stray that correlates to the legacy identity => deleted, rc 0.
    legacy = _identity("wp-id-abcd1234", LEGACY_PID)
    _roles, idents = _patch_cleanup_io(
        monkeypatch,
        assignments=[_assignment(LEGACY_PID, BLOB, name="legacy-blob")],
        identities=[legacy],
    )
    rc = CLI._cleanup(SA_ID, {API_PID, WORKER_PID}, RG_NAME, None, dry_run=False)
    assert rc == 0
    assert idents == [legacy["id"]]


# --------------------------------------------------------------------------------------------------
# MED 1 (R6): ONE strict UUID normalizer everywhere — a whitespace/case variant of an ALLOWED
# writer must be classified NON-stray and never have its role deleted.
# --------------------------------------------------------------------------------------------------
def test_find_stray_normalizes_allowed_principal_whitespace_case() -> None:
    # api principal present with surrounding whitespace + upper-case must still match the allowlist.
    wrapped = _assignment(f"  {API_PID.upper()}  ", BLOB)
    strays = CLI.find_stray_state_writers([wrapped], {API_PID, WORKER_PID}, SA_ID)
    assert strays == []


def test_cleanup_allowed_writer_whitespace_case_not_deleted(monkeypatch) -> None:
    roles, idents = _patch_cleanup_io(
        monkeypatch,
        assignments=[
            _assignment(f"  {API_PID.upper()}  ", BLOB, name="api-ws"),
            _assignment(WORKER_PID, TABLE, name="worker-tbl"),
        ],
        identities=[_identity("wp-id-abcd1234", LEGACY_PID)],
    )
    rc = CLI._cleanup(SA_ID, {API_PID, WORKER_PID}, RG_NAME, None, dry_run=False)
    assert rc == 0
    assert roles == []  # the allowed writer's role assignment is NOT deleted
    assert idents == []


def test_validate_allowlist_normalizes_whitespace_case() -> None:
    allowed = CLI.validate_allowlist([f"  {API_PID.upper()}  ", WORKER_PID])
    assert allowed == {API_PID, WORKER_PID}


def test_validate_allowlist_dedups_case_whitespace_variants_of_one_id() -> None:
    # Two case/whitespace variants of the SAME uuid collapse to one distinct id — now VALID (#98:
    # the allow-list requires >= 1 distinct id, not two).
    allowed = CLI.validate_allowlist([f" {API_PID} ", API_PID.upper()])
    assert allowed == {API_PID}


# --------------------------------------------------------------------------------------------------
# MED 2 (R6): destructive ids must be SCOPE-BOUND — an out-of-scope/non-canonical assignment or an
# identity outside the expected RG must never be deleted (fail closed).
# --------------------------------------------------------------------------------------------------
_OTHER_SA = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg"
    "/providers/Microsoft.Storage/storageAccounts/evilaccount9999999"
)


def test_cleanup_out_of_scope_assignment_id_not_deleted(monkeypatch) -> None:
    # Stray recorded AT the SA scope, but whose assignment resource id points at a DIFFERENT SA.
    foreign_aid = (
        f"{_OTHER_SA}/providers/Microsoft.Authorization/roleAssignments/{_ra_guid('x')}"
    )
    crafted = _assignment(LEGACY_PID, BLOB, scope=SA_ID, assignment_id=foreign_aid)
    roles, idents = _patch_cleanup_io(
        monkeypatch,
        assignments=[crafted],
        identities=[_identity("wp-id-abcd1234", LEGACY_PID)],
    )
    rc = CLI._cleanup(SA_ID, {API_PID, WORKER_PID}, RG_NAME, None, dry_run=False)
    assert rc != 0
    assert roles == []  # never deletes an assignment id outside the target SA scope
    assert idents == []


def test_cleanup_noncanonical_assignment_id_not_deleted(monkeypatch) -> None:
    # An assignment id that is NOT a canonical roleAssignments/<guid> id under the SA is rejected.
    crafted = _assignment(LEGACY_PID, BLOB, scope=SA_ID, assignment_id="not-a-resource-id")
    roles, idents = _patch_cleanup_io(
        monkeypatch, assignments=[crafted], identities=[_identity("wp-id-abcd1234", LEGACY_PID)]
    )
    rc = CLI._cleanup(SA_ID, {API_PID, WORKER_PID}, RG_NAME, None, dry_run=False)
    assert rc != 0
    assert roles == []
    assert idents == []


def test_cleanup_identity_outside_rg_not_deleted(monkeypatch) -> None:
    # A correlatable legacy identity whose resource id lives in a DIFFERENT resource group must NOT
    # be deleted (its role assignment at the SA is still removed, but the run fails closed).
    foreign = {
        "name": "wp-id-abcd1234",
        "principalId": LEGACY_PID,
        "id": (
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/OTHER-RG"
            "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/wp-id-abcd1234"
        ),
    }
    roles, idents = _patch_cleanup_io(
        monkeypatch,
        assignments=[_assignment(LEGACY_PID, BLOB, name="legacy-blob")],
        identities=[foreign],
    )
    rc = CLI._cleanup(SA_ID, {API_PID, WORKER_PID}, RG_NAME, None, dry_run=False)
    assert rc != 0
    assert len(roles) == 1  # the SA-scoped role assignment IS removed
    assert idents == []  # but the out-of-RG identity resource is NOT deleted


def test_cleanup_canonical_ids_happy_path(monkeypatch) -> None:
    # Canonical SA-scoped assignment id + canonical in-RG legacy identity id => both removed, rc 0.
    legacy = _identity("wp-id-abcd1234", LEGACY_PID)
    roles, idents = _patch_cleanup_io(
        monkeypatch,
        assignments=[_assignment(LEGACY_PID, OWNER, name="legacy-owner")],
        identities=[legacy],
    )
    rc = CLI._cleanup(SA_ID, {API_PID, WORKER_PID}, RG_NAME, None, dry_run=False)
    assert rc == 0
    assert len(roles) == 1
    assert idents == [legacy["id"]]


# --------------------------------------------------------------------------------------------------
# issue #98 — CUSTOM RBAC roles with equivalent Blob/Table write dataActions must be detected.
# --------------------------------------------------------------------------------------------------
# Pure matcher: data_actions_grant_state_write / role_definition_grants_state_write.
def test_data_actions_blob_write_is_a_state_write() -> None:
    assert CLI.data_actions_grant_state_write([BLOB_WRITE], [])


def test_data_actions_table_write_is_a_state_write() -> None:
    assert CLI.data_actions_grant_state_write([TABLE_WRITE], [])


def test_data_actions_blob_delete_is_a_state_write() -> None:
    assert CLI.data_actions_grant_state_write([BLOB_DELETE], [])


# #98 HIGH-2: granular mutation verbs (add/move/update/action) each mutate state -> writers.
@pytest.mark.parametrize("action", [BLOB_ADD, BLOB_MOVE, TABLE_ADD, TABLE_UPDATE])
def test_granular_mutation_actions_are_state_writes(action: str) -> None:
    assert CLI.data_actions_grant_state_write([action], [])


def test_table_add_and_update_only_role_is_a_state_write() -> None:
    assert CLI.role_definition_grants_state_write(RD_TABLE_ADDUPD)


def test_blob_add_only_role_is_a_state_write() -> None:
    assert CLI.role_definition_grants_state_write(RD_BLOB_ADD)


def test_blob_move_only_role_is_a_state_write() -> None:
    assert CLI.role_definition_grants_state_write(RD_BLOB_MOVE)


def test_read_only_granular_actions_are_not_a_state_write() -> None:
    # Guard against over-broad matching: read data actions must NOT be classified as writers.
    assert not CLI.data_actions_grant_state_write([BLOB_READ, TABLE_READ], [])


@pytest.mark.parametrize(
    "wildcard",
    [
        "*",
        "Microsoft.Storage/*",
        "Microsoft.Storage/storageAccounts/*",
        "Microsoft.Storage/storageAccounts/blobServices/*",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*",
        "Microsoft.Storage/storageAccounts/tableServices/*",
        "Microsoft.Storage/storageAccounts/tableServices/tables/entities/*",
    ],
)
def test_data_actions_wildcards_expand_to_state_write(wildcard: str) -> None:
    assert CLI.data_actions_grant_state_write([wildcard], [])


def test_read_only_data_actions_are_not_a_state_write() -> None:
    assert not CLI.data_actions_grant_state_write([BLOB_READ, TABLE_READ], [])


def test_wildcard_revoked_by_not_data_actions_is_not_a_state_write() -> None:
    # A broad grant fully revoked by an equally-broad notDataActions grants nothing.
    assert not CLI.data_actions_grant_state_write(["Microsoft.Storage/*"], ["Microsoft.Storage/*"])


def test_partial_revocation_still_leaves_a_writer() -> None:
    # Grant blobs/* but revoke only blobs/write -> blobs/delete survives -> still a writer.
    granted = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*"
    assert CLI.data_actions_grant_state_write([granted], [BLOB_WRITE])


def test_role_definition_grants_state_write_variants() -> None:
    assert CLI.role_definition_grants_state_write(RD_BLOB_WRITER)
    assert CLI.role_definition_grants_state_write(RD_TABLE_WRITER)
    assert CLI.role_definition_grants_state_write(RD_STORAGE_WILDCARD)
    assert CLI.role_definition_grants_state_write(RD_BLOB_DELETER)
    assert not CLI.role_definition_grants_state_write(RD_READER)
    assert not CLI.role_definition_grants_state_write(RD_REVOKED_WILDCARD)
    # Management-plane-only custom role (control-plane actions, NO dataActions) is OUT OF SCOPE.
    assert not CLI.role_definition_grants_state_write(RD_MGMT_PLANE)


def test_build_role_definition_index_keys_by_guid() -> None:
    idx = _index(ALL_CUSTOM_ROLE_DEFS)
    assert set(idx) == {
        CUSTOM_BLOB_WRITER, CUSTOM_TABLE_WRITER, CUSTOM_STORAGE_WILDCARD,
        CUSTOM_BLOB_DELETER, CUSTOM_READER, CUSTOM_REVOKED_WILDCARD, CUSTOM_MGMT_PLANE,
        CUSTOM_TABLE_ADDUPD, CUSTOM_BLOB_ADD, CUSTOM_BLOB_MOVE,
    }


# find_stray_state_writers with a role-definition index resolves custom roles.
@pytest.mark.parametrize(
    "guid", [CUSTOM_BLOB_WRITER, CUSTOM_TABLE_WRITER, CUSTOM_STORAGE_WILDCARD, CUSTOM_BLOB_DELETER]
)
def test_custom_writer_role_is_a_stray(guid: str) -> None:
    strays = CLI.find_stray_state_writers(
        [_assignment(LEGACY_PID, guid, name="custom")],
        {API_PID, WORKER_PID},
        SA_ID,
        role_definitions=_index(ALL_CUSTOM_ROLE_DEFS),
    )
    assert len(strays) == 1
    assert strays[0]["principalId"] == LEGACY_PID


def test_custom_reader_role_is_not_a_stray() -> None:
    strays = CLI.find_stray_state_writers(
        [_assignment(WEB_PID, CUSTOM_READER, name="custom-read")],
        {API_PID, WORKER_PID},
        SA_ID,
        role_definitions=_index(ALL_CUSTOM_ROLE_DEFS),
    )
    assert strays == []


# #98 HIGH-2: custom roles granting ONLY granular mutation verbs must be flagged as strays.
@pytest.mark.parametrize("guid", [CUSTOM_TABLE_ADDUPD, CUSTOM_BLOB_ADD, CUSTOM_BLOB_MOVE])
def test_custom_granular_mutation_role_is_a_stray(guid: str) -> None:
    strays = CLI.find_stray_state_writers(
        [_assignment(LEGACY_PID, guid, name="custom-granular")],
        {API_PID, WORKER_PID},
        SA_ID,
        role_definitions=_index(ALL_CUSTOM_ROLE_DEFS),
    )
    assert len(strays) == 1
    assert strays[0]["principalId"] == LEGACY_PID


def test_custom_granular_mutation_role_cleanup_removes_stray(monkeypatch) -> None:
    # Cleanup-path proof: a role granting only blobs/add/action is a PROVEN writer -> its stray
    # assignment is removed and the correlated legacy identity deleted.
    legacy = _identity("wp-id-abcd1234", LEGACY_PID)
    roles, idents = _patch_cleanup_io(
        monkeypatch,
        assignments=[_assignment(LEGACY_PID, CUSTOM_BLOB_ADD, name="custom-add")],
        identities=[legacy],
        role_definitions=ALL_CUSTOM_ROLE_DEFS,
    )
    rc = CLI._cleanup(SA_ID, {API_PID, WORKER_PID}, RG_NAME, None, dry_run=False)
    assert rc == 0
    assert len(roles) == 1
    assert idents == [legacy["id"]]
    strays = CLI.find_stray_state_writers(
        [_assignment(WEB_PID, CUSTOM_REVOKED_WILDCARD, name="custom-revoked")],
        {API_PID, WORKER_PID},
        SA_ID,
        role_definitions=_index(ALL_CUSTOM_ROLE_DEFS),
    )
    assert strays == []


def test_custom_management_plane_role_is_not_a_stray() -> None:
    # A custom role granting only control-plane actions (no dataActions) is out of scope while
    # shared-key access is disabled -> not flagged.
    strays = CLI.find_stray_state_writers(
        [_assignment(WEB_PID, CUSTOM_MGMT_PLANE, name="custom-mgmt")],
        {API_PID, WORKER_PID},
        SA_ID,
        role_definitions=_index(ALL_CUSTOM_ROLE_DEFS),
    )
    assert strays == []


def test_allowed_principal_with_custom_writer_role_is_not_a_stray() -> None:
    # api holding an equivalent custom writer role is allowed -> not flagged.
    strays = CLI.find_stray_state_writers(
        [_assignment(API_PID, CUSTOM_BLOB_WRITER, name="api-custom")],
        {API_PID, WORKER_PID},
        SA_ID,
        role_definitions=_index(ALL_CUSTOM_ROLE_DEFS),
    )
    assert strays == []


def test_builtins_still_detected_with_role_index_present() -> None:
    # The three built-in write GUIDs are detected via the fast path even alongside custom detection.
    idx = _index(ALL_CUSTOM_ROLE_DEFS)
    for builtin in (OWNER, BLOB, TABLE):
        strays = CLI.find_stray_state_writers(
            [_assignment(LEGACY_PID, builtin, name="builtin")],
            {API_PID, WORKER_PID},
            SA_ID,
            role_definitions=idx,
        )
        assert len(strays) == 1


def test_unresolvable_role_definition_is_flagged_fail_closed() -> None:
    # An opaque role GUID absent from the index, held by a non-allowed principal, must be surfaced
    # as a POSSIBLE writer (fail closed), never silently ignored.
    strays = CLI.find_effective_state_writers(
        [_assignment(LEGACY_PID, OPAQUE_ROLE, name="opaque")],
        {API_PID, WORKER_PID},
        role_definitions=_index(ALL_CUSTOM_ROLE_DEFS),  # does NOT contain OPAQUE_ROLE
    )
    assert len(strays) == 1
    assert strays[0]["principalId"] == LEGACY_PID


def test_unresolvable_role_held_by_allowed_principal_is_not_flagged() -> None:
    # api may hold any writer role; an unresolvable role on api is not a boundary violation.
    strays = CLI.find_effective_state_writers(
        [_assignment(API_PID, OPAQUE_ROLE, name="opaque-api")],
        {API_PID, WORKER_PID},
        role_definitions=_index(ALL_CUSTOM_ROLE_DEFS),
    )
    assert strays == []


def test_no_role_index_means_builtin_only_legacy_behaviour() -> None:
    # With role_definitions=None (legacy/offline), a custom writer role is NOT resolved -> not a
    # stray. This preserves prior behaviour for callers that do not fetch role definitions.
    strays = CLI.find_stray_state_writers(
        [_assignment(LEGACY_PID, CUSTOM_BLOB_WRITER, name="custom")],
        {API_PID, WORKER_PID},
        SA_ID,
    )
    assert strays == []


# _cleanup integration (live path, monkeypatched az): a custom-role stray is selected for removal.
def test_cleanup_removes_custom_role_stray_and_deletes_legacy(monkeypatch) -> None:
    legacy = _identity("wp-id-abcd1234", LEGACY_PID)
    roles, idents = _patch_cleanup_io(
        monkeypatch,
        assignments=[_assignment(LEGACY_PID, CUSTOM_BLOB_WRITER, name="custom-blob")],
        identities=[legacy],
        role_definitions=ALL_CUSTOM_ROLE_DEFS,
    )
    rc = CLI._cleanup(SA_ID, {API_PID, WORKER_PID}, RG_NAME, None, dry_run=False)
    assert rc == 0
    assert len(roles) == 1  # the custom-role stray assignment IS removed
    assert idents == [legacy["id"]]  # and the correlated legacy identity deleted


def test_cleanup_custom_reader_role_is_not_removed(monkeypatch) -> None:
    roles, idents = _patch_cleanup_io(
        monkeypatch,
        assignments=[
            _assignment(API_PID, BLOB),
            _assignment(WEB_PID, CUSTOM_READER, name="custom-read"),
        ],
        identities=[_identity("wp-id-production", PROD_PID)],
        role_definitions=ALL_CUSTOM_ROLE_DEFS,
    )
    rc = CLI._cleanup(SA_ID, {API_PID, WORKER_PID}, RG_NAME, None, dry_run=False)
    assert rc == 0
    assert roles == []  # read-only custom role is not a writer -> nothing removed
    assert idents == []


def test_cleanup_unresolvable_custom_role_fails_closed(monkeypatch, capsys) -> None:
    # #98 MEDIUM: an opaque role (GUID absent from a non-None index) held by a non-allowed principal
    # is a POSSIBLE (not proven) writer. Destroying on uncertainty is wrong: the assignment must NOT
    # be deleted, the principal must NOT be correlated for identity deletion, the run must fail
    # closed (rc != 0), and a warning must be surfaced for manual remediation.
    roles, idents = _patch_cleanup_io(
        monkeypatch,
        assignments=[_assignment(LEGACY_PID, OPAQUE_ROLE, name="opaque")],
        identities=[_identity("wp-id-abcd1234", LEGACY_PID)],  # legacy-named, would be deletable
        role_definitions=ALL_CUSTOM_ROLE_DEFS,  # OPAQUE_ROLE absent -> unresolvable
    )
    rc = CLI._cleanup(SA_ID, {API_PID, WORKER_PID}, RG_NAME, None, dry_run=False)
    assert rc != 0
    assert roles == []  # unresolved -> assignment NOT deleted (never destroy on uncertainty)
    assert idents == []  # and its identity NOT deleted
    assert "unresolved" in capsys.readouterr().err.lower()


def test_cleanup_proven_builtin_writer_still_deleted(monkeypatch) -> None:
    # #98 MEDIUM: brownfield path intact — a PROVEN built-in writer (Storage Blob Data Contributor)
    # is still deleted and its correlated legacy identity still deleted.
    legacy = _identity("wp-id-abcd1234", LEGACY_PID)
    roles, idents = _patch_cleanup_io(
        monkeypatch,
        assignments=[_assignment(LEGACY_PID, BLOB, name="legacy-blob")],
        identities=[legacy],
        role_definitions=ALL_CUSTOM_ROLE_DEFS,
    )
    rc = CLI._cleanup(SA_ID, {API_PID, WORKER_PID}, RG_NAME, None, dry_run=False)
    assert rc == 0
    assert len(roles) == 1  # proven built-in writer assignment removed
    assert idents == [legacy["id"]]  # and legacy identity deleted


def test_cleanup_fails_closed_when_role_definition_fetch_errors(monkeypatch) -> None:
    # If `az role definition list` fails, the run must fail closed, not silently skip custom-role
    # detection.
    monkeypatch.setattr(
        CLI, "list_role_assignments",
        lambda *a, **k: [_assignment(LEGACY_PID, CUSTOM_BLOB_WRITER, name="custom")],
    )

    def boom(*_a, **_k):
        raise CLI.AzureOutputError("`az role` failed (exit 1)")

    monkeypatch.setattr(CLI, "list_role_definitions", boom)
    with pytest.raises(CLI.AzureOutputError):
        CLI._cleanup(SA_ID, {API_PID, WORKER_PID}, RG_NAME, None, dry_run=False)


# Offline CLI with --role-definitions-file exercises the pure matcher end-to-end (no Azure).
def _write_defs(tmp_path: Path, role_defs: list[dict]) -> str:
    p = tmp_path / "roledefs.json"
    p.write_text(json.dumps(role_defs), encoding="utf-8")
    return str(p)


def test_cli_offline_fails_on_custom_role_stray(tmp_path: Path) -> None:
    a = _write(tmp_path, [_assignment(API_PID, BLOB), _assignment(LEGACY_PID, CUSTOM_BLOB_WRITER)])
    d = _write_defs(tmp_path, ALL_CUSTOM_ROLE_DEFS)
    rc = CLI.main(
        [
            "prog", "--scope", SA_ID,
            "--allow", API_PID, "--allow", WORKER_PID,
            "--assignments-file", a, "--role-definitions-file", d,
        ]
    )
    assert rc == 1


def test_cli_offline_passes_with_custom_reader_role(tmp_path: Path) -> None:
    a = _write(
        tmp_path,
        [_assignment(API_PID, BLOB), _assignment(WORKER_PID, TABLE),
         _assignment(WEB_PID, CUSTOM_READER)],
    )
    d = _write_defs(tmp_path, ALL_CUSTOM_ROLE_DEFS)
    rc = CLI.main(
        [
            "prog", "--scope", SA_ID,
            "--allow", API_PID, "--allow", WORKER_PID,
            "--assignments-file", a, "--role-definitions-file", d,
        ]
    )
    assert rc == 0


def test_cli_offline_fails_on_unresolvable_role(tmp_path: Path) -> None:
    a = _write(tmp_path, [_assignment(API_PID, BLOB), _assignment(LEGACY_PID, OPAQUE_ROLE)])
    d = _write_defs(tmp_path, ALL_CUSTOM_ROLE_DEFS)  # OPAQUE_ROLE not present -> unresolvable
    rc = CLI.main(
        [
            "prog", "--scope", SA_ID,
            "--allow", API_PID, "--allow", WORKER_PID,
            "--assignments-file", a, "--role-definitions-file", d,
        ]
    )
    assert rc == 1


# --------------------------------------------------------------------------------------------------
# Offline CLI: verify gate fails on a stray, passes when clean (no Azure required)
# --------------------------------------------------------------------------------------------------
def _write(tmp_path: Path, assignments: list[dict]) -> str:
    p = tmp_path / "assignments.json"
    p.write_text(json.dumps(assignments), encoding="utf-8")
    return str(p)


def test_cli_offline_passes_when_only_writers(tmp_path: Path) -> None:
    f = _write(tmp_path, [_assignment(API_PID, BLOB), _assignment(WORKER_PID, TABLE)])
    rc = CLI.main(
        [
            "prog", "--scope", SA_ID,
            "--allow", API_PID, "--allow", WORKER_PID,
            "--assignments-file", f,
        ]
    )
    assert rc == 0


def test_cli_offline_fails_on_stray_writer(tmp_path: Path) -> None:
    f = _write(tmp_path, [_assignment(API_PID, BLOB), _assignment(LEGACY_PID, TABLE)])
    rc = CLI.main(
        [
            "prog", "--scope", SA_ID,
            "--allow", API_PID, "--allow", WORKER_PID,
            "--assignments-file", f,
        ]
    )
    assert rc == 1


def test_cli_offline_fails_on_stray_blob_data_owner(tmp_path: Path) -> None:
    # Storage Blob Data Owner held by a non-api/worker principal must fail the gate.
    f = _write(tmp_path, [_assignment(API_PID, BLOB), _assignment(LEGACY_PID, OWNER)])
    rc = CLI.main(
        [
            "prog", "--scope", SA_ID,
            "--allow", API_PID, "--allow", WORKER_PID,
            "--assignments-file", f, "--cleanup",
        ]
    )
    assert rc == 1


def test_cli_offline_passes_with_owner_and_contributor(tmp_path: Path) -> None:
    f = _write(
        tmp_path,
        [
            _assignment(API_PID, OWNER),
            _assignment(API_PID, BLOB),
            _assignment(WORKER_PID, TABLE),
        ],
    )
    rc = CLI.main(
        [
            "prog", "--scope", SA_ID,
            "--allow", API_PID, "--allow", WORKER_PID,
            "--assignments-file", f,
        ]
    )
    assert rc == 0


def test_cli_offline_inherited_stray_fails_with_manual_remediation(
    tmp_path: Path, capsys
) -> None:
    # An inherited (RG-scope) stray writer must FAIL verify with a manual-remediation message naming
    # the principal, role and ancestor scope; cleanup (SA-scope only) must NOT target it.
    inherited = _assignment(LEGACY_PID, OWNER, scope=RG_ID, name="rg-owner")
    f = _write(tmp_path, [_assignment(API_PID, BLOB), _assignment(WORKER_PID, TABLE), inherited])
    rc = CLI.main(
        [
            "prog", "--scope", SA_ID,
            "--allow", API_PID, "--allow", WORKER_PID,
            "--assignments-file", f, "--cleanup",
        ]
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "INHERITED" in err
    assert RG_ID in err
    assert LEGACY_PID in err
    # cleanup logic must not consider the ancestor-scoped assignment deletable.
    assert CLI.find_stray_state_writers([inherited], {API_PID, WORKER_PID}, SA_ID) == []


def test_cli_offline_cleanup_is_dry_run_and_still_reports_stray(tmp_path: Path) -> None:
    # In offline mode --cleanup must NOT mutate anything, so the gate still fails on the stray.
    f = _write(tmp_path, [_assignment(WEB_PID, BLOB)])
    rc = CLI.main(
        [
            "prog",
            "--scope",
            SA_ID,
            "--allow",
            API_PID,
            "--allow",
            WORKER_PID,
            "--assignments-file",
            f,
            "--cleanup",
        ]
    )
    assert rc == 1


def test_cli_requires_allow() -> None:
    rc = CLI.main(["prog", "--scope", SA_ID])
    assert rc == 2


# --------------------------------------------------------------------------------------------------
# Fail-closed preconditions: malformed allowlist / scope must ERROR before any cleanup runs.
# --------------------------------------------------------------------------------------------------
def test_validate_allowlist_returns_distinct_lowercased() -> None:
    assert CLI.validate_allowlist([API_PID, WORKER_PID]) == {API_PID, WORKER_PID}


def test_validate_allowlist_accepts_single_id() -> None:
    # #98: the boundary is API-only since #97, and CD passes exactly ONE --allow. A single valid
    # UUID must be accepted (previously wrongly rejected as "fewer than two distinct").
    assert CLI.validate_allowlist([API_PID]) == {API_PID}


def test_validate_allowlist_dedups_identical_ids_to_one_valid() -> None:
    # Two identical values collapse to one distinct id -> VALID (>= 1), not an error.
    assert CLI.validate_allowlist([API_PID, API_PID]) == {API_PID}


def test_validate_allowlist_rejects_empty_blank_and_nonuuid() -> None:
    for bad in ([], [API_PID, ""], [""], ["not-a-uuid", WORKER_PID], ["not-a-uuid"]):
        with pytest.raises(CLI.PreconditionError):
            CLI.validate_allowlist(bad)


def test_validate_scope_rejects_non_storage_scope() -> None:
    CLI.validate_scope(SA_ID)  # valid: does not raise
    for bad in ("", "not-a-scope", RG_ID, f"{RG_ID}/providers/Microsoft.Compute/foo/bar"):
        with pytest.raises(CLI.PreconditionError):
            CLI.validate_scope(bad)


def test_cli_blank_principal_errors_before_any_delete(tmp_path: Path, monkeypatch) -> None:
    # A missing/blank deployment output (empty allowlist entry) must abort BEFORE cleanup so a
    # legitimate api/worker assignment is never deleted against an empty allowlist.
    deletes: list[str] = []
    monkeypatch.setattr(CLI, "delete_role_assignment", lambda aid: deletes.append(aid))
    monkeypatch.setattr(CLI, "delete_identity", lambda iid: deletes.append(iid))
    f = _write(tmp_path, [_assignment(LEGACY_PID, BLOB)])
    rc = CLI.main(
        [
            "prog", "--scope", SA_ID,
            "--allow", API_PID, "--allow", "",
            "--assignments-file", f, "--cleanup",
        ]
    )
    assert rc == 2
    assert deletes == []


def test_cli_duplicate_principals_accepted_as_single(tmp_path: Path) -> None:
    # #98: two identical --allow values dedup to one distinct id -> VALID (not rc 2). With an empty
    # assignments file there are no strays, so verification passes -> rc 0.
    f = _write(tmp_path, [])
    rc = CLI.main(
        [
            "prog", "--scope", SA_ID,
            "--allow", API_PID, "--allow", API_PID,
            "--assignments-file", f,
        ]
    )
    assert rc == 0


def test_cli_single_api_principal_accepted(tmp_path: Path) -> None:
    # #98 HIGH-1: the exact API-only allow-list shape from CD must be accepted (was rejected as
    # "missing worker" before #97). Empty assignments -> no strays -> rc 0.
    f = _write(tmp_path, [])
    rc = CLI.main(
        ["prog", "--scope", SA_ID, "--allow", API_PID, "--assignments-file", f]
    )
    assert rc == 0


def test_cd_single_allow_reaches_cleanup_and_live_role_def_load(monkeypatch) -> None:
    # #98 HIGH-1: the EXACT CD invocation (one --allow, --cleanup, live scope) must NOT be rejected
    # by validation (rc 2), must run _cleanup, and must exercise the LIVE role-definition load path
    # (offline=False -> build_role_definition_index(list_role_definitions(scope))). This locks in
    # that the single-allow CD path actually activates custom-role detection.
    calls = {"cleanup": 0, "role_defs": 0}
    real_cleanup = CLI._cleanup

    def tracking_cleanup(*a, **k) -> int:
        calls["cleanup"] += 1
        return real_cleanup(*a, **k)

    def tracking_role_defs(scope: str) -> list[dict]:
        calls["role_defs"] += 1
        return list(ALL_CUSTOM_ROLE_DEFS)

    monkeypatch.setattr(CLI, "_cleanup", tracking_cleanup)
    monkeypatch.setattr(CLI, "list_role_definitions", tracking_role_defs)
    monkeypatch.setattr(CLI, "list_role_assignments", lambda *a, **k: [_assignment(API_PID, BLOB)])
    monkeypatch.setattr(CLI, "list_user_assigned_identities", lambda *a, **k: [])
    monkeypatch.setattr(CLI, "delete_role_assignment", lambda aid: None)
    monkeypatch.setattr(CLI, "delete_identity", lambda iid: None)

    rc = CLI.main(
        ["prog", "--scope", SA_ID, "--resource-group", "rg", "--allow", API_PID, "--cleanup"]
    )
    assert rc != 2  # NOT rejected by validate_allowlist -> the gate is reachable
    assert calls["cleanup"] == 1  # _cleanup actually ran
    assert calls["role_defs"] >= 1  # live role-definition load path exercised (custom detection on)


def test_cli_malformed_scope_errors(tmp_path: Path) -> None:
    f = _write(tmp_path, [])
    rc = CLI.main(
        [
            "prog", "--scope", RG_ID,
            "--allow", API_PID, "--allow", WORKER_PID,
            "--assignments-file", f,
        ]
    )
    assert rc == 2


# --------------------------------------------------------------------------------------------------
# Fail-closed on invalid Azure output: an empty/non-list/errored response must NEVER look "clean".
# --------------------------------------------------------------------------------------------------
def test_list_role_assignments_rejects_none(monkeypatch) -> None:
    monkeypatch.setattr(CLI, "_az_json", lambda args: None)
    with pytest.raises(CLI.AzureOutputError):
        CLI.list_role_assignments(SA_ID)


def test_list_role_assignments_rejects_non_list(monkeypatch) -> None:
    monkeypatch.setattr(CLI, "_az_json", lambda args: {"value": []})
    with pytest.raises(CLI.AzureOutputError):
        CLI.list_role_assignments(SA_ID, include_inherited=True)


def test_verify_fails_closed_on_az_error(monkeypatch) -> None:
    # A failed `az` call (auth/throttle/timeout) must fail the gate, not be read as "no strays".
    def boom(*_a, **_k):
        raise CLI.AzureOutputError("`az role` failed (exit 1)")

    monkeypatch.setattr(CLI, "list_role_assignments", boom)
    rc = CLI.main(["prog", "--scope", SA_ID, "--allow", API_PID, "--allow", WORKER_PID])
    assert rc == 1


def test_verify_fails_closed_on_non_list_live_output(monkeypatch) -> None:
    monkeypatch.setattr(CLI, "_az_json", lambda args: None)  # az returned empty/None
    rc = CLI.main(["prog", "--scope", SA_ID, "--allow", API_PID, "--allow", WORKER_PID])
    assert rc == 1


def test_verify_clean_on_genuine_empty_list_live(monkeypatch) -> None:
    # A SUCCESSFUL call returning a real empty array, with valid distinct principals, is clean.
    monkeypatch.setattr(CLI, "_az_json", lambda args: [])
    rc = CLI.main(["prog", "--scope", SA_ID, "--allow", API_PID, "--allow", WORKER_PID])
    assert rc == 0


def test_cli_offline_fails_closed_on_non_list_file(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text('{"not": "an array"}', encoding="utf-8")
    rc = CLI.main(
        [
            "prog", "--scope", SA_ID,
            "--allow", API_PID, "--allow", WORKER_PID,
            "--assignments-file", str(p),
        ]
    )
    assert rc == 1


def test_cli_offline_fails_closed_on_empty_file(tmp_path: Path) -> None:
    p = tmp_path / "empty.json"
    p.write_text("", encoding="utf-8")
    rc = CLI.main(
        [
            "prog", "--scope", SA_ID,
            "--allow", API_PID, "--allow", WORKER_PID,
            "--assignments-file", str(p),
        ]
    )
    assert rc == 1


def test_cli_offline_clean_on_genuine_empty_list(tmp_path: Path) -> None:
    f = _write(tmp_path, [])
    rc = CLI.main(
        [
            "prog", "--scope", SA_ID,
            "--allow", API_PID, "--allow", WORKER_PID,
            "--assignments-file", f,
        ]
    )
    assert rc == 0
