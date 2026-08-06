"""Tests asserting the API-only state-writer RBAC boundary (issue #97).

Guarantees under test:
  1. The worker identity is NOT granted either state-write role — Storage Blob Data Contributor
     (``ba92f5b4-2d11-453d-a403-e96b0029c9fe``) or Storage Table Data Contributor
     (``0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3``) — in ``infra/bicep/modules/core.bicep``. The former
     worker role-assignment resources (``stateBlobDataContributorWorker`` /
     ``stateTableDataContributorWorker``) must be absent (removed per #97).
  2. The API identity IS still granted both state-write roles (it is the sole state writer).
  3. No role assignment pairs ``identityWorker.properties.principalId`` with either write role.
  4. The CD writer-gate invocation in ``.github/workflows/release.yml`` allow-lists the API
     principal ONLY — the worker principal is not passed to ``cleanup_verify_state_writers.py``.

The parsing is deliberately lightweight (text/regex over the real infra tree), matching the pattern
of ``tests/unit/test_check_data_residency.py``. No secrets or PHI in fixtures.
"""
from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CORE_BICEP = _REPO_ROOT / "infra" / "bicep" / "modules" / "core.bicep"
_RELEASE_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "release.yml"

# Built-in role GUIDs for the two state-write roles removed from the worker (#97).
_BLOB_DATA_CONTRIBUTOR = "ba92f5b4-2d11-453d-a403-e96b0029c9fe"
_TABLE_DATA_CONTRIBUTOR = "0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3"

# The bicep references the roles by these variable names (bound to the GUIDs above).
_BLOB_ROLE_VAR = "storageBlobDataContributorRoleId"
_TABLE_ROLE_VAR = "storageTableDataContributorRoleId"


def _core_text() -> str:
    return _CORE_BICEP.read_text(encoding="utf-8")


def _role_assignment_blocks(text: str) -> list[str]:
    """Return the source of each ``roleAssignments`` resource block (brace-balanced)."""
    blocks: list[str] = []
    for match in re.finditer(
        r"resource\s+\w+\s+'Microsoft\.Authorization/roleAssignments@[^']+'\s*=\s*\{",
        text,
    ):
        start = match.end() - 1  # position of the opening brace
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    blocks.append(text[match.start() : i + 1])
                    break
    return blocks


def test_worker_state_write_role_resources_are_absent() -> None:
    text = _core_text()
    assert "stateBlobDataContributorWorker" not in text
    assert "stateTableDataContributorWorker" not in text


def test_api_state_write_role_resources_are_present() -> None:
    text = _core_text()
    assert "stateBlobDataContributorApi" in text
    assert "stateTableDataContributorApi" in text


def test_role_guid_variables_bind_expected_guids() -> None:
    # The role-id variables must resolve to the documented built-in role GUIDs (#97).
    text = _core_text()
    assert f"var {_BLOB_ROLE_VAR} = '{_BLOB_DATA_CONTRIBUTOR}'" in text
    assert f"var {_TABLE_ROLE_VAR} = '{_TABLE_DATA_CONTRIBUTOR}'" in text


def test_no_role_assignment_pairs_worker_with_state_write_role() -> None:
    for block in _role_assignment_blocks(_core_text()):
        grants_state_write = (
            _BLOB_ROLE_VAR in block
            or _TABLE_ROLE_VAR in block
            or _BLOB_DATA_CONTRIBUTOR in block
            or _TABLE_DATA_CONTRIBUTOR in block
        )
        targets_worker = "identityWorker.properties.principalId" in block
        assert not (
            grants_state_write and targets_worker
        ), f"worker identity must not hold a state-write role:\n{block}"


def test_api_identity_holds_both_state_write_roles() -> None:
    blocks = _role_assignment_blocks(_core_text())

    def _api_holds(role_var: str) -> bool:
        return any(
            role_var in b and "identityApi.properties.principalId" in b for b in blocks
        )

    assert _api_holds(_BLOB_ROLE_VAR)
    assert _api_holds(_TABLE_ROLE_VAR)


def test_cd_writer_gate_allow_lists_api_only() -> None:
    text = _RELEASE_WORKFLOW.read_text(encoding="utf-8")
    # The verification gate invokes the state-writer script.
    assert "cleanup_verify_state_writers.py" in text
    # The API principal is allow-listed; the worker principal is not plumbed into the gate.
    assert "API_PID" in text
    assert "WORKER_PID" not in text
    assert "workerIdentityPrincipalId" not in text
