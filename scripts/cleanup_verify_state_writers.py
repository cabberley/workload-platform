#!/usr/bin/env python
"""Enforce the API-only-writer boundary on brownfield deploys (issue #79).

Incremental ARM deployment (the default ``az deployment group create`` used by CD) does NOT delete
resources or role assignments that were removed from the template. An environment first deployed
with the single *shared* user-assigned identity (``wp-id-<token>``) therefore KEEPS that shared
state-writer — and its ``Storage Blob Data Contributor`` / ``Storage Table Data Contributor`` role
assignments at the storage-account scope — even after the per-component-identity update. So the
"the API (and the worker/job that runs modules) are the only state writers" RBAC boundary is NOT
enforced on those environments unless we clean the legacy grant up and then PROVE it is gone.

This script does BOTH, idempotently and least-privilege, using the CD OIDC login already present in
``.github/workflows/release.yml`` (no extra secrets, keyless):

1. **Cleanup (``--cleanup``, idempotent, no-op on greenfield):** at the storage-account SCOPE,
   delete every state-write role assignment (Blob Data Owner / Blob Data Contributor / Table Data
   Contributor) whose principal is NOT an allowed writer (``--allow`` = the api and worker identity
   principal ids). Then, if a ``--resource-group`` is given, delete the *legacy shared*
   user-assigned identity resource — but ONLY when there is positive EVIDENCE it was a state-writer:
   its ``principalId`` must be one of the stray state-writers just detected/removed at this storage
   account, AND its name must match the legacy convention ``wp-id-<token>`` (never the per-component
   ``wp-id-api-*`` / ``wp-id-worker-*`` / ``wp-id-web-*`` / ``wp-id-grafana-*``). A bystander
   identity an operator happens to have named ``wp-id-production`` / ``wp-id-monitoring`` — that
   never held a state-write role at the account — is therefore NEVER deleted on name alone. If a
   removed stray principal cannot be unambiguously correlated to a deletable legacy identity — or a
   stray assignment has a missing/malformed (non-UUID) ``principalId`` or missing assignment id so
   it cannot be correlated at all — the run fails CLOSED (non-zero; deletes no identity by name).
   Every stray removed at the SA is thus accounted for: deleted, legitimately skipped
   (per-component), or flagged unresolved. Principal ids are compared with ONE strict UUID
   normalizer (stripped + lower-cased) across the allowlist, stray classification and correlation,
   so a whitespace/case variant of an allowed writer is never mis-classified stray. Deletion is
   scope-bound: a role assignment is deleted only when its resource id is canonical UNDER this
   account, and the legacy identity only when its resource id is canonical in the EXPECTED resource
   group — a crafted/out-of-scope id fails closed rather than deleting anything foreign. On a fresh
   environment there is no legacy identity and no stray assignment, so nothing is deleted. Cleanup
   only ever deletes assignments defined AT the account scope — an inherited (RG/subscription)
   assignment cannot and must not be deleted from here.

2. **Verify (always, fail-closed):** re-list the assignments EFFECTIVE at the storage-account scope
   (``--include-inherited``, so grants inherited from the resource group or subscription are seen)
   and assert the ONLY principals holding a state-write role there are the allowed writers. If ANY
   other principal (the legacy shared identity, the web reader identity, or anything else) still
   holds one — whether assigned at the account or inherited from an ancestor — EXIT NON-ZERO with a
   clear error (naming the principal, role and, for inherited grants, the ancestor scope to
   remediate) so CD fails the release. This also catches regressions.

A principal counts as a state-writer if EITHER its role-definition id is one of the three enumerated
built-in write roles (:data:`STATE_WRITE_ROLE_IDS`) OR its resolved role DEFINITION grants
equivalent blob/table write/delete via effective ``dataActions`` — including a **custom RBAC role**
or a wildcard (``*``, ``Microsoft.Storage/*``, ``.../blobServices/*``, …) that expands to cover
them (issue #98). ``notDataActions`` that revoke those actions are honoured. Only DATA-plane actions
are inspected: MANAGEMENT/control-plane rights (``actions`` — e.g. ``storageAccounts/write`` or key
listing) are OUT OF SCOPE while ``allowSharedKeyAccess=false``, so key-exfil / management-plane
roles are intentionally not flagged. A role definition that cannot be RESOLVED (unknown/opaque) is
treated fail-closed as a POSSIBLE writer (surfaced / failing), never silently ignored.

Object ids are not credentials, and ``allowSharedKeyAccess`` is ``false`` on the account, so this is
keyless and in-boundary. The Azure I/O is isolated behind thin helpers; the decision logic
(:func:`find_stray_state_writers`, :func:`role_definition_grants_state_write`,
:func:`is_legacy_shared_identity_name`) is pure and unit-tested
(``tests/unit/test_state_writer_cleanup.py``).

Usage (as run by CD):

    python scripts/cleanup_verify_state_writers.py \
        --scope "$STORAGE_ACCOUNT_ID" \
        --resource-group "$RG" \
        --allow "$API_PRINCIPAL_ID" \
        --allow "$WORKER_PRINCIPAL_ID" \
        --cleanup

Offline dry-run (feed assignments from a file to demonstrate the gate without Azure):

    python scripts/cleanup_verify_state_writers.py \
        --scope "/subscriptions/s/resourceGroups/rg/.../storageAccounts/wpst" \
        --allow api --allow worker \
        --assignments-file sample.json
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

# Storage state-store WRITE data roles — the roles that can create/modify/DELETE state blobs or
# tables. Kept in sync with infra/bicep/modules/core.bicep. A principal holding ANY of these at (or
# inherited above) the storage account can write state, so all three must gate the boundary:
#   * Storage Blob Data Owner       — full blob read/write/DELETE *and* POSIX ACL management. It is
#                                     a WRITER (a superset of Contributor); do NOT mistake it for a
#                                     reader (its GUID has historically been mislabeled "Reader").
#   * Storage Blob Data Contributor — blob read/write/delete.
#   * Storage Table Data Contributor— table entity read/write/delete.
STATE_WRITE_ROLE_IDS: frozenset[str] = frozenset(
    {
        "b7e6dc6d-f1e8-4753-8033-0f276bb0955b",  # Storage Blob Data Owner (WRITE — incl. delete)
        "ba92f5b4-2d11-453d-a403-e96b0029c9fe",  # Storage Blob Data Contributor
        "0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3",  # Storage Table Data Contributor
    }
)

# Read-only storage data roles — deliberately NOT in the write set. Listed here so it is explicit
# that a reader identity legitimately holding one of these is NOT a boundary violation:
#   Storage Blob Data Reader   = 2a2b9908-6ea1-4ae2-8e65-a410df84e7d1
#   Storage Table Data Reader  = 76199698-9eea-4c19-bc75-cec21354c6b6
# Storage Queue Data Contributor (974c5e8b-45b9-4653-ba55-5f855dd0fb88) is a queue role, not a
# state-store role, so it is also intentionally excluded from the state-write set.

# Representative concrete data-plane WRITE/DELETE actions on the state store (issue #98). A CUSTOM
# RBAC role that grants equivalent write access via its ``dataActions`` — even without one of the
# three built-in GUIDs above — is just as much a state-writer, so the gate must also detect it. We
# do NOT enumerate every possible action: instead we test whether the role's effective data actions
# (dataActions minus notDataActions) would grant ANY of these canonical blob/table mutation targets,
# accounting for wildcards (``*``, ``Microsoft.Storage/*``, ``.../blobServices/*``, …) that expand
# to cover them. If any target is granted and not revoked, the role is a writer. The set includes
# the granular ``add/action`` / ``update/action`` / ``move/action`` mutation verbs (NOT just the
# coarse ``write``/``delete``) so a custom role granting only those still trips the gate.
#
# SCOPE NOTE (keyless assumption): only DATA-plane actions (``dataActions``) are inspected.
# MANAGEMENT-plane / control-plane actions (``actions`` — e.g. ``Microsoft.Storage/storageAccounts/
# write`` or ``.../listKeys/action``) are OUT OF SCOPE for this gate: with ``allowSharedKeyAccess=
# false`` on the account, control-plane rights cannot be turned into state writes via shared keys.
# Key-exfiltration / management-plane roles are therefore intentionally NOT flagged here.
_STATE_WRITE_DATA_ACTIONS: tuple[str, ...] = (
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/move/action",
    "Microsoft.Storage/storageAccounts/tableServices/tables/entities/write",
    "Microsoft.Storage/storageAccounts/tableServices/tables/entities/delete",
    "Microsoft.Storage/storageAccounts/tableServices/tables/entities/add/action",
    "Microsoft.Storage/storageAccounts/tableServices/tables/entities/update/action",
)

# Per-component identity name segments introduced by issue #79 — a name whose segment after
# "wp-id-" is one of these (i.e. contains a hyphen) is NOT the legacy shared identity.
_LEGACY_IDENTITY_RE = re.compile(r"^wp-id-[a-z0-9]+$")
_RESERVED_SUFFIXES = ("api", "worker", "web", "grafana")
# Sanctioned per-component identity names: wp-id-{api,worker,web,grafana}-<token>. Used to recognise
# (and never delete) a legitimate component identity that may appear as a stray writer.
_PER_COMPONENT_IDENTITY_RE = re.compile(r"^wp-id-(?:api|worker|web|grafana)-[a-z0-9]+$")

# Precondition validation. The verify gate is only trustworthy if the allowlist (api + worker
# principal ids) and the storage-account scope are well-formed; otherwise an empty stray-list could
# be a FALSE "clean" result and cleanup could delete legitimate assignments against an empty
# allowlist. So both are validated up front and the tool fails CLOSED on anything malformed.
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_SA_SCOPE_RE = re.compile(
    r"^/subscriptions/[^/]+/resourceGroups/[^/]+"
    r"/providers/Microsoft\.Storage/storageAccounts/[^/]+$",
    re.IGNORECASE,
)


class PreconditionError(Exception):
    """A required input (allowlist / scope) is missing or malformed — refuse to run, fail closed."""


class AzureOutputError(Exception):
    """`az` failed, timed out, or returned output that is not a JSON array — treat as fail closed.

    Crucially this is raised (never coerced to an empty list) so a failed/unexpected Azure response
    can NEVER be mistaken for a genuinely empty "clean" result by the verify gate.
    """


def _normalize_uuid(value: object) -> str | None:
    """Return the canonical (stripped, lower-cased) UUID string, or ``None`` if not a valid UUID.

    This is the SINGLE principal-id normalizer used everywhere a principalId is compared — the
    allowlist, the stray/allowed comparison, the removed-stray correlation set, and the identity
    correlation. Using one normalizer guarantees that a principalId differing only by surrounding
    whitespace or letter case can never be classified as "stray" by one code path and "allowed"
    (or "correlated") by another — the inconsistency that could delete a legitimate api/worker
    write-role assignment.
    """
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped.lower() if _UUID_RE.match(stripped) else None


def validate_allowlist(raw_allow: list[str]) -> set[str]:
    """Return the normalized set of allow-listed writer principal ids, or raise
    ``PreconditionError``.

    The allow-list is the set of service principal (object) ids permitted to hold a state-write role
    at the storage account — the ``api`` identity, and optionally others. Since #97 the boundary is
    **API-only**, so CD passes exactly ONE ``--allow "$API_PID"``; the gate therefore accepts **one
    or more** entries (earlier it wrongly demanded two, a stale pre-#97 api+worker assumption that
    made the whole gate unreachable — ``main`` returned 2 before cleanup/verify ever ran).

    Each entry must be present (non-blank) and a valid UUID; duplicates collapse via
    :func:`_normalize_uuid` (the same helper used by classification/correlation, so config-side
    whitespace/case cannot split classification from correlation). This still guards against
    empty/missing deployment outputs that would otherwise yield an empty allow-list — which would
    make cleanup treat every legitimate ``api`` assignment as a stray and delete it.
    """
    if not raw_allow:
        raise PreconditionError(
            "no allowed principals given — pass at least one service principal id permitted to "
            "hold a state-write role (the api identity) via --allow"
        )
    normalized: set[str] = set()
    for raw in raw_allow:
        norm = _normalize_uuid(raw)
        if norm is None:
            if not (isinstance(raw, str) and raw.strip()):
                raise PreconditionError(
                    "an allowed principal id is missing/blank — every --allow value must be a "
                    "present, valid UUID (check the deployment outputs)"
                )
            raise PreconditionError(f"allowed principal id {raw!r} is not a valid UUID")
        normalized.add(norm)
    return normalized


def validate_scope(scope: str) -> None:
    """Raise :class:`PreconditionError` unless ``scope`` is a storage-account resource id."""
    if not scope or not _SA_SCOPE_RE.match(scope.strip()):
        raise PreconditionError(
            "--scope must be a storage-account resource id "
            "(/subscriptions/.../resourceGroups/.../providers/Microsoft.Storage/storageAccounts/"
            f"<name>); got {scope!r}"
        )


# --------------------------------------------------------------------------------------------------
# Pure decision logic (no Azure I/O) — unit-tested.
# --------------------------------------------------------------------------------------------------
def _role_guid(role_definition_id: str) -> str:
    """Return the lowercased trailing GUID of an ARM roleDefinitionId (or the value itself)."""
    return role_definition_id.rstrip("/").rsplit("/", 1)[-1].lower()


def _norm_scope(scope: str) -> str:
    return scope.rstrip("/").lower()


def _action_pattern_matches(pattern: str, action: str) -> bool:
    """True iff an Azure RBAC action ``pattern`` matches the concrete ``action``.

    Azure permission strings use ``*`` as a wildcard that matches any sequence of characters —
    INCLUDING ``/`` separators — so ``Microsoft.Storage/*`` and even a bare ``*`` expand to cover
    ``Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write``. We translate ``*`` to
    a regex ``.*`` (escaping every other character) and anchor a full, case-insensitive match. This
    is a PURE string test — no Azure I/O.
    """
    if not isinstance(pattern, str) or not pattern:
        return False
    regex = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
    return re.match(regex, action, re.IGNORECASE) is not None


def data_actions_grant_state_write(
    data_actions: list[str],
    not_data_actions: list[str],
    targets: tuple[str, ...] = _STATE_WRITE_DATA_ACTIONS,
) -> bool:
    """PURE: do the effective data actions grant blob/table WRITE or DELETE on the state store?

    A target write/delete action counts as GRANTED when some ``dataActions`` pattern matches it AND
    no ``notDataActions`` pattern matches it (``notDataActions`` revoke specific data actions). This
    is evaluated PER target, so a role that grants ``.../blobs/*`` but revokes only ``.../blobs/
    write`` via ``notDataActions`` is still a writer (it retains ``.../blobs/delete``); a wildcard
    ``*`` fully revoked by an equally-broad ``notDataActions`` grants nothing. Returns ``True`` as
    soon as any target is granted-and-not-revoked. No Azure I/O.
    """
    for target in targets:
        granted = any(_action_pattern_matches(p, target) for p in data_actions)
        if not granted:
            continue
        revoked = any(_action_pattern_matches(p, target) for p in not_data_actions)
        if not revoked:
            return True
    return False


def role_definition_grants_state_write(role_def: dict[str, Any]) -> bool:
    """PURE: does a resolved role-DEFINITION dict grant state-store write via its data actions?

    Inspects every ``permissions[]`` block's ``dataActions`` / ``notDataActions`` (control-plane
    ``actions`` / ``notActions`` are intentionally ignored — see the scope note by
    ``_STATE_WRITE_DATA_ACTIONS``: management-plane rights are out of scope while shared-key access
    is disabled). Missing / null keys are treated as empty lists. Returns ``True`` if ANY permission
    block grants an un-revoked blob/table write-or-delete data action. Operates only on an
    already-fetched dict — the fetch stays at the Azure I/O edge, keeping this Azure-free.
    """
    for perm in role_def.get("permissions") or []:
        if not isinstance(perm, dict):
            continue
        data_actions = [a for a in (perm.get("dataActions") or []) if isinstance(a, str)]
        not_data_actions = [a for a in (perm.get("notDataActions") or []) if isinstance(a, str)]
        if data_actions_grant_state_write(data_actions, not_data_actions):
            return True
    return False


def build_role_definition_index(
    role_definitions: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Index resolved role-definition dicts by their lowercased GUID (from ``id`` or ``name``).

    The index is what :func:`find_effective_state_writers` consults to resolve a non-built-in
    assignment's role definition. A definition whose id/name yields no GUID is skipped (it can never
    be soundly correlated); an assignment referencing a GUID absent from the index is treated as
    UNRESOLVABLE (fail-closed → possible writer) by the matcher.
    """
    index: dict[str, dict[str, Any]] = {}
    for role_def in role_definitions:
        if not isinstance(role_def, dict):
            continue
        rid = role_def.get("id")
        guid = _role_guid(rid) if isinstance(rid, str) and rid.strip() else None
        if not guid:
            name = role_def.get("name")
            guid = name.strip().lower() if isinstance(name, str) and name.strip() else None
        if guid:
            index[guid] = role_def
    return index


def assignment_writer_status(
    assignment: dict[str, Any],
    write_role_ids: frozenset[str],
    role_definitions: dict[str, dict[str, Any]] | None,
) -> str:
    """Classify an assignment's state-write status as ``"proven"`` | ``"possible"`` | ``"no"``.

    * ``"proven"`` — POSITIVE evidence the assignment grants state write: its role-definition GUID
      is one of the enumerated built-in write roles (:data:`STATE_WRITE_ROLE_IDS`, fast path), OR a
      RESOLVED role definition whose effective data actions grant blob/table write/delete
      (:func:`role_definition_grants_state_write`). Safe to act on destructively (cleanup).
    * ``"possible"`` — the GUID is NOT built-in and is ABSENT from a supplied (non-``None``) role
      definition index: an UNRESOLVED / opaque definition. Fail-closed for VERIFICATION (counts as a
      writer → surface / fail) but NOT proof — cleanup must never DELETE on this alone.
    * ``"no"`` — a resolved definition that does not grant write, OR (legacy/offline-without-defs,
      ``role_definitions is None``) any non-built-in role. Not a state-writer.

    This is the single pure classifier both the verify path (proven+possible ⇒ writer) and the
    destructive cleanup path (only ``proven`` may be deleted) share, so the two never diverge.
    """
    guid = _role_guid(str(assignment.get("roleDefinitionId", "")))
    if guid in write_role_ids:
        return "proven"
    if role_definitions is None:
        return "no"
    role_def = role_definitions.get(guid)
    if role_def is None:
        return "possible"  # unresolvable / opaque definition — writer for verify, not for delete
    return "proven" if role_definition_grants_state_write(role_def) else "no"


def _assignment_is_state_writer(
    assignment: dict[str, Any],
    write_role_ids: frozenset[str],
    role_definitions: dict[str, dict[str, Any]] | None,
) -> bool:
    """Does this assignment grant (or possibly grant) a state-write role? (verification semantics.)

    Returns ``True`` for BOTH proven writers (built-in fast path OR a resolved role definition that
    grants write) AND unresolved/opaque roles ("possible" — fail-closed for verification). Returns
    ``False`` only for a resolved non-writer, or — when no ``role_definitions`` index is supplied
    (legacy/offline-without-defs) — any non-built-in role (prior behaviour). Thin wrapper over
    :func:`assignment_writer_status` so verification and cleanup share one classifier.
    """
    return assignment_writer_status(assignment, write_role_ids, role_definitions) != "no"


def canonical_assignment_id_under_scope(assignment_id: object, scope: str) -> str | None:
    """Return ``assignment_id`` iff it is a canonical role-assignment resource id directly under the
    target storage-account ``scope`` (fail closed → ``None`` otherwise).

    A stray is only DELETABLE from here when its assignment resource id is exactly
    ``{scope}/providers/Microsoft.Authorization/roleAssignments/{guid}`` (case-insensitive on the
    ARM path, GUID validated). A missing/blank/non-canonical/OUT-OF-SCOPE id must never be passed to
    ``delete_role_assignment`` — a crafted record must not be able to delete an assignment in
    another scope.
    """
    if not isinstance(assignment_id, str):
        return None
    candidate = assignment_id.strip()
    if not candidate:
        return None
    pattern = (
        "^"
        + re.escape(_norm_scope(scope))
        + r"/providers/microsoft\.authorization/roleassignments/"
        + r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )
    return candidate if re.match(pattern, candidate.rstrip("/").lower()) else None


def canonical_identity_id_in_rg(identity_id: object, resource_group: str, name: str) -> str | None:
    """Return ``identity_id`` iff it is a canonical userAssignedIdentities resource id beneath the
    expected ``resource_group`` AND whose trailing name equals ``name`` (fail closed → ``None``).

    Combined with :func:`is_legacy_shared_identity_name` at the call site, this ensures
    ``delete_identity`` can only ever target a user-assigned identity that lives in the expected
    resource group and whose resource id matches its (legacy-convention) name — a crafted/foreign
    id can never cause a bystander identity in another RG to be deleted.
    """
    if not isinstance(identity_id, str) or not name:
        return None
    candidate = identity_id.strip()
    if not candidate:
        return None
    pattern = (
        r"^/subscriptions/[^/]+/resourcegroups/"
        + re.escape(resource_group.lower())
        + r"/providers/microsoft\.managedidentity/userassignedidentities/"
        + re.escape(name.lower())
        + r"$"
    )
    return candidate if re.match(pattern, candidate.rstrip("/").lower()) else None


def find_stray_state_writers(
    assignments: list[dict[str, Any]],
    allowed_principal_ids: set[str],
    scope_id: str,
    write_role_ids: frozenset[str] = STATE_WRITE_ROLE_IDS,
    *,
    role_definitions: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Return SA-scope assignments granting a state-write role to a non-allowed principal.

    Only assignments defined *at* ``scope_id`` (the storage account) are returned — these are the
    ones cleanup may safely DELETE. Assignments inherited from an ancestor (RG/subscription) are
    excluded here on purpose: they cannot be deleted from this scope. Use
    :func:`find_effective_state_writers` for the fail-closed verify gate, which must also see
    inherited grants. Comparison is case-insensitive. ``role_definitions`` (a GUID→role-def index)
    extends detection to CUSTOM roles whose data actions grant equivalent write access; when
    ``None`` only the built-in ``write_role_ids`` are considered (legacy behaviour).
    """
    scope_norm = _norm_scope(scope_id)
    return [
        a
        for a in find_effective_state_writers(
            assignments, allowed_principal_ids, write_role_ids, role_definitions=role_definitions
        )
        if _norm_scope(str(a.get("scope", ""))) == scope_norm
    ]


def find_effective_state_writers(
    assignments: list[dict[str, Any]],
    allowed_principal_ids: set[str],
    write_role_ids: frozenset[str] = STATE_WRITE_ROLE_IDS,
    *,
    role_definitions: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Return EVERY assignment granting a state-write role to a non-allowed principal, any scope.

    Intended to be fed the ``--include-inherited`` listing so an assignment that grants write at the
    storage account OR at an ancestor scope (resource group / subscription) — and is therefore
    EFFECTIVE at the account — is detected. Each returned assignment keeps its own ``scope`` so the
    caller can tell SA-scoped (deletable) from inherited (manual remediation). Case-insensitive.
    An empty result means the boundary holds: only the allowed writers can write state.

    A role assignment counts as a state-writer when EITHER its role-definition GUID is a built-in in
    ``write_role_ids`` (fast path, unchanged) OR its resolved role DEFINITION grants blob/table
    write/delete via effective data actions (custom-role detection, issue #98). ``role_definitions``
    is a GUID→role-def index (see :func:`build_role_definition_index`); when supplied, a GUID that
    is not built-in AND is ABSENT from the index is treated as UNRESOLVABLE and, if held by a
    non-allowed principal, surfaced as a POSSIBLE writer (fail closed) — never silently ignored.
    """
    allowed = {norm for p in allowed_principal_ids if (norm := _normalize_uuid(p))}
    strays: list[dict[str, Any]] = []
    for a in assignments:
        if not _assignment_is_state_writer(a, write_role_ids, role_definitions):
            continue
        if _normalize_uuid(a.get("principalId")) not in allowed:
            strays.append(a)
    return strays


def is_legacy_shared_identity_name(name: str) -> bool:
    """True iff ``name`` is the pre-#79 shared identity ``wp-id-<token>`` (not a per-component one).

    The per-component identities are ``wp-id-api-*`` / ``wp-id-worker-*`` / ``wp-id-web-*`` /
    ``wp-id-grafana-*`` — their segment after ``wp-id-`` contains a hyphen, so the anchored
    ``^wp-id-[a-z0-9]+$`` pattern (no interior hyphen) already excludes them. The explicit reserved
    check is defence-in-depth in case a token ever collided with a component word.

    NOTE: this is only the *secondary* naming guard. It is deliberately NOT sufficient on its own to
    authorise deletion — a bystander identity an operator named ``wp-id-production`` /
    ``wp-id-monitoring`` also matches this shape. Deletion additionally requires positive evidence
    that the identity actually held a state-write role at the storage account (see
    :func:`correlate_deletable_legacy_identities`).
    """
    if not _LEGACY_IDENTITY_RE.match(name):
        return False
    segment = name[len("wp-id-") :]
    return segment not in _RESERVED_SUFFIXES


def is_per_component_identity_name(name: str) -> bool:
    """True iff ``name`` is a sanctioned per-component identity (wp-id-api/worker/web/grafana-*)."""
    return bool(_PER_COMPONENT_IDENTITY_RE.match(name))


def correlate_deletable_legacy_identities(
    identities: list[dict[str, Any]],
    stray_principal_ids: set[str],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Correlate REMOVED stray-writer principals back to the identity resources to delete.

    An identity is eligible for deletion ONLY when BOTH hold:

    1. **Evidence gate (primary):** its ``principalId`` is one of ``stray_principal_ids`` — i.e. a
       principal we positively detected holding a state-WRITE role at *this* storage account that is
       not a sanctioned writer (api/worker). A bystander like ``wp-id-production`` that never held a
       state-write role at the SA is never in this set, so it is never deleted.
    2. **Naming guard (secondary):** its name matches the legacy shared-identity convention and is
       not a per-component identity.

    Returns ``(to_delete, unresolved)`` where ``unresolved`` lists stray principals that could NOT
    be safely correlated to a deletable legacy identity and are NOT a known per-component identity
    (zero matches, more than one match, or a single match whose name is neither the legacy
    convention nor a per-component identity). Callers MUST treat a non-empty ``unresolved`` as
    fail-closed (flag / non-zero) and delete NOTHING for those principals — never fall back to
    deleting on name alone.
    """
    by_pid: dict[str, list[dict[str, Any]]] = {}
    for ident in identities:
        norm = _normalize_uuid(ident.get("principalId"))
        if norm is None:
            continue  # an identity whose principalId is malformed cannot be soundly correlated
        by_pid.setdefault(norm, []).append(ident)

    to_delete: list[dict[str, Any]] = []
    unresolved: list[str] = []
    for pid in sorted({norm for p in stray_principal_ids if (norm := _normalize_uuid(p))}):
        matches = by_pid.get(pid, [])
        if len(matches) == 1 and is_legacy_shared_identity_name(str(matches[0].get("name", ""))):
            to_delete.append(matches[0])
        elif len(matches) == 1 and is_per_component_identity_name(str(matches[0].get("name", ""))):
            # A sanctioned per-component identity that wrongly held a write role: its stray role
            # assignment is removed, but the identity resource itself is legitimate — never delete.
            continue
        else:
            unresolved.append(pid)
    return to_delete, unresolved


# --------------------------------------------------------------------------------------------------
# Azure I/O (thin wrappers around the `az` CLI; keyless via the caller's existing login).
# --------------------------------------------------------------------------------------------------
def _az_json(args: list[str]) -> Any:
    """Run `az <args> -o json` and return the parsed JSON.

    Fail-closed: a non-zero `az` exit, a timeout, or output that is not valid JSON raises
    :class:`AzureOutputError` (never a silent empty result). The message is kept non-secret — it
    names the sub-command and exit code but does not echo raw stderr, which could carry tokens.
    """
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell; args are not user-controlled
            ["az", *args, "--only-show-errors", "-o", "json"],  # noqa: S607 - `az` from PATH
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:  # az not installed / not on PATH
        raise AzureOutputError("`az` CLI not found on PATH") from exc
    except subprocess.CalledProcessError as exc:
        raise AzureOutputError(
            f"`az {' '.join(args[:2])}` failed (exit {exc.returncode})"
        ) from exc
    out = proc.stdout.strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError as exc:
        raise AzureOutputError(
            f"`az {' '.join(args[:2])}` returned output that is not valid JSON"
        ) from exc


def _require_list(data: Any, source: str) -> list[dict[str, Any]]:
    """Fail-closed: accept ONLY a genuine JSON array; anything else raises ``AzureOutputError``.

    This is what distinguishes "az succeeded and returned an empty list" (a valid clean result)
    from "az errored / returned null / returned a non-array" (which must never look clean).
    """
    if not isinstance(data, list):
        raise AzureOutputError(
            f"{source} did not return a JSON array (got {type(data).__name__}); refusing to treat "
            "it as an empty/clean result"
        )
    return data


def _az(args: list[str]) -> None:
    """Run `az <args>` for its side effect (delete), surfacing failures."""
    subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["az", *args, "--only-show-errors"],  # noqa: S607 - `az` resolved from PATH
        check=True,
        capture_output=True,
        text=True,
    )


def list_role_assignments(scope: str, *, include_inherited: bool = False) -> list[dict[str, Any]]:
    """List role assignments at ``scope``.

    With ``include_inherited=True`` the listing also contains assignments defined at ancestor
    scopes (resource group / subscription) that are EFFECTIVE at ``scope`` — required by the verify
    gate so an inherited state-writer cannot slip past. Cleanup lists without inheritance because it
    may only delete assignments defined at the account scope itself.
    """
    args = ["role", "assignment", "list", "--scope", scope]
    if include_inherited:
        args.append("--include-inherited")
    return _require_list(_az_json(args), "`az role assignment list`")


def delete_role_assignment(assignment_id: str) -> None:
    _az(["role", "assignment", "delete", "--ids", assignment_id])


def list_user_assigned_identities(resource_group: str) -> list[dict[str, Any]]:
    data = _az_json(["identity", "list", "--resource-group", resource_group])
    return _require_list(data, "`az identity list`")


def delete_identity(identity_id: str) -> None:
    _az(["identity", "delete", "--ids", identity_id])


def list_role_definitions(scope: str) -> list[dict[str, Any]]:
    """List role definitions (built-in AND custom) visible at ``scope``.

    Used to RESOLVE each assignment's role definition so the gate can inspect a custom role's
    ``dataActions`` (issue #98). Fail-closed: a failed/timed-out `az` call or a non-array response
    raises :class:`AzureOutputError` and never looks like an empty/clean result. The Azure I/O stays
    here at the edge; the decision logic in :func:`role_definition_grants_state_write` is pure.
    """
    data = _az_json(["role", "definition", "list", "--scope", scope])
    return _require_list(data, "`az role definition list`")


# --------------------------------------------------------------------------------------------------
# Orchestration.
# --------------------------------------------------------------------------------------------------
def _load_assignments(
    scope: str, assignments_file: str | None, *, include_inherited: bool = False
) -> list[dict[str, Any]]:
    if assignments_file:
        text = Path(assignments_file).read_text(encoding="utf-8")
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            raise AzureOutputError(
                f"assignments file {assignments_file} is not valid JSON"
            ) from exc
        return _require_list(raw, f"assignments file {assignments_file}")
    return list_role_assignments(scope, include_inherited=include_inherited)


def _load_role_definitions(
    scope: str, role_definitions_file: str | None, *, offline: bool
) -> dict[str, dict[str, Any]] | None:
    """Build the GUID→role-definition index for custom-role detection, or ``None`` (built-in only).

    * Live mode (``offline=False``): always fetch role definitions from Azure so a custom role's
      ``dataActions`` can be inspected; an unresolved reference then fails closed in the matcher.
    * Offline mode: use ``role_definitions_file`` when given (for local dry-runs / tests), else
      return ``None`` so only the three built-in write GUIDs are considered (legacy behaviour, no
      Azure call).
    """
    if role_definitions_file:
        text = Path(role_definitions_file).read_text(encoding="utf-8")
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            raise AzureOutputError(
                f"role-definitions file {role_definitions_file} is not valid JSON"
            ) from exc
        return build_role_definition_index(
            _require_list(raw, f"role-definitions file {role_definitions_file}")
        )
    if offline:
        return None
    return build_role_definition_index(list_role_definitions(scope))


def _stray_descriptor(a: dict[str, Any]) -> str:
    """Non-secret one-line descriptor of a stray assignment (role GUID + assignment id only)."""
    role = _role_guid(str(a.get("roleDefinitionId", ""))) or "<unknown-role>"
    aid = a.get("id")
    aid_str = aid if isinstance(aid, str) and aid.strip() else "<missing-id>"
    return f"role {role} assignment {aid_str}"


def _cleanup(
    scope: str,
    allowed: set[str],
    resource_group: str | None,
    assignments_file: str | None,
    role_definitions_file: str | None = None,
    *,
    dry_run: bool,
) -> int:
    """Remove stray state-write assignments and the legacy shared identity (idempotent).

    Returns 0 only when EVERY stray writer removed at the SA is accounted for; returns non-zero
    (fail-closed) when any stray cannot be soundly correlated. Identity deletion is gated on
    EVIDENCE (the principal held a state-write role at THIS storage account) and never on the name
    convention alone, so a bystander identity that merely follows a similar name
    (``wp-id-production``, ``wp-id-monitoring``, …) is never deleted.

    Accounting invariant: every stray writer at the SA must EITHER be correlated to a deletable
    legacy identity (deleted), OR be a legitimately-skipped per-component identity, OR be flagged
    UNRESOLVED with a non-zero exit. In particular a stray whose ``principalId`` is
    missing/empty/malformed (not a UUID) — or whose assignment id is missing / not a canonical
    role-assignment id under THIS storage account — cannot be soundly correlated, so it is treated
    as UNRESOLVED (non-zero) rather than silently dropped while returning success. Deletion is
    additionally scope-bound: ``delete_role_assignment`` only ever runs for a canonical assignment
    id directly under the target SA, and ``delete_identity`` only for a canonical
    userAssignedIdentities id in the expected resource group whose name is the legacy convention.

    Destructive-op gate (issue #98 MEDIUM): only PROVEN writers are ever deleted — a built-in
    write-role GUID, or a RESOLVED custom role whose data actions grant blob/table write/delete.
    A stray whose role definition is UNRESOLVED/opaque (``assignment_writer_status`` ==
    ``"possible"``) is NEVER auto-deleted on that uncertainty (it could be read-only): it is
    surfaced with a WARNING, its principal is NOT correlated for identity deletion, and the run
    exits non-zero (fail closed). Verification (:func:`_verify`) still treats such a role as a
    writer, so it is never silently ignored — but destruction requires proof, not mere uncertainty.
    """
    offline = assignments_file is not None
    role_definitions = _load_role_definitions(scope, role_definitions_file, offline=offline)
    strays = find_stray_state_writers(
        _load_assignments(scope, assignments_file),
        allowed,
        scope,
        role_definitions=role_definitions,
    )

    stray_principal_ids: set[str] = set()
    malformed: list[dict[str, Any]] = []
    unresolved_writers: list[dict[str, Any]] = []
    for a in strays:
        # DESTRUCTIVE-op gate: only PROVEN writers may be deleted. An UNRESOLVED/opaque role
        # ("possible") is fail-closed for VERIFICATION but must never be auto-deleted on uncertainty
        # — it could be read-only. Surface it and fail the run; delete nothing, correlate nothing.
        if assignment_writer_status(a, STATE_WRITE_ROLE_IDS, role_definitions) == "possible":
            print(
                "[cleanup] WARNING: stray assignment with an UNRESOLVED/opaque role definition "
                f"({_stray_descriptor(a)}); refusing to auto-delete on uncertainty — failing "
                "closed. Investigate/remediate this principal manually.",
                file=sys.stderr,
            )
            unresolved_writers.append(a)
            continue

        norm_pid = _normalize_uuid(a.get("principalId"))
        canonical_aid = canonical_assignment_id_under_scope(a.get("id"), scope)
        pid_ok = norm_pid is not None
        id_ok = canonical_aid is not None
        role = _role_guid(str(a.get("roleDefinitionId", "")))
        principal = norm_pid if norm_pid else "?"

        if dry_run or offline:
            print(f"[cleanup] would remove state-write role {role} from principal {principal}")
        elif id_ok:
            print(f"[cleanup] removing state-write role {role} from stray principal {principal}")
            delete_role_assignment(canonical_aid)  # type: ignore[arg-type]  # id_ok => not None
        else:
            print(
                f"[cleanup] cannot remove malformed stray assignment ({_stray_descriptor(a)}): "
                "missing / non-canonical / out-of-scope assignment id",
                file=sys.stderr,
            )

        if pid_ok and id_ok:
            stray_principal_ids.add(norm_pid)  # type: ignore[arg-type]  # pid_ok => not None
        else:
            malformed.append(a)

    for a in malformed:
        print(
            "[cleanup] WARNING: stray state-writer with a missing/malformed principalId or "
            f"missing/out-of-scope assignment id could not be correlated to an identity "
            f"({_stray_descriptor(a)}); failing closed — investigate/remediate this principal "
            "manually.",
            file=sys.stderr,
        )

    # Legacy identity deletion requires live az + a resource group; skipped in offline dry-run — but
    # malformed / unresolved strays still fail the run closed (surfaced but not accounted for).
    if offline or not resource_group:
        return 1 if (malformed or unresolved_writers) else 0

    to_delete: list[dict[str, Any]] = []
    unresolved: list[str] = []
    scope_blocked: list[str] = []
    if stray_principal_ids:
        identities = list_user_assigned_identities(resource_group)
        to_delete, unresolved = correlate_deletable_legacy_identities(
            identities, stray_principal_ids
        )
        for ident in to_delete:
            name = str(ident.get("name", ""))
            canonical_iid = canonical_identity_id_in_rg(ident.get("id"), resource_group, name)
            if canonical_iid is None or not is_legacy_shared_identity_name(name):
                scope_blocked.append(name or "<unknown>")
                print(
                    f"[cleanup] WARNING: refusing to delete identity {name or '<unknown>'}: its "
                    "resource id is not a canonical userAssignedIdentities id in the expected "
                    "resource group (or its name is not the legacy convention). Failing closed — "
                    "investigate/remediate manually.",
                    file=sys.stderr,
                )
                continue
            if dry_run:
                print(f"[cleanup] would delete legacy shared identity {name}")
                continue
            print(f"[cleanup] deleting legacy shared identity {name} (state-writer at the SA)")
            delete_identity(canonical_iid)
        for pid in unresolved:
            print(
                f"[cleanup] WARNING: stray state-writer principal {pid} could not be correlated "
                "to a deletable legacy identity in the resource group (no unambiguous match). "
                "Refusing to delete any identity by name alone — investigate/remediate this "
                "principal manually.",
                file=sys.stderr,
            )

    return 1 if (unresolved or malformed or scope_blocked or unresolved_writers) else 0


def _verify(
    scope: str,
    allowed: set[str],
    assignments_file: str | None,
    role_definitions_file: str | None = None,
    *,
    retries: int,
    delay: float,
) -> int:
    """Fail-closed gate: 0 iff only allowed writers hold a state-write role EFFECTIVE at ``scope``.

    Uses the ``--include-inherited`` listing so a state-write role granted at the storage account OR
    inherited from an ancestor scope (resource group / subscription) is caught. Strays whose
    assignment scope is the account itself should have been removed by cleanup; strays inherited
    from an ancestor cannot be deleted from here, so the gate fails with a manual-remediation
    message naming the offending principal, role and actual (ancestor) scope. Custom roles granting
    equivalent write data actions are detected via the resolved role-definition index (issue #98);
    an unresolvable role held by a non-allowed principal fails the gate closed.
    """
    offline = assignments_file is not None
    scope_norm = _norm_scope(scope)
    strays: list[dict[str, Any]] = []
    role_definitions: dict[str, dict[str, Any]] | None = None
    role_defs_loaded = False
    attempts = 1 if offline else max(1, retries)
    for attempt in range(1, attempts + 1):
        assignments = _load_assignments(scope, assignments_file, include_inherited=True)
        if not role_defs_loaded:
            # Loaded once, AFTER a successful assignments fetch so a failing assignments listing
            # fails the gate before any extra Azure work.
            role_definitions = _load_role_definitions(
                scope, role_definitions_file, offline=offline
            )
            role_defs_loaded = True
        strays = find_effective_state_writers(
            assignments, allowed, role_definitions=role_definitions
        )
        if not strays:
            print(
                "[verify] OK: only the allowed writer principals hold a state-store WRITE role "
                "(Storage Blob Data Owner / Blob Data Contributor / Table Data Contributor) "
                f"effective at {scope}."
            )
            return 0
        if attempt < attempts:
            print(
                f"[verify] {len(strays)} stray writer(s) still visible "
                f"(attempt {attempt}/{attempts}); retrying in {delay:g}s for RBAC propagation…",
                file=sys.stderr,
            )
            time.sleep(delay)

    print(
        f"[verify] FAIL: {len(strays)} principal(s) other than the api/worker identities hold a "
        f"state-store WRITE role (Storage Blob Data Owner / Blob Data Contributor / Table Data "
        f"Contributor) effective at {scope} — the API-only-writer boundary is NOT enforced:",
        file=sys.stderr,
    )
    for a in strays:
        principal = a.get("principalId", "?")
        role = _role_guid(str(a.get("roleDefinitionId", "")))
        a_scope = str(a.get("scope", ""))
        aid = str(a.get("id", "?"))
        if _norm_scope(a_scope) == scope_norm:
            print(
                f"          - principal {principal} role {role} assigned AT the account "
                f"(assignment {aid}); cleanup should have removed it — re-run with --cleanup.",
                file=sys.stderr,
            )
        else:
            print(
                f"          - principal {principal} role {role} INHERITED from ancestor scope "
                f"{a_scope or '<unknown>'}; it cannot be removed at the account scope. Remediate "
                f"manually at that scope, e.g. `az role assignment delete --ids {aid}`.",
                file=sys.stderr,
            )
    return 1


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Enforce the API-only-writer boundary (issue #79): clean up the legacy shared "
        "identity's state-write grants and fail-closed if any non-api/worker principal still holds "
        "a state-store WRITE role (Storage Blob Data Owner / Blob Data Contributor / Table Data "
        "Contributor) effective at the storage-account scope, including grants inherited from an "
        "ancestor scope.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--scope", required=True, help="Storage-account resource id (SA scope).")
    parser.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="PRINCIPAL_ID",
        help="An allowed writer principal (object) id. Pass twice: the api and worker identities.",
    )
    parser.add_argument(
        "--resource-group",
        default=None,
        help="Resource group — enables deletion of a leftover legacy shared identity resource.",
    )
    parser.add_argument(
        "--cleanup", action="store_true", help="Remove stray writers before verifying."
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Print intended deletions but do not delete."
    )
    parser.add_argument(
        "--assignments-file",
        default=None,
        help="Offline mode: read role assignments from this JSON file instead of calling az "
        "(verify-only; used for local dry-runs and tests).",
    )
    parser.add_argument(
        "--role-definitions-file",
        default=None,
        help="Offline mode: read role DEFINITIONS (built-in + custom) from this JSON file instead "
        "of calling az. Enables custom-role dataAction detection (issue #98) in offline dry-runs "
        "and tests; live runs fetch definitions from Azure automatically.",
    )
    parser.add_argument(
        "--retries", type=int, default=6, help="Verify re-list attempts (RBAC propagation)."
    )
    parser.add_argument(
        "--retry-delay", type=float, default=5.0, help="Seconds between verify attempts."
    )
    args = parser.parse_args(argv[1:])

    try:
        allowed = validate_allowlist(args.allow)
        validate_scope(args.scope)
    except PreconditionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        cleanup_status = 0
        if args.cleanup:
            cleanup_status = _cleanup(
                args.scope,
                allowed,
                args.resource_group,
                args.assignments_file,
                args.role_definitions_file,
                dry_run=args.dry_run,
            )

        verify_status = _verify(
            args.scope,
            allowed,
            args.assignments_file,
            args.role_definitions_file,
            retries=args.retries,
            delay=args.retry_delay,
        )
        # Fail-closed: a verify failure OR an uncorrelated stray writer from cleanup fails the gate.
        return verify_status or cleanup_status
    except AzureOutputError as exc:
        print(f"[error] fail-closed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
