"""Least-privilege role model + deny-by-default policy for the platform's Entra app roles.

Three roles, strictly nested (Reader ⊂ Operator ⊂ Admin):

* **Reader** — read the platform's read models (GET endpoints).
* **Operator** — Reader plus every state-mutating action: run modules and submit
  results/estate/graph/findings/snapshot.
* **Admin** — Operator plus any future admin-only action (pack assignment, module toggle, …).

Authorization is **table-driven and deny-by-default**: a request declares the single role it
requires and :meth:`Principal.grants` answers only from the explicit :data:`ROLE_GRANTS` closure —
a principal with no recognized role is denied everything (even Reader). App role *values* on the
Entra token's ``roles`` claim are mapped to these roles through the explicit
:data:`APP_ROLE_TO_ROLE` table; unrecognized app-role strings are ignored (grant nothing).
"""
from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum

__all__ = [
    "APP_ROLE_ADMIN",
    "APP_ROLE_OPERATOR",
    "APP_ROLE_READER",
    "APP_ROLE_TO_ROLE",
    "ROLE_GRANTS",
    "Role",
    "roles_from_app_roles",
]


class Role(StrEnum):
    """A platform authorization role. String-valued so it is trivially loggable (non-PII)."""

    reader = "reader"
    operator = "operator"
    admin = "admin"


# The Entra **app role** values (the strings that appear in a token's ``roles`` claim) the API
# recognizes. These are the app-registration "App roles" an admin assigns to users/apps; they are
# non-secret identifiers. Kept as constants so the mapping table and docs share one source of truth.
APP_ROLE_READER = "Workloads.Reader"
APP_ROLE_OPERATOR = "Workloads.Operator"
APP_ROLE_ADMIN = "Workloads.Admin"

# Explicit app-role-string → :class:`Role` table (deny-by-default: anything absent grants nothing).
APP_ROLE_TO_ROLE: dict[str, Role] = {
    APP_ROLE_READER: Role.reader,
    APP_ROLE_OPERATOR: Role.operator,
    APP_ROLE_ADMIN: Role.admin,
}

# The explicit privilege closure: holding a role grants exactly this set of required-roles. Admin
# implies Operator implies Reader. Authorization consults ONLY this table — there is no implicit
# ordering or numeric comparison to get subtly wrong.
ROLE_GRANTS: dict[Role, frozenset[Role]] = {
    Role.reader: frozenset({Role.reader}),
    Role.operator: frozenset({Role.reader, Role.operator}),
    Role.admin: frozenset({Role.reader, Role.operator, Role.admin}),
}


def roles_from_app_roles(app_roles: Iterable[str]) -> frozenset[Role]:
    """Map an Entra ``roles`` claim (app-role strings) to recognized :class:`Role` values.

    Unrecognized strings are dropped (deny-by-default — an unknown app role grants nothing). Returns
    the possibly-empty set of recognized roles; an empty set authorizes nothing.
    """
    return frozenset(
        APP_ROLE_TO_ROLE[value] for value in app_roles if value in APP_ROLE_TO_ROLE
    )
