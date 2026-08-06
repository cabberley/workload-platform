"""The validated, **non-PII** principal extracted from a verified Entra token.

A :class:`Principal` carries ONLY the caller's object id (``oid`` — a directory guid, not a name or
email) and the recognized platform roles. It deliberately holds no ``name``/``upn``/``email`` claim,
so a principal can never introduce PII into logs, audit subjects, or traces. Authorization is
answered by :meth:`grants`, which consults the explicit deny-by-default :data:`~shared.auth.roles.
ROLE_GRANTS` closure — never an ad-hoc comparison.
"""
from __future__ import annotations

from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict, Field

from shared.auth.roles import ROLE_GRANTS, Role

__all__ = ["Principal"]


class Principal(BaseModel):
    """A validated caller: a non-PII object id + the recognized roles it was granted.

    Immutable (``frozen``) and closed (``extra="forbid"``) so it cannot be widened with a PII claim
    downstream. ``oid`` is the token's ``oid`` claim — the directory object id, a guid — used as the
    audit actor. ``roles`` is the set of recognized platform roles (may be empty ⇒ authorizes
    nothing). ``tenant_id`` is the token's ``tid`` claim (the caller's Entra tenant/directory guid,
    also non-PII), threaded so tenant isolation (issue #65) resolves from the VALIDATED token.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    oid: str
    roles: frozenset[Role] = Field(default_factory=frozenset)
    # The caller's Entra tenant (directory) id — the token's ``tid`` claim, a non-PII guid. Carried
    # so the API can resolve tenant isolation (issue #65) from the VALIDATED token, never a header.
    # ``None`` on the deliberate no-auth local/dev path (no token ⇒ single-tenant default).
    tenant_id: str | None = None

    def grants(self, required: Role) -> bool:
        """Return ``True`` iff any held role's grant-closure includes ``required`` (deny default).

        Consults ONLY :data:`~shared.auth.roles.ROLE_GRANTS`; a principal with no recognized role
        grants nothing (not even Reader).
        """
        return any(required in ROLE_GRANTS[held] for held in self.roles)

    @property
    def granted(self) -> frozenset[Role]:
        """The full set of roles this principal effectively satisfies (its grant closure)."""
        closure: set[Role] = set()
        for held in self.roles:
            closure |= ROLE_GRANTS[held]
        return frozenset(closure)

    @classmethod
    def build(cls, *, oid: str, roles: Iterable[Role], tenant_id: str | None = None) -> Principal:
        """Construct a principal from an oid, recognized roles, and an optional tenant id."""
        return cls(oid=oid, roles=frozenset(roles), tenant_id=tenant_id)
