"""Provenance completeness guard — no finding may be emitted without its evidence (issue #59).

Guardrail #8 (Provenance): *every* finding must cite the evidence it was derived from. A
:class:`~shared.contracts.Finding` carries that provenance in its ``evidence`` list of
:class:`~shared.contracts.SourceReference` (resource id / metric / log / pack), plus the optional
``packId``/``packVersion`` when the finding derives from a signed pack. A finding with an empty
``evidence`` list is unattributable — it cannot be traced back to what produced it — so this module
**fails closed**: it refuses to let such a finding be emitted rather than persisting an
un-provenanced result.

The guard is a **pure function** (no I/O), so it is trivially unit-testable and can be hooked at
any emission boundary. It is enforced at the module-emission boundary in
:func:`shared.module_base.run_module`, so a module that produces an un-provenanced finding fails
closed *before* the finding ever reaches the API single writer / durable state.

Note we require ``evidence`` (source references) but deliberately NOT ``packVersion``: some findings
are derived from the estate/graph rather than a pack (e.g. a dependency-graph single-point-of-
failure), so they legitimately have evidence but no pack. The hard requirement is that *something*
attributable is always cited.
"""
from __future__ import annotations

from collections.abc import Iterable

from shared.contracts import SOURCE_REFERENCE_KINDS, Finding, SourceReference


class ProvenanceError(ValueError):
    """Raised when a finding lacks provenance (no ``sourceReferences``). Fail closed."""


def _reference_is_attributable(ref: SourceReference) -> bool:
    """Return ``True`` iff ``ref`` really attributes evidence: a non-blank ``id`` AND a non-blank,
    SUPPORTED ``kind`` (one of :data:`~shared.contracts.SOURCE_REFERENCE_KINDS`).

    A present-but-empty reference (blank id, or a blank/unknown kind) is NOT attributable — it
    cannot be traced back to anything real — so it does not satisfy the provenance guarantee.
    """
    return bool(ref.id.strip()) and ref.kind.strip() in SOURCE_REFERENCE_KINDS


def finding_has_provenance(finding: Finding) -> bool:
    """Return ``True`` iff ``finding`` cites at least one *attributable* source reference."""
    return any(_reference_is_attributable(ref) for ref in finding.evidence)


def enforce_finding_provenance(findings: Iterable[Finding]) -> None:
    """Raise :class:`ProvenanceError` on the first finding that has no provenance (fail closed).

    Callers at an emission boundary use this to guarantee no un-provenanced finding is emitted:
    on a violation the whole emission fails rather than persisting a finding that cannot be traced
    to its evidence. A finding whose only references are blank/unknown (e.g. ``kind=""`` or
    ``id=""``) is treated as un-provenanced and rejected the same as one with no references at all.
    """
    for finding in findings:
        if not finding_has_provenance(finding):
            raise ProvenanceError(
                f"Finding {finding.id!r} from module {finding.module!r} has no attributable "
                "sourceReferences (provenance); refusing to emit (fail closed)"
            )


def revalidate_finding_provenance(findings: Iterable[Finding]) -> None:
    """Re-run the :class:`Finding` pack-vs-structural invariant at a persistence boundary (#83).

    Defense in depth: ``Finding`` enforces its provenance invariant in a construction-time
    ``model_validator``, and ``validate_assignment=True`` re-runs it on attribute mutation. This is
    a belt-and-braces re-check at the durable-write boundary — even if a finding somehow reached
    persistence in an invalid provenance state (e.g. built via ``model_construct`` which bypasses
    validation, or an attribute forced through ``__dict__``), we reject it here fail-closed,
    consistent with the evidence gate in :func:`enforce_finding_provenance`. Re-validating the
    round-tripped ``model_dump()`` re-executes ``_enforce_provenance``; on a violation Pydantic
    raises (a :class:`pydantic.ValidationError`) so the whole write rolls back and NOTHING is
    persisted.
    """
    for finding in findings:
        Finding.model_validate(finding.model_dump())

