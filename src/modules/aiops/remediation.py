"""RCA -> Ops-pack **advisory** remediation lookup (issue #52).

Pure logic — no I/O, no Azure. Turns a confidence-gated Auto-RCA :class:`AgentResponse` (issue #50)
into advisory remediation proposals sourced from **Ops packs** (signed, versioned content), plus an
explicit "call support" path. **No auto-apply, ever** (guardrail 5).

Design (guardrails: advisory only, provenance on every conclusion, fail-closed, content-over-code):

* The remediation KNOWLEDGE lives in Ops-pack ``remediations`` content, not in Python branches.
  This module only (a) parses that content fail-closed into bounded, typed tables, (b) maps a
  root-cause *category* to its ordered advisory steps, and (c) enforces the confidence /
  verification / no-match gates. There is **no** code path that mutates customer infrastructure —
  no ``apply``, no exec, no Azure write client. Steps are advisory human-readable text only.
* **Fail-closed gate.** If RCA confidence is below :data:`~modules.aiops.rca.RCA_CONFIDENCE_FLOOR`,
  OR no verified Ops-pack remediation matches the root-cause category, we emit an explicit
  **"call support"** ``nextAction`` and NO guessed remediation. Only when confidence >= floor AND a
  matching table exists do we return its advisory steps, each citing the source **pack id +
  version** in ``sourceReferences``.
* **Deterministic & PII-free.** Steps are ordered by (pack id, pack version) then authored order.
  The advisory text WE generate contains no resource id / PII — we only cite the root-cause node id
  in ``sourceReferences`` exactly as RCA already does (provenance, not free text).

The parsed tables are passed in (already verified + loaded at the module edge), keeping this
function pure and Azure/IO-free.
"""
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from modules.aiops.rca import RCA_CONFIDENCE_FLOOR
from shared.contracts import AgentResponse, ResourceNode, SourceReference

# The explicit "call support" next action (mirrors rca.py's low-confidence path so the AIOps
# support-escalation vocabulary stays consistent).
CALL_SUPPORT_ACTION = "recommend-contact-support"

# Documented catch-all category keys: matched only when no category-specific list applies. These
# are VALID keys INSIDE a pack, but a node's derived role must never equal one (a role claiming a
# catch-all token would smuggle a catch-all/exact match) — see :func:`node_category`.
CATCH_ALL_KEYS: tuple[str, ...] = ("*", "default")

# Fail-closed bounds enforced independently of the JSON Schema (the schema gate runs at CI, but at
# runtime only the pack signature is verified — so an oversized/malformed remediation section must
# still be rejected here). Kept in sync with ``packs_engine/schemas/ops.schema.json``.
MAX_CATEGORIES = 64
MAX_STEPS_PER_CATEGORY = 20
MAX_DESCRIPTION_LEN = 500
MAX_RUNBOOK_LEN = 2048
# Category-key constraints — mirror EXACTLY the ``remediations`` propertyNames rule in
# ``packs_engine/schemas/ops.schema.json`` (maxLength 64 + pattern), so a runtime pack can never
# carry a schema-invalid category key (e.g. ``odb::evil``) that CI would have rejected.
MAX_CATEGORY_KEY_LEN = 64
_CATEGORY_KEY_RE = re.compile(r"^(\*|[a-z0-9][a-z0-9._/-]*)$")
_VALID_SEVERITIES: frozenset[str] = frozenset(
    {"info", "low", "medium", "high", "critical"}
)

# PII-free input summary for the guided-remediation response: the affected entity is cited ONLY in
# ``sourceReferences`` provenance, never in emitted free text (MED 4 / MED B).
_GUIDED_INPUT_SUMMARY = (
    "advisory remediation for a confidence-gated RCA; root cause cited in sourceReferences"
)


def _is_valid_category_key(key: str) -> bool:
    """True iff ``key`` satisfies the Ops-pack category-key schema (length + pattern). Catch-all
    tokens (``*``/``default``) satisfy it — they are valid pack keys."""
    return len(key) <= MAX_CATEGORY_KEY_LEN and _CATEGORY_KEY_RE.match(key) is not None


@dataclass(frozen=True)
class RemediationStep:
    """One advisory remediation step. Advisory text only — never an executable action."""

    description: str
    runbook: str | None = None
    escalate_severity: str | None = None


@dataclass(frozen=True)
class RemediationTable:
    """A verified Ops pack's parsed ``remediations``: provenance + category -> ordered steps."""

    pack_id: str
    pack_version: str
    steps_by_category: Mapping[str, tuple[RemediationStep, ...]] = field(default_factory=dict)


def node_category(node: ResourceNode | None) -> str | None:
    """Derive the stable, low-cardinality remediation category from a resource node.

    We key on the node's **classified ``role``** — the Discovery classification that
    workload-definition packs assign (e.g. ``odb``/``ecp``/``web``/``lb``) and the same field the
    AIOps telemetry ``role:`` selectors resolve against — normalized (trimmed, lowercased). This is
    a stable low-cardinality token, NOT the raw Azure resource ``type`` (e.g.
    ``Microsoft.Compute/virtualMachines``), which is high-cardinality and would never match an
    authored role category. NO domain-knowledge lookup table lives here (content-over-code: the
    mapping of category -> steps is Ops-pack content).

    Fail closed: a node with no classified role — or a role that is not a valid category key, or
    that equals a reserved catch-all token (``*``/``default``) — yields ``None`` (⇒ no category ⇒
    "call support"), rather than guessing a resource-type token that silently never matches or
    letting a hostile role smuggle a catch-all/exact match. A documented ``*``/``default`` catch-all
    in the Ops pack remains the last resort for matched-but-unmapped categories.

    TODO(human): if a richer, cross-workload category taxonomy is desired (e.g. collapsing
    ``odb``/``db`` synonyms into a canonical ``database``), define it as signed *content* (a
    taxonomy pack) rather than a Python branch, and resolve it at the edge before this lookup.
    """
    if node is None:
        return None
    role = (node.role or "").strip().lower()
    if not role or role in CATCH_ALL_KEYS or not _is_valid_category_key(role):
        return None
    return role


def extract_root_cause_node_id(rca: AgentResponse) -> str | None:
    """Return the RCA's asserted root-cause node id, or ``None`` if it did not assert one.

    RCA (issue #50) appends exactly one ``kind="resource"`` reference whose ``detail`` starts with
    ``"identified root cause"`` when — and only when — it is confident. Below the floor it asserts
    no root cause and carries no such reference, so this returns ``None`` (⇒ support path).
    """
    for ref in rca.sourceReferences:
        if ref.kind == "resource" and (ref.detail or "").startswith("identified root cause"):
            return ref.id
    return None


def parse_remediation_table(
    pack_id: str, pack_version: str, body: object
) -> tuple[RemediationTable | None, list[str]]:
    """Parse one Ops pack's ``remediations`` into a bounded typed table. Returns ``(table, notes)``.

    **All-or-nothing, fail-closed.** ANY validation error anywhere in the remediation section
    rejects the ENTIRE table (no partial acceptance): a non-mapping body, an
    absent/malformed/oversized ``remediations`` section, a non-string/empty category key, a
    non-list category, an empty/oversized step list, or a step that is not an object / carries an
    unknown field / has a missing-or-oversized ``description`` / an invalid ``runbook`` / an
    invalid ``escalateSeverity`` (wrong type or not an allowed severity). Every value is
    type-checked BEFORE any set-membership test or sort, and the whole parse is wrapped so no
    exception can escape (⇒ fail closed with a surfaced note). An ABSENT ``remediations`` key is
    not an error (a routing-only Ops pack) and yields ``(None, [])``.
    """
    try:
        return _parse_remediation_table(pack_id, pack_version, body)
    except Exception as exc:  # never let a malformed pack raise — fail closed
        return None, [
            f"ops pack {pack_id}: remediations rejected — unparseable "
            f"({type(exc).__name__}) — fail-closed"
        ]


def _parse_remediation_table(
    pack_id: str, pack_version: str, body: object
) -> tuple[RemediationTable | None, list[str]]:
    """Inner parser (see :func:`parse_remediation_table`); any error ⇒ ``(None, [note])``."""
    if not isinstance(body, Mapping):
        return None, [f"ops pack {pack_id}: body is not an object — remediations rejected"]
    raw = body.get("remediations")
    if raw is None:
        return None, []  # no remediation content in this pack — not an error
    if not isinstance(raw, Mapping):
        return None, [
            f"ops pack {pack_id}: 'remediations' is not an object — rejected (fail-closed)"
        ]
    if not raw or len(raw) > MAX_CATEGORIES:
        return None, [
            f"ops pack {pack_id}: 'remediations' has {len(raw)} categories "
            f"(expected 1..{MAX_CATEGORIES}) — rejected (fail-closed)"
        ]

    table: dict[str, tuple[RemediationStep, ...]] = {}
    for category, raw_steps in raw.items():
        if not isinstance(category, str) or not category.strip():
            return None, [
                f"ops pack {pack_id}: non-string/empty category key {category!r} — "
                "whole table rejected (fail-closed)"
            ]
        if not _is_valid_category_key(category):
            return None, [
                f"ops pack {pack_id}: category key {category!r} violates the allowed "
                f"pattern/length (<= {MAX_CATEGORY_KEY_LEN} chars) — "
                "whole table rejected (fail-closed)"
            ]
        steps, note = _parse_category(pack_id, category, raw_steps)
        if note is not None:
            # All-or-nothing: ANY invalid category rejects the ENTIRE table (never a partial guess).
            return None, [note]
        assert steps is not None
        table[category] = steps
    return RemediationTable(
        pack_id=pack_id, pack_version=pack_version, steps_by_category=table
    ), []


def _parse_category(
    pack_id: str, category: str, raw_steps: object
) -> tuple[tuple[RemediationStep, ...] | None, str | None]:
    """Parse one category's step list. Returns ``(steps, None)`` or ``(None, note)`` fail-closed."""
    if not isinstance(raw_steps, list):
        return None, (
            f"ops pack {pack_id}: category {category!r} is not a list — "
            "whole table rejected (fail-closed)"
        )
    if not raw_steps or len(raw_steps) > MAX_STEPS_PER_CATEGORY:
        return None, (
            f"ops pack {pack_id}: category {category!r} has {len(raw_steps)} steps "
            f"(expected 1..{MAX_STEPS_PER_CATEGORY}) — whole table rejected (fail-closed)"
        )
    steps: list[RemediationStep] = []
    for index, raw_step in enumerate(raw_steps):
        step, note = _parse_step(pack_id, category, index, raw_step)
        if note is not None:
            return None, note
        assert step is not None
        steps.append(step)
    return tuple(steps), None


def _parse_step(
    pack_id: str, category: str, index: int, raw_step: object
) -> tuple[RemediationStep | None, str | None]:
    """Validate one advisory step. Returns ``(step, None)`` or ``(None, note)`` fail-closed.

    Every value is type-checked before use so a malformed value (e.g. an array-valued
    ``escalateSeverity``) can never raise at a set-membership test or sort — it fails closed.
    """
    prefix = f"ops pack {pack_id}: category {category!r} step {index}"
    suffix = "whole table rejected (fail-closed)"
    if not isinstance(raw_step, Mapping):
        return None, f"{prefix} is not an object — {suffix}"
    unknown = {str(k) for k in raw_step} - {"description", "runbook", "escalateSeverity"}
    if unknown:
        return None, f"{prefix} has unknown field(s) {sorted(unknown)} — {suffix}"
    description = raw_step.get("description")
    if not isinstance(description, str) or not description.strip():
        return None, f"{prefix} has a missing/empty description — {suffix}"
    if len(description) > MAX_DESCRIPTION_LEN:
        return None, f"{prefix} description exceeds {MAX_DESCRIPTION_LEN} chars — {suffix}"
    runbook = raw_step.get("runbook")
    if runbook is not None and (not isinstance(runbook, str) or len(runbook) > MAX_RUNBOOK_LEN):
        return None, f"{prefix} has an invalid/oversized runbook — {suffix}"
    escalate = raw_step.get("escalateSeverity")
    # Type-check BEFORE the set-membership test: an unhashable value (e.g. a list) would otherwise
    # raise TypeError at ``in`` — reject it fail-closed instead.
    if escalate is not None and (
        not isinstance(escalate, str) or escalate not in _VALID_SEVERITIES
    ):
        return None, f"{prefix} has an invalid escalateSeverity {escalate!r} — {suffix}"
    return (
        RemediationStep(
            description=description.strip(),
            runbook=runbook,
            escalate_severity=escalate,
        ),
        None,
    )


def _match_steps(
    category: str, tables: Sequence[RemediationTable]
) -> list[tuple[RemediationStep, RemediationTable]]:
    """Resolve ``category`` to ordered ``(step, source table)`` pairs across all tables.

    Exact category wins; only if NO table carries the exact category do we fall back to the
    documented catch-alls (``*`` then ``default``). Deterministic: tables are ordered by
    ``(pack_id, pack_version)``, steps keep their authored order.
    """
    ordered = sorted(tables, key=lambda t: (t.pack_id, t.pack_version))
    exact: list[tuple[RemediationStep, RemediationTable]] = []
    for table in ordered:
        for step in table.steps_by_category.get(category, ()):
            exact.append((step, table))
    if exact:
        return exact
    for key in CATCH_ALL_KEYS:
        catch: list[tuple[RemediationStep, RemediationTable]] = []
        for table in ordered:
            for step in table.steps_by_category.get(key, ()):
                catch.append((step, table))
        if catch:
            return catch
    return []


def propose_remediation(
    rca: AgentResponse,
    *,
    root_cause_category: str | None,
    tables: Sequence[RemediationTable],
) -> AgentResponse:
    """Enrich a confidence-gated RCA with advisory Ops-pack remediation, or advise support.

    Pure and advisory only. Fail-closed: if ``rca.confidence`` is below
    :data:`~modules.aiops.rca.RCA_CONFIDENCE_FLOOR`, if ``root_cause_category`` is ``None``, or if
    no verified table matches the category (exact or catch-all), the returned response's
    ``nextActions`` is the explicit :data:`CALL_SUPPORT_ACTION` and NO remediation step is emitted.
    Only when confidence >= floor AND a matching table exists do we return its advisory steps as
    ``recommendations``/``nextActions``, each citing its source pack id + version in
    ``sourceReferences``.
    """
    if rca.confidence < RCA_CONFIDENCE_FLOOR or not root_cause_category:
        return _support_response(rca, reason="rca-below-floor-or-no-category")

    matched = _match_steps(root_cause_category, tables)
    if not matched:
        return _support_response(rca, reason=f"no-remediation-for-category:{root_cause_category}")

    # PII-free: the guided-remediation advisory text we EMIT is sourced from Ops-pack content ONLY.
    # We never copy RCA's own recommendation strings (which carry the root resource id) into these
    # fields — the resource id stays solely in ``sourceReferences`` provenance (as RCA emitted it).
    recommendations: list[str] = []
    next_actions: list[str] = []
    citations: list[SourceReference] = []
    seen_citation: set[tuple[str, str]] = set()
    for step, table in matched:
        recommendations.append(_advisory_line(step, table))
        next_actions.append(step.description)
        key = (table.pack_id, table.pack_version)
        if key not in seen_citation:
            seen_citation.add(key)
            citations.append(
                SourceReference(
                    kind="pack", id=table.pack_id, detail=f"version {table.pack_version}"
                )
            )

    return rca.model_copy(
        update={
            "taskType": "guided-remediation",
            "inputSummary": _GUIDED_INPUT_SUMMARY,
            # PII-free: a count, not the id-bearing RCA risk text ("... explained by <node>").
            "risks": [
                f"{len(matched)} advisory remediation step(s) proposed from Ops pack content"
            ],
            "recommendations": recommendations,
            "sourceReferences": _dedup_refs([*rca.sourceReferences, *citations]),
            "nextActions": next_actions,
        }
    )


def _advisory_line(step: RemediationStep, table: RemediationTable) -> str:
    """Render one advisory recommendation line with its pack provenance (advisory text only)."""
    line = f"Advisory ({table.pack_id}@{table.pack_version}): {step.description}"
    if step.escalate_severity:
        line += f" [escalate/call support at severity >= {step.escalate_severity}]"
    if step.runbook:
        line += f" (runbook: {step.runbook})"
    return line


def _support_response(rca: AgentResponse, *, reason: str) -> AgentResponse:
    """Fail-closed: keep the RCA surfaced but assert no remediation — advise contacting support.

    All emitted free text is PII-free: we do NOT copy RCA's own ``recommendations``/
    ``inputSummary``/``risks`` (which carry the root resource id) into the guided-remediation
    response. The affected entity is retained solely in ``sourceReferences`` (as RCA emitted it).
    """
    recommendations = [
        "No verified advisory remediation available (fail-closed: "
        f"{reason}) — contact support."
    ]
    return rca.model_copy(
        update={
            "taskType": "guided-remediation",
            "inputSummary": _GUIDED_INPUT_SUMMARY,
            "risks": [],
            "recommendations": recommendations,
            "nextActions": [CALL_SUPPORT_ACTION],
        }
    )


def _dedup_refs(refs: Sequence[SourceReference]) -> list[SourceReference]:
    seen: set[tuple[str, str, str | None]] = set()
    out: list[SourceReference] = []
    for ref in refs:
        key = (ref.kind, ref.id, ref.detail)
        if key in seen:
            continue
        seen.add(key)
        out.append(ref)
    return out


__all__ = [
    "CALL_SUPPORT_ACTION",
    "CATCH_ALL_KEYS",
    "MAX_CATEGORIES",
    "MAX_DESCRIPTION_LEN",
    "MAX_RUNBOOK_LEN",
    "MAX_STEPS_PER_CATEGORY",
    "RemediationStep",
    "RemediationTable",
    "extract_root_cause_node_id",
    "node_category",
    "parse_remediation_table",
    "propose_remediation",
]
