"""Quality Checks module — run versioned Rule Packs against the estate.

Applies **Rule Packs** (WAF / WARA / APRL / app-specific) to discovered nodes and emits
PASS/FAIL `Finding`s with evidence and provenance (pack id + version). Runs as an ACA **Job**
that fans out 0→30 — one replica per workload/rule batch — so large estates finish fast.
"""
from __future__ import annotations

from typing import Any, Protocol, cast

from pydantic import BaseModel, ConfigDict, ValidationError

from shared.contracts import (
    AgentResponse,
    Finding,
    ModuleKind,
    ModuleManifest,
    ModuleRunResult,
    PackType,
    ResourceNode,
    ScaleProfile,
    ScaleTrigger,
    Severity,
    SourceReference,
)
from shared.module_base import Module, ModuleContext

_MANIFEST = ModuleManifest(
    name="quality_checks",
    displayName="Quality Checks",
    kind=ModuleKind.job,
    consumes=[PackType.rule],
    produces=["Finding[]"],
    scaleProfile=ScaleProfile(
        kind=ModuleKind.job,
        minReplicas=0,
        maxReplicas=30,
        triggers=[ScaleTrigger(type="azure-queue", metadata={"queueName": "assessments"})],
        cpu=0.5,
        memoryGi=1.0,
    ),
)


class _PackManifestLike(Protocol):
    """Structural view of the fields a Rule Pack manifest must expose for provenance."""

    id: str
    version: str


class _RulePackLike(Protocol):
    """Structural view of a verified pack: a manifest for provenance + a rules body."""

    @property
    def manifest(self) -> _PackManifestLike: ...

    @property
    def body(self) -> dict[str, Any]: ...


class _PacksEngineLike(Protocol):
    """The narrow slice of the packs engine this module depends on (the trust gate).

    ``load_for_workload`` verifies each pack's hash/signature **before** returning it (fail-closed)
    and filters by ``PackManifest.targets`` so a workload is only assessed against packs that
    target it. Casting ``ctx.packs`` to this local Protocol keeps ``shared`` decoupled from
    ``packs_engine`` — the same DI seam used for edge clients.
    """

    def load_for_workload(
        self, workload: str, pack_type: PackType
    ) -> list[_RulePackLike]: ...


# The predicates this module knows how to evaluate. A rule that applies to a node's type but
# declares none of these is *unevaluable* and must fail closed (never a silent PASS).
_SUPPORTED_PREDICATES: tuple[str, ...] = ("requiredTag",)


def _coerce_severity(value: Any) -> tuple[Severity, bool]:
    """Coerce an untrusted severity value to a ``Severity``. Returns ``(severity, invalid)``.

    Fail-closed and total: a non-scalar shape (list/dict/number/bool), or a string that is not a
    recognized ``Severity``, defaults to ``medium`` and flags ``invalid=True`` so callers can
    surface it. An absent value (``None``) is the normal default and is **not** flagged invalid.
    Never raises — the membership/enum check is guarded against unhashable and wrong-typed input.
    """
    if value is None:
        return Severity.medium, False
    if isinstance(value, str):
        try:
            return Severity(value), False
        except (ValueError, TypeError):
            return Severity.medium, True
    return Severity.medium, True  # non-scalar (list/dict/number/bool) → invalid, surfaced


class RuleSpec(BaseModel):
    """Typed, defensively-validated shape of a single rule from a Rule Pack body.

    Unknown keys are ignored (forward-compatible with richer packs). Structural validation here
    means malformed rules are surfaced and skipped rather than crashing the run (fail-closed).
    """

    model_config = ConfigDict(extra="ignore")

    id: str = "rule"
    title: str | None = None
    resourceType: str | None = None
    requiredTag: str | None = None
    severity: Severity = Severity.medium
    description: str = ""
    packId: str | None = None
    packVersion: str | None = None


def evaluate_rule(node: ResourceNode, rule: dict[str, Any]) -> Finding | None:
    """Pure rule evaluation for one node/rule. Returns a Finding or None if not applicable.

    A rule targets a resource type and asserts a supported predicate (currently ``requiredTag``).
    Fail-closed in two ways:
      * if the rule applies but the required evidence is missing → FAIL (not a silent pass);
      * if the rule applies but declares **no recognized/supported predicate** → FAIL (surfaced,
        never silently passed) — an unevaluable rule must not report success.

    Never raises on malformed content: a non-scalar or unrecognized ``severity`` is coerced to
    ``medium``.

    TODO(human): richer, property/resource-graph-based rule predicates (e.g. SKU tier,
    diagnostic settings, private-endpoint presence) beyond simple tag presence. Add them to
    ``_SUPPORTED_PREDICATES`` and keep the logic pure and content-driven — new predicates are
    declared in the Rule Pack body, not branched into Python here.
    """
    resource_type = rule.get("resourceType")
    if resource_type and resource_type != node.type:
        return None  # not applicable to this node's type
    rule_severity, _invalid = _coerce_severity(rule.get("severity"))
    description = rule.get("description") or ""
    predicate = next((p for p in _SUPPORTED_PREDICATES if rule.get(p) is not None), None)
    if predicate == "requiredTag":
        passed = node.tags.get(rule["requiredTag"]) is not None
        detail = description
        severity = Severity.info if passed else rule_severity
    else:
        # Applies to this resource type but declares no recognized predicate → fail closed.
        passed = False
        detail = "unsupported/unevaluable rule predicate — surfaced, not passed"
        if description:
            detail = f"{detail}; {description}"
        severity = rule_severity
    return Finding(
        id=f"{rule.get('id', 'rule')}::{node.id}",
        module="quality_checks",
        title=rule.get("title") or rule.get("id") or "rule",
        passed=passed,
        severity=severity,
        nodeId=node.id,
        evidence=[SourceReference(kind="resource", id=node.id, detail=detail)],
        packId=rule.get("packId"),
        packVersion=rule.get("packVersion"),
        detail=detail,
    )


def _normalize_rule(
    raw: Any, pack_id: str, pack_version: str
) -> tuple[dict[str, Any] | None, str | None]:
    """Validate one raw rule entry into a stamped dict. Returns ``(rule, note)``.

    Non-mapping entries and structurally-invalid rules are skipped with a surfaced note. An
    unrecognized ``severity`` is coerced to ``medium`` (with a note) rather than dropping the rule.
    """
    if not isinstance(raw, dict):
        return None, f"pack {pack_id}: non-mapping rule entry skipped"
    data: dict[str, Any] = dict(raw)
    data["packId"] = pack_id
    data["packVersion"] = pack_version
    note: str | None = None
    sev = data.get("severity")
    rule_severity, invalid = _coerce_severity(sev)
    if invalid:
        rule_id = data.get("id", "?")
        note = f"pack {pack_id}: rule {rule_id} invalid severity {sev!r} — defaulted to medium"
    data["severity"] = rule_severity.value
    try:
        spec = RuleSpec.model_validate(data)
    except ValidationError as exc:
        rule_id = data.get("id", "?")
        return None, (
            f"pack {pack_id}: rule {rule_id} failed validation "
            f"({exc.error_count()}) — skipped"
        )
    return spec.model_dump(), note


def load_rules(packs: object | None, workload: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Load target-aware Rule Packs for ``workload`` and return ``(rules, notes)``.

    Only packs whose ``manifest.targets`` include ``workload`` (or that target everything) are
    loaded, so e.g. an epic-only pack never runs against a sap estate. Each rule is stamped with
    its source ``packId``/``packVersion`` so every emitted ``Finding`` cites the exact content that
    produced it (guardrail: provenance on every finding). Malformed bodies/rules are skipped and
    surfaced in ``notes`` — never raised (fail-closed).

    TODO(human): the packs engine's ``load_for_workload`` is the signature trust gate and verifies
    hash/signature before returning packs. If signature verification is ever made optional at that
    layer, re-verify each pack's signature here **before** executing its rules (fail-closed — never
    run unverified content).
    """
    if packs is None:
        return [], []
    engine = cast(_PacksEngineLike, packs)
    rules: list[dict[str, Any]] = []
    notes: list[str] = []
    loaded = list(engine.load_for_workload(workload, PackType.rule))
    # SHIPPED rule ids are AUTHORITATIVE over IMPORTED rule ids (the rule-granularity analog of the
    # shipped-wins-by-pack-id / shipped-wins-per-key model). A Finding id is ``{rule_id}::{node}`` —
    # NOT namespaced by pack — and findings persist last-wins on ``(workload, finding_id)``, so a
    # NEW-pack-id imported rule that REUSES a shipped rule id would overwrite (and could suppress a
    # FAIL from) the shipped rule's finding. We resolve in TWO passes by provenance: SHIPPED packs
    # first (build the authoritative rule-id set), IMPORTED packs second (skip any rule whose id
    # collides with a shipped rule id, surfacing a note). Provenance is read defensively from
    # ``pack.imported`` (default False = shipped = authoritative); the engine sets ``imported=True``
    # on every store-resolved pack (engine.py). Imports may ADD new rule ids, not suppress shipped.
    shipped_rule_ids: set[str] = set()

    def _normalize_pack_rules(pack: _RulePackLike) -> list[dict[str, Any]]:
        body = pack.body
        raw_rules = body.get("rules") if isinstance(body, dict) else None
        if not isinstance(raw_rules, list):
            if isinstance(body, dict) and "rules" in body:
                notes.append(f"pack {pack.manifest.id}: 'rules' is not a list — skipped")
            return []
        out: list[dict[str, Any]] = []
        for raw in raw_rules:
            rule, note = _normalize_rule(raw, pack.manifest.id, pack.manifest.version)
            if note is not None:
                notes.append(note)
            if rule is not None:
                out.append(rule)
        return out

    # First pass — SHIPPED packs (order-preserving); their rule ids become authoritative.
    for pack in loaded:
        if getattr(pack, "imported", False):
            continue
        for rule in _normalize_pack_rules(pack):
            rules.append(rule)
            shipped_rule_ids.add(str(rule.get("id", "rule")))
    # Second pass — IMPORTED packs may ADD new rule ids but NEVER shadow a shipped rule id.
    for pack in loaded:
        if not getattr(pack, "imported", False):
            continue
        for rule in _normalize_pack_rules(pack):
            rule_id = str(rule.get("id", "rule"))
            if rule_id in shipped_rule_ids:
                notes.append(
                    f"pack {pack.manifest.id}: imported rule {rule_id!r} shadows shipped rule id "
                    "— skipped (shipped wins)"
                )
                continue
            rules.append(rule)
    return rules, notes


def _target_workloads(ctx: ModuleContext, scope: dict[str, str]) -> list[str]:
    """Resolve the workloads to assess: an explicit scope wins, else every known workload.

    Fail-closed: with no readable state we assess nothing rather than guessing.
    """
    if scope.get("workload"):
        return [scope["workload"]]
    if ctx.state is None:
        return []
    return ctx.state.list_workloads()


class QualityChecksModule(Module):
    @property
    def manifest(self) -> ModuleManifest:
        return _MANIFEST

    def run(self, ctx: ModuleContext, *, scope: dict[str, str] | None = None) -> ModuleRunResult:
        scope = scope or {}
        workloads = _target_workloads(ctx, scope)
        findings: list[Finding] = []
        notes: list[str] = []
        pack_refs: dict[tuple[str | None, str | None], SourceReference] = {}
        checked = 0
        for workload in workloads:
            if ctx.state is None:
                continue  # fail-closed: no readable estate → assess nothing
            rules, rule_notes = load_rules(ctx.packs, workload)
            notes.extend(rule_notes)
            _collect_pack_sources(rules, pack_refs)
            for node in ctx.state.get_estate(workload):
                for rule in rules:
                    f = evaluate_rule(node, rule)
                    if f is None:
                        continue  # rule not applicable to this node type
                    checked += 1
                    findings.append(f)
        failed = [f for f in findings if f.passed is False]
        summary = [f"{checked} checks, {len(failed)} failed"]
        if notes:
            summary.append(f"{len(notes)} rule(s) surfaced (unsupported/invalid)")
        response = AgentResponse(
            agentName="quality_checks",
            taskType="run-rule-packs",
            inputSummary=(
                f"scope={scope or 'all'}; workloads={len(workloads)}; "
                f"packs={len(pack_refs)}; checks={checked}"
            ),
            findings=summary,
            risks=[f.title for f in failed],
            sourceReferences=list(pack_refs.values()),
            confidence=1.0,
            nextActions=["route-findings"] if failed else [],
        )
        return ModuleRunResult(
            module=self.name, ok=True, findings=findings, response=response,
            extra={"surfacedNotes": notes},
        )


def _collect_pack_sources(
    rules: list[dict[str, Any]],
    into: dict[tuple[str | None, str | None], SourceReference],
) -> None:
    """Accumulate a distinct ``SourceReference`` per Rule Pack (id@version) into ``into``."""
    for rule in rules:
        key = (rule.get("packId"), rule.get("packVersion"))
        if key[0] is None or key in into:
            continue
        into[key] = SourceReference(kind="pack", id=str(key[0]), detail=f"version {key[1]}")


__all__ = ["QualityChecksModule", "evaluate_rule", "load_rules"]
