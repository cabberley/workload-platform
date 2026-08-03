"""AIOps module — fuse telemetry, detect proactively, auto-RCA, and *advise* remediation.

Always-on ACA **service** (1→20). Consumes **Telemetry Packs** to know what to watch and how to
detect (metric thresholds + AI log analysis). On a detection it correlates against the dependency
graph to localize root cause and produces an advisory remediation recommendation — **never**
auto-applied (fail-closed; humans dispose). Escalates to "call support" when confidence is low.
"""
from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any, Literal, Protocol, cast

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from modules.aiops.connectors.azure_monitor import to_signals as azure_monitor_to_signals
from modules.aiops.connectors.system_pulse import FetchResult, Signal
from modules.aiops.connectors.system_pulse import to_signals as system_pulse_to_signals
from modules.aiops.rca import (
    RCA_CONFIDENCE_FLOOR,
    correlate_rca,
    correlate_root_cause,
)
from modules.aiops.remediation import (
    RemediationTable,
    extract_root_cause_node_id,
    node_category,
    parse_remediation_table,
    propose_remediation,
)
from shared.blast_radius import blast_radius
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
    WorkloadGraph,
)
from shared.module_base import Module, ModuleContext
from shared.state import ReadableState

_MANIFEST = ModuleManifest(
    name="aiops",
    displayName="AIOps (System Pulse + Azure Monitor)",
    kind=ModuleKind.service,
    consumes=[PackType.telemetry],
    produces=["detections", "rca", "Finding[]"],
    scaleProfile=ScaleProfile(
        kind=ModuleKind.service,
        minReplicas=1,
        maxReplicas=20,
        triggers=[
            ScaleTrigger(type="azure-queue", metadata={"queueName": "telemetry"}),
            ScaleTrigger(type="cpu", metadata={"type": "Utilization", "value": "70"}),
        ],
        cpu=1.0,
        memoryGi=2.0,
    ),
)

# ``RCA_CONFIDENCE_FLOOR`` and the correlation logic live in ``modules.aiops.rca`` (issue #50) and
# are imported above; re-exported here so the module's public RCA surface is unchanged.


def _encode_id_component(text: object) -> str:
    """Percent-encode ``%`` and ``:`` in one finding-id component so it can never contain the ``::``
    delimiter. This keeps the detection-id namespaces provably disjoint regardless of metric/node
    content: a legacy id (``detect::<metric>::<node>``) always has exactly two structural ``::``
    (three components) while a windowed/expression id (``detect::win::…`` / ``detect::expr::…``)
    always has three — so a metric literally named ``win::cpu`` cannot collide with a windowed
    ``cpu``. Components without ``%``/``:`` (the common case) are returned unchanged, so existing
    ids stay byte-for-byte identical."""
    return str(text).replace("%", "%25").replace(":", "%3A")


def detect_metric_breach(signal: dict) -> Finding | None:
    """Pure threshold detection for one telemetry signal.

    signal = {name, value, op ('gt'|'lt'), threshold, nodeId, severity}
    Fail-closed: a malformed signal returns None (surfaced upstream), never a silent pass.
    """
    required = {"name", "value", "op", "threshold"}
    if not required.issubset(signal):
        return None
    op = signal["op"]
    threshold = signal["threshold"]
    value = signal["value"]
    breached = value > threshold if op == "gt" else value < threshold
    if not breached:
        return None
    return Finding(
        id=f"detect::{_encode_id_component(signal['name'])}::"
        f"{_encode_id_component(signal.get('nodeId', 'na'))}",
        module="aiops",
        title=f"Telemetry breach: {signal['name']}",
        passed=False,
        severity=Severity(signal.get("severity", "high")),
        nodeId=signal.get("nodeId"),
        evidence=[SourceReference(kind="metric", id=signal["name"],
                                  detail=f"{signal['value']} {op} {signal['threshold']}")],
        detail="Proactive detection from telemetry pack threshold.",
    )


# Well-known telemetry source keys in the edge-client registry (``ctx.clients``). Each present
# source yields ``Signal``-shaped observations; an absent/unavailable source is surfaced, never
# fabricated over. Adding a source is a registry-key + adapter change, not a contract change.
_WELL_KNOWN_SOURCES: tuple[str, ...] = ("system_pulse", "azure_monitor")

_ROLE_SELECTOR_PREFIX = "role:"


class _PackManifestLike(Protocol):
    """Structural view of the pack manifest fields we need for provenance."""

    id: str
    version: str


class _TelemetryPackLike(Protocol):
    """Structural view of a verified telemetry pack: manifest (provenance) + a signals body."""

    @property
    def manifest(self) -> _PackManifestLike: ...

    @property
    def body(self) -> dict[str, Any]: ...


class _PacksEngineLike(Protocol):
    """The narrow slice of the packs engine this module depends on (the signature trust gate).

    ``load_for_workload`` verifies each pack's hash/signature **before** returning it (fail-closed)
    and filters by ``PackManifest.targets`` so an epic telemetry pack never runs against a sap
    workload. Casting ``ctx.packs`` to this local Protocol keeps ``shared`` decoupled.
    """

    def load_for_workload(
        self, workload: str, pack_type: PackType
    ) -> list[_TelemetryPackLike]: ...


class _SignalFetcher(Protocol):
    """Structural view of a telemetry edge client: one read-only, fail-closed fetch method.

    Both :class:`SystemPulseClient` and :class:`AzureMonitorClient` satisfy this shape and return
    the shared :class:`FetchResult`, so the module treats every source uniformly.
    """

    def fetch_raw(self, *, metric_names: Sequence[str] | None = None) -> FetchResult: ...


class TelemetryRuleSpec(BaseModel):
    """Typed, defensively-validated shape of one detection rule from a Telemetry Pack body.

    Structural validation here means a malformed pack signal (bad ``op``, non-numeric
    ``threshold``, invalid ``severity``, non-scalar shape) is surfaced and skipped rather than
    crashing the run or silently passing (fail-closed). Unknown keys are ignored (forward-compat).
    """

    model_config = ConfigDict(extra="ignore")

    name: str
    op: Literal["gt", "lt"]
    threshold: float
    severity: Severity
    nodeId: str

    @field_validator("name", "nodeId", mode="before")
    @classmethod
    def _must_be_str(cls, value: Any) -> Any:
        if not isinstance(value, str):
            raise ValueError("must be a string")
        return value

    @field_validator("threshold", mode="before")
    @classmethod
    def _must_be_numeric(cls, value: Any) -> Any:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("threshold must be a non-bool number")
        # Reject NaN / ±inf: a non-finite threshold cannot define a meaningful breach and would
        # otherwise fabricate detections (e.g. value < +inf is always true) — fail closed.
        if not math.isfinite(float(value)):
            raise ValueError("threshold must be finite")
        return value


def _role_from_selector(selector: str) -> str | None:
    """Resolve a ``role:<name>`` selector to a lowercased role, or ``None`` if not a role selector.

    Telemetry pack ``nodeId`` values are role selectors (like dependency packs). We re-derive this
    tiny resolver locally rather than importing another module (module isolation).
    """
    if not selector.startswith(_ROLE_SELECTOR_PREFIX):
        return None
    role = selector[len(_ROLE_SELECTOR_PREFIX):].strip().lower()
    return role or None


def _parse_signal_rule(
    raw: Any, pack_id: str, pack_version: str
) -> tuple[dict[str, Any] | None, str | None]:
    """Validate one raw pack signal into a stamped detection rule. Returns ``(rule, note)``.

    Fail-closed: non-mapping entries, structurally-invalid signals, and non-role selectors are
    skipped with a surfaced note — never raised, never silently passed.
    """
    if not isinstance(raw, dict):
        return None, f"pack {pack_id}: non-mapping signal entry skipped"
    try:
        spec = TelemetryRuleSpec.model_validate(raw)
    except ValidationError as exc:
        sig_id = raw.get("name", "?")
        return None, (
            f"pack {pack_id}: signal {sig_id!r} failed validation "
            f"({exc.error_count()}) — skipped"
        )
    role = _role_from_selector(spec.nodeId)
    if role is None:
        return None, (
            f"pack {pack_id}: signal {spec.name!r} has non-role selector "
            f"{spec.nodeId!r} — skipped"
        )
    rule = {
        "name": spec.name,
        "op": spec.op,
        "threshold": spec.threshold,
        "severity": spec.severity.value,
        "role": role,
        "packId": pack_id,
        "packVersion": pack_version,
    }
    return rule, None


def load_telemetry_rules(
    packs: object | None, workload: str
) -> tuple[list[dict[str, Any]], list[str]]:
    """Load target-aware Telemetry Packs for ``workload`` and return ``(rules, notes)``.

    Only packs whose ``manifest.targets`` include ``workload`` are loaded (the engine filters), so
    an epic telemetry pack never detects against a sap estate. Each rule keeps its ``packId`` /
    ``packVersion`` provenance. Malformed bodies/signals are skipped and surfaced — never raised.

    Signals that declare a ``window`` or ``expression`` are NOT threshold rules: they are routed to
    the compiled-detector path (:func:`load_windowed_detectors`) and skipped here (no note — they
    are re-homed, not malformed), so a single-sample threshold never double-fires a windowed one.
    """
    if packs is None:
        return [], []
    engine = cast(_PacksEngineLike, packs)
    rules: list[dict[str, Any]] = []
    notes: list[str] = []
    for pack in engine.load_for_workload(workload, PackType.telemetry):
        body = pack.body
        if not isinstance(body, dict):
            notes.append(f"pack {pack.manifest.id}: body is not an object — skipped")
            continue
        raw_signals = body.get("signals")
        if not isinstance(raw_signals, list):
            notes.append(
                f"pack {pack.manifest.id}: 'signals' is absent or not a list — skipped"
            )
            continue
        for raw in raw_signals:
            if _is_windowed_signal(raw):
                continue  # handled by the compiled-detector path, not the threshold path
            rule, note = _parse_signal_rule(raw, pack.manifest.id, pack.manifest.version)
            if note is not None:
                notes.append(note)
            if rule is not None:
                rules.append(rule)
    return rules, notes


def _is_windowed_signal(raw: Any) -> bool:
    """True if a raw signal declares a ``window`` or ``expression`` (compiled-detector path).

    Mirrors ``modules.aiops.detectors.classify_signal`` without importing it at module load time
    (that module imports this one). Kept trivial and in-sync by the shared unit tests.
    """
    return isinstance(raw, dict) and ("window" in raw or "expression" in raw)


def load_windowed_detectors(
    packs: object | None, workload: str
) -> tuple[list[Any], list[str]]:
    """Compile target-aware windowed/expression detectors for ``workload``. Returns ``(detectors,
    notes)``.

    Delegates to the pure :func:`modules.aiops.detectors.compile_detectors` (imported lazily to
    avoid an import cycle) restricted to the ``window``/``expression`` kinds — the threshold kind
    stays on the cross-pack collective fuse in :func:`load_telemetry_rules`/``fuse_detections`` so
    multi-pack collision-merge is byte-for-byte preserved. Malformed/unsafe detectors are surfaced,
    never silently skipped.
    """
    if packs is None:
        return [], []
    from modules.aiops.detectors import compile_detectors

    engine = cast(_PacksEngineLike, packs)
    detectors: list[Any] = []
    notes: list[str] = []
    for pack in engine.load_for_workload(workload, PackType.telemetry):
        pack_detectors, pack_notes = compile_detectors(
            pack.body,
            pack.manifest.id,
            pack.manifest.version,
            kinds={"window", "expression"},
        )
        detectors.extend(pack_detectors)
        notes.extend(pack_notes)
    return detectors, notes


def run_windowed_detectors(
    detectors: list[Any], signals: list[Signal], estate: list[ResourceNode]
) -> list[Finding]:
    """Run compiled window/expression detectors over the observed signals; dedup by id. Pure.

    Detectors emit kind-namespaced ids (``detect::win::`` / ``detect::expr::``) that never clash
    with threshold ids, but two packs can define the same windowed signal on the same node. We emit
    exactly one deterministic finding per id (highest severity, then pack provenance) while citing
    every contributing pack — no provenance lost, output order-free.
    """
    by_id: dict[str, list[Finding]] = defaultdict(list)
    for detector in detectors:
        for finding in detector(signals, estate):
            by_id[finding.id].append(finding)
    merged = [_merge_windowed(group) for group in by_id.values()]
    merged.sort(key=lambda f: f.id)
    return merged


def _merge_windowed(group: list[Finding]) -> Finding:
    """Pick the deterministic winner for one id and union the contributing pack references."""
    winner = sorted(
        group,
        key=lambda f: (
            -_severity_rank(f.severity.value),
            str(f.packId or ""),
            str(f.packVersion or ""),
        ),
    )[0]
    if len(group) == 1:
        return winner
    pack_refs = {
        (str(f.packId or ""), str(f.packVersion or ""))
        for f in group
        if f.packId
    }
    existing = {(ref.kind, ref.id, ref.detail) for ref in winner.evidence}
    for pack_id, version in sorted(pack_refs):
        ref = SourceReference(kind="pack", id=pack_id, detail=f"version {version}")
        if (ref.kind, ref.id, ref.detail) not in existing:
            winner.evidence.append(ref)
    return winner


def _collect_detector_pack_sources(
    detectors: list[Any],
    into: dict[tuple[str | None, str | None], SourceReference],
) -> None:
    """Accumulate a distinct ``SourceReference`` per detector's Telemetry Pack (id@version)."""
    for detector in detectors:
        key = (detector.pack_id, detector.pack_version)
        if not detector.pack_id or key in into:
            continue
        into[key] = SourceReference(
            kind="pack", id=str(detector.pack_id), detail=f"version {detector.pack_version}"
        )


def _fetch_source_signals(
    key: str, client: object, metric_names: Sequence[str]
) -> tuple[bool, list[Signal]]:
    """Fetch ``Signal``-shaped observations from one well-known edge client. Fail-closed.

    Returns ``(available, signals)``. A source that is unavailable (or unknown) yields
    ``(False, [])`` so the caller can surface it in ``sourcesUnavailable`` without fabricating data.
    """
    fetcher = cast(_SignalFetcher, client)
    result = fetcher.fetch_raw(metric_names=list(metric_names) or None)
    if not result.available:
        return False, []
    if key == "system_pulse":
        return True, system_pulse_to_signals(result)
    if key == "azure_monitor":
        return True, azure_monitor_to_signals(result)
    return False, []


def _observe_signals(
    clients: Mapping[str, object], metric_names: Sequence[str]
) -> tuple[list[Signal], set[str], set[str]]:
    """Collect observations from every well-known telemetry source present in ``clients``.

    Returns ``(signals, available, unavailable)`` where ``available`` is the set of well-known
    source keys that were present and returned data, and ``unavailable`` is the set that were
    absent or returned unavailable — both surfaced upstream, never silently conflated.
    """
    signals: list[Signal] = []
    available: set[str] = set()
    unavailable: set[str] = set()
    for key in _WELL_KNOWN_SOURCES:
        client = clients.get(key)
        if client is None:
            unavailable.add(key)
            continue
        is_available, source_signals = _fetch_source_signals(key, client, metric_names)
        if not is_available:
            unavailable.add(key)
            continue
        available.add(key)
        signals.extend(source_signals)
    return signals, available, unavailable


def _role_nodes(estate: list[ResourceNode]) -> dict[str, list[ResourceNode]]:
    """Map a lowercased ``role`` to the estate nodes carrying it (selector resolution)."""
    index: dict[str, list[ResourceNode]] = defaultdict(list)
    for node in estate:
        if node.role:
            index[node.role.lower()].append(node)
    return index


def fuse_detections(
    rules: list[dict[str, Any]],
    signals: list[Signal],
    estate: list[ResourceNode],
) -> list[Finding]:
    """Fuse pack **rules** × observed **signals** into detection findings — pure and **order-free**.

    For each rule, resolve its ``role:`` selector to estate nodes; for each observed signal whose
    ``metric`` matches the rule and whose ``resourceId`` maps (case-insensitively — Azure resource
    ids are case-insensitive) to a selected estate node, run the pure ``detect_metric_breach`` with
    the rule's threshold and the node's **canonical** id. Thresholds stay pack-driven, observations
    stay edge-driven; malformed inputs yield no fabricated detection.

    Collision merge (fully order-independent): several rules/packs and/or several observations can
    breach the same ``(metric, node)``; they would all produce the same ``detect::<metric>::<node>``
    id and clobber each other. We emit exactly ONE deterministic detection per ``(metric, node)``:

      * **winning rule** = highest severity, then most-conservative threshold, stable
        ``(packId, packVersion)`` tie-break;
      * **cited observation** = the most-extreme breach of the winning rule (max exceedance beyond
        threshold for ``gt``, min value below threshold for ``lt``), tie-broken by earliest
        observation timestamp, then highest value, then ``resourceId`` — so the SAME observation is
        cited regardless of the order signals arrive in;
      * **every** contributing pack is cited in the finding's evidence (no provenance lost).

    The returned list is sorted by finding id (``detect::<metric>::<node>``) so the output order is
    independent of rule/signal input order.
    """
    role_nodes = _role_nodes(estate)
    by_metric: dict[str, list[Signal]] = defaultdict(list)
    for signal in signals:
        by_metric[signal.metric].append(signal)

    # Group breaching (rule, signal) candidates by (metric name, canonical estate node id).
    groups: dict[tuple[str, str], list[tuple[dict[str, Any], Signal]]] = defaultdict(list)
    for rule in rules:
        nodes = role_nodes.get(rule["role"], [])
        if not nodes:
            continue
        canonical = {node.id.casefold(): node.id for node in nodes}
        for signal in by_metric.get(rule["name"], ()):
            node_id = canonical.get(signal.resourceId.casefold())
            if node_id is None:
                continue
            if detect_metric_breach(_breach_input(rule, signal, node_id)) is None:
                continue
            groups[(rule["name"], node_id)].append((rule, signal))

    detections = [
        _merge_candidates(node_id, candidates) for (_metric, node_id), candidates in groups.items()
    ]
    detections.sort(key=lambda finding: finding.id)
    return detections


def _breach_input(rule: dict[str, Any], signal: Signal, node_id: str) -> dict[str, Any]:
    """Build the ``detect_metric_breach`` input for one rule × observation on a canonical node."""
    return {
        "name": rule["name"],
        "value": signal.value,
        "op": rule["op"],
        "threshold": rule["threshold"],
        "nodeId": node_id,  # canonical estate id, not the raw signal casing
        "severity": rule["severity"],
    }


_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.info,
    Severity.low,
    Severity.medium,
    Severity.high,
    Severity.critical,
)


def _severity_rank(value: str) -> int:
    """Rank a severity string; unknown values sort lowest (fail-closed, never crashes)."""
    try:
        return _SEVERITY_ORDER.index(Severity(value))
    except (ValueError, TypeError):
        return -1


def _conservativeness(rule: dict[str, Any]) -> float:
    """How eagerly a rule trips: for ``gt`` a lower threshold is more conservative, for ``lt`` a
    higher one is. Higher return value ⇒ more conservative ⇒ preferred winner."""
    threshold = float(rule["threshold"])
    return -threshold if rule["op"] == "gt" else threshold


def _winner_rule(rules: list[dict[str, Any]]) -> dict[str, Any]:
    """Pick the deterministic winning rule.

    Priority (highest first): severity, then most-conservative threshold, then pack provenance
    ``(packId, packVersion)``. Those keep the semantics. The final keys ``(op, threshold, name)``
    form a total order over the rule identity so two rules can never compare equal unless they are
    truly identical — this breaks the residual tie between e.g. same-pack ``gt 0`` and ``lt 0``
    rules whose severity and conservativeness scores coincide, making the winner input-order-free.
    """
    best = max((_severity_rank(r["severity"]), _conservativeness(r)) for r in rules)
    tied = [r for r in rules if (_severity_rank(r["severity"]), _conservativeness(r)) == best]
    tied.sort(
        key=lambda r: (
            str(r.get("packId") or ""),
            str(r.get("packVersion") or ""),
            str(r["op"]),
            float(r["threshold"]),
            str(r["name"]),
        )
    )
    return tied[0]


def _cited_observation(rule: dict[str, Any], signals: list[Signal]) -> Signal:
    """Pick the deterministic observation to cite: the most-extreme breach of ``rule``.

    Exceedance = ``value - threshold`` for ``gt`` and ``threshold - value`` for ``lt`` (larger ⇒
    more extreme). Ties break by earliest observation timestamp, then highest value, then
    ``resourceId`` — so the same observation is always cited regardless of input order.
    """
    threshold = float(rule["threshold"])
    op = rule["op"]

    def exceedance(signal: Signal) -> float:
        return signal.value - threshold if op == "gt" else threshold - signal.value

    most_extreme = max(exceedance(signal) for signal in signals)
    tied = [signal for signal in signals if exceedance(signal) == most_extreme]
    tied.sort(key=lambda signal: (signal.timestamp, -signal.value, signal.resourceId))
    return tied[0]


def _merge_candidates(
    node_id: str, candidates: list[tuple[dict[str, Any], Signal]]
) -> Finding:
    """Merge same-``(metric, node)`` breaching candidates into one deterministic detection.

    Deterministic in both the winning rule and the cited observation (see :func:`fuse_detections`),
    so the emitted finding — including its evidence value — is identical under any input order.
    Every contributing pack is cited in the finding's evidence (provenance is never lost).
    """
    distinct_rules: list[dict[str, Any]] = []
    seen: set[int] = set()
    for rule, _signal in candidates:
        if id(rule) not in seen:
            seen.add(id(rule))
            distinct_rules.append(rule)
    winner_rule = _winner_rule(distinct_rules)
    # Observations that breach the winning rule specifically (non-empty by construction).
    winner_signals = [signal for rule, signal in candidates if rule is winner_rule]
    cited = _cited_observation(winner_rule, winner_signals)

    finding = detect_metric_breach(_breach_input(winner_rule, cited, node_id))
    assert finding is not None  # `cited` breaches `winner_rule` by construction

    contributing = sorted(
        {
            (str(rule.get("packId") or ""), str(rule.get("packVersion") or ""))
            for rule, _signal in candidates
        }
    )
    pack_refs = [
        SourceReference(kind="pack", id=pack_id, detail=f"version {version}")
        for pack_id, version in contributing
        if pack_id
    ]
    # Carry connector provenance (MED 6): now that signals can come from >1 connector, cite which
    # connector(s) supplied the observations so an operator can trace a finding back to its source.
    # Deterministic / order-free: distinct source ids, sorted. The cited observation's source is
    # listed first (as the primary evidence), followed by any other contributing sources.
    cited_source = str(cited.source)
    contributing_sources = sorted({str(signal.source) for _rule, signal in candidates})
    ordered_sources = [cited_source] + [s for s in contributing_sources if s != cited_source]
    connector_refs = [
        SourceReference(
            kind="connector",
            id=source_id,
            detail=(
                "cited observation source" if source_id == cited_source else "observation source"
            ),
        )
        for source_id in ordered_sources
    ]
    finding.evidence = list(finding.evidence) + pack_refs + connector_refs
    finding.packId = winner_rule["packId"]
    finding.packVersion = winner_rule["packVersion"]
    if len(contributing) > 1:
        finding.detail = (
            f"{finding.detail} Merged from {len(contributing)} telemetry packs; "
            f"highest-severity rule wins, all sources cited."
        )
    return finding


def _blast_radius_map(graph: WorkloadGraph | None) -> dict[str, int]:
    """Blast radius per node id for RCA. ``None`` graph ⇒ empty map ⇒ low-confidence path."""
    if graph is None:
        return {}
    return {node.id: blast_radius(graph, node.id) for node in graph.nodes}


def _collect_pack_sources(
    rules: list[dict[str, Any]],
    into: dict[tuple[str | None, str | None], SourceReference],
) -> None:
    """Accumulate a distinct ``SourceReference`` per Telemetry Pack (id@version) into ``into``."""
    for rule in rules:
        key = (rule.get("packId"), rule.get("packVersion"))
        if key[0] is None or key in into:
            continue
        into[key] = SourceReference(kind="pack", id=str(key[0]), detail=f"version {key[1]}")


def _resolve_workloads(state: ReadableState | None, scope: dict[str, str]) -> list[str]:
    """Resolve the workload(s) to inspect: an explicit ``scope['workload']`` wins, else every known
    workload. Fail-closed to ``[]`` when there is no readable state (guardrail 4)."""
    if scoped := scope.get("workload"):
        return [scoped]
    if state is None:
        return []
    return list(state.list_workloads())


class _OpsPackLike(Protocol):
    """Structural view of a verified Ops pack: manifest (provenance) + a body with remediations."""

    @property
    def manifest(self) -> _PackManifestLike: ...

    @property
    def body(self) -> dict[str, Any]: ...


class _OpsPacksEngineLike(Protocol):
    """The narrow packs-engine slice for loading verified Ops packs (same trust gate as telemetry).

    ``load_for_workload`` verifies each pack's hash/signature **before** returning it (fail-closed)
    and filters by ``PackManifest.targets``. We load Ops packs the same verified way the Alerts
    module does WITHOUT importing that module (module isolation).
    """

    def load_for_workload(self, workload: str, pack_type: PackType) -> list[_OpsPackLike]: ...


def load_ops_remediations(
    packs: object | None, workload: str
) -> tuple[list[RemediationTable], list[str]]:
    """Load verified **Ops Packs** for ``workload`` and parse their advisory ``remediations``.

    Fail-closed (guardrail 4): if the packs engine is absent, or an Ops pack fails verification, we
    return no tables (⇒ the pure lookup advises support) and surface a note — we never act on an
    unverified pack. Malformed/oversized remediation sections are rejected by the pure parser and
    surfaced, never silently accepted. Advisory only — nothing here mutates infrastructure.
    """
    if packs is None:
        return [], []
    source = cast(_OpsPacksEngineLike, packs)
    try:
        loaded = source.load_for_workload(workload, PackType.ops)
    except Exception:  # unverifiable/unavailable Ops packs -> fail closed, no remediation
        return [], [
            f"{workload}: Ops pack(s) failed verification — no remediation, advise support "
            "(fail-closed)"
        ]
    tables: list[RemediationTable] = []
    notes: list[str] = []
    for pack in loaded:
        table, pack_notes = parse_remediation_table(
            pack.manifest.id, pack.manifest.version, pack.body
        )
        notes.extend(pack_notes)
        if table is not None:
            tables.append(table)
    return tables, notes


def enrich_rca_with_remediation(
    rca: AgentResponse,
    graph: WorkloadGraph | None,
    tables: list[RemediationTable],
) -> AgentResponse:
    """Attach advisory Ops-pack remediation to an RCA, resolving root-cause category at the edge.

    The category is derived from the RCA's asserted root-cause node (its classified Discovery
    ``role``, via :func:`node_category`); the confidence/verification/no-match gates live in the
    pure :func:`propose_remediation`. Below the floor RCA asserts no root cause ⇒ no node ⇒ support.
    """
    node_id = extract_root_cause_node_id(rca)
    node = None
    if node_id and graph is not None:
        node = next((n for n in graph.nodes if n.id == node_id), None)
    category = node_category(node)
    return propose_remediation(rca, root_cause_category=category, tables=tables)


class AiopsModule(Module):
    @property
    def manifest(self) -> ModuleManifest:
        return _MANIFEST

    def run(self, ctx: ModuleContext, *, scope: dict[str, str] | None = None) -> ModuleRunResult:
        scope = scope or {}
        state = ctx.state
        workloads = _resolve_workloads(state, scope)

        detections: list[Finding] = []
        rca_responses: list[AgentResponse] = []
        notes: list[str] = []
        sources_available: set[str] = set()
        sources_unavailable: set[str] = set()
        sources_observed = False
        pack_sources: dict[tuple[str | None, str | None], SourceReference] = {}

        if state is None:
            notes.append("state unavailable — no workloads resolved (fail-closed)")

        for workload in workloads:
            if state is None:
                continue  # fail-closed: no readable estate/graph → detect nothing
            if ctx.packs is None:
                notes.append(f"{workload}: packs engine unavailable — skipped")
                continue

            rules, rule_notes = load_telemetry_rules(ctx.packs, workload)
            notes.extend(rule_notes)
            _collect_pack_sources(rules, pack_sources)
            # Windowed/expression detectors (issue #51) compile at load time (fail-closed) and run
            # over the SAME signal stream, feeding the SAME detection -> RCA path as thresholds.
            windowed_detectors, detector_notes = load_windowed_detectors(ctx.packs, workload)
            notes.extend(detector_notes)
            _collect_detector_pack_sources(windowed_detectors, pack_sources)
            if not rules and not windowed_detectors:
                continue  # no telemetry detection content for this workload

            # Fetch every metric named by a threshold rule OR a compiled detector, so a windowed
            # detector over a metric no threshold watches still gets its observations.
            metric_names = sorted(
                {str(rule["name"]) for rule in rules}
                | {str(det.name) for det in windowed_detectors}
            )
            signals, available, unavailable = _observe_signals(ctx.clients, metric_names)
            sources_observed = True
            sources_available.update(available)
            sources_unavailable.update(unavailable)
            if not signals:
                notes.append(f"{workload}: no telemetry observed from any source")
                continue

            estate = state.get_estate(workload)
            # Threshold path (unchanged, cross-pack collision-merge) + compiled windowed/expression
            # detectors, combined into one order-free detection set for correlation.
            workload_detections = fuse_detections(rules, signals, estate)
            workload_detections.extend(
                run_windowed_detectors(windowed_detectors, signals, estate)
            )
            workload_detections.sort(key=lambda finding: finding.id)
            graph = state.get_graph(workload)
            blast_of = _blast_radius_map(graph)
            for finding in workload_detections:
                if finding.nodeId is not None:
                    finding.blastRadius = blast_of.get(finding.nodeId, 0)
            # Graph-wide, multi-detection correlation (issue #50): one correlated RCA per workload's
            # active detection set. Single-finding sets preserve the original single-node semantics.
            if workload_detections:
                rca = correlate_root_cause(workload_detections, graph)
                # Advisory-only remediation (issue #52): enrich the confidence-gated RCA with steps
                # sourced from verified Ops packs, or advise "call support" (fail-closed). Pack
                # loading/verification stays at this edge; the mapping is pure. NO infra-mutation.
                # TODO(human): remediation Ops packs MUST be signature-enforced once the Key Vault
                # signing key is provisioned (#37/#44). load_ops_remediations already uses the same
                # verified load_for_workload path as Alerts and fails closed the moment a verifier/
                # secret is configured; today the default runtime PacksEngine has no verifier, so
                # local unsigned packs still load (the tracked pre-existing signing gap, out of
                # scope for #52 — do NOT force enforcement here or CI/dev/packs_studio break).
                ops_tables, ops_notes = load_ops_remediations(ctx.packs, workload)
                notes.extend(ops_notes)
                rca = enrich_rca_with_remediation(rca, graph, ops_tables)
                rca_responses.append(rca)
            detections.extend(workload_detections)

        # Accurate accounting (partial outages preserved): ``sourcesAvailable`` = sources that
        # returned data for at least one observed workload; ``sourcesUnavailable`` = sources absent
        # or that failed for at least one observed workload — we do NOT subtract available, so a
        # source that succeeded for one workload and failed for another stays visible in both.
        # ``sourcesPartial`` = the intersection: succeeded somewhere AND failed somewhere, so an
        # operator can act on an intermittent/partial outage. If nothing was observed at all (no
        # state/packs/rules) every well-known source is reported unavailable.
        if not sources_observed:
            sources_unavailable = set(_WELL_KNOWN_SOURCES)
        sources_partial = sources_available & sources_unavailable
        response = AgentResponse(
            agentName="aiops",
            taskType="proactive-detect",
            inputSummary=(
                f"scope={scope or 'all'}; workloads={len(workloads)}; "
                f"sources={len(sources_available)}; detections={len(detections)}"
            ),
            findings=[f"{len(detections)} detection(s)"],
            risks=[f.title for f in detections],
            # Advisory only: detections are routed to auto-RCA; a human disposes remediation.
            recommendations=["route detections to auto-rca"] if detections else [],
            sourceReferences=list(pack_sources.values()),
            confidence=1.0,
            nextActions=["auto-rca"] if detections else [],
        )
        extra: dict[str, Any] = {
            "rca": [r.model_dump(mode="json") for r in rca_responses],
            "surfacedNotes": notes,
            "sourcesAvailable": sorted(sources_available),
            "sourcesUnavailable": sorted(sources_unavailable),
            "sourcesPartial": sorted(sources_partial),
            "packSources": [ref.model_dump(mode="json") for ref in pack_sources.values()],
        }
        return ModuleRunResult(
            module=self.name, ok=True, findings=detections, response=response, extra=extra
        )


__all__ = [
    "AiopsModule",
    "RCA_CONFIDENCE_FLOOR",
    "correlate_rca",
    "correlate_root_cause",
    "detect_metric_breach",
    "enrich_rca_with_remediation",
    "fuse_detections",
    "load_ops_remediations",
    "load_telemetry_rules",
    "load_windowed_detectors",
    "propose_remediation",
    "run_windowed_detectors",
]
