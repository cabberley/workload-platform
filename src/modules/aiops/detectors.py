"""Compile a VERIFIED telemetry pack body into pure detector callables (issue #51).

Content-over-code: a telemetry pack can declare, alongside today's single-sample threshold
signals, **windowed** detectors (a pure aggregation over recent samples of a ``(metric, node)``)
and an optional safe boolean **expression**. This module turns such a pack body into a list of
pure :class:`Detector` callables *at load time*, validating everything up front and **failing
closed**: an unknown aggregate, a malformed window, an unsafe/invalid expression, a non-role
selector or a non-finite constant means that detector is **not** compiled and the reason is
SURFACED as a note — never silently skipped, never fabricated.

Guardrails honoured here:

* **Pure ⟂ I/O.** Detectors are pure functions of ``(signals, estate)``; no network, no Azure, no
  new connector call. They run over the in-memory ``Signal`` stream the AIOps run already fetched.
* **Reuse, don't fork.** Threshold signals compile to a detector that delegates to
  :func:`modules.aiops.module.fuse_detections` (which itself reuses ``detect_metric_breach``), so
  the existing single-sample behavior is byte-for-byte preserved. Base-field validation reuses
  ``_parse_signal_rule``/``TelemetryRuleSpec``; the expression sandbox is the shared, audited
  :mod:`shared.safe_expr`.
* **Provenance.** Every emitted ``Finding`` cites its pack (id + version) and the observation(s)
  via ``SourceReference``.
* **Signed-packs-only.** This module only ever receives a body from a pack the engine already
  VERIFIED — compilation is downstream of the trust gate and never bypasses it.

## Window grammar (declarative, pure)

A signal MAY carry a ``window`` object:

    window := { <selector>, "aggregate"?: <agg>, "mode"?: <mode> }
    selector := "samples": <int >= 1>        # the most-recent N samples of (metric, node)
              | "durationSeconds": <number > 0>   # samples within D seconds of the latest sample
    agg  := avg | max | min | count | sum | last | rate   (default: avg)
    mode := aggregate | all | any                          (default: aggregate)

* ``aggregate`` mode: reduce the selected samples with ``agg`` to one scalar, breach if
  ``op(scalar, threshold)``.
* ``all`` / ``any`` mode: breach if ``op(sample, threshold)`` holds for every / some selected
  sample.
* ``rate`` = ``(last.value - first.value) / (last.ts - first.ts)`` in seconds; undefined (no
  detection) for a single sample or a zero/negative time span.

An empty or short window yields **no** detection (surfaced by absence).

## Expression detectors

A signal MAY carry a safe boolean ``expression`` (see :mod:`shared.safe_expr`). When present it
REPLACES the ``op``/``threshold`` check. It is evaluated once per ``(metric, node)`` over the
window aggregates, with ``value`` bound to the window's primary aggregate (``window.aggregate``,
default ``avg``) and ``threshold`` bound to the signal's threshold. A signal with an expression but
no window uses a default one-sample window. A division-by-zero / type error / missing name at
evaluation time yields no detection (fail-closed), never a crash.
"""
from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Literal

from modules.aiops.connectors.system_pulse import Signal
from modules.aiops.module import (
    TelemetryRuleSpec,  # noqa: F401 - re-validated indirectly via _parse_signal_rule
    _encode_id_component,
    _parse_signal_rule,
    _role_nodes,
    fuse_detections,
)
from shared.contracts import Finding, ResourceNode, Severity, SourceReference
from shared.safe_expr import (
    TELEMETRY_EXPR_NAMES,
    SafeExpression,
    UnsafeExpressionError,
    compile_expression,
)

DetectorKind = Literal["threshold", "window", "expression"]

# Aggregates a window may expose / select. Mirrors ``shared.safe_expr.TELEMETRY_EXPR_NAMES`` minus
# the ``value``/``threshold`` rule bindings.
AGGREGATES: frozenset[str] = frozenset({"avg", "max", "min", "count", "sum", "last", "rate"})

_WINDOW_MODES: frozenset[str] = frozenset({"aggregate", "all", "any"})

# Sentinel distinguishing a genuinely ABSENT ``window`` key (may default) from an explicit
# ``"window": null`` / malformed value (must fail closed). ``dict.get(key, _ABSENT)`` returns this
# only when the key is missing; an explicit null returns ``None`` and is rejected + surfaced.
_ABSENT: Any = object()

# Bound a time-based window so building a ``timedelta`` at evaluation can never overflow. ~31 years
# of seconds — far beyond any real telemetry window, safely below ``timedelta``'s ceiling.
MAX_WINDOW_SECONDS = 1e9

# Evaluate a detector over the observed signals + estate → findings. Pure.
DetectorFn = Callable[[list[Signal], list[ResourceNode]], list[Finding]]


@dataclass(frozen=True)
class Detector:
    """A pure, compiled detector. Callable as ``detector(signals, estate) -> list[Finding]``."""

    kind: DetectorKind
    name: str  # the metric this detector observes
    role: str
    pack_id: str
    pack_version: str
    evaluate: DetectorFn

    def __call__(self, signals: list[Signal], estate: list[ResourceNode]) -> list[Finding]:
        return self.evaluate(signals, estate)


def classify_signal(raw: Any) -> DetectorKind:
    """Route a raw signal to a detector kind by shape (fail-safe default: ``threshold``).

    ``expression`` takes precedence over ``window`` (an expression may reference window aggregates),
    then ``window``; anything else — including a non-mapping entry — is a plain threshold signal and
    stays on the legacy single-sample path.
    """
    if not isinstance(raw, dict):
        return "threshold"
    if "expression" in raw:
        return "expression"
    if "window" in raw:
        return "window"
    return "threshold"


def compile_detectors(
    body: object,
    pack_id: str,
    pack_version: str,
    *,
    kinds: frozenset[str] | set[str] | None = None,
) -> tuple[list[Detector], list[str]]:
    """Compile a verified telemetry pack ``body`` into pure detectors. Returns ``(detectors,
    notes)``.

    Every signal is validated up front; a malformed/unsafe signal is NOT compiled and the reason is
    appended to ``notes`` (fail-closed). ``kinds`` optionally restricts which detector kinds are
    compiled (and which signals are noted) — the AIOps run compiles only ``{"window",
    "expression"}`` here, sourcing threshold detections from the cross-pack collective fuse to
    preserve multi-pack collision-merge; ``kinds=None`` compiles everything (the complete API).
    """
    detectors: list[Detector] = []
    notes: list[str] = []
    if not isinstance(body, dict):
        notes.append(f"pack {pack_id}: body is not an object — no detectors compiled")
        return detectors, notes
    signals = body.get("signals")
    if not isinstance(signals, list):
        notes.append(
            f"pack {pack_id}: 'signals' is absent or not a list — no detectors compiled"
        )
        return detectors, notes
    for raw in signals:
        kind = classify_signal(raw)
        if kinds is not None and kind not in kinds:
            continue
        detector, note = _compile_one(raw, kind, pack_id, pack_version)
        if note is not None:
            notes.append(note)
        if detector is not None:
            detectors.append(detector)
    return detectors, notes


def _compile_one(
    raw: Any, kind: DetectorKind, pack_id: str, pack_version: str
) -> tuple[Detector | None, str | None]:
    """Validate + compile one signal. Fail-closed: returns ``(None, note)`` on any problem."""
    rule, note = _parse_signal_rule(raw, pack_id, pack_version)
    if rule is None:
        return None, note
    if kind == "threshold":
        return _threshold_detector(rule), None

    # window / expression share the same base rule; validate the extra declarations.
    # Distinguish an absent ``window`` key (may default) from an explicit null/malformed value.
    raw_window = raw.get("window", _ABSENT) if isinstance(raw, dict) else _ABSENT
    window_spec, werr = _normalize_window(raw_window, kind)
    if window_spec is None:
        return None, f"pack {pack_id}: signal {rule['name']!r}: {werr} — skipped"

    expr_obj: SafeExpression | None = None
    if kind == "expression":
        source = raw.get("expression") if isinstance(raw, dict) else None
        try:
            expr_obj = compile_expression(
                source,  # type: ignore[arg-type]
                allowed_names=TELEMETRY_EXPR_NAMES,
            )
        except UnsafeExpressionError as exc:
            return None, (
                f"pack {pack_id}: signal {rule['name']!r}: unsafe/invalid expression "
                f"({exc}) — skipped"
            )

    def _evaluate(signals: list[Signal], estate: list[ResourceNode]) -> list[Finding]:
        return _evaluate_windowed(kind, rule, window_spec, expr_obj, signals, estate)

    return (
        Detector(
            kind=kind,
            name=rule["name"],
            role=rule["role"],
            pack_id=pack_id,
            pack_version=pack_version,
            evaluate=_evaluate,
        ),
        None,
    )


def _threshold_detector(rule: dict[str, Any]) -> Detector:
    """A threshold detector that DELEGATES to ``fuse_detections`` (no logic duplicated)."""

    def _evaluate(signals: list[Signal], estate: list[ResourceNode]) -> list[Finding]:
        return fuse_detections([rule], signals, estate)

    return Detector(
        kind="threshold",
        name=rule["name"],
        role=rule["role"],
        pack_id=str(rule.get("packId") or ""),
        pack_version=str(rule.get("packVersion") or ""),
        evaluate=_evaluate,
    )


# --------------------------------------------------------------------------------------
# Window declaration → normalized spec (pure validation)
# --------------------------------------------------------------------------------------
def _normalize_window(
    window: Any, kind: DetectorKind
) -> tuple[dict[str, Any] | None, str | None]:
    """Validate a ``window`` declaration into a normalized spec, or ``(None, error)``.

    ``window`` is ``_ABSENT`` only when the key is genuinely missing: an ``expression`` signal then
    defaults to a one-sample window (so a bare expression over ``value``/``threshold`` still works),
    while a ``window`` signal reports that a window is required. An explicit ``"window": null`` (or
    any non-object value) is NOT defaulted — it is rejected and surfaced (fail-closed), matching the
    schema which types ``window`` as an object.
    """
    if window is _ABSENT:
        if kind == "expression":
            return {"selector": ("samples", 1), "aggregate": "avg", "mode": "aggregate"}, None
        return None, "window is required"
    if not isinstance(window, dict):
        return None, "window must be an object"

    has_samples = "samples" in window
    has_duration = "durationSeconds" in window
    if has_samples == has_duration:
        return None, "window must set exactly one of 'samples' or 'durationSeconds'"

    if has_samples:
        n = window["samples"]
        if isinstance(n, bool) or not isinstance(n, int) or n < 1:
            return None, "window.samples must be an integer >= 1"
        selector: tuple[str, float] = ("samples", n)
    else:
        d = window["durationSeconds"]
        if isinstance(d, bool) or not isinstance(d, (int, float)):
            return None, "window.durationSeconds must be a number"
        if not math.isfinite(float(d)) or float(d) <= 0:
            return None, "window.durationSeconds must be a finite number > 0"
        if float(d) > MAX_WINDOW_SECONDS:
            return None, f"window.durationSeconds must be <= {MAX_WINDOW_SECONDS:g}"
        selector = ("durationSeconds", float(d))

    aggregate = window.get("aggregate", "avg")
    if not isinstance(aggregate, str) or aggregate not in AGGREGATES:
        return None, f"window.aggregate {aggregate!r} is not an allowed aggregate"
    mode = window.get("mode", "aggregate")
    if not isinstance(mode, str) or mode not in _WINDOW_MODES:
        return None, f"window.mode {mode!r} is not an allowed mode"
    return {"selector": selector, "aggregate": aggregate, "mode": mode}, None


# --------------------------------------------------------------------------------------
# Pure window evaluation
# --------------------------------------------------------------------------------------
def select_window_samples(samples: list[Signal], selector: tuple[str, float]) -> list[Signal]:
    """Select the in-window samples from ``samples`` (assumed ascending by timestamp). Pure.

    For a ``samples: N`` selector the window must be **full**: fewer than ``N`` samples available
    yields an empty selection (no detection) rather than an early/partial fire — a ``samples: 5,
    mode: all`` sustained-condition detector must never trip on a single breaching sample.
    """
    if not samples:
        return []
    kind, value = selector
    if kind == "samples":
        n = int(value)
        if len(samples) < n:
            return []  # insufficient samples — window not yet full, no detection
        return samples[-n:]
    latest = samples[-1].timestamp
    cutoff = latest - timedelta(seconds=float(value))
    return [s for s in samples if s.timestamp >= cutoff]


def compute_aggregates(selected: list[Signal]) -> dict[str, float] | None:
    """Compute the exposed aggregates over ``selected`` values, or ``None`` when the window is
    untrustworthy (empty, a non-finite sample present, or an aggregation overflows).

    Non-finite telemetry is treated as undecidable: if any selected sample value is non-finite, or
    if summing overflows to ``inf`` (e.g. ``[1e308, 1e308]``), the whole window yields ``None`` so
    no mode (``aggregate``/``all``/``any``) can fabricate a detection and nothing ever crashes.
    ``rate`` is only present with >= 2 samples over a positive span; any individually non-finite
    aggregate is dropped so a downstream comparison/expression simply sees a missing name.
    """
    if not selected:
        return None
    values = [s.value for s in selected]
    if any(not (isinstance(v, (int, float)) and math.isfinite(v)) for v in values):
        return None  # non-finite sample (inf/nan) ⇒ undecidable, never drives a breach
    try:
        total = math.fsum(values)
    except (OverflowError, ValueError):
        return None
    if not math.isfinite(total):
        return None  # aggregation overflowed (e.g. 1e308 + 1e308) ⇒ undecidable
    aggregates: dict[str, float] = {
        "avg": total / len(values),
        "max": max(values),
        "min": min(values),
        "sum": total,
        "count": float(len(values)),
        "last": selected[-1].value,
    }
    if len(selected) >= 2:
        span = (selected[-1].timestamp - selected[0].timestamp).total_seconds()
        if span > 0:
            aggregates["rate"] = (selected[-1].value - selected[0].value) / span
    return {name: v for name, v in aggregates.items() if math.isfinite(v)}


def _op(op: str, left: float, right: float) -> bool:
    return left > right if op == "gt" else left < right


def _group_by_node(
    metric: str, role: str, signals: list[Signal], estate: list[ResourceNode]
) -> dict[str, list[Signal]]:
    """Group ``metric`` signals onto the canonical estate node ids selected by ``role``. Pure."""
    nodes = _role_nodes(estate).get(role, [])
    if not nodes:
        return {}
    canonical = {node.id.casefold(): node.id for node in nodes}
    grouped: dict[str, list[Signal]] = defaultdict(list)
    for signal in signals:
        if signal.metric != metric:
            continue
        node_id = canonical.get(signal.resourceId.casefold())
        if node_id is None:
            continue
        grouped[node_id].append(signal)
    for node_signals in grouped.values():
        # Total-order sort (timestamp, resourceId, value) so equal-timestamp/­resource samples are
        # ordered deterministically — ``last``/``rate``/count selection is then input-order-free.
        node_signals.sort(key=lambda s: (s.timestamp, s.resourceId, s.value))
    return dict(grouped)


def _evaluate_windowed(
    kind: DetectorKind,
    rule: dict[str, Any],
    window_spec: dict[str, Any],
    expr_obj: SafeExpression | None,
    signals: list[Signal],
    estate: list[ResourceNode],
) -> list[Finding]:
    """Evaluate a window/expression detector over the observed signals. Pure, order-free output."""
    findings: list[Finding] = []
    grouped = _group_by_node(rule["name"], rule["role"], signals, estate)
    for node_id, node_signals in grouped.items():
        try:
            selected = select_window_samples(node_signals, window_spec["selector"])
            aggregates = compute_aggregates(selected)
            if aggregates is None:
                continue
            result = _decide(kind, rule, window_spec, expr_obj, selected, aggregates)
        except (ValueError, OverflowError, TypeError, ZeroDivisionError):
            # Fail-closed: malformed/pathological telemetry never crashes a run — no detection.
            continue
        if result is None:
            continue
        findings.append(_build_finding(kind, rule, node_id, result))
    findings.sort(key=lambda f: f.id)
    return findings


def _decide(
    kind: DetectorKind,
    rule: dict[str, Any],
    window_spec: dict[str, Any],
    expr_obj: SafeExpression | None,
    selected: list[Signal],
    aggregates: dict[str, float],
) -> str | None:
    """Return an evidence summary string if the window breaches, else ``None`` (no detection)."""
    metric = rule["name"]
    threshold = float(rule["threshold"])
    window_desc = _window_desc(window_spec["selector"], len(selected))
    primary = window_spec["aggregate"]

    if kind == "expression" and expr_obj is not None:
        value = aggregates.get(primary, aggregates.get("last"))
        if value is None:
            return None
        env: dict[str, float] = dict(aggregates)
        env["value"] = value
        env["threshold"] = threshold
        if expr_obj.evaluate(env) is not True:
            return None
        shown = ", ".join(f"{k}={aggregates[k]:.6g}" for k in sorted(aggregates))
        return f"expression[{expr_obj.source}] true over {window_desc}; {shown}"

    mode = window_spec["mode"]
    op = rule["op"]
    if mode == "aggregate":
        if primary not in aggregates:
            return None
        agg_val = aggregates[primary]
        if not _op(op, agg_val, threshold):
            return None
        return f"{primary}({metric})={agg_val:.6g} {op} {threshold:.6g} over {window_desc}"
    if mode == "all":
        if not all(_op(op, s.value, threshold) for s in selected):
            return None
        return f"all {len(selected)} samples of {metric} {op} {threshold:.6g} over {window_desc}"
    # any
    if not any(_op(op, s.value, threshold) for s in selected):
        return None
    return f"a sample of {metric} {op} {threshold:.6g} over {window_desc}"


def _window_desc(selector: tuple[str, float], selected_count: int) -> str:
    kind, value = selector
    if kind == "samples":
        return f"last {int(value)} sample(s) (n={selected_count})"
    return f"last {value:g}s (n={selected_count})"


def _build_finding(
    kind: DetectorKind, rule: dict[str, Any], node_id: str, summary: str
) -> Finding:
    """Build a provenance-bearing ``Finding`` in a kind-namespaced id space (no threshold clash)."""
    tag = "win" if kind == "window" else "expr"
    label = "window" if kind == "window" else "expression"
    pack_id = str(rule.get("packId") or "")
    pack_version = str(rule.get("packVersion") or "")
    evidence = [SourceReference(kind="metric", id=rule["name"], detail=summary)]
    if pack_id:
        evidence.append(
            SourceReference(kind="pack", id=pack_id, detail=f"version {pack_version}")
        )
    return Finding(
        id=f"detect::{tag}::{_encode_id_component(rule['name'])}::"
        f"{_encode_id_component(node_id)}",
        module="aiops",
        title=f"Telemetry {label} breach: {rule['name']}",
        passed=False,
        severity=Severity(rule["severity"]),
        nodeId=node_id,
        evidence=evidence,
        packId=pack_id or None,
        packVersion=pack_version or None,
        detail=f"Proactive detection from telemetry pack {label} detector.",
    )


__all__ = [
    "AGGREGATES",
    "Detector",
    "DetectorFn",
    "DetectorKind",
    "classify_signal",
    "compile_detectors",
    "compute_aggregates",
    "select_window_samples",
]
