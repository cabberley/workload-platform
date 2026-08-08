"""Pure statistical log-anomaly scoring (issue #53, deliverable 2).

Given a BASELINE (prior windows' :class:`shared.contracts.LogFeatures`) and the CURRENT window's
features, score anomalies with ROBUST statistics — median + MAD (scaled) or EWMA + z-score — and
emit ADVISORY :class:`shared.contracts.Finding`s. Deterministic; no ML training, no external call,
no I/O.

Guardrails honoured here (advisory only, fail-closed, provenance, content-over-code):

* **Robust + deterministic.** Median+MAD (``mad``) or EWMA mean/variance (``ewma``) z-scores — no
  fitting, no randomness. The SAME baseline/current always yields the SAME findings.
* **Confidence floor.** :data:`LOG_ANOMALY_CONFIDENCE_FLOOR` mirrors
  :data:`modules.aiops.rca.RCA_CONFIDENCE_FLOOR`. A deviation that only reaches the *advisory* band
  (below the assertion threshold), or a baseline whose robust scale is degenerate (all-equal), is
  NOT asserted — it is SURFACED with an "advise contacting support" note, never a finding.
* **Short/empty baseline ⇒ no detection.** Fewer than the pack's ``minBaseline`` usable prior
  windows yields NO finding for that feature (fail-closed by absence) — never a fabricated one.
* **Provenance.** Every emitted finding cites its telemetry pack (id + version) and the observation
  window via ``SourceReference`` (kinds ``pack`` + ``log``), so it feeds the auto-RCA path with
  full evidence.
* **Content-over-code.** WHICH features to watch and the z-score→severity bands come from the
  VERIFIED telemetry pack body (:func:`compile_log_anomaly_specs`), never a hard-coded Python
  threshold. Field mapping (how a record is shaped) stays a connector/deployment concern.

The scorer emits only aggregate, statistical strings (feature name, z-score, median/current values,
confidence) — never a raw log body, message, id, or PII (those never reach this layer; it consumes
only :class:`LogFeatures`).
"""
from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from modules.aiops.rca import RCA_CONFIDENCE_FLOOR
from shared.contracts import Finding, LogFeatures, Severity, SourceReference

# Confidence below which we do NOT assert a log anomaly — we surface + advise contacting support.
# Mirrors the RCA floor (issue #50) so the two advisory gates stay aligned.
LOG_ANOMALY_CONFIDENCE_FLOOR = RCA_CONFIDENCE_FLOOR

# MAD → standard-deviation consistency constant for a normal distribution.
_MAD_SCALE = 1.4826

# Default EWMA smoothing factor and the fraction of the entry (assertion) z that marks the lower
# "advisory" band, used when the pack does not specify them explicitly.
_DEFAULT_EWMA_ALPHA = 0.3
_DEFAULT_ADVISORY_FRACTION = 0.75

# Confidence ceiling — a statistical detection never claims certainty (advisory only).
_CONFIDENCE_CEILING = 0.99

AnomalyMethod = Literal["mad", "ewma"]
AnomalyDirection = Literal["up", "down", "both"]

# The watchable, PII-free NUMERIC scalar features of ``LogFeatures``. A pack anomaly spec may only
# reference a key in this allowlist; anything else is surfaced + skipped (fail-closed). Percentile
# accessors return ``None`` when no duration field was present, so a window without durations simply
# contributes no usable sample for those features.
FEATURE_ACCESSORS: dict[str, Callable[[LogFeatures], float | None]] = {
    "totalCount": lambda f: float(f.totalCount),
    "errorRate": lambda f: f.errorRate,
    "warnRate": lambda f: f.warnRate,
    "distinctTemplateCount": lambda f: float(f.distinctTemplateCount),
    "durationP50": lambda f: f.durationP50,
    "durationP90": lambda f: f.durationP90,
    "durationP95": lambda f: f.durationP95,
    "durationP99": lambda f: f.durationP99,
}

WATCHABLE_FEATURES: frozenset[str] = frozenset(FEATURE_ACCESSORS)


def _encode_id_component(text: object) -> str:
    """Percent-encode ``%`` and ``:`` in one finding-id component so it can never contain ``::``.

    Mirrors ``modules.aiops.module._encode_id_component`` (kept local to avoid an import cycle —
    ``module`` imports this scorer). Keeps the log-anomaly id namespace ``detect::log::…`` provably
    disjoint from the metric/windowed namespaces regardless of feature/node content.
    """
    return str(text).replace("%", "%25").replace(":", "%3A")


# --------------------------------------------------------------------------------------
# Pack-driven spec (content-over-code) — compiled from the VERIFIED telemetry pack body.
# --------------------------------------------------------------------------------------
@dataclass(frozen=True)
class _Band:
    """A z-score threshold → severity band. Sorted ascending by ``z``."""

    z: float
    severity: Severity


@dataclass(frozen=True)
class LogAnomalyFeatureSpec:
    """One watched feature: its direction, its severity bands, and its advisory-band entry z."""

    feature: str
    direction: AnomalyDirection
    bands: tuple[_Band, ...]  # ascending by z; bands[0].z is the assertion threshold
    advisory_z: float         # lower bound of the "surface + advise support" band (< bands[0].z)


@dataclass(frozen=True)
class LogAnomalySpec:
    """Pack-derived log-anomaly detection spec for one role selector. Provenance-bearing."""

    role: str
    min_baseline: int
    method: AnomalyMethod
    ewma_alpha: float
    features: tuple[LogAnomalyFeatureSpec, ...]
    pack_id: str
    pack_version: str


def _parse_bands(raw: Any) -> tuple[tuple[_Band, ...] | None, str | None]:
    """Validate a feature's ``bands`` list into ascending ``_Band``s, or ``(None, error)``."""
    if not isinstance(raw, list) or not raw:
        return None, "bands must be a non-empty list"
    bands: list[_Band] = []
    for entry in raw:
        if not isinstance(entry, dict):
            return None, "each band must be an object"
        z = entry.get("z")
        severity = entry.get("severity")
        if isinstance(z, bool) or not isinstance(z, (int, float)) or not math.isfinite(float(z)):
            return None, "band z must be a finite number"
        if float(z) <= 0.0:
            return None, "band z must be positive"
        try:
            sev = Severity(str(severity))
        except ValueError:
            return None, f"band severity {severity!r} is invalid"
        bands.append(_Band(z=float(z), severity=sev))
    bands.sort(key=lambda b: b.z)
    return tuple(bands), None


def _parse_feature_spec(raw: Any) -> tuple[LogAnomalyFeatureSpec | None, str | None]:
    """Validate one raw feature entry into a :class:`LogAnomalyFeatureSpec`, or ``(None, err)``."""
    if not isinstance(raw, dict):
        return None, "feature entry must be an object"
    feature = raw.get("feature")
    if feature not in WATCHABLE_FEATURES:
        return None, f"feature {feature!r} is not a watchable aggregate feature"
    direction = raw.get("direction", "both")
    if direction not in ("up", "down", "both"):
        return None, f"feature {feature!r}: direction {direction!r} is invalid"
    bands, berr = _parse_bands(raw.get("bands"))
    if bands is None:
        return None, f"feature {feature!r}: {berr}"
    entry_z = bands[0].z
    advisory_raw = raw.get("advisoryZScore")
    if advisory_raw is None:
        advisory_z = entry_z * _DEFAULT_ADVISORY_FRACTION
    elif (
        isinstance(advisory_raw, bool)
        or not isinstance(advisory_raw, (int, float))
        or not math.isfinite(float(advisory_raw))
    ):
        return None, f"feature {feature!r}: advisoryZScore must be a finite number"
    else:
        advisory_z = float(advisory_raw)
        if advisory_z < 0.0 or advisory_z >= entry_z:
            return None, (
                f"feature {feature!r}: advisoryZScore must be in [0, {entry_z}) "
                "(below the lowest band)"
            )
    return (
        LogAnomalyFeatureSpec(
            feature=str(feature),
            direction=direction,
            bands=bands,
            advisory_z=advisory_z,
        ),
        None,
    )


def compile_log_anomaly_specs(
    body: object, pack_id: str, pack_version: str
) -> tuple[list[LogAnomalySpec], list[str]]:
    """Compile a VERIFIED telemetry pack ``body``'s ``logAnalysis.anomaly`` into specs. Pure.

    Returns ``(specs, notes)``. Content-over-code: the detection KNOWLEDGE (which features to watch,
    the z→severity bands, the baseline/method params) lives in the signed pack, not in Python. A
    missing/malformed anomaly section or feature is SURFACED as a note and skipped (fail-closed),
    never raised and never silently passed. The pack body is only ever reached here downstream of
    the engine's signature/trust gate.
    """
    notes: list[str] = []
    if not isinstance(body, dict):
        return [], notes
    log_analysis = body.get("logAnalysis")
    if not isinstance(log_analysis, dict):
        return [], notes
    if log_analysis.get("enabled") is False:
        notes.append(f"pack {pack_id}: logAnalysis disabled — skipped")
        return [], notes
    anomaly = log_analysis.get("anomaly")
    if anomaly is None:
        return [], notes
    if not isinstance(anomaly, dict):
        notes.append(f"pack {pack_id}: logAnalysis.anomaly is not an object — skipped")
        return [], notes
    if anomaly.get("enabled") is False:
        notes.append(f"pack {pack_id}: logAnalysis.anomaly disabled — skipped")
        return [], notes

    node_id = anomaly.get("nodeId")
    role = _role_from_selector(node_id) if isinstance(node_id, str) else None
    if role is None:
        notes.append(
            f"pack {pack_id}: logAnalysis.anomaly has non-role selector {node_id!r} — skipped"
        )
        return [], notes

    method = anomaly.get("method", "mad")
    if method not in ("mad", "ewma"):
        notes.append(f"pack {pack_id}: logAnalysis.anomaly method {method!r} is invalid — skipped")
        return [], notes

    min_baseline_raw = anomaly.get("minBaseline", 5)
    if (
        isinstance(min_baseline_raw, bool)
        or not isinstance(min_baseline_raw, int)
        or min_baseline_raw < 2
    ):
        notes.append(
            f"pack {pack_id}: logAnalysis.anomaly minBaseline must be an integer >= 2 — skipped"
        )
        return [], notes

    alpha_raw = anomaly.get("ewmaAlpha", _DEFAULT_EWMA_ALPHA)
    if (
        isinstance(alpha_raw, bool)
        or not isinstance(alpha_raw, (int, float))
        or not (0.0 < float(alpha_raw) < 1.0)
    ):
        notes.append(
            f"pack {pack_id}: logAnalysis.anomaly ewmaAlpha must be in (0, 1) — skipped"
        )
        return [], notes

    raw_features = anomaly.get("features")
    if not isinstance(raw_features, list) or not raw_features:
        notes.append(
            f"pack {pack_id}: logAnalysis.anomaly 'features' is absent or empty — skipped"
        )
        return [], notes

    features: list[LogAnomalyFeatureSpec] = []
    for raw_feature in raw_features:
        feature_spec, ferr = _parse_feature_spec(raw_feature)
        if ferr is not None:
            notes.append(f"pack {pack_id}: {ferr} — skipped")
        if feature_spec is not None:
            features.append(feature_spec)

    if not features:
        notes.append(
            f"pack {pack_id}: logAnalysis.anomaly declared no usable features — skipped"
        )
        return [], notes

    return (
        [
            LogAnomalySpec(
                role=role,
                min_baseline=int(min_baseline_raw),
                method=method,
                ewma_alpha=float(alpha_raw),
                features=tuple(features),
                pack_id=pack_id,
                pack_version=pack_version,
            )
        ],
        notes,
    )


_ROLE_SELECTOR_PREFIX = "role:"


def _role_from_selector(selector: str) -> str | None:
    """Resolve ``role:<name>`` to a lowercased role, or ``None`` (kept local; module isolation)."""
    if not selector.startswith(_ROLE_SELECTOR_PREFIX):
        return None
    role = selector[len(_ROLE_SELECTOR_PREFIX):].strip().lower()
    return role or None


# --------------------------------------------------------------------------------------
# Robust statistics (pure).
# --------------------------------------------------------------------------------------
def _median(values: list[float]) -> float:
    """Median of a non-empty list. Pure."""
    ordered = sorted(values)
    n = len(ordered)
    mid = n // 2
    if n % 2 == 1:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def _mad_stats(values: list[float]) -> tuple[float, float]:
    """Return ``(center, scale)`` = ``(median, MAD * 1.4826)``. ``scale`` may be 0 (degenerate)."""
    center = _median(values)
    deviations = [abs(v - center) for v in values]
    scale = _median(deviations) * _MAD_SCALE
    return center, scale


def _ewma_stats(values: list[float], alpha: float) -> tuple[float, float]:
    """Return ``(mean, std)`` from the EWMA/EWMV recursion. ``std`` may be 0 (degenerate)."""
    mean = values[0]
    var = 0.0
    for v in values[1:]:
        diff = v - mean
        incr = alpha * diff
        mean += incr
        var = (1.0 - alpha) * (var + diff * incr)
    return mean, math.sqrt(var) if var > 0.0 else 0.0


def _robust_z(
    baseline_values: list[float], current: float, method: AnomalyMethod, alpha: float
) -> tuple[float, float, float] | None:
    """Return ``(z, center, scale)`` or ``None`` when the robust scale is degenerate (all-equal).

    A ``None`` return means the baseline has no robust spread, so a deviating current cannot be
    quantified confidently — the caller treats it as advisory (below the floor), never asserting.
    """
    if method == "ewma":
        center, scale = _ewma_stats(baseline_values, alpha)
    else:
        center, scale = _mad_stats(baseline_values)
    if scale <= 0.0 or not math.isfinite(scale):
        return None
    z = (current - center) / scale
    if not math.isfinite(z):
        return None
    return z, center, scale


def _directional_z(z: float, direction: AnomalyDirection) -> float:
    """Fold a signed z into the watched direction (``up`` positive, ``down`` neg, ``both`` abs)."""
    if direction == "up":
        return max(z, 0.0)
    if direction == "down":
        return max(-z, 0.0)
    return abs(z)


def _severity_for(bands: tuple[_Band, ...], directional_z: float) -> Severity:
    """Highest band severity whose z threshold is <= ``directional_z`` (bands ascending)."""
    severity = bands[0].severity
    for band in bands:
        if directional_z >= band.z:
            severity = band.severity
        else:
            break
    return severity


def _confidence_for(directional_z: float, entry_z: float) -> float:
    """Map a directional z (>= entry_z) to a confidence in ``[FLOOR, 0.99]``. Monotonic.

    At the assertion threshold (``entry_z``) confidence == the floor exactly; it rises linearly with
    z and saturates at :data:`_CONFIDENCE_CEILING`. Advisory only — never claims certainty.
    """
    span = _CONFIDENCE_CEILING - LOG_ANOMALY_CONFIDENCE_FLOOR
    over = (directional_z - entry_z) / entry_z if entry_z > 0.0 else 0.0
    confidence = LOG_ANOMALY_CONFIDENCE_FLOOR + span * over
    return max(LOG_ANOMALY_CONFIDENCE_FLOOR, min(_CONFIDENCE_CEILING, confidence))


# --------------------------------------------------------------------------------------
# Scoring — baseline + current → advisory findings (pure).
# --------------------------------------------------------------------------------------
def score_log_anomalies(
    baseline: list[LogFeatures],
    current: LogFeatures,
    spec: LogAnomalySpec,
    node_id: str,
) -> tuple[list[Finding], list[str]]:
    """Score the current window against the baseline for one node. Returns ``(findings, notes)``.

    Advisory only + fail-closed:

    * A feature with fewer than ``spec.min_baseline`` usable prior values, or no current value,
      yields NO finding (short-baseline ⇒ no detection) and a surfaced note.
    * A deviation that reaches only the advisory band (below the assertion threshold), or whose
      baseline has a degenerate robust scale, yields NO finding — only an "advise support" note.
    * A deviation at/above the assertion threshold yields exactly one provenance-bearing
      :class:`Finding` (severity from the z-bands, confidence >= the floor), citing the pack and the
      observation window.

    Deterministic; no I/O. Findings feed the auto-RCA correlation path with full evidence.
    """
    findings: list[Finding] = []
    notes: list[str] = []

    for feature_spec in spec.features:
        accessor = FEATURE_ACCESSORS[feature_spec.feature]
        current_value = accessor(current)
        if current_value is None:
            continue  # feature not present in the current window (e.g. no durations) — skip
        baseline_values = [v for f in baseline if (v := accessor(f)) is not None]
        if len(baseline_values) < spec.min_baseline:
            notes.append(
                f"pack {spec.pack_id}: {feature_spec.feature} on role {spec.role}: baseline of "
                f"{len(baseline_values)} < minBaseline {spec.min_baseline} — no detection "
                "(fail-closed); advise contacting support if anomalies are suspected"
            )
            continue

        scored = _robust_z(
            baseline_values, current_value, spec.method, spec.ewma_alpha
        )
        if scored is None:
            notes.append(
                f"pack {spec.pack_id}: {feature_spec.feature} on role {spec.role}: baseline has no "
                "robust spread — deviation cannot be confidently scored (below floor); advise "
                "contacting support"
            )
            continue

        z, center, _scale = scored
        directional = _directional_z(z, feature_spec.direction)
        entry_z = feature_spec.bands[0].z

        if directional < feature_spec.advisory_z:
            continue  # within normal variation — no detection
        if directional < entry_z:
            notes.append(
                f"pack {spec.pack_id}: {feature_spec.feature} on role {spec.role}:"
                f" z={directional:.2f}"
                f" below assertion threshold {entry_z:.2f} (below confidence floor "
                f"{LOG_ANOMALY_CONFIDENCE_FLOOR}) — advise contacting support, not asserting"
            )
            continue

        severity = _severity_for(feature_spec.bands, directional)
        confidence = _confidence_for(directional, entry_z)
        findings.append(
            _build_finding(feature_spec, spec, node_id, z, directional, center, current_value,
                           severity, confidence)
        )

    return findings, notes


def _build_finding(
    feature_spec: LogAnomalyFeatureSpec,
    spec: LogAnomalySpec,
    node_id: str,
    z: float,
    directional_z: float,
    center: float,
    current_value: float,
    severity: Severity,
    confidence: float,
) -> Finding:
    """Construct one provenance-bearing, PII-free advisory log-anomaly finding.

    All emitted strings are aggregate statistics (feature name, z-score, center/current values,
    confidence) — never a raw message, id, or PII. Cites the pack (id+version) and the observation
    window (``kind="log"``) so the finding carries full evidence into auto-RCA.
    """
    window = f"{spec.method} z-score over {feature_spec.feature}"
    detail = (
        f"Advisory log anomaly: {feature_spec.feature} z={directional_z:.2f} "
        f"(baseline center {center:.4g}, current {current_value:.4g}, {feature_spec.direction}); "
        f"confidence {confidence:.2f}. Advisory only — human disposes."
    )
    return Finding(
        id=(
            f"detect::log::{_encode_id_component(spec.pack_id)}::"
            f"{_encode_id_component(feature_spec.feature)}::"
            f"{_encode_id_component(node_id)}"
        ),
        module="aiops",
        title=f"Log anomaly: {feature_spec.feature}",
        passed=False,
        severity=severity,
        nodeId=node_id,
        evidence=[
            SourceReference(
                kind="log",
                id=feature_spec.feature,
                detail=f"z={directional_z:.2f} ({window}); signed z={z:.2f}",
            ),
            SourceReference(
                kind="pack", id=spec.pack_id, detail=f"version {spec.pack_version}"
            ),
        ],
        packId=spec.pack_id,
        packVersion=spec.pack_version,
        detail=detail,
    )


__all__ = [
    "FEATURE_ACCESSORS",
    "LOG_ANOMALY_CONFIDENCE_FLOOR",
    "WATCHABLE_FEATURES",
    "LogAnomalyFeatureSpec",
    "LogAnomalySpec",
    "compile_log_anomaly_specs",
    "score_log_anomalies",
]
