"""Pure JSON Schema validation for pack bodies (dev/CI + studio-time gate).

Each of the five pack types has a strict JSON Schema (draft 2020-12) packaged under
``packs_engine/schemas/<type>.schema.json``. :func:`validate_pack` selects the schema by
``pack["manifest"]["type"]`` and validates ``pack["body"]`` against it, returning a list of
human-readable errors ([] == valid).

Guardrails:
* **Pure / Azure-free.** No Azure imports, no I/O beyond reading the packaged schema JSON.
* **Fail-closed.** An unknown type, a missing body, a body that violates its schema, or a
  non-finite telemetry threshold yields a non-empty error list — nothing is silently accepted.
* **jsonschema is a DEV/CI dependency, not a runtime one.** The import is guarded so importing this
  module never hard-requires ``jsonschema``; the runtime trust gate remains the signature check in
  ``packs_engine.engine``. If the body cannot be validated because ``jsonschema`` is absent, that
  is surfaced as an error (fail-closed) rather than treated as valid.

Schemas are loaded via :mod:`importlib.resources`, so they resolve both from a repo checkout and
from an installed wheel (they ship as package data — see ``pyproject.toml``).
"""
from __future__ import annotations

import json
import math
from functools import cache
from importlib import resources
from typing import Any

try:  # jsonschema ships in the [dev] extra (CI runs `pip install -e .[dev]`), not base runtime.
    from jsonschema import Draft202012Validator

    _JSONSCHEMA_IMPORT_ERROR: str | None = None
except ImportError as exc:  # pragma: no cover - only hit in a jsonschema-free runtime
    Draft202012Validator = None
    _JSONSCHEMA_IMPORT_ERROR = str(exc)

# The five signed, versioned pack types (mirrors shared.contracts.PackType by value, without
# importing pydantic/contracts so this stays a tiny pure leaf module).
PACK_TYPES: tuple[str, ...] = ("workload", "rule", "telemetry", "dependency", "ops")

_SCHEMA_SUBDIR = "schemas"


@cache
def _load_schema(pack_type: str) -> dict[str, Any] | None:
    """Load and cache the packaged schema JSON for ``pack_type`` (``None`` if absent)."""
    resource = (
        resources.files("packs_engine").joinpath(_SCHEMA_SUBDIR).joinpath(f"{pack_type}.schema.json")
    )
    if not resource.is_file():
        return None
    return json.loads(resource.read_text(encoding="utf-8"))


@cache
def _validator(pack_type: str) -> Any:
    """Build and cache a draft 2020-12 validator for ``pack_type`` (``None`` if no schema)."""
    schema = _load_schema(pack_type)
    if schema is None:
        return None
    return Draft202012Validator(schema)


def _format_error(error: Any) -> str:
    """Render one jsonschema error as ``<path>: <message>`` (``<body>`` for a root error)."""
    location = "/".join(str(part) for part in error.absolute_path) or "<body>"
    return f"{location}: {error.message}"


def _telemetry_finite_errors(body: dict[str, Any]) -> list[str]:
    """Reject non-finite (nan/inf) constants and unsafe expressions in telemetry signals.

    JSON Schema has no native finite check and a YAML loader can produce ``nan``/``inf`` floats,
    which ``aiops`` rejects (aiops/module.py:184-192). A non-finite threshold or window duration
    cannot define a meaningful breach, so surface it here as a fail-closed error after structural
    validation. Windowed/expression detectors (issue #51) add two extra fail-closed checks:

    * a non-finite ``window.durationSeconds`` is rejected (same reasoning as the threshold);
    * an ``expression`` string is validated against the shared allowlisted-AST sandbox
      (:func:`shared.safe_expr.validate_expression`) so an unsafe or non-finite-literal expression
      fails the pack gate here, not just at compile time.
    """
    errors: list[str] = []
    signals = body.get("signals")
    if not isinstance(signals, list):
        return errors
    for index, signal in enumerate(signals):
        if not isinstance(signal, dict):
            continue
        threshold = signal.get("threshold")
        if (
            isinstance(threshold, (int, float))
            and not isinstance(threshold, bool)
            and not math.isfinite(float(threshold))
        ):
            errors.append(f"signals/{index}/threshold: {threshold!r} is not a finite number")
        errors.extend(_window_finite_errors(index, signal.get("window")))
        errors.extend(_expression_errors(index, signal.get("expression")))
    errors.extend(_anomaly_finite_errors(body))
    return errors


def _anomaly_finite_errors(body: dict[str, Any]) -> list[str]:
    """Reject non-finite (nan/inf) constants in the ``logAnalysis.anomaly`` section (issue #53).

    JSON Schema cannot express a finite check, and a non-finite z-band / ``ewmaAlpha`` /
    ``advisoryZScore`` cannot define a meaningful anomaly threshold, so surface it here as a
    fail-closed error (mirrors the telemetry threshold/window checks). Structural validity is left
    to the schema; this only guards the numeric leaves against ``nan``/``inf``.
    """
    log_analysis = body.get("logAnalysis")
    if not isinstance(log_analysis, dict):
        return []
    anomaly = log_analysis.get("anomaly")
    if not isinstance(anomaly, dict):
        return []
    errors: list[str] = []
    errors.extend(_finite_leaf_error("logAnalysis/anomaly/ewmaAlpha", anomaly.get("ewmaAlpha")))
    features = anomaly.get("features")
    if isinstance(features, list):
        for f_index, feature in enumerate(features):
            if not isinstance(feature, dict):
                continue
            base = f"logAnalysis/anomaly/features/{f_index}"
            errors.extend(
                _finite_leaf_error(f"{base}/advisoryZScore", feature.get("advisoryZScore"))
            )
            bands = feature.get("bands")
            if isinstance(bands, list):
                for b_index, band in enumerate(bands):
                    if isinstance(band, dict):
                        errors.extend(
                            _finite_leaf_error(f"{base}/bands/{b_index}/z", band.get("z"))
                        )
    return errors


def _finite_leaf_error(path: str, value: Any) -> list[str]:
    """Return a single error iff ``value`` is a non-finite (nan/inf) number; else ``[]``."""
    if (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and not math.isfinite(float(value))
    ):
        return [f"{path}: {value!r} is not a finite number"]
    return []


def _window_finite_errors(index: int, window: Any) -> list[str]:
    """Reject a non-finite ``window.durationSeconds`` (nan/inf) for signal ``index``."""
    if not isinstance(window, dict):
        return []
    duration = window.get("durationSeconds")
    if (
        isinstance(duration, (int, float))
        and not isinstance(duration, bool)
        and not math.isfinite(float(duration))
    ):
        return [
            f"signals/{index}/window/durationSeconds: {duration!r} is not a finite number"
        ]
    return []


def _expression_errors(index: int, expression: Any) -> list[str]:
    """Reject an unsafe/invalid ``expression`` (allowlisted-AST sandbox), for signal ``index``."""
    if expression is None:
        return []
    if not isinstance(expression, str):
        return [f"signals/{index}/expression: must be a string"]
    from shared.safe_expr import TELEMETRY_EXPR_NAMES, validate_expression

    return [
        f"signals/{index}/expression: {err}"
        for err in validate_expression(expression, allowed_names=TELEMETRY_EXPR_NAMES)
    ]


def validate_pack(pack: dict[str, Any]) -> list[str]:
    """Validate a pack's ``body`` against its type's JSON Schema.

    Returns a list of human-readable error strings; an empty list means the body is valid. The
    schema is chosen from ``pack["manifest"]["type"]`` and applied to ``pack["body"]``. Fail-closed:
    a missing manifest/body, an unknown type, an absent schema, a missing ``jsonschema`` install, or
    a non-finite telemetry threshold all yield a non-empty error list rather than a silent pass.
    """
    manifest = pack.get("manifest")
    if not isinstance(manifest, dict):
        return ["pack is missing a 'manifest' object"]
    pack_id = manifest.get("id", "<unknown>")
    pack_type = manifest.get("type")
    if pack_type not in PACK_TYPES:
        return [f"pack '{pack_id}': unknown pack type {pack_type!r}"]
    body = pack.get("body")
    if not isinstance(body, dict):
        return [f"pack '{pack_id}': missing or non-object 'body'"]
    if Draft202012Validator is None:
        return [
            f"pack '{pack_id}': jsonschema is not installed "
            f"({_JSONSCHEMA_IMPORT_ERROR}); cannot validate body — fail closed"
        ]
    validator = _validator(pack_type)
    if validator is None:
        return [f"pack '{pack_id}': no schema found for type {pack_type!r}"]
    errors = [
        _format_error(error)
        for error in sorted(validator.iter_errors(body), key=lambda e: list(e.absolute_path))
    ]
    if pack_type == "telemetry":
        errors.extend(_telemetry_finite_errors(body))
    return errors


__all__ = ["PACK_TYPES", "validate_pack"]
