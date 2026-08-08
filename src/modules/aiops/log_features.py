"""Pure, PII-free log feature extraction (issue #53, deliverable 1).

Given a bounded, in-boundary sample of raw log records, compute ONLY aggregate, PII-free features
(:class:`shared.contracts.LogFeatures`). This is the core safety boundary: the extractor is a pure
function of its input (no I/O, no Azure, no network) and is provably incapable of retaining or
emitting a raw message, identifier, or any PII.

## Why it is provably PII-free

* **Allowlist read.** Only the fields NAMED in the injected :class:`LogFeatureExtractionSpec`
  (level / message / duration / timestamp) are ever read from a record; every other key is ignored
  by construction. The field NAMES are a deployment concern (connector config), never pack content.
* **Structural signature is a one-way hash.** A message is used in-boundary ONLY to compute a
  SHA-256 hex digest of its *structural shape* — after every value token (numbers, GUIDs, emails,
  IPs, timestamps, paths, urls, quoted strings, long hex/ids) has been replaced with a class
  placeholder AND residual identifier-like tokens neutralized to ``<tok>``. The raw message is
  NEVER stored on the returned features; only the irreversible hash and its frequency exist
  in-boundary. The digest is an INTERNAL structural correlation key whose preimage MAY still embed
  residual lowercase keyword tokens, so it is NOT claimed literal-free and NEVER egresses: the LLM
  enrichment edge is fed :meth:`shared.contracts.LogFeatures.enrichment_payload`, which drops the
  signatures entirely.
* **Closed level enum.** Levels normalize to the CLOSED :class:`shared.contracts.LogLevel`; an
  unknown/absent level becomes ``other`` — never an arbitrary retained string.
* **Aggregates only.** Everything emitted is a count, rate, one-way hash, or numeric percentile.

Default-DENY: a record that is not a mapping, or a message/level/duration leaf that is not a
str/number as expected, contributes nothing free-text — it is counted structurally (or skipped),
never echoed.
"""
from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from shared.contracts import LogFeatures, LogLevel, TemplateFrequency

# Default number of most-frequent templates to surface (signatures only). Bounded so the emitted
# feature set stays small and enumerable.
DEFAULT_TOP_TEMPLATES = 10

# Hard cap on records processed from a single sample — a fail-closed bound so an oversized sample
# can never exhaust memory/CPU at the extraction edge. The caller (connector) also bounds its fetch.
MAX_SAMPLE_RECORDS = 100_000

# Map of common textual level tokens onto the closed LogLevel enum. Anything not here → ``other``.
_LEVEL_ALIASES: dict[str, LogLevel] = {
    "trace": LogLevel.debug,
    "debug": LogLevel.debug,
    "dbg": LogLevel.debug,
    "verbose": LogLevel.debug,
    "info": LogLevel.info,
    "information": LogLevel.info,
    "informational": LogLevel.info,
    "notice": LogLevel.info,
    "warn": LogLevel.warn,
    "warning": LogLevel.warn,
    "error": LogLevel.error,
    "err": LogLevel.error,
    "fail": LogLevel.error,
    "failure": LogLevel.error,
    "critical": LogLevel.critical,
    "crit": LogLevel.critical,
    "fatal": LogLevel.critical,
    "alert": LogLevel.critical,
    "emergency": LogLevel.critical,
    "emerg": LogLevel.critical,
}

# Numeric syslog severities (RFC 5424) → LogLevel, for records that carry an integer level.
_SYSLOG_SEVERITY: dict[int, LogLevel] = {
    0: LogLevel.critical,
    1: LogLevel.critical,
    2: LogLevel.critical,
    3: LogLevel.error,
    4: LogLevel.warn,
    5: LogLevel.info,
    6: LogLevel.info,
    7: LogLevel.debug,
}


class LogFeatureExtractionSpec(BaseModel):
    """Which record fields to read + extraction bounds — a DEPLOYMENT concern (connector config).

    The field NAMES describe the shape of the log source's records; they are supplied by the
    connector/composition root, never by pack content (a pack declares WHICH aggregate features to
    watch, not how a record is shaped). Holds no secrets and no thresholds. ``extra="forbid"`` so a
    malformed spec fails closed rather than silently ignoring a typo'd field.
    """

    model_config = ConfigDict(extra="forbid")

    levelField: str = Field(default="level", description="Record key holding the log level")
    messageField: str = Field(
        default="message",
        description="Record key holding the free-text message (hashed, never kept)",
    )
    durationField: str | None = Field(
        default=None, description="Optional record key holding a numeric duration/latency"
    )
    timestampField: str | None = Field(
        default=None, description="Optional record key holding the observation timestamp"
    )
    topTemplates: int = Field(
        default=DEFAULT_TOP_TEMPLATES, ge=0, le=100,
        description="How many most-frequent template signatures to surface",
    )


# --------------------------------------------------------------------------------------
# Structural signature — strip every value token, THEN hash. One-way; PII-free by construction.
# --------------------------------------------------------------------------------------
# Order matters: the more specific patterns (guid/email/ip/url/path) run before the generic number
# pattern so a value is classified by its most specific shape. Each match becomes a bare class
# placeholder that retains NO original token.
_SIGNATURE_SUBSTITUTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Quoted string literals — collapse the whole quoted run (could contain a name/PII).
    (re.compile(r"\"[^\"]*\"|'[^']*'"), " <str> "),
    # ISO-8601-ish timestamps.
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"),
     " <ts> "),
    # Emails.
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), " <email> "),
    # GUIDs / UUIDs.
    (re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
     " <guid> "),
    # URLs.
    (re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://\S+"), " <url> "),
    # Windows and POSIX file/resource paths (incl. Azure resource ids under /subscriptions).
    (re.compile(r"(?:[A-Za-z]:\\|\\\\|/)[^\s\"']*"), " <path> "),
    # IPv4 addresses.
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), " <ip> "),
    # Long hex runs / hashes / opaque ids (>=8 hex chars).
    (re.compile(r"\b[0-9a-fA-F]{8,}\b"), " <hex> "),
    # Any remaining number (int/float/scientific, optionally signed).
    (re.compile(r"[+-]?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?"), " <num> "),
)

_WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_WS_RE = re.compile(r"\s+")

# Maximum length of a residual token kept as a structural keyword. Anything longer is treated as an
# identifier-like token and neutralized to ``<tok>`` (see :func:`_normalize_word`).
_MAX_KEYWORD_LEN = 20


def _normalize_word(token: str) -> str:
    """Lower-case a short keyword, or neutralize an identifier-like residual token to ``<tok>``.

    A bare unquoted token that the value-token stripper did NOT classify (e.g. a username, hostname,
    or opaque identifier that is not a quoted/number/email/guid/url/path/ip token) could otherwise
    survive into the signature preimage. To reduce that residual PII sensitivity, any token that
    contains a digit or underscore, carries any upper/mixed case, or is longer than
    :data:`_MAX_KEYWORD_LEN` is replaced with a bare ``<tok>`` placeholder. Short, all-lowercase,
    purely-alphabetic words (structural keywords like "connection"/"refused") are kept (lowercased)
    so the signature stays a meaningful shape.
    """
    if (
        len(token) > _MAX_KEYWORD_LEN
        or "_" in token
        or any(ch.isdigit() for ch in token)
        or not token.islower()
    ):
        return "<tok>"
    return token


def structural_signature(message: str) -> str:
    """Return a SHA-256 hex digest of ``message``'s value-stripped structural shape. One-way.

    Pure and deterministic. Every value token (quoted string, timestamp, email, guid, url, path,
    ip, long hex/id, number) is replaced with a class placeholder, and any residual identifier-like
    token (digit/underscore-bearing, mixed/upper case, or over-long) is further neutralized to
    ``<tok>``, BEFORE hashing — so the digest identifies only the message's *shape*.

    This signature is an INTERNAL, in-boundary-only structural correlation key. Its preimage MAY
    still embed residual *lowercase lexical keyword* tokens (a bare word the stripper did not
    classify), so it is NOT claimed to be literal-free and MUST NOT leave the boundary. The
    no-egress guarantee is enforced structurally by
    :meth:`shared.contracts.LogFeatures.enrichment_payload`, which drops signatures from the only
    outbound payload — never by asserting the preimage is PII-free. The raw ``message`` is used
    solely to derive the digest and is never returned/stored.
    """
    shape = message
    for pattern, placeholder in _SIGNATURE_SUBSTITUTIONS:
        shape = pattern.sub(placeholder, shape)
    # Lower-case short structural keywords and neutralize residual identifier-like tokens, so
    # trivial casing/spacing differences collapse to the same template while a bare identifier
    # cannot survive verbatim into the preimage.
    shape = _WORD_RE.sub(lambda m: _normalize_word(m.group(0)), shape)
    shape = _WS_RE.sub(" ", shape).strip()
    return hashlib.sha256(shape.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------------------
# Field readers — fail-closed, allowlist only.
# --------------------------------------------------------------------------------------
def _normalize_level(raw: Any) -> LogLevel:
    """Map a raw level token/severity onto the closed :class:`LogLevel` (unknown → ``other``)."""
    if isinstance(raw, bool):
        return LogLevel.other
    if isinstance(raw, int):
        return _SYSLOG_SEVERITY.get(raw, LogLevel.other)
    if isinstance(raw, str):
        return _LEVEL_ALIASES.get(raw.strip().lower(), LogLevel.other)
    return LogLevel.other


def _coerce_duration(raw: Any) -> float | None:
    """Return a finite non-negative float duration, or ``None`` (skip) — fail-closed."""
    if isinstance(raw, bool) or raw is None:
        return None
    if isinstance(raw, (int, float)):
        value = float(raw)
    elif isinstance(raw, str):
        try:
            value = float(raw.strip())
        except ValueError:
            return None
    else:
        return None
    if not math.isfinite(value) or value < 0.0:
        return None
    return value


def _coerce_timestamp(raw: Any) -> datetime | None:
    """Parse an ISO-8601 string / epoch / datetime to aware UTC, or ``None`` — fail-closed."""
    if isinstance(raw, bool) or raw is None:
        return None
    try:
        if isinstance(raw, datetime):
            dt = raw
        elif isinstance(raw, (int, float)):
            if not math.isfinite(float(raw)):
                return None
            dt = datetime.fromtimestamp(float(raw), tz=UTC)
        elif isinstance(raw, str):
            dt = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
        else:
            return None
    except (ValueError, OverflowError, OSError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _percentile(sorted_values: list[float], pct: float) -> float:
    """Linear-interpolated percentile of a pre-sorted list (``pct`` in ``[0, 100]``). Pure."""
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (pct / 100.0) * (len(sorted_values) - 1)
    lower = int(rank)
    upper = min(lower + 1, len(sorted_values) - 1)
    frac = rank - lower
    return sorted_values[lower] * (1.0 - frac) + sorted_values[upper] * frac


def extract_log_features(
    records: Iterable[Mapping[str, Any]], spec: LogFeatureExtractionSpec | None = None
) -> LogFeatures:
    """Compute aggregate, PII-free :class:`LogFeatures` from a bounded log sample. PURE.

    Reads ONLY the fields named by ``spec`` from each record; every other key is ignored. A message
    is used solely to derive a one-way structural-signature hash (never stored). Levels normalize to
    the closed :class:`LogLevel`; durations/timestamps are coerced fail-closed (a malformed leaf is
    skipped, never echoed). Non-mapping records are skipped. Processing is bounded by
    :data:`MAX_SAMPLE_RECORDS`. No I/O, no Azure, no network — deterministic in its input.
    """
    spec = spec or LogFeatureExtractionSpec()

    total = 0
    counts: dict[LogLevel, int] = {}
    signature_counts: dict[str, int] = {}
    durations: list[float] = []
    earliest: datetime | None = None
    latest: datetime | None = None

    for index, record in enumerate(records):
        if index >= MAX_SAMPLE_RECORDS:
            break
        if not isinstance(record, Mapping):
            continue
        total += 1

        level = _normalize_level(record.get(spec.levelField))
        counts[level] = counts.get(level, 0) + 1

        message = record.get(spec.messageField)
        # Only a genuine string is a message; anything else contributes the empty-shape signature
        # (structural) rather than being coerced/echoed.
        text = message if isinstance(message, str) else ""
        signature = structural_signature(text)
        signature_counts[signature] = signature_counts.get(signature, 0) + 1

        if spec.durationField is not None:
            duration = _coerce_duration(record.get(spec.durationField))
            if duration is not None:
                durations.append(duration)

        if spec.timestampField is not None:
            ts = _coerce_timestamp(record.get(spec.timestampField))
            if ts is not None:
                earliest = ts if earliest is None or ts < earliest else earliest
                latest = ts if latest is None or ts > latest else latest

    error_count = counts.get(LogLevel.error, 0) + counts.get(LogLevel.critical, 0)
    warn_count = counts.get(LogLevel.warn, 0)
    error_rate = error_count / total if total else 0.0
    warn_rate = warn_count / total if total else 0.0

    # Top templates by frequency, ties broken by signature for determinism.
    ordered = sorted(signature_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    top = [
        TemplateFrequency(
            signature=sig,
            count=count,
            fraction=(count / total if total else 0.0),
        )
        for sig, count in ordered[: spec.topTemplates]
    ]

    duration_sorted = sorted(durations)
    has_durations = bool(duration_sorted)

    return LogFeatures(
        windowStart=earliest,
        windowEnd=latest,
        totalCount=total,
        countsByLevel=dict(counts),
        errorRate=error_rate,
        warnRate=warn_rate,
        distinctTemplateCount=len(signature_counts),
        topTemplates=top,
        durationP50=_percentile(duration_sorted, 50.0) if has_durations else None,
        durationP90=_percentile(duration_sorted, 90.0) if has_durations else None,
        durationP95=_percentile(duration_sorted, 95.0) if has_durations else None,
        durationP99=_percentile(duration_sorted, 99.0) if has_durations else None,
        durationSampleCount=len(duration_sorted),
    )


__all__ = [
    "DEFAULT_TOP_TEMPLATES",
    "MAX_SAMPLE_RECORDS",
    "LogFeatureExtractionSpec",
    "extract_log_features",
    "structural_signature",
]
