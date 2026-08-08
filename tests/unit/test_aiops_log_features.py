"""AIOps log-feature extraction tests (issue #53, deliverable 1) — PII-free by construction.

All fixtures are clearly-fake synthetic data (guardrail 2). The extractor is a PURE function of its
input (no I/O, no Azure): these tests prove it can never retain or emit a raw message, id, or PII —
only aggregate counts, rates, one-way structural hashes, and numeric percentiles.
"""
from __future__ import annotations

import re

from modules.aiops.log_features import (
    LogFeatureExtractionSpec,
    extract_log_features,
    structural_signature,
)
from shared.contracts import LogFeatures, LogLevel

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

# A synthetic message packed with things that WOULD be PII/identifiers if ever retained.
_PII_MESSAGE = (
    "User alice@contoso.example failed login from 10.0.0.5 "
    "session 3fa85f64-5717-4562-b3fc-2c963f66afa6 "
    "path C:\\Users\\alice\\secret.txt token deadbeefcafef00d1234"
)


def test_structural_signature_is_a_one_way_hex_digest() -> None:
    sig = structural_signature(_PII_MESSAGE)
    assert _HEX64.match(sig)
    # None of the raw value tokens survive into the (hashed) signature output.
    for token in ("alice", "contoso", "10.0.0.5", "3fa85f64", "secret.txt", "deadbeef"):
        assert token not in sig


def test_structural_signature_collapses_values_to_the_same_shape() -> None:
    a = structural_signature("connection refused after 12 ms to 10.0.0.1")
    b = structural_signature("connection refused after 9999 ms to 172.16.3.9")
    assert a == b  # only the values differ → same structural template
    c = structural_signature("cache miss for key foo")
    assert a != c  # different shape → different signature


def test_structural_signature_is_deterministic() -> None:
    assert structural_signature(_PII_MESSAGE) == structural_signature(_PII_MESSAGE)


def test_structural_signature_neutralizes_residual_identifier_tokens() -> None:
    # Bare unquoted identifiers the value-token stripper does NOT classify — a mixed-case name, an
    # underscore/digit-bearing host, an over-long opaque token — are neutralized to <tok> before
    # hashing, so two lines differing only in such an identifier collapse to the SAME signature.
    a = structural_signature("auth failed for user Alice on host web_01")
    b = structural_signature("auth failed for user Bob on host prod_99")
    assert a == b
    # An over-long alphabetic token is also neutralized (only the over-long token differs).
    c = structural_signature("auth failed for user aaaaaaaaaaaaaaaaaaaaaaaa on host web")
    d = structural_signature("auth failed for user bbbbbbbbbbbbbbbbbbbbbbbb on host web")
    assert c == d


def test_structural_signature_keeps_short_lowercase_keywords_distinct() -> None:
    # Short all-lowercase keyword words are preserved, so genuinely different shapes stay distinct.
    a = structural_signature("connection refused")
    b = structural_signature("connection accepted")
    assert a != b


def _records() -> list[dict[str, object]]:
    return [
        {"level": "INFO", "message": "request ok in 12 ms", "dur": 12,
         "ts": "2026-08-03T04:00:00Z"},
        {"level": "info", "message": "request ok in 30 ms", "dur": 30,
         "ts": "2026-08-03T04:00:01Z"},
        {"level": "WARNING", "message": "slow path 900 ms", "dur": 900,
         "ts": "2026-08-03T04:00:02Z"},
        {"level": "error", "message": _PII_MESSAGE, "dur": 50, "ts": "2026-08-03T04:00:03Z"},
        {"level": "CRITICAL", "message": "db down", "dur": 5, "ts": "2026-08-03T04:00:04Z"},
    ]


def _spec() -> LogFeatureExtractionSpec:
    return LogFeatureExtractionSpec(
        levelField="level", messageField="message",
        durationField="dur", timestampField="ts",
    )


def test_extract_counts_rates_and_levels() -> None:
    features = extract_log_features(_records(), _spec())
    assert isinstance(features, LogFeatures)
    assert features.totalCount == 5
    assert features.countsByLevel[LogLevel.info] == 2
    assert features.countsByLevel[LogLevel.warn] == 1
    assert features.countsByLevel[LogLevel.error] == 1
    assert features.countsByLevel[LogLevel.critical] == 1
    # error rate = (error + critical) / total; warn rate = warn / total.
    assert features.errorRate == 2 / 5
    assert features.warnRate == 1 / 5


def test_extract_duration_percentiles_present_when_field_present() -> None:
    features = extract_log_features(_records(), _spec())
    assert features.durationSampleCount == 5
    assert features.durationP50 is not None
    assert features.durationP95 is not None
    # p99 >= p50 for a non-degenerate sample.
    assert features.durationP99 >= features.durationP50


def test_extract_duration_percentiles_none_when_no_duration_field() -> None:
    spec = LogFeatureExtractionSpec(levelField="level", messageField="message")
    features = extract_log_features(_records(), spec)
    assert features.durationSampleCount == 0
    assert features.durationP50 is None
    assert features.durationP90 is None
    assert features.durationP95 is None
    assert features.durationP99 is None


def test_extracted_features_never_contain_raw_message_or_pii() -> None:
    """The core safety property: a message/id/PII in the input NEVER appears in the features."""
    features = extract_log_features(_records(), _spec())
    dumped = features.model_dump_json()
    for token in (
        "alice", "contoso", "10.0.0.5", "3fa85f64", "secret.txt",
        "deadbeef", "login", "connection", "request ok", "db down",
    ):
        assert token not in dumped
    # Every surfaced template signature is a one-way 64-char hex digest, not text.
    for tpl in features.topTemplates:
        assert _HEX64.match(tpl.signature)


def test_distinct_template_count_and_top_templates() -> None:
    records = [
        {"level": "info", "message": "ok 1"},
        {"level": "info", "message": "ok 2"},
        {"level": "info", "message": "ok 3"},
        {"level": "info", "message": "different shape here"},
    ]
    spec = LogFeatureExtractionSpec(levelField="level", messageField="message", topTemplates=5)
    features = extract_log_features(records, spec)
    # "ok <num>" collapses to one template; "different shape here" is another.
    assert features.distinctTemplateCount == 2
    top = features.topTemplates[0]
    assert top.count == 3
    assert top.fraction == 3 / 4


def test_unknown_and_missing_levels_map_to_other() -> None:
    records = [
        {"level": "bogus", "message": "x"},
        {"message": "no level key"},
        {"level": 12345, "message": "numeric non-syslog"},
    ]
    spec = LogFeatureExtractionSpec(levelField="level", messageField="message")
    features = extract_log_features(records, spec)
    assert features.countsByLevel[LogLevel.other] == 3
    assert features.errorRate == 0.0


def test_non_mapping_records_are_skipped() -> None:
    records: list[object] = ["not-a-dict", 42, None, {"level": "info", "message": "ok"}]
    spec = LogFeatureExtractionSpec(levelField="level", messageField="message")
    features = extract_log_features(records, spec)  # type: ignore[arg-type]
    assert features.totalCount == 1


def test_empty_sample_yields_zeroed_features() -> None:
    features = extract_log_features([], _spec())
    assert features.totalCount == 0
    assert features.errorRate == 0.0
    assert features.distinctTemplateCount == 0
    assert features.topTemplates == []


def test_non_string_message_contributes_structural_not_echoed() -> None:
    records = [{"level": "info", "message": {"nested": "secret-value"}}]
    spec = LogFeatureExtractionSpec(levelField="level", messageField="message")
    features = extract_log_features(records, spec)
    assert "secret-value" not in features.model_dump_json()
    assert features.totalCount == 1
