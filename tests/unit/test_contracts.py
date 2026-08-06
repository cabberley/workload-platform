"""Contract round-trips and validation."""
import pytest
from pydantic import ValidationError

from shared import contracts
from shared.contracts import (
    PLATFORM_SAFE_TAG_KEYS,
    REDACTED,
    AgentResponse,
    DurationSample,
    DurationSampleView,
    HealthState,
    MetricLabelKey,
    MetricSample,
    MetricSampleView,
    MetricsSnapshot,
    MetricsSnapshotView,
    ModuleKind,
    ModuleManifest,
    ResourceNode,
    ScaleProfile,
    SourceReference,
    bound_labels,
    redact_node_tags,
    redact_tree,
    redact_value,
)


def test_agent_response_roundtrip():
    r = AgentResponse(
        agentName="aiops",
        taskType="auto-rca",
        inputSummary="finding=x",
        findings=["latency breach"],
        sourceReferences=[SourceReference(kind="metric", id="odb_latency_ms")],
        confidence=0.8,
        nextActions=["propose-remediation"],
    )
    dumped = r.model_dump()
    again = AgentResponse(**dumped)
    assert again.agentName == "aiops"
    assert again.confidence == 0.8
    assert again.sourceReferences[0].kind == "metric"


def test_confidence_bounds_enforced():
    with pytest.raises(ValidationError):
        AgentResponse(agentName="a", taskType="t", inputSummary="s", confidence=1.5)


def test_module_manifest_scale_profile():
    m = ModuleManifest(
        name="quality_checks",
        displayName="Quality Checks",
        kind=ModuleKind.job,
        scaleProfile=ScaleProfile(kind=ModuleKind.job, minReplicas=0, maxReplicas=30),
    )
    assert m.scaleProfile.maxReplicas == 30
    assert m.enabled is True


# --------------------------------------------------------------------------------------
# Issue #91 — pure egress redaction + bounded metrics-label projection.
# --------------------------------------------------------------------------------------
def test_redact_value_passes_bounded_pii_free_identifiers():
    assert redact_value("discovery") == "discovery"
    assert redact_value("ok") == "ok"
    assert redact_value("production") == "production"


@pytest.mark.parametrize(
    "unsafe",
    [
        "alice@contoso.com",  # email marker
        "/subscriptions/abc/resourceGroups/rg",  # azure resource path
        "/providers/Microsoft.Compute",
        "has\tcontrol",  # control character
        "x" * 300,  # oversized
        "",  # empty
    ],
)
def test_redact_value_drops_anything_not_provably_safe(unsafe):
    assert redact_value(unsafe) == REDACTED


def test_redact_value_non_string_is_redacted():
    assert redact_value(None) == REDACTED
    assert redact_value(123) == REDACTED
    assert redact_value({"k": "v"}) == REDACTED


def test_bound_labels_keeps_allowlist_drops_unknown_and_redacts_values():
    out = bound_labels(
        {
            "module": "discovery",
            "outcome": "alice@contoso.com",  # allow-listed key, PII value
            "email": "bob@contoso.com",  # unknown key → dropped
            "region": "eastus",  # unknown key → dropped
        }
    )
    assert set(out) == {"module", "outcome"}
    assert out["module"] == "discovery"
    assert out["outcome"] == REDACTED


def test_bound_labels_non_mapping_is_empty():
    assert bound_labels(None) == {}
    assert bound_labels("nope") == {}


# --------------------------------------------------------------------------------------
# Issue #91 (review fixes) — nested egress redaction (redact_tree) + tag redaction.
# --------------------------------------------------------------------------------------
def test_redact_tree_default_redacts_all_string_leaves_keeps_structure():
    tree = {
        "drift": {
            "newFailures": [
                {"id": "f1", "detail": "alice@contoso.com", "severity": "high"},
            ],
        },
    }
    out = redact_tree(tree)
    # ``drift``/``newFailures``/``id``/``detail``/``severity`` are module-defined schema keys
    # (allow-listed) so the structure SURVIVES; every free-form string leaf beneath is redacted.
    assert set(out) == {"drift"}
    assert set(out["drift"]) == {"newFailures"}
    leaf = out["drift"]["newFailures"][0]
    assert leaf == {"id": REDACTED, "detail": REDACTED, "severity": REDACTED}


def test_redact_tree_redacts_value_under_untrusted_key_even_if_safe_scalar():
    # Finding 1 (R4): under a NON-allow-listed key the platform has NO schema knowledge of the
    # value, so even a provably-safe scalar (a numeric SSN, a bool, an Enum) must be redacted
    # wholesale — never recursed/preserved. The SAME scalar under an allow-listed key survives.
    assert redact_tree({"patientSSN": 123456789}) == {"redacted_key_0": REDACTED}
    assert redact_tree({"flag": True}) == {"redacted_key_0": REDACTED}
    assert redact_tree({"ratio": 1.5}) == {"redacted_key_0": REDACTED}
    assert redact_tree({"state": HealthState.down}) == {"redacted_key_0": REDACTED}
    # Allow-listed keys → the scalar value is preserved.
    assert redact_tree({"nodeCount": 123456789}) == {"nodeCount": 123456789}
    assert redact_tree({"passed": True}) == {"passed": True}
    assert redact_tree({"confidence": 1.5}) == {"confidence": 1.5}
    assert redact_tree({"severity": HealthState.down}) == {"severity": HealthState.down}


def test_redact_key_exact_match_no_unicode_folding_is_collision_safe():
    # Finding 2 (R4): the allow-list is matched by RAW exact equality (no NFKC folding), so a
    # customer-crafted fullwidth key does NOT impersonate the ASCII platform key ``detail``
    # and does NOT collide with / overwrite a real ``detail`` in the same mapping.
    fullwidth = "\uff44\uff45\uff54\uff41\uff49\uff4c"  # ｄｅｔａｉｌ
    out = redact_tree({"detail": "x", fullwidth: 123456789})
    assert len(out) == 2  # no silent overwrite
    assert out["detail"] == REDACTED  # real ASCII key survives, value (a str) redacted
    assert out["redacted_key_1"] == REDACTED  # fullwidth key → distinct positional placeholder
    assert fullwidth not in out


def test_redact_tree_preserves_non_string_scalars_and_structure():
    # Module-schema keys survive; the values follow the scalar rules (numbers/bools/None pass, the
    # one string leaf is redacted).
    tree = {
        "nodeCount": 7,
        "confidence": 1.5,
        "passed": True,
        "detail": None,
        "newFailures": [1, 2, "ok"],
    }
    out = redact_tree(tree)
    assert out == {
        "nodeCount": 7,
        "confidence": 1.5,
        "passed": True,
        "detail": None,
        "newFailures": [1, 2, REDACTED],
    }
    # bool is not coerced by the str branch.
    assert out["passed"] is True


def test_redact_tree_preserves_enum_members_before_str_rule():
    # A StrEnum member IS a str, but is a bounded platform-defined value — it must pass through.
    # ``severity``/``detail`` are allow-listed module-schema keys.
    tree = {"severity": HealthState.down, "detail": "down"}
    out = redact_tree(tree)
    assert out["severity"] == HealthState.down
    assert out["detail"] == REDACTED  # the plain string is redacted


def test_redact_tree_redacts_unsupported_leaf_types():
    # Finding 1: default-DENY — a nested set/frozenset/bytes/BaseModel/dataclass/arbitrary object
    # must be redacted, never serialized. The values sit under ALLOW-LISTED keys so the container
    # recursion (which redacts set/frozenset ELEMENTS) is exercised.
    class _PHI(ResourceNode):
        pass

    tree = {
        "newFailures": {"alice@contoso.com", "bob@contoso.com"},  # set → recurse elements
        "recovered": frozenset({"MRN123456"}),  # frozenset → recurse elements
        "detail": b"123-45-6789",  # bytes leaf → sentinel
        "summary": _PHI(id="n", name="AliceSmith", type="t"),  # nested model → sentinel
    }
    out = redact_tree(tree)
    # set/frozenset of string PII → a set/frozenset of the sentinel (collapsed).
    assert out["newFailures"] == {REDACTED}
    assert out["recovered"] == frozenset({REDACTED})
    # bytes and the nested Pydantic model → the scalar sentinel (never introspected).
    assert out["detail"] == REDACTED
    assert out["summary"] == REDACTED


def test_redact_tree_sanitizes_pii_and_workload_derived_keys():
    # Customer-derived / workload-derived mapping KEYS can themselves carry PII — every such key is
    # redacted to a distinct positional placeholder (default-DENY); an SSN-shaped key is NOT safe.
    # The value under each untrusted key is also fully redacted (Finding 1, R4).
    tree = {
        "drift": {
            "alice@contoso.com": {"detail": "x"},  # PII key → placeholder, value redacted
            "123-45-6789": {"detail": "y"},  # SSN-shaped but still customer-derived → placeholder
        }
    }
    out = redact_tree(tree)
    assert set(out["drift"]) == {"redacted_key_0", "redacted_key_1"}
    assert out["drift"]["redacted_key_0"] == REDACTED
    assert out["drift"]["redacted_key_1"] == REDACTED
    assert "alice@contoso.com" not in out["drift"]
    assert "123-45-6789" not in out["drift"]


def test_redact_tree_handles_lists_and_tuples_as_lists():
    assert redact_tree(["ok", "a@b.com", 3]) == [REDACTED, REDACTED, 3]
    assert redact_tree(("ok", "a@b.com")) == [REDACTED, REDACTED]


def test_redact_tree_redacts_set_and_frozenset_elements():
    # A set/frozenset ELEMENT is a free-form leaf → redacted; distinct PII collapses to one.
    assert redact_tree({"a@b.com", "c@d.com"}) == {REDACTED}
    assert redact_tree(frozenset({"x@y.com"})) == frozenset({REDACTED})
    # A non-hashable redacted element (a tuple element redacts to a list) collapses to the sentinel.
    assert redact_tree({("k",)}) == {REDACTED}
    # A hashable redacted element (frozenset → frozenset) stays a set element.
    assert redact_tree({frozenset({"k"})}) == {frozenset({REDACTED})}


def test_redact_tree_is_idempotent():
    tree = {"detail": "alice@contoso.com", "drift": {"summary": ["x@y.com", "safe"]}}
    once = redact_tree(tree)
    assert redact_tree(once) == once
    assert once == {"detail": REDACTED, "drift": {"summary": [REDACTED, REDACTED]}}


def test_redact_tree_passes_through_non_string_scalar():
    # Non-string safe scalars pass through; a bounded string identifier no longer does.
    assert redact_tree(7) == 7
    assert redact_tree(True) is True
    assert redact_tree(None) is None
    assert redact_tree("production") == REDACTED


def test_redact_tree_redacts_bytes_leaf():
    # bytes is NOT a safe scalar (default-DENY) — it must be redacted, not passed through.
    assert redact_tree(b"123-45-6789") == REDACTED


def test_redact_tree_fails_closed_on_cycles():
    tree: dict = {"k": "v"}
    tree["self"] = tree  # cyclic
    out = redact_tree(tree)
    # customer-derived keys become positional placeholders; cycle broken, not infinite recursion.
    assert out["redacted_key_0"] == REDACTED
    assert out["redacted_key_1"] == REDACTED


def test_redact_node_tags_default_redacts_all_values_and_sanitizes_keys():
    node = ResourceNode(
        id="vm1",
        name="vm1",
        type="Microsoft.Compute/virtualMachines",
        tags={
            "patientName": "AliceSmith",
            "patientSSN": "123-45-6789",
            "patientMRN": "MRN123456",
            "env": "prod",
            "costCenter": "1234",
        },
    )
    out = redact_node_tags(node)
    # Default-redact: NO customer tag key OR value survives (PLATFORM_SAFE_TAG_KEYS is empty) —
    # every key becomes a distinct positional placeholder and every value the sentinel, so PII like
    # AliceSmith/123-45-6789/MRN123456 can never egress verbatim as a key OR a value.
    assert out.tags == {
        "redacted_key_0": REDACTED,
        "redacted_key_1": REDACTED,
        "redacted_key_2": REDACTED,
        "redacted_key_3": REDACTED,
        "redacted_key_4": REDACTED,
    }
    # No original PII key survives.
    assert not ({"patientName", "patientSSN", "patientMRN"} & set(out.tags))
    # Original node is not mutated (egress operates on a copy).
    assert node.tags["patientName"] == "AliceSmith"
    assert out.id == "vm1"


def test_redact_node_tags_sanitizes_pii_tag_key():
    # A tag KEY is customer-controlled and may itself be PII — it is redacted (key AND value) so it
    # cannot egress verbatim.
    node = ResourceNode(
        id="vm1", name="vm1", type="t", tags={"alice@contoso.com": "whatever"}
    )
    out = redact_node_tags(node)
    assert out.tags == {"redacted_key_0": REDACTED}
    assert "alice@contoso.com" not in out.tags


def test_redact_node_tags_platform_safe_key_value_passes_through(monkeypatch):
    # If the platform DOES own a tag key, its value is allow-listed through verbatim; the default
    # (empty allow-list) redacts everything.
    monkeypatch.setattr(contracts, "PLATFORM_SAFE_TAG_KEYS", frozenset({"aegis:managed"}))
    node = ResourceNode(
        id="vm1", name="vm1", type="t",
        tags={"aegis:managed": "true", "patientName": "AliceSmith"},
    )
    out = redact_node_tags(node)
    assert out.tags["aegis:managed"] == "true"  # platform-owned key → survives + value preserved
    assert out.tags["redacted_key_1"] == REDACTED  # customer key → placeholder + value redacted
    assert "patientName" not in out.tags


def test_redact_node_tags_is_idempotent():
    node = ResourceNode(
        id="vm1", name="vm1", type="t", tags={"env": "prod", "alice@contoso.com": "x"}
    )
    once = redact_node_tags(node)
    twice = redact_node_tags(once)
    assert twice.tags == once.tags


def test_redact_node_tags_empty_tags_is_noop():
    node = ResourceNode(id="vm1", name="vm1", type="t")
    assert redact_node_tags(node).tags == {}


def test_platform_safe_tag_keys_is_empty_by_default():
    # No platform-owned resource tag exists today, so the allow-list is intentionally empty (safe
    # default = redact every customer tag value).
    assert not PLATFORM_SAFE_TAG_KEYS


def test_metric_label_key_enum_is_exactly_module_and_outcome():
    assert {k.value for k in MetricLabelKey} == {"module", "outcome"}


def test_metric_sample_view_bounds_labels_on_construction():
    view = MetricSampleView.from_sample(
        MetricSample(
            name="module_runs_total",
            labels={"module": "discovery", "outcome": "ok", "secret": "a@b.com"},
            value=3,
        )
    )
    dumped = view.model_dump(mode="json")
    assert dumped["labels"] == {"module": "discovery", "outcome": "ok"}
    assert "secret" not in dumped["labels"]


def test_duration_sample_view_bounds_labels_and_redacts():
    view = DurationSampleView.from_sample(
        DurationSample(
            name="module_run_duration_ms",
            labels={"module": "discovery", "op": "scan", "outcome": "/subscriptions/x"},
            count=1,
            totalMs=5.0,
            minMs=5.0,
            maxMs=5.0,
        )
    )
    dumped = view.model_dump(mode="json")
    assert set(dumped["labels"]) == {"module", "outcome"}
    assert dumped["labels"]["outcome"] == REDACTED


def test_metrics_snapshot_view_projects_whole_snapshot():
    snap = MetricsSnapshot(
        counters=[
            MetricSample(name="c", labels={"module": "m", "pii": "a@b.com"}, value=1),
        ],
        durations=[
            DurationSample(
                name="d",
                labels={"kind": "x"},
                count=1,
                totalMs=1.0,
                minMs=1.0,
                maxMs=1.0,
            )
        ],
    )
    view = MetricsSnapshotView.from_snapshot(snap)
    dumped = view.model_dump(mode="json")
    assert dumped["counters"][0]["labels"] == {"module": "m"}
    # An entirely non-allow-listed label map collapses to empty on egress.
    assert dumped["durations"][0]["labels"] == {}
