"""Pure grounding-gate tests for the advisory RCA explanation (issue #54).

The gate (:mod:`modules.aiops.rca_grounding`) is deterministic and I/O-free: it must ACCEPT a
faithful natural-language summary that only names cited evidence and REJECT any explanation that
introduces an entity (resource id / nodeId / metric name) that is NOT in the RCA's cited fields.

All fixtures are clearly-fake synthetic data (guardrail 2) — no real ids, secrets, or PII.
"""
from __future__ import annotations

from modules.aiops.rca_grounding import (
    candidate_entity_tokens,
    evidence_corpus,
    ground_or_reject,
    is_grounded,
)
from shared.contracts import AgentResponse, SourceReference

# Synthetic, obviously-fake cited evidence: a fake node id, a fake resource path, a fake metric.
_CITED_NODE = "node-fake-01"
_CITED_RESOURCE = "/subscriptions/00000000/rg/synthetic/widget-01"
_CITED_METRIC = "cpu_saturation_ratio"

# A fabricated entity that is NOT cited anywhere — the hallucination the gate must catch.
_HALLUCINATED_RESOURCE = "/subscriptions/99999999/rg/ghost/phantom-99"
_HALLUCINATED_METRIC = "disk_latency_p99"


def _response(confidence: float = 0.9) -> AgentResponse:
    return AgentResponse(
        agentName="aiops",
        taskType="auto-rca",
        inputSummary="synthetic",
        findings=[f"{_CITED_NODE} shows {_CITED_METRIC} above threshold"],
        risks=["availability degraded for the widget workload"],
        recommendations=["investigate the cited node"],
        sourceReferences=[
            SourceReference(kind="resource", id=_CITED_RESOURCE, detail=None),
            SourceReference(kind="metric", id=_CITED_METRIC, detail="observed breach"),
        ],
        confidence=confidence,
        nextActions=["auto-rca"],
    )


def test_evidence_corpus_includes_cited_tokens_and_path_segments() -> None:
    corpus = evidence_corpus(_response())
    assert _CITED_NODE in corpus
    assert _CITED_METRIC in corpus
    # The full path AND its short segment are both grounded so a faithful summary may use either.
    assert _CITED_RESOURCE.strip("/").lower() in corpus
    assert "widget-01" in corpus


def test_faithful_summary_is_grounded_and_accepted() -> None:
    response = _response()
    explanation = (
        f"The evidence indicates {_CITED_NODE} breached {_CITED_METRIC}; an operator should "
        "review the cited widget-01 resource before taking action."
    )
    assert is_grounded(response, explanation) is True
    assert ground_or_reject(response, explanation) == explanation.strip()


def test_pure_prose_with_no_entities_is_trivially_grounded() -> None:
    response = _response()
    explanation = (
        "The root-cause analysis suggests a resource is saturated; a human operator should review "
        "the cited evidence and decide on remediation. This is advisory only."
    )
    assert is_grounded(response, explanation) is True
    assert ground_or_reject(response, explanation) == explanation.strip()


def test_hallucinated_resource_id_is_rejected() -> None:
    response = _response()
    explanation = (
        f"The failure originates from {_HALLUCINATED_RESOURCE}, which is overloaded."
    )
    assert is_grounded(response, explanation) is False
    assert ground_or_reject(response, explanation) is None


def test_hallucinated_metric_name_is_rejected() -> None:
    response = _response()
    explanation = f"The node is affected by {_HALLUCINATED_METRIC} spikes."
    assert is_grounded(response, explanation) is False
    assert ground_or_reject(response, explanation) is None


def test_candidate_entity_tokens_ignores_plain_english() -> None:
    tokens = candidate_entity_tokens(
        "the resource is saturated and availability is degraded for operators"
    )
    assert tokens == set()


def test_candidate_entity_tokens_detects_identifier_shapes() -> None:
    tokens = candidate_entity_tokens(
        f"see {_HALLUCINATED_RESOURCE} and {_HALLUCINATED_METRIC}"
    )
    assert any("phantom-99" in t or "99999999" in t for t in tokens)
    assert _HALLUCINATED_METRIC in tokens


def test_blank_explanation_is_treated_as_none() -> None:
    assert ground_or_reject(_response(), "   ") is None
    assert ground_or_reject(_response(), "") is None


# --- HIGH-1 hardening: proven bypasses that must now fail closed ---------------------------------


def test_dotted_hostname_fqdn_is_rejected() -> None:
    # Pure dotted host (no digit/hyphen/underscore/slash) previously slipped through.
    response = _response()
    explanation = "The traffic is redirected to patchserver.attacker.example.com by the fault."
    assert is_grounded(response, explanation) is False
    assert ground_or_reject(response, explanation) is None


def test_email_domain_is_grounded_against_citations() -> None:
    response = _response()
    explanation = "Contact soc@patchserver.attacker.example.com about the outage."
    # The email domain is an entity that is NOT cited → rejected.
    assert is_grounded(response, explanation) is False
    assert ground_or_reject(response, explanation) is None
    # Its domain must be one of the candidates (email split on '@'). Compare by exact
    # equality against each extracted token (not a substring ``in`` test) so this membership
    # assertion is not misread as URL-substring sanitization.
    candidates = candidate_entity_tokens(explanation)
    assert any(token == "patchserver.attacker.example.com" for token in candidates)


def test_uncited_ipv4_is_rejected() -> None:
    response = _response()
    explanation = "The node at 203.0.113.7 is unreachable."
    assert is_grounded(response, explanation) is False
    assert ground_or_reject(response, explanation) is None


def test_prose_with_abbreviations_stays_grounded() -> None:
    # e.g. / i.e. / etc. must NOT read as hostnames — faithful prose using them stays grounded.
    response = _response()
    explanation = (
        "The evidence indicates saturation, e.g. sustained load; the operator should review the "
        "cited node, i.e. the widget-01 resource, before acting, etc."
    )
    assert is_grounded(response, explanation) is True
    assert ground_or_reject(response, explanation) == explanation.strip()


def test_unicode_nonbreaking_hyphen_evasion_is_rejected() -> None:
    # U+2011 non-breaking hyphen previously split phantom-99 into non-entity fragments.
    response = _response()
    explanation = "Node phantom\u201199 is the culprit."
    assert is_grounded(response, explanation) is False
    assert ground_or_reject(response, explanation) is None


def test_zero_width_joiner_evasion_is_rejected() -> None:
    # A zero-width joiner between letters and digits must not hide an identifier.
    response = _response()
    explanation = "Node phantom\u200d99 is the culprit."
    assert is_grounded(response, explanation) is False
    assert ground_or_reject(response, explanation) is None


def test_non_ascii_homoglyph_token_requires_exact_citation() -> None:
    # A Cyrillic-homoglyph resource name is a non-ASCII entity that is not cited → rejected.
    response = _response()
    explanation = "The failure is in wid\u0433et-01 (a look-alike)."
    assert is_grounded(response, explanation) is False
    assert ground_or_reject(response, explanation) is None


def test_segment_recombination_is_rejected() -> None:
    # Every segment below is cited, but ACROSS DIFFERENT references — the FULL fabricated path was
    # never cited, so recombining segments into a new resource id must fail closed.
    response = AgentResponse(
        agentName="aiops",
        taskType="auto-rca",
        inputSummary="synthetic",
        findings=["subscriptions and rg observed"],
        risks=["widget-02 degraded"],
        recommendations=["review the a group"],
        sourceReferences=[
            SourceReference(kind="resource", id="subscriptions", detail=None),
            SourceReference(kind="resource", id="00000000", detail=None),
            SourceReference(kind="resource", id="rg", detail=None),
            SourceReference(kind="resource", id="a", detail=None),
            SourceReference(kind="resource", id="widget-02", detail=None),
        ],
        confidence=0.9,
        nextActions=["auto-rca"],
    )
    fabricated = "The failure is in /subscriptions/00000000/rg/a/widget-02."
    assert is_grounded(response, fabricated) is False
    assert ground_or_reject(response, fabricated) is None


def test_single_cited_segment_naming_still_grounds() -> None:
    # A faithful summary naming a single cited path segment (widget-01) stays grounded.
    response = _response()
    explanation = "The widget-01 resource is saturated per the cited evidence."
    assert is_grounded(response, explanation) is True
    assert ground_or_reject(response, explanation) == explanation.strip()


def test_faithful_full_path_still_grounds() -> None:
    # Naming the full cited resource path verbatim stays grounded (exact corpus match).
    response = _response()
    explanation = f"The resource {_CITED_RESOURCE} is implicated by the cited evidence."
    assert is_grounded(response, explanation) is True
    assert ground_or_reject(response, explanation) == explanation.strip()


def test_empty_corpus_grounds_nothing() -> None:
    # With no cited evidence, you cannot ground on nothing — any non-empty explanation is rejected,
    # even one with no entity tokens at all.
    empty = AgentResponse(
        agentName="aiops",
        taskType="auto-rca",
        inputSummary="synthetic",
        findings=[],
        risks=[],
        recommendations=[],
        sourceReferences=[],
        confidence=0.9,
        nextActions=[],
    )
    assert ground_or_reject(empty, "The database is corrupted and must be restored.") is None


def test_decimal_and_zscore_are_not_entities() -> None:
    # Plain decimals / z-scores must not be misread as IPs or hostnames (no false rejects). The
    # hyphenated word "z-score" is benign platform vocabulary, so the only tokens here are decimals.
    assert candidate_entity_tokens("confidence 0.90 with a score of 3.5 and 99.9% load") == set()


# --- HIGH-1 (round 2): IPv6 literals and fabricated numbers must fail closed ---------------------


def _response_citing(*parts: str, confidence: float = 0.9) -> AgentResponse:
    """A response whose findings are exactly ``parts`` (clearly-fake synthetic evidence)."""
    return AgentResponse(
        agentName="aiops",
        taskType="auto-rca",
        inputSummary="synthetic",
        findings=list(parts),
        risks=[],
        recommendations=[],
        sourceReferences=[SourceReference(kind="resource", id=parts[0], detail=None)],
        confidence=confidence,
        nextActions=[],
    )


def test_uncited_ipv6_compressed_is_rejected() -> None:
    response = _response()
    explanation = "The failing loopback host is ::1 per the trace."
    assert is_grounded(response, explanation) is False
    assert ground_or_reject(response, explanation) is None


def test_uncited_ipv6_expanded_is_rejected() -> None:
    response = _response()
    explanation = "The node at 2001:0:0:0:0:0:0:1 is unreachable."
    assert is_grounded(response, explanation) is False
    assert ground_or_reject(response, explanation) is None


def test_cited_ipv6_grounds_and_matches_compressed_and_expanded() -> None:
    # A cited IPv6 (compressed) grounds whether the model names it compressed or expanded — they
    # are compared in canonical form.
    response = _response_citing("host 2001:db8::1 is saturated")
    assert is_grounded(response, "The host 2001:db8::1 is implicated.") is True
    assert is_grounded(response, "The host 2001:db8:0:0:0:0:0:1 is implicated.") is True
    assert (
        ground_or_reject(response, "The host 2001:db8::1 is implicated.")
        == "The host 2001:db8::1 is implicated."
    )


def test_fabricated_numbers_are_rejected() -> None:
    # Pure numbers were previously ignored, so fabricated statistics passed. Now every number in the
    # output must appear in the cited numeric set.
    response = _response()
    explanation = "The saturation reached 97 percent across 12 nodes."
    assert is_grounded(response, explanation) is False
    assert ground_or_reject(response, explanation) is None


def test_cited_number_grounds() -> None:
    response = _response_citing("cpu_saturation_ratio reached 87 on the cited node")
    explanation = "The cited metric reached 87 at peak."
    assert is_grounded(response, explanation) is True
    assert ground_or_reject(response, explanation) == explanation.strip()


def test_confidence_value_grounds() -> None:
    # The RCA confidence is part of the cited numeric set, so naming it does not fail closed.
    response = _response(confidence=0.9)
    explanation = "The cited node-fake-01 analysis carries confidence 0.9."
    assert is_grounded(response, explanation) is True
    assert ground_or_reject(response, explanation) == explanation.strip()


# --- MED-4: digit-fragments inside entity tokens (GUIDs, resource ids, versions) are NOT numbers --

_AZ_RESOURCE_ID = (
    "/subscriptions/3f2504e0-4f89-41d3-9a0c-0305e82c3301"
    "/resourceGroups/rg-fake/providers/Microsoft.Compute/virtualMachines/vm-01"
)


def _response_azure_ids(confidence: float = 0.5) -> AgentResponse:
    """An RCA citing a realistic Azure resource id (GUID) + a ``1.4.0`` version detail — no bare
    quantities are cited, so ONLY the confidence should populate the numeric corpus."""
    return AgentResponse(
        agentName="aiops",
        taskType="auto-rca",
        inputSummary="synthetic",
        findings=["the cited resource is saturated"],
        risks=[],
        recommendations=[],
        sourceReferences=[
            SourceReference(kind="resource", id=_AZ_RESOURCE_ID, detail="pack version 1.4.0"),
        ],
        confidence=confidence,
        nextActions=[],
    )


def test_fabricated_numbers_not_harvested_from_guid_or_version() -> None:
    # The GUID/resource-id/version digit fragments must NOT pollute the cited number corpus, so all
    # of these fabricated statistics fail closed (previously they falsely grounded).
    response = _response_azure_ids(confidence=0.5)
    for fabricated in (
        "Availability fell to 89 percent.",
        "Only 4 replicas recovered.",
        "There were 0 successful probes.",
        "The backlog hit 12,000 messages.",
        "The delta was -12 units.",
    ):
        assert is_grounded(response, fabricated) is False, fabricated
        assert ground_or_reject(response, fabricated) is None, fabricated
    # The genuine confidence quantity still grounds.
    assert is_grounded(response, "The analysis confidence is 0.5.") is True


def test_genuinely_cited_number_still_grounds() -> None:
    response = AgentResponse(
        agentName="aiops",
        taskType="auto-rca",
        inputSummary="synthetic",
        findings=["error rate reached 89 percent on the cited node"],
        risks=[],
        recommendations=[],
        sourceReferences=[SourceReference(kind="metric", id="error_rate", detail=None)],
        confidence=0.9,
        nextActions=[],
    )
    assert is_grounded(response, "error_rate was 89 percent at peak.") is True
    assert ground_or_reject(response, "error_rate was 89 percent at peak.") is not None


def test_grouped_thousands_ground_canonically() -> None:
    response = AgentResponse(
        agentName="aiops",
        taskType="auto-rca",
        inputSummary="synthetic",
        findings=["the queue backlog reached 12,000 messages"],
        risks=[],
        recommendations=[],
        sourceReferences=[SourceReference(kind="metric", id="queue_backlog", detail=None)],
        confidence=0.9,
        nextActions=[],
    )
    # Grouped and un-grouped forms of the SAME quantity both ground (canonical Decimal compare).
    assert is_grounded(response, "queue_backlog was 12,000.") is True
    assert is_grounded(response, "queue_backlog was 12000.") is True
    # A different quantity does not.
    assert is_grounded(response, "queue_backlog was 13,000.") is False


# --- MED-4 (v5): operator-glued numbers, version/hex/exp shapes, and .5 collision fail closed ---


def test_operator_glued_numbers_fail_closed_when_uncited() -> None:
    # A digit run glued to an operator ('%', '$', '#', '~') was previously seen by NEITHER path (the
    # number path could not fullmatch it and the entity path split it to a bare, non-entity number),
    # so a fabricated statistic slipped through. Now the shared tokenizer splits the operator off
    # and the bare quantity must appear in the cited numeric set.
    response = _response()  # numeric corpus == {confidence 0.9}
    for fabricated in (
        "Utilisation hit 97% at peak.",
        "The cost was $18000 last month.",
        "Incident #4711 is the cause.",
        "Latency spiked by ~450 units.",
    ):
        assert is_grounded(response, fabricated) is False, fabricated
        assert ground_or_reject(response, fabricated) is None, fabricated


def test_operator_glued_number_grounds_when_cited() -> None:
    # A genuinely cited '97' (however the output writes it) grounds; '97%' -> 97 symmetrically.
    response = _response_citing("cpu_saturation_ratio reached 97 on the cited node")
    assert is_grounded(response, "cpu_saturation_ratio was 97%.") is True
    assert is_grounded(response, "cpu_saturation_ratio was 97 percent.") is True
    # And a cited '97%' grounds an output '97'.
    cited_pct = _response_citing("cpu_saturation_ratio reached 97% on the cited node")
    assert is_grounded(cited_pct, "cpu_saturation_ratio reached 97 at peak.") is True


def test_version_hex_exponent_shapes_are_entities_fail_closed() -> None:
    # A version '9.9.9', a hex '0x1f', an exponent '1e3', a ratio '24/7' and a malformed group
    # '12,34' / Indian grouping '1,00,000' are all digit-bearing NON-numeric tokens: entities that
    # must be cited EXACTLY. Uncited, each fails closed (none is silently ignored as before).
    response = _response()
    for fabricated in (
        "The pack is on version 9.9.9 now.",
        "The mask is 0x1f as observed.",
        "The rate was 1e3 requests.",
        "It runs 24/7 without pause.",
        "The value was 12,34 exactly.",
        "The total was 1,00,000 items.",
    ):
        assert is_grounded(response, fabricated) is False, fabricated
        assert ground_or_reject(response, fabricated) is None, fabricated


def test_cited_version_grounds_exactly() -> None:
    # The version cited in a sourceReference detail grounds when named verbatim.
    response = _response_azure_ids(confidence=0.5)  # cites '... pack version 1.4.0'
    assert is_grounded(response, "The cited pack version 1.4.0 is implicated.") is True
    # A different version does NOT ground (exact entity match).
    assert is_grounded(response, "The cited pack version 1.4.1 is implicated.") is False


def test_leading_dot_number_does_not_collide_with_cited_integer() -> None:
    # '.5' must NOT be parsed as the integer 5: with cited '5' present as a quantity, an output '.5'
    # is a DISTINCT digit-bearing entity token that is not cited -> fail closed.
    response = _response_citing("cpu_saturation_ratio reached 5 on the cited node")
    assert is_grounded(response, "cpu_saturation_ratio was 5 at peak.") is True  # cited integer
    assert is_grounded(response, "cpu_saturation_ratio was .5 at peak.") is False  # fabricated '.5'
    assert ground_or_reject(response, "the ratio was .5 exactly.") is None


def test_number_only_citation_grounds_its_quantity() -> None:
    # An RCA that cites only a number (no entity) can still ground that exact quantity, and rejects
    # a fabricated one — the "nothing cited" fail-closed only triggers when confidence is the sole
    # number and there is no entity/IP.
    response = AgentResponse(
        agentName="aiops",
        taskType="auto-rca",
        inputSummary="synthetic",
        findings=["the observed count reached 42"],
        risks=[],
        recommendations=[],
        sourceReferences=[],
        confidence=0.9,
        nextActions=[],
    )
    assert is_grounded(response, "the count was 42.") is True
    assert is_grounded(response, "the count was 43.") is False


# --- MED-4 residual (v6): plain-Decimal compare — no precision-boundary collision, controls hold --


def test_long_numbers_differing_in_last_digit_do_not_collide() -> None:
    # Two 61-digit quantities differing ONLY in the final digit must be DISTINCT: a model that
    # alters the trailing digits of a cited large number must fail closed (the old fixed-precision
    # normalize could round them together beyond the 60-digit boundary).
    cited = "1" + "0" * 59 + "1"  # 61 digits, ...0001
    fabricated = "1" + "0" * 59 + "2"  # 61 digits, ...0002 (differs only in the last digit)
    response = _response_citing(f"the observed count reached {cited}")
    assert is_grounded(response, f"the count was {cited}.") is True
    assert is_grounded(response, f"the count was {fabricated}.") is False
    assert ground_or_reject(response, f"the count was {fabricated}.") is None


def test_decimal_equality_controls_still_hold() -> None:
    # Plain Decimal equality still equates grouping/trailing-zero forms exactly and keeps signs and
    # the confidence value distinct — no normalize/localcontext needed.
    grouped = AgentResponse(
        agentName="aiops",
        taskType="auto-rca",
        inputSummary="synthetic",
        findings=["the queue backlog reached 12,000 messages and 0.90 error ratio"],
        risks=[],
        recommendations=[],
        sourceReferences=[SourceReference(kind="metric", id="queue_backlog", detail=None)],
        confidence=0.6,
        nextActions=[],
    )
    # Grouped <-> un-grouped and trailing-zero forms ground either direction.
    assert is_grounded(grouped, "queue_backlog was 12000.") is True
    assert is_grounded(grouped, "queue_backlog was 12,000.") is True
    assert is_grounded(grouped, "the error ratio was 0.9.") is True
    # The confidence value (0.6) grounds as a cited quantity.
    assert is_grounded(grouped, "the model confidence was 0.6.") is True
    # A sign flip is a DIFFERENT quantity — fabricated -12,000 rejects.
    assert is_grounded(grouped, "queue_backlog was -12000.") is False



