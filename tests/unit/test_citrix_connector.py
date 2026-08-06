"""Citrix connector — fail-closed-by-default, supplement-only, PII-safe edge + pure mapping.

All fixtures are obviously synthetic (zeroed GUIDs, fake hosts, no PII/PHI); there is no real
network, credential, or Citrix schema. Tests exercise the pure validators/mapping and the network
edge via ``httpx.MockTransport`` — never a real socket.
"""
from __future__ import annotations

import gzip
import importlib
import sys
import time

import httpx
import pytest

from modules.dependency_graph.connectors.citrix import (
    ALLOWED_HEALTH,
    EDGE_ORIGIN,
    MAX_RESOURCE_ID_LEN,
    SUPPLEMENTAL_HEALTH_TAG,
    SUPPLEMENTAL_SOURCE,
    SUPPLEMENTAL_SOURCE_TAG,
    CitrixClient,
    CitrixConfig,
    CitrixConnector,
    CitrixDependencyHint,
    CitrixEndpointNotApproved,
    CitrixHealthHint,
    CitrixSignalError,
    InvalidCitrixEndpoint,
    apply_supplemental,
    dependency_edges,
    parse_signals_atomic,
    signals_from_result,
    to_source_reference,
    validate_dependency_hint,
    validate_endpoint,
    validate_health_hint,
)
from shared.connectors import FetchResult, TokenProvider
from shared.contracts import EdgeType, ResourceNode
from support.connectors import (
    FAKE_CITRIX_TARGET_ID,
    FAKE_RESOURCE_ID,
    MockCitrixTokenProvider,
    RecordingSleep,
    flaky_transport,
    raising_transport,
    synthetic_citrix_dependency,
    synthetic_citrix_health,
)

# A clearly-fake, non-placeholder, operator-approved host used across the edge tests.
APPROVED_HOST = "citrix.approved.test"
APPROVED_BASE_URL = f"https://{APPROVED_HOST}"


def _config(**overrides: object) -> CitrixConfig:
    base: dict[str, object] = {
        "base_url": APPROVED_BASE_URL,
        "approved_hosts": (APPROVED_HOST,),
    }
    base.update(overrides)
    return CitrixConfig(**base)  # type: ignore[arg-type]


def _node(node_id: str = FAKE_RESOURCE_ID, *, role: str | None = "vda") -> ResourceNode:
    """A synthetic already-discovered estate node (authoritative)."""
    return ResourceNode(
        id=node_id, name="vda-01", type="Fake.Compute/widgets", workload="epic",
        tier="presentation", role=role, tags={"epic-role": "vda"},
    )


# --------------------------------------------------------------------------------------
# validate_endpoint — credential-exfil safety
# --------------------------------------------------------------------------------------
def test_validate_endpoint_accepts_approved_https() -> None:
    url = validate_endpoint(APPROVED_BASE_URL, "/v1/control-plane/signals", (APPROVED_HOST,))
    assert url == f"{APPROVED_BASE_URL}/v1/control-plane/signals"


def test_validate_endpoint_rejects_http() -> None:
    with pytest.raises(InvalidCitrixEndpoint):
        validate_endpoint(f"http://{APPROVED_HOST}", "/v1/x", (APPROVED_HOST,))


def test_validate_endpoint_rejects_non_https_scheme() -> None:
    with pytest.raises(InvalidCitrixEndpoint):
        validate_endpoint(f"ftp://{APPROVED_HOST}", "/v1/x", (APPROVED_HOST,))


def test_validate_endpoint_rejects_empty_base_url() -> None:
    with pytest.raises(InvalidCitrixEndpoint):
        validate_endpoint("", "/v1/x", (APPROVED_HOST,))


@pytest.mark.parametrize("host", ["citrix.internal", "localhost", "example.com", "placeholder"])
def test_validate_endpoint_rejects_placeholder_host_even_if_allowlisted(host: str) -> None:
    with pytest.raises(InvalidCitrixEndpoint):
        validate_endpoint(f"https://{host}", "/v1/x", (host,))


def test_validate_endpoint_rejects_userinfo() -> None:
    # A REAL userinfo URL (``user:pass@host``) must trip the dedicated userinfo guard — not the
    # scheme check — so this exercises the credential-exfil control at that specific line.
    with pytest.raises(InvalidCitrixEndpoint, match="userinfo"):
        validate_endpoint(f"https://user:pass@{APPROVED_HOST}", "/v1/x", (APPROVED_HOST,))


def test_validate_endpoint_rejects_userinfo_username_only() -> None:
    with pytest.raises(InvalidCitrixEndpoint, match="userinfo"):
        validate_endpoint(f"https://user@{APPROVED_HOST}", "/v1/x", (APPROVED_HOST,))


def test_validate_endpoint_rejects_query() -> None:
    with pytest.raises(InvalidCitrixEndpoint):
        validate_endpoint(f"{APPROVED_BASE_URL}?a=1", "/v1/x", (APPROVED_HOST,))


def test_validate_endpoint_rejects_fragment() -> None:
    with pytest.raises(InvalidCitrixEndpoint):
        validate_endpoint(f"{APPROVED_BASE_URL}#frag", "/v1/x", (APPROVED_HOST,))


def test_validate_endpoint_rejects_host_not_on_allowlist() -> None:
    with pytest.raises(CitrixEndpointNotApproved):
        validate_endpoint(APPROVED_BASE_URL, "/v1/x", ())


@pytest.mark.parametrize("bad_path", ["v1/x", "/v1/x?y=1", "/v1/x#f", "/v1 x", "/v1@x"])
def test_validate_endpoint_rejects_unsafe_path(bad_path: str) -> None:
    with pytest.raises(InvalidCitrixEndpoint):
        validate_endpoint(APPROVED_BASE_URL, bad_path, (APPROVED_HOST,))


# --- canonicalization bypass attempts (trailing dot / explicit port / IDN / IP literal) ----------
def test_validate_endpoint_rejects_trailing_dot_placeholder_host() -> None:
    with pytest.raises(InvalidCitrixEndpoint):
        validate_endpoint("https://localhost.", "/v1/x", ("localhost.",))


def test_validate_endpoint_trailing_dot_matches_canonical_placeholder() -> None:
    with pytest.raises(InvalidCitrixEndpoint):
        validate_endpoint("https://example.com.", "/v1/x", ("example.com",))


def test_validate_endpoint_rejects_explicit_port() -> None:
    with pytest.raises(InvalidCitrixEndpoint):
        validate_endpoint(f"https://{APPROVED_HOST}:4443", "/v1/x", (APPROVED_HOST,))


def test_validate_endpoint_rejects_explicit_port_even_when_hostport_allowlisted() -> None:
    with pytest.raises(InvalidCitrixEndpoint):
        validate_endpoint(
            f"https://{APPROVED_HOST}:4443", "/v1/x", (APPROVED_HOST, f"{APPROVED_HOST}:4443")
        )


@pytest.mark.parametrize("loopback", ["https://127.0.0.1", "https://[::1]", "https://169.254.1.1"])
def test_validate_endpoint_rejects_ip_literal_hosts(loopback: str) -> None:
    host = loopback.removeprefix("https://").strip("[]")
    with pytest.raises(InvalidCitrixEndpoint):
        validate_endpoint(loopback, "/v1/x", (host,))


def test_validate_endpoint_trailing_dot_matches_approved_host() -> None:
    url = validate_endpoint(f"https://{APPROVED_HOST}.", "/v1/x", (APPROVED_HOST,))
    assert url == f"https://{APPROVED_HOST}/v1/x"


def test_validate_endpoint_idn_host_returns_punycode_request_target() -> None:
    url = validate_endpoint("https://münchen.example", "/v1/x", ("xn--mnchen-3ya.example",))
    assert url == "https://xn--mnchen-3ya.example/v1/x"
    punycode = validate_endpoint(
        "https://xn--mnchen-3ya.example", "/v1/x", ("münchen.example",)
    )
    assert punycode == "https://xn--mnchen-3ya.example/v1/x"


def test_validate_endpoint_rejects_confusable_idna2003_host() -> None:
    # ``straße`` maps to ``strasse`` under the LEGACY stdlib idna codec but to ``xn--strae-oqa``
    # under HTTPX's idna. Allow-listing the legacy form must NOT admit the confusable.
    with pytest.raises(CitrixEndpointNotApproved):
        validate_endpoint("https://straße.example", "/v1/x", ("strasse.example",))


def test_validate_endpoint_fails_closed_on_idna_encoding_error() -> None:
    with pytest.raises(InvalidCitrixEndpoint):
        validate_endpoint("https://\U0001f600.example", "/v1/x", ("\U0001f600.example",))


@pytest.mark.parametrize("numeric_host", ["0177.0.0.1", "0x7f.0.0.1", "2130706433", "127.1"])
def test_validate_endpoint_rejects_legacy_numeric_ipv4_literals(numeric_host: str) -> None:
    with pytest.raises(InvalidCitrixEndpoint):
        validate_endpoint(f"https://{numeric_host}", "/v1/x", (numeric_host,))


# --------------------------------------------------------------------------------------
# validate_health_hint / validate_dependency_hint — PII-safe, closed vocabulary
# --------------------------------------------------------------------------------------
def test_validate_health_hint_accepts_well_formed() -> None:
    hint = validate_health_hint(synthetic_citrix_health(), max_field_len=512)
    assert hint.resource_id == FAKE_RESOURCE_ID
    assert hint.health == "degraded"


def test_validate_health_hint_rejects_unexpected_key_pii_smuggle() -> None:
    raw = synthetic_citrix_health()
    raw["name"] = "jane.doe@example.com"
    with pytest.raises(CitrixSignalError):
        validate_health_hint(raw, max_field_len=512)


def test_validate_health_hint_rejects_email_in_resource_id() -> None:
    with pytest.raises(CitrixSignalError):
        validate_health_hint(
            synthetic_citrix_health(resource_id="jane.doe@example.com"), max_field_len=512
        )


def test_validate_health_hint_rejects_unknown_kind() -> None:
    raw = synthetic_citrix_health()
    raw["kind"] = "dependency"
    with pytest.raises(CitrixSignalError):
        validate_health_hint(raw, max_field_len=512)


def test_validate_health_hint_rejects_health_outside_allowlist() -> None:
    with pytest.raises(CitrixSignalError):
        validate_health_hint(synthetic_citrix_health(health="totally-made-up"), max_field_len=512)


def test_validate_health_hint_rejects_missing_health() -> None:
    with pytest.raises(CitrixSignalError):
        validate_health_hint({"kind": "host-health", "resourceId": FAKE_RESOURCE_ID},
                             max_field_len=512)


def test_validate_health_hint_rejects_oversized_resource_id() -> None:
    with pytest.raises(CitrixSignalError):
        validate_health_hint(
            synthetic_citrix_health(resource_id="a" * 600), max_field_len=512
        )


def test_validate_health_hint_rejects_non_mapping() -> None:
    with pytest.raises(CitrixSignalError):
        validate_health_hint(["not", "a", "dict"], max_field_len=512)


def test_validate_dependency_hint_accepts_well_formed() -> None:
    hint = validate_dependency_hint(synthetic_citrix_dependency(), max_field_len=512)
    assert hint.resource_id == FAKE_RESOURCE_ID
    assert hint.depends_on == FAKE_CITRIX_TARGET_ID


def test_validate_dependency_hint_rejects_unexpected_key() -> None:
    raw = synthetic_citrix_dependency()
    raw["note"] = "free text"
    with pytest.raises(CitrixSignalError):
        validate_dependency_hint(raw, max_field_len=512)


def test_validate_dependency_hint_rejects_charset_invalid_endpoint() -> None:
    with pytest.raises(CitrixSignalError):
        validate_dependency_hint(
            synthetic_citrix_dependency(depends_on="jane.doe@example.com"), max_field_len=512
        )


def test_validate_dependency_hint_rejects_missing_depends_on() -> None:
    with pytest.raises(CitrixSignalError):
        validate_dependency_hint(
            {"kind": "session-dependency", "resourceId": FAKE_RESOURCE_ID}, max_field_len=512
        )


def test_allowed_health_is_closed_vocabulary() -> None:
    assert frozenset({"healthy", "degraded", "unreachable", "maintenance"}) == ALLOWED_HEALTH


def test_parse_signals_atomic_accepts_mixed_kinds() -> None:
    records = [
        synthetic_citrix_health(resource_id=FAKE_RESOURCE_ID, health="healthy"),
        synthetic_citrix_dependency(resource_id=FAKE_RESOURCE_ID, depends_on=FAKE_CITRIX_TARGET_ID),
    ]
    signals = parse_signals_atomic(records, max_records=10, max_field_len=512)
    assert len(signals.health) == 1
    assert len(signals.dependencies) == 1


def test_parse_signals_atomic_rejects_entire_batch_on_one_bad_record() -> None:
    good = synthetic_citrix_health()
    bad = synthetic_citrix_health(health="bogus")
    with pytest.raises(CitrixSignalError):
        parse_signals_atomic([good, bad], max_records=10, max_field_len=512)


def test_parse_signals_atomic_rejects_unknown_kind() -> None:
    with pytest.raises(CitrixSignalError):
        parse_signals_atomic([{"kind": "mystery", "resourceId": FAKE_RESOURCE_ID}],
                             max_records=10, max_field_len=512)


def test_parse_signals_atomic_rejects_too_many_records() -> None:
    records = [synthetic_citrix_health() for _ in range(5)]
    with pytest.raises(CitrixSignalError):
        parse_signals_atomic(records, max_records=4, max_field_len=512)


# --------------------------------------------------------------------------------------
# signals_from_result / apply_supplemental — supplement-only, estate always wins
# --------------------------------------------------------------------------------------
def test_signals_from_result_unavailable_yields_empty() -> None:
    signals = signals_from_result(FetchResult(available=False))
    assert signals.health == []
    assert signals.dependencies == []


def test_signals_from_result_rehydrates_normalized_records() -> None:
    result = FetchResult(
        available=True,
        raw=[
            {"kind": "host-health", "resource_id": FAKE_RESOURCE_ID, "health": "degraded"},
            {"kind": "session-dependency", "resource_id": FAKE_RESOURCE_ID,
             "depends_on": FAKE_CITRIX_TARGET_ID},
        ],
    )
    signals = signals_from_result(result)
    assert signals.health == [CitrixHealthHint(resource_id=FAKE_RESOURCE_ID, health="degraded")]
    assert signals.dependencies == [
        CitrixDependencyHint(resource_id=FAKE_RESOURCE_ID, depends_on=FAKE_CITRIX_TARGET_ID)
    ]


def test_citrix_health_hint_construction_rejects_pii_health() -> None:
    with pytest.raises(ValueError):
        CitrixHealthHint(resource_id=FAKE_RESOURCE_ID, health="patient=Jane-Doe")


def test_citrix_health_hint_construction_rejects_charset_invalid_resource_id() -> None:
    with pytest.raises(ValueError):
        CitrixHealthHint(resource_id="jane.doe@example.com", health="healthy")


def test_citrix_health_hint_construction_rejects_oversized_resource_id() -> None:
    with pytest.raises(ValueError):
        CitrixHealthHint(resource_id="a" * (MAX_RESOURCE_ID_LEN + 1), health="healthy")


def test_citrix_health_hint_model_validate_forbids_extra_key() -> None:
    with pytest.raises(ValueError):
        CitrixHealthHint.model_validate(
            {"resource_id": FAKE_RESOURCE_ID, "health": "healthy", "smuggled": "x"}
        )


@pytest.mark.parametrize(
    "raw",
    [
        {"kind": "host-health", "resource_id": FAKE_RESOURCE_ID, "health": "patient=Jane-Doe"},
        {"kind": "host-health", "resource_id": "jane.doe@example.com", "health": "healthy"},
        {"kind": "host-health", "resource_id": "a" * (MAX_RESOURCE_ID_LEN + 1),
         "health": "healthy"},
        {"kind": "host-health", "resource_id": FAKE_RESOURCE_ID, "health": "healthy", "leak": "x"},
        {"kind": "session-dependency", "resource_id": FAKE_RESOURCE_ID,
         "depends_on": "jane.doe@example.com"},
    ],
)
def test_signals_from_result_rejects_untrusted_malicious_raw(raw: dict[str, object]) -> None:
    # An INJECTED connector's unvalidated FetchResult.raw is re-validated here and rejected
    # atomically (fail closed) — nothing ever reaches a hint / persisted state.
    result = FetchResult(
        available=True,
        raw=[{"kind": "host-health", "resource_id": FAKE_RESOURCE_ID, "health": "healthy"}, raw],
    )
    with pytest.raises(CitrixSignalError):
        signals_from_result(result)


def test_signals_from_result_rejects_unknown_kind() -> None:
    result = FetchResult(available=True, raw=[{"kind": "mystery", "resource_id": FAKE_RESOURCE_ID}])
    with pytest.raises(CitrixSignalError):
        signals_from_result(result)


def test_apply_supplemental_annotates_matching_node_only() -> None:
    nodes = [_node(FAKE_RESOURCE_ID), _node("/other/id", role="web")]
    health = [CitrixHealthHint(resource_id=FAKE_RESOURCE_ID, health="degraded")]
    result = apply_supplemental(nodes, health)
    assert len(result.nodes) == 2  # nothing added or removed
    matched = next(n for n in result.nodes if n.id == FAKE_RESOURCE_ID)
    assert matched.tags[SUPPLEMENTAL_SOURCE_TAG] == SUPPLEMENTAL_SOURCE
    assert matched.tags[SUPPLEMENTAL_HEALTH_TAG] == "degraded"
    assert result.annotated_ids == [FAKE_RESOURCE_ID]
    other = next(n for n in result.nodes if n.id == "/other/id")
    assert SUPPLEMENTAL_SOURCE_TAG not in other.tags


def test_apply_supplemental_preserves_prior_connector_provenance() -> None:
    # A node already annotated by Kuiper (aegis:source=kuiper + aegis:kuiper-signal) must keep that
    # provenance when Citrix later annotates it: Citrix is UNIONED into aegis:source, never clobbers
    # it, and Kuiper's own signal tag survives untouched.
    kuiper_node = ResourceNode(
        id=FAKE_RESOURCE_ID, name="vda-01", type="Fake.Compute/widgets", workload="epic",
        tier="presentation", role="vda",
        tags={"aegis:source": "kuiper", "aegis:kuiper-signal": "corroborated"},
    )
    health = [CitrixHealthHint(resource_id=FAKE_RESOURCE_ID, health="degraded")]
    result = apply_supplemental([kuiper_node], health)
    annotated = result.nodes[0]
    # Both sources represented (sorted, comma-joined set) — neither erased.
    assert annotated.tags[SUPPLEMENTAL_SOURCE_TAG] == "citrix,kuiper"
    # Kuiper's own signal tag is untouched, and Citrix's health tag is added.
    assert annotated.tags["aegis:kuiper-signal"] == "corroborated"
    assert annotated.tags[SUPPLEMENTAL_HEALTH_TAG] == "degraded"
    assert result.annotated_ids == [FAKE_RESOURCE_ID]
    # Original object not mutated.
    assert kuiper_node.tags["aegis:source"] == "kuiper"


def test_apply_supplemental_source_tag_is_idempotent_for_citrix() -> None:
    # Re-annotating a node already tagged by Citrix keeps a single 'citrix' entry (set semantics).
    citrix_node = ResourceNode(
        id=FAKE_RESOURCE_ID, name="vda-01", type="Fake.Compute/widgets", workload="epic",
        tier="presentation", role="vda", tags={"aegis:source": "citrix"},
    )
    health = [CitrixHealthHint(resource_id=FAKE_RESOURCE_ID, health="healthy")]
    result = apply_supplemental([citrix_node], health)
    assert result.nodes[0].tags[SUPPLEMENTAL_SOURCE_TAG] == "citrix"


def test_apply_supplemental_never_mutates_authoritative_fields() -> None:
    original = _node(FAKE_RESOURCE_ID)
    health = [CitrixHealthHint(resource_id=FAKE_RESOURCE_ID, health="unreachable")]
    result = apply_supplemental([original], health)
    annotated = result.nodes[0]
    assert annotated.id == original.id
    assert annotated.name == original.name
    assert annotated.type == original.type
    assert annotated.workload == original.workload
    assert annotated.tier == original.tier
    assert annotated.role == original.role
    assert SUPPLEMENTAL_SOURCE_TAG not in original.tags  # original object not mutated


def test_apply_supplemental_drops_signal_matching_no_node() -> None:
    nodes = [_node(FAKE_RESOURCE_ID)]
    health = [CitrixHealthHint(resource_id="/subscriptions/0/rg/fake/nope", health="healthy")]
    result = apply_supplemental(nodes, health)
    assert result.annotated_ids == []
    assert all(SUPPLEMENTAL_SOURCE_TAG not in n.tags for n in result.nodes)
    assert len(result.nodes) == 1  # never creates a node from a signal


def test_apply_supplemental_revalidates_validator_bypass_constructions() -> None:
    # model_construct / model_copy(update=...) BYPASS pydantic validators; apply_supplemental is the
    # persistence-adjacent boundary and RE-VALIDATES every hint, dropping any violation.
    node = _node(FAKE_RESOURCE_ID)
    smuggled_health = CitrixHealthHint.model_construct(
        resource_id=FAKE_RESOURCE_ID, health="patient=Jane-Doe-MRN-123"
    )
    valid = CitrixHealthHint(resource_id=FAKE_RESOURCE_ID, health="healthy")
    copied_pii = valid.model_copy(update={"health": "patient=Jane-Doe"})
    smuggled_id = CitrixHealthHint.model_construct(
        resource_id="jane.doe@example.com", health="healthy"
    )
    result = apply_supplemental([node], [smuggled_health, copied_pii, smuggled_id])
    assert result.annotated_ids == []
    tags = result.nodes[0].tags
    assert SUPPLEMENTAL_SOURCE_TAG not in tags
    assert SUPPLEMENTAL_HEALTH_TAG not in tags
    for value in tags.values():
        assert "patient" not in value.lower() and "jane" not in value.lower()


# --------------------------------------------------------------------------------------
# dependency_edges — pure mapping, DEFERRED (never persisted)
# --------------------------------------------------------------------------------------
def test_dependency_edges_maps_only_both_endpoints_present() -> None:
    hints = [CitrixDependencyHint(resource_id=FAKE_RESOURCE_ID, depends_on=FAKE_CITRIX_TARGET_ID)]
    edges = dependency_edges(hints, {FAKE_RESOURCE_ID, FAKE_CITRIX_TARGET_ID})
    assert len(edges) == 1
    edge = edges[0]
    assert edge.source == FAKE_RESOURCE_ID
    assert edge.target == FAKE_CITRIX_TARGET_ID
    assert edge.type == EdgeType.depends_on
    assert edge.origin == EDGE_ORIGIN
    assert edge.redundant is False


def test_dependency_edges_drops_edge_with_unknown_endpoint() -> None:
    hints = [CitrixDependencyHint(resource_id=FAKE_RESOURCE_ID, depends_on=FAKE_CITRIX_TARGET_ID)]
    # Only one endpoint exists in the estate ⇒ no phantom-endpoint edge.
    assert dependency_edges(hints, {FAKE_RESOURCE_ID}) == []


def test_dependency_edges_drops_self_edge() -> None:
    hints = [CitrixDependencyHint(resource_id=FAKE_RESOURCE_ID, depends_on=FAKE_RESOURCE_ID)]
    assert dependency_edges(hints, {FAKE_RESOURCE_ID}) == []


def test_dependency_edges_dedupes() -> None:
    hints = [
        CitrixDependencyHint(resource_id=FAKE_RESOURCE_ID, depends_on=FAKE_CITRIX_TARGET_ID),
        CitrixDependencyHint(resource_id=FAKE_RESOURCE_ID, depends_on=FAKE_CITRIX_TARGET_ID),
    ]
    edges = dependency_edges(hints, {FAKE_RESOURCE_ID, FAKE_CITRIX_TARGET_ID})
    assert len(edges) == 1


def test_dependency_edges_drops_bypass_constructed_invalid_id() -> None:
    smuggled = CitrixDependencyHint.model_construct(
        resource_id="jane.doe@example.com", depends_on=FAKE_CITRIX_TARGET_ID
    )
    edges = dependency_edges([smuggled], {"jane.doe@example.com", FAKE_CITRIX_TARGET_ID})
    assert edges == []


def test_to_source_reference_cites_connector() -> None:
    ref = to_source_reference(FAKE_RESOURCE_ID)
    assert ref.kind == "connector"
    assert ref.id == SUPPLEMENTAL_SOURCE
    assert ref.detail == FAKE_RESOURCE_ID


# --------------------------------------------------------------------------------------
# Network edge — httpx.MockTransport, no real network
# --------------------------------------------------------------------------------------
def _raise_if_called(request: httpx.Request) -> httpx.Response:
    raise AssertionError("no HTTP request should have been made")


def _client_with(
    transport: httpx.MockTransport,
    *,
    config: CitrixConfig | None = None,
    credential_provider: TokenProvider | None = None,
    **kwargs: object,
) -> CitrixClient:
    cfg = config or _config()
    provider = credential_provider if credential_provider is not None else MockCitrixTokenProvider()
    http_client = httpx.Client(transport=transport)
    return CitrixClient(
        cfg, client=http_client, credential_provider=provider, **kwargs  # type: ignore[arg-type]
    )


def test_fetch_raw_success_returns_normalized_signals() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/control-plane/signals"
        return httpx.Response(200, json=[synthetic_citrix_health(resource_id=FAKE_RESOURCE_ID)])

    result = _client_with(httpx.MockTransport(handle)).fetch_raw()
    assert result.available is True
    assert result.raw == [
        {"kind": "host-health", "resource_id": FAKE_RESOURCE_ID, "health": "degraded"}
    ]


def test_fetch_raw_invalid_endpoint_fails_closed_without_resolving_credential() -> None:
    spy = MockCitrixTokenProvider()
    client = _client_with(
        httpx.MockTransport(_raise_if_called),
        config=_config(base_url="", approved_hosts=()),
        credential_provider=spy,
    )
    result = client.fetch_raw()
    assert result.available is False
    assert result.error == "InvalidCitrixEndpoint"
    assert spy.calls == 0  # credential NEVER resolved for an unvalidated endpoint


def test_fetch_raw_unapproved_host_fails_closed_without_credential() -> None:
    spy = MockCitrixTokenProvider()
    client = _client_with(
        httpx.MockTransport(_raise_if_called),
        config=_config(base_url="https://citrix.evil.test", approved_hosts=(APPROVED_HOST,)),
        credential_provider=spy,
    )
    result = client.fetch_raw()
    assert result.available is False
    assert result.error == "CitrixEndpointNotApproved"
    assert spy.calls == 0


def test_fetch_raw_no_token_provider_fails_closed_without_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CITRIX_READ_TOKEN", raising=False)
    result = _client_with(
        httpx.MockTransport(_raise_if_called),
        credential_provider=MockCitrixTokenProvider(token=None),
    ).fetch_raw()
    assert result.available is False
    assert result.error == "NoCredential"


def test_fetch_raw_sends_bearer_only_to_validated_endpoint() -> None:
    token = "fake-citrix-read-token"
    seen: dict[str, str] = {}

    def handle(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, json=[])

    _client_with(
        httpx.MockTransport(handle), credential_provider=MockCitrixTokenProvider(token=token)
    ).fetch_raw()
    assert seen.get("authorization") == "Bearer" + " " + token


def test_fetch_raw_fails_closed_on_http_error() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="unavailable")

    result = _client_with(httpx.MockTransport(handle)).fetch_raw()
    assert result.available is False
    assert result.raw == []
    assert result.error is not None


def test_fetch_raw_retries_transient_then_succeeds() -> None:
    transport = flaky_transport(
        httpx.ConnectError("boom"),
        fail_times=1,
        then_payload=[synthetic_citrix_health(resource_id=FAKE_RESOURCE_ID)],
    )
    result = _client_with(transport, sleep=RecordingSleep()).fetch_raw()
    assert result.available is True
    assert result.raw == [
        {"kind": "host-health", "resource_id": FAKE_RESOURCE_ID, "health": "degraded"}
    ]


def test_fetch_raw_fails_closed_when_retries_exhausted() -> None:
    transport = raising_transport(httpx.ConnectError("boom"))
    result = _client_with(
        transport, config=_config(retries=2), sleep=RecordingSleep()
    ).fetch_raw()
    assert result.available is False
    assert result.error == "ConnectError"


def test_fetch_raw_fails_closed_on_oversized_response() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[synthetic_citrix_health(resource_id=FAKE_RESOURCE_ID)])

    result = _client_with(
        httpx.MockTransport(handle), config=_config(max_response_bytes=1)
    ).fetch_raw()
    assert result.available is False
    assert result.error == "CitrixResponseTooLarge"


def test_fetch_raw_aborts_oversized_streamed_body_without_buffering() -> None:
    yielded = {"chunks": 0}

    def handle(request: httpx.Request) -> httpx.Response:
        def gen() -> object:
            for _ in range(1000):
                yielded["chunks"] += 1
                yield b"x" * 1024

        return httpx.Response(200, content=gen())

    result = _client_with(
        httpx.MockTransport(handle), config=_config(max_response_bytes=4096)
    ).fetch_raw()
    assert result.available is False
    assert result.error == "CitrixResponseTooLarge"
    assert yielded["chunks"] < 1000


def test_fetch_raw_rejects_compressed_body_without_decoding() -> None:
    huge_json = b'["' + b"A" * (1024 * 1024) + b'"]'
    compressed = gzip.compress(huge_json)
    assert len(compressed) < 4096

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Encoding": "gzip"}, content=compressed)

    result = _client_with(
        httpx.MockTransport(handle), config=_config(max_response_bytes=65_536)
    ).fetch_raw()
    assert result.available is False
    assert result.error == "InvalidCitrixResponse"


def test_fetch_raw_bounds_on_wire_bytes_before_buffer_exceeds() -> None:
    pulled = {"chunks": 0}

    def handle(request: httpx.Request) -> httpx.Response:
        def gen() -> object:
            pulled["chunks"] += 1
            yield b"x" * (10 * 1024)
            pulled["chunks"] += 1
            yield b"y" * (10 * 1024)

        return httpx.Response(200, content=gen())

    result = _client_with(
        httpx.MockTransport(handle), config=_config(max_response_bytes=8 * 1024)
    ).fetch_raw()
    assert result.available is False
    assert result.error == "CitrixResponseTooLarge"
    assert pulled["chunks"] == 1


def test_fetch_raw_requests_identity_encoding() -> None:
    seen: dict[str, str] = {}

    def handle(request: httpx.Request) -> httpx.Response:
        seen["accept-encoding"] = request.headers.get("accept-encoding", "")
        return httpx.Response(200, json=[synthetic_citrix_health(resource_id=FAKE_RESOURCE_ID)])

    result = _client_with(httpx.MockTransport(handle)).fetch_raw()
    assert result.available is True
    assert seen["accept-encoding"] == "identity"


def test_fetch_raw_deadline_stops_retries_after_slow_attempt() -> None:
    attempts = {"n": 0}

    def handle(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        time.sleep(0.05)
        raise httpx.ConnectError("boom")

    result = _client_with(
        httpx.MockTransport(handle), config=_config(retries=5, max_elapsed_s=0.01)
    ).fetch_raw()
    assert result.available is False
    assert attempts["n"] == 1


def test_fetch_raw_deadline_rejects_slow_but_successful_attempt() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        time.sleep(0.05)
        return httpx.Response(200, json=[synthetic_citrix_health(resource_id=FAKE_RESOURCE_ID)])

    result = _client_with(
        httpx.MockTransport(handle), config=_config(retries=1, max_elapsed_s=0.01)
    ).fetch_raw()
    assert result.available is False
    assert result.error == "CitrixDeadlineExceeded"


def test_fetch_raw_aborts_slow_drip_stream_within_deadline() -> None:
    yielded = {"chunks": 0}

    def handle(request: httpx.Request) -> httpx.Response:
        def slow_gen() -> object:
            for _ in range(50):
                time.sleep(0.02)
                yielded["chunks"] += 1
                yield b"x" * 8

        return httpx.Response(200, content=slow_gen())

    start = time.monotonic()
    result = _client_with(
        httpx.MockTransport(handle),
        config=_config(retries=1, max_elapsed_s=0.01, max_response_bytes=1_000_000),
    ).fetch_raw()
    elapsed = time.monotonic() - start
    assert result.available is False
    assert result.error == "CitrixDeadlineExceeded"
    assert yielded["chunks"] < 50
    assert elapsed < 1.0


def test_fetch_raw_fails_closed_atomically_on_one_bad_record() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=[
                synthetic_citrix_health(resource_id=FAKE_RESOURCE_ID),
                synthetic_citrix_health(resource_id=FAKE_RESOURCE_ID, health="bogus"),
            ],
        )

    result = _client_with(httpx.MockTransport(handle)).fetch_raw()
    assert result.available is False
    assert result.raw == []


@pytest.mark.parametrize(
    "payload",
    [
        {"unexpected": "shape"},
        [1, "bad"],
        {"signals": [1]},
        {"signals": [], "value": []},  # ambiguous multi-key envelope
        "not-a-shape",
    ],
)
def test_fetch_raw_fails_closed_on_malformed_payload(payload: object) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    result = _client_with(httpx.MockTransport(handle)).fetch_raw()
    assert result.available is False
    assert result.raw == []


def test_fetch_raw_accepts_envelope_shape() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"signals": [synthetic_citrix_health(resource_id=FAKE_RESOURCE_ID)]}
        )

    result = _client_with(httpx.MockTransport(handle)).fetch_raw()
    assert result.available is True
    assert result.raw == [
        {"kind": "host-health", "resource_id": FAKE_RESOURCE_ID, "health": "degraded"}
    ]


def test_fetch_raw_pii_like_value_never_reaches_state() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=[
                {"kind": "host-health", "resourceId": "jane.doe@example.com", "health": "healthy"},
                {"kind": "host-health", "resourceId": FAKE_RESOURCE_ID, "health": "healthy",
                 "name": "Jane Doe"},
            ],
        )

    result = _client_with(httpx.MockTransport(handle)).fetch_raw()
    assert result.available is False
    assert result.raw == []
    signals = signals_from_result(result)
    applied = apply_supplemental([_node(FAKE_RESOURCE_ID)], signals.health)
    assert applied.annotated_ids == []
    assert all(SUPPLEMENTAL_SOURCE_TAG not in n.tags for n in applied.nodes)


def test_failing_provider_fails_closed_without_leaking() -> None:
    def boom() -> str | None:
        raise RuntimeError("super-secret-token-value")

    result = _client_with(
        httpx.MockTransport(_raise_if_called), credential_provider=boom
    ).fetch_raw()
    assert result.available is False
    assert result.error == "RuntimeError"  # class name only — no message, no token


# --------------------------------------------------------------------------------------
# Fail-closed observer seam (issue #60)
# --------------------------------------------------------------------------------------
def test_fetch_raw_fail_closed_fires_injected_observer() -> None:
    from shared.observability import (
        METRIC_CONNECTOR_FAIL_CLOSED,
        MetricsRegistry,
        connector_fail_closed_observer,
    )

    reg = MetricsRegistry()

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="unavailable")

    client = _client_with(
        httpx.MockTransport(handle),
        fail_closed_observer=connector_fail_closed_observer("dependency_graph", reg),
    )
    assert client.fetch_raw().available is False
    fc = next(s for s in reg.snapshot().counters if s.name == METRIC_CONNECTOR_FAIL_CLOSED)
    assert fc.labels == {"module": "dependency_graph"}
    assert fc.value == 1


def test_fetch_raw_success_does_not_fire_observer() -> None:
    from shared.observability import MetricsRegistry, connector_fail_closed_observer

    reg = MetricsRegistry()

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[])

    client = _client_with(
        httpx.MockTransport(handle),
        fail_closed_observer=connector_fail_closed_observer("dependency_graph", reg),
    )
    assert client.fetch_raw().available is True
    assert reg.snapshot().counters == []


# --------------------------------------------------------------------------------------
# Protocol conformance + lazy httpx import
# --------------------------------------------------------------------------------------
def test_citrix_client_satisfies_connector_protocol() -> None:
    assert isinstance(_client_with(httpx.MockTransport(_raise_if_called)), CitrixConnector)


def test_importing_citrix_connector_does_not_import_httpx(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Importing the connector (or dependency_graph) must NOT import httpx when Citrix is absent.
    monkeypatch.setitem(sys.modules, "httpx", None)
    for mod in (
        "modules.dependency_graph.module",
        "modules.dependency_graph.connectors",
        "modules.dependency_graph.connectors.citrix",
    ):
        monkeypatch.delitem(sys.modules, mod, raising=False)
    reloaded = importlib.import_module("modules.dependency_graph.connectors.citrix")
    assert reloaded is not None
