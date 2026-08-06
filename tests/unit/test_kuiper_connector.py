"""Kuiper connector — fail-closed-by-default, supplement-only, PII-safe edge + pure mapping.

All fixtures are obviously synthetic (zeroed GUIDs, fake hosts, no PII/PHI); there is no real
network, credential, or Kuiper schema. Tests exercise the pure validators/mapping and the network
edge via ``httpx.MockTransport`` — never a real socket.
"""
from __future__ import annotations

import gzip
import importlib
import sys
import time

import httpx
import pytest

from modules.discovery.connectors.kuiper import (
    ALLOWED_SIGNALS,
    MAX_RESOURCE_ID_LEN,
    SUPPLEMENTAL_SIGNAL_TAG,
    SUPPLEMENTAL_SOURCE,
    SUPPLEMENTAL_SOURCE_TAG,
    InvalidKuiperEndpoint,
    KuiperClient,
    KuiperConfig,
    KuiperConnector,
    KuiperEndpointNotApproved,
    KuiperHint,
    KuiperHintError,
    apply_supplemental,
    hints_from_result,
    parse_hints_atomic,
    to_source_reference,
    validate_endpoint,
    validate_hint,
)
from shared.connectors import FetchResult, TokenProvider
from shared.contracts import ResourceNode
from support.connectors import (
    FAKE_RESOURCE_ID,
    RecordingSleep,
    flaky_transport,
    raising_transport,
    synthetic_kuiper_hint,
)

# A clearly-fake, non-placeholder, operator-approved host used across the edge tests.
APPROVED_HOST = "kuiper.approved.test"
APPROVED_BASE_URL = f"https://{APPROVED_HOST}"


def _config(**overrides: object) -> KuiperConfig:
    base: dict[str, object] = {
        "base_url": APPROVED_BASE_URL,
        "approved_hosts": (APPROVED_HOST,),
    }
    base.update(overrides)
    return KuiperConfig(**base)  # type: ignore[arg-type]


def _arg_node(node_id: str = FAKE_RESOURCE_ID, *, role: str | None = "odb") -> ResourceNode:
    """A synthetic already-ARG-discovered node (authoritative)."""
    return ResourceNode(
        id=node_id, name="widget-01", type="Fake.Compute/widgets", workload="epic",
        tier="data", role=role, tags={"epic-role": "odb"},
    )


# --------------------------------------------------------------------------------------
# validate_endpoint — credential-exfil safety (HIGH-1)
# --------------------------------------------------------------------------------------
def test_validate_endpoint_accepts_approved_https() -> None:
    url = validate_endpoint(APPROVED_BASE_URL, "/v1/discovery/hints", (APPROVED_HOST,))
    assert url == f"{APPROVED_BASE_URL}/v1/discovery/hints"


def test_validate_endpoint_rejects_http() -> None:
    with pytest.raises(InvalidKuiperEndpoint):
        validate_endpoint(f"http://{APPROVED_HOST}", "/v1/x", (APPROVED_HOST,))


def test_validate_endpoint_rejects_non_https_scheme() -> None:
    with pytest.raises(InvalidKuiperEndpoint):
        validate_endpoint(f"ftp://{APPROVED_HOST}", "/v1/x", (APPROVED_HOST,))


def test_validate_endpoint_rejects_empty_base_url() -> None:
    with pytest.raises(InvalidKuiperEndpoint):
        validate_endpoint("", "/v1/x", (APPROVED_HOST,))


@pytest.mark.parametrize("host", ["kuiper.internal", "localhost", "example.com", "placeholder"])
def test_validate_endpoint_rejects_placeholder_host_even_if_allowlisted(host: str) -> None:
    with pytest.raises(InvalidKuiperEndpoint):
        validate_endpoint(f"https://{host}", "/v1/x", (host,))


def test_validate_endpoint_rejects_userinfo() -> None:
    with pytest.raises(InvalidKuiperEndpoint):
        validate_endpoint(f"https://user:pw@{APPROVED_HOST}", "/v1/x", (APPROVED_HOST,))


def test_validate_endpoint_rejects_query() -> None:
    with pytest.raises(InvalidKuiperEndpoint):
        validate_endpoint(f"{APPROVED_BASE_URL}?a=1", "/v1/x", (APPROVED_HOST,))


def test_validate_endpoint_rejects_fragment() -> None:
    with pytest.raises(InvalidKuiperEndpoint):
        validate_endpoint(f"{APPROVED_BASE_URL}#frag", "/v1/x", (APPROVED_HOST,))


def test_validate_endpoint_rejects_host_not_on_allowlist() -> None:
    with pytest.raises(KuiperEndpointNotApproved):
        validate_endpoint(APPROVED_BASE_URL, "/v1/x", ())


@pytest.mark.parametrize("bad_path", ["v1/x", "/v1/x?y=1", "/v1/x#f", "/v1 x", "/v1@x"])
def test_validate_endpoint_rejects_unsafe_path(bad_path: str) -> None:
    with pytest.raises(InvalidKuiperEndpoint):
        validate_endpoint(APPROVED_BASE_URL, bad_path, (APPROVED_HOST,))


# --- LOW: canonicalization bypass attempts (trailing dot / explicit port / IDN / IP literal) -----
def test_validate_endpoint_rejects_trailing_dot_host() -> None:
    # ``localhost.`` must not sneak past the placeholder gate via a trailing-dot FQDN form.
    with pytest.raises(InvalidKuiperEndpoint):
        validate_endpoint("https://localhost.", "/v1/x", ("localhost.",))


def test_validate_endpoint_trailing_dot_matches_canonical_placeholder() -> None:
    # An approved host with a trailing dot canonicalizes to the same placeholder and is rejected.
    with pytest.raises(InvalidKuiperEndpoint):
        validate_endpoint("https://example.com.", "/v1/x", ("example.com",))


def test_validate_endpoint_rejects_explicit_port() -> None:
    with pytest.raises(InvalidKuiperEndpoint):
        validate_endpoint(f"https://{APPROVED_HOST}:4443", "/v1/x", (APPROVED_HOST,))


def test_validate_endpoint_rejects_explicit_port_even_when_hostport_allowlisted() -> None:
    # Allow-listing a bare host must NOT admit an explicit-port variant of it.
    with pytest.raises(InvalidKuiperEndpoint):
        validate_endpoint(
            f"https://{APPROVED_HOST}:4443", "/v1/x", (APPROVED_HOST, f"{APPROVED_HOST}:4443")
        )


@pytest.mark.parametrize("loopback", ["https://127.0.0.1", "https://[::1]", "https://169.254.1.1"])
def test_validate_endpoint_rejects_ip_literal_hosts(loopback: str) -> None:
    host = loopback.removeprefix("https://").strip("[]")
    with pytest.raises(InvalidKuiperEndpoint):
        validate_endpoint(loopback, "/v1/x", (host,))


def test_validate_endpoint_trailing_dot_matches_approved_host() -> None:
    # A benign approved host reached via its trailing-dot FQDN form still validates, and the
    # returned URL is rebuilt from the CANONICAL host (trailing dot stripped) — MED-A.
    url = validate_endpoint(f"https://{APPROVED_HOST}.", "/v1/x", (APPROVED_HOST,))
    assert url == f"https://{APPROVED_HOST}/v1/x"


def test_validate_endpoint_idn_host_returns_punycode_request_target() -> None:
    # MED-A: an IDN host is canonicalized with the SAME idna HTTPX uses, and the returned URL host
    # is the exact punycode form HTTPX will request — never the raw unicode nor a different domain.
    url = validate_endpoint("https://münchen.example", "/v1/x", ("xn--mnchen-3ya.example",))
    assert url == "https://xn--mnchen-3ya.example/v1/x"
    # The punycode form is accepted against the same allowlist entry and returned verbatim.
    punycode = validate_endpoint(
        "https://xn--mnchen-3ya.example", "/v1/x", ("münchen.example",)
    )
    assert punycode == "https://xn--mnchen-3ya.example/v1/x"


def test_validate_endpoint_rejects_confusable_idna2003_host() -> None:
    # MED-A regression: ``straße`` maps to ``strasse`` under the LEGACY stdlib idna codec but to
    # ``xn--strae-oqa`` under HTTPX's idna. Allow-listing the legacy ``strasse`` form must NOT admit
    # ``straße`` — the two canonicalize to DIFFERENT hosts, so it is rejected (never a bearer sent
    # to a different domain than the one allowlist-checked).
    with pytest.raises(KuiperEndpointNotApproved):
        validate_endpoint("https://straße.example", "/v1/x", ("strasse.example",))


def test_validate_endpoint_confusable_host_requests_exact_validated_punycode() -> None:
    # When the confusable host IS legitimately allow-listed, the returned target is the exact
    # HTTPX punycode — proving validate→use-the-validated-value (no downstream re-parse of raw).
    url = validate_endpoint("https://straße.example", "/v1/x", ("xn--strae-oqa.example",))
    assert url == "https://xn--strae-oqa.example/v1/x"


def test_validate_endpoint_fails_closed_on_idna_encoding_error() -> None:
    # MED-A: a non-ASCII host that idna cannot encode fails CLOSED (no lossy fallback).
    with pytest.raises(InvalidKuiperEndpoint):
        validate_endpoint("https://\U0001f600.example", "/v1/x", ("\U0001f600.example",))


@pytest.mark.parametrize(
    "numeric_host",
    ["0177.0.0.1", "0x7f.0.0.1", "2130706433", "127.1"],
)
def test_validate_endpoint_rejects_legacy_numeric_ipv4_literals(numeric_host: str) -> None:
    # LOW-D: alternate IPv4 encodings (octal/hex/integer/short) that ``ipaddress`` treats as
    # hostnames must be rejected as IP literals even when allow-listed (may resolve to loopback).
    with pytest.raises(InvalidKuiperEndpoint):
        validate_endpoint(f"https://{numeric_host}", "/v1/x", (numeric_host,))


# --------------------------------------------------------------------------------------
# validate_hint / parse_hints_atomic — PII-safe, closed vocabulary (HIGH-3, MED-1)
# --------------------------------------------------------------------------------------
def test_validate_hint_accepts_well_formed_hint() -> None:
    hint = validate_hint(synthetic_kuiper_hint(), max_field_len=512)
    assert hint.resource_id == FAKE_RESOURCE_ID
    assert hint.signal == "corroborated"


def test_validate_hint_accepts_missing_signal() -> None:
    hint = validate_hint(synthetic_kuiper_hint(signal=None), max_field_len=512)
    assert hint.signal is None


def test_validate_hint_rejects_unexpected_key_pii_smuggle() -> None:
    # A payload smuggling a free-text field (potential PII) is rejected outright.
    raw = synthetic_kuiper_hint()
    raw["name"] = "jane.doe@example.com"
    with pytest.raises(KuiperHintError):
        validate_hint(raw, max_field_len=512)


def test_validate_hint_rejects_email_in_resource_id() -> None:
    with pytest.raises(KuiperHintError):
        validate_hint(
            synthetic_kuiper_hint(resource_id="jane.doe@example.com"), max_field_len=512
        )


def test_validate_hint_rejects_unknown_kind() -> None:
    raw = synthetic_kuiper_hint()
    raw["kind"] = "dependency"
    with pytest.raises(KuiperHintError):
        validate_hint(raw, max_field_len=512)


def test_validate_hint_rejects_signal_outside_allowlist() -> None:
    with pytest.raises(KuiperHintError):
        validate_hint(synthetic_kuiper_hint(signal="totally-made-up"), max_field_len=512)


def test_validate_hint_rejects_missing_resource_id() -> None:
    with pytest.raises(KuiperHintError):
        validate_hint({"kind": "entity-signal", "signal": "candidate"}, max_field_len=512)


def test_validate_hint_rejects_oversized_resource_id() -> None:
    with pytest.raises(KuiperHintError):
        validate_hint(synthetic_kuiper_hint(resource_id="a" * 600), max_field_len=512)


def test_validate_hint_rejects_non_mapping() -> None:
    with pytest.raises(KuiperHintError):
        validate_hint(["not", "a", "dict"], max_field_len=512)


def test_allowed_signals_is_closed_vocabulary() -> None:
    assert frozenset({"corroborated", "candidate", "stale"}) == ALLOWED_SIGNALS


def test_parse_hints_atomic_accepts_all_good() -> None:
    records = [synthetic_kuiper_hint(resource_id=FAKE_RESOURCE_ID), synthetic_kuiper_hint(
        resource_id=FAKE_RESOURCE_ID, signal="stale")]
    hints = parse_hints_atomic(records, max_records=10, max_field_len=512)
    assert len(hints) == 2


def test_parse_hints_atomic_rejects_entire_batch_on_one_bad_record() -> None:
    # MED-1: one malformed record ⇒ reject the WHOLE fetch (never partially-fabricated topology).
    good = synthetic_kuiper_hint()
    bad = synthetic_kuiper_hint(signal="bogus")
    with pytest.raises(KuiperHintError):
        parse_hints_atomic([good, bad], max_records=10, max_field_len=512)


def test_parse_hints_atomic_rejects_too_many_records() -> None:
    records = [synthetic_kuiper_hint() for _ in range(5)]
    with pytest.raises(KuiperHintError):
        parse_hints_atomic(records, max_records=4, max_field_len=512)


# --------------------------------------------------------------------------------------
# hints_from_result / apply_supplemental — supplement-only, ARG always wins (HIGH-2/HIGH-3)
# --------------------------------------------------------------------------------------
def test_hints_from_result_unavailable_yields_no_hints() -> None:
    assert hints_from_result(FetchResult(available=False)) == []


def test_hints_from_result_rehydrates_normalized_records() -> None:
    result = FetchResult(
        available=True, raw=[{"resource_id": FAKE_RESOURCE_ID, "signal": "corroborated"}]
    )
    hints = hints_from_result(result)
    assert hints == [KuiperHint(resource_id=FAKE_RESOURCE_ID, signal="corroborated")]


# --- MED-A: KuiperHint self-validates NO MATTER how it is constructed (injected-connector safe) ---
def test_kuiper_hint_construction_rejects_pii_signal() -> None:
    # A PII-bearing signal cannot be constructed even directly — the field validator rejects it.
    with pytest.raises(ValueError):
        KuiperHint(resource_id=FAKE_RESOURCE_ID, signal="patient=Jane-Doe")


def test_kuiper_hint_construction_rejects_charset_invalid_resource_id() -> None:
    with pytest.raises(ValueError):
        KuiperHint(resource_id="jane.doe@example.com")


def test_kuiper_hint_construction_rejects_oversized_resource_id() -> None:
    with pytest.raises(ValueError):
        KuiperHint(resource_id="a" * (MAX_RESOURCE_ID_LEN + 1))


def test_kuiper_hint_construction_rejects_empty_resource_id() -> None:
    with pytest.raises(ValueError):
        KuiperHint(resource_id="")


def test_kuiper_hint_model_validate_forbids_extra_key() -> None:
    with pytest.raises(ValueError):
        KuiperHint.model_validate(
            {"resource_id": FAKE_RESOURCE_ID, "signal": "stale", "smuggled": "x"}
        )


@pytest.mark.parametrize(
    "raw",
    [
        {"resource_id": FAKE_RESOURCE_ID, "signal": "patient=Jane-Doe-MRN-123"},  # PII in signal
        {"resource_id": "jane.doe@example.com", "signal": "corroborated"},  # PII/charset in id
        {"resource_id": "a" * (MAX_RESOURCE_ID_LEN + 1)},  # oversized id
        {"resource_id": FAKE_RESOURCE_ID, "signal": "candidate", "leak": "x"},  # smuggled key
    ],
)
def test_hints_from_result_rejects_untrusted_malicious_raw(raw: dict[str, object]) -> None:
    # An INJECTED connector's unvalidated FetchResult.raw is re-validated here and rejected
    # atomically (fail closed) — nothing ever reaches a KuiperHint / persisted state.
    result = FetchResult(available=True, raw=[{"resource_id": FAKE_RESOURCE_ID}, raw])
    with pytest.raises(KuiperHintError):
        hints_from_result(result)


def test_apply_supplemental_annotates_matching_node_only() -> None:
    nodes = [_arg_node(FAKE_RESOURCE_ID), _arg_node("/other/id", role="web")]
    hints = [KuiperHint(resource_id=FAKE_RESOURCE_ID, signal="corroborated")]
    result = apply_supplemental(nodes, hints)
    assert len(result.nodes) == 2  # nothing added or removed
    matched = next(n for n in result.nodes if n.id == FAKE_RESOURCE_ID)
    assert matched.tags[SUPPLEMENTAL_SOURCE_TAG] == SUPPLEMENTAL_SOURCE
    assert matched.tags[SUPPLEMENTAL_SIGNAL_TAG] == "corroborated"
    assert result.annotated_ids == [FAKE_RESOURCE_ID]
    other = next(n for n in result.nodes if n.id == "/other/id")
    assert SUPPLEMENTAL_SOURCE_TAG not in other.tags


def test_apply_supplemental_never_mutates_authoritative_fields() -> None:
    original = _arg_node(FAKE_RESOURCE_ID)
    hints = [KuiperHint(resource_id=FAKE_RESOURCE_ID, signal="stale")]
    result = apply_supplemental([original], hints)
    annotated = result.nodes[0]
    # Only tags changed; every authoritative field is preserved. The input node is untouched.
    assert annotated.id == original.id
    assert annotated.name == original.name
    assert annotated.type == original.type
    assert annotated.workload == original.workload
    assert annotated.tier == original.tier
    assert annotated.role == original.role
    assert SUPPLEMENTAL_SOURCE_TAG not in original.tags  # original object not mutated


def test_apply_supplemental_without_signal_adds_only_source_tag() -> None:
    hints = [KuiperHint(resource_id=FAKE_RESOURCE_ID, signal=None)]
    result = apply_supplemental([_arg_node(FAKE_RESOURCE_ID)], hints)
    tags = result.nodes[0].tags
    assert tags[SUPPLEMENTAL_SOURCE_TAG] == SUPPLEMENTAL_SOURCE
    assert SUPPLEMENTAL_SIGNAL_TAG not in tags


def test_apply_supplemental_drops_hint_matching_no_node() -> None:
    nodes = [_arg_node(FAKE_RESOURCE_ID)]
    hints = [KuiperHint(resource_id="/subscriptions/0/rg/fake/does-not-exist")]
    result = apply_supplemental(nodes, hints)
    assert result.annotated_ids == []
    assert all(SUPPLEMENTAL_SOURCE_TAG not in n.tags for n in result.nodes)
    assert len(result.nodes) == 1  # never creates a node from a hint


def test_apply_supplemental_revalidates_validator_bypass_constructions() -> None:
    # LOW-C: ``model_construct`` and ``model_copy(update=...)`` BYPASS pydantic field validators, so
    # a PII/charset-invalid value can be smuggled into a KuiperHint instance. apply_supplemental is
    # the persistence-adjacent boundary: it RE-VALIDATES every hint and drops any violation, so no
    # free-form/PII value ever reaches a node tag — no matter how the hint was constructed.
    node = _arg_node(FAKE_RESOURCE_ID)

    # (1) model_construct with a PII signal outside the closed vocabulary.
    smuggled_signal = KuiperHint.model_construct(
        resource_id=FAKE_RESOURCE_ID, signal="patient=Jane-Doe-MRN-123"
    )
    # (2) model_copy(update=...) mutating a valid hint's signal to PII.
    valid = KuiperHint(resource_id=FAKE_RESOURCE_ID, signal="corroborated")
    copied_pii = valid.model_copy(update={"signal": "patient=Jane-Doe"})
    # (3) model_construct with a charset-invalid (email-like) resource_id.
    smuggled_id = KuiperHint.model_construct(
        resource_id="jane.doe@example.com", signal="corroborated"
    )

    result = apply_supplemental([node], [smuggled_signal, copied_pii, smuggled_id])
    assert result.annotated_ids == []  # all three dropped at the write boundary
    tags = result.nodes[0].tags
    assert SUPPLEMENTAL_SOURCE_TAG not in tags
    assert SUPPLEMENTAL_SIGNAL_TAG not in tags
    for value in tags.values():
        assert "patient" not in value.lower() and "jane" not in value.lower()


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
    config: KuiperConfig | None = None,
    credential_provider: TokenProvider | None = lambda: "fake-read-token",
    **kwargs: object,
) -> KuiperClient:
    cfg = config or _config()
    http_client = httpx.Client(transport=transport)
    return KuiperClient(
        cfg, client=http_client, credential_provider=credential_provider, **kwargs  # type: ignore[arg-type]
    )


class _SpyProvider:
    """A credential provider that records whether it was ever consulted."""

    def __init__(self, token: str | None = "fake-read-token") -> None:
        self.calls = 0
        self._token = token

    def __call__(self) -> str | None:
        self.calls += 1
        return self._token


def test_fetch_raw_success_returns_normalized_hints() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/discovery/hints"
        return httpx.Response(200, json=[synthetic_kuiper_hint(resource_id=FAKE_RESOURCE_ID)])

    result = _client_with(httpx.MockTransport(handle)).fetch_raw()
    assert result.available is True
    assert result.raw == [{"resource_id": FAKE_RESOURCE_ID, "signal": "corroborated"}]


def test_fetch_raw_invalid_endpoint_fails_closed_without_resolving_credential() -> None:
    # HIGH-1: an unapproved/placeholder endpoint fails closed BEFORE any credential is resolved and
    # WITHOUT any network call.
    spy = _SpyProvider()
    client = _client_with(
        httpx.MockTransport(_raise_if_called),
        config=_config(base_url="", approved_hosts=()),
        credential_provider=spy,
    )
    result = client.fetch_raw()
    assert result.available is False
    assert result.error == "InvalidKuiperEndpoint"
    assert spy.calls == 0  # credential NEVER resolved for an unvalidated endpoint


def test_fetch_raw_unapproved_host_fails_closed_without_credential() -> None:
    spy = _SpyProvider()
    client = _client_with(
        httpx.MockTransport(_raise_if_called),
        config=_config(base_url="https://kuiper.evil.test", approved_hosts=(APPROVED_HOST,)),
        credential_provider=spy,
    )
    result = client.fetch_raw()
    assert result.available is False
    assert result.error == "KuiperEndpointNotApproved"
    assert spy.calls == 0


def test_fetch_raw_no_credential_fails_closed_without_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("KUIPER_READ_TOKEN", raising=False)
    result = _client_with(
        httpx.MockTransport(_raise_if_called), credential_provider=None
    ).fetch_raw()
    assert result.available is False
    assert result.error == "NoCredential"


def test_fetch_raw_sends_bearer_only_to_validated_endpoint() -> None:
    token = "fake-read-token"
    seen: dict[str, str] = {}

    def handle(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, json=[])

    _client_with(httpx.MockTransport(handle), credential_provider=lambda: token).fetch_raw()
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
        then_payload=[synthetic_kuiper_hint(resource_id=FAKE_RESOURCE_ID)],
    )
    result = _client_with(transport, sleep=RecordingSleep()).fetch_raw()
    assert result.available is True
    assert result.raw == [{"resource_id": FAKE_RESOURCE_ID, "signal": "corroborated"}]


def test_fetch_raw_fails_closed_when_retries_exhausted() -> None:
    transport = raising_transport(httpx.ConnectError("boom"))
    result = _client_with(
        transport, config=_config(retries=2), sleep=RecordingSleep()
    ).fetch_raw()
    assert result.available is False
    assert result.error == "ConnectError"


def test_fetch_raw_fails_closed_on_oversized_response() -> None:
    # MED-2: a response whose declared size exceeds the ceiling is rejected before it is trusted.
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[synthetic_kuiper_hint(resource_id=FAKE_RESOURCE_ID)])

    result = _client_with(
        httpx.MockTransport(handle), config=_config(max_response_bytes=1)
    ).fetch_raw()
    assert result.available is False
    assert result.error == "KuiperResponseTooLarge"


def test_fetch_raw_aborts_oversized_streamed_body_without_buffering() -> None:
    # MED-B: a body with NO/absent Content-Length is streamed and aborted by a running byte total
    # as soon as the ceiling is crossed — the whole body is NEVER buffered.
    yielded = {"chunks": 0}

    def handle(request: httpx.Request) -> httpx.Response:
        def gen() -> object:
            for _ in range(1000):
                yielded["chunks"] += 1
                yield b"x" * 1024  # 1 KiB per chunk, chunked (no Content-Length)

        return httpx.Response(200, content=gen())

    result = _client_with(
        httpx.MockTransport(handle), config=_config(max_response_bytes=4096)
    ).fetch_raw()
    assert result.available is False
    assert result.error == "KuiperResponseTooLarge"
    # Aborted early — only a few chunks were pulled, not the whole 1000-chunk (~1 MiB) body.
    assert yielded["chunks"] < 1000


def test_fetch_raw_rejects_compressed_body_without_decoding() -> None:
    # MED (decompression bomb): a Content-Encoding:gzip body from an APPROVED endpoint (that ignored
    # our Accept-Encoding: identity) is REFUSED fail-closed and NEVER decoded — the byte ceiling is
    # measured on the wire, so a small compressed blob that would balloon on decode can't exhaust
    # memory. Here a highly-compressible ~1 MiB payload gzips to a tiny wire body but is rejected
    # by the content-encoding gate before any decompression.
    huge_json = b'["' + b"A" * (1024 * 1024) + b'"]'
    compressed = gzip.compress(huge_json)
    assert len(compressed) < 4096  # tiny on the wire...

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"Content-Encoding": "gzip"}, content=compressed
        )

    # max_response_bytes comfortably admits the small WIRE body; the decoded body would be ~1 MiB.
    result = _client_with(
        httpx.MockTransport(handle), config=_config(max_response_bytes=65_536)
    ).fetch_raw()
    assert result.available is False
    assert result.error == "InvalidKuiperResponse"


def test_fetch_raw_bounds_on_wire_bytes_before_buffer_exceeds() -> None:
    # The ceiling is enforced on RAW wire bytes and rejected the moment it WOULD be exceeded — an
    # over-limit body is never fully buffered. A single ~10 KiB chunk over an 8 KiB ceiling is
    # refused without appending it.
    pulled = {"chunks": 0}

    def handle(request: httpx.Request) -> httpx.Response:
        def gen() -> object:
            pulled["chunks"] += 1
            yield b"x" * (10 * 1024)  # first chunk already exceeds the 8 KiB ceiling
            pulled["chunks"] += 1
            yield b"y" * (10 * 1024)  # must never be pulled

        return httpx.Response(200, content=gen())

    result = _client_with(
        httpx.MockTransport(handle), config=_config(max_response_bytes=8 * 1024)
    ).fetch_raw()
    assert result.available is False
    assert result.error == "KuiperResponseTooLarge"
    assert pulled["chunks"] == 1  # rejected on the first over-limit chunk, second never streamed


def test_fetch_raw_requests_identity_encoding() -> None:
    # The request must ask the server not to compress, so the body we bound is the wire body.
    seen: dict[str, str] = {}

    def handle(request: httpx.Request) -> httpx.Response:
        seen["accept-encoding"] = request.headers.get("accept-encoding", "")
        return httpx.Response(200, json=[synthetic_kuiper_hint(resource_id=FAKE_RESOURCE_ID)])

    result = _client_with(httpx.MockTransport(handle)).fetch_raw()
    assert result.available is True
    assert seen["accept-encoding"] == "identity"


def test_fetch_raw_deadline_stops_retries_after_slow_attempt() -> None:
    # MED-C: an attempt that itself overruns the deadline must NOT be retried — total work bounded.
    attempts = {"n": 0}

    def handle(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        time.sleep(0.05)  # blow the 0.01s deadline within a single attempt
        raise httpx.ConnectError("boom")

    result = _client_with(
        httpx.MockTransport(handle), config=_config(retries=5, max_elapsed_s=0.01)
    ).fetch_raw()
    assert result.available is False
    assert attempts["n"] == 1  # deadline prevented any retry


def test_fetch_raw_deadline_rejects_slow_but_successful_attempt() -> None:
    # MED-C: even a SUCCESSFUL attempt that overran the deadline fails closed — a tiny (~0.01s)
    # deadline must never succeed by smuggling late data.
    def handle(request: httpx.Request) -> httpx.Response:
        time.sleep(0.05)  # overshoot the 0.01s deadline
        return httpx.Response(200, json=[synthetic_kuiper_hint(resource_id=FAKE_RESOURCE_ID)])

    result = _client_with(
        httpx.MockTransport(handle), config=_config(retries=1, max_elapsed_s=0.01)
    ).fetch_raw()
    assert result.available is False
    assert result.error == "KuiperDeadlineExceeded"


def test_fetch_raw_aborts_slow_drip_stream_within_deadline() -> None:
    # MED-B: a slow-drip body (HTTPX read timeouts are per-inactivity, NOT a total ceiling) must be
    # aborted by the overall deadline mid-stream — not streamed to completion. A tiny deadline fails
    # closed promptly and only a few of the many chunks are ever pulled.
    yielded = {"chunks": 0}

    def handle(request: httpx.Request) -> httpx.Response:
        def slow_gen() -> object:
            for _ in range(50):
                time.sleep(0.02)  # each chunk drips slower than the 0.01s deadline
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
    assert result.error == "KuiperDeadlineExceeded"
    assert yielded["chunks"] < 50  # aborted mid-stream, never drained the whole body
    assert elapsed < 1.0  # promptly, not the ~1s a full 50-chunk drip would take


def test_fetch_raw_fails_closed_atomically_on_one_bad_record() -> None:
    # MED-1: one bad record ⇒ the ENTIRE fetch is rejected (available=False), never partial.
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=[
                synthetic_kuiper_hint(resource_id=FAKE_RESOURCE_ID),
                synthetic_kuiper_hint(resource_id=FAKE_RESOURCE_ID, signal="bogus"),
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
        {"hints": [1]},
        {"hints": [], "value": []},  # ambiguous multi-key envelope
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
            200, json={"hints": [synthetic_kuiper_hint(resource_id=FAKE_RESOURCE_ID)]}
        )

    result = _client_with(httpx.MockTransport(handle)).fetch_raw()
    assert result.available is True
    assert result.raw == [{"resource_id": FAKE_RESOURCE_ID, "signal": "corroborated"}]


def test_fetch_raw_pii_like_value_never_reaches_state() -> None:
    # HIGH-3: a PII-like value (email) in a Kuiper record is dropped fail-closed — the whole fetch
    # is rejected and NOTHING (no node, no tag, no free-text) reaches persisted state.
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=[
                {"kind": "entity-signal", "resourceId": "jane.doe@example.com"},
                {"kind": "entity-signal", "resourceId": FAKE_RESOURCE_ID, "name": "Jane Doe"},
            ],
        )

    result = _client_with(httpx.MockTransport(handle)).fetch_raw()
    assert result.available is False
    assert result.raw == []
    # Even if a caller ignored availability, rehydration yields nothing to apply.
    assert hints_from_result(result) == []
    applied = apply_supplemental([_arg_node(FAKE_RESOURCE_ID)], hints_from_result(result))
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
        fail_closed_observer=connector_fail_closed_observer("discovery", reg),
    )
    assert client.fetch_raw().available is False
    fc = next(s for s in reg.snapshot().counters if s.name == METRIC_CONNECTOR_FAIL_CLOSED)
    assert fc.labels == {"module": "discovery"}
    assert fc.value == 1


def test_fetch_raw_success_does_not_fire_observer() -> None:
    from shared.observability import MetricsRegistry, connector_fail_closed_observer

    reg = MetricsRegistry()

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[])

    client = _client_with(
        httpx.MockTransport(handle),
        fail_closed_observer=connector_fail_closed_observer("discovery", reg),
    )
    assert client.fetch_raw().available is True
    assert reg.snapshot().counters == []


# --------------------------------------------------------------------------------------
# Protocol conformance + lazy httpx import (LOW)
# --------------------------------------------------------------------------------------
def test_kuiper_client_satisfies_connector_protocol() -> None:
    assert isinstance(_client_with(httpx.MockTransport(_raise_if_called)), KuiperConnector)


def test_importing_kuiper_connector_does_not_import_httpx(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # LOW: importing the connector (or Discovery) must NOT import httpx when Kuiper is absent.
    monkeypatch.setitem(sys.modules, "httpx", None)
    for mod in (
        "modules.discovery.module",
        "modules.discovery.connectors",
        "modules.discovery.connectors.kuiper",
    ):
        monkeypatch.delitem(sys.modules, mod, raising=False)
    reloaded = importlib.import_module("modules.discovery.connectors.kuiper")
    assert reloaded is not None
