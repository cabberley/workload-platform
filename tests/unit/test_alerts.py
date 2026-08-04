"""Alerts & Notifications module unit tests — pure logic + delivery seam (Azure/network-free).

All fixtures are synthetic and clearly fake. Delivery is exercised through an injected
:class:`FakeChannel`; no test touches the network. The HTTPS-enforcement tests construct a
:class:`WebhookChannel` only to assert its constructor validates the scheme (no network I/O).
"""
from collections.abc import Mapping
from typing import Any

import httpx
import pytest

from modules.alerts.channels import (
    DeliveryResult,
    InsecureWebhookError,
    NotificationChannel,
    WebhookChannel,
    build_webhook_channel,
    build_webhook_http_client,
    require_https_webhook,
)
from modules.alerts.module import (
    AlertsModule,
    channel_egresses_out_of_boundary,
    load_ops_routing,
    opaque_finding_id,
    route,
    weight_by_blast_radius,
)
from shared.contracts import Finding, PackType, Severity
from shared.module_base import ModuleContext


# --------------------------------------------------------------------------------------
# Synthetic doubles (no Azure, no network).
# --------------------------------------------------------------------------------------
class FakeChannel:
    """Records every routed notification instead of sending it. Injected as the notifier.

    Declares ``egresses_out_of_boundary = False`` so it doubles as the IN-BOUNDARY channel stub:
    the module keeps the raw ``findingId`` for it (proving the opaque-id policy is boundary-gated,
    not a blanket hash).
    """

    egresses_out_of_boundary = False

    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    def send(self, notification: Mapping[str, Any]) -> DeliveryResult:
        self.sent.append(dict(notification))
        return DeliveryResult(channel=str(notification["channel"]), delivered=True)


class EgressChannel:
    """OUT-OF-BOUNDARY channel stub (like ``WebhookChannel``): findingId must be opaqued."""

    egresses_out_of_boundary = True

    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    def send(self, notification: Mapping[str, Any]) -> DeliveryResult:
        self.sent.append(dict(notification))
        return DeliveryResult(channel=str(notification["channel"]), delivered=True)


class MarkerlessChannel:
    """Channel with NO boundary marker — the module must fail closed and opaque the id."""

    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    def send(self, notification: Mapping[str, Any]) -> DeliveryResult:
        self.sent.append(dict(notification))
        return DeliveryResult(channel=str(notification["channel"]), delivered=True)


class FakeState:
    """Read-only state double exposing just what the module reads."""

    def __init__(self, findings_by_workload: dict[str, list[Finding]]) -> None:
        self._findings = findings_by_workload

    def list_workloads(self) -> list[str]:
        return list(self._findings)

    def get_findings(self, workload: str, module: str | None = None) -> list[Finding]:
        return list(self._findings.get(workload, []))


class FakePack:
    def __init__(self, body: dict[str, Any]) -> None:
        self.body = body


class FakeOpsPacks:
    """Packs-engine double returning fixed Ops Packs for any workload."""

    def __init__(self, packs: list[FakePack]) -> None:
        self._packs = packs

    def load_for_workload(self, workload: str, pack_type: PackType) -> list[FakePack]:
        assert pack_type == PackType.ops
        return list(self._packs)


def _failing(fid: str, severity: Severity, blast: int) -> Finding:
    return Finding(id=fid, module="quality_checks", title=f"check {fid}", passed=False,
                   nodeId=f"/synthetic/{fid}", severity=severity, blastRadius=blast)


def _ops_pack() -> FakePack:
    return FakePack({
        "routes": {"critical": "page", "high": "oncall", "medium": "ticket"},
        "default": "ticket",
        "runbook": "kb/epic-odb-runbook",  # synthetic link, not a real/secret URL
    })


# --------------------------------------------------------------------------------------
# Pure: weight_by_blast_radius (radius bands) — never downgrades.
# --------------------------------------------------------------------------------------
def test_weight_by_blast_radius_bands() -> None:
    assert weight_by_blast_radius(_failing("a", Severity.info, 0)) == Severity.info
    assert weight_by_blast_radius(_failing("b", Severity.low, 1)) == Severity.medium
    assert weight_by_blast_radius(_failing("c", Severity.medium, 4)) == Severity.high
    assert weight_by_blast_radius(_failing("d", Severity.high, 5)) == Severity.critical
    assert weight_by_blast_radius(_failing("e", Severity.info, 6)) == Severity.critical


def test_weight_by_blast_radius_never_downgrades() -> None:
    # Already critical, no blast radius: stays critical (monotonic escalation only).
    assert weight_by_blast_radius(_failing("f", Severity.critical, 0)) == Severity.critical


# --------------------------------------------------------------------------------------
# Pure: route + ops routing table.
# --------------------------------------------------------------------------------------
def test_route_maps_escalated_severity_to_ops_channel() -> None:
    decision = route(_failing("g", Severity.medium, 6),
                     {"routes": {"critical": "page"}, "default": "ticket", "runbook": "kb/r"})
    assert decision["severity"] == "critical"
    assert decision["channel"] == "page"
    assert decision["runbook"] == "kb/r"


def test_route_falls_back_to_default_channel() -> None:
    decision = route(_failing("h", Severity.low, 0), {"default": "ticket"})
    assert decision["channel"] == "ticket"


def test_load_ops_routing_merges_bodies() -> None:
    ops = load_ops_routing(FakeOpsPacks([_ops_pack()]), "epic")
    assert ops["routes"]["critical"] == "page"
    assert ops["default"] == "ticket"
    assert ops["runbook"] == "kb/epic-odb-runbook"


def test_load_ops_routing_fails_closed_without_packs() -> None:
    assert load_ops_routing(None, "epic") == {}


# --------------------------------------------------------------------------------------
# run(): delivery via injected channel + audit records.
# --------------------------------------------------------------------------------------
def test_run_delivers_failing_finding_and_records_audit() -> None:
    failing = _failing("q1", Severity.medium, 6)  # -> escalates to critical -> "page"
    passing = Finding(id="q2", module="quality_checks", title="ok", passed=True,
                      severity=Severity.info)
    state = FakeState({"epic": [failing, passing]})
    channel = FakeChannel()
    ctx = ModuleContext(state=state, clients={"notifier": channel},
                        packs=FakeOpsPacks([_ops_pack()]))

    result = AlertsModule().run(ctx, scope={})

    # Blast-radius escalation + Ops-pack routing delivered exactly the failing finding.
    assert len(channel.sent) == 1
    sent = channel.sent[0]
    # FIX 1: outbound payload is an EXPLICIT allowlist — no nodeId/title/detail leaks out.
    assert set(sent.keys()) == {"findingId", "severity", "channel", "runbook"}
    assert sent["findingId"] == "q1"
    assert sent["severity"] == "critical"
    assert sent["channel"] == "page"
    assert sent["runbook"] == "kb/epic-odb-runbook"

    notifications = result.extra["notifications"]
    assert len(notifications) == 1  # passing finding was not routed
    audit = notifications[0]
    assert audit == {
        "workload": "epic",
        "findingId": "q1",
        "severity": "critical",
        "channel": "page",
        "delivered": True,
        "suppressed": False,
        "runbook": "kb/epic-odb-runbook",
    }
    assert result.ok is True


def test_run_outbound_payload_excludes_customer_derived_fields() -> None:
    # FIX 1: even though the finding carries nodeId/title, they must NOT cross the boundary.
    failing = _failing("q1", Severity.medium, 6)
    assert failing.nodeId  # fixture really has a node id + title...
    assert failing.title
    channel = FakeChannel()
    ctx = ModuleContext(state=FakeState({"epic": [failing]}),
                        clients={"notifier": channel}, packs=FakeOpsPacks([_ops_pack()]))

    AlertsModule().run(ctx, scope={})

    sent = channel.sent[0]
    assert set(sent.keys()) == {"findingId", "severity", "channel", "runbook"}
    assert "nodeId" not in sent
    assert "title" not in sent


def test_run_isinstance_channel_protocol() -> None:
    # FakeChannel structurally satisfies the delivery Protocol (runtime_checkable seam).
    assert isinstance(FakeChannel(), NotificationChannel)


def test_run_suppresses_none_route_without_sending() -> None:
    # FIX 2: an Ops Pack routing a severity to "none" silences delivery entirely.
    failing = _failing("q1", Severity.info, 0)  # stays info -> routed to "none"
    channel = FakeChannel()
    ops = FakePack({"routes": {"info": "none"}, "default": "ticket"})
    ctx = ModuleContext(state=FakeState({"epic": [failing]}),
                        clients={"notifier": channel}, packs=FakeOpsPacks([ops]))

    result = AlertsModule().run(ctx, scope={})

    assert channel.sent == []  # notifier was never called
    notifications = result.extra["notifications"]
    assert len(notifications) == 1
    audit = notifications[0]
    assert audit["channel"] == "none"
    assert audit["suppressed"] is True
    assert audit["delivered"] is False
    assert result.ok is True


def test_run_fails_closed_without_notifier() -> None:
    failing = _failing("q1", Severity.high, 2)
    passing = Finding(id="q2", module="quality_checks", title="ok", passed=True)
    state = FakeState({"epic": [failing, passing]})
    ctx = ModuleContext(state=state, clients={}, packs=FakeOpsPacks([_ops_pack()]))

    result = AlertsModule().run(ctx, scope={})

    notifications = result.extra["notifications"]
    assert len(notifications) == 1  # route computed for the failing finding only
    audit = notifications[0]
    assert audit["findingId"] == "q1"
    assert audit["delivered"] is False  # fail closed: no notifier -> undelivered, no crash
    assert audit["suppressed"] is False  # a real channel was decided, just not delivered
    assert audit["channel"]  # a channel was still decided
    assert result.ok is True


def test_run_no_state_is_noop() -> None:
    result = AlertsModule().run(ModuleContext(), scope={})
    assert result.ok is True
    assert result.extra["notifications"] == []


# --------------------------------------------------------------------------------------
# Opaque/sanitized finding ids for out-of-boundary egress (#78).
# --------------------------------------------------------------------------------------
def _egress_finding() -> Finding:
    # Mirrors the real quality_checks id format "{rule}::{node.id}" so the raw id embeds node.id.
    node = "/synthetic/rg/db-node-01"
    return Finding(id=f"require-tag::{node}", module="quality_checks", title="tag check",
                   passed=False, nodeId=node, severity=Severity.medium, blastRadius=6)


def test_opaque_finding_id_is_deterministic_bounded_hex() -> None:
    fid = "require-tag::/synthetic/rg/db-node-01"
    token = opaque_finding_id(fid)
    assert token == opaque_finding_id(fid)  # deterministic
    assert len(token) == 64
    assert token == token.lower()
    assert all(c in "0123456789abcdef" for c in token)  # lowercase hex, control-free


def test_opaque_finding_id_hides_raw_id_and_node_id() -> None:
    node = "/synthetic/rg/db-node-01"
    fid = f"require-tag::{node}"
    token = opaque_finding_id(fid)
    assert token != fid
    assert node not in token
    assert "db-node-01" not in token
    assert fid not in token


def test_opaque_finding_id_is_domain_separated() -> None:
    import hashlib

    fid = "require-tag::/synthetic/rg/db-node-01"
    plain = hashlib.sha256(fid.encode("utf-8")).hexdigest()  # NO domain prefix
    assert opaque_finding_id(fid) != plain  # domain separation changes the token space


def test_opaque_finding_id_handles_surrogate_and_unicode() -> None:
    # A lone surrogate (as json/yaml can yield) must hash without raising (errors="surrogatepass").
    assert len(opaque_finding_id("rule::" + chr(0xD800))) == 64
    assert len(opaque_finding_id("rule::/synthetic/café-\u3053\u3093")) == 64


def test_channel_egresses_out_of_boundary_fail_closed() -> None:
    assert channel_egresses_out_of_boundary(EgressChannel()) is True
    assert channel_egresses_out_of_boundary(FakeChannel()) is False  # explicit in-boundary
    assert channel_egresses_out_of_boundary(MarkerlessChannel()) is True  # missing marker
    assert channel_egresses_out_of_boundary(None) is True  # no notifier
    assert channel_egresses_out_of_boundary(WebhookChannel(
        "https://alerts.internal.invalid/hook", transport=_boom_transport())) is True

    class NonBoolMarker:
        egresses_out_of_boundary = "no"  # not a bool -> unreadable -> fail closed

        def send(self, notification: Mapping[str, Any]) -> DeliveryResult:  # pragma: no cover
            return DeliveryResult(channel="x", delivered=True)

    assert channel_egresses_out_of_boundary(NonBoolMarker()) is True


def test_run_opaques_finding_id_for_out_of_boundary_channel() -> None:
    finding = _egress_finding()  # escalates to critical -> "page"
    channel = EgressChannel()
    ctx = ModuleContext(state=FakeState({"epic": [finding]}),
                        clients={"notifier": channel}, packs=FakeOpsPacks([_ops_pack()]))

    AlertsModule().run(ctx, scope={})

    assert len(channel.sent) == 1
    sent = channel.sent[0]
    assert set(sent.keys()) == {"findingId", "severity", "channel", "runbook"}  # allowlist intact
    outbound = sent["findingId"]
    assert outbound == opaque_finding_id(finding.id)  # opaque token, not the raw id
    assert outbound != finding.id
    assert finding.nodeId not in outbound  # node id never crosses the boundary
    assert finding.id not in outbound
    assert len(outbound) == 64 and outbound == outbound.lower()
    assert all(c in "0123456789abcdef" for c in outbound)


def test_run_opaque_finding_id_is_deterministic_across_runs() -> None:
    finding = _egress_finding()

    def _deliver_once() -> str:
        channel = EgressChannel()
        ctx = ModuleContext(state=FakeState({"epic": [finding]}),
                            clients={"notifier": channel}, packs=FakeOpsPacks([_ops_pack()]))
        AlertsModule().run(ctx, scope={})
        return str(channel.sent[0]["findingId"])

    assert _deliver_once() == _deliver_once()  # external dedup still works


def test_run_keeps_raw_finding_id_for_in_boundary_channel() -> None:
    # An explicitly in-boundary channel (marker False) keeps the raw id — policy is boundary-gated.
    finding = _egress_finding()
    channel = FakeChannel()
    ctx = ModuleContext(state=FakeState({"epic": [finding]}),
                        clients={"notifier": channel}, packs=FakeOpsPacks([_ops_pack()]))

    AlertsModule().run(ctx, scope={})

    assert channel.sent[0]["findingId"] == finding.id  # raw id retained in boundary


def test_run_fails_closed_and_opaques_when_marker_missing() -> None:
    # A channel with NO boundary marker is treated as out-of-boundary (fail closed) -> opaqued.
    finding = _egress_finding()
    channel = MarkerlessChannel()
    ctx = ModuleContext(state=FakeState({"epic": [finding]}),
                        clients={"notifier": channel}, packs=FakeOpsPacks([_ops_pack()]))

    AlertsModule().run(ctx, scope={})

    outbound = channel.sent[0]["findingId"]
    assert outbound == opaque_finding_id(finding.id)
    assert outbound != finding.id
    assert finding.nodeId not in outbound


def test_run_audit_keeps_raw_finding_id_even_when_egressed_opaque() -> None:
    # The IN-BOUNDARY audit trail keeps the raw id for correlation/dedup even though the OUTBOUND
    # copy was opaqued for the out-of-boundary channel.
    finding = _egress_finding()
    channel = EgressChannel()
    ctx = ModuleContext(state=FakeState({"epic": [finding]}),
                        clients={"notifier": channel}, packs=FakeOpsPacks([_ops_pack()]))

    result = AlertsModule().run(ctx, scope={})

    audit = result.extra["notifications"][0]
    assert audit["findingId"] == finding.id  # raw id preserved in-boundary
    assert channel.sent[0]["findingId"] != finding.id  # but opaqued outbound


# --------------------------------------------------------------------------------------
# HTTPS enforcement (#84): the shared validator + channel defense-in-depth (no network).
# --------------------------------------------------------------------------------------
def _boom_transport() -> httpx.MockTransport:
    # A transport that errors if ever dialled — proves construction never touches the network.
    def _boom(_req: httpx.Request) -> httpx.Response:  # pragma: no cover - must never be called
        raise AssertionError("network must not be touched")

    return httpx.MockTransport(_boom)


def test_require_https_webhook_accepts_https() -> None:
    url = "https://alerts.internal.invalid/hook"
    assert require_https_webhook(url) == url


@pytest.mark.parametrize(
    "bad_url",
    [
        "http://alerts.evil.invalid/hook",  # cleartext, non-loopback
        "",  # blank
        "   ",  # whitespace only
        "alerts.internal.invalid/hook",  # scheme-less
        "https://",  # no host
        "ftp://alerts.internal.invalid/hook",  # wrong scheme
    ],
)
def test_require_https_webhook_rejects_non_https(bad_url: str) -> None:
    with pytest.raises(InsecureWebhookError):
        require_https_webhook(bad_url)


def test_require_https_webhook_loopback_rejected_by_default() -> None:
    with pytest.raises(InsecureWebhookError):
        require_https_webhook("http://127.0.0.1:9000/hook")


@pytest.mark.parametrize(
    "loopback_url",
    [
        "http://127.0.0.1:9000/hook",
        "http://127.0.0.1/hook",
        "http://localhost:9000/hook",
        "http://LocalHost/hook",  # case-insensitive host
        "http://[::1]:9000/hook",  # IPv6 loopback
        "http://127.5.5.5/hook",  # anywhere in 127.0.0.0/8
    ],
)
def test_require_https_webhook_loopback_accepted_with_optout(loopback_url: str) -> None:
    assert require_https_webhook(loopback_url, allow_insecure_loopback=True) == loopback_url


@pytest.mark.parametrize(
    "spoofed_url",
    [
        "http://127.0.0.1.evil.com/hook",
        "http://localhost.evil.com/hook",
        "http://127.0.0.1@evil.com/hook",  # userinfo trick — real host is evil.com
    ],
)
def test_require_https_webhook_spoofed_loopback_rejected_even_with_optout(spoofed_url: str) -> None:
    with pytest.raises(InsecureWebhookError):
        require_https_webhook(spoofed_url, allow_insecure_loopback=True)


def test_require_https_webhook_error_message_is_pii_free() -> None:
    with pytest.raises(InsecureWebhookError) as excinfo:
        require_https_webhook("http://alerts.evil.invalid/hook?token=SECRET123")
    message = str(excinfo.value)
    assert "SECRET123" not in message  # query/token never echoed
    assert "/hook" not in message  # path never echoed


def test_webhook_channel_constructor_rejects_cleartext() -> None:
    # Defense in depth: constructing the channel directly still refuses a non-HTTPS URL.
    with pytest.raises(InsecureWebhookError):
        WebhookChannel("http://alerts.evil.invalid/hook", transport=_boom_transport())


def test_webhook_channel_constructor_accepts_https() -> None:
    channel = WebhookChannel("https://alerts.internal.invalid/hook", transport=_boom_transport())
    assert isinstance(channel, NotificationChannel)


def test_webhook_channel_constructor_allows_loopback_optout() -> None:
    channel = WebhookChannel(
        "http://127.0.0.1:9000/hook", allow_insecure_loopback=True, transport=_boom_transport()
    )
    assert isinstance(channel, NotificationChannel)


def test_build_webhook_channel_rejects_cleartext() -> None:
    from modules.alerts.channels import WEBHOOK_URL_CONFIG_KEY

    with pytest.raises(InsecureWebhookError):
        build_webhook_channel(
            {WEBHOOK_URL_CONFIG_KEY: "http://alerts.evil.invalid/hook"},
            transport=_boom_transport(),
        )


def test_build_webhook_channel_loopback_optout_via_config() -> None:
    from modules.alerts.channels import (
        WEBHOOK_ALLOW_INSECURE_LOOPBACK_CONFIG_KEY,
        WEBHOOK_URL_CONFIG_KEY,
    )

    channel = build_webhook_channel(
        {
            WEBHOOK_URL_CONFIG_KEY: "http://127.0.0.1:9000/hook",
            WEBHOOK_ALLOW_INSECURE_LOOPBACK_CONFIG_KEY: "true",
        },
        transport=_boom_transport(),
    )
    assert channel is not None


# --------------------------------------------------------------------------------------
# R1 MED 2 (#84): a malformed / userinfo-bearing / bad-port URL raises a CONSTANT sanitized
# error — the raw netloc (incl. user:token@host) never leaks via a urlparse/.port ValueError.
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "leaky_url",
    [
        "https://user:SECRETTOKEN@alerts.evil.invalid:bad/hook",  # userinfo + bad port
        "http://admin:hunter2@127.0.0.1:notaport/hook",  # userinfo + non-numeric port
        "https://alerts.evil.invalid:99999/hook?token=SECRETTOKEN",  # out-of-range port
    ],
)
def test_require_https_webhook_malformed_url_error_is_sanitized(leaky_url: str) -> None:
    with pytest.raises(InsecureWebhookError) as excinfo:
        require_https_webhook(leaky_url, allow_insecure_loopback=True)
    message = str(excinfo.value)
    # No userinfo, host, token or port fragment from the raw URL may appear in the message.
    for secret in ("SECRETTOKEN", "hunter2", "admin", "user", "alerts.evil.invalid", "127.0.0.1",
                   "notaport", "99999", "bad"):
        assert secret not in message
    # And the leaking ValueError cause is suppressed (raise ... from None).
    assert excinfo.value.__cause__ is None


# --------------------------------------------------------------------------------------
# R1 MED 3 (#84): an invalid port fails closed AT VALIDATION, not late inside httpx at send().
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "bad_port_url",
    [
        "https://alerts.internal.invalid:bad/hook",  # https, non-numeric port
        "https://alerts.internal.invalid:70000/hook",  # https, out-of-range port
        "http://127.0.0.1:bad/hook",  # opted-in loopback http, non-numeric port
    ],
)
def test_require_https_webhook_rejects_invalid_port_at_validation(bad_port_url: str) -> None:
    # Rejected by the validator itself (config time) — a WebhookChannel is never even constructed.
    with pytest.raises(InsecureWebhookError):
        require_https_webhook(bad_port_url, allow_insecure_loopback=True)


def test_webhook_channel_rejects_invalid_port_at_construction() -> None:
    with pytest.raises(InsecureWebhookError):
        WebhookChannel("https://alerts.internal.invalid:bad/hook", transport=_boom_transport())


# --------------------------------------------------------------------------------------
# R1/R2 MED 1 (#84): the CHANNEL owns a hardened client — no caller can inject one with env
# proxies or redirect-following enabled. Verified via the PUBLIC channel API (not just wiring).
# --------------------------------------------------------------------------------------
def test_webhook_channel_owns_client_ignoring_env_proxies(monkeypatch) -> None:
    # A hostile environment proxy must NOT be honored — the channel builds its own trust_env=False
    # client, so HTTP_PROXY/HTTPS_PROXY/ALL_PROXY cannot exfiltrate the cleartext loopback POST.
    monkeypatch.setenv("HTTP_PROXY", "http://evil-proxy.invalid:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://evil-proxy.invalid:8080")
    monkeypatch.setenv("ALL_PROXY", "http://evil-proxy.invalid:8080")
    channel = WebhookChannel(
        "http://127.0.0.1:9000/hook", allow_insecure_loopback=True, transport=_boom_transport()
    )
    client = channel._client
    try:
        assert client.trust_env is False
        assert client.follow_redirects is False
        assert client._mounts == {}  # no proxy transport mounted for either scheme
    finally:
        client.close()


def test_build_webhook_channel_owns_client_ignoring_env_proxies(monkeypatch) -> None:
    from modules.alerts.channels import WEBHOOK_URL_CONFIG_KEY

    monkeypatch.setenv("HTTPS_PROXY", "http://evil-proxy.invalid:8080")
    channel = build_webhook_channel(
        {WEBHOOK_URL_CONFIG_KEY: "https://alerts.internal.invalid/hook"},
        transport=_boom_transport(),
    )
    assert channel is not None
    client = channel._client
    try:
        assert client.trust_env is False
        assert client.follow_redirects is False
    finally:
        client.close()


def test_webhook_channel_does_not_follow_redirect_downgrade() -> None:
    # An https endpoint answering 307 -> http:// must NOT be followed (no cleartext downgrade),
    # asserted through the PUBLIC channel API (the channel owns the non-redirecting client).
    seen: list[httpx.URL] = []

    def _handler(req: httpx.Request) -> httpx.Response:
        seen.append(req.url)
        if req.url.scheme == "https":
            return httpx.Response(
                307, headers={"Location": "http://alerts.internal.invalid/hook"}
            )
        # Reaching the http target would mean the redirect was followed (cleartext downgrade).
        raise AssertionError("redirect to http:// must not be followed")

    channel = WebhookChannel(
        "https://alerts.internal.invalid/hook", transport=httpx.MockTransport(_handler)
    )
    try:
        result = channel.send({"channel": "page", "findingId": "q1"})
    finally:
        channel._client.close()

    # The redirect was NOT followed: exactly one (https) request, surfaced as undelivered non-2xx.
    assert [u.scheme for u in seen] == ["https"]
    assert result.delivered is False
    assert result.statusCode == 307


def test_webhook_http_client_hardening_flags() -> None:
    # The low-level seam builder is hardened by default (channel + wiring both rely on this).
    client = build_webhook_http_client()
    try:
        assert client.trust_env is False
        assert client.follow_redirects is False
    finally:
        client.close()


# --------------------------------------------------------------------------------------
# R2 MED 2 (#84): the validator uses httpx's OWN parser as source of truth, so a URL httpx would
# reject at send() (control chars, invalid IDNA, ...) is rejected AT VALIDATION with the constant
# sanitized error — never a late, uncaught httpx.InvalidURL/idna.IDNAError leaking host data.
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "mismatch_url",
    [
        "https\t://alerts.internal.invalid/hook",  # control char in scheme (httpx.InvalidURL)
        "https://alerts.internal.invalid\n/hook",  # control char in host
        "https://xn--.invalid/hook",  # invalid A-label (idna.IDNAError, a UnicodeError)
        "https://xn--a.invalid/hook",  # malformed punycode host
        "https://\u0080.invalid/hook",  # non-ASCII control host → IDNA failure
    ],
)
def test_require_https_webhook_rejects_httpx_parser_mismatches(mismatch_url: str) -> None:
    from modules.alerts.channels import _MALFORMED_WEBHOOK_MSG

    with pytest.raises(InsecureWebhookError) as excinfo:
        require_https_webhook(mismatch_url)
    # Constant sanitized message; the attacker host substring is absent; leaking cause suppressed.
    assert str(excinfo.value) == _MALFORMED_WEBHOOK_MSG
    assert "alerts.internal.invalid" not in str(excinfo.value)
    assert "xn--" not in str(excinfo.value)
    assert excinfo.value.__cause__ is None


def test_require_https_webhook_mismatch_rejected_at_validation_not_send() -> None:
    # The whole point: a parser mismatch fails closed HERE — a WebhookChannel is never constructed
    # (so httpx never raises an uncaught InvalidURL/IDNAError at send()).
    with pytest.raises(InsecureWebhookError):
        WebhookChannel("https\t://alerts.internal.invalid/hook", transport=_boom_transport())


# --------------------------------------------------------------------------------------
# R3 MED (#84): httpx.URL() succeeding does NOT guarantee httpx.Request() can be built. An IPv6
# zone-id with a non-ASCII char parses + passes URL validation but raises UnicodeEncodeError while
# encoding the Host header at send(), leaking the netloc. The request-construction preflight must
# reject it AT VALIDATION with the constant sanitized error — never late/uncaught at delivery.
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "url_ok_request_bad",
    [
        "https://[::1%zone\u3002]/hook",  # IPv6 zone-id + ideographic full stop
        "https://[::1%25zone\u3002]/hook",  # percent-encoded zone marker + non-ASCII
        "https://[fe80::1%\u3002]/hook",  # link-local zone-id, bare non-ASCII zone
    ],
)
def test_require_https_webhook_rejects_late_request_leak(url_ok_request_bad: str) -> None:
    import httpx

    from modules.alerts.channels import _MALFORMED_WEBHOOK_MSG

    # Precondition: this really is the URL-ok-but-Request-bad class (else the test proves nothing).
    parsed = httpx.URL(url_ok_request_bad)  # must NOT raise
    with pytest.raises(UnicodeError):
        httpx.Request("POST", parsed)  # httpx itself cannot build the request

    with pytest.raises(InsecureWebhookError) as excinfo:
        require_https_webhook(url_ok_request_bad)
    message = str(excinfo.value)
    assert message == _MALFORMED_WEBHOOK_MSG  # constant sanitized error
    # No netloc / host / zone fragment leaks into the message or the suppressed cause.
    for leak in ("::1", "fe80", "zone", "\u3002"):
        assert leak not in message
    assert excinfo.value.__cause__ is None


def test_request_preflight_rejected_at_validation_not_send() -> None:
    # Fails closed at construction — a WebhookChannel is never built, so send() is unreachable and
    # the leaking UnicodeEncodeError never fires (no netloc reaches any exception/log at delivery).
    with pytest.raises(InsecureWebhookError):
        WebhookChannel("https://[::1%zone\u3002]/hook", transport=_boom_transport())


# --------------------------------------------------------------------------------------
# R4 MED (#84): CLASS-CLOSING host allowlist. A malformed bracketed IPv6 authority survives
# httpx.URL() + the httpx.Request preflight (httpx.URL.host strips the [ ] but keeps junk contents)
# and only blows up later in httpx's RESPONSE cookie-jar URL parse at send(), leaking the raw host
# (and any token in the URL). The validator now requires the canonical host to be EXACTLY one of
# three well-formed shapes (IPv6 / IPv4 / DNS), so such authorities are rejected AT VALIDATION and
# the transport is never reached.
# --------------------------------------------------------------------------------------
def _counting_transport() -> tuple[httpx.MockTransport, list[httpx.Request]]:
    # Records every request it is asked to handle, so a test can assert ZERO transport calls.
    seen: list[httpx.Request] = []

    def _handler(req: httpx.Request) -> httpx.Response:  # pragma: no cover - must never be called
        seen.append(req)
        return httpx.Response(200)

    return httpx.MockTransport(_handler), seen


def test_require_https_webhook_rejects_malformed_ipv6_authority_no_leak() -> None:
    from modules.alerts.channels import _MALFORMED_WEBHOOK_MSG

    leaky = "https://[fd00:1234:5678::abcd%]:x]/private/path?token=SECRET#frag"
    with pytest.raises(InsecureWebhookError) as excinfo:
        require_https_webhook(leaky)
    message = str(excinfo.value)
    assert message == _MALFORMED_WEBHOOK_MSG  # constant sanitized error
    # None of the attacker-controlled host / token / structural fragments leak anywhere.
    for leak in ("fd00", "abcd", "token", "SECRET", "%", "]"):
        assert leak not in message
    assert excinfo.value.__cause__ is None


def test_webhook_channel_malformed_ipv6_authority_never_reaches_transport() -> None:
    # Fail closed at construction: the malformed authority is rejected before any send(), so the
    # counting transport records ZERO calls (the cookie-jar leak at delivery is unreachable).
    transport, seen = _counting_transport()
    leaky = "https://[fd00:1234:5678::abcd%]:x]/private/path?token=SECRET#frag"
    with pytest.raises(InsecureWebhookError):
        WebhookChannel(leaky, transport=transport)
    assert seen == []


@pytest.mark.parametrize(
    "bad_authority",
    [
        "https://[fd00::1%]/hook",  # empty/malformed zone id
        "https://[fd00::1%]:9]/hook",  # junk after the closing bracket
        "https://[gggg::1]/hook",  # non-hex IPv6 groups
        "https://[fd00::abcd%]:x]/hook",  # trailing ]:x junk (the R4 class)
        "https://[::1",  # missing closing bracket
        "https://[]/hook",  # empty brackets
        "https://[fd00:::1]/hook",  # triple-colon (invalid IPv6)
    ],
)
def test_require_https_webhook_rejects_malformed_ipv6_matrix(bad_authority: str) -> None:
    from modules.alerts.channels import _MALFORMED_WEBHOOK_MSG

    with pytest.raises(InsecureWebhookError) as excinfo:
        require_https_webhook(bad_authority)
    assert str(excinfo.value) == _MALFORMED_WEBHOOK_MSG
    assert excinfo.value.__cause__ is None


@pytest.mark.parametrize(
    ("url", "allow_loopback"),
    [
        ("https://alerts.internal.invalid/hook", False),  # normal https DNS host
        ("https://[2001:db8::1]/hook", False),  # valid bracketed IPv6 literal
        ("http://[::1]/hook", True),  # opt-in loopback IPv6 literal
        ("http://127.0.0.1/hook", True),  # opt-in loopback IPv4 literal
    ],
)
def test_webhook_channel_delivers_to_well_formed_hosts(url: str, allow_loopback: bool) -> None:
    # Positive path: every well-formed shape still delivers, and delivery POSTs to the CANONICAL
    # validated URL (byte-identical to httpx.URL(url)) — send() never re-parses a different string.
    seen: list[httpx.URL] = []

    def _handler(req: httpx.Request) -> httpx.Response:
        seen.append(req.url)
        return httpx.Response(200)

    channel = WebhookChannel(
        url, allow_insecure_loopback=allow_loopback, transport=httpx.MockTransport(_handler)
    )
    try:
        result = channel.send({"channel": "page", "findingId": "q1"})
    finally:
        channel._client.close()

    assert result.delivered is True
    assert result.statusCode == 200
    assert len(seen) == 1
    assert seen[0] == httpx.URL(url)  # delivered to the canonical validated URL


# --------------------------------------------------------------------------------------
# R5 MED (#84): DNS labels / IPv6 zone ids have NO length limit, so an over-long label/zone passes
# the 3-shape allowlist + httpx.URL/httpx.Request preflights but raises an UNCAUGHT UnicodeError
# ("label too long") in the idna codec during getaddrinfo at send() — whose .object/.args carry the
# COMPLETE canonical host (attacker-chosen, secret-looking). Fix: enforce DNS length bounds
# (total ≤ 253, label 1..63) and IPv6 zone length (≤ 63) at VALIDATION (fail closed), plus a
# defensive UnicodeError late-catch in send() converting to a CONSTANT sanitized detail (no leak).
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "overlong_url",
    [
        "https://" + "a" * 64 + ".invalid/private?token=SECRET",  # single label > 63
        "https://" + ".".join(["a" * 63] * 5) + ".invalid/x?token=SECRET",  # total host > 253
    ],
)
def test_require_https_webhook_rejects_overlong_dns_no_leak(overlong_url: str) -> None:
    from modules.alerts.channels import _MALFORMED_WEBHOOK_MSG

    with pytest.raises(InsecureWebhookError) as excinfo:
        require_https_webhook(overlong_url)
    message = str(excinfo.value)
    assert message == _MALFORMED_WEBHOOK_MSG  # constant sanitized error
    # The over-long host run and any secret-looking token never leak into the message.
    for leak in ("a" * 64, "a" * 63, "token", "SECRET"):
        assert leak not in message
    assert excinfo.value.__cause__ is None


def test_webhook_channel_rejects_overlong_dns_at_construction() -> None:
    # Fail closed at construction — the leak PoC never becomes a live channel (send() unreachable).
    with pytest.raises(InsecureWebhookError):
        WebhookChannel("https://" + "a" * 64 + ".invalid/hook", transport=_boom_transport())


def test_require_https_webhook_rejects_overlong_ipv6_zone_no_leak() -> None:
    from modules.alerts.channels import _MALFORMED_WEBHOOK_MSG

    url = "https://[fe80::1%" + "Z" * 64 + "]/hook"
    with pytest.raises(InsecureWebhookError) as excinfo:
        require_https_webhook(url, allow_insecure_loopback=True)
    message = str(excinfo.value)
    assert message == _MALFORMED_WEBHOOK_MSG
    assert "Z" * 64 not in message
    assert "fe80" not in message
    assert excinfo.value.__cause__ is None


def test_require_https_webhook_accepts_max_valid_dns_label() -> None:
    # A 63-byte label (the DNS maximum) is still ACCEPTED — the bound rejects only > 63.
    url = "https://" + "a" * 63 + ".invalid/hook"
    assert require_https_webhook(url) == url


def test_webhook_channel_send_late_catch_sanitizes_unicode_host_leak() -> None:
    # Defense in depth: prove that IF a host somehow reaches send() and raises a UnicodeError in the
    # REAL idna/getaddrinfo path (MockTransport bypasses getaddrinfo, which is why the suite missed
    # this), the leaking host/token is converted to a CONSTANT sanitized detail. Validation now
    # blocks this URL, so we bypass it by setting the stored URL directly (using the real default
    # transport — no MockTransport) to simulate a future parser corner slipping past validation.
    from modules.alerts.channels import _SANITIZED_DELIVERY_DETAIL

    channel = WebhookChannel("https://alerts.internal.invalid/hook")  # real default transport
    channel._url = httpx.URL("https://" + "a" * 64 + ".invalid/private?token=SECRET")
    try:
        result = channel.send({"channel": "page", "findingId": "q1"})
    finally:
        channel._client.close()

    assert result.delivered is False  # fail closed
    assert result.detail == _SANITIZED_DELIVERY_DETAIL  # constant, host-free
    detail = result.detail or ""
    for leak in ("a" * 64, "token", "SECRET", "invalid"):
        assert leak not in detail


# --------------------------------------------------------------------------------------
# Final-gate MED (#84): the ``httpx.HTTPError`` delivery branch must NOT surface ``str(exc)`` —
# httpx messages are not host/URL-free by contract, so a connect/cert error would echo the
# configured webhook hostname (and a URL could carry a token). The detail must be a CONSTANT.
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "exc",
    [
        httpx.ConnectError("failed to connect to secret.host.example"),
        httpx.ConnectTimeout("timeout dialing secret.host.example?token=SECRET"),
        httpx.ReadError("read error from secret.host.example"),
    ],
)
def test_webhook_channel_http_error_detail_is_constant_host_free(exc: httpx.HTTPError) -> None:
    from modules.alerts.channels import _TRANSPORT_ERROR_DETAIL

    def _handler(_req: httpx.Request) -> httpx.Response:
        raise exc

    channel = WebhookChannel(
        "https://secret.host.example/path?token=SECRET", transport=httpx.MockTransport(_handler)
    )
    try:
        result = channel.send({"channel": "page", "findingId": "q1"})
    finally:
        channel._client.close()

    assert result.delivered is False  # fail closed
    # Constant, stable across httpx.HTTPError subtypes; NONE of the host / token / exc text leaks.
    assert result.detail == _TRANSPORT_ERROR_DETAIL
    detail = result.detail or ""
    for leak in ("secret.host.example", "token", "SECRET", str(exc)):
        assert leak not in detail


# --------------------------------------------------------------------------------------
# Final-gate LOW (#84): the loopback opt-out is EXACTLY ``::1`` for IPv6. An ipv4-mapped IPv6 form
# (``::ffff:127.0.0.1``) — which ``ipaddress``'s ``.is_loopback`` treats as loopback — is a
# disguised loopback and must be rejected everywhere (default-off, https, AND the opt-in) with the
# constant sanitized error. Genuine ``::1`` / ``127.0.0.1`` loopback sinks still work.
# --------------------------------------------------------------------------------------
def test_require_https_webhook_rejects_ipv4_mapped_loopback_no_leak() -> None:
    from modules.alerts.channels import _MALFORMED_WEBHOOK_MSG

    url = "http://[::ffff:127.0.0.1]/hook?token=SECRET"
    with pytest.raises(InsecureWebhookError) as excinfo:
        require_https_webhook(url, allow_insecure_loopback=True)  # even WITH the opt-out
    message = str(excinfo.value)
    assert message == _MALFORMED_WEBHOOK_MSG  # constant sanitized error
    for leak in ("ffff", "127.0.0.1", "token", "SECRET"):
        assert leak not in message
    assert excinfo.value.__cause__ is None


def test_webhook_channel_rejects_ipv4_mapped_loopback_even_with_optout() -> None:
    # Disguised loopback rejected at construction even with the opt-out — transport never dialled.
    with pytest.raises(InsecureWebhookError):
        WebhookChannel(
            "http://[::ffff:127.0.0.1]/hook",
            allow_insecure_loopback=True,
            transport=_boom_transport(),
        )


@pytest.mark.parametrize("url", ["http://[::1]/hook", "http://127.0.0.1/hook"])
def test_webhook_channel_genuine_loopback_still_delivers_with_optout(url: str) -> None:
    # The exact ``::1`` IPv6 sink and IPv4 ``127.0.0.1`` still deliver under the opt-out.
    seen: list[httpx.URL] = []

    def _handler(req: httpx.Request) -> httpx.Response:
        seen.append(req.url)
        return httpx.Response(200)

    channel = WebhookChannel(
        url, allow_insecure_loopback=True, transport=httpx.MockTransport(_handler)
    )
    try:
        result = channel.send({"channel": "page", "findingId": "q1"})
    finally:
        channel._client.close()

    assert result.delivered is True
    assert result.statusCode == 200
    assert seen == [httpx.URL(url)]  # canonical-URL delivery


@pytest.mark.parametrize(
    "url",
    ["http://[::1]/hook", "http://127.0.0.1/hook", "http://[::ffff:127.0.0.1]/hook"],
)
def test_require_https_webhook_all_http_rejected_with_optout_off(url: str) -> None:
    # Default OFF: every cleartext http:// URL (loopback or disguised) is rejected.
    with pytest.raises(InsecureWebhookError):
        require_https_webhook(url)
