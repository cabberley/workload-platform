"""Alerts & Notifications module unit tests — pure logic + delivery seam (Azure/network-free).

All fixtures are synthetic and clearly fake. Delivery is exercised through an injected
:class:`FakeChannel`; no test constructs :class:`WebhookChannel` or touches the network.
"""
from collections.abc import Mapping
from typing import Any

from modules.alerts.channels import DeliveryResult, NotificationChannel
from modules.alerts.module import (
    AlertsModule,
    load_ops_routing,
    route,
    weight_by_blast_radius,
)
from shared.contracts import Finding, PackType, Severity
from shared.module_base import ModuleContext


# --------------------------------------------------------------------------------------
# Synthetic doubles (no Azure, no network).
# --------------------------------------------------------------------------------------
class FakeChannel:
    """Records every routed notification instead of sending it. Injected as the notifier."""

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
