"""Alerts & Notifications module — route findings/incidents with blast-radius-weighted severity.

Always-on ACA **service** (1→10). Consumes **Ops Packs** (who to tell, how, and the runbook link)
and escalates severity by blast radius, so a failure that downs the whole workload pages, while an
isolated, redundant-node issue is a low-priority ticket.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from typing import Any, Protocol, cast, runtime_checkable

from shared.contracts import (
    AgentResponse,
    Finding,
    ModuleKind,
    ModuleManifest,
    ModuleRunResult,
    PackType,
    ScaleProfile,
    ScaleTrigger,
    Severity,
)
from shared.module_base import Module, ModuleContext
from shared.state import ReadableState

from .channels import DeliveryResult, NotificationChannel

_MANIFEST = ModuleManifest(
    name="alerts",
    displayName="Alerts & Notifications",
    kind=ModuleKind.service,
    consumes=[PackType.ops],
    produces=["notifications"],
    scaleProfile=ScaleProfile(
        kind=ModuleKind.service,
        minReplicas=1,
        maxReplicas=10,
        triggers=[ScaleTrigger(type="azure-queue", metadata={"queueName": "findings"})],
        cpu=0.5,
        memoryGi=1.0,
    ),
)

_ESCALATION_ORDER = [Severity.info, Severity.low, Severity.medium, Severity.high, Severity.critical]

# Channels that mean "silence this notification": an Ops Pack maps a severity here (e.g.
# ``info`` -> ``"none"``) to suppress delivery. Empty/whitespace channels are treated the same.
_SUPPRESSED_CHANNELS = frozenset({"none"})

# Domain-separation prefix for the opaque outbound finding-id digest (see ``opaque_finding_id``).
# Bumping the ``v1`` version (or the label) yields a DIFFERENT, non-colliding token space; keeping
# it stable keeps tokens deterministic so an out-of-boundary receiver can still dedup on them.
_OPAQUE_FINDING_ID_DOMAIN = b"wp-finding-id:v1|"


def opaque_finding_id(finding_id: str) -> str:
    """Opaque, keyless, deterministic token for an OUT-OF-BOUNDARY ``findingId``.

    A raw :attr:`Finding.id` is ``"{rule}::{node.id}"`` and thus embeds the customer resource node
    id. When a notification egresses OUTSIDE the customer boundary (see
    :attr:`~modules.alerts.channels.NotificationChannel.egresses_out_of_boundary`) the raw id must
    not leave, so we substitute this token. It is:

    * **keyless** — a plain domain-separated SHA-256, NO secret/HMAC key (keyless guardrail);
    * **deterministic/stable** — same input ⇒ same token, so an external receiver can still dedup;
    * **non-reversible** & **PII-free** — a one-way digest; the node id (nor any substring of it)
      cannot appear in the 64-hex output;
    * **bounded & control-free** — always 64 lowercase hex chars.

    The ``errors="surrogatepass"`` encoding is TOTAL and deterministic for ANY ``str`` (including a
    lone surrogate that strict UTF-8 cannot encode), mirroring the opaque-digest pattern in
    :func:`packs_engine.engine._audit_safe_identifier`, so hashing never raises.
    """
    return hashlib.sha256(
        _OPAQUE_FINDING_ID_DOMAIN + finding_id.encode("utf-8", errors="surrogatepass")
    ).hexdigest()


def is_suppressed(channel: str | None) -> bool:
    """True if a routed ``channel`` means "do not deliver" (suppression sentinel or empty)."""
    normalized = (channel or "").strip().casefold()
    return normalized == "" or normalized in _SUPPRESSED_CHANNELS


def weight_by_blast_radius(finding: Finding) -> Severity:
    """Pure severity escalation: bump severity up by blast radius bands.

    radius 0 -> unchanged; 1-4 -> +1 band; 5+ -> critical. Never downgrades.
    """
    idx = _ESCALATION_ORDER.index(finding.severity) if finding.severity in _ESCALATION_ORDER else 2
    if finding.blastRadius >= 5:
        return Severity.critical
    if finding.blastRadius >= 1:
        idx = min(idx + 1, len(_ESCALATION_ORDER) - 1)
    return _ESCALATION_ORDER[idx]


def route(finding: Finding, ops: dict) -> dict:
    """Pure routing decision: map an (escalated) finding to a channel per the Ops Pack."""
    severity = weight_by_blast_radius(finding)
    routes = ops.get("routes", {})
    channel = routes.get(severity.value, ops.get("default", "ticket"))
    return {
        "findingId": finding.id,
        "severity": severity.value,
        "channel": channel,
        "runbook": ops.get("runbook"),
    }


@runtime_checkable
class _OpsPack(Protocol):
    """Local view of a verified pack — the parsed body plus its shipped/imported provenance."""

    @property
    def body(self) -> Mapping[str, Any]: ...

    @property
    def imported(self) -> bool: ...


@runtime_checkable
class _OpsPacksSource(Protocol):
    """Local view of the packs engine: hand back verified Ops Packs for a workload."""

    def load_for_workload(self, workload: str, pack_type: PackType) -> Sequence[_OpsPack]: ...


def load_ops_routing(packs: object | None, workload: str) -> dict[str, Any]:
    """Merge verified **Ops Pack** bodies into a single routing table for :func:`route`.

    Ops Pack body shape (content, not code): ``{"routes": {<severity>: <channel>}, "default":
    <channel>, "runbook": <url>}``. Fail closed: if the packs engine is absent or a pack fails
    verification, return ``{}`` so routing falls back to the safe default channel instead of acting
    on an unverified pack.
    """
    if packs is None:
        return {}
    source = cast(_OpsPacksSource, packs)
    routes: dict[str, str] = {}
    ops: dict[str, Any] = {"routes": routes}
    try:
        loaded = source.load_for_workload(workload, PackType.ops)
    except Exception:  # unverifiable/unavailable ops packs -> fail closed, no routing table
        return {}
    # Shipped Ops policy is AUTHORITATIVE per key: a signed IMPORTED pack (customer/third-party,
    # store-resolved) may only CONTRIBUTE routing keys the shipped policy does not already define —
    # it may NEVER override (suppress/reroute) a shipped ``route``, ``default`` or ``runbook`` and
    # thus can never, e.g., divert ``critical`` away from paging. In this last-wins merge we apply
    # IMPORTED packs FIRST and SHIPPED packs LAST so shipped keys win. This does not rely on engine
    # iteration order: provenance is read from ``pack.imported`` (PacksEngine.load_all marks
    # store-resolved packs ``imported=True``; shipped content-root packs default to ``False``).
    ordered = sorted(
        loaded, key=lambda p: bool(getattr(p, "imported", False)), reverse=True
    )
    for pack in ordered:
        body = pack.body
        pack_routes = body.get("routes")
        if isinstance(pack_routes, Mapping):
            routes.update({str(k): str(v) for k, v in pack_routes.items()})
        if body.get("default") is not None:
            ops["default"] = body["default"]
        if body.get("runbook"):
            ops["runbook"] = body["runbook"]
    return ops


def _notification_payload(
    finding: Finding, decision: Mapping[str, Any], *, out_of_boundary: bool
) -> dict[str, Any]:
    """Build the outbound payload as an EXPLICIT allowlist — this data leaves the boundary.

    Only ``findingId``, ``severity``, ``channel`` and ``runbook`` are ever egressed. This is a
    deliberate allowlist, NOT a pass-through of ``Finding`` fields: ``nodeId``, ``title``,
    ``detail``, ``evidence`` and the raw finding are excluded so no unconstrained,
    customer-derived data crosses the process boundary.

    Egress policy for ``findingId`` (issue #78): the raw :attr:`Finding.id` is
    ``"{rule}::{node.id}"`` and embeds the customer resource node id. When the target channel
    egresses OUT OF the customer boundary (``out_of_boundary`` true — the fail-closed default for an
    unknown/undeclared boundary) the id is replaced with :func:`opaque_finding_id`, a keyless,
    deterministic, non-reversible 64-hex token that carries no node id. Only an IN-boundary channel
    (explicitly ``egresses_out_of_boundary is False``) keeps the raw id. The raw id is UNCHANGED in
    in-boundary state (audit/correlation/dedup); only this outbound copy is opaqued.
    """
    finding_id = opaque_finding_id(finding.id) if out_of_boundary else finding.id
    return {
        "findingId": finding_id,
        "severity": decision["severity"],
        "channel": decision["channel"],
        "runbook": decision.get("runbook"),
    }


def channel_egresses_out_of_boundary(notifier: object | None) -> bool:
    """Fail-closed read of a channel's egress boundary (issue #78).

    Returns ``True`` (⇒ the module opaques the outbound ``findingId``) UNLESS the channel explicitly
    declares :attr:`~modules.alerts.channels.NotificationChannel.egresses_out_of_boundary` as the
    bool ``False``. A missing marker, a non-bool marker, an accessor that raises, or a ``None``
    notifier are ALL treated as out-of-boundary — a channel must PROVE it stays in boundary to keep
    the raw id.
    """
    if notifier is None:
        return True
    try:
        marker = notifier.egresses_out_of_boundary  # type: ignore[attr-defined]
    except Exception:
        return True
    if not isinstance(marker, bool):
        return True
    return marker


def _deliver(notifier: NotificationChannel | None, payload: Mapping[str, Any]) -> DeliveryResult:
    """Deliver via the injected channel, failing closed if it is missing or errors."""
    channel = str(payload.get("channel", ""))
    if notifier is None:
        return DeliveryResult(
            channel=channel, delivered=False, detail="no notifier client injected"
        )
    try:
        return notifier.send(payload)
    except Exception as exc:  # never crash a run on a delivery error — surface undelivered
        return DeliveryResult(channel=channel, delivered=False, detail=f"send error: {exc!s}")


def _resolve_workloads(state: ReadableState | None, scope: Mapping[str, str]) -> list[str]:
    """Scope wins; otherwise every workload the read-only store knows (empty if no state)."""
    if scope.get("workload"):
        return [scope["workload"]]
    if state is None:
        return []
    return state.list_workloads()


class AlertsModule(Module):
    @property
    def manifest(self) -> ModuleManifest:
        return _MANIFEST

    def run(self, ctx: ModuleContext, *, scope: dict[str, str] | None = None) -> ModuleRunResult:
        scope = scope or {}
        state = ctx.state
        notifier = cast(NotificationChannel | None, ctx.clients.get("notifier"))
        # Fail-closed egress policy (#78): opaque the outbound findingId unless the target channel
        # PROVES it stays in boundary. Read once — the notifier is fixed for the whole run.
        out_of_boundary = channel_egresses_out_of_boundary(notifier)
        workloads = _resolve_workloads(state, scope)

        audit: list[dict[str, Any]] = []
        routed = 0
        for workload in workloads:
            findings = state.get_findings(workload) if state is not None else []
            failing = [f for f in findings if f.passed is False]
            ops = load_ops_routing(ctx.packs, workload)
            for finding in failing:
                decision = route(finding, ops)
                channel = str(decision["channel"])
                routed += 1
                if is_suppressed(channel):
                    # Ops Pack silenced this severity — record it, but never call the notifier.
                    audit.append({
                        "workload": workload,
                        "findingId": finding.id,
                        "severity": decision["severity"],
                        "channel": channel,
                        "delivered": False,
                        "suppressed": True,
                        "runbook": decision.get("runbook"),
                    })
                    continue
                result = _deliver(
                    notifier,
                    _notification_payload(finding, decision, out_of_boundary=out_of_boundary),
                )
                audit.append({
                    "workload": workload,
                    "findingId": finding.id,
                    "severity": decision["severity"],
                    "channel": channel,
                    "delivered": result.delivered,
                    "suppressed": False,
                    "runbook": decision.get("runbook"),
                })

        delivered = sum(1 for a in audit if a["delivered"])
        risks = (
            [] if notifier is not None
            else ["no notifier channel injected — routes computed, undelivered"]
        )
        response = AgentResponse(
            agentName="alerts",
            taskType="route-notifications",
            inputSummary=f"scope={scope or 'all'}; workloads={len(workloads)}; routed={routed}",
            findings=[f"{routed} notification(s) routed, {delivered} delivered"],
            risks=risks,
            confidence=1.0,
        )
        return ModuleRunResult(module=self.name, ok=True, response=response,
                               extra={"notifications": audit})
