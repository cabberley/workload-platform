"""Citrix control-plane connector — fail-closed-by-default, supplement-only health source.

Citrix is a read-only **control-plane** signal source for the Dependency & Blast Radius module. Like
the Discovery *Kuiper* connector (issue #47) this is written **defensively**: the real Citrix
endpoint, payload schema, and auth scheme are still an **external dependency owned by the product
team** (issue #48), so until a human wires an **approved https endpoint** the connector does
**nothing** — it stays unavailable and never emits a request. Even once wired it is provably
**supplemental** and **PII-safe**:

* **Fail closed by default (credential-exfil safe).** :meth:`CitrixClient.fetch_raw` validates the
  configured endpoint **before** resolving any credential. Unless the endpoint is ``https``, has a
  real (non-placeholder) host that is on an explicit operator-configured **approved-host allowlist**
  (there is **no** default host), carries **no** userinfo / query / fragment and **no** explicit
  port, it returns ``available=False`` (error = the validation exception's **class name only**) and
  **never** calls :func:`~shared.connectors.resolve_bearer_token`, never builds an ``Authorization``
  header, and never makes a network call. The empty default ``base_url`` therefore resolves to
  *unavailable* — the connector is inert until a human wires an APPROVED endpoint.
* **Supplement-only (never authoritative).** The pure mapping can ONLY *annotate* a resource the
  authoritative estate already discovered: a **health** signal is accepted only when its
  ``resourceId`` **exactly matches** an existing node id, and then a bounded, fixed-vocabulary
  supplemental tag (``aegis:source=citrix``, plus a closed-allowlist ``aegis:citrix-health``) is
  added to that node. Citrix **never** creates a node, **never** overrides/replaces/mutates an
  authoritative field (id/name/type/workload/tier/role are untouched).
* **Dependency edges are PARSED but DEFERRED (never persisted here).** A **dependency** signal maps
  to a :class:`~shared.contracts.DependencyEdge` between two nodes the estate already discovered
  (both endpoints must match existing node ids), tagged provenance ``origin="connector:citrix"``.
  :func:`dependency_edges` is a **pure** mapping returned for a future, merge-aware integration —
  it is deliberately **NOT** merged into the persisted graph (see the ``TODO(human)`` below on the
  graph-replace hazard).
* **PII-safe by construction.** No free-form Citrix string is ever copied into persisted state: each
  signal schema is a **closed** set of keys; any unexpected key, any oversized/charset-invalid id,
  or any non-allowlisted ``health`` token **rejects the whole fetch** (atomic — see below). The only
  Citrix-derived values written are fixed constants / closed-vocabulary tokens.
* **Atomic validation.** If ANY record is unknown/malformed/oversized/schema-invalid the ENTIRE
  fetch fails closed (``available=False``) — never a partially-fabricated set of signals.
* **Bounded.** TLS verify on, a finite per-request timeout, a max response-body size, a max record
  count, a max per-field length, capped retries/delays, and an overall elapsed-time deadline across
  retries (built on the shared :func:`~shared.connectors.run_with_retries`).
* **SDK-free at import.** ``httpx`` is imported **lazily inside the edge**; importing this module
  (or the dependency_graph module) never imports ``httpx`` when Citrix is absent.

TODO(human): Citrix *dependency-edge* signals are intentionally NOT integrated into the persisted
graph here. The dependency_graph module UPSERT-REPLACES a workload's ``graph`` via the state writer
(``shared.state`` ``_write_graph``), so merging Citrix edges naively would wipe the authoritative
auto/pack-derived edges. A future, merge-aware, **non-destructive** edge integration is owned by the
dependency_graph module and needs an Architect ADR (see
``docs/adr/0015-citrix-dependency-edge-merge-deferred.md``); this connector deliberately contributes
supplemental ESTATE NODE (health) annotations only, and returns dependency edges as a pure,
un-persisted mapping.

TODO(human): the real Citrix base URL, ``signals_path``, response envelope, signal schema, and auth
scheme are an EXTERNAL dependency (issue #48). The values/validators here are conservative,
synthetic placeholders; confirm and replace them (with an ADR) once the Citrix contract is
published. There is intentionally NO default ``base_url`` or approved host, so the connector is
inert until a human wires an approved endpoint.
"""
from __future__ import annotations

import ipaddress
import json
import random
import re
import time
from collections.abc import Callable, Iterable, Sequence
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable
from urllib.parse import urlsplit, urlunsplit

import idna
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from shared.connectors import (
    FailClosedObserver,
    FetchResult,
    SecretProvider,
    TokenProvider,
    fail_closed,
    resolve_bearer_token,
    run_with_retries,
)
from shared.contracts import DependencyEdge, EdgeType, ResourceNode, SourceReference

if TYPE_CHECKING:  # httpx is imported lazily inside the edge so importing this module is SDK-free.
    import httpx

__all__ = [
    "ALLOWED_HEALTH",
    "DEFAULT_TOKEN_ENV",
    "DEPENDENCY_KIND",
    "EDGE_ORIGIN",
    "HEALTH_KIND",
    "MAX_RESOURCE_ID_LEN",
    "SUPPLEMENTAL_HEALTH_TAG",
    "SUPPLEMENTAL_SOURCE",
    "SUPPLEMENTAL_SOURCE_TAG",
    "CitrixClient",
    "CitrixConfig",
    "CitrixConnector",
    "CitrixDeadlineExceeded",
    "CitrixDependencyHint",
    "CitrixEndpointError",
    "CitrixEndpointNotApproved",
    "CitrixHealthHint",
    "CitrixResponseTooLarge",
    "CitrixSignalError",
    "CitrixSignals",
    "InvalidCitrixEndpoint",
    "InvalidCitrixResponse",
    "SupplementalResult",
    "apply_supplemental",
    "dependency_edges",
    "parse_signals_atomic",
    "signals_from_result",
    "to_source_reference",
    "validate_dependency_hint",
    "validate_endpoint",
    "validate_health_hint",
]

# The environment variable that (Key Vault backed) holds a customer-supplied read token. We read
# the *name* here — never a literal secret.
DEFAULT_TOKEN_ENV = "CITRIX_READ_TOKEN"  # noqa: S105 - env var name, not a secret

# The two signal kinds this connector understands. Anything else fails the whole fetch (atomic).
# A ``host-health`` signal annotates an existing node; a ``session-dependency`` signal maps to a
# (deferred, un-persisted) dependency edge between two existing nodes.
HEALTH_KIND = "host-health"
DEPENDENCY_KIND = "session-dependency"

# Provenance markers — SUPPLEMENTAL and non-authoritative — expressed with ONLY the existing
# ``ResourceNode.tags`` field (no contract change). ``aegis:source=citrix`` marks a node as
# corroborated by Citrix; ``aegis:citrix-health`` carries a CLOSED-vocabulary health token.
SUPPLEMENTAL_SOURCE = "citrix"
SUPPLEMENTAL_SOURCE_TAG = "aegis:source"
SUPPLEMENTAL_HEALTH_TAG = "aegis:citrix-health"

# Provenance origin stamped on a (deferred) Citrix-derived dependency edge — mirrors the module's
# ``pack:<id>`` / ``auto`` origin vocabulary so a future merge can attribute + de-dupe it.
EDGE_ORIGIN = "connector:citrix"

# The CLOSED allowlist of health tokens Citrix may contribute. Anything outside this set rejects the
# whole fetch — no free-form string is ever admitted. Synthetic placeholder vocabulary;
# TODO(human): confirm the real Citrix host/session health vocabulary with the product team.
ALLOWED_HEALTH: frozenset[str] = frozenset({"healthy", "degraded", "unreachable", "maintenance"})

# A resourceId is used ONLY to match an already-discovered node id; it is never written as new data.
# It must still pass a strict charset/length gate so a PII-like value (e.g. an email) is rejected
# outright. Azure resource ids use only these characters.
_RESOURCE_ID_RE = re.compile(r"^[A-Za-z0-9/_.\-]+$")

# A HARD, module-level ceiling on a resource id's length. This is the model's OWN self-validation
# bound and is deliberately independent of any external/injected config so the invariant holds no
# matter how a hint is constructed. ``CitrixConfig.max_field_len`` may impose a *tighter* bound on
# the fetch path, but never a looser one.
MAX_RESOURCE_ID_LEN = 1024

# A legacy/alternate IPv4-literal label: a bare decimal integer, a 0x-hex form, or a leading-zero
# octal form. ``ipaddress.ip_address`` only rejects the canonical dotted-quad, so hosts whose labels
# are ALL numeric/hex (e.g. ``2130706433``, ``0x7f.0.0.1``, ``0177.0.0.1``, ``127.1``) would slip
# through as "hostnames" and may resolve to loopback — they are rejected as IP literals.
_NUMERIC_LABEL_RE = re.compile(r"(?i)^(0x[0-9a-f]+|\d+)$")


def _resource_id_ok(value: object) -> bool:
    """True iff ``value`` is a well-formed, bounded, charset-restricted resource id (no PII)."""
    return (
        isinstance(value, str)
        and 1 <= len(value) <= MAX_RESOURCE_ID_LEN
        and bool(_RESOURCE_ID_RE.match(value))
    )


def _health_ok(value: object) -> bool:
    """True iff ``value`` is a member of the CLOSED health vocabulary."""
    return isinstance(value, str) and value in ALLOWED_HEALTH


def _is_numeric_ipv4_literal(host: str) -> bool:
    """True iff every label of ``host`` is numeric/hex — i.e. a legacy/alternate IPv4 literal."""
    labels = host.split(".")
    return any(labels) and all(_NUMERIC_LABEL_RE.match(label) for label in labels if label != "")


# Hosts that are obvious non-production placeholders — rejected even if mistakenly allow-listed.
_PLACEHOLDER_HOSTS: frozenset[str] = frozenset(
    {
        "",
        "citrix.internal",
        "citrix.fake",
        "citrix.local",
        "localhost",
        "example.com",
        "example.org",
        "changeme",
        "placeholder",
        "todo",
    }
)

# HTTP auth scheme for the resolved token — kept as a bare constant so the token is interpolated at
# runtime and never embedded in source.
_AUTH_SCHEME = "Bearer"

# Slice size for bounding an already-buffered (non-streaming) response body — keeps the size check
# operating on fixed-size chunks. The live edge streams network-sized ``iter_raw()`` chunks instead.
_WIRE_CHUNK_BYTES = 65536


class CitrixSignalError(ValueError):
    """Raised when a raw Citrix signal is unknown/malformed/oversized — fail closed (atomic)."""


class CitrixResponseTooLarge(ValueError):
    """Raised when a Citrix response exceeds the configured byte ceiling — fail closed."""


class InvalidCitrixResponse(ValueError):
    """Raised when a Citrix response cannot be safely/bounded-ly read (e.g. an unbounded content
    coding we refused to decode) — fail closed."""


class CitrixDeadlineExceeded(ValueError):
    """Raised when the overall fetch deadline is exhausted before/within an attempt."""


class CitrixEndpointError(ValueError):
    """Base: the configured Citrix endpoint is not safe to send a credential to — fail closed."""


class InvalidCitrixEndpoint(CitrixEndpointError):
    """Endpoint is structurally unsafe (not https / userinfo / query / fragment / placeholder)."""


class CitrixEndpointNotApproved(CitrixEndpointError):
    """The endpoint host is not on the operator-configured approved-host allowlist — fail closed."""


class CitrixConfig(BaseModel):
    """Connector configuration. Holds no secrets — only a Key Vault-backed env var *name*.

    There is intentionally **no default host**: ``base_url`` defaults to empty and
    ``approved_hosts`` defaults to empty, so the connector is inert (unavailable) until a human
    wires an approved ``https`` endpoint AND adds its host to ``approved_hosts``.
    """

    model_config = ConfigDict(extra="forbid")

    # Empty by default ⇒ unavailable. A real value must be an https URL whose host is in
    # ``approved_hosts`` (see :func:`validate_endpoint`). TODO(human): real Citrix URL + path.
    base_url: str = Field(default="", description="Approved https Citrix base URL (none default)")
    signals_path: str = Field(
        default="/v1/control-plane/signals", description="Control-plane signals path"
    )
    # The operator-configured approved-host allowlist. NO default host — empty ⇒ nothing approved.
    approved_hosts: tuple[str, ...] = Field(
        default_factory=tuple, description="Explicit approved endpoint hosts (no default)"
    )
    timeout_s: float = Field(default=10.0, gt=0.0, le=60.0)
    token_env: str = DEFAULT_TOKEN_ENV
    token_secret_name: str | None = None
    # Bounded work: capped retries/delays + an overall elapsed-time deadline across retries, a max
    # response-body size, a max record count, and a max per-field length. Any exceeded bound fails
    # closed. Only transient transport errors are retried; else fail at once.
    retries: int = Field(default=3, ge=1, le=8, description="Max fetch attempts (bounded)")
    base_delay_s: float = Field(default=0.2, gt=0.0, le=5.0)
    max_delay_s: float = Field(default=2.0, gt=0.0, le=30.0)
    max_elapsed_s: float = Field(default=15.0, gt=0.0, le=120.0, description="Total retry deadline")
    max_response_bytes: int = Field(default=1_048_576, ge=1, le=10_485_760)
    max_records: int = Field(default=1000, ge=1, le=10_000)
    max_field_len: int = Field(default=512, ge=1, le=4096)


class CitrixHealthHint(BaseModel):
    """A validated, bounded supplemental **health** signal — a resource id + a closed health token.

    ``resource_id`` is only ever matched against an existing node id (never written as new data);
    ``health`` is a CLOSED-allowlist token. No free-form field exists on purpose.

    The charset/length/vocabulary invariants are enforced by pydantic **field validators** DIRECTLY
    on this model, so they hold no matter HOW a ``CitrixHealthHint`` is constructed — including
    :func:`signals_from_result` rehydrating an *injected* connector's untrusted ``FetchResult.raw``.
    ``extra="forbid"`` rejects any smuggled extra key.
    """

    model_config = ConfigDict(extra="forbid")

    resource_id: str
    health: str

    @field_validator("resource_id")
    @classmethod
    def _validate_resource_id(cls, value: str) -> str:
        if not _resource_id_ok(value):
            raise ValueError("resource_id out of bounds or contains disallowed characters")
        return value

    @field_validator("health")
    @classmethod
    def _validate_health(cls, value: str) -> str:
        if not _health_ok(value):
            raise ValueError("health not in the closed allowlist")
        return value


class CitrixDependencyHint(BaseModel):
    """A validated, bounded supplemental **dependency** signal — a source + target resource id.

    Both endpoints are only ever matched against existing node ids; nothing is written as new data.
    A dependency hint maps to a (deferred, un-persisted) :class:`~shared.contracts.DependencyEdge`.
    Both fields pass the same strict charset/length gate as a health hint's ``resource_id`` — no
    free-form field exists, so no PII can ride along. ``extra="forbid"`` rejects any smuggled key.
    """

    model_config = ConfigDict(extra="forbid")

    resource_id: str
    depends_on: str

    @field_validator("resource_id", "depends_on")
    @classmethod
    def _validate_ids(cls, value: str) -> str:
        if not _resource_id_ok(value):
            raise ValueError("id out of bounds or contains disallowed characters")
        return value


class CitrixSignals(BaseModel):
    """The atomic result of parsing a Citrix fetch: bounded health + dependency signals.

    Both lists are validated together; if ANY record in the batch is invalid the whole parse raises
    (fail closed) — never a partially-accepted set.
    """

    model_config = ConfigDict(extra="forbid")

    health: list[CitrixHealthHint] = Field(default_factory=list)
    dependencies: list[CitrixDependencyHint] = Field(default_factory=list)


class SupplementalResult(BaseModel):
    """Result of applying Citrix health signals onto the authoritative estate.

    ``nodes`` is the SAME estate as the input (same ids, same order, authoritative fields untouched)
    with the supplemental tag(s) added to matched nodes only. ``annotated_ids`` lists the ids that
    received a tag. Citrix never adds or removes a node.
    """

    model_config = ConfigDict(extra="forbid")

    nodes: list[ResourceNode] = Field(default_factory=list)
    annotated_ids: list[str] = Field(default_factory=list)


@runtime_checkable
class CitrixConnector(Protocol):
    """Narrow read-only seam the dependency_graph module casts its injected Citrix client to.

    The concrete :class:`CitrixClient` is injected at the process boundary via
    ``ctx.clients["citrix"]``; unit tests inject a fake returning a synthetic
    :class:`~shared.connectors.FetchResult`. Keeping the surface this small lets the module treat
    "no connector" and "a connector that failed closed" identically, and keeps the module SDK-free.
    """

    def fetch_raw(self) -> FetchResult:
        """Return validated supplemental signals, or a fail-closed ``available=False`` result."""
        ...


# --------------------------------------------------------------------------------------
# Pure validation + mapping — no I/O, fully unit-testable with synthetic payloads.
# --------------------------------------------------------------------------------------
def validate_health_hint(raw: Any, *, max_field_len: int) -> CitrixHealthHint:
    """Strictly validate ONE raw ``host-health`` record → hint, or raise :class:`CitrixSignalError`.

    Fail closed on: a non-mapping; a wrong/absent ``kind``; a missing/non-string/oversized/
    charset-invalid ``resourceId``; a ``health`` outside :data:`ALLOWED_HEALTH`; or ANY unexpected
    key (so a payload smuggling a free-text field is rejected outright — PII never even enters the
    mapping).
    """
    if not isinstance(raw, dict):
        raise CitrixSignalError("health record is not a mapping")
    unexpected = set(raw) - {"kind", "resourceId", "health"}
    if unexpected:
        raise CitrixSignalError(f"unexpected health field(s): {sorted(unexpected)}")
    if raw.get("kind") != HEALTH_KIND:
        raise CitrixSignalError(f"unknown health kind: {raw.get('kind')!r}")
    resource_id = raw.get("resourceId")
    if not isinstance(resource_id, str):
        raise CitrixSignalError("resourceId must be a string")
    if not (1 <= len(resource_id) <= max_field_len):
        raise CitrixSignalError("resourceId length out of bounds")
    if not _RESOURCE_ID_RE.match(resource_id):
        raise CitrixSignalError("resourceId contains disallowed characters")
    health = raw.get("health")
    if not isinstance(health, str) or health not in ALLOWED_HEALTH:
        raise CitrixSignalError("health not in the closed allowlist")
    return CitrixHealthHint(resource_id=resource_id, health=health)


def validate_dependency_hint(raw: Any, *, max_field_len: int) -> CitrixDependencyHint:
    """Strictly validate ONE raw ``session-dependency`` record → hint, or raise on any violation.

    Both ``resourceId`` and ``dependsOn`` must be present, string, bounded, and charset-restricted;
    any unexpected key rejects the record (PII-safe). Fail closed via :class:`CitrixSignalError`.
    """
    if not isinstance(raw, dict):
        raise CitrixSignalError("dependency record is not a mapping")
    unexpected = set(raw) - {"kind", "resourceId", "dependsOn"}
    if unexpected:
        raise CitrixSignalError(f"unexpected dependency field(s): {sorted(unexpected)}")
    if raw.get("kind") != DEPENDENCY_KIND:
        raise CitrixSignalError(f"unknown dependency kind: {raw.get('kind')!r}")
    source = _require_bounded_id(raw.get("resourceId"), max_field_len=max_field_len)
    target = _require_bounded_id(raw.get("dependsOn"), max_field_len=max_field_len)
    return CitrixDependencyHint(resource_id=source, depends_on=target)


def _require_bounded_id(value: Any, *, max_field_len: int) -> str:
    """Return ``value`` iff it is a bounded, charset-restricted string, else fail closed."""
    if not isinstance(value, str):
        raise CitrixSignalError("dependency id must be a string")
    if not (1 <= len(value) <= max_field_len):
        raise CitrixSignalError("dependency id length out of bounds")
    if not _RESOURCE_ID_RE.match(value):
        raise CitrixSignalError("dependency id contains disallowed characters")
    return value


def parse_signals_atomic(
    records: Sequence[Any], *, max_records: int, max_field_len: int
) -> CitrixSignals:
    """Validate ALL records atomically → :class:`CitrixSignals`, dispatching on ``kind``.

    If the batch is oversized, or ANY single record is unknown/malformed/schema-invalid, the whole
    call raises (fail closed) — never a partially-accepted, partially-fabricated set. A record's
    ``kind`` selects the health or dependency validator; an unrecognized ``kind`` fails closed.
    """
    if len(records) > max_records:
        raise CitrixSignalError(f"too many signal records: {len(records)} > {max_records}")
    health: list[CitrixHealthHint] = []
    dependencies: list[CitrixDependencyHint] = []
    for record in records:
        if not isinstance(record, dict):
            raise CitrixSignalError("signal record is not a mapping")
        kind = record.get("kind")
        if kind == HEALTH_KIND:
            health.append(validate_health_hint(record, max_field_len=max_field_len))
        elif kind == DEPENDENCY_KIND:
            dependencies.append(validate_dependency_hint(record, max_field_len=max_field_len))
        else:
            raise CitrixSignalError(f"unknown signal kind: {kind!r}")
    return CitrixSignals(health=health, dependencies=dependencies)


def signals_from_result(result: FetchResult) -> CitrixSignals:
    """Rehydrate validated :class:`CitrixSignals` from a fetch result — pure, UNTRUSTED input.

    Unavailable ⇒ empty signals (fail closed). The ``result`` may come from ANY connector wired into
    ``ctx.clients`` — including an injected test double or a misconfigured/alternate connector — so
    its ``raw`` is treated as **untrusted**: every record is re-validated by constructing the
    corresponding hint model through its field validators (charset/length/closed-vocabulary +
    ``extra="forbid"``). The internal normalized record carries a ``kind`` discriminator. If ANY
    record is invalid the whole batch is rejected (atomic, fail closed), so a smuggled PII value can
    never reach persisted state. A tighter, config-driven bound is additionally enforced on the
    fetch path.
    """
    if not result.available:
        return CitrixSignals()
    health: list[CitrixHealthHint] = []
    dependencies: list[CitrixDependencyHint] = []
    try:
        for record in result.raw:
            kind = record.get("kind")
            payload = {k: v for k, v in record.items() if k != "kind"}
            if kind == HEALTH_KIND:
                health.append(CitrixHealthHint.model_validate(payload))
            elif kind == DEPENDENCY_KIND:
                dependencies.append(CitrixDependencyHint.model_validate(payload))
            else:
                raise CitrixSignalError(f"unknown signal kind: {kind!r}")
    except ValidationError as exc:
        raise CitrixSignalError("untrusted Citrix record failed re-validation") from exc
    return CitrixSignals(health=health, dependencies=dependencies)


def apply_supplemental(
    authoritative: Iterable[ResourceNode], health: Iterable[CitrixHealthHint]
) -> SupplementalResult:
    """Apply Citrix ``health`` signals onto the **authoritative** estate — pure, estate always wins.

    A signal is applied ONLY when its ``resource_id`` exactly matches an existing node id; the
    matched node is COPIED with ``citrix`` added to the ``aegis:source`` provenance set plus a
    closed ``aegis:citrix-health`` token. Provenance is ADDITIVE — a pre-existing ``aegis:source``
    (e.g. from Kuiper) is preserved and Citrix is unioned into it, never overwritten. Authoritative
    fields (id/name/type/workload/tier/role) are never changed, no node is ever created from a
    signal, and a signal that matches nothing is dropped.

    This is the persistence-adjacent boundary (the last step before a tag is written), so every
    signal is RE-VALIDATED here with the SAME rules the field validators use — independent of how
    the :class:`CitrixHealthHint` was constructed. ``model_construct``/``model_copy(update=...)``
    bypass pydantic validators, so a hint whose ``resource_id`` fails the charset/length gate or
    whose ``health`` is outside the closed vocabulary is DROPPED here (fail closed), guaranteeing no
    free-form/PII value can reach a node tag.
    """
    authoritative_nodes = list(authoritative)
    known_ids = {node.id for node in authoritative_nodes}
    # Collapse signals to at-most-one health per matched id (last valid wins; deterministic).
    health_by_id: dict[str, str] = {}
    for hint in health:
        # Re-assert the invariant at the write boundary — drop any bypass-constructed hint.
        if not _resource_id_ok(hint.resource_id) or not _health_ok(hint.health):
            continue
        if hint.resource_id in known_ids:
            health_by_id[hint.resource_id] = hint.health
    out: list[ResourceNode] = []
    annotated_ids: list[str] = []
    for node in authoritative_nodes:
        if node.id not in health_by_id:
            out.append(node)
            continue
        new_tags = dict(node.tags)
        # Additive, non-destructive provenance: preserve any pre-existing ``aegis:source`` (e.g. a
        # Kuiper annotation) and represent MULTIPLE contributing connectors as a sorted, comma-
        # joined set rather than clobbering it. Citrix must never erase another connector's source;
        # a lone ``kuiper`` stays a valid 1-element value and Kuiper's own tags are untouched.
        existing_source = new_tags.get(SUPPLEMENTAL_SOURCE_TAG, "")
        sources = {s for s in existing_source.split(",") if s} | {SUPPLEMENTAL_SOURCE}
        new_tags[SUPPLEMENTAL_SOURCE_TAG] = ",".join(sorted(sources))
        new_tags[SUPPLEMENTAL_HEALTH_TAG] = health_by_id[node.id]
        out.append(node.model_copy(update={"tags": new_tags}))
        annotated_ids.append(node.id)
    return SupplementalResult(nodes=out, annotated_ids=annotated_ids)


def dependency_edges(
    dependencies: Iterable[CitrixDependencyHint], known_ids: Iterable[str]
) -> list[DependencyEdge]:
    """Map Citrix ``dependency`` signals to typed edges — pure, DEFERRED (never persisted here).

    An edge is produced ONLY when BOTH endpoints exactly match an existing node id (a phantom
    endpoint never becomes an edge) and the endpoints differ (no self-edge). Each edge is
    ``origin="connector:citrix"`` so a future merge can attribute + de-dupe it. Every hint is
    RE-VALIDATED at this boundary so a bypass-constructed (``model_construct``) hint with a
    charset-invalid/oversized id is dropped.

    TODO(human): this mapping is returned for a future **merge-aware, non-destructive** integration
    owned by the dependency_graph module; it is deliberately NOT merged into the persisted graph
    (the graph is UPSERT-REPLACED — a naive merge would wipe authoritative edges). See the module
    docstring and ``docs/adr/0015-citrix-dependency-edge-merge-deferred.md``.
    """
    known = set(known_ids)
    out: list[DependencyEdge] = []
    seen: set[tuple[str, str]] = set()
    for hint in dependencies:
        if not _resource_id_ok(hint.resource_id) or not _resource_id_ok(hint.depends_on):
            continue
        source, target = hint.resource_id, hint.depends_on
        if source == target or source not in known or target not in known:
            continue
        key = (source, target)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            DependencyEdge(
                source=source, target=target, type=EdgeType.depends_on,
                redundant=False, origin=EDGE_ORIGIN,
            )
        )
    return out


def to_source_reference(resource_id: str) -> SourceReference:
    """Provenance for a Citrix supplemental annotation — cites the connector + resource id."""
    return SourceReference(kind="connector", id=SUPPLEMENTAL_SOURCE, detail=resource_id)


def _canonicalize_host(host: str) -> str:
    """Canonicalize a hostname EXACTLY as HTTPX will encode it — fail closed on any IDNA error.

    Mirrors ``httpx._urlparse.encode_host``: an ASCII host is lower-cased and used as-is (already
    the punycode/``xn--`` form for an internationalized name); a non-ASCII host is encoded with the
    SAME ``idna`` library HTTPX uses (``idna.encode``, IDNA2008 — NOT the legacy stdlib ``idna``
    codec, which would map e.g. ``ß`` → ``ss`` and validate a DIFFERENT host than HTTPX requests).
    A single trailing FQDN dot is stripped. Any IDNA failure raises :class:`InvalidCitrixEndpoint`
    (fail closed) — never a lossy fallback. The returned value is the byte-for-byte host HTTPX will
    put on the wire, so the allowlist check and the actual request target can never diverge.
    """
    normalized = host.strip().rstrip(".").lower()
    if not normalized:
        raise InvalidCitrixEndpoint("endpoint host is empty")
    if normalized.isascii():
        return normalized
    try:
        return idna.encode(normalized).decode("ascii")
    except idna.IDNAError as exc:
        raise InvalidCitrixEndpoint("endpoint host is not IDNA-encodable") from exc


def validate_endpoint(base_url: str, signals_path: str, approved_hosts: Sequence[str]) -> str:
    """Validate the endpoint BEFORE any credential is resolved — or raise (credential-exfil safe).

    Returns the full endpoint URL only when ALL hold: scheme is ``https``; there is no userinfo,
    query, or fragment; **no explicit port**; the host is non-empty, not an IP literal (canonical
    dotted-quad/IPv6 OR a legacy numeric/hex/octal/short form), not a known placeholder (after
    canonicalization), and — compared on its canonical (lower-cased, trailing-dot-stripped,
    HTTPX-identical IDNA-encoded) form — present in ``approved_hosts`` (there is no default host);
    and ``signals_path`` is a simple, safe path. Any failure raises :class:`InvalidCitrixEndpoint` /
    :class:`CitrixEndpointNotApproved` so the caller fails closed and NEVER resolves a credential or
    sends a request.

    The returned URL is rebuilt from the VALIDATED scheme + canonical host + validated path — the
    raw ``base_url`` host is never handed to HTTPX downstream, so the allowlist-checked host is
    byte-for-byte the host that is requested. Canonicalization closes trailing-dot, explicit-port,
    IDN-equivalent/confusable, and loopback/IP-literal (incl. legacy numeric) bypasses; ``http://``
    is rejected so it can never be used even with ``verify=True``.
    """
    parts = urlsplit(base_url)
    if parts.scheme != "https":
        raise InvalidCitrixEndpoint("endpoint scheme must be https")
    if parts.username or parts.password:
        raise InvalidCitrixEndpoint("endpoint must not contain userinfo")
    if parts.query or parts.fragment:
        raise InvalidCitrixEndpoint("endpoint must not contain a query or fragment")
    # An explicit port is part of the endpoint identity but is not covered by a host-only allowlist,
    # so reject it outright rather than let ``host:port`` slip through on host alone.
    if parts.port is not None:
        raise InvalidCitrixEndpoint("endpoint must not specify an explicit port")
    raw_host = parts.hostname
    if not raw_host:
        raise InvalidCitrixEndpoint("endpoint host is empty")
    normalized_host = raw_host.strip().rstrip(".").lower()
    # Reject IP literals — the canonical dotted-quad/IPv6 forms AND legacy numeric/hex/octal/short
    # forms that ``ipaddress`` would treat as a hostname. Citrix must be a named host.
    try:
        ipaddress.ip_address(normalized_host)
    except ValueError:
        if _is_numeric_ipv4_literal(normalized_host):
            raise InvalidCitrixEndpoint("endpoint host must not be a numeric IP literal") from None
    else:
        raise InvalidCitrixEndpoint("endpoint host must not be an IP literal")
    host = _canonicalize_host(raw_host)
    if host in _PLACEHOLDER_HOSTS:
        raise InvalidCitrixEndpoint("endpoint host is a placeholder")
    approved = {_canonicalize_host(h) for h in approved_hosts}
    if host not in approved:
        raise CitrixEndpointNotApproved("endpoint host is not on the approved-host allowlist")
    if not signals_path.startswith("/") or any(c in signals_path for c in "?#@ "):
        raise InvalidCitrixEndpoint("signals_path is not a simple path")
    # Rebuild from the VALIDATED components only — canonical host + validated scheme/path — so HTTPX
    # is never handed the raw host and requests exactly the host we allowlist-checked.
    base_path = parts.path.rstrip("/")
    full_path = f"{base_path}/{signals_path.lstrip('/')}"
    return urlunsplit((parts.scheme, host, full_path, "", ""))


def _coerce_signal_list(payload: Any) -> list[dict[str, Any]]:
    """Strictly extract a list of signal dicts from the response payload.

    Accepts a bare list, or a ``{signals|value|data: [...]}`` envelope with **exactly one**
    recognized key present. Ambiguous, unrecognized, a non-list value, or any non-dict entry all
    **raise** — so a broken feed surfaces as ``available=False`` rather than masquerading as
    healthy-but-empty.

    TODO(human): confirm the real Citrix response envelope and tighten this once the contract is
    published; the recognized keys are a synthetic placeholder.
    """
    if isinstance(payload, list):
        items: list[Any] = payload
    elif isinstance(payload, dict):
        present = [k for k in ("signals", "value", "data") if k in payload]
        if len(present) != 1:
            raise CitrixSignalError("ambiguous or unrecognized Citrix payload shape")
        candidate = payload[present[0]]
        if not isinstance(candidate, list):
            raise CitrixSignalError("Citrix envelope value is not a list")
        items = candidate
    else:
        raise CitrixSignalError("unrecognized Citrix payload shape")
    if not all(isinstance(item, dict) for item in items):
        raise CitrixSignalError("Citrix payload contains non-dict entries")
    return [item for item in items if isinstance(item, dict)]


def _signals_to_raw(signals: CitrixSignals) -> list[dict[str, Any]]:
    """Normalize validated signals to internal wire records carrying a ``kind`` discriminator.

    These records populate ``FetchResult.raw``; :func:`signals_from_result` re-validates them
    (untrusted) by dispatching on ``kind``. Only closed-vocabulary / charset-bounded values appear.
    """
    raw: list[dict[str, Any]] = []
    for hint in signals.health:
        raw.append({"kind": HEALTH_KIND, "resource_id": hint.resource_id, "health": hint.health})
    for dep in signals.dependencies:
        raw.append(
            {"kind": DEPENDENCY_KIND, "resource_id": dep.resource_id, "depends_on": dep.depends_on}
        )
    return raw


# --------------------------------------------------------------------------------------
# Network edge — the ONLY place that performs I/O. httpx is imported lazily here.
# --------------------------------------------------------------------------------------
class CitrixClient:
    """Thin, read-only Citrix client. Fail-closed by default; validates the endpoint FIRST.

    On :meth:`fetch_raw` the endpoint is validated **before** any credential is resolved — an
    unapproved/placeholder/non-https endpoint fails closed with **no** credential resolution and
    **no** network call. Only then is a keyless token resolved (injected provider → Key Vault by
    identity → local-dev env fallback); absent ⇒ ``error="NoCredential"``, still no request. Inject
    ``client`` (an ``httpx.Client`` on ``httpx.MockTransport``), ``credential_provider``, and/or
    ``secret_provider`` to keep everything testable without touching the network or a vault.
    """

    def __init__(
        self,
        config: CitrixConfig,
        *,
        client: httpx.Client | None = None,
        credential_provider: TokenProvider | None = None,
        secret_provider: SecretProvider | None = None,
        fail_closed_observer: FailClosedObserver | None = None,
        sleep: Callable[[float], None] = time.sleep,
        rng: random.Random | None = None,
    ) -> None:
        self._config = config
        self._client = client
        self._credential_provider = credential_provider
        self._secret_provider = secret_provider
        self._fail_closed_observer = fail_closed_observer
        self._sleep = sleep
        self._rng = rng if rng is not None else random.Random()  # noqa: S311 - backoff jitter

    def fetch_raw(self) -> FetchResult:
        """The single network edge. Read-only GET; returns validated signals or fails closed.

        Fails closed (``available=False``, error *class* name only — no body, no token) on: an
        unapproved/invalid endpoint (BEFORE resolving any credential), an unresolvable credential,
        any transport/decoding error, an oversized (streamed) response, a malformed payload
        (atomic), or the overall time deadline being exhausted. Transient transport errors are
        retried only while the deadline has time left; everything else fails closed at once. When
        the endpoint is invalid or no credential resolves, **no** request runs.
        """
        return fail_closed(self._fetch, observer=self._fail_closed_observer)

    def _fetch(self) -> FetchResult:
        """Validate endpoint, resolve credential, then bounded/atomic read. May raise; guarded.

        The endpoint is validated FIRST so a credential is never resolved for — nor a request ever
        sent to — an unapproved endpoint. The token is only ever used to build the auth header.
        """
        # Validate BEFORE touching any credential. Raises ⇒ fail closed, no credential read.
        endpoint = validate_endpoint(
            self._config.base_url, self._config.signals_path, self._config.approved_hosts
        )
        token = resolve_bearer_token(
            self._credential_provider,
            self._config.token_env,
            secret_provider=self._secret_provider,
            secret_name=self._config.token_secret_name,
        )
        if not token:
            return FetchResult(available=False, error="NoCredential")

        import httpx  # lazy: keeps importing this module (and dependency_graph) SDK-free.

        # TLS verification on — never an insecure request. Per-request timeouts are set per attempt
        # (bounded by the remaining deadline), so no client-wide timeout is configured here.
        active_client = self._client or httpx.Client(verify=True)
        owns_client = self._client is None
        deadline = time.monotonic() + self._config.max_elapsed_s

        def _remaining() -> float:
            return deadline - time.monotonic()

        def _bounded_sleep(seconds: float) -> None:
            # Never sleep past the overall deadline.
            self._sleep(max(0.0, min(seconds, _remaining())))

        def _retry_on(exc: BaseException) -> bool:
            # Retry only transient transport failures, and only while the deadline has time left.
            transient = isinstance(exc, httpx.TransportError)
            return transient and _remaining() > 0.0

        try:
            def _attempt() -> list[dict[str, Any]]:
                # Bound EVERY attempt by the remaining deadline — check before the request and cap
                # the per-request timeout to what is left.
                remaining = _remaining()
                if remaining <= 0.0:
                    raise CitrixDeadlineExceeded("citrix fetch deadline exhausted")
                per_attempt_timeout = min(self._config.timeout_s, remaining)
                # Stream RAW wire bytes and ask the server not to compress, so the byte ceiling is
                # measured on the on-the-wire body — never on the far-larger decoded side of a
                # decompression bomb.
                with active_client.stream(
                    "GET",
                    endpoint,
                    headers={
                        "Authorization": f"{_AUTH_SCHEME} {token}",
                        "Accept-Encoding": "identity",
                    },
                    timeout=per_attempt_timeout,
                ) as response:
                    response.raise_for_status()
                    payload = _read_bounded_json(
                        response, self._config.max_response_bytes, deadline
                    )
                records = _coerce_signal_list(payload)
                # Atomic validation + bounds. Any bad record ⇒ the whole fetch fails.
                signals = parse_signals_atomic(
                    records,
                    max_records=self._config.max_records,
                    max_field_len=self._config.max_field_len,
                )
                return _signals_to_raw(signals)

            raw = run_with_retries(
                _attempt,
                attempts=self._config.retries,
                base_delay_s=self._config.base_delay_s,
                max_delay_s=self._config.max_delay_s,
                sleep=_bounded_sleep,
                rng=self._rng,
                retry_on=_retry_on,
            )
            # A successful attempt that overran the deadline is still rejected (fail closed): a
            # single slow attempt must never smuggle late data past the overall time ceiling.
            if _remaining() <= 0.0:
                raise CitrixDeadlineExceeded("citrix fetch overran the deadline")
            return FetchResult(available=True, raw=raw)
        finally:
            if owns_client:
                active_client.close()


def _read_bounded_json(response: httpx.Response, max_bytes: int, deadline: float) -> Any:
    """Stream + size- AND time-bound a response body on the WIRE, then JSON-decode it — fail closed.

    Defends against a decompression bomb from a compromised/malfunctioning APPROVED endpoint: the
    byte ceiling MUST be measured on the on-the-wire body, never on the far-larger decoded side of a
    content coding. So this:

    * rejects an over-limit declared ``Content-Length`` BEFORE reading;
    * refuses any non-``identity`` ``Content-Encoding`` (we requested ``Accept-Encoding: identity``;
      a server that compresses anyway is refused, not decoded) — :class:`InvalidCitrixResponse`;
    * streams RAW wire bytes via ``iter_raw()`` (NO implicit decompression) and rejects the moment
      the ceiling WOULD be exceeded — ``len(buffer) + len(chunk) > max_bytes`` is checked BEFORE the
      chunk is appended, so an over-limit buffer is never materialized;
    * checks the remaining overall deadline on EVERY chunk so a slow-drip body is aborted mid-stream
      rather than drained.

    Because a non-identity coding is refused, the buffered raw bytes are the literal body and are
    JSON-decoded as-is. Byte-ceiling breach ⇒ :class:`CitrixResponseTooLarge`; deadline breach ⇒
    :class:`CitrixDeadlineExceeded`; unbounded/refused coding ⇒ :class:`InvalidCitrixResponse`.
    """
    declared = response.headers.get("content-length")
    if declared is not None:
        try:
            declared_n = int(declared)
        except ValueError as exc:
            raise CitrixResponseTooLarge("invalid Content-Length header") from exc
        if declared_n > max_bytes:
            raise CitrixResponseTooLarge("declared response exceeds byte ceiling")
    # Refuse a body we cannot bound on the wire: any content coding other than identity is rejected
    # rather than decoded (a decompression bomb would blow the ceiling on the decoded side).
    encoding = response.headers.get("content-encoding", "").strip().lower()
    if encoding and encoding != "identity":
        raise InvalidCitrixResponse("response carries a non-identity content-encoding")
    buffer = bytearray()
    for chunk in _iter_wire_bytes(response):
        # Bound total streaming time — abort the moment the overall deadline is exhausted.
        if time.monotonic() >= deadline:
            raise CitrixDeadlineExceeded("citrix fetch deadline exhausted while streaming")
        # Reject BEFORE appending so an over-limit buffer is never materialized (decompression-bomb
        # / oversized-body safe — the check is on raw wire bytes, the correct side of any coding).
        if len(buffer) + len(chunk) > max_bytes:
            raise CitrixResponseTooLarge("streamed response exceeds byte ceiling")
        buffer.extend(chunk)
    return json.loads(bytes(buffer))


def _iter_wire_bytes(response: httpx.Response) -> Iterable[bytes]:
    """Yield RAW, undecoded wire chunks — the correct (compressed) side of any content coding.

    The live streaming edge (``client.stream(...)``) exposes an un-consumed stream, so
    ``iter_raw()`` yields network-sized chunks with NO implicit decompression — the size ceiling is
    enforced on the wire (decompression-bomb safe). If the response body was already buffered
    (``is_stream_consumed`` — e.g. a non-streaming transport), fall back to slicing that in-memory
    body into fixed-size chunks so the same bounded check applies; a non-identity coding was already
    refused above, so the buffered bytes are the literal body.
    """
    if response.is_stream_consumed:
        body = response.content
        for start in range(0, len(body), _WIRE_CHUNK_BYTES):
            yield body[start : start + _WIRE_CHUNK_BYTES]
        return
    yield from response.iter_raw()
