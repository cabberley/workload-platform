"""Kuiper connector — fail-closed-by-default, supplement-only Discovery **assist** client.

Epic *Kuiper* is a read-only discovery-assist source. This connector is written **defensively**:
its real endpoint, payload schema, and auth scheme are still an **external dependency** owned by the
product team (issue #47), so until a human wires an **approved https endpoint** the connector does
**nothing** — it stays unavailable and never emits a request. Even once wired it is provably
**supplemental** and **PII-safe**:

* **Fail closed by default (credential-exfil safe).** :meth:`KuiperClient.fetch_raw` validates the
  configured endpoint **before** resolving any credential. Unless the endpoint is ``https``, has a
  real (non-placeholder) host that is on an explicit operator-configured **approved-host allowlist**
  (there is **no** default host), and carries no userinfo / query / fragment, it returns
  ``available=False`` (error = the validation exception's **class name only**) and **never** calls
  :func:`~shared.connectors.resolve_bearer_token`, never builds an ``Authorization`` header, and
  never makes a network call. The placeholder ``base_url`` therefore resolves to *unavailable*.
* **Supplement-only (never authoritative).** The pure mapping can ONLY *annotate* a resource that
  ARG already discovered: a hint is accepted only when its ``resourceId`` **exactly matches** an
  existing ARG node id, and then a bounded, fixed-vocabulary supplemental tag
  (``aegis:source=kuiper``, plus an optional closed-allowlist ``aegis:kuiper-signal``) is added to
  that node. Kuiper **never** creates a node, **never** overrides/replaces/mutates an ARG field
  (id/name/type/workload/tier/role are untouched), and **never** emits a dependency edge or graph.
  See ``TODO(human)`` below on the deferred, non-destructive edge integration.
* **PII-safe by construction.** No free-form Kuiper string is ever copied into persisted state: the
  hint schema is a **closed** set of keys (``kind``/``resourceId``/``signal``); any unexpected key,
  any oversized/charset-invalid ``resourceId``, or any non-allowlisted ``signal`` **rejects the
  whole fetch** (atomic — see below). The only Kuiper-derived values written are fixed constants /
  closed-vocabulary tokens.
* **Atomic validation.** If ANY record is unknown/malformed/oversized/schema-invalid the ENTIRE
  fetch fails closed (``available=False``) — never a partially-fabricated topology.
* **Bounded.** TLS verify on, a finite per-request timeout, a max response-body size, a max record
  count, a max per-field length, capped retries/delays, and an overall elapsed-time deadline across
  retries (built on the shared :func:`~shared.connectors.run_with_retries`).
* **SDK-free at import.** ``httpx`` is imported **lazily inside the edge**; importing this module
  (or the Discovery module) never imports ``httpx`` when Kuiper is absent.

TODO(human): Kuiper *dependency-edge* hints are intentionally NOT integrated here. Discovery's
``graph`` is UPSERT-REPLACED by the state writer (``shared.state`` ~L506), so emitting a graph
from Discovery would wipe the authoritative dependency_graph edges. A future, merge-aware,
non-destructive edge integration is owned by the dependency_graph module and needs an Architect
ADR; this connector deliberately contributes supplemental ESTATE NODE annotations only.

TODO(human): the real Kuiper base URL, ``hints_path``, response envelope, hint schema, and auth
scheme are an EXTERNAL dependency (issue #47). The values/validators here are conservative,
synthetic placeholders; confirm and replace them (with an ADR) once the Kuiper contract is
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
from shared.contracts import ResourceNode, SourceReference

if TYPE_CHECKING:  # httpx is imported lazily inside the edge so importing this module is SDK-free.
    import httpx

__all__ = [
    "ALLOWED_SIGNALS",
    "DEFAULT_TOKEN_ENV",
    "HINT_KIND",
    "MAX_RESOURCE_ID_LEN",
    "SUPPLEMENTAL_SIGNAL_TAG",
    "SUPPLEMENTAL_SOURCE",
    "SUPPLEMENTAL_SOURCE_TAG",
    "InvalidKuiperEndpoint",
    "InvalidKuiperResponse",
    "KuiperClient",
    "KuiperConfig",
    "KuiperConnector",
    "KuiperDeadlineExceeded",
    "KuiperEndpointError",
    "KuiperEndpointNotApproved",
    "KuiperHint",
    "KuiperHintError",
    "KuiperResponseTooLarge",
    "SupplementalResult",
    "apply_supplemental",
    "hints_from_result",
    "parse_hints_atomic",
    "to_source_reference",
    "validate_endpoint",
    "validate_hint",
]

# The environment variable that (Key Vault backed) holds a customer-supplied read token. We read
# the *name* here — never a literal secret.
DEFAULT_TOKEN_ENV = "KUIPER_READ_TOKEN"  # noqa: S105 - env var name, not a secret

# The single hint kind this connector understands. Anything else fails the whole fetch (atomic).
HINT_KIND = "entity-signal"

# Provenance markers — SUPPLEMENTAL and non-authoritative — expressed with ONLY the existing
# ``ResourceNode.tags`` field (no contract change). ``aegis:source=kuiper`` marks a node as
# corroborated by Kuiper; ``aegis:kuiper-signal`` optionally carries a CLOSED-vocabulary token.
SUPPLEMENTAL_SOURCE = "kuiper"
SUPPLEMENTAL_SOURCE_TAG = "aegis:source"
SUPPLEMENTAL_SIGNAL_TAG = "aegis:kuiper-signal"

# The CLOSED allowlist of supplemental-signal tokens Kuiper may contribute. Anything outside this
# set rejects the whole fetch — no free-form string is ever admitted. Synthetic placeholder
# vocabulary; TODO(human): confirm the real signal vocabulary with the Kuiper team.
ALLOWED_SIGNALS: frozenset[str] = frozenset({"corroborated", "candidate", "stale"})

# A resourceId is used ONLY to match an already-ARG-discovered node id; it is never written as new
# data. It must still pass a strict charset/length gate so a PII-like value (e.g. an email) is
# rejected outright. Azure resource ids use only these characters.
_RESOURCE_ID_RE = re.compile(r"^[A-Za-z0-9/_.\-]+$")

# A HARD, module-level ceiling on a resource id's length. This is the model's OWN self-validation
# bound (see :class:`KuiperHint`) and is deliberately independent of any external/injected config so
# the invariant holds no matter how a ``KuiperHint`` is constructed. ``KuiperConfig.max_field_len``
# may impose a *tighter* bound on the fetch path, but never a looser one.
MAX_RESOURCE_ID_LEN = 1024

# A legacy/alternate IPv4-literal label: a bare decimal integer, a 0x-hex form, or a leading-zero
# octal form. ``ipaddress.ip_address`` only rejects the canonical dotted-quad, so hosts whose labels
# are ALL numeric/hex (e.g. ``2130706433``, ``0x7f.0.0.1``, ``0177.0.0.1``, ``127.1``) would slip
# through as "hostnames" and may resolve to loopback — they are rejected as IP literals (LOW-D).
_NUMERIC_LABEL_RE = re.compile(r"(?i)^(0x[0-9a-f]+|\d+)$")


def _resource_id_ok(value: object) -> bool:
    """True iff ``value`` is a well-formed, bounded, charset-restricted resource id (no PII)."""
    return (
        isinstance(value, str)
        and 1 <= len(value) <= MAX_RESOURCE_ID_LEN
        and bool(_RESOURCE_ID_RE.match(value))
    )


def _signal_ok(value: object) -> bool:
    """True iff ``value`` is ``None`` or a member of the CLOSED signal vocabulary."""
    return value is None or (isinstance(value, str) and value in ALLOWED_SIGNALS)


def _is_numeric_ipv4_literal(host: str) -> bool:
    """True iff every label of ``host`` is numeric/hex — i.e. a legacy/alternate IPv4 literal."""
    labels = host.split(".")
    return any(labels) and all(_NUMERIC_LABEL_RE.match(label) for label in labels if label != "")

# Hosts that are obvious non-production placeholders — rejected even if mistakenly allow-listed.
_PLACEHOLDER_HOSTS: frozenset[str] = frozenset(
    {
        "",
        "kuiper.internal",
        "kuiper.fake",
        "kuiper.local",
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


class KuiperHintError(ValueError):
    """Raised when a raw Kuiper hint is unknown/malformed/oversized — fail closed (atomic)."""


class KuiperResponseTooLarge(ValueError):
    """Raised when a Kuiper response exceeds the configured byte ceiling — fail closed."""


class InvalidKuiperResponse(ValueError):
    """Raised when a Kuiper response cannot be safely/bounded-ly read (e.g. an unbounded content
    coding we refused to decode) — fail closed."""


class KuiperDeadlineExceeded(ValueError):
    """Raised when the overall fetch deadline is exhausted before/within an attempt."""


class KuiperEndpointError(ValueError):
    """Base: the configured Kuiper endpoint is not safe to send a credential to — fail closed."""


class InvalidKuiperEndpoint(KuiperEndpointError):
    """Endpoint is structurally unsafe (not https / userinfo / query / fragment / placeholder)."""


class KuiperEndpointNotApproved(KuiperEndpointError):
    """The endpoint host is not on the operator-configured approved-host allowlist — fail closed."""


class KuiperConfig(BaseModel):
    """Connector configuration. Holds no secrets — only a Key Vault-backed env var *name*.

    There is intentionally **no default host**: ``base_url`` defaults to empty and
    ``approved_hosts`` defaults to empty, so the connector is inert (unavailable) until a human
    wires an approved ``https`` endpoint AND adds its host to ``approved_hosts``.
    """

    model_config = ConfigDict(extra="forbid")

    # Empty by default ⇒ unavailable. A real value must be an https URL whose host is in
    # ``approved_hosts`` (see :func:`validate_endpoint`). TODO(human): real Kuiper URL + path.
    base_url: str = Field(default="", description="Approved https Kuiper base URL (none default)")
    hints_path: str = Field(default="/v1/discovery/hints", description="Discovery-hints path")
    # The operator-configured approved-host allowlist. NO default host — empty ⇒ nothing approved.
    approved_hosts: tuple[str, ...] = Field(
        default_factory=tuple, description="Explicit approved endpoint hosts (no default)"
    )
    timeout_s: float = Field(default=10.0, gt=0.0, le=60.0)
    token_env: str = DEFAULT_TOKEN_ENV
    token_secret_name: str | None = None
    # Bounded work (MED-2): capped retries/delays + an overall elapsed-time deadline across
    # retries, a max response-body size, a max record count, and a max per-field length. Any
    # exceeded bound fails closed. Only transient transport errors are retried; else fail at once.
    retries: int = Field(default=3, ge=1, le=8, description="Max fetch attempts (bounded)")
    base_delay_s: float = Field(default=0.2, gt=0.0, le=5.0)
    max_delay_s: float = Field(default=2.0, gt=0.0, le=30.0)
    max_elapsed_s: float = Field(default=15.0, gt=0.0, le=120.0, description="Total retry deadline")
    max_response_bytes: int = Field(default=1_048_576, ge=1, le=10_485_760)
    max_records: int = Field(default=1000, ge=1, le=10_000)
    max_field_len: int = Field(default=512, ge=1, le=4096)


class KuiperHint(BaseModel):
    """A validated, bounded supplemental hint — a resource id to corroborate + an optional signal.

    ``resource_id`` is only ever matched against an existing ARG node id (never written as new
    data); ``signal`` is a CLOSED-allowlist token or ``None``. No free-form field exists on purpose.

    The charset/length/vocabulary invariants are enforced by pydantic **field validators** DIRECTLY
    on this model, so they hold no matter HOW a ``KuiperHint`` is constructed — including
    :func:`hints_from_result` rehydrating an *injected* connector's untrusted ``FetchResult.raw``.
    An injected/misconfigured connector therefore cannot smuggle PII (e.g. into the signal tag) or a
    charset-invalid/oversized id past this model. ``extra="forbid"`` rejects any smuggled extra key.
    """

    model_config = ConfigDict(extra="forbid")

    resource_id: str
    signal: str | None = None

    @field_validator("resource_id")
    @classmethod
    def _validate_resource_id(cls, value: str) -> str:
        if not _resource_id_ok(value):
            raise ValueError("resource_id out of bounds or contains disallowed characters")
        return value

    @field_validator("signal")
    @classmethod
    def _validate_signal(cls, value: str | None) -> str | None:
        if not _signal_ok(value):
            raise ValueError("signal not in the closed allowlist")
        return value


class SupplementalResult(BaseModel):
    """Result of applying Kuiper hints onto the authoritative ARG estate.

    ``nodes`` is the SAME estate as the input (same ids, same order, ARG fields untouched) with the
    supplemental tag(s) added to matched nodes only. ``annotated_ids`` lists the ids that received a
    tag. Kuiper never adds or removes a node.
    """

    model_config = ConfigDict(extra="forbid")

    nodes: list[ResourceNode] = Field(default_factory=list)
    annotated_ids: list[str] = Field(default_factory=list)


@runtime_checkable
class KuiperConnector(Protocol):
    """Narrow read-only seam Discovery casts its injected Kuiper client to.

    The concrete :class:`KuiperClient` is injected at the process boundary via
    ``ctx.clients["kuiper"]``; unit tests inject a fake returning a synthetic
    :class:`~shared.connectors.FetchResult`. Keeping the surface this small lets Discovery treat "no
    connector" and "a connector that failed closed" identically, and keeps the module SDK-free.
    """

    def fetch_raw(self) -> FetchResult:
        """Return validated supplemental hints, or a fail-closed ``available=False`` result."""
        ...


# --------------------------------------------------------------------------------------
# Pure validation + mapping — no I/O, fully unit-testable with synthetic payloads.
# --------------------------------------------------------------------------------------
def validate_hint(raw: Any, *, max_field_len: int) -> KuiperHint:
    """Strictly validate ONE raw hint → :class:`KuiperHint`, or raise :class:`KuiperHintError`.

    Fail closed on: a non-mapping; an unexpected ``kind``; a missing/non-string/oversized/
    charset-invalid ``resourceId``; a ``signal`` outside :data:`ALLOWED_SIGNALS`; or ANY unexpected
    key (so a payload smuggling a free-text ``name``/``description``/``email`` field is rejected
    outright — PII never even enters the mapping).
    """
    if not isinstance(raw, dict):
        raise KuiperHintError("hint record is not a mapping")
    unexpected = set(raw) - {"kind", "resourceId", "signal"}
    if unexpected:
        raise KuiperHintError(f"unexpected hint field(s): {sorted(unexpected)}")
    if raw.get("kind") != HINT_KIND:
        raise KuiperHintError(f"unknown hint kind: {raw.get('kind')!r}")
    resource_id = raw.get("resourceId")
    if not isinstance(resource_id, str):
        raise KuiperHintError("resourceId must be a string")
    if not (1 <= len(resource_id) <= max_field_len):
        raise KuiperHintError("resourceId length out of bounds")
    if not _RESOURCE_ID_RE.match(resource_id):
        raise KuiperHintError("resourceId contains disallowed characters")
    signal = raw.get("signal")
    if signal is not None and (not isinstance(signal, str) or signal not in ALLOWED_SIGNALS):
        raise KuiperHintError("signal not in the closed allowlist")
    return KuiperHint(resource_id=resource_id, signal=signal)


def parse_hints_atomic(
    records: Sequence[Any], *, max_records: int, max_field_len: int
) -> list[KuiperHint]:
    """Validate ALL records atomically → list of :class:`KuiperHint`.

    If the batch is oversized, or ANY single record is unknown/malformed/schema-invalid, the whole
    call raises (fail closed) — never a partially-accepted, partially-fabricated set.
    """
    if len(records) > max_records:
        raise KuiperHintError(f"too many hint records: {len(records)} > {max_records}")
    return [validate_hint(record, max_field_len=max_field_len) for record in records]


def hints_from_result(result: FetchResult) -> list[KuiperHint]:
    """Rehydrate validated :class:`KuiperHint`\\ s from a fetch result — pure, UNTRUSTED input.

    Unavailable ⇒ ``[]`` (fail closed). The ``result`` may come from ANY connector wired into
    ``ctx.clients`` — including an injected test double or a misconfigured/alternate connector — so
    its ``raw`` is treated as **untrusted**: every record is re-validated by constructing a
    :class:`KuiperHint` through its field validators (charset/length/closed-signal-vocabulary +
    ``extra="forbid"``). If ANY record is invalid the whole batch is rejected (atomic, fail closed),
    so a smuggled PII ``signal`` or a charset-invalid/oversized ``resource_id`` can never reach
    persisted state. A tighter, config-driven bound is additionally enforced on the fetch path.
    """
    if not result.available:
        return []
    try:
        return [KuiperHint.model_validate(record) for record in result.raw]
    except ValidationError as exc:
        raise KuiperHintError("untrusted Kuiper record failed re-validation") from exc


def apply_supplemental(
    authoritative: Iterable[ResourceNode], hints: Iterable[KuiperHint]
) -> SupplementalResult:
    """Apply Kuiper ``hints`` onto the **authoritative** ARG estate — pure, ARG always wins.

    A hint is applied ONLY when its ``resource_id`` exactly matches an existing ARG node id; the
    matched node is COPIED with the ``aegis:source=kuiper`` tag added (and, if present, a closed
    ``aegis:kuiper-signal`` token). ARG's authoritative fields (id/name/type/workload/tier/role) are
    never changed, no node is ever created from a hint, and a hint that matches nothing is dropped.

    LOW-C: this is the persistence-adjacent boundary (the last step before a tag is written), so
    every hint is RE-VALIDATED here with the SAME rules the field validators use — independent of
    how the :class:`KuiperHint` was constructed. ``model_construct``/``model_copy(update=...)``
    bypass pydantic validators, so a hint whose ``resource_id`` fails the charset/length gate or
    whose ``signal`` is outside the closed vocabulary is DROPPED here (fail closed), guaranteeing no
    free-form/PII value can reach a node tag.
    """
    authoritative_nodes = list(authoritative)
    known_ids = {node.id for node in authoritative_nodes}
    # Collapse hints to at-most-one signal per matched id (last valid wins; deterministic, bounded).
    signals: dict[str, str | None] = {}
    for hint in hints:
        # Re-assert the invariant at the write boundary (LOW-C) — drop any bypass-constructed hint.
        if not _resource_id_ok(hint.resource_id) or not _signal_ok(hint.signal):
            continue
        if hint.resource_id in known_ids:
            signals[hint.resource_id] = hint.signal
    out: list[ResourceNode] = []
    annotated_ids: list[str] = []
    for node in authoritative_nodes:
        if node.id not in signals:
            out.append(node)
            continue
        new_tags = dict(node.tags)
        new_tags[SUPPLEMENTAL_SOURCE_TAG] = SUPPLEMENTAL_SOURCE
        signal = signals[node.id]
        if signal is not None:
            new_tags[SUPPLEMENTAL_SIGNAL_TAG] = signal
        out.append(node.model_copy(update={"tags": new_tags}))
        annotated_ids.append(node.id)
    return SupplementalResult(nodes=out, annotated_ids=annotated_ids)


def to_source_reference(resource_id: str) -> SourceReference:
    """Provenance for a Kuiper supplemental annotation — cites the connector + ARG resource id."""
    return SourceReference(kind="connector", id=SUPPLEMENTAL_SOURCE, detail=resource_id)


def _canonicalize_host(host: str) -> str:
    """Canonicalize a hostname EXACTLY as HTTPX will encode it — fail closed on any IDNA error.

    Mirrors ``httpx._urlparse.encode_host``: an ASCII host is lower-cased and used as-is (already
    the punycode/``xn--`` form for an internationalized name); a non-ASCII host is encoded with the
    SAME ``idna`` library HTTPX uses (``idna.encode``, IDNA2008 — NOT the legacy stdlib ``idna``
    codec, which would map e.g. ``ß`` → ``ss`` and validate a DIFFERENT host than HTTPX requests).
    A single trailing FQDN dot is stripped. Any IDNA failure raises :class:`InvalidKuiperEndpoint`
    (fail closed) — never a lossy fallback. The returned value is the byte-for-byte host HTTPX will
    put on the wire, so the allowlist check and the actual request target can never diverge (MED-A).
    """
    normalized = host.strip().rstrip(".").lower()
    if not normalized:
        raise InvalidKuiperEndpoint("endpoint host is empty")
    if normalized.isascii():
        return normalized
    try:
        return idna.encode(normalized).decode("ascii")
    except idna.IDNAError as exc:
        raise InvalidKuiperEndpoint("endpoint host is not IDNA-encodable") from exc


def validate_endpoint(base_url: str, hints_path: str, approved_hosts: Sequence[str]) -> str:
    """Validate the endpoint BEFORE any credential is resolved — or raise (credential-exfil safe).

    Returns the full endpoint URL only when ALL hold: scheme is ``https``; there is no userinfo,
    query, or fragment; **no explicit port**; the host is non-empty, not an IP literal (canonical
    dotted-quad/IPv6 OR a legacy numeric/hex/octal/short form), not a known placeholder (after
    canonicalization), and — compared on its canonical (lower-cased, trailing-dot-stripped,
    HTTPX-identical IDNA-encoded) form — present in ``approved_hosts`` (there is no default host);
    and ``hints_path`` is a simple, safe path. Any failure raises :class:`InvalidKuiperEndpoint` /
    :class:`KuiperEndpointNotApproved` so the caller fails closed and NEVER resolves a credential or
    sends a request.

    MED-A: the returned URL is rebuilt from the VALIDATED scheme + canonical host + validated path —
    the raw ``base_url`` host is never handed to HTTPX downstream, so the host that was
    allowlist-checked is byte-for-byte the host that is requested. Canonicalization closes
    trailing-dot, explicit-port, IDN-equivalent/confusable, and loopback/IP-literal (incl. legacy
    numeric) bypasses; ``http://`` is rejected so it can never be used even with ``verify=True``.
    """
    parts = urlsplit(base_url)
    if parts.scheme != "https":
        raise InvalidKuiperEndpoint("endpoint scheme must be https")
    if parts.username or parts.password:
        raise InvalidKuiperEndpoint("endpoint must not contain userinfo")
    if parts.query or parts.fragment:
        raise InvalidKuiperEndpoint("endpoint must not contain a query or fragment")
    # An explicit port is part of the endpoint identity but is not covered by a host-only allowlist,
    # so reject it outright rather than let ``host:port`` slip through on host alone.
    if parts.port is not None:
        raise InvalidKuiperEndpoint("endpoint must not specify an explicit port")
    raw_host = parts.hostname
    if not raw_host:
        raise InvalidKuiperEndpoint("endpoint host is empty")
    normalized_host = raw_host.strip().rstrip(".").lower()
    # Reject IP literals — the canonical dotted-quad/IPv6 forms AND legacy numeric/hex/octal/short
    # forms (LOW-D) that ``ipaddress`` would treat as a hostname. Kuiper must be a named host.
    try:
        ipaddress.ip_address(normalized_host)
    except ValueError:
        if _is_numeric_ipv4_literal(normalized_host):
            raise InvalidKuiperEndpoint("endpoint host must not be a numeric IP literal") from None
    else:
        raise InvalidKuiperEndpoint("endpoint host must not be an IP literal")
    host = _canonicalize_host(raw_host)
    if host in _PLACEHOLDER_HOSTS:
        raise InvalidKuiperEndpoint("endpoint host is a placeholder")
    approved = {_canonicalize_host(h) for h in approved_hosts}
    if host not in approved:
        raise KuiperEndpointNotApproved("endpoint host is not on the approved-host allowlist")
    if not hints_path.startswith("/") or any(c in hints_path for c in "?#@ "):
        raise InvalidKuiperEndpoint("hints_path is not a simple path")
    # MED-A: rebuild from the VALIDATED components only — canonical host + validated scheme/path —
    # so HTTPX is never handed the raw host and requests exactly the host we allowlist-checked.
    base_path = parts.path.rstrip("/")
    full_path = f"{base_path}/{hints_path.lstrip('/')}"
    return urlunsplit((parts.scheme, host, full_path, "", ""))


def _coerce_hint_list(payload: Any) -> list[dict[str, Any]]:
    """Strictly extract a list of hint dicts from the response payload.

    Accepts a bare list, or a ``{hints|value|data: [...]}`` envelope with **exactly one** recognized
    key present. Ambiguous, unrecognized, a non-list value, or any non-dict entry all **raise** — so
    a broken feed surfaces as ``available=False`` rather than masquerading as healthy-but-empty.

    TODO(human): confirm the real Kuiper response envelope and tighten this once the contract is
    published; the recognized keys are a synthetic placeholder.
    """
    if isinstance(payload, list):
        items: list[Any] = payload
    elif isinstance(payload, dict):
        present = [k for k in ("hints", "value", "data") if k in payload]
        if len(present) != 1:
            raise KuiperHintError("ambiguous or unrecognized Kuiper payload shape")
        candidate = payload[present[0]]
        if not isinstance(candidate, list):
            raise KuiperHintError("Kuiper envelope value is not a list")
        items = candidate
    else:
        raise KuiperHintError("unrecognized Kuiper payload shape")
    if not all(isinstance(item, dict) for item in items):
        raise KuiperHintError("Kuiper payload contains non-dict entries")
    return [item for item in items if isinstance(item, dict)]


# --------------------------------------------------------------------------------------
# Network edge — the ONLY place that performs I/O. httpx is imported lazily here.
# --------------------------------------------------------------------------------------
class KuiperClient:
    """Thin, read-only Kuiper client. Fail-closed by default; validates the endpoint FIRST.

    On :meth:`fetch_raw` the endpoint is validated **before** any credential is resolved — an
    unapproved/placeholder/non-https endpoint fails closed with **no** credential resolution and
    **no** network call. Only then is a keyless token resolved (injected provider → Key Vault by
    identity → local-dev env fallback); absent ⇒ ``error="NoCredential"``, still no request. Inject
    ``client`` (an ``httpx.Client`` on ``httpx.MockTransport``), ``credential_provider``, and/or
    ``secret_provider`` to keep everything testable without touching the network or a vault.
    """

    def __init__(
        self,
        config: KuiperConfig,
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
        """The single network edge. Read-only GET; returns validated hints or fails closed.

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
        # HIGH-1: validate BEFORE touching any credential. Raises ⇒ fail closed, no credential read.
        endpoint = validate_endpoint(
            self._config.base_url, self._config.hints_path, self._config.approved_hosts
        )
        token = resolve_bearer_token(
            self._credential_provider,
            self._config.token_env,
            secret_provider=self._secret_provider,
            secret_name=self._config.token_secret_name,
        )
        if not token:
            return FetchResult(available=False, error="NoCredential")

        import httpx  # lazy: keeps importing this module (and Discovery) SDK-free (LOW).

        # TLS verification on — never an insecure request. Per-request timeouts are set per attempt
        # (bounded by the remaining deadline), so no client-wide timeout is configured here.
        active_client = self._client or httpx.Client(verify=True)
        owns_client = self._client is None
        deadline = time.monotonic() + self._config.max_elapsed_s

        def _remaining() -> float:
            return deadline - time.monotonic()

        def _bounded_sleep(seconds: float) -> None:
            # MED-2/MED-C: never sleep past the overall deadline.
            self._sleep(max(0.0, min(seconds, _remaining())))

        def _retry_on(exc: BaseException) -> bool:
            # Retry only transient transport failures, and only while the deadline has time left.
            transient = isinstance(exc, httpx.TransportError)
            return transient and _remaining() > 0.0

        try:
            def _attempt() -> list[dict[str, Any]]:
                # MED-C: bound EVERY attempt by the remaining deadline — check before the request
                # and cap the per-request timeout to what is left.
                remaining = _remaining()
                if remaining <= 0.0:
                    raise KuiperDeadlineExceeded("kuiper fetch deadline exhausted")
                per_attempt_timeout = min(self._config.timeout_s, remaining)
                # MED-B/MED (decompression bomb): stream RAW wire bytes and ask the server not to
                # compress, so the byte ceiling is measured on the on-the-wire body — never on the
                # far-larger decoded side of a decompression bomb.
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
                records = _coerce_hint_list(payload)
                # Atomic validation (MED-1) + bounds (MED-2). Any bad record ⇒ whole fetch fails.
                hints = parse_hints_atomic(
                    records,
                    max_records=self._config.max_records,
                    max_field_len=self._config.max_field_len,
                )
                return [hint.model_dump() for hint in hints]

            raw = run_with_retries(
                _attempt,
                attempts=self._config.retries,
                base_delay_s=self._config.base_delay_s,
                max_delay_s=self._config.max_delay_s,
                sleep=_bounded_sleep,
                rng=self._rng,
                retry_on=_retry_on,
            )
            # MED-C: a successful attempt that overran the deadline is still rejected (fail closed):
            # a single slow attempt must never smuggle late data past the overall time ceiling.
            if _remaining() <= 0.0:
                raise KuiperDeadlineExceeded("kuiper fetch overran the deadline")
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
      a server that compresses anyway is refused, not decoded) — :class:`InvalidKuiperResponse`;
    * streams RAW wire bytes via ``iter_raw()`` (NO implicit decompression) and rejects the moment
      the ceiling WOULD be exceeded — ``len(buffer) + len(chunk) > max_bytes`` is checked BEFORE the
      chunk is appended, so an over-limit buffer is never materialized;
    * checks the remaining overall deadline on EVERY chunk (MED-B) so a slow-drip body is aborted
      mid-stream rather than drained.

    Because a non-identity coding is refused, the buffered raw bytes are the literal body and are
    JSON-decoded as-is. Byte-ceiling breach ⇒ :class:`KuiperResponseTooLarge`; deadline breach ⇒
    :class:`KuiperDeadlineExceeded`; unbounded/refused coding ⇒ :class:`InvalidKuiperResponse`.
    """
    declared = response.headers.get("content-length")
    if declared is not None:
        try:
            declared_n = int(declared)
        except ValueError as exc:
            raise KuiperResponseTooLarge("invalid Content-Length header") from exc
        if declared_n > max_bytes:
            raise KuiperResponseTooLarge("declared response exceeds byte ceiling")
    # Refuse a body we cannot bound on the wire: any content coding other than identity is rejected
    # rather than decoded (a decompression bomb would blow the ceiling on the decoded side).
    encoding = response.headers.get("content-encoding", "").strip().lower()
    if encoding and encoding != "identity":
        raise InvalidKuiperResponse("response carries a non-identity content-encoding")
    buffer = bytearray()
    for chunk in _iter_wire_bytes(response):
        # MED-B: bound total streaming time — abort the moment the overall deadline is exhausted.
        if time.monotonic() >= deadline:
            raise KuiperDeadlineExceeded("kuiper fetch deadline exhausted while streaming")
        # Reject BEFORE appending so an over-limit buffer is never materialized (decompression-bomb
        # / oversized-body safe — the check is on raw wire bytes, the correct side of any coding).
        if len(buffer) + len(chunk) > max_bytes:
            raise KuiperResponseTooLarge("streamed response exceeds byte ceiling")
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
