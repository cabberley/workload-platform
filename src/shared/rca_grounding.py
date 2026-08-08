"""Pure, provable grounding gate for the advisory RCA explanation (issue #54).

The RCA-explanation edge (:mod:`modules.aiops.connectors.rca_explanation`) asks an in-boundary LLM
to *explain* an existing auto-RCA :class:`shared.contracts.AgentResponse` — strictly in terms of the
evidence the RCA already cited. This module is the **no-hallucination enforcement**: a pure,
deterministic, I/O-free post-generation check that REJECTS an explanation which introduces any
evidence-like entity (a resource id, nodeId, metric name, hostname/FQDN, email domain, IP literal,
or numeric quantity) that is NOT present in the RCA's own cited fields.

It lives in ``shared`` (not ``modules.aiops``) so the durable persistence boundary
(:func:`shared.contracts.build_rca_advisories`) can RE-RUN the very same gate when materialising a
worker-supplied advisory — a caller/worker token must never be able to inject ungrounded text that
is then persisted and served as "grounded". ``modules.aiops.rca_grounding`` re-exports this module,
so the aiops edge and its tests keep importing from their own module (module isolation holds:
importing ``shared.*`` from a module is allowed; ``shared`` imports no module).

Design (fail-closed, advisory-only):

* :func:`evidence_corpus` builds the ALLOWED token set from ONLY the RCA's already-egress-classified
  cited fields (``findings`` / ``risks`` / ``recommendations`` / ``sourceReferences``). Resource-id
  paths are additionally split on ``/`` so a faithful explanation may name any cited *segment*
  (e.g. the short resource name) without tripping the gate.
* :func:`candidate_entity_tokens` extracts the *entity-like* tokens from a model's output — the
  resource-id / nodeId / metric-name / hostname / IP / email-domain shapes that are the real
  hallucination vector. Plain English words carry no identifier marker and are never treated as
  evidence, so a natural-language summary is not spuriously rejected. Two allow-lists keep ordinary
  prose from reading as an entity: benign platform-vocabulary hyphenated words (``root-cause`` …)
  and common dotted abbreviations (``e.g.`` / ``i.e.`` / ``etc.`` …).
* IP literals (IPv4 AND IPv6, compressed or expanded) are detected structurally with the stdlib
  :mod:`ipaddress` module — colons make IPv6 vanish under the identifier tokenizer, so IP literals
  are extracted at the TEXT level and canonicalised (``ipaddress.ip_address(...).compressed``) so
  ``::1`` and its expanded form ``0:0:0:0:0:0:0:1`` ground consistently. Any IP literal in the
  output must appear (canonically) in the cited corpus.
* Numeric quantities in the output must each appear in the cited numeric set (numbers in the cited
  text PLUS the RCA ``confidence``). An explanation must NOT introduce a new quantity (a fabricated
  ``97 percent across 12 nodes`` fails closed). This is intentionally strict; a dropped advisory
  degrades safely to the pure RCA.
* :func:`is_grounded` returns ``True`` iff EVERY entity token, EVERY IP literal, AND EVERY numeric
  quantity in the output appears in the cited corpus **exactly** (there is NO per-segment
  recombination — a fabricated full path whose individual segments happen to be cited elsewhere is
  NOT grounded). :func:`ground_or_reject` returns the explanation when grounded, else ``None`` — the
  edge then surfaces the "review evidence / call support" path (it never asserts an ungrounded one).

Robustness against evasion:

* All text is Unicode-hardened BEFORE tokenising (:func:`_preprocess`): NFKC-normalised, Unicode
  format / zero-width characters (category ``Cf``, incl. U+200B-U+200D, U+FEFF) are stripped, and
  Unicode dashes (category ``Pd`` and the math minus U+2212) are folded to ASCII ``-``. Any token
  that still contains a non-ASCII letter/digit (e.g. a homoglyph) is treated as an entity that must
  match a cited token EXACTLY (fail closed).
* Dotted host/FQDN/email-domain/IPv4 shapes are entities even without a ``/``/``_``/``-``/digit
  marker, closing the "pure dotted hostname" bypass.
* An EMPTY evidence corpus grounds NOTHING: :func:`ground_or_reject` fails closed for any non-empty
  explanation when there is nothing cited to ground on.

**Residual limitation (documented, not code-caught):** a single-label bare-word hostname
(``patchserver``) or an allow-listed word used as a host (``root-cause``) is indistinguishable from
ordinary prose by token shape — no lexical gate can catch it. The robust future fix is structured /
extractive model output referencing cited evidence by id/index, rendered through fixed backend
templates so free text never reaches the operator (see ADR 0020). The feature ships flag-OFF and
GO-LIVE is gated on the CELA/HiTrust sign-off that owns acceptance of this residual; advisory-only +
human-disposes + evidence-shown-alongside keeps the residual risk low today.
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from decimal import Decimal, InvalidOperation

from shared.contracts import AgentResponse

# Shared projection bounds (reused by the persistence boundary in ``shared.contracts`` + the edge):
# a bounded advisory can never bloat the result envelope or the read model.
MAX_ADVISORY_CHARS = 2000
MAX_RCA_ADVISORIES = 64
MAX_SOURCE_REFERENCES = 32
# Bounds for the grounding-evidence projection SHOWN alongside an advisory (issue #54, MED-5): the
# advisory is grounded on — and the console displays — the SAME bounded findings/risks/recs (plus
# sourceReferences), so evidence-grounded-on == evidence-shown. Caps keep the read model small.
MAX_GROUNDING_ITEMS = 16
MAX_GROUNDING_ITEM_CHARS = 500

# ONE tokenizer for entities AND numbers (issue #54, MED-4): split on whitespace and the
# operator/quote/bracket punctuation that separates values (``@`` splits an email into local-part +
# domain), but KEEP the value-internal chars ``.`` ``,`` ``-`` ``_`` ``/`` ``:`` inside a token so
# resource ids, GUIDs, versions, grouped-thousands (``12,000``) and IPv6 literals (``2001:db8::1``)
# all survive WHOLE. Sharing one split across both paths closes the MED-4 gap where a digit run
# glued to an operator (``97%`` / ``$18000`` / ``#4711`` / ``~450``) was seen by NEITHER check (the
# number path couldn't fullmatch it and the entity path split it to a bare, non-entity ``97``).
_TOKEN_SPLIT = re.compile(r"[\s@;()\[\]{}\"'`<>=!?|~^*%$#&+\\]+")

# Surrounding characters trimmed from a raw token before classification. Surrounding brackets/quotes
# and TRAILING sentence punctuation (plus a dangling group comma) are stripped so ``5.`` /
# ``12,000,`` classify cleanly, but a LEADING ``.`` / ``-`` / ``+`` is deliberately KEPT so ``.5``
# never collapses to ``5`` (they stay distinct) and a signed number keeps its sign.
_TOKEN_WRAP = "()[]{}\"'`<>"  # noqa: S105 - bracket/quote set, not a secret
_TOKEN_TRAIL = ".,;:!?"  # noqa: S105 - sentence punctuation set, not a secret
_TOKEN_LEAD = ",:"  # noqa: S105 - leading punctuation set, not a secret

# A WHOLE clean numeric lexeme (issue #54, MED-4): optional sign, an integer part that is either
# a plain digit run OR grouped thousands (``12,000``), an optional single ``.decimal`` — fully
# anchored and REQUIRING a leading digit. Matched against the token WITHOUT any leading
# strip/normalize that could mutate it, so ``.5`` does NOT match (no leading digit ⇒ entity), a
# version ``1.4.0`` (two dots) does NOT match, and a GUID / resource id (internal ``-``/``_``/``/``
# or letters) does NOT match — those are all entities, cited exactly. Only a bare quantity reaches
# the numeric path.
_NUMERIC_LEXEME = re.compile(r"[-+]?(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?\Z")

# Numeric comparison uses plain :class:`Decimal` equality/hash — no ``normalize()``, no bounded
# precision context. Decimal already equates grouping/trailing-zero forms (``12,000`` == ``12000``,
# ``0.90`` == ``0.9``, ``1E+1`` == ``10``, ``-0`` == ``0``) EXACTLY with no rounding, so distinct
# large quantities can never collide beyond a precision boundary.

# The math minus sign (category Sm, so not caught by the Pd dash fold) - normalised to ASCII '-'.
_MATH_MINUS = "\u2212"

# Benign, platform-vocabulary hyphenated words that legitimately appear in advisory prose and must
# NOT be treated as cited-evidence entities (they are English, not identifiers). Kept small and
# explicit; anything not here that looks like an identifier must be grounded.
_BENIGN_HYPHENATED: frozenset[str] = frozenset(
    {
        "root-cause",
        "fail-closed",
        "in-boundary",
        "auto-rca",
        "blast-radius",
        "call-support",
        "read-only",
        "single-point-of-failure",
        "point-of-failure",
        "well-known",
        "up-to-date",
        "z-score",
        "end-to-end",
    }
)

# Common dotted abbreviations that appear in ordinary prose and must NOT read as a hostname/FQDN.
# Matched on the normalized (trailing-dot-stripped, lower-cased) token form.
_ABBREVIATIONS: frozenset[str] = frozenset(
    {
        "e.g",
        "i.e",
        "etc",
        "vs",
        "a.k.a",
        "cf",
        "et.al",
        "a.m",
        "p.m",
        "u.s",
    }
)


def _preprocess(text: str) -> str:
    """Unicode-harden text before tokenising: NFKC, strip format/zero-width, fold dashes to ASCII.

    Removes category ``Cf`` characters (Unicode format / zero-width joiners, U+200B-U+200D, U+FEFF)
    that could split or hide an identifier, and folds every Unicode dash (category ``Pd``, plus the
    math minus U+2212) to an ASCII ``-`` so a non-breaking-hyphen cannot smuggle a hyphenated id
    past the tokenizer.
    """
    normalized = unicodedata.normalize("NFKC", text)
    out: list[str] = []
    for ch in normalized:
        category = unicodedata.category(ch)
        if category == "Cf":
            continue
        if category == "Pd" or ch == _MATH_MINUS:
            out.append("-")
            continue
        out.append(ch)
    return "".join(out)


def _normalize(token: str) -> str:
    """Lower-case a raw token and strip separator punctuation from both ends."""
    return token.strip("._-/").lower()


def _try_ip(token: str) -> str | None:
    """Return the canonical (compressed, lower-cased) form of ``token`` if it is an IP literal.

    Accepts IPv4 and IPv6 (compressed or expanded). Canonicalising via
    :attr:`ipaddress._BaseAddress.compressed` makes ``::1`` and ``0:0:0:0:0:0:0:1`` compare equal.
    A trailing sentence punctuation char is tolerated so ``the host is ::1.`` still detects ``::1``.
    """
    for candidate in (token, token.rstrip(".,;:!?")):
        try:
            return ipaddress.ip_address(candidate).compressed.lower()
        except ValueError:
            continue
    return None


def _to_decimal(lexeme: str) -> Decimal | None:
    """Canonicalise a clean numeric lexeme to a comparable :class:`Decimal`.

    Grouping commas are removed and the value is compared as a plain :class:`Decimal`: its own
    equality/hash equate grouping and trailing-zero forms EXACTLY with no precision loss —
    ``12,000`` == ``12000``, ``0.90`` == ``0.9``, ``1E+1`` == ``10``, ``-0`` == ``0`` — while
    keeping distinct quantities distinct (``-12`` != ``12``; two long numbers differing in any digit
    never collide). Returns ``None`` for an unparseable lexeme (never raises).
    """
    try:
        return Decimal(lexeme.replace(",", ""))
    except InvalidOperation:
        return None


def _clean_token(raw: str) -> str:
    """Strip surrounding wrappers + TRAILING sentence punctuation, KEEPING a leading sign/dot."""
    tok = raw.strip(_TOKEN_WRAP)
    tok = tok.rstrip(_TOKEN_TRAIL)
    tok = tok.lstrip(_TOKEN_LEAD)
    return tok


def _classify_token(token: str, entities: set[str], numbers: set[Decimal]) -> None:
    """Route ONE non-IP token into the entity or number bucket (exhaustive, fail-closed).

    A token with no digit is an entity only if it looks like an identifier (marker / dotted host /
    non-ASCII). A digit-bearing token is a NUMBER iff the WHOLE token is a clean numeric lexeme;
    otherwise (a version ``1.4.0``, a GUID, ``vm-01``, ``.5``, ``0x1f``, ``1e3``, ``24/7``,
    ``250ms``, ``12,34``) it is an ENTITY that must be cited EXACTLY. Every digit-bearing token
    therefore lands in exactly one grounded bucket — the exhaustive classification closing MED-4.
    """
    if not any(ch.isdigit() for ch in token):
        if _looks_like_entity(token):
            entities.add(_normalize(token))
        return
    if _NUMERIC_LEXEME.fullmatch(token):
        value = _to_decimal(token)
        if value is not None:
            numbers.add(value)
        return
    entities.add(_normalize(token))


def _classify_segment(segment: str, entities: set[str]) -> None:
    """Entity-ONLY classification for a ``/``-split path segment.

    A faithful summary may name a single cited segment (e.g. the short resource name), so segments
    feed the ENTITY corpus. They deliberately never feed the NUMBER corpus: a pure-digit segment
    (e.g. a subscription ``00000000``) must NOT contribute a harvested quantity — that was the
    original MED-4 digit-fragment bug.
    """
    if _try_ip(segment) is not None:
        return
    if not any(ch.isdigit() for ch in segment):
        if _looks_like_entity(segment):
            entities.add(_normalize(segment))
        return
    if _NUMERIC_LEXEME.fullmatch(segment):
        return
    entities.add(_normalize(segment))


def _extract(text: str) -> tuple[set[str], set[str], set[Decimal]]:
    """Classify ``text`` into (entity tokens, canonical IP literals, numeric quantities).

    The SINGLE tokenization + exhaustive per-token classification, used symmetrically for the cited
    corpus AND the model-output candidates so membership is exact and there is no tokenizer gap
    between the entity and number paths (issue #54, MED-4). IP literals are detected structurally
    (:func:`_try_ip`, keeping ``:`` inside a token so IPv6 stays whole) and never double-counted as
    numbers.
    """
    entities: set[str] = set()
    ips: set[str] = set()
    numbers: set[Decimal] = set()
    for raw in _TOKEN_SPLIT.split(_preprocess(text)):
        stripped = raw.strip(_TOKEN_WRAP)
        if not stripped:
            continue
        ip = _try_ip(stripped)
        if ip is not None:
            ips.add(ip)
            continue
        token = _clean_token(raw)
        if not token:
            continue
        _classify_token(token, entities, numbers)
        if "/" in token:
            for segment in token.split("/"):
                if segment:
                    _classify_segment(segment, entities)
    return entities, ips, numbers


def _is_ipv4(token: str) -> bool:
    """True iff ``token`` is a dotted-quad IPv4 literal (four 0-255 octets)."""
    parts = token.split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def _is_dotted_entity(token: str) -> bool:
    """True iff ``token`` is a hostname/FQDN/email-domain shape (dotted, TLD-like or digit-bearing).

    Requires at least two dot-separated labels AND at least one ASCII letter somewhere (so a plain
    decimal like ``0.90`` or a z-score like ``3.5`` is NOT an entity). It is an entity if the final
    label is alphabetic with length >= 2 (a TLD-like suffix, e.g. ``example.com``) OR any label
    contains a digit (e.g. ``server01.internal.example``).
    """
    labels = token.split(".")
    if len(labels) < 2:
        return False
    if not any(ch.isalpha() for ch in token):
        return False
    final = labels[-1]
    if final.isalpha() and len(final) >= 2:
        return True
    return any(any(ch.isdigit() for ch in label) for label in labels)


def _looks_like_entity(token: str) -> bool:
    """Return True iff ``token`` has the shape of a resource id / nodeId / metric / host / IP.

    Fail-closed classifier. Non-ASCII content (e.g. a homoglyph) is ALWAYS an entity (must be cited
    exactly). Dotted host/FQDN/email-domain/IPv4 shapes are entities even without an
    ``/``/``_``/``-``/digit marker. Otherwise a token is an entity iff it contains at least one
    letter AND at least one identifier marker: a path ``/``, an underscore, a hyphen, or an internal
    digit. Plain English words (no marker) are never entities; a benign hyphenated word or a common
    dotted abbreviation is treated as ordinary prose.
    """
    if token in _BENIGN_HYPHENATED:
        return False
    if _normalize(token) in _ABBREVIATIONS:
        return False
    if any(ord(ch) > 127 for ch in token):
        return True
    if _is_ipv4(token):
        return True
    if _is_dotted_entity(token):
        return True
    if not any(ch.isalpha() for ch in token):
        return False
    return "/" in token or "_" in token or "-" in token or any(ch.isdigit() for ch in token)


def _cited_text(response: AgentResponse) -> list[str]:
    """The RCA's already-cited fields - the ONLY evidence an explanation may draw on."""
    parts: list[str] = []
    parts.extend(response.findings)
    parts.extend(response.risks)
    parts.extend(response.recommendations)
    for ref in response.sourceReferences:
        parts.append(ref.kind)
        parts.append(ref.id)
        if ref.detail:
            parts.append(ref.detail)
    return parts


def _corpus(response: AgentResponse) -> tuple[set[str], set[str], set[Decimal]]:
    """The cited (entity, IP, number) corpora — the ONLY evidence an explanation may draw on.

    Built from the RCA's already-cited fields via the SAME :func:`_extract` classification used for
    the model output, so corpus/candidate membership is exact and symmetric. The number corpus is
    seeded with the RCA ``confidence`` (canonical :class:`Decimal`, via ``str(confidence)`` so the
    float never leaks a binary artefact). Entity path segments let a faithful summary name a single
    cited segment; there is NO per-segment recombination of a fabricated full path.
    """
    entities: set[str] = set()
    ips: set[str] = set()
    numbers: set[Decimal] = set()
    conf = _to_decimal(str(response.confidence))
    if conf is not None:
        numbers.add(conf)
    for part in _cited_text(response):
        part_entities, part_ips, part_numbers = _extract(part)
        entities |= part_entities
        ips |= part_ips
        numbers |= part_numbers
    return entities, ips, numbers


def evidence_corpus(response: AgentResponse) -> set[str]:
    """Build the ALLOWED entity-token corpus from the RCA's cited fields (findings/risks/recs/refs).

    Includes every entity-like token and - for path-like ids - each ``/``-split segment, so a
    faithful summary may name a cited resource by its full id or by a cited segment (e.g. its short
    name). Bare numbers and IP literals are NOT entities (they ground on their own corpora), so a
    fabricated ``.5`` can never match a cited quantity ``5``. Grounding still requires a candidate
    to match EXACTLY: a fabricated full path is NOT reconstructable from independently-cited
    segments.
    """
    entities, _, _ = _corpus(response)
    return entities


def candidate_entity_tokens(text: str) -> set[str]:
    """Extract the entity-like (resource-id / nodeId / metric / host / version) tokens from text."""
    entities, _, _ = _extract(text)
    return entities


def _has_cited_evidence(response: AgentResponse) -> bool:
    """True iff the RCA cited ANY textual evidence (an entity, an IP, or a non-confidence number).

    The confidence always seeds the number corpus, so "confidence only" is NOT cited evidence — an
    RCA that cited nothing else cannot ground any explanation (fail closed).
    """
    entities, ips, numbers = _corpus(response)
    conf = _to_decimal(str(response.confidence))
    textual_numbers = numbers - ({conf} if conf is not None else set())
    return bool(entities or ips or textual_numbers)


def is_grounded(response: AgentResponse, explanation: str) -> bool:
    """Return True iff every entity/IP/number in ``explanation`` is present in the cited corpus.

    Pure and deterministic. An explanation is grounded only when ALL of these hold: every entity
    token (resource id / nodeId / metric / hostname / email domain / version), every IP literal
    (IPv4 or IPv6, compared canonically), AND every numeric quantity in the output appears EXACTLY
    in the RCA's cited evidence (numbers additionally allow the RCA ``confidence``). There is
    deliberately no per-segment recombination: a fabricated multi-segment path is rejected even when
    each of its segments is cited elsewhere. An explanation with no entity tokens, IPs, or numbers
    (pure natural-language prose) is trivially grounded - callers must additionally reject the
    "nothing cited" case (see :func:`ground_or_reject`).
    """
    cand_entities, cand_ips, cand_numbers = _extract(explanation)
    corpus_entities, corpus_ips, corpus_numbers = _corpus(response)
    if any(candidate not in corpus_entities for candidate in cand_entities):
        return False
    if any(candidate not in corpus_ips for candidate in cand_ips):
        return False
    return all(candidate in corpus_numbers for candidate in cand_numbers)


def ground_or_reject(response: AgentResponse, explanation: str) -> str | None:
    """Return the trimmed ``explanation`` if grounded on the cited evidence, else ``None``.

    ``None`` ⇒ the edge fails closed: it drops the explanation and surfaces the advisory
    "review the cited evidence / call support" path rather than asserting an ungrounded narrative.
    A blank explanation is treated as no explanation (``None``). If the RCA cites NO evidence at all
    (confidence only), any non-empty explanation is rejected - you cannot ground on nothing.
    """
    trimmed = explanation.strip()
    if not trimmed:
        return None
    if not _has_cited_evidence(response):
        return None
    if not is_grounded(response, trimmed):
        return None
    return trimmed


__all__ = [
    "MAX_ADVISORY_CHARS",
    "MAX_GROUNDING_ITEMS",
    "MAX_GROUNDING_ITEM_CHARS",
    "MAX_RCA_ADVISORIES",
    "MAX_SOURCE_REFERENCES",
    "candidate_entity_tokens",
    "evidence_corpus",
    "ground_or_reject",
    "is_grounded",
]
