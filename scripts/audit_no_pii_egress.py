#!/usr/bin/env python
"""Static no-PII-egress audit for the Workloads Platform (HITRUST CSF: Data Protection & Privacy).

Guardrail #1 (`.github/copilot-instructions.md`) says only **opt-in, aggregated, PII-free findings**
may ever cross the customer boundary. This check turns that guardrail into a **fail-closed**
regression gate over the platform's **external-egress-facing contracts** — the API response models
and the alert/notification payload delivered to a webhook/Teams.

**Fail-closed principle:** when the audit cannot statically *prove* an egress surface is
PII-free-and-bounded, it **FAILS** (exit 1) rather than passing. Concretely:

* **Self-updating route enumeration.** It imports the FastAPI app and derives the egress response
  models from every route's ``response_model`` (plus any ``responses[...].model``), so a newly added
  API response cannot silently drift past the audit. A route that declares **no** ``response_model``
  (raw ``dict`` / ``Response`` / ``JSONResponse``) is treated as **unbounded egress** and flagged.
* **Recursion over the whole serialized graph.** For every response model it walks nested Pydantic
  models to arbitrary depth — through ``list[...]``, ``dict[..., Model]``, ``Optional``/``Union``
  members and ``RootModel`` roots — with a cycle guard, checking the **effective emitted key** of
  every field. A PII field name anywhere in the reachable graph ⇒ violation.
* **Alias + computed-field resolution.** The effective emitted key is the attribute name **or** any
  Pydantic alias (``alias`` / ``serialization_alias`` / ``validation_alias`` / ``AliasChoices``),
  and ``model_computed_fields`` are audited too (a computed field emitting a denylisted key ⇒
  violation) — a ``serialization_alias="patientName"`` cannot hide behind a benign attribute name.
* **Unbounded mappings are tracked waivers, never silent passes.** A free-form mapping whose
  emitted **keys** are statically unbounded (``dict[str, Any]``, ``Mapping[str, ...]``, ``extra``,
  ``model_config extra="allow"``) or a raw-dict route is a violation **unless** it carries an
  explicit waiver keyed tightly on ``Model.field`` or ``"METHOD /path"`` **with a tracking issue**
  (e.g. ``#91``). A mapping whose **key type is bounded** (``Enum`` / ``Literal[...]``) is *not*
  unbounded — its emitted keys are enumerable — so it needs no waiver, though its **value** type is
  still recursed for PII. Waived surfaces are printed **loudly** as ``TRACKED WAIVER (#91)`` so the
  residual data-minimization gap stays visible; any *new*, unkeyed open mapping still fails closed.
* **Serialization paths cannot fail open.** A ``response_model`` that is ``Any`` / ``object`` /
  bare ``dict`` / missing / an unsupported annotation is unbounded egress (violation unless waived).
  A model carrying a custom ``@model_serializer`` emits a statically-unknown shape ⇒ flagged. The
  reachable graph also recurses **dataclasses** and **TypedDict**s (not just ``BaseModel``). And for
  a route that declares a typed model, the handler body is AST-checked: returning a raw
  ``Response``/``JSONResponse``/``PlainTextResponse``/bare ``dict`` bypasses the declared model ⇒
  violation.
* **Handler/return analysis fails closed on ordinary FastAPI/Pydantic shapes.** Beyond a bare
  return, the AST walk transparently unwraps ``await`` (async handlers are the FastAPI default), and
  evaluates every branch of a ternary (``a if x else b``) or boolean-expression (``a and b`` /
  ``a or b``) return — a raw ``Response`` reachable on *any* branch is flagged. Functional
  serializers hidden in ``Annotated`` metadata (``PlainSerializer`` / ``WrapSerializer`` /
  ``SerializeAsAny``) are inspected even when nested inside containers/unions, and PEP 695
  ``type X = Annotated[...]`` aliases are unwrapped. A field annotation that cannot be reduced to a
  bounded, fully-inspected shape is flagged rather than silently passed.
* **HTTPException details use a principled three-way split.** A ``raise HTTPException(detail=...)``
  serialises ``detail`` into the response body. (1) A **provably STRING** detail — a string literal
  (still denylist-checked), an f-string, ``str(...)``, or a string ``%``/``+``/method coercion — is
  bounded or, if non-literal, flagged under a **waivable** ``<raise HTTPException detail>`` key (the
  3 tracked ``#96`` src sites use it). (2) A **provably-or-strongly STRUCTURED** detail — a
  ``dict``/``list``/``set``/``tuple`` literal or comprehension, OR a structure-producing call
  (builtin collection constructor in bare-Name ``dict(...)``, attribute ``collections.OrderedDict``
  or module-level ``X = dict`` alias form; a mapping-dump method ``model_dump()``/``to_dict()``/
  ``asdict()``; a structure encoder ``jsonable_encoder(...)`` incl. attribute/alias forms; or
  ``json.loads``) — is an **unwaivable** hard finding so no route-level string-coercion waiver can
  silence a newly-introduced PII collection. (3) A **genuinely OPAQUE** detail (a bare name of
  unknown type, or an unclassifiable call/attribute) stays on the waivable key:
  fail-closed-with-human-signoff — a human must explicitly waive each opaque surface, never a
  silent pass. This rule is applied to the handler body, to a resolved one-level module-global
  helper called in a return, and to ``Depends(...)`` dependency callables in the route's dependency
  tree — including a class dependency ``Depends(Guard)`` (FastAPI instantiates it, running
  ``__new__``/``__init__``/a user metaclass ``__call__``) and an instance dependency
  ``Depends(Guard())`` (its ``__call__``). HTTPException/Response **import aliases** (``from fastapi
  import HTTPException as ApiError``; ``X = JSONResponse``) are resolved by identity — a raw return
  of a Response subclass via a local or module-level alias, including an **attribute-bound** alias
  (``RT = responses.JSONResponse; return RT(content=...)``), is caught by identity, not just by
  name.
* **Contract dict payloads audit every branch.** The alert/notification dict contract audits EVERY
  ``return {...}`` in the function (incl. dicts behind a ternary/BoolOp), not just the first, so a
  PII key in a later branch is still caught.
* **Fail closed on introspection failure.** If the app or a model cannot be imported/introspected,
  that is a violation (never a silent skip).

**Documented static-analysis residuals (accepted, tracked under #91 unless noted):** local variable
resolution is SINGLE-LEVEL but UNION / may-reach — EVERY value that may be assigned to a name
(across ``if``/``else`` and other branches) is considered, not just the last write, so a
raw/structured value reachable on ANY branch of a returned or ``detail`` name is flagged;
correspondingly a name is treated as a bounded string only if ALL of its assignments are
provably-string (any structured branch dominates, string requires unanimity). This deliberately
over-approximates straight-line reassignment (``x = raw(); x = safe(); return x``) — an accepted,
waivable false-positive. A ``Name`` that resolves to another ``Name``, a parameter, or a value
needing more than one level of indirection is not chased further and keeps its fail-closed (waivable
scalar / model-coerced) default (a ``set[str]`` name guard prevents cyclic-assignment recursion);
helper and dependency delegation is likewise resolved ONE level
deep — a helper that itself calls another helper which returns/raises raw egress is not followed; a
dependency FUNCTION's own ``return`` expressions ARE audited one level (a dependency that returns a
raw dict/list/Response — incl. the attribute-bound alias forms — bypasses the route's
response_model and is flagged at its source), but a dependency or helper that delegates to ANOTHER
function's return is not chased past one level; an
unresolvable attribute-call return (``return service.emit()`` whose return type cannot be proven) is
not flagged (the explicit egress allowlist is the real boundary); a genuinely OPAQUE HTTPException
detail (a bare name of unknown type or an unclassifiable call/attribute that is neither
provably-string nor provably-structured) stays waivable-by-human (a human must sign off each opaque
surface); validator / ``Annotated``-metadata callables (``BeforeValidator``/``AfterValidator``/
``field_validator``) that raise a structured ``HTTPException`` from a dependency/route parameter are
NOT yet audited — a documented, deliberately-deferred residual tracked in issue **#103** (an
anti-pattern of near-zero realism; the real app uses no validators; covered by over-approximation +
human-waiver + downstream guardrails); and genuinely esoteric annotation wrappers beyond the handled
``TypeAliasType``/serializer markers may not be fully reducible. (Builtin collection constructors —
bare-Name, attribute and module-level alias forms — mapping-dump methods, the ``jsonable_encoder``
structure encoder incl. attribute and one-level alias forms, ``json.loads``,
aliased-Response-subclass raw returns incl. attribute-bound aliases, dependency-function
raw/structured RETURN values (one level), and direct class-dependency ``__new__``/``__init__``
constructors are COVERED, not residual.)

Because value-constrained unbounded mappings (`ResourceNode.tags`, `ModuleRunResult.extra`,
`ImpactResult.states`, `ScaleTrigger.metadata`) still exist in ``src/**`` and are tracked by
**#91**, the corresponding HITRUST control remains documented as **Partial** in
``docs/compliance/hitrust-control-map.md`` — though issue #91 has since bounded every raw-dict
endpoint (each now returns a typed ``response_model``) and the metrics label maps (projected onto
the bounded ``MetricsSnapshotView`` at ``/api/metrics``), cutting the #91 waivers from 13 to 4.
This audit prevents *new* PII-named or unbounded egress while those residual gaps are closed.
(Opaque finding-ID value hardening is separately tracked by **#78**.)

The audit imports the platform packages — run it with the repo installed (``pip install -e .`` — the
CI ``compliance`` job does this) or ``PYTHONPATH=src``.

Usage::

    python scripts/audit_no_pii_egress.py            # audit the real egress surfaces (default)

Exit codes: ``0`` all egress surfaces provably PII-free-and-bounded (waivers allowed) · ``1`` a
violation was found (incl. an introspection failure) · ``2`` a usage error.
"""
from __future__ import annotations

import argparse
import ast
import dataclasses
import enum
import functools
import inspect
import sys
import textwrap
import types
import typing
from collections.abc import Callable, Iterator, Mapping, MutableMapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, get_args, get_origin, is_typeddict

from pydantic import (
    AliasChoices,
    BaseModel,
    PlainSerializer,
    WrapSerializer,
)
from pydantic.fields import FieldInfo
from pydantic_core import PydanticUndefined

_REPO_ROOT = Path(__file__).resolve().parents[1]


# Real exception / response base classes, resolved once so import ALIASES (e.g.
# ``from fastapi import HTTPException as ApiError``) are recognised by identity, not just by name.
_STARLETTE_HTTP_EXC: type | None
_FASTAPI_HTTP_EXC: type | None
_STARLETTE_RESPONSE: type | None
try:  # pragma: no cover - guarded so the tool degrades gracefully if the dep shape changes.
    from starlette.exceptions import HTTPException as _StarletteHTTPExc

    _STARLETTE_HTTP_EXC = _StarletteHTTPExc
except Exception:  # noqa: BLE001 - optional dependency shape; fall back to name matching.
    _STARLETTE_HTTP_EXC = None
try:  # pragma: no cover
    from fastapi import HTTPException as _FastAPIHTTPExc

    _FASTAPI_HTTP_EXC = _FastAPIHTTPExc
except Exception:  # noqa: BLE001
    _FASTAPI_HTTP_EXC = None
try:  # pragma: no cover
    from starlette.responses import Response as _StarletteResponse

    _STARLETTE_RESPONSE = _StarletteResponse
except Exception:  # noqa: BLE001
    _STARLETTE_RESPONSE = None

_HTTP_EXCEPTION_CLASSES: tuple[type, ...] = tuple(
    c for c in (_STARLETTE_HTTP_EXC, _FASTAPI_HTTP_EXC) if isinstance(c, type)
)


# --------------------------------------------------------------------------------------
# PII field-name detection (matches on the effective emitted key name).
# --------------------------------------------------------------------------------------
_PII_EXACT_TOKENS: frozenset[str] = frozenset(
    {
        "firstname", "lastname", "fullname", "givenname", "surname", "middlename",
        "maidenname", "personname", "patientname", "username",
        "phone", "mobile", "msisdn", "fax",
        "address", "gender", "sex", "dob", "ssn", "mrn", "iban", "nino", "sin",
    }
)
_PII_SUBSTRING_MARKERS: tuple[str, ...] = (
    "email", "socialsecurity", "patient", "passport", "nationalid", "dateofbirth", "birthdate",
    "creditcard", "cardnumber", "telephone", "phonenumber", "homeaddress", "streetaddress",
    "postalcode", "zipcode", "ethnicity", "religion", "biometric", "geolocation", "healthrecord",
    "medicalrecord",
)


def _normalize(name: str) -> str:
    """Lowercase and strip separators so name variants collapse (e.g. ``a_b`` -> ``ab``)."""
    return "".join(ch for ch in name.lower() if ch.isalnum())


def pii_reason(name: str) -> str | None:
    """Return a human-readable reason iff ``name`` indicates PII, else ``None``."""
    norm = _normalize(name)
    if norm in _PII_EXACT_TOKENS:
        return f"emitted key '{name}' is a known PII identifier"
    for marker in _PII_SUBSTRING_MARKERS:
        if marker in norm:
            return f"emitted key '{name}' contains PII marker '{marker}'"
    return None


# --------------------------------------------------------------------------------------
# Annotation helpers (unwrap Optional/Union/Annotated; find mappings + nested models).
# --------------------------------------------------------------------------------------
_MAPPING_TYPES = (dict, Mapping, MutableMapping)


def _iter_union_members(annotation: Any) -> list[Any]:
    """Unwrap ``Annotated`` and flatten ``X | Y`` / ``Optional[X]`` / ``Union[...]``."""
    if hasattr(annotation, "__metadata__"):  # Annotated[T, ...]
        annotation = get_args(annotation)[0]
    origin = get_origin(annotation)
    if origin is typing.Union or origin is types.UnionType:
        members: list[Any] = []
        for arg in get_args(annotation):
            members.extend(_iter_union_members(arg))
        return members
    return [annotation]


def _enum_is_closed(cls: type[enum.Enum]) -> bool:
    """True iff ``cls`` is a standard CLOSED enum (does not override ``_missing_``).

    An enum that overrides ``_missing_`` can coerce *arbitrary* values into members at runtime, so
    its key space is NOT statically enumerable — such a key must be treated as unbounded. We compare
    the underlying function of ``cls._missing_`` against ``enum.Enum._missing_`` (identity on the
    unbound function): if they differ, membership can be extended dynamically. Fail closed on any
    introspection error (treat as not-closed).
    """
    try:
        own = getattr(cls, "_missing_", None)
        base = enum.Enum._missing_
        return getattr(own, "__func__", own) is getattr(base, "__func__", base)
    except Exception:  # noqa: BLE001 — unknown => not provably closed => unbounded.
        return False


def _mapping_key_bounded(key_annotation: Any) -> bool:
    """True iff a mapping's KEY type is statically enumerable (closed ``Enum`` / ``Literal``).

    A bounded key type means the emitted keys are a known finite set, so the mapping is NOT an
    unbounded egress surface. A free-form ``str`` / ``Any`` / ``int`` / ``object`` key is unbounded,
    and so is an *open-ended* enum (one overriding ``_missing_``) whose membership can grow at
    runtime.
    """
    members = _iter_union_members(key_annotation)
    if not members:
        return False
    for member in members:
        if get_origin(member) is Literal:
            continue
        if isinstance(member, type) and issubclass(member, enum.Enum) and _enum_is_closed(member):
            continue
        return False
    return True


def _mapping_key_pii_reason(key_annotation: Any) -> str | None:
    """If a bounded key type enumerates a PII-named literal/enum value, return the reason."""
    for member in _iter_union_members(key_annotation):
        if get_origin(member) is Literal:
            for value in get_args(member):
                if isinstance(value, str) and (reason := pii_reason(value)) is not None:
                    return reason
        elif isinstance(member, type) and issubclass(member, enum.Enum):
            for choice in member:
                if isinstance(choice.value, str) and (reason := pii_reason(choice.value)):
                    return reason
    return None


def unbounded_egress_reason(annotation: Any) -> str | None:
    """Return a reason iff ``annotation`` contains a statically UNBOUNDED egress surface.

    Unbounded means: ``Any`` / ``object`` anywhere, or a mapping with a free-form (non-``Enum`` /
    non-``Literal``) key type. A mapping with a bounded key type is fine (its value is still
    recursed here for nested unbounded surfaces). Never recurses into a ``BaseModel`` (those are
    audited by model recursion), so a bounded nested model is not conflated with an open mapping.
    """
    for member in _iter_union_members(annotation):
        if member is Any or member is object:
            return f"annotation {getattr(member, '__name__', member)!r} is unbounded (Any/object)"
        # BaseModels and TypedDicts have statically-known fields — audited by model/TypedDict
        # recursion, not treated as open mappings (a TypedDict is a dict subclass, so skip early).
        if is_typeddict(member) or (isinstance(member, type) and issubclass(member, BaseModel)):
            continue
        origin = get_origin(member) or member
        if isinstance(origin, type) and issubclass(origin, _MAPPING_TYPES):
            args = get_args(member)
            key_type = args[0] if args else Any
            if not _mapping_key_bounded(key_type):
                return f"open mapping with unbounded key type ({member})"
            for value_arg in args[1:]:
                if (nested := unbounded_egress_reason(value_arg)) is not None:
                    return nested
            continue
        for arg in get_args(member):
            if (nested := unbounded_egress_reason(arg)) is not None:
                return nested
    return None


def iter_referenced_types(annotation: Any) -> list[Any]:
    """Every BaseModel / dataclass / TypedDict reachable in ``annotation`` (for recursion)."""
    found: list[Any] = []
    for member in _iter_union_members(annotation):
        is_model = isinstance(member, type) and issubclass(member, BaseModel)
        is_dc = dataclasses.is_dataclass(member) and isinstance(member, type)
        if is_model or is_typeddict(member) or is_dc:
            found.append(member)
        for arg in get_args(member):
            found.extend(iter_referenced_types(arg))
    return found


# Egress models whose static type is only PII-safe BECAUSE a reviewed egress projection redacts
# their customer-controlled/-derived free-form surface (``ResourceNode.tags`` / ``ModuleRunResult
# .extra``) before the boundary — the ``ResourceNode.tags`` / ``ModuleRunResult.extra`` waivers ride
# on that projection actually running. A route whose response_model transitively contains one of
# these MUST hand FastAPI a value produced by a trusted projection; a raw ``return store.get_estate
# (...)`` bypasses redaction while riding the model-wide waiver, so it is failed closed.
_REDACTION_REQUIRED_MODELS: frozenset[str] = frozenset({"ResourceNode", "ModuleRunResult"})

# The human-readable names of the EXACT reviewed sanitizer projections (for the violation message
# only). The ACTUAL trust decision is made by RESOLVING a call to its bound method/function and
# matching that against the reviewed definitions (see ``_reviewed_projection_callables`` /
# ``_call_is_trusted_projection``) — NOT by matching a simple attribute name, so a decoy
# ``log.redact(...)`` cannot masquerade as ``_estate_egress.redact``. Keep in lockstep with
# ``src/shared/contracts.py`` and ``src/api/app/main.py``.
_TRUSTED_EGRESS_PROJECTIONS: frozenset[str] = frozenset(
    {
        "contracts.redact_tree", "contracts.redact_node_tags", "contracts.redact_value",
        "_estate_egress.redact", "_redact_run_result_for_egress",
    }
)

# Depth bound when resolving a projection WRAPPER (a ``.redact`` staticmethod / helper that itself
# maps a canonical projection over its input) to prove it is trusted. Bounds mutual recursion.
_MAX_PROJECTION_WRAPPER_DEPTH = 4


@functools.lru_cache(maxsize=1)
def _reviewed_projection_callables() -> frozenset:
    """The EXACT reviewed egress-projection CALLABLES, resolved by identity (not by name).

    The canonical leaf projections live in ``shared.contracts`` (``redact_tree`` /
    ``redact_node_tags`` / ``redact_value``); the reviewed wrappers live in ``api.app.main``
    (``_redact_run_result_for_egress`` and ``_EstateEgress.redact``). Resolved once and matched by
    object identity so an import ALIAS (``from shared.contracts import redact_node_tags as _r``)
    still resolves, while a same-named decoy defined elsewhere does NOT. Guarded: if a module cannot
    be imported the set simply omits it (a wrapper is then re-proved structurally instead).
    """
    reviewed: set = set()
    try:
        from shared import contracts as _contracts

        reviewed.update({_contracts.redact_tree, _contracts.redact_node_tags,
                         _contracts.redact_value})
    except Exception:  # noqa: BLE001,S110 — degrade gracefully; wrappers re-proved structurally.
        pass
    try:
        from api.app import main as _main

        reviewed.add(_main._redact_run_result_for_egress)
        egress_redact = inspect.getattr_static(type(_main._estate_egress), "redact", None)
        if isinstance(egress_redact, (staticmethod, classmethod)):
            egress_redact = egress_redact.__func__
        if egress_redact is not None:
            reviewed.add(egress_redact)
    except Exception:  # noqa: BLE001,S110 — degrade gracefully; wrappers re-proved structurally.
        pass
    return frozenset(reviewed)


def _resolve_call_target(call: ast.Call, module_globals: Mapping[str, Any]) -> Any:
    """Resolve a ``Call`` node's callee to its actual Python callable, or ``None`` if unresolvable.

    A bare name resolves via ``module_globals``; an attribute call ``obj.attr(...)`` resolves
    ``obj`` (a module → its member; an instance/class → the STATIC attribute on the class, so no
    descriptor/property is triggered) and unwraps a ``staticmethod``/``classmethod``. Fail-closed:
    anything that cannot be resolved (e.g. ``log.redact`` where ``log`` has no ``redact``) is
    ``None`` and therefore NOT trusted.
    """
    func = call.func
    if isinstance(func, ast.Name):
        return module_globals.get(func.id)
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        base = module_globals.get(func.value.id)
        if base is None:
            return None
        if isinstance(base, types.ModuleType):
            return getattr(base, func.attr, None)
        owner = base if isinstance(base, type) else type(base)
        # FIX 5 (issue #91 R4): resolution is against the STATIC class attribute, so an instance
        # monkeypatch (``_estate_egress.redact = lambda n: n``) is out of the static threat model —
        # a source-edit attacker able to add that line is already inside the trust boundary and
        # could edit the redaction body directly, so the static audit gains nothing by chasing it.
        attr = inspect.getattr_static(owner, func.attr, None)
        if isinstance(attr, (staticmethod, classmethod)):
            attr = attr.__func__
        return attr
    return None


def _call_is_trusted_projection(
    call: ast.Call, module_globals: Mapping[str, Any], _depth: int = 0
) -> bool:
    """Whether ``call`` resolves to a reviewed egress projection (by identity) or a proven wrapper.

    A call is trusted when it resolves to one of the EXACT reviewed callables
    (:func:`_reviewed_projection_callables`), or — for a thin wrapper the reviewed set does not
    contain (e.g. a ``.redact`` staticmethod that maps ``redact_node_tags`` over its input) — when
    EVERY data-bearing ``return`` of the resolved function is itself fully sanitized. Bounded by
    :data:`_MAX_PROJECTION_WRAPPER_DEPTH`. A decoy (``log.redact`` / an identity wrapper) resolves
    to a non-reviewed callable whose returns are NOT fully sanitized → ``False``.
    """
    target = _resolve_call_target(call, module_globals)
    if target is None:
        return False
    if target in _reviewed_projection_callables():
        return True
    if _depth >= _MAX_PROJECTION_WRAPPER_DEPTH:
        return False
    hfunc = _resolve_helper_func(target)
    if hfunc is None:
        return False
    hglobals = getattr(target, "__globals__", {}) or {}
    returns = _iter_returns(hfunc)
    if not returns:
        return False
    return all(_return_fully_sanitized(r.value, hglobals, _depth + 1) for r in returns)


def _model_constructor_fully_sanitized(
    call: ast.Call, module_globals: Mapping[str, Any], _depth: int
) -> bool:
    """Whether a ``Model(...)`` constructor supplies fully-sanitized values for its
    redaction-required fields (and is thus safe to egress).

    Resolves the constructed class; a NON-model callable, positional args, or a ``**spread`` cannot
    be mapped to fields and fail closed. Constructing a REDACTION-REQUIRED model directly (e.g.
    ``ResourceNode(tags=...)`` / ``ModuleRunResult(extra=...)``) is NEVER sanitized — the raw
    ``tags``/``extra`` it carries is exactly what must be redacted, so only a reviewed projection
    (never a bare constructor) may produce one. For a wrapper model, each keyword whose FIELD type
    transitively contains a redaction-required model must be fully sanitized; other fields are
    irrelevant. This lets ``GraphResponse(nodes=[redact_node_tags(n) for n in ...], edges=...)``
    pass while ``GraphResponse(nodes=raw_nodes, ...)`` and ``ResourceNode(tags=raw)`` fail.
    """
    if not isinstance(call.func, ast.Name):
        return False
    target = module_globals.get(call.func.id)
    if not (isinstance(target, type) and issubclass(target, BaseModel)):
        return False
    if target.__name__ in _REDACTION_REQUIRED_MODELS:
        return False
    if call.args or any(kw.arg is None for kw in call.keywords):
        return False
    # A redaction-required field must be sanitized regardless of WHICH accepted input name the
    # constructor uses — a validation alias (``validation_alias``/``alias``, incl. every
    # ``AliasChoices`` member) lets ``Model(items=raw_nodes)`` populate field ``nodes``. Map every
    # accepted input name back to the field's redaction requirement (fail-closed).
    required: set[str] = set()
    for name, info in target.model_fields.items():
        if _REDACTION_REQUIRED_MODELS & _referenced_model_names(info.annotation):
            required |= emitted_field_keys(name, info)
    for kw in call.keywords:
        if kw.arg in required and not _return_fully_sanitized(kw.value, module_globals, _depth):
            return False
    return True


def _return_fully_sanitized(
    value: ast.expr | None, module_globals: Mapping[str, Any], _depth: int = 0
) -> bool:
    """Whether the WHOLE returned value is provably free of unsanitized redaction-required data.

    Default-deny/fail-closed: a value passes ONLY when every redaction-required part is proven to
    flow through a reviewed projection. A trusted-projection call passes; a trivial/constant passes;
    a literal collection / comprehension / dict / ternary / boolean / concatenation passes iff ALL
    its data-bearing parts pass; a model constructor passes iff its redaction-required fields are
    sanitized. Anything else — a bare ``return store.get_estate(...)``, a partially-sanitized
    collection (one raw element / concatenated raw list), a decoy wrapper, an identity wrapper —
    FAILS.
    """
    value = _unwrap_await(value)
    if _is_trivial_return(value):
        return True
    if value is None:
        return True
    if isinstance(value, ast.Call):
        if _call_is_trusted_projection(value, module_globals, _depth):
            return True
        return _model_constructor_fully_sanitized(value, module_globals, _depth)
    if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        return all(_return_fully_sanitized(e, module_globals, _depth) for e in value.elts)
    if isinstance(value, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
        return _return_fully_sanitized(value.elt, module_globals, _depth)
    if isinstance(value, ast.DictComp):
        return _return_fully_sanitized(value.value, module_globals, _depth)
    if isinstance(value, ast.Dict):
        # A ``**spread`` (key is None) injects unknown entries → fail closed.
        return all(
            k is not None and _return_fully_sanitized(v, module_globals, _depth)
            for k, v in zip(value.keys, value.values, strict=False)
        )
    if isinstance(value, ast.IfExp):
        return _return_fully_sanitized(
            value.body, module_globals, _depth
        ) and _return_fully_sanitized(value.orelse, module_globals, _depth)
    if isinstance(value, ast.BoolOp):
        return all(_return_fully_sanitized(v, module_globals, _depth) for v in value.values)
    if isinstance(value, ast.BinOp):
        return _return_fully_sanitized(
            value.left, module_globals, _depth
        ) and _return_fully_sanitized(value.right, module_globals, _depth)
    return False


def _referenced_model_names(annotation: Any, _seen: set[int] | None = None) -> set[str]:
    """Every BaseModel name transitively reachable from ``annotation`` (through nested fields).

    ``iter_referenced_types`` stops at the first model it meets (it does not descend into a model's
    OWN fields); this walk continues into each model's ``model_fields`` so a ``ResourceNode`` buried
    inside ``GraphResponse.nodes`` (or ``ModuleRunResult.estate``) is still discovered. Cycle-safe
    via an id guard.
    """
    seen = _seen if _seen is not None else set()
    names: set[str] = set()
    for ref in iter_referenced_types(annotation):
        if not (isinstance(ref, type) and issubclass(ref, BaseModel)) or id(ref) in seen:
            continue
        seen.add(id(ref))
        names.add(ref.__name__)
        for info in ref.model_fields.values():
            names |= _referenced_model_names(info.annotation, seen)
    return names


def _is_trivial_return(value: ast.expr | None) -> bool:
    """A return that carries no model data (so it needs no projection): ``None`` / empty literal."""
    value = _unwrap_await(value)
    if value is None or isinstance(value, ast.Constant):
        return True
    if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        return not value.elts
    if isinstance(value, ast.Dict):
        return not value.keys
    return False


def _call_name(func: ast.expr) -> str | None:
    """The simple callee name of a call (``JSONResponse(...)`` -> ``"JSONResponse"``)."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _iter_returns(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.Return]:
    """Every ``return <value>`` in ``func`` excluding nested function/lambda scopes."""
    returns: list[ast.Return] = []

    def visit(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
                continue  # a nested helper's return is not this handler's egress
            if isinstance(child, ast.Return) and child.value is not None:
                returns.append(child)
            visit(child)

    visit(func)
    return returns


def _iter_raises(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.Raise]:
    """Every ``raise <exc>`` in ``func`` excluding nested function/lambda scopes."""
    raises: list[ast.Raise] = []

    def visit(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
                continue  # a nested helper's raise is not this handler's egress
            if isinstance(child, ast.Raise) and child.exc is not None:
                raises.append(child)
            visit(child)

    visit(func)
    return raises


def _expr_pii_reason(node: ast.expr | None) -> str | None:
    """Reason iff any identifier / attribute / string literal in ``node`` is PII-named.

    Used to inspect the *content* of an otherwise string-typed egress value (an f-string's
    interpolations, a ``str(...)`` argument, or a structured literal): a reference such as
    ``user.email`` or a literal segment ``'patientEmail'`` marks the value as PII-bearing.
    """
    if node is None:
        return None
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and (reason := pii_reason(sub.id)) is not None:
            return reason
        if isinstance(sub, ast.Attribute) and (reason := pii_reason(sub.attr)) is not None:
            return reason
        if (
            isinstance(sub, ast.Constant)
            and isinstance(sub.value, str)
            and (reason := pii_reason(sub.value)) is not None
        ):
            return reason
        if isinstance(sub, ast.keyword) and sub.arg and (reason := pii_reason(sub.arg)) is not None:
            return reason
    return None


_HTTP_EXCEPTION_NAMES = {"HTTPException", "StarletteHTTPException"}


def _unwrap_walrus(node: ast.expr | None) -> ast.expr | None:
    """Peel a walrus binding so ``(x := value)`` classifies by its ``value`` (one level).

    ``ast.NamedExpr`` wraps the assigned value; the value is what is actually returned/passed, so a
    ``return (x := raw())`` or ``detail=(d := jsonable_encoder(...))`` must classify like the inner
    expression. Only the direct wrapper is peeled — the bound name's own further assignments stay a
    one-level concern of :func:`build_assignment_map`.
    """
    while isinstance(node, ast.NamedExpr):
        node = node.value
    return node


def _unwrap_await(node: ast.expr | None) -> ast.expr | None:
    """Peel ``await``/``*``/walrus wrappers so ``await helper()`` classifies like ``helper()``.

    Async handlers are the FastAPI default, so ``return await helper()`` parses as
    ``Return(Await(Call(...)))``; without unwrapping, an awaited return would be silently skipped. A
    walrus binding (``return (x := raw())``) is peeled to its value in the same pass.
    """
    while isinstance(node, ast.Await | ast.Starred | ast.NamedExpr):
        node = node.value
    return node


def _http_exc_resolver(module_globals: dict[str, Any]) -> Callable[[str], bool]:
    """Build a predicate that recognises HTTPException by name OR by resolved import alias.

    ``from fastapi import HTTPException as ApiError`` binds ``ApiError`` in the module globals to
    the real class, so ``raise ApiError(...)`` is matched by identity even though its name differs.
    """

    def resolves(name: str) -> bool:
        if name in _HTTP_EXCEPTION_NAMES:
            return True
        obj = module_globals.get(name)
        return (
            isinstance(obj, type)
            and bool(_HTTP_EXCEPTION_CLASSES)
            and issubclass(obj, _HTTP_EXCEPTION_CLASSES)
        )

    return resolves


def _is_response_class(obj: Any) -> bool:
    """True iff ``obj`` is a Starlette ``Response`` subclass (``return X(...)`` skips a model)."""
    return (
        isinstance(obj, type)
        and _STARLETTE_RESPONSE is not None
        and issubclass(obj, _STARLETTE_RESPONSE)
    )


def _is_string_literal(node: ast.expr) -> bool:
    """True iff ``node`` is a plain string literal or a ``+`` concatenation of string literals.

    An f-string with NO interpolant (``JoinedStr`` of only ``Constant`` parts) also counts; any
    interpolant (``FormattedValue``) makes it non-literal. This is the ONLY shape the auditor will
    treat as a bounded HTTPException detail — everything else fails closed.
    """
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    if isinstance(node, ast.JoinedStr):
        return all(isinstance(part, ast.Constant) for part in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_string_literal(node.left) and _is_string_literal(node.right)
    return False


_STRUCTURED_DETAIL_NODES = (
    ast.Dict, ast.DictComp, ast.List, ast.ListComp,
    ast.Set, ast.SetComp, ast.Tuple, ast.GeneratorExp,
)

# Builtin collection constructors: ``dict(...)`` / ``list(...)`` etc. build the same unbounded
# structured payloads as the literal forms, but parse as ``ast.Call`` (bare-Name func), so they
# must be recognised alongside ``_STRUCTURED_DETAIL_NODES``. Over-approximate: a shadowed builtin
# is a waivable false-positive, whereas a missed constructor egresses PII (fail closed).
_COLLECTION_CONSTRUCTORS = frozenset({"dict", "list", "set", "tuple", "frozenset"})


# Attribute-form collection constructors (``collections.OrderedDict(...)``, ``defaultdict``,
# ``Counter``) and the common mapping-dump methods / ``json`` parse fns all PRODUCE an unbounded
# structured payload. Recognising them (alongside the bare-Name builtin constructors) closes the
# gap where an attribute/alias/method form serialised a mapping into an error body — or a raw
# return — yet was mis-classified as a waivable scalar. Over-approximate/fail-closed: a shadowed
# name is a waivable false-positive; a missed structure-producer egresses PII.
_COLLECTION_CONSTRUCTOR_ATTRS = frozenset(
    {"dict", "list", "set", "tuple", "frozenset", "OrderedDict", "defaultdict", "Counter"}
)
_MAPPING_DUMP_METHODS = frozenset({"model_dump", "dict", "to_dict", "asdict", "dict_"})
_JSON_PARSE_FUNCS = frozenset({"loads", "load"})
# Structure-producing helper functions that return a JSON-able ``dict``/``list`` (not a string).
# ``jsonable_encoder`` is FastAPI's idiomatic structure encoder — a common accidental-egress
# mistake in an error ``detail`` or a raw return. Recognised in bare-Name, attribute and one-level
# alias forms. Over-approximate/fail-closed: a shadowed name is a waivable false-positive.
_STRUCTURE_PRODUCING_FUNCS = frozenset({"jsonable_encoder"})
_BUILTIN_COLLECTION_TYPES = (dict, list, set, tuple, frozenset)


def _resolve_attribute_object(node: ast.expr | None, module_globals: dict[str, Any]) -> Any:
    """Resolve one-level ``root.attr`` to its object via ``module_globals``, else ``None``.

    Only a single depth on a module/object bound in ``module_globals`` is resolved
    (``responses.JSONResponse`` where ``responses`` is imported). Returns the ``getattr`` result, or
    ``None`` when the root Name is unbound or the attribute is absent. Used to resolve
    attribute-bound aliases (``encode = encoders.jsonable_encoder``; ``RT = responses.JSON``)
    to their target by identity — one level deep, like the rest of the analyser.
    """
    if not (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)):
        return None
    root = module_globals.get(node.value.id)
    if root is None:
        return None
    return getattr(root, node.attr, None)


def _structured_call_reason(
    value: ast.expr | None,
    assignments: dict[str, list[ast.expr]] | None = None,
    module_globals: dict[str, Any] | None = None,
) -> str | None:
    """Short phrase iff ``value`` is a call that PRODUCES a structured mapping/collection payload.

    Fail-closed / over-approximating. Matches:
      * a builtin collection constructor — bare-Name (``dict(...)``) or attribute-form
        (``collections.OrderedDict(...)``, ``defaultdict``/``Counter``);
      * a mapping-dump method call (``x.model_dump()``/``x.dict()``/``x.to_dict()``/``asdict(x)``);
      * a structure encoder (``jsonable_encoder(...)``) in bare-Name or attribute
        (``encoders.jsonable_encoder(...)``) form;
      * ``json.loads(...)`` / ``json.load(...)`` (returns a parsed structure);
      * a bare-Name call whose func resolves — one level via the local assignment map, or via a
        module-level alias in ``module_globals`` — to a builtin collection constructor or a
        structure encoder (``enc = jsonable_encoder``; ``X = dict``).

    Returns ``None`` for anything not provably structure-producing (kept as the opaque residual).
    String-producing calls (``str(...)``, ``.json()``/``.model_dump_json()``, ``.join``/``.format``)
    are deliberately NOT matched — those remain the scalar (waivable-by-human) path.
    """
    if not isinstance(value, ast.Call):
        return None
    func = value.func
    if isinstance(func, ast.Attribute):
        attr = func.attr
        if attr in _COLLECTION_CONSTRUCTOR_ATTRS:
            return f"{attr}(...) constructor"
        if attr in _MAPPING_DUMP_METHODS:
            return f"mapping-dump {attr}(...) call"
        if attr in _STRUCTURE_PRODUCING_FUNCS:
            return f"{attr}(...) structure encoder"
        if (
            attr in _JSON_PARSE_FUNCS
            and isinstance(func.value, ast.Name)
            and func.value.id == "json"
        ):
            return f"json.{attr}(...) parsed structure"
        return None
    if isinstance(func, ast.Name):
        if func.id in _COLLECTION_CONSTRUCTORS:
            return f"{func.id}(...) constructor"
        if func.id in _STRUCTURE_PRODUCING_FUNCS:
            return f"{func.id}(...) structure encoder"
        if assignments is not None:
            for bound in assignments.get(func.id, []):
                if isinstance(bound, ast.Name):
                    if bound.id in _COLLECTION_CONSTRUCTORS:
                        return f"{func.id}(...) collection alias"
                    if bound.id in _STRUCTURE_PRODUCING_FUNCS:
                        return f"{func.id}(...) structure-encoder alias"
                elif isinstance(bound, ast.Attribute):
                    # e.g. ``encode = encoders.jsonable_encoder`` — resolve one level by identity,
                    # and (like the direct attribute form) accept the ``.attr`` name.
                    if bound.attr in _STRUCTURE_PRODUCING_FUNCS:
                        return f"{func.id}(...) structure-encoder alias"
                    if module_globals is not None:
                        resolved = _resolve_attribute_object(bound, module_globals)
                        if getattr(resolved, "__name__", None) in _STRUCTURE_PRODUCING_FUNCS:
                            return f"{func.id}(...) structure-encoder alias"
        if module_globals is not None:
            target = module_globals.get(func.id)
            if target in _BUILTIN_COLLECTION_TYPES:
                return f"{func.id}(...) collection alias"
            if getattr(target, "__name__", None) in _STRUCTURE_PRODUCING_FUNCS:
                return f"{func.id}(...) structure-encoder alias"
    return None


def _classify_http_detail(
    detail: ast.expr | None,
    assignments: dict[str, list[ast.expr]] | None = None,
    module_globals: dict[str, Any] | None = None,
) -> tuple[bool, str] | None:
    """Classify an HTTPException ``detail``: ``None`` if bounded, else ``(structured, reason)``.

    FastAPI serialises ``detail`` into the response body ``{"detail": ...}``. A principled three-way
    split governs classification:

    1. **provably STRING → bounded/scalar.** A plain string literal, an f-string, ``str(...)``,
       string ``%``/``+``/method coercions, or a ``Name`` resolving to one of these. A literal is
       still denylist-checked and returns ``None`` (bounded); any other scalar coercion is flagged
       under a **waivable** key.
    2. **provably-or-strongly STRUCTURED → UNWAIVABLE.** A ``dict``/``list``/``set``/``tuple``
       literal or comprehension, OR a structure-producing call (see :func:`_structured_call_reason`
       — builtin collection constructors incl. attribute/alias forms, mapping-dump methods like
       ``model_dump()``, and ``json.loads``). A route-level string-coercion waiver must never
       silence a newly-introduced PII collection, so these are hard findings.
    3. **genuinely OPAQUE → scalar, waivable-by-human.** A bare ``Name`` of unknown type or an
       unclassifiable ``Call``/``Attribute`` that is neither provably-string nor provably-structured
       cannot be proven PII-free, so it is flagged under the waivable key. This is a DELIBERATE
       fail-closed-with-human-signoff residual (a human must explicitly waive each opaque surface),
       NOT a silent pass.

    When ``assignments`` is given, a ``detail`` that is a local ``Name`` is resolved ONE level
    (``payload = {..}; raise HTTPException(detail=payload)``) so a variable-held structured payload
    is classified structured/unwaivable. Resolution uses UNION (may-reach) semantics — a branch-
    conditional name (``if c: detail = jsonable_encoder(m) else: detail = "safe"``) is STRUCTURED if
    ANY branch is structured-producing, provably-STRING only if EVERY branch is provably-string, and
    OPAQUE otherwise (any-structured dominates; string requires unanimity). ``module_globals`` lets
    a module-level ``X = dict`` alias call resolve to a builtin collection constructor. An
    unresolvable Name keeps the opaque-scalar default.
    """
    if detail is None:
        return None
    detail = _unwrap_walrus(detail) or detail  # ``detail=(d := ...)`` classifies by its value
    _opaque = (
        False,
        "detail is not a plain string literal — an object/expression coerced into the error body "
        "cannot be proven PII-free (fail closed)",
    )

    def classify_one(node: ast.expr) -> tuple[str, tuple[bool, str] | None]:
        if isinstance(node, _STRUCTURED_DETAIL_NODES):
            inner = _expr_pii_reason(node)
            base = "detail is a structured dict/list/set/tuple serialised into the error body"
            return ("structured", (True, f"{base} ({inner})" if inner is not None else base))
        struct_phrase = _structured_call_reason(node, assignments, module_globals)
        if struct_phrase is not None:
            inner = _expr_pii_reason(node)
            base = f"detail is a structured {struct_phrase} serialised into the error body"
            return ("structured", (True, f"{base} ({inner})" if inner is not None else base))
        if _is_string_literal(node):
            inner = _expr_pii_reason(node)
            return ("string", None if inner is None else (False, inner))
        return ("opaque", _opaque)

    if assignments is not None and isinstance(detail, ast.Name):
        bounds = assignments.get(detail.id, [])
        nodes: list[ast.expr] = [_unwrap_await(b) or b for b in bounds] if bounds else [detail]
    else:
        nodes = [detail]

    string_payloads: list[tuple[bool, str] | None] = []
    all_string = True
    for node in nodes:
        category, payload = classify_one(node)
        if category == "structured":
            return payload  # any structured branch dominates (unwaivable)
        if category == "string":
            string_payloads.append(payload)
        else:
            all_string = False
    if all_string:
        for payload in string_payloads:
            if payload is not None:
                return payload  # a string literal carrying a denylisted PII token
        return None  # every branch is a bounded, PII-free string
    return _opaque  # some branch is opaque (none structured) → scalar, waivable-by-human


def _http_detail_findings(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    resolves_http_exc: Callable[[str], bool],
    assignments: dict[str, list[ast.expr]] | None = None,
    module_globals: dict[str, Any] | None = None,
) -> list[tuple[bool, str]]:
    """``(structured, reason)`` per unbounded-detail ``raise HTTPException(...)`` in ``func``.

    Only the function's own body is scanned (nested scopes are excluded by ``_iter_raises``).
    ``structured=True`` marks an unwaivable hard finding (see :func:`_classify_http_detail`). When
    ``assignments`` is given, a variable-held ``detail`` Name is resolved one level before classify;
    ``module_globals`` lets a module-level collection alias (``X = dict``) resolve to a constructor.
    """
    findings: list[tuple[bool, str]] = []
    for raised in _iter_raises(func):
        call = raised.exc
        if not isinstance(call, ast.Call):
            continue
        name = _call_name(call.func)
        if name is None or not resolves_http_exc(name):
            continue
        detail = next((kw.value for kw in call.keywords if kw.arg == "detail"), None)
        if detail is None and len(call.args) >= 2:
            detail = call.args[1]
        result = _classify_http_detail(detail, assignments, module_globals)
        if result is not None:
            findings.append(result)
    return findings


# Suffix keys for raised-HTTPException findings. The scalar suffix stays waivable (the 3 tracked
# #96 src sites use it); the structured suffix is deliberately NOT in ``_DEFAULT_WAIVERS`` so a
# dict/list/set/tuple detail can never be silenced by a route-level string-coercion waiver.
_HTTP_DETAIL_SUFFIX = "<raise HTTPException detail>"
_HTTP_STRUCTURED_SUFFIX = "<raise HTTPException structured detail>"


def _raise_finding(structured: bool, note: str) -> tuple[str, str, bool]:
    """Map a shape-classified raised-detail finding to ``(suffix, note, unwaivable)``."""
    if structured:
        return (_HTTP_STRUCTURED_SUFFIX, note, True)
    return (_HTTP_DETAIL_SUFFIX, note, False)


def _resolve_helper_func(
    target: Any,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Parse a resolved callable's source and return its top-level function node (or ``None``)."""
    try:
        htree = ast.parse(textwrap.dedent(inspect.getsource(target)))
    except (OSError, TypeError, SyntaxError):
        return None
    for node in htree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            return node
    return None


def _resolve_callable_func(
    obj: Any,
) -> list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, dict[str, Any]]]:
    """Return ``(FunctionDef, module_globals)`` pairs for every method FastAPI actually executes.

    - a plain function/coroutine/method → audit ``obj`` itself;
    - a CLASS used directly as a dependency (``Depends(Guard)``) → FastAPI INSTANTIATES it, which
      runs (in order) a custom ``__new__``, then ``__init__``; a user ``__call__`` and a user
      metaclass ``__call__`` may also run. All user-defined ones are audited; inherited
      ``object``/``type`` slot-wrappers are skipped so a plain class does not false-positive;
    - an INSTANCE callable (``Depends(Guard())``) → audit ``type(obj).__call__``.

    Returning a LIST lets a class contribute more than one method; each pair carries its OWN
    ``__globals__``. This lets idiomatic FastAPI class-based dependencies be audited, not silently
    skipped (their ``ClassDef`` has no top-level FunctionDef).
    """
    candidates: list[Any] = []
    if inspect.isfunction(obj) or inspect.iscoroutinefunction(obj) or inspect.ismethod(obj):
        candidates.append(obj)
    elif isinstance(obj, type):
        # FastAPI instantiates a class dependency: ``__new__``/``__init__`` run on construction, and
        # a user ``__call__`` may run too. Only USER-defined members (present in the class's own MRO
        # ``__dict__``, not inherited ``object`` slot-wrappers) are real functions we can audit.
        for dunder in ("__new__", "__init__", "__call__"):
            member = _user_defined_member(obj, dunder)
            if member is not None:
                candidates.append(member)
        # A user metaclass ``__call__`` (not the ``type.__call__`` slot) also runs on instantiation.
        meta = type(obj)
        if meta is not type:
            meta_call = _user_defined_member(meta, "__call__")
            if meta_call is not None:
                candidates.append(meta_call)
    else:
        member = _user_defined_member(type(obj), "__call__")
        if member is not None:
            candidates.append(member)

    resolved: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, dict[str, Any]]] = []
    for candidate in candidates:
        if not (
            inspect.isfunction(candidate)
            or inspect.iscoroutinefunction(candidate)
            or inspect.ismethod(candidate)
        ):
            continue
        func = _resolve_helper_func(candidate)
        if func is not None:
            resolved.append((func, getattr(candidate, "__globals__", {}) or {}))
    return resolved


def _user_defined_member(cls: type, name: str) -> Any:
    """Return a user-defined ``cls.name`` method walking the MRO, or ``None`` for slots/builtins.

    Skips the inherited ``object``/``type`` slot-wrappers so a plain class with a default
    constructor is not treated as an auditable (and potentially false-positive) surface. Implicit
    ``staticmethod``/``classmethod`` wrappers (notably ``__new__``) are unwrapped to their
    underlying function so they can be sourced and audited.
    """
    for base in getattr(cls, "__mro__", (cls,)):
        if base is object or base is type:
            continue
        member = base.__dict__.get(name)
        if member is not None:
            if isinstance(member, staticmethod | classmethod):
                member = member.__func__
            return member if (
                inspect.isfunction(member) or inspect.iscoroutinefunction(member)
            ) else None
    return None


def _iter_target_names(target: ast.expr) -> Iterator[ast.Name]:
    """Yield every ``ast.Name`` bound under a (possibly nested) Tuple/List/Starred assign target."""
    if isinstance(target, ast.Name):
        yield target
    elif isinstance(target, ast.Starred):
        yield from _iter_target_names(target.value)
    elif isinstance(target, ast.Tuple | ast.List):
        for elt in target.elts:
            yield from _iter_target_names(elt)


def build_assignment_map(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> dict[str, list[ast.expr]]:
    """Map each simple local name to EVERY value that MAY be assigned to it in ``func`` (may-reach).

    Unlike a last-write-wins map, this records ALL assignments to each name in source order, so a
    branch-conditional value (``if c: x = raw() else: x = safe()``) is not lost — every consumer
    resolves a Name with UNION semantics (a raw/structured value reachable on ANY branch is
    flagged). This deliberately over-approximates straight-line reassignment
    (``x = raw(); x = safe(); return x`` may flag the overwritten raw value) — an accepted,
    waivable false-positive under the fail-closed philosophy.

    Nested ``def``/``async def``/``lambda`` scopes are skipped so an inner-scope assignment cannot
    masquerade as the outer local. Walrus (``:=`` / ``ast.NamedExpr``) targets reached anywhere in
    the body (an ``if``/``while`` test, comprehension, boolop or call arg) are recorded too.
    Tuple/list UNPACKING is captured: a statically pairable ``(a, b) = (x, y)`` (same-length literal
    Tuple/List, no ``*`` on either side) binds each name to its element (recursing for nesting);
    anything unpairable (non-literal RHS, arity mismatch or any ``ast.Starred``) FAILS CLOSED —
    every name under the target is bound to the WHOLE RHS so it inherits the RHS's raw/structured
    classification. Shared by the handler, helper and dependency scopes so all three use identical
    single-level, may-reach resolution semantics.
    """
    assignments: dict[str, list[ast.expr]] = {}

    def record(name: str, value: ast.expr) -> None:
        assignments.setdefault(name, []).append(value)

    def record_target(target: ast.expr, value: ast.expr) -> None:
        if isinstance(target, ast.Name):
            record(target.id, value)
            return
        if isinstance(target, ast.Starred):
            record_target(target.value, value)
            return
        if isinstance(target, ast.Tuple | ast.List):
            pairable = (
                isinstance(value, ast.Tuple | ast.List)
                and len(target.elts) == len(value.elts)
                and not any(isinstance(e, ast.Starred) for e in target.elts)
                and not any(isinstance(e, ast.Starred) for e in value.elts)
            )
            if pairable:
                assert isinstance(value, ast.Tuple | ast.List)
                for t_elt, v_elt in zip(target.elts, value.elts, strict=True):
                    record_target(t_elt, v_elt)
            else:
                # Fail closed: bind every unpacked name to the whole (unknowable) RHS.
                for name_node in _iter_target_names(target):
                    record(name_node.id, value)

    def collect(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
                continue
            if isinstance(child, ast.Assign) and child.value is not None:
                for target in child.targets:
                    record_target(target, child.value)
            elif (
                isinstance(child, ast.AnnAssign | ast.NamedExpr)
                and child.value is not None
                and isinstance(child.target, ast.Name)
            ):
                record(child.target.id, child.value)
            collect(child)

    collect(func)
    return assignments


_RAW_RESPONSE_NAMES = frozenset(
    {
        "Response", "JSONResponse", "ORJSONResponse", "UJSONResponse",
        "PlainTextResponse", "HTMLResponse", "StreamingResponse", "FileResponse",
        "RedirectResponse",
    }
)


def _resolve_response_alias(
    name: str,
    assignments: dict[str, list[ast.expr]] | None,
    module_globals: dict[str, Any],
) -> type | None:
    """Resolve a bare Name to a Response SUBCLASS by identity (direct global, or one-level alias).

    ``return RT(content=...)`` where ``RT`` is a module-level global bound to a Response subclass,
    OR a local alias (``RT = JSONResponse`` resolved one level via the assignment map), emits a raw
    Response that bypasses the declared response_model. The match is by IDENTITY
    (``issubclass(obj, starlette Response)`` via :func:`_is_response_class`), so ANY alias of a
    Response subclass is caught — not just the known ``_RAW_RESPONSE_NAMES`` strings. Returns the
    resolved Response class, or ``None`` for a non-Response name (kept model-coerced / opaque).
    """
    obj = module_globals.get(name)
    if _is_response_class(obj):
        return obj
    if assignments is not None:
        for bound in assignments.get(name, []):
            if isinstance(bound, ast.Name):
                aliased = module_globals.get(bound.id)
                if _is_response_class(aliased):
                    return aliased
            elif isinstance(bound, ast.Attribute):
                # e.g. ``RT = responses.JSONResponse`` — resolve one level by identity.
                aliased = _resolve_attribute_object(bound, module_globals)
                if _is_response_class(aliased):
                    return aliased
    return None


def _direct_raw_literal(value: ast.expr | None, module_globals: dict[str, Any]) -> str | None:
    """Reason iff ``value`` is *directly* a raw dict/list/set literal or a Response construction.

    A bare-name call is also flagged when the name resolves via module globals to a Response
    subclass (``X = JSONResponse; return X({...})``). ``value`` is assumed already await-unwrapped.
    """
    if isinstance(value, ast.Dict | ast.DictComp):
        return "returns a raw dict — declared response_model not enforced"
    if isinstance(value, ast.List | ast.ListComp | ast.Set | ast.SetComp):
        return "returns a raw list/set — declared response_model not enforced"
    struct_phrase = _structured_call_reason(value, None, module_globals)
    if struct_phrase is not None:
        return f"returns a raw {struct_phrase} — declared response_model not enforced"
    if isinstance(value, ast.Call):
        name = _call_name(value.func)
        if name in _RAW_RESPONSE_NAMES:
            return f"returns a raw {name} — declared response_model not enforced"
        if isinstance(value.func, ast.Name) and _is_response_class(
            module_globals.get(value.func.id)
        ):
            resolved = module_globals[value.func.id]
            return (
                f"returns a raw {resolved.__name__} via alias {value.func.id} — "
                "declared response_model not enforced"
            )
    return None


def _classify_raw_return(
    value: ast.expr | None,
    assignments: dict[str, list[ast.expr]],
    module_globals: dict[str, Any],
    _seen: set[str] | None = None,
) -> str | None:
    """Reason iff a return value is a (resolvably) raw dict/list/Response, using a local assign map.

    Peels ``await``, evaluates both ternary branches and all BoolOp operands, and resolves a local
    ``Name`` through ``assignments`` with UNION (may-reach) semantics — a Name that MAY be bound to
    a raw value on ANY branch is flagged. A literal ``ast.Tuple``/``ast.List`` return is inspected
    element-wise: a helper returning ``(JSONResponse({...}), 200)`` hides a raw element from an
    unpacking caller, and the analyser cannot know which unpack position was selected, so it fails
    closed on ANY raw element (one level — a tuple/list element that is itself another helper CALL
    is NOT descended). A ``set[str]`` name guard prevents infinite recursion on cyclic assignments
    (``x = y; y = x``). This is the same single-level, local resolution the handler applies to its
    own returns — now available to helper and dependency bodies too. Does NOT delegate into further
    helper CALLS (that stays one level deep).
    """
    _seen = _seen if _seen is not None else set()
    value = _unwrap_await(value)
    reason = _direct_raw_literal(value, module_globals)
    if reason is not None:
        return reason
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
        aliased = _resolve_response_alias(value.func.id, assignments, module_globals)
        if aliased is not None:
            return (
                f"returns a raw {aliased.__name__} via alias {value.func.id} — "
                "declared response_model not enforced"
            )
    if isinstance(value, ast.IfExp):
        return _classify_raw_return(value.body, assignments, module_globals, _seen) or (
            _classify_raw_return(value.orelse, assignments, module_globals, _seen)
        )
    if isinstance(value, ast.BoolOp):
        for operand in value.values:
            if (reason := _classify_raw_return(operand, assignments, module_globals, _seen)):
                return reason
        return None
    if isinstance(value, ast.Tuple | ast.List):
        # A directly-returned literal tuple/list hides a raw element from an unpacking caller; fail
        # closed on ANY raw element (an element that is itself a further helper CALL is not chased).
        for elt in value.elts:
            if (reason := _classify_raw_return(elt, assignments, module_globals, _seen)):
                return reason
        return None
    if isinstance(value, ast.Name) and value.id not in _seen:
        _seen.add(value.id)
        for bound in assignments.get(value.id, []):
            if (reason := _classify_raw_return(bound, assignments, module_globals, _seen)):
                return reason
    return None


def _iter_dict_operands(value: ast.expr | None) -> list[ast.Dict]:
    """Every dict-literal reachable as a return value, through ``await``/ternary/BoolOp nesting.

    ``return {..}`` yields one dict; ``return a if x else b`` yields each dict branch; ``return
    cond and {..}`` yields each dict operand. This lets the contract audit see dicts hidden behind
    ordinary conditional-return code, not just a bare top-level literal.
    """
    value = _unwrap_await(value)
    if isinstance(value, ast.Dict):
        return [value]
    if isinstance(value, ast.IfExp):
        return _iter_dict_operands(value.body) + _iter_dict_operands(value.orelse)
    if isinstance(value, ast.BoolOp):
        out: list[ast.Dict] = []
        for operand in value.values:
            out.extend(_iter_dict_operands(operand))
        return out
    return []


def _iter_annotation_metadata(annotation: Any) -> list[Any]:
    """Collect EVERY ``Annotated[...]`` metadata object anywhere in a (possibly nested) annotation.

    Walks into ``list``/``set``/``tuple``/``dict`` (keys AND values), ``Optional``/``Union`` and any
    depth of nesting, following each ``Annotated`` node's wrapped type too. This lets the serializer
    inspection reach a ``PlainSerializer``/``WrapSerializer``/``SerializeAsAny`` buried inside a
    container or union element — not just the top-level ``FieldInfo.metadata``.
    """
    found: list[Any] = []
    seen: set[int] = set()
    stack: list[Any] = [annotation]
    while stack:
        node = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        # PEP 695 ``type X = Annotated[...]`` hides its shape behind a TypeAliasType; unwrap the
        # aliased value so a serializer/PII marker buried inside the alias is still reached.
        if type(node).__name__ == "TypeAliasType":
            value = getattr(node, "__value__", None)
            if value is not None:
                stack.append(value)
                continue
        meta = getattr(node, "__metadata__", None)
        if meta is not None:
            found.extend(meta)
            wrapped = getattr(node, "__origin__", None)
            if wrapped is not None:
                stack.append(wrapped)
            continue
        stack.extend(get_args(node))
    return found


def emitted_field_keys(name: str, info: FieldInfo) -> set[str]:
    """Every name a field could be EMITTED/ACCEPTED as (attribute + all aliases) — fail-closed."""
    names = {name}
    for alias in (info.alias, info.serialization_alias):
        if isinstance(alias, str):
            names.add(alias)
    validation_alias = info.validation_alias
    if isinstance(validation_alias, str):
        names.add(validation_alias)
    elif isinstance(validation_alias, AliasChoices):
        for choice in validation_alias.choices:
            if isinstance(choice, str):
                names.add(choice)
    return names


# --------------------------------------------------------------------------------------
# Egress inventory: the notification dict payload + the tracked open-mapping waivers.
# --------------------------------------------------------------------------------------
@dataclass(frozen=True)
class DictReturnContract:
    """A function whose ``return {...}`` dict literal is a payload that crosses the boundary."""

    name: str
    path: str
    symbol: str
    allowed: frozenset[str]


@dataclass(frozen=True)
class Violation:
    """One egress-audit failure. ``kind`` is ``pii``, ``unlisted``, ``dynamic`` or ``error``."""

    target: str
    kind: str
    message: str


# Tracked waivers for genuinely-reviewed UNBOUNDED egress surfaces that live in src/** (which this
# task must not edit). Each MUST carry a tracking issue; an unkeyed open mapping anywhere else fails
# closed. Keys are ``Model.field`` / ``Model.<model_config ...>`` / ``"METHOD /path"``. These
# free-form mappings + raw-dict endpoints are tracked by **#91** (bound/redact externally-returned
# free-form mappings & raw-dict endpoints); non-literal HTTPException error details are tracked by
# **#96**; opaque finding-ID hardening is the separate **#78**.
_DEFAULT_WAIVERS: dict[str, str] = {
    # Free-form ``dict[str, ...]`` mapping fields on egress read models whose KEY TYPE stays open
    # (so the static type audit still flags them) but whose CONTENTS are DEFAULT-REDACTED at the API
    # response boundary. ``ModuleRunResult.extra`` is heterogeneous internal module analysis output
    # (nested dicts + lists + scalars across every module) and may carry customer-derived PII in any
    # leaf OR mapping key, so the run endpoint recursively sanitizes the WHOLE ``extra`` tree via
    # ``shared.contracts.redact_tree`` before egress (default-DENY): EVERY str/bytes/object leaf
    # becomes ``[redacted]`` and every mapping KEY is redacted to a positional placeholder UNLESS it
    # is an exact member of the platform/module schema allow-list ``PLATFORM_SAFE_STRUCTURAL_KEYS``
    # (so a customer-/workload-derived key like ``extra.drift.<scope>`` is redacted) — only
    # numbers/bools/None/enums pass through.
    # ``ImpactResult.states`` maps graph node ids (not enumerable) to a bounded ``HealthState`` enum
    # value — the same ids already egress via ``down``/``degraded``.
    # ``ResourceNode.tags`` is customer-controlled Azure tag data: the API-egress projection (GET
    # estate/graph and the run-result carrier) runs each node through ``redact_node_tags``, which
    # DEFAULT-REDACTS (default-DENY) — every tag VALUE becomes ``[redacted]`` and every tag KEY
    # becomes a positional placeholder unless its key is in the (currently empty)
    # ``PLATFORM_SAFE_TAG_KEYS`` platform-owned allow-list, so a PII key (e.g. ``a@contoso.com``,
    # or a "structurally valid" ``123-45-6789``) can never egress verbatim. The stored estate and
    # the in-boundary copy used for internal module classification / impact analysis keep the raw
    # keys and values. Each remains #91 because the RESPONSE MODEL TYPE (open key type) still reads
    # as unbounded to the static audit; the handler-bypass detector additionally requires these
    # routes to route EVERY returned redaction-required value through a reviewed egress projection
    # (see ``_REDACTION_REQUIRED_MODELS`` / ``_return_fully_sanitized``), so a NEW raw endpoint,
    # partially-sanitized collection, or decoy wrapper returning an unsanitized
    # ``ResourceNode``/``ModuleRunResult`` FAILS (unwaivably, even under a route-level unbounded
    # waiver) rather than riding this model-wide waiver. The metrics label maps are separately
    # bounded on egress by the ``MetricsSnapshotView`` projection served at ``/api/metrics``
    # (allow-listed keys + redacted values) so ``MetricSample.labels``/``DurationSample.labels`` no
    # longer need a waiver.
    "ModuleRunResult.extra": "#91",
    "ImpactResult.states": "#91",
    "ResourceNode.tags": "#91",
    # ``ScaleTrigger.metadata`` is KEDA scaler config (scaler-specific keys, str values) surfaced
    # transitively by typing ``GET /api/modules`` as ``list[ModuleManifest]``. It is infra config
    # consumed by iac-deploy, not customer data; the value type is already bounded to ``str`` and
    # the keys are scaler-defined (not enumerable). Tracked by #91 as a tightly-scoped field waiver
    # (replaces the former endpoint-level ``GET /api/modules`` waiver — a precision improvement).
    "ScaleTrigger.metadata": "#91",
}

_DICT_CONTRACTS: tuple[DictReturnContract, ...] = (
    DictReturnContract(
        "alerts._notification_payload",
        "src/modules/alerts/module.py",
        "_notification_payload",
        frozenset({"findingId", "severity", "channel", "runbook"}),
    ),
)


# --------------------------------------------------------------------------------------
# The recursive auditor.
# --------------------------------------------------------------------------------------
class Auditor:
    """Accumulates violations + tracked waivers while walking the egress surface graph."""

    def __init__(self, waivers: dict[str, str]) -> None:
        self.waivers = waivers
        self.visited: set[type] = set()
        self.violations: list[Violation] = []
        self.waived: list[tuple[str, str, str]] = []  # (key, issue, note)

    def _flag_unbounded(self, key: str, note: str) -> None:
        """Record an unbounded egress surface as a tracked waiver, or a fail-closed violation."""
        issue = self.waivers.get(key)
        if issue is not None:
            self.waived.append((key, issue, note))
        else:
            self.violations.append(
                Violation(
                    key,
                    "dynamic",
                    f"{note} — cannot be proven PII-free; bound it to a typed schema or add a "
                    "tracked waiver (key -> issue) after review",
                )
            )

    def _check_field_annotation(self, owner: str, name: str, annotation: Any) -> None:
        """Flag an unbounded mapping / recurse referenced models for one field's annotation."""
        reason = unbounded_egress_reason(annotation)
        if reason is not None:
            self._flag_unbounded(f"{owner}.{name}", reason)
        self.audit_annotation(annotation)

    def _check_annotated_serializers(self, owner: str, name: str, info: FieldInfo) -> None:
        """Inspect ``Annotated`` serializer metadata that can emit an unbounded/polymorphic shape.

        ``PlainSerializer``/``WrapSerializer`` re-shape a field's output exactly like a
        ``@field_serializer`` (their emitted keys are not statically knowable unless a bounded
        ``return_type`` model is declared), and ``SerializeAsAny`` lets a subclass instance
        serialise fields the declared model would otherwise filter. Both are fail-closed surfaces.
        Metadata is inspected at the TOP level (``FieldInfo.metadata``) AND anywhere it is nested
        inside a container/union element (``list[Annotated[..., PlainSerializer(...)]]``, etc.).
        """
        key = f"{owner}.{name}"
        metas = list(info.metadata or [])
        metas.extend(_iter_annotation_metadata(info.annotation))
        seen: set[int] = set()
        for meta in metas:
            if id(meta) in seen:
                continue
            seen.add(id(meta))
            self._inspect_serializer_meta(key, meta)

    def _inspect_serializer_meta(self, key: str, meta: Any) -> None:
        """Flag one ``Annotated`` metadata object if it is an unbounded/polymorphic serializer."""
        cls_name = type(meta).__name__
        if cls_name == "SerializeAsAny":
            self._flag_unbounded(
                key,
                "field is SerializeAsAny — a subclass instance can serialise extra fields "
                "past the declared model (polymorphic egress)",
            )
            return
        is_functional = isinstance(meta, PlainSerializer | WrapSerializer) or cls_name in {
            "PlainSerializer", "WrapSerializer",
            "FunctionPlainSerializer", "FunctionWrapSerializer",
        }
        if is_functional:
            rt = getattr(meta, "return_type", PydanticUndefined)
            if rt is PydanticUndefined or rt is None or rt is Any or rt in (dict, object):
                self._flag_unbounded(
                    key,
                    "field has a functional serializer with an unbounded return_type — "
                    "emitted shape is statically unknown",
                )
            elif (reason := unbounded_egress_reason(rt)) is not None:
                self._flag_unbounded(
                    key,
                    f"field has a functional serializer whose return_type is unbounded — {reason}",
                )
            else:
                # A declared bounded return model: recurse into it rather than blanket-flag.
                self.audit_annotation(rt)

    def audit_annotation(self, annotation: Any) -> None:
        """Recurse into every BaseModel / dataclass / TypedDict reachable from ``annotation``."""
        for referenced in iter_referenced_types(annotation):
            if isinstance(referenced, type) and issubclass(referenced, BaseModel):
                self.audit_model(referenced)
            elif is_typeddict(referenced):
                self.audit_typeddict(referenced)
            elif dataclasses.is_dataclass(referenced) and isinstance(referenced, type):
                self.audit_dataclass(referenced)

    def audit_model(self, model: type[BaseModel]) -> None:
        """Recursively audit a Pydantic egress model (aliases, inheritance, computed, mappings)."""
        if model in self.visited:
            return
        self.visited.add(model)

        config = getattr(model, "model_config", {}) or {}
        if config.get("extra") == "allow":
            self._flag_unbounded(
                f"{model.__name__}.<model_config extra=allow>",
                "response model permits arbitrary extra fields (unbounded emitted keys)",
            )

        decorators = getattr(model, "__pydantic_decorators__", None)
        if decorators is not None:
            if getattr(decorators, "model_serializers", None):
                self._flag_unbounded(
                    f"{model.__name__}.<model_serializer>",
                    "model has a custom @model_serializer — emitted keys are statically unknown",
                )
            # A @field_serializer can emit an arbitrary shape/key for the field it decorates, so its
            # output is not statically knowable — flag every decorated field as unbounded egress.
            for dec in (getattr(decorators, "field_serializers", None) or {}).values():
                info = getattr(dec, "info", None)
                fields = getattr(info, "fields", None) or ()
                for fname in fields:
                    self._flag_unbounded(
                        f"{model.__name__}.{fname}",
                        "field has a custom @field_serializer — emitted shape is statically "
                        "unknown",
                    )

        for name, info in model.model_fields.items():
            for key in emitted_field_keys(name, info):
                reason = pii_reason(key)
                if reason is not None:
                    detail = reason if key == name else f"{reason} (via alias of '{name}')"
                    self.violations.append(Violation(f"{model.__name__}.{key}", "pii", detail))
            self._check_mapping_key_pii(f"{model.__name__}.{name}", info.annotation)
            self._check_field_annotation(model.__name__, name, info.annotation)
            self._check_annotated_serializers(model.__name__, name, info)

        for name, computed in model.model_computed_fields.items():
            alias = getattr(computed, "alias", None)
            key = alias if isinstance(alias, str) and alias else name
            reason = pii_reason(key)
            if reason is not None:
                self.violations.append(
                    Violation(f"{model.__name__}.{key}", "pii", f"{reason} (computed field)")
                )
            return_type = getattr(computed, "return_type", None)
            if return_type is None:
                # An unannotated computed field can emit an arbitrary value — fail closed.
                self._flag_unbounded(
                    f"{model.__name__}.{key}",
                    "computed field has no resolved return type — emitted value is unbounded",
                )
            else:
                self._check_mapping_key_pii(f"{model.__name__}.{key}", return_type)
                self._check_field_annotation(model.__name__, key, return_type)

    def _check_mapping_key_pii(self, owner: str, annotation: Any) -> None:
        """Flag a bounded-key mapping whose enumerable keys are themselves PII-named."""
        for member in _iter_union_members(annotation):
            origin = get_origin(member) or member
            if isinstance(origin, type) and issubclass(origin, _MAPPING_TYPES):
                args = get_args(member)
                if args and (reason := _mapping_key_pii_reason(args[0])) is not None:
                    self.violations.append(
                        Violation(owner, "pii", f"{reason} (mapping key)")
                    )

    def audit_dataclass(self, dc: type) -> None:
        """Audit a dataclass reachable from an egress model (field names + nested types)."""
        if dc in self.visited:
            return
        self.visited.add(dc)
        hints = self._resolve_hints(dc)
        for name, hint in hints.items():
            reason = pii_reason(name)
            if reason is not None:
                self.violations.append(Violation(f"{dc.__name__}.{name}", "pii", reason))
            self._check_field_annotation(dc.__name__, name, hint)

    def audit_typeddict(self, td: Any) -> None:
        """Audit a TypedDict reachable from an egress model (key names + nested value types)."""
        if td in self.visited:
            return
        self.visited.add(td)
        hints = self._resolve_hints(td)
        for name, hint in hints.items():
            reason = pii_reason(name)
            if reason is not None:
                self.violations.append(Violation(f"{td.__name__}.{name}", "pii", reason))
            self._check_field_annotation(td.__name__, name, hint)

    @staticmethod
    def _resolve_hints(obj: Any) -> dict[str, Any]:
        """Resolve annotations to real types; fall back to raw ``__annotations__`` on failure."""
        try:
            return typing.get_type_hints(obj, include_extras=True)
        except Exception:  # noqa: BLE001 — unresolved hints must still be walked, not skipped.
            return dict(getattr(obj, "__annotations__", {}))

    def audit_app(self, app: Any) -> None:
        """Derive egress surfaces from EVERY route, recursing mounts/sub-apps (self-updating).

        Fail-closed enumeration: FastAPI ``APIRoute``s are audited via their response_model; raw
        Starlette ``Route``s (``add_route``), ``WebSocketRoute``s, and any unrecognised
        body-emitting route type declare no bounded schema and are flagged (waivable). ``Mount`` /
        ``Host`` routers and mounted sub-applications are recursed so nothing nested is skipped.
        """
        self._audit_routes(app.routes, "")

    def _audit_routes(self, routes: Any, prefix: str) -> None:
        """Walk a route list recursively; audit/flag every body-emitting route (fail-closed)."""
        from fastapi.routing import APIRoute
        from starlette.routing import Host, Mount, Route, WebSocketRoute

        for route in routes:
            if isinstance(route, APIRoute):
                self._audit_api_route(route, prefix)
                continue
            if isinstance(route, Mount):
                mount_path = prefix + (getattr(route, "path", "") or "")
                sub_routes = getattr(getattr(route, "app", None), "routes", None)
                if sub_routes is None:
                    sub_routes = getattr(route, "routes", None)
                if sub_routes is not None:
                    self._audit_routes(sub_routes, mount_path)
                else:
                    self._flag_unbounded(
                        f"MOUNT {mount_path}",
                        "mounted sub-application exposes no introspectable routes "
                        "(unbounded egress)",
                    )
                continue
            if isinstance(route, Host):
                self._audit_routes(getattr(route, "routes", None) or [], prefix)
                continue
            # FastAPI >=0.140 represents include_router() as an ``_IncludedRouter`` wrapper holding
            # the child router + its mount prefix (rather than copied APIRoutes) — recurse into it
            # so included/nested routers are never silently skipped.
            included = getattr(route, "original_router", None)
            if included is not None and hasattr(included, "routes"):
                ctx = getattr(route, "include_context", None)
                sub_prefix = (getattr(ctx, "prefix", "") or "") if ctx is not None else ""
                self._audit_routes(included.routes, prefix + sub_prefix)
                continue
            if self._is_framework_route(route):
                # Framework-owned schema/docs routes (openapi.json, /docs, /redoc) are not
                # application egress surfaces — they serve the fixed OpenAPI schema / static HTML.
                continue
            if isinstance(route, WebSocketRoute):
                path = prefix + (getattr(route, "path", "") or "")
                self._flag_unbounded(
                    f"WS {path}",
                    "websocket route bypasses response_model entirely (unbounded egress)",
                )
                continue
            if isinstance(route, Route):
                path = prefix + (getattr(route, "path", "") or "")
                methods = ",".join(sorted(getattr(route, "methods", None) or [])) or "ANY"
                self._flag_unbounded(
                    f"{methods} {path}",
                    "raw Starlette route declares no response_model (raw dict/Response egress)",
                )
                continue
            if hasattr(route, "endpoint") or hasattr(route, "app") or hasattr(route, "path"):
                path = prefix + (getattr(route, "path", "") or "")
                self._flag_unbounded(
                    f"ROUTE {path}",
                    f"unrecognised body-emitting route type {type(route).__name__} — "
                    "cannot prove bounded egress",
                )

    @staticmethod
    def _is_framework_route(route: Any) -> bool:
        """True iff ``route``'s handler is defined in FastAPI/Starlette itself (not app egress)."""
        endpoint = getattr(route, "endpoint", None)
        if endpoint is None:
            return False
        module = inspect.getmodule(endpoint)
        top = (getattr(module, "__name__", "") or "").split(".", 1)[0]
        return top in {"fastapi", "starlette"}

    @staticmethod
    def _endpoint_return_requires_redaction(endpoint: Any) -> bool:
        """Whether a ``response_model=None`` route must run the fail-closed redaction check.

        Resolve the handler's return annotation and decide (FIX 4, issue #91 R4):
        * references a redaction-required model (``ResourceNode``/``ModuleRunResult``) → True;
        * a ``Response``/``JSONResponse``/... subclass (an opaque already-serialized body that
          bypasses ``response_model``) → True (fail closed — its payload is not statically
          knowable);
        * unresolvable / absent / raw-or-unbounded (bare ``dict``/``list``, ``Any``, ...) → True
          (fail closed — we cannot prove the payload is free of a redaction-required value);
        * a resolvable, bounded, non-redaction annotation → False (no redaction check needed).
        """
        try:
            hints = typing.get_type_hints(endpoint)
        except Exception:  # noqa: BLE001 — unresolved return hint must fail closed, not skip.
            return True
        if "return" not in hints:
            return True
        ann = hints["return"]
        if _REDACTION_REQUIRED_MODELS & _referenced_model_names(ann):
            return True
        # A Response/JSONResponse/StreamingResponse return hands FastAPI an ALREADY-SERIALIZED body
        # that bypasses response_model; its payload is opaque to static type analysis, so it cannot
        # be proven free of a redaction-required value → fail closed (issue #91 R5). ``Any``/
        # ``object`` are already caught below by ``unbounded_egress_reason``.
        for member in _iter_union_members(ann):
            if isinstance(member, type) and any(
                base.__name__ == "Response"
                and (getattr(base, "__module__", "") or "").split(".", 1)[0]
                in {"starlette", "fastapi"}
                for base in getattr(member, "__mro__", ())
            ):
                return True
        return unbounded_egress_reason(ann) is not None

    def _audit_api_route(self, route: Any, prefix: str = "") -> None:
        """Audit one FastAPI ``APIRoute``: response_model boundedness + handler-bypass check."""
        methods = ",".join(sorted(route.methods or []))
        label = f"{methods} {prefix}{route.path}"

        annotations: list[Any] = []
        if route.response_model is not None:
            annotations.append(route.response_model)
        for spec in (route.responses or {}).values():
            model = spec.get("model") if isinstance(spec, dict) else None
            if model is not None:
                annotations.append(model)

        if not annotations:
            self._flag_unbounded(
                label, "route declares no response_model (raw dict/Response egress)"
            )
            # FIX 4 (issue #91 R4): a ``response_model=None`` route still egresses whatever the
            # handler returns. The unbounded flag above is route-waivable, but a raw
            # ResourceNode/ModuleRunResult egress must NEVER ride a waiver. Derive the redaction
            # requirement from the handler's actual return annotation; an unknown/raw/Any return is
            # not provably free of a redaction-required payload → fail closed (require redaction).
            if self._endpoint_return_requires_redaction(route.endpoint):
                for suffix, note, _unwaivable in self._handler_bypasses_model(
                    route.endpoint, require_redaction=True, redaction_only=True
                ):
                    key = f"{label} {suffix}" if suffix else label
                    self.violations.append(Violation(key, "dynamic", note))
            return

        route_unbounded = False
        for annotation in annotations:
            reason = unbounded_egress_reason(annotation)
            if reason is not None:
                self._flag_unbounded(label, f"route response_model is unbounded — {reason}")
                route_unbounded = True
            self.audit_annotation(annotation)

        # A route that declares a bounded model but hands FastAPI a raw dict / Response bypasses
        # that model at runtime — the declared schema is NOT enforced. Fail closed.
        require_redaction = any(
            _REDACTION_REQUIRED_MODELS & _referenced_model_names(a) for a in annotations
        )
        if not route_unbounded:
            for suffix, note, unwaivable in self._handler_bypasses_model(
                route.endpoint, require_redaction=require_redaction
            ):
                key = f"{label} {suffix}" if suffix else label
                if unwaivable:
                    self.violations.append(Violation(key, "dynamic", note))
                else:
                    self._flag_unbounded(key, note)
        elif require_redaction:
            # The fail-closed redaction check must run EVEN when the response_model is structurally
            # unbounded (and thus covered by a model-wide / route-level unbounded waiver) — an
            # unsanitized ResourceNode/ModuleRunResult egress can never ride a waiver (issue #91 R3,
            # finding 3). Only the unwaivable ``<unredacted egress>`` finding is produced here; the
            # unbounded surface itself is already accounted for above via ``_flag_unbounded``.
            for suffix, note, _unwaivable in self._handler_bypasses_model(
                route.endpoint, require_redaction=True, redaction_only=True
            ):
                key = f"{label} {suffix}" if suffix else label
                self.violations.append(Violation(key, "dynamic", note))

        # FastAPI resolves ``Depends(...)`` dependencies before the handler; a dependency that
        # raises HTTPException egresses its detail to the client exactly like the handler. Audit
        # every resolved dependency callable in the route's dependency tree.
        self._audit_route_dependencies(route, label)

    def _audit_route_dependencies(self, route: Any, label: str) -> None:
        """Scan each dependency callable for unbounded raised details and raw/structured returns."""
        dependant = getattr(route, "dependant", None)
        if dependant is None:
            return
        stack = list(getattr(dependant, "dependencies", []) or [])
        seen: set[int] = set()
        while stack:
            dep = stack.pop()
            stack.extend(getattr(dep, "dependencies", []) or [])
            call = getattr(dep, "call", None)
            if call is None or id(call) in seen:
                continue
            seen.add(id(call))
            module = inspect.getmodule(call)
            top = (getattr(module, "__name__", "") or "").split(".", 1)[0]
            if top in {"fastapi", "starlette"}:
                continue  # framework-owned dependency, not app egress
            # A function, a class-instance (``__call__``), OR a class dependency (``__init__``).
            name = getattr(call, "__name__", None) or type(call).__name__
            # Only a plain-function dependency "returns" a body to the handler; a class/instance
            # dependency injects an instance, so its returns are not audited here (one-level
            # residual). FastAPI returns a dependency's raw Response/dict unchanged, bypassing the
            # route's response_model — so audit the dependency's own returns, one level deep.
            is_plain_func_dep = inspect.isfunction(call) or inspect.iscoroutinefunction(call)
            for dfunc, dep_globals in _resolve_callable_func(call):
                resolver = _http_exc_resolver(dep_globals)
                dep_assigns = build_assignment_map(dfunc)
                for structured, reason in _http_detail_findings(
                    dfunc, resolver, dep_assigns, dep_globals
                ):
                    note = (
                        f"dependency {name}() raises HTTPException with an unbounded detail — "
                        f"{reason}"
                    )
                    suffix = (
                        _HTTP_STRUCTURED_SUFFIX if structured
                        else f"<dependency {name} raise detail>"
                    )
                    key = f"{label} {suffix}"
                    if structured:
                        self.violations.append(Violation(key, "dynamic", note))
                    else:
                        self._flag_unbounded(key, note)
                if not is_plain_func_dep:
                    continue
                for stmt in _iter_returns(dfunc):
                    rreason = _classify_raw_return(stmt.value, dep_assigns, dep_globals)
                    if rreason is None:
                        continue
                    note = f"dependency {name}() {rreason}"
                    key = f"{label} <dependency {name} raw return>"
                    self.violations.append(Violation(key, "dynamic", note))

    @staticmethod
    def _handler_bypasses_model(
        endpoint: Any, *, require_redaction: bool = False, redaction_only: bool = False
    ) -> list[tuple[str, str, bool]]:
        """Return ``(key-suffix, reason, unwaivable)`` findings iff a handler can emit a bad body.

        FastAPI serialises a handler's return value THROUGH the declared model *unless* the value is
        a ``Response`` instance (returned as-is) — so a reachable ``Response`` (or a raw dict/list
        literal) means the declared schema is not enforced. This performs a conservative,
        fail-closed intra-module analysis: it follows local variable assignments and resolves ONE
        level of module-level/global helper calls. Anything that cannot be proven to be a value
        FastAPI coerces through the bounded model is flagged (over-approximating: false-positives
        are waivable, false-negatives are not). Unreadable source ⇒ flagged.

        When ``require_redaction`` is set (the route's response_model transitively contains a
        :data:`_REDACTION_REQUIRED_MODELS` model whose free-form surface only survives the type
        audit because a reviewed projection redacts it), EVERY returned redaction-required value
        MUST flow through a reviewed egress projection (:func:`_return_fully_sanitized`); a raw
        ``return store.get_estate(...)``, a partially-sanitized collection, or an identity/decoy
        wrapper is failed closed (UNWAIVABLE) so it cannot ride the model-wide ``tags``/``extra``
        ``ModuleRunResult.extra`` waiver. With ``redaction_only`` set, ONLY that fail-closed
        redaction check runs (used when the route is otherwise already flagged unbounded, so the raw
        dict/Response and raised-detail scans are skipped) — the redaction check itself is never
        skipped.
        """
        try:
            source = textwrap.dedent(inspect.getsource(endpoint))
            tree = ast.parse(source)
        except (OSError, TypeError, SyntaxError) as exc:
            return [
                ("", f"handler source could not be introspected ({exc}) — cannot prove model "
                     "enforced", False),
            ]

        func: ast.FunctionDef | ast.AsyncFunctionDef | None = None
        for node in tree.body:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                func = node
                break
        if func is None:
            return []

        module_globals = getattr(endpoint, "__globals__", {}) or {}

        # Local may-reach assignment map for the handler body (shared semantics via the helper).
        assignments: dict[str, list[ast.expr]] = build_assignment_map(func)

        def direct_raw(value: ast.expr | None) -> str | None:
            """Flag a value that is *directly* a raw dict/list/set literal or a Response call."""
            reason = _direct_raw_literal(_unwrap_await(value), module_globals)
            return f"handler {reason}" if reason is not None else None

        def helper_returns_raw(callee: str) -> str | None:
            """Resolve a bare-name callee via module globals; check its RETURN values (one level).

            The helper's OWN local single-assignment map and module globals are used, so a
            helper-local ``result = JSONResponse({...}); return result`` is resolved like the
            handler resolves its own locals. Raises inside a resolved helper are handled separately
            (``helper_raise_findings``). Resolution stays one level deep — a helper delegating to
            another raising/returning helper is an accepted documented residual.
            """
            target = module_globals.get(callee)
            if target is None:
                return (
                    f"handler returns an unresolved call {callee}() — "
                    "cannot prove the declared response_model is enforced"
                )
            if isinstance(target, type):
                if _is_response_class(target):
                    return (
                        f"handler returns a raw {target.__name__} via alias {callee} — "
                        "declared response_model not enforced"
                    )
                return None  # constructing a model class => a value FastAPI coerces through it
            try:
                inspect.getsource(target)
            except (OSError, TypeError):
                return (
                    f"handler delegates to {callee}() whose source is unreadable — "
                    "cannot prove the declared response_model is enforced"
                )
            hfunc = _resolve_helper_func(target)
            if hfunc is None:
                return None
            hglobals = getattr(target, "__globals__", {}) or {}
            hmap = build_assignment_map(hfunc)
            for stmt in _iter_returns(hfunc):
                if (reason := _classify_raw_return(stmt.value, hmap, hglobals)) is not None:
                    return f"handler delegates to {callee}() which {reason}"
            return None

        def value_is_raw(
            value: ast.expr | None, resolve_helpers: bool, _seen: set[str] | None = None
        ) -> str | None:
            _seen = _seen if _seen is not None else set()
            value = _unwrap_await(value)
            reason = direct_raw(value)
            if reason is not None:
                return reason
            # A ternary/boolean-expression return can reach a raw Response on either branch.
            if isinstance(value, ast.IfExp):
                return value_is_raw(value.body, resolve_helpers, _seen) or value_is_raw(
                    value.orelse, resolve_helpers, _seen
                )
            if isinstance(value, ast.BoolOp):
                for operand in value.values:
                    if (reason := value_is_raw(operand, resolve_helpers, _seen)) is not None:
                        return reason
                return None
            if isinstance(value, ast.Name):
                if value.id in _seen:
                    return None
                bounds = assignments.get(value.id, [])
                if bounds:
                    # UNION (may-reach): a name bound to a raw value on ANY branch is flagged.
                    _seen.add(value.id)
                    for bound in bounds:
                        if (reason := value_is_raw(bound, resolve_helpers, _seen)) is not None:
                            return reason
                    return None
                # An unresolved bare Name is a parameter (usually coerced through the model) or an
                # unknown name. A returned Depends-injected param that is itself a raw Response is
                # covered at its source by auditing the dependency's own returns in
                # ``_audit_route_dependencies`` — we do NOT flag every ``return <param>`` here, as
                # that would over-flag ordinary bounded params.
                return None
            if isinstance(value, ast.Call):
                # Attribute calls (obj.method(...)) yield values FastAPI coerces through the model.
                if isinstance(value.func, ast.Attribute):
                    return None
                if isinstance(value.func, ast.Name):
                    aliased = _resolve_response_alias(
                        value.func.id, assignments, module_globals
                    )
                    if aliased is not None:
                        return (
                            f"handler returns a raw {aliased.__name__} via alias "
                            f"{value.func.id} — declared response_model not enforced"
                        )
                    if resolve_helpers:
                        return helper_returns_raw(value.func.id)
            return None

        def helper_raise_findings() -> list[tuple[str, str, bool]]:
            """Shape-split ``raise HTTPException`` findings for one-level helpers called in returns.

            The returned value is resolved one level through the handler's assignment map first, so
            an ``result = await load(); return result`` recovers the underlying ``load()`` call
            before the helper lookup. Each resolved helper is scanned with its OWN module resolver
            and assignment map. Structured details are unwaivable.
            """
            out: list[tuple[str, str, bool]] = []
            seen: set[int] = set()
            for stmt in _iter_returns(func):
                base = _unwrap_await(stmt.value)
                # UNION (may-reach): a returned Name may be bound to a helper CALL on any branch.
                if isinstance(base, ast.Name):
                    candidates = [_unwrap_await(b) for b in assignments.get(base.id, [])]
                else:
                    candidates = [base]
                for called in candidates:
                    if not (isinstance(called, ast.Call) and isinstance(called.func, ast.Name)):
                        continue
                    target = module_globals.get(called.func.id)
                    if target is None or isinstance(target, type) or id(target) in seen:
                        continue
                    seen.add(id(target))
                    hfunc = _resolve_helper_func(target)
                    if hfunc is None:
                        continue
                    hmodule_globals = getattr(target, "__globals__", {}) or {}
                    hresolver = _http_exc_resolver(hmodule_globals)
                    hmap = build_assignment_map(hfunc)
                    for structured, reason in _http_detail_findings(
                        hfunc, hresolver, hmap, hmodule_globals
                    ):
                        note = (
                            f"handler delegates to {called.func.id}() which raises HTTPException "
                            f"with an unbounded detail — {reason}"
                        )
                        out.append(_raise_finding(structured, note))
            return out

        findings: list[tuple[str, str, bool]] = []
        if not redaction_only:
            for stmt in _iter_returns(func):
                if (reason := value_is_raw(stmt.value, resolve_helpers=True)) is not None:
                    findings.append(("", reason, False))
                    break

        # When the response_model carries a redaction-required model, a data-bearing return that
        # does NOT fully flow through a reviewed egress projection would emit an unsanitized
        # ``ResourceNode``/``ModuleRunResult`` while riding the model-wide ``ResourceNode.tags`` /
        # ``ModuleRunResult.extra`` waiver. Fail CLOSED (unwaivable) so a NEW raw endpoint (e.g.
        # ``return store.get_estate(...)``), a partially-sanitized collection, or a decoy/identity
        # wrapper trips the audit rather than passing green. This check runs even under a
        # route-level unbounded waiver (see ``_audit_api_route``); it is never skipped.
        if require_redaction:
            for stmt in _iter_returns(func):
                if _is_trivial_return(stmt.value) or _return_fully_sanitized(
                    stmt.value, module_globals
                ):
                    continue
                findings.append((
                    "<unredacted egress>",
                    "handler returns a redaction-required model "
                    f"({', '.join(sorted(_REDACTION_REQUIRED_MODELS))}) without routing every "
                    "returned redaction-required value through a reviewed egress projection "
                    f"({', '.join(sorted(_TRUSTED_EGRESS_PROJECTIONS))}) — customer-controlled "
                    "tags/extra could egress unredacted (see issue #91)",
                    True,
                ))
                break

        if redaction_only:
            return findings

        # A ``raise HTTPException(detail=...)`` in the handler body serialises ``detail`` into the
        # response body, bypassing the declared response_model. A scalar string-coercion detail is
        # keyed to a waivable suffix; a STRUCTURED (dict/list/set/tuple) detail is unwaivable so no
        # route-level string-coercion waiver can ever silence a newly-introduced PII payload.
        resolves = _http_exc_resolver(module_globals)
        for structured, reason in _http_detail_findings(
            func, resolves, assignments, module_globals
        ):
            note = f"raises HTTPException with an unbounded detail — {reason}"
            findings.append(_raise_finding(structured, note))
        findings.extend(helper_raise_findings())
        return findings

    def audit_dict_return(self, source: str, contract: DictReturnContract) -> None:
        """Audit a ``return {...}`` payload via ``ast`` (never executes the code).

        EVERY ``return`` whose value is a dict literal is audited (not just the first) — a
        multi-branch contract such as ``if leak: return {...}; return {...}`` must have all branches
        checked. A dict reachable through a ternary/BoolOp inside a ``return`` is audited per
        operand (``await`` is unwrapped). ``LookupError`` is raised only if the function has no
        dict-literal return at all.
        """
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
                and node.name == contract.symbol
            ):
                continue
            found_dict = False
            for stmt in ast.walk(node):
                if not isinstance(stmt, ast.Return):
                    continue
                for dict_node in _iter_dict_operands(stmt.value):
                    found_dict = True
                    self._audit_payload_dict_keys(dict_node, contract)
            if found_dict:
                return
        raise LookupError(f"function {contract.symbol!r} with a returned dict literal not found")

    def _audit_payload_dict_keys(self, dict_node: ast.Dict, contract: DictReturnContract) -> None:
        """Check every key of one payload dict literal against the contract's allow-list."""
        for key in dict_node.keys:
            if key is None:
                self.violations.append(
                    Violation(
                        f"{contract.name}.<spread>",
                        "dynamic",
                        "payload uses dict-unpacking ({**x}) — unbounded emitted keys",
                    )
                )
                continue
            if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
                self.violations.append(
                    Violation(
                        f"{contract.name}.<computed-key>",
                        "dynamic",
                        "payload has a computed/non-literal key — unbounded emitted key",
                    )
                )
                continue
            name = key.value
            if name not in contract.allowed:
                self.violations.append(
                    Violation(
                        f"{contract.name}.{name}",
                        "unlisted",
                        f"unclassified egress key '{name}' — add it to the PII-free "
                        "allow-list after confirming it carries no PII",
                    )
                )
            reason = pii_reason(name)
            if reason is not None:
                self.violations.append(
                    Violation(f"{contract.name}.{name}", "pii", reason)
                )


def run_audit(
    root: Path,
    waivers: dict[str, str] | None = None,
    dict_contracts: tuple[DictReturnContract, ...] = _DICT_CONTRACTS,
) -> Auditor:
    """Import the app, enumerate its egress models + the notification payloads, and audit them all.

    Fail-closed: an import/introspection failure is recorded as a violation, never a silent skip.
    """
    auditor = Auditor(_DEFAULT_WAIVERS if waivers is None else waivers)
    try:
        from api.app.main import app

        auditor.audit_app(app)
    except Exception as exc:  # noqa: BLE001 — any failure to introspect the app must fail closed.
        auditor.violations.append(
            Violation("api.app.main", "error", f"could not import/introspect the app: {exc}")
        )
    for contract in dict_contracts:
        try:
            source = (root / Path(contract.path)).read_text(encoding="utf-8")
            auditor.audit_dict_return(source, contract)
        except (OSError, SyntaxError, LookupError) as exc:
            auditor.violations.append(
                Violation(contract.name, "error", f"could not audit payload: {exc}")
            )
    return auditor


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="audit_no_pii_egress.py",
        description=(
            "Fail closed if an egress surface carries a PII-named field or an un-analyzable "
            "(open-mapping / raw-dict / no-response_model) egress that is not a tracked waiver."
        ),
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=_REPO_ROOT,
        help="Repository root to audit (default: the repo this script lives in).",
    )
    args = parser.parse_args(argv)

    auditor = run_audit(args.root)

    for key, issue, note in auditor.waived:
        print(f"TRACKED WAIVER ({issue}): {key} — {note}")

    if auditor.violations:
        print(
            f"\nFAIL: {len(auditor.violations)} no-PII-egress violation(s) found:",
            file=sys.stderr,
        )
        for v in auditor.violations:
            print(f"  [{v.kind}] {v.target}: {v.message}", file=sys.stderr)
        print(
            "\nEgress surfaces may carry ONLY PII-free field names with statically bounded keys; "
            "an unbounded surface requires a tracked-issue waiver.",
            file=sys.stderr,
        )
        return 1

    print(
        f"\nOK: no-PII-egress audit passed — {len(auditor.visited)} response model(s) audited, "
        f"{len(auditor.waived)} tracked waiver(s)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
