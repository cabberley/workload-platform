"""Tests for scripts/audit_no_pii_egress.py — the no-PII-egress regression gate (issue #63).

Guarantees under test:
  1. The REAL egress surfaces on the current tree PASS (only tracked waivers, no violations).
  2. The gate FAILS CLOSED on every R2/R3 evasion probe — nested-model PII, computed-field PII,
     RootModel PII, an UNJUSTIFIED open mapping, a route with no bounded response_model, an
     `Any`/`dict`/`object` response_model, a custom `@model_serializer`, nested dataclass/TypedDict
     PII, and a handler that returns a raw dict/JSONResponse bypassing its declared model — while
     the genuine `extra`/label/raw-dict gaps are surfaced as LOUD tracked waivers (#91).
  3. Alias resolution and the dict-payload dynamic-key checks from earlier reviews still hold.

All fixtures are synthetic, clearly-fake, secret-free.
"""
from __future__ import annotations

import collections
import importlib.util
import json
import os
import sys
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal

import pytest
from fastapi import APIRouter, Depends, FastAPI, HTTPException, encoders, responses
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import (
    AliasChoices,
    BaseModel,
    Field,
    PlainSerializer,
    RootModel,
    SerializeAsAny,
    WrapSerializer,
    computed_field,
    field_serializer,
    model_serializer,
)
from starlette.applications import Starlette
from starlette.routing import Route
from typing_extensions import TypedDict  # Pydantic needs typing_extensions.TypedDict on py<3.12

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "scripts" / "audit_no_pii_egress.py"


def _load_cli():
    spec = importlib.util.spec_from_file_location("audit_no_pii_egress_cli", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # register so dataclasses resolve via __module__
    spec.loader.exec_module(module)
    return module


AUDIT = _load_cli()


def _audit_model(model: type[BaseModel], waivers: dict[str, str] | None = None):
    auditor = AUDIT.Auditor(waivers or {})
    auditor.audit_model(model)
    return auditor


# ---------------------------------------------------------------------------------------
# 1. The real egress surfaces pass (waivers allowed, no violations).
# ---------------------------------------------------------------------------------------
def test_real_egress_surfaces_pass() -> None:
    auditor = AUDIT.run_audit(_REPO_ROOT)
    assert auditor.violations == [], f"unexpected egress violations: {auditor.violations}"


def test_main_exit_zero_on_current_tree() -> None:
    assert AUDIT.main([]) == 0


def test_extra_open_mapping_is_a_tracked_waiver() -> None:
    # ModuleRunResult.extra is a genuine gap in src/** — present + labelled #91, NOT a violation.
    auditor = AUDIT.run_audit(_REPO_ROOT)
    keys = {k: issue for k, issue, _note in auditor.waived}
    assert keys.get("ModuleRunResult.extra") == "#91"
    assert not any(v.target == "ModuleRunResult.extra" for v in auditor.violations)


def test_all_default_waivers_track_issue_91() -> None:
    # R3/R6: every waiver is tracked by #91 (free-form mappings / raw-dict endpoints) or #96
    # (non-literal HTTPException details) — never #78, which is only opaque finding-ID hardening.
    assert AUDIT._DEFAULT_WAIVERS
    assert all(issue in {"#91", "#96"} for issue in AUDIT._DEFAULT_WAIVERS.values())


def test_default_waivers_include_issue_96_http_detail_sites() -> None:
    # R6 HIGH 2: the real src/** non-literal HTTPException detail sites are waived under #96. The
    # results/findings sites became visible once those routes gained a bounded response_model
    # (issue #91) — the detail check only runs for routes that declare one.
    issue_96 = {k for k, v in AUDIT._DEFAULT_WAIVERS.items() if v == "#96"}
    assert issue_96 == {
        "POST /api/modules/{name}/run <raise HTTPException detail>",
        "GET /api/workloads/{workload}/graph <raise HTTPException detail>",
        "GET /api/workloads/{workload}/impact <raise HTTPException detail>",
        "POST /api/workloads/{workload}/results <raise HTTPException detail>",
        "POST /api/workloads/{workload}/findings <raise HTTPException detail>",
    }


def test_real_egress_audit_passes_with_default_waivers() -> None:
    # R6: the strict literal-only detail rule keeps the real tree GREEN via the #96 waivers.
    assert AUDIT.run_audit(_REPO_ROOT).violations == []


def test_notification_payload_is_audited() -> None:
    assert any(c.name == "alerts._notification_payload" for c in AUDIT._DICT_CONTRACTS)


# ---------------------------------------------------------------------------------------
# 2. Field-name PII detection.
# ---------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "field",
    ["email", "customerEmail", "given_name", "passport_number", "home_address", "phone",
     "birth_date", "patientName"],
)
def test_pii_reason_flags_pii_field_names(field: str) -> None:
    assert AUDIT.pii_reason(field) is not None


@pytest.mark.parametrize(
    "field",
    ["id", "nodeId", "packId", "findingId", "name", "severity", "blastRadius", "createdAt",
     "graphRevision", "agentName", "moduleName"],
)
def test_pii_reason_allows_safe_field_names(field: str) -> None:
    assert AUDIT.pii_reason(field) is None


# ---------------------------------------------------------------------------------------
# 3. R2 evasion probes — each must now FAIL closed.
# ---------------------------------------------------------------------------------------
def test_probe_nested_model_pii_is_caught() -> None:
    class Inner(BaseModel):
        patientEmail: str

    class Outer(BaseModel):
        payload: Inner

    auditor = _audit_model(Outer)
    assert any(v.kind == "pii" and v.target == "Inner.patientEmail" for v in auditor.violations)


def test_probe_deeply_nested_list_and_dict_pii_is_caught() -> None:
    class Leaf(BaseModel):
        homeAddress: str

    class Mid(BaseModel):
        leaves: list[Leaf]

    class Top(BaseModel):
        mids: dict[str, Mid]

    auditor = _audit_model(Top)
    assert any(v.kind == "pii" and v.target == "Leaf.homeAddress" for v in auditor.violations)


def test_probe_computed_field_pii_is_caught() -> None:
    class Comp(BaseModel):
        x: int

        @computed_field(alias="patientEmail")
        @property
        def derived(self) -> str:
            return "x"

    auditor = _audit_model(Comp)
    assert any(v.kind == "pii" and v.target == "Comp.patientEmail" for v in auditor.violations)


def test_probe_rootmodel_pii_is_caught() -> None:
    class Inner(BaseModel):
        patientEmail: str

    class Wrapped(RootModel[Inner]):
        pass

    auditor = _audit_model(Wrapped)
    assert any(v.kind == "pii" and v.target == "Inner.patientEmail" for v in auditor.violations)


def test_probe_alias_and_alias_choices_pii_is_caught() -> None:
    class Aliased(BaseModel):
        display: str = Field(serialization_alias="patientName")
        who: str = Field(validation_alias=AliasChoices("who", "fullName"))

    auditor = _audit_model(Aliased)
    targets = {v.target for v in auditor.violations if v.kind == "pii"}
    assert "Aliased.patientName" in targets
    assert "Aliased.fullName" in targets


def test_probe_unjustified_open_mapping_is_a_violation() -> None:
    class Leaky(BaseModel):
        id: str
        blob: dict[str, Any]

    auditor = _audit_model(Leaky)  # no waivers
    assert any(v.kind == "dynamic" and v.target == "Leaky.blob" for v in auditor.violations)


def test_probe_model_config_extra_allow_is_a_violation() -> None:
    class OpenEnvelope(BaseModel):
        model_config = {"extra": "allow"}
        id: str

    auditor = _audit_model(OpenEnvelope)
    assert any(v.kind == "dynamic" and "extra=allow" in v.target for v in auditor.violations)


def test_justified_open_mapping_is_waived_not_violated() -> None:
    class Reviewed(BaseModel):
        id: str
        extra: dict[str, Any]

    auditor = _audit_model(Reviewed, waivers={"Reviewed.extra": "#78"})
    assert auditor.violations == []
    assert any(k == "Reviewed.extra" and i == "#78" for k, i, _n in auditor.waived)


def test_probe_route_without_response_model_is_a_violation() -> None:
    app = FastAPI()

    @app.get("/raw")
    def raw():  # no response_model / return annotation => unbounded egress
        return {"patientEmail": "nobody@example.invalid"}

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and v.target == "GET /raw" for v in auditor.violations)


def test_probe_route_returning_open_mapping_is_a_violation() -> None:
    app = FastAPI()

    @app.get("/counts", response_model=dict[str, int])
    def counts() -> dict[str, int]:
        return {}

    auditor = AUDIT.Auditor({})  # not waived
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and v.target == "GET /counts" for v in auditor.violations)


def test_route_open_mapping_can_be_waived() -> None:
    app = FastAPI()

    @app.get("/counts", response_model=dict[str, int])
    def counts() -> dict[str, int]:
        return {}

    auditor = AUDIT.Auditor({"GET /counts": "#78"})
    auditor.audit_app(app)
    assert auditor.violations == []
    assert any(k == "GET /counts" and i == "#78" for k, i, _n in auditor.waived)


# ---------------------------------------------------------------------------------------
# 3b. R3 evasion probes — serialization paths and open-mapping refinements must fail closed.
# ---------------------------------------------------------------------------------------
def test_probe_response_model_any_is_a_violation() -> None:
    app = FastAPI()

    @app.get("/any", response_model=Any)
    def anything() -> Any:
        return {"patientEmail": "nobody@example.invalid"}

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and v.target == "GET /any" for v in auditor.violations)


def test_probe_response_model_object_is_a_violation() -> None:
    app = FastAPI()

    @app.get("/obj", response_model=object)
    def obj() -> object:
        return {}

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and v.target == "GET /obj" for v in auditor.violations)


def test_probe_handler_returns_jsonresponse_bypassing_model_is_a_violation() -> None:
    app = FastAPI()

    class Safe(BaseModel):
        id: str

    @app.get("/bypass", response_model=Safe)
    def bypass() -> Any:
        # Declared model is Safe, but the handler emits an unvalidated raw JSONResponse.
        return JSONResponse({"patientEmail": "nobody@example.invalid"})

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and v.target == "GET /bypass" for v in auditor.violations)


def test_probe_handler_returns_raw_dict_bypassing_model_is_a_violation() -> None:
    app = FastAPI()

    class Safe(BaseModel):
        id: str

    @app.get("/rawdict", response_model=Safe)
    def rawdict() -> Any:
        return {"patientEmail": "nobody@example.invalid"}

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and v.target == "GET /rawdict" for v in auditor.violations)


def test_probe_model_serializer_is_a_violation() -> None:
    class Serialized(BaseModel):
        value: str

        @model_serializer
        def serialize(self) -> dict[str, str]:
            return {"patientEmail": self.value}

    auditor = _audit_model(Serialized)
    assert any(
        v.kind == "dynamic" and "<model_serializer>" in v.target for v in auditor.violations
    )


def test_probe_nested_dataclass_pii_is_caught() -> None:
    @dataclass
    class Person:
        patientEmail: str

    class Envelope(BaseModel):
        person: Person

        model_config = {"arbitrary_types_allowed": True}

    auditor = _audit_model(Envelope)
    assert any(v.kind == "pii" and v.target == "Person.patientEmail" for v in auditor.violations)


def test_probe_nested_typeddict_pii_is_caught() -> None:
    class PersonTD(TypedDict):
        patientEmail: str

    class Envelope(BaseModel):
        person: PersonTD

    auditor = _audit_model(Envelope)
    # A nested TypedDict carrying PII must be caught fail-closed. Depending on the runtime's
    # TypedDict introspection (Python version), the auditor either recurses to
    # `PersonTD.patientEmail` (pii) or fails closed on the opaque `Envelope.person` field
    # (dynamic) — both are a catch; neither is silently waivable.
    assert auditor.violations, (
        f"nested TypedDict PII must be caught: {[(v.kind, v.target) for v in auditor.violations]}"
    )
    assert not auditor.waived


def test_bounded_enum_key_mapping_passes_without_waiver() -> None:
    class Channel(StrEnum):
        teams = "teams"
        webhook = "webhook"

    class Metrics(BaseModel):
        counts: dict[Channel, int]

    auditor = _audit_model(Metrics)  # no waivers — bounded key type needs none
    assert auditor.violations == []
    assert auditor.waived == []


def test_bounded_literal_key_mapping_passes_but_recurses_value_for_pii() -> None:
    class Leaf(BaseModel):
        patientEmail: str

    class Bounded(BaseModel):
        # Bounded key type (Literal) => no waiver required, but the VALUE is still recursed.
        by_kind: dict[Literal["a", "b"], Leaf]

    auditor = _audit_model(Bounded)  # no waivers
    assert not any(v.kind == "dynamic" for v in auditor.violations)  # key type is bounded
    assert any(v.kind == "pii" and v.target == "Leaf.patientEmail" for v in auditor.violations)


def test_second_open_mapping_on_same_model_still_fails_closed() -> None:
    class TwoMaps(BaseModel):
        id: str
        tags: dict[str, str]
        extra: dict[str, Any]

    # Only ONE mapping is waived; the second remains a fail-closed violation.
    auditor = _audit_model(TwoMaps, waivers={"TwoMaps.tags": "#91"})
    assert any(v.kind == "dynamic" and v.target == "TwoMaps.extra" for v in auditor.violations)
    assert any(k == "TwoMaps.tags" and i == "#91" for k, i, _n in auditor.waived)


# ---------------------------------------------------------------------------------------
# 4. A genuinely-clean synthetic graph passes; introspection failures fail closed.
# ---------------------------------------------------------------------------------------
def test_clean_contract_graph_passes() -> None:
    class Inner(BaseModel):
        id: str
        count: int

    class Outer(BaseModel):
        id: str
        severity: str
        items: list[Inner]

    auditor = _audit_model(Outer)
    assert auditor.violations == []
    assert auditor.waived == []


def test_cycle_guard_terminates() -> None:
    class Node(BaseModel):
        id: str
        children: list[Node] = []

    Node.model_rebuild()
    auditor = _audit_model(Node)  # must not infinite-loop
    assert auditor.violations == []


def test_import_failure_fails_closed() -> None:
    # A missing payload source must be recorded as a violation, never a silent skip.
    auditor = AUDIT.run_audit(Path(_REPO_ROOT / "does-not-exist-anywhere"))
    assert any(v.kind == "error" for v in auditor.violations)


# ---------------------------------------------------------------------------------------
# 5. Notification-payload (dict return) dynamic-key + PII checks.
# ---------------------------------------------------------------------------------------
def _dict_contract() -> Any:
    return AUDIT.DictReturnContract(
        "payload", "synthetic.py", "_notification_payload",
        frozenset({"findingId", "severity", "channel", "runbook"}),
    )


def test_probe_dict_unpacking_spread_is_flagged() -> None:
    source = (
        "def _notification_payload(finding, pii):\n"
        "    return {\n"
        "        'findingId': finding.id,\n"
        "        **pii,\n"
        "    }\n"
    )
    auditor = AUDIT.Auditor({})
    auditor.audit_dict_return(source, _dict_contract())
    assert any(v.kind == "dynamic" and "<spread>" in v.target for v in auditor.violations)


def test_probe_computed_dict_key_is_flagged() -> None:
    source = (
        "def _notification_payload(finding, key):\n"
        "    EMAIL = 'email'\n"
        "    return {\n"
        "        'findingId': finding.id,\n"
        "        EMAIL: 'nobody@example.invalid',\n"
        "    }\n"
    )
    auditor = AUDIT.Auditor({})
    auditor.audit_dict_return(source, _dict_contract())
    assert any(v.kind == "dynamic" and "<computed-key>" in v.target for v in auditor.violations)


def test_literal_pii_key_in_payload_is_caught() -> None:
    source = (
        "def _notification_payload(finding):\n"
        "    return {\n"
        "        'findingId': finding.id,\n"
        "        'reporterEmail': 'nobody@example.invalid',\n"
        "    }\n"
    )
    auditor = AUDIT.Auditor({})
    auditor.audit_dict_return(source, _dict_contract())
    assert any(v.kind == "pii" and v.target.endswith("reporterEmail") for v in auditor.violations)
    assert any(
        v.kind == "unlisted" and v.target.endswith("reporterEmail") for v in auditor.violations
    )


def test_clean_payload_passes() -> None:
    source = (
        "def _notification_payload(finding, decision):\n"
        "    return {\n"
        "        'findingId': finding.id,\n"
        "        'severity': decision['severity'],\n"
        "        'channel': 'teams',\n"
        "        'runbook': 'rb-1',\n"
        "    }\n"
    )
    auditor = AUDIT.Auditor({})
    auditor.audit_dict_return(source, _dict_contract())
    assert auditor.violations == []


def test_stale_dict_symbol_fails_closed() -> None:
    auditor = AUDIT.Auditor({})
    with pytest.raises(LookupError):
        auditor.audit_dict_return("def other():\n    return {'a': 1}\n", _dict_contract())


# ---------------------------------------------------------------------------------------
# 6. R4 evasion probes — the detector must fail closed on every skipped-surface class.
# ---------------------------------------------------------------------------------------
class _Safe(BaseModel):
    id: str


def _leak_response() -> JSONResponse:
    return JSONResponse({"patientEmail": "nobody@example.invalid"})


# R4 HIGH 1 — non-APIRoute / included / mounted / websocket routes are all audited.
def test_probe_included_router_pii_route_is_a_violation() -> None:
    router = APIRouter()

    @router.get("/inner")
    def inner():  # no response_model on an included route => unbounded egress
        return {"patientEmail": "nobody@example.invalid"}

    app = FastAPI()
    app.include_router(router, prefix="/sub")

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and v.target == "GET /sub/inner" for v in auditor.violations)


def test_probe_add_route_raw_starlette_route_is_a_violation() -> None:
    app = FastAPI()

    def raw(request):
        return JSONResponse({"patientEmail": "nobody@example.invalid"})

    app.add_route("/added", raw, methods=["GET"])

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and "/added" in v.target for v in auditor.violations)


def test_probe_mounted_subapp_pii_route_is_a_violation() -> None:
    sub = FastAPI()

    @sub.get("/leak")
    def leak():
        return {"patientEmail": "nobody@example.invalid"}

    app = FastAPI()
    app.mount("/mounted", sub)

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and v.target == "GET /mounted/leak" for v in auditor.violations)


def test_probe_websocket_route_is_a_violation() -> None:
    app = FastAPI()

    @app.websocket("/ws")
    async def ws(websocket):  # bypasses response_model entirely
        await websocket.accept()

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and v.target == "WS /ws" for v in auditor.violations)


def test_clean_included_typed_route_passes() -> None:
    router = APIRouter()

    @router.get("/ok", response_model=_Safe)
    def ok() -> _Safe:
        return _Safe(id="x")

    app = FastAPI()
    app.include_router(router, prefix="/sub")

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert auditor.violations == []


def test_mounted_starlette_route_can_be_waived() -> None:
    sub = Starlette(routes=[Route("/leak", _leak_response, methods=["GET"])])
    app = FastAPI()
    app.mount("/m", sub)

    auditor = AUDIT.Auditor({"GET,HEAD /m/leak": "#91"})
    auditor.audit_app(app)
    assert auditor.violations == []
    assert any(k == "GET,HEAD /m/leak" and i == "#91" for k, i, _n in auditor.waived)


# R4 HIGH 2 — indirect response-model bypasses (helper / variable / unresolved call).
def test_probe_handler_returns_helper_jsonresponse_is_a_violation() -> None:
    app = FastAPI()

    @app.get("/helper", response_model=_Safe)
    def handler() -> Any:
        return _leak_response()  # helper returns a raw JSONResponse

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and v.target == "GET /helper" for v in auditor.violations)


def test_probe_handler_returns_variable_response_is_a_violation() -> None:
    app = FastAPI()

    @app.get("/var", response_model=_Safe)
    def handler() -> Any:
        result = JSONResponse({"patientEmail": "nobody@example.invalid"})
        return result

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and v.target == "GET /var" for v in auditor.violations)


def test_probe_handler_returns_unresolved_call_is_a_violation() -> None:
    app = FastAPI()

    @app.get("/unresolved", response_model=_Safe)
    def handler() -> Any:
        return _not_defined_anywhere()  # noqa: F821 — intentionally unresolvable

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and v.target == "GET /unresolved" for v in auditor.violations)


def test_clean_handler_returns_model_constructor_passes() -> None:
    app = FastAPI()

    @app.get("/clean", response_model=_Safe)
    def handler() -> _Safe:
        return _Safe(id="x")

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert auditor.violations == []


# R4 HIGH 3 — field_serializer / computed_field(Any) emitted shapes are unbounded.
def test_probe_field_serializer_is_a_violation() -> None:
    class WithFieldSerializer(BaseModel):
        value: str

        @field_serializer("value")
        def ser(self, v: str) -> dict[str, str]:
            return {"patientEmail": v}

    auditor = _audit_model(WithFieldSerializer)
    assert any(
        v.kind == "dynamic" and v.target == "WithFieldSerializer.value"
        for v in auditor.violations
    )


def test_probe_computed_field_returning_any_is_a_violation() -> None:
    class WithComputedAny(BaseModel):
        @computed_field  # type: ignore[prop-decorator]
        @property
        def derived(self) -> Any:
            return {}

    auditor = _audit_model(WithComputedAny)
    assert any(
        v.kind == "dynamic" and v.target == "WithComputedAny.derived" for v in auditor.violations
    )


def test_plain_typed_field_passes() -> None:
    class Plain(BaseModel):
        value: str
        count: int

    auditor = _audit_model(Plain)
    assert auditor.violations == []
    assert auditor.waived == []


# R4 HIGH 4 — open-ended enum (overriding _missing_) keys are NOT bounded.
def test_probe_open_ended_enum_key_is_unbounded() -> None:
    class LooseEnum(StrEnum):
        known = "known"

        @classmethod
        def _missing_(cls, value: object) -> LooseEnum:
            return cls.known  # accepts arbitrary strings => not statically enumerable

    class LooseKeyed(BaseModel):
        values: dict[LooseEnum, int]

    auditor = _audit_model(LooseKeyed)  # no waiver
    assert any(v.kind == "dynamic" and v.target == "LooseKeyed.values" for v in auditor.violations)


def test_closed_enum_key_stays_bounded() -> None:
    class ClosedEnum(StrEnum):
        a = "a"
        b = "b"

    class ClosedKeyed(BaseModel):
        values: dict[ClosedEnum, int]

    auditor = _audit_model(ClosedKeyed)  # no waiver needed
    assert auditor.violations == []
    assert auditor.waived == []


def test_bounded_key_with_pii_value_still_flagged_via_value_recursion() -> None:
    class ClosedEnum(StrEnum):
        a = "a"

    class Leaf(BaseModel):
        patientEmail: str

    class BoundedKeyPiiValue(BaseModel):
        by_kind: dict[ClosedEnum, Leaf]

    auditor = _audit_model(BoundedKeyPiiValue)
    assert not any(v.kind == "dynamic" for v in auditor.violations)  # key bounded
    assert any(v.kind == "pii" and v.target == "Leaf.patientEmail" for v in auditor.violations)


# ---------------------------------------------------------------------------------------
# R5 HIGH A / R6 HIGH 2 — a raised HTTPException detail egresses via the body {"detail": ...}.
# The ONLY bounded detail is a plain string literal; every coerced object/expression fails closed.
# ---------------------------------------------------------------------------------------
_HTTP_DETAIL_KEY = "<raise HTTPException detail>"
_HTTP_STRUCTURED_KEY = "<raise HTTPException structured detail>"


def test_probe_http_exception_dict_detail_is_a_violation() -> None:
    app = FastAPI()

    @app.get("/boom", response_model=_Safe)
    def boom() -> Any:
        # The dict detail serialises straight into the response body — declared model bypassed.
        raise HTTPException(status_code=400, detail={"patientEmail": "nobody@example.invalid"})

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic" and v.target == f"GET /boom {_HTTP_STRUCTURED_KEY}"
        for v in auditor.violations
    )


def test_http_exception_plain_str_detail_passes() -> None:
    app = FastAPI()

    @app.get("/okstr", response_model=_Safe)
    def okstr(bad: bool = False) -> Any:
        if bad:  # pragma: no cover - only the static shape matters
            raise HTTPException(status_code=404, detail="workload not found")
        return _Safe(id="n1")

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert not any(v.target.startswith("GET /okstr") for v in auditor.violations)


def test_http_exception_concatenated_str_literals_pass() -> None:
    app = FastAPI()

    @app.get("/concat", response_model=_Safe)
    def concat(bad: bool = False) -> Any:
        if bad:  # pragma: no cover - static shape only
            raise HTTPException(status_code=404, detail="workload " + "not found")
        return _Safe(id="n1")

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert not any(v.target.startswith("GET /concat") for v in auditor.violations)


def test_http_exception_str_coercion_detail_is_a_violation() -> None:
    # R6 HIGH 2: `str(record)` can stringify a Pydantic model to `field='value'` pairs (PII).
    app = FastAPI()

    @app.get("/coerce", response_model=_Safe)
    def coerce(exc: str = "") -> Any:
        if exc:  # pragma: no cover - static shape only
            raise HTTPException(status_code=400, detail=str(exc))
        return _Safe(id="n1")

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic" and v.target == f"GET /coerce {_HTTP_DETAIL_KEY}"
        for v in auditor.violations
    )


def test_http_exception_fstring_detail_with_pii_is_a_violation() -> None:
    app = FastAPI()

    @app.get("/fstr", response_model=_Safe)
    def fstr() -> Any:
        patient_email = "nobody@example.invalid"
        raise HTTPException(status_code=400, detail=f"rejected {patient_email}")

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic" and v.target == f"GET /fstr {_HTTP_DETAIL_KEY}"
        for v in auditor.violations
    )


def test_http_exception_any_fstring_detail_is_a_violation() -> None:
    # R6 HIGH 2: ANY f-string with an interpolant fails closed — even a benign-looking variable.
    app = FastAPI()

    @app.get("/anyfstr/{workload}", response_model=_Safe)
    def anyfstr(workload: str) -> Any:
        if not workload:  # pragma: no cover - static shape only
            raise HTTPException(status_code=404, detail=f"no graph for workload {workload!r}")
        return _Safe(id="n1")

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic" and v.target == f"GET /anyfstr/{{workload}} {_HTTP_DETAIL_KEY}"
        for v in auditor.violations
    )


def test_http_exception_detail_can_be_waived() -> None:
    # A tracked #96 waiver on the raised-detail key silences only that surface, not the whole route.
    app = FastAPI()

    @app.get("/waivable", response_model=_Safe)
    def waivable(exc: str = "") -> Any:
        if exc:  # pragma: no cover - static shape only
            raise HTTPException(status_code=400, detail=str(exc))
        return _Safe(id="n1")

    key = f"GET /waivable {_HTTP_DETAIL_KEY}"
    auditor = AUDIT.Auditor({key: "#96"})
    auditor.audit_app(app)
    assert not any(v.target.startswith("GET /waivable") for v in auditor.violations)
    assert any(k == key and issue == "#96" for k, issue, _ in auditor.waived)


# ---------------------------------------------------------------------------------------
# R6 HIGH 3 — an HTTPException raised inside a one-level resolved helper must be caught.
# ---------------------------------------------------------------------------------------
def _load_record_raising() -> _Safe:
    raise HTTPException(status_code=400, detail={"patientEmail": "nobody@example.invalid"})


def test_probe_helper_raise_http_detail_is_a_violation() -> None:
    app = FastAPI()

    @app.get("/viahelper", response_model=_Safe)
    def viahelper() -> Any:
        return _load_record_raising()

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic" and v.target == f"GET /viahelper {_HTTP_STRUCTURED_KEY}"
        for v in auditor.violations
    )


# ---------------------------------------------------------------------------------------
# R5 HIGH B — Annotated functional serializers / SerializeAsAny must be inspected, not stripped.
# ---------------------------------------------------------------------------------------
def test_probe_plain_serializer_return_dict_is_a_violation() -> None:
    class WithPlainSerializer(BaseModel):
        value: Annotated[
            str, PlainSerializer(lambda v: {"patientEmail": v}, return_type=dict)
        ]

    auditor = _audit_model(WithPlainSerializer)
    assert any(
        v.kind == "dynamic" and v.target == "WithPlainSerializer.value"
        for v in auditor.violations
    )


def test_probe_plain_serializer_undeclared_return_type_is_a_violation() -> None:
    class WithBareSerializer(BaseModel):
        value: Annotated[str, PlainSerializer(lambda v: {"x": v})]

    auditor = _audit_model(WithBareSerializer)
    assert any(
        v.kind == "dynamic" and v.target == "WithBareSerializer.value"
        for v in auditor.violations
    )


def test_probe_wrap_serializer_return_dict_is_a_violation() -> None:
    class WithWrapSerializer(BaseModel):
        value: Annotated[
            str, WrapSerializer(lambda v, handler: {"patientEmail": v}, return_type=dict)
        ]

    auditor = _audit_model(WithWrapSerializer)
    assert any(
        v.kind == "dynamic" and v.target == "WithWrapSerializer.value"
        for v in auditor.violations
    )


def test_plain_serializer_bounded_return_model_is_recursed_not_flagged() -> None:
    class Bounded(BaseModel):
        id: str

    class LeakyBounded(BaseModel):
        patientEmail: str

    class WithBoundedReturn(BaseModel):
        good: Annotated[str, PlainSerializer(lambda v: Bounded(id=v), return_type=Bounded)]

    auditor = _audit_model(WithBoundedReturn)
    # A declared bounded return model must NOT be blanket-flagged as unbounded egress...
    assert not any(v.target == "WithBoundedReturn.good" for v in auditor.violations)

    class WithLeakyReturn(BaseModel):
        bad: Annotated[
            str, PlainSerializer(lambda v: LeakyBounded(patientEmail=v), return_type=LeakyBounded)
        ]

    leaky = _audit_model(WithLeakyReturn)
    # ...but the auditor DOES recurse into it, so PII inside the return model is still caught.
    assert any(
        v.kind == "pii" and v.target == "LeakyBounded.patientEmail" for v in leaky.violations
    )


def test_probe_serialize_as_any_field_is_a_violation() -> None:
    class Safe(BaseModel):
        id: str

    class WithSerializeAsAny(BaseModel):
        node: SerializeAsAny[Safe]

    auditor = _audit_model(WithSerializeAsAny)
    assert any(
        v.kind == "dynamic" and v.target == "WithSerializeAsAny.node"
        for v in auditor.violations
    )


def test_plain_annotated_field_stays_bounded() -> None:
    class WithPlainAnnotated(BaseModel):
        value: Annotated[str, Field(description="a bounded, non-serializer annotation")]

    auditor = _audit_model(WithPlainAnnotated)
    assert auditor.violations == []
    assert auditor.waived == []


# ---------------------------------------------------------------------------------------
# R6 HIGH 1 — Annotated serializers / SerializeAsAny nested inside containers & unions.
# ---------------------------------------------------------------------------------------
def test_probe_plain_serializer_nested_in_list_is_a_violation() -> None:
    class NestedListSerializer(BaseModel):
        items: list[
            Annotated[str, PlainSerializer(lambda v: {"patientEmail": v}, return_type=dict)]
        ]

    auditor = _audit_model(NestedListSerializer)
    assert any(
        v.kind == "dynamic" and v.target == "NestedListSerializer.items"
        for v in auditor.violations
    )


def test_probe_serialize_as_any_nested_in_list_is_a_violation() -> None:
    class Safe(BaseModel):
        id: str

    class NestedListSaa(BaseModel):
        nodes: list[SerializeAsAny[Safe]]

    auditor = _audit_model(NestedListSaa)
    assert any(
        v.kind == "dynamic" and v.target == "NestedListSaa.nodes" for v in auditor.violations
    )


def test_probe_serializer_nested_in_dict_value_is_a_violation() -> None:
    class NestedDictSerializer(BaseModel):
        by_id: dict[
            str, Annotated[str, WrapSerializer(lambda v, h: {"patientEmail": v}, return_type=dict)]
        ]

    auditor = _audit_model(NestedDictSerializer)
    assert any(
        v.kind == "dynamic" and v.target == "NestedDictSerializer.by_id"
        for v in auditor.violations
    )


def test_probe_serializer_nested_in_optional_is_a_violation() -> None:
    class NestedOptionalSerializer(BaseModel):
        maybe: (
            Annotated[str, PlainSerializer(lambda v: {"x": v}, return_type=dict)] | None
        ) = None

    auditor = _audit_model(NestedOptionalSerializer)
    assert any(
        v.kind == "dynamic" and v.target == "NestedOptionalSerializer.maybe"
        for v in auditor.violations
    )


def test_plain_list_of_str_field_stays_bounded() -> None:
    class WithPlainList(BaseModel):
        tags: list[str]
        ids: tuple[str, ...]

    auditor = _audit_model(WithPlainList)
    assert auditor.violations == []
    assert auditor.waived == []


# =======================================================================================
# R7 — realistic ordinary-usage fail-opens closed in this round.
# =======================================================================================
# Module-level helpers/aliases so a handler's `__globals__` can resolve them (one level deep).
async def _async_returns_raw_dict() -> Any:
    return {"patientEmail": "nobody@example.invalid"}


async def _async_raises_dict_detail() -> _Safe:
    raise HTTPException(status_code=400, detail={"patientEmail": "nobody@example.invalid"})


async def _async_returns_bounded() -> _Safe:
    return _Safe(id="n1")


ApiError = HTTPException  # simulates `from fastapi import HTTPException as ApiError`
_JsonAlias = JSONResponse  # simulates a module-level `X = JSONResponse` Response alias


def _guard_raises_dict() -> None:
    raise HTTPException(status_code=403, detail={"patientEmail": "nobody@example.invalid"})


# --- HIGH-A: `await helper()` must not bypass helper/raise resolution -------------------
def test_r7_await_helper_returning_raw_dict_flags() -> None:
    app = FastAPI()

    @app.get("/awaitraw", response_model=_Safe)
    async def h() -> Any:
        return await _async_returns_raw_dict()

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and v.target == "GET /awaitraw" for v in auditor.violations)


def test_r7_await_helper_raising_dict_detail_flags() -> None:
    app = FastAPI()

    @app.get("/awaitraise", response_model=_Safe)
    async def h() -> Any:
        return await _async_raises_dict_detail()

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic" and v.target == f"GET /awaitraise {_HTTP_STRUCTURED_KEY}"
        for v in auditor.violations
    )


def test_r7_await_helper_returning_bounded_model_passes() -> None:
    app = FastAPI()

    @app.get("/awaitok", response_model=_Safe)
    async def h() -> Any:
        return await _async_returns_bounded()

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert not any(v.target.startswith("GET /awaitok") for v in auditor.violations)


# --- HIGH-B: ternary / boolean-expression Response returns ------------------------------
def test_r7_ternary_response_return_flags() -> None:
    app = FastAPI()

    @app.get("/tern", response_model=_Safe)
    def h(x: bool = False) -> Any:
        return JSONResponse({"patientEmail": "x"}) if x else _Safe(id="n1")

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and v.target == "GET /tern" for v in auditor.violations)


def test_r7_boolop_response_return_flags() -> None:
    app = FastAPI()

    @app.get("/boolop", response_model=_Safe)
    def h(maybe: bool = False) -> Any:
        return maybe and JSONResponse({"patientEmail": "x"})

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and v.target == "GET /boolop" for v in auditor.violations)


def test_r7_ternary_between_bounded_models_passes() -> None:
    app = FastAPI()

    @app.get("/ternok", response_model=_Safe)
    def h(x: bool = False) -> Any:
        return _Safe(id="a") if x else _Safe(id="b")

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert not any(v.target.startswith("GET /ternok") for v in auditor.violations)


# --- HIGH-C: contract dict audit must inspect EVERY return branch -----------------------
def test_r7_multi_branch_contract_dict_second_branch_pii_flags() -> None:
    source = (
        "def _notification_payload(finding, leak):\n"
        "    if leak:\n"
        "        return {'findingId': finding.id}\n"
        "    return {'reporterEmail': 'nobody@example.invalid'}\n"
    )
    auditor = AUDIT.Auditor({})
    auditor.audit_dict_return(source, _dict_contract())
    assert any(v.kind == "pii" and v.target.endswith("reporterEmail") for v in auditor.violations)


def test_r7_ternary_return_dict_operands_audited() -> None:
    source = (
        "def _notification_payload(finding, leak):\n"
        "    return {'reporterEmail': 'x'} if leak else {'findingId': finding.id}\n"
    )
    auditor = AUDIT.Auditor({})
    auditor.audit_dict_return(source, _dict_contract())
    assert any(v.kind == "pii" and v.target.endswith("reporterEmail") for v in auditor.violations)


# --- HIGH-D: a structured detail on a route with a string-coercion waiver stays flagged --
def test_r7_structured_detail_is_unwaivable_by_route_string_waiver() -> None:
    app = FastAPI()

    @app.get("/waived", response_model=_Safe)
    def h(bad: bool = False, worse: bool = False) -> Any:
        if bad:  # pragma: no cover - only the static shape matters
            raise HTTPException(status_code=400, detail=str(bad))
        if worse:  # pragma: no cover
            raise HTTPException(status_code=400, detail={"patientEmail": "x"})
        return _Safe(id="n1")

    # A route-level string-coercion waiver must NOT silence the structured (dict) detail.
    waivers = {f"GET /waived {_HTTP_DETAIL_KEY}": "#96 bounded str(exc) on /waived"}
    auditor = AUDIT.Auditor(waivers)
    auditor.audit_app(app)
    # scalar coercion detail is waived; the structured dict detail is an unwaivable violation.
    assert any(
        v.kind == "dynamic" and v.target == f"GET /waived {_HTTP_STRUCTURED_KEY}"
        for v in auditor.violations
    )
    assert not any(v.target == f"GET /waived {_HTTP_DETAIL_KEY}" for v in auditor.violations)


def test_r7_scalar_detail_on_waived_route_stays_waived() -> None:
    app = FastAPI()

    @app.get("/scalarwaived", response_model=_Safe)
    def h(bad: bool = False) -> Any:
        if bad:  # pragma: no cover
            raise HTTPException(status_code=400, detail=str(bad))
        return _Safe(id="n1")

    waivers = {f"GET /scalarwaived {_HTTP_DETAIL_KEY}": "#96 bounded str(exc)"}
    auditor = AUDIT.Auditor(waivers)
    auditor.audit_app(app)
    assert not any(v.target.startswith("GET /scalarwaived") for v in auditor.violations)


# --- HIGH-E1: a Depends(...) dependency that raises HTTPException is audited ------------
def test_r7_dependency_raising_dict_detail_flags() -> None:
    app = FastAPI()

    @app.get("/dep", response_model=_Safe, dependencies=[Depends(_guard_raises_dict)])
    def h() -> Any:
        return _Safe(id="n1")

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic"
        and v.target == f"GET /dep {_HTTP_STRUCTURED_KEY}"
        for v in auditor.violations
    )


# --- HIGH-E2: HTTPException / Response import ALIASES are resolved ----------------------
def test_r7_httpexception_alias_raise_flags() -> None:
    app = FastAPI()

    @app.get("/alias", response_model=_Safe)
    def h(bad: bool = False) -> Any:
        if bad:  # pragma: no cover
            raise ApiError(status_code=400, detail={"patientEmail": "x"})
        return _Safe(id="n1")

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic" and v.target == f"GET /alias {_HTTP_STRUCTURED_KEY}"
        for v in auditor.violations
    )


def test_r7_module_level_response_alias_return_flags() -> None:
    app = FastAPI()

    @app.get("/respalias", response_model=_Safe)
    def h() -> Any:
        return _JsonAlias({"patientEmail": "x"})

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and v.target == "GET /respalias" for v in auditor.violations)


# --- MED: named serializer alias + TypeAliasType wrappers ------------------------------
def test_r7_named_serializer_alias_is_caught() -> None:
    _ser = PlainSerializer(lambda v: {"patientEmail": v}, return_type=dict)

    class WithAliasedSerializer(BaseModel):
        value: Annotated[str, _ser]

    auditor = _audit_model(WithAliasedSerializer)
    assert any(
        v.kind == "dynamic" and v.target == "WithAliasedSerializer.value"
        for v in auditor.violations
    )


@pytest.mark.skipif(sys.version_info < (3, 12), reason="TypeAliasType requires Python 3.12+")
def test_r7_type_alias_type_serializer_is_caught() -> None:
    from typing import TypeAliasType

    Wrapped = TypeAliasType(
        "Wrapped",
        Annotated[str, PlainSerializer(lambda v: {"patientEmail": v}, return_type=dict)],
    )

    class WithTypeAlias(BaseModel):
        value: Wrapped  # type: ignore[valid-type]

    auditor = _audit_model(WithTypeAlias)
    assert any(
        v.kind == "dynamic" and v.target == "WithTypeAlias.value" for v in auditor.violations
    )


# =======================================================================================
# R8 — single-level local-assignment resolution propagated into helper/detail/dep scopes.
# =======================================================================================
def _helper_local_response() -> _Safe:
    result = JSONResponse({"patientEmail": "nobody@example.invalid"})
    return result  # type: ignore[return-value]  # F1: helper-local raw Response, then returned


def _helper_local_model() -> _Safe:
    result = _Safe(id="ok")
    return result  # a helper-local BOUNDED model bound to a Name must NOT flag


async def _async_load_raises_dict() -> _Safe:
    raise HTTPException(status_code=400, detail={"patientEmail": "nobody@example.invalid"})


class _GuardStructured:
    def __call__(self) -> None:
        raise HTTPException(status_code=403, detail={"patientEmail": "nobody@example.invalid"})


class _GuardScalar:
    def __call__(self, bad: bool = False) -> None:
        raise HTTPException(status_code=403, detail=str(bad))


# --- F1: helper-local Response assignment must be detected ------------------------------
def test_r8_helper_local_response_assignment_flags() -> None:
    app = FastAPI()

    @app.get("/f1", response_model=_Safe)
    def h() -> Any:
        return _helper_local_response()

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and v.target == "GET /f1" for v in auditor.violations)


def test_r8_helper_local_bounded_model_assignment_passes() -> None:
    app = FastAPI()

    @app.get("/f1ok", response_model=_Safe)
    def h() -> Any:
        return _helper_local_model()

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert not any(v.target.startswith("GET /f1ok") for v in auditor.violations)


# --- F2: variable-held structured detail is unwaivable; scalar var stays waivable -------
def test_r8_variable_held_structured_detail_is_unwaivable() -> None:
    app = FastAPI()

    @app.get("/f2", response_model=_Safe)
    def h(bad: bool = False) -> Any:
        if bad:  # pragma: no cover - only the static shape matters
            payload = {"patientEmail": "nobody@example.invalid"}
            raise HTTPException(status_code=400, detail=payload)
        return _Safe(id="ok")

    # A route-level string-coercion waiver must NOT silence the variable-held dict detail.
    waivers = {f"GET /f2 {_HTTP_DETAIL_KEY}": "#96 bounded str(exc) on /f2"}
    auditor = AUDIT.Auditor(waivers)
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic" and v.target == f"GET /f2 {_HTTP_STRUCTURED_KEY}"
        for v in auditor.violations
    )


def test_r8_variable_held_scalar_detail_stays_waivable() -> None:
    app = FastAPI()

    @app.get("/f2scalar", response_model=_Safe)
    def h(bad: bool = False) -> Any:
        if bad:  # pragma: no cover
            msg = str(bad)
            raise HTTPException(status_code=400, detail=msg)
        return _Safe(id="ok")

    waivers = {f"GET /f2scalar {_HTTP_DETAIL_KEY}": "#96 bounded str(exc)"}
    auditor = AUDIT.Auditor(waivers)
    auditor.audit_app(app)
    assert not any(v.target.startswith("GET /f2scalar") for v in auditor.violations)


def test_r8_direct_str_call_detail_stays_waivable() -> None:
    app = FastAPI()

    @app.get("/f2direct", response_model=_Safe)
    def h(bad: bool = False) -> Any:
        if bad:  # pragma: no cover
            raise HTTPException(status_code=400, detail=str(bad))
        return _Safe(id="ok")

    waivers = {f"GET /f2direct {_HTTP_DETAIL_KEY}": "#96 bounded str(exc)"}
    auditor = AUDIT.Auditor(waivers)
    auditor.audit_app(app)
    assert not any(v.target.startswith("GET /f2direct") for v in auditor.violations)


# --- F3: class-instance dependency (Depends(Guard())) is audited -----------------------
def test_r8_class_instance_dependency_structured_detail_flags() -> None:
    app = FastAPI()

    @app.get("/f3", response_model=_Safe, dependencies=[Depends(_GuardStructured())])
    def h() -> Any:
        return _Safe(id="ok")

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic" and v.target == f"GET /f3 {_HTTP_STRUCTURED_KEY}"
        for v in auditor.violations
    )


def test_r8_class_instance_dependency_scalar_detail_is_scalar() -> None:
    app = FastAPI()

    @app.get("/f3scalar", response_model=_Safe, dependencies=[Depends(_GuardScalar())])
    def h() -> Any:
        return _Safe(id="ok")

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    # scalar dependency detail keys to the waivable per-dependency suffix, not the structured one
    scalar_key = "GET /f3scalar <dependency _GuardScalar raise detail>"
    assert any(v.kind == "dynamic" and v.target == scalar_key for v in auditor.violations)
    assert not any(
        v.target == f"GET /f3scalar {_HTTP_STRUCTURED_KEY}" for v in auditor.violations
    )


# --- F4: assigned-then-returned awaited helper call is raise-analysed ------------------
def test_r8_assigned_awaited_helper_raise_flags() -> None:
    app = FastAPI()

    @app.get("/f4", response_model=_Safe)
    async def h() -> Any:
        result = await _async_load_raises_dict()
        return result

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic" and v.target == f"GET /f4 {_HTTP_STRUCTURED_KEY}"
        for v in auditor.violations
    )


# =======================================================================================
# R9 — builtin collection CONSTRUCTOR details/returns; direct class-dependency __init__.
# =======================================================================================
class _GuardInitStructured:
    def __init__(self) -> None:
        # G2a: FastAPI instantiates a class dependency, so __init__ runs and this raises.
        raise HTTPException(status_code=403, detail={"patientEmail": "nobody@example.invalid"})


class _SafeClassDep:
    def __init__(self) -> None:  # a default-ish safe constructor must NOT false-positive
        self.ok = True

    def __call__(self) -> None:  # safe body — no unbounded raise
        return None


# --- G1a: dict(...) constructor detail on a #96-waived route is unwaivable structured ---
def test_r9_dict_constructor_detail_is_unwaivable() -> None:
    app = FastAPI()

    @app.get("/g1a", response_model=_Safe)
    def h(bad: bool = False) -> Any:
        if bad:  # pragma: no cover - only the static shape matters
            raise HTTPException(
                status_code=400, detail=dict(patientEmail="nobody@example.invalid")
            )
        return _Safe(id="ok")

    waivers = {f"GET /g1a {_HTTP_DETAIL_KEY}": "#96 bounded str(exc) on /g1a"}
    auditor = AUDIT.Auditor(waivers)
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic" and v.target == f"GET /g1a {_HTTP_STRUCTURED_KEY}"
        for v in auditor.violations
    )


# --- G1b: variable-held dict(...) constructor detail is likewise unwaivable -------------
def test_r9_variable_held_dict_constructor_detail_is_unwaivable() -> None:
    app = FastAPI()

    @app.get("/g1b", response_model=_Safe)
    def h(bad: bool = False) -> Any:
        if bad:  # pragma: no cover
            payload = dict(patientEmail="nobody@example.invalid")
            raise HTTPException(status_code=400, detail=payload)
        return _Safe(id="ok")

    waivers = {f"GET /g1b {_HTTP_DETAIL_KEY}": "#96 bounded str(exc) on /g1b"}
    auditor = AUDIT.Auditor(waivers)
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic" and v.target == f"GET /g1b {_HTTP_STRUCTURED_KEY}"
        for v in auditor.violations
    )


# --- G1c: a handler returning dict(...) bypasses its bounded model (raw) ----------------
def test_r9_dict_constructor_return_flags_raw() -> None:
    app = FastAPI()

    @app.get("/g1c", response_model=_Safe)
    def h() -> Any:
        return dict(patientEmail="nobody@example.invalid")

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and v.target == "GET /g1c" for v in auditor.violations)


# --- G1d: a direct str(...) coercion detail stays waivable-scalar (no regression) -------
def test_r9_direct_str_call_detail_still_waivable() -> None:
    app = FastAPI()

    @app.get("/g1d", response_model=_Safe)
    def h(bad: bool = False) -> Any:
        if bad:  # pragma: no cover
            raise HTTPException(status_code=400, detail=str(bad))
        return _Safe(id="ok")

    waivers = {f"GET /g1d {_HTTP_DETAIL_KEY}": "#96 bounded str(exc)"}
    auditor = AUDIT.Auditor(waivers)
    auditor.audit_app(app)
    assert not any(v.target.startswith("GET /g1d") for v in auditor.violations)


# --- G2a: Depends(Guard) CLASS whose __init__ raises structured detail flags ------------
def test_r9_class_dependency_init_structured_detail_flags() -> None:
    app = FastAPI()

    @app.get("/g2a", response_model=_Safe, dependencies=[Depends(_GuardInitStructured)])
    def h() -> Any:
        return _Safe(id="ok")

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic" and v.target == f"GET /g2a {_HTTP_STRUCTURED_KEY}"
        for v in auditor.violations
    )


# --- G2b: Depends(Guard()) INSTANCE __call__ structured detail still flags --------------
def test_r9_class_instance_dependency_call_structured_still_flags() -> None:
    app = FastAPI()

    @app.get("/g2b", response_model=_Safe, dependencies=[Depends(_GuardStructured())])
    def h() -> Any:
        return _Safe(id="ok")

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic" and v.target == f"GET /g2b {_HTTP_STRUCTURED_KEY}"
        for v in auditor.violations
    )


# --- G2c: a plain safe class dependency does NOT false-positive -------------------------
def test_r9_safe_class_dependency_does_not_false_positive() -> None:
    app = FastAPI()

    @app.get("/g2c", response_model=_Safe, dependencies=[Depends(_SafeClassDep)])
    def h() -> Any:
        return _Safe(id="ok")

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert not any(v.target.startswith("GET /g2c") for v in auditor.violations)


# =======================================================================================
# R10 — principled structured-producing-call classification; class __new__ dependency.
# =======================================================================================
DictAlias = dict  # a module-level alias bound to the builtin dict constructor (H1d)


class _GuardNewStructured:
    def __new__(cls, email: str = "nobody@example.invalid") -> _GuardNewStructured:
        # H2a: FastAPI instantiates a class dependency, running __new__, which leaks here.
        raise HTTPException(status_code=403, detail={"patientEmail": email})


# --- H1a: a mapping-dump method detail (record.model_dump()) is unwaivable structured --
def test_r10_model_dump_detail_is_unwaivable() -> None:
    app = FastAPI()

    @app.get("/h1a", response_model=_Safe)
    def h(bad: bool = False) -> Any:
        if bad:  # pragma: no cover - only the static shape matters
            rec = _Safe(id="x")
            raise HTTPException(status_code=400, detail=rec.model_dump())
        return _Safe(id="ok")

    waivers = {f"GET /h1a {_HTTP_DETAIL_KEY}": "#96 bounded str(exc) on /h1a"}
    auditor = AUDIT.Auditor(waivers)
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic" and v.target == f"GET /h1a {_HTTP_STRUCTURED_KEY}"
        for v in auditor.violations
    )


# --- H1b: an attribute-form collection constructor (collections.OrderedDict) structured -
def test_r10_attribute_collection_constructor_detail_is_unwaivable() -> None:
    app = FastAPI()

    @app.get("/h1b", response_model=_Safe)
    def h(bad: bool = False) -> Any:
        if bad:  # pragma: no cover
            raise HTTPException(
                status_code=400,
                detail=collections.OrderedDict(patientEmail="nobody@example.invalid"),
            )
        return _Safe(id="ok")

    waivers = {f"GET /h1b {_HTTP_DETAIL_KEY}": "#96 bounded str(exc) on /h1b"}
    auditor = AUDIT.Auditor(waivers)
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic" and v.target == f"GET /h1b {_HTTP_STRUCTURED_KEY}"
        for v in auditor.violations
    )


# --- H1c: json.loads(...) returns a parsed structure → unwaivable structured -----------
def test_r10_json_loads_detail_is_unwaivable() -> None:
    app = FastAPI()

    @app.get("/h1c", response_model=_Safe)
    def h(bad: bool = False) -> Any:
        if bad:  # pragma: no cover
            raw = '{"patientEmail": "nobody@example.invalid"}'
            raise HTTPException(status_code=400, detail=json.loads(raw))
        return _Safe(id="ok")

    waivers = {f"GET /h1c {_HTTP_DETAIL_KEY}": "#96 bounded str(exc) on /h1c"}
    auditor = AUDIT.Auditor(waivers)
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic" and v.target == f"GET /h1c {_HTTP_STRUCTURED_KEY}"
        for v in auditor.violations
    )


# --- H1d: a module-level dict-alias constructor call → unwaivable structured ------------
def test_r10_module_alias_constructor_detail_is_unwaivable() -> None:
    app = FastAPI()

    @app.get("/h1d", response_model=_Safe)
    def h(bad: bool = False) -> Any:
        if bad:  # pragma: no cover
            raise HTTPException(
                status_code=400, detail=DictAlias(patientEmail="nobody@example.invalid")
            )
        return _Safe(id="ok")

    waivers = {f"GET /h1d {_HTTP_DETAIL_KEY}": "#96 bounded str(exc) on /h1d"}
    auditor = AUDIT.Auditor(waivers)
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic" and v.target == f"GET /h1d {_HTTP_STRUCTURED_KEY}"
        for v in auditor.violations
    )


# --- H1e: str(...) and an interpolated f-string detail stay waivable-scalar -------------
def test_r10_str_and_fstring_detail_stay_waivable() -> None:
    app = FastAPI()

    @app.get("/h1e", response_model=_Safe)
    def h(bad: bool = False) -> Any:
        if bad:  # pragma: no cover
            raise HTTPException(status_code=400, detail=str(bad))
        return _Safe(id="ok")

    @app.get("/h1efs", response_model=_Safe)
    def hfs(bad: bool = False) -> Any:
        if bad:  # pragma: no cover
            raise HTTPException(status_code=400, detail=f"failure for {bad}")
        return _Safe(id="ok")

    waivers = {
        f"GET /h1e {_HTTP_DETAIL_KEY}": "#96 bounded str(exc)",
        f"GET /h1efs {_HTTP_DETAIL_KEY}": "#96 bounded f-string",
    }
    auditor = AUDIT.Auditor(waivers)
    auditor.audit_app(app)
    assert not any(v.target.startswith("GET /h1e ") for v in auditor.violations)
    assert not any(v.target.startswith("GET /h1efs ") for v in auditor.violations)


# --- H1f: a handler returning record.model_dump() flags as raw-structured ---------------
def test_r10_model_dump_return_flags_raw() -> None:
    app = FastAPI()

    @app.get("/h1f", response_model=_Safe)
    def h() -> Any:
        rec = _Safe(id="x")
        return rec.model_dump()

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and v.target == "GET /h1f" for v in auditor.violations)


# --- H2a: Depends(Guard) whose __new__ raises a structured detail flags unwaivable ------
def test_r10_class_dependency_new_structured_detail_flags() -> None:
    app = FastAPI()

    @app.get("/h2a", response_model=_Safe, dependencies=[Depends(_GuardNewStructured)])
    def h() -> Any:
        return _Safe(id="ok")

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic" and v.target == f"GET /h2a {_HTTP_STRUCTURED_KEY}"
        for v in auditor.violations
    )


# --- H2b: a plain safe class dependency still does NOT false-positive -------------------
def test_r10_safe_class_dependency_still_not_false_positive() -> None:
    app = FastAPI()

    @app.get("/h2b", response_model=_Safe, dependencies=[Depends(_SafeClassDep)])
    def h() -> Any:
        return _Safe(id="ok")

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert not any(v.target.startswith("GET /h2b") for v in auditor.violations)


# =======================================================================================
# R11 — jsonable_encoder structure encoder (I1); aliased Response-subclass raw return (I2).
# =======================================================================================
class _PatientR11(BaseModel):
    patientEmail: str


# --- I1a: jsonable_encoder(...) detail on a #96-waived route → unwaivable structured ----
def test_r11_jsonable_encoder_detail_is_unwaivable() -> None:
    app = FastAPI()

    @app.get("/i1a", response_model=_Safe)
    def h(bad: bool = False) -> Any:
        if bad:  # pragma: no cover - only the static shape matters
            raise HTTPException(
                status_code=400,
                detail=jsonable_encoder(_PatientR11(patientEmail="nobody@example.invalid")),
            )
        return _Safe(id="ok")

    waivers = {f"GET /i1a {_HTTP_DETAIL_KEY}": "#96 bounded str(exc) on /i1a"}
    auditor = AUDIT.Auditor(waivers)
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic" and v.target == f"GET /i1a {_HTTP_STRUCTURED_KEY}"
        for v in auditor.violations
    )


# --- I1b: a local alias of jsonable_encoder is likewise unwaivable structured -----------
def test_r11_jsonable_encoder_alias_detail_is_unwaivable() -> None:
    app = FastAPI()

    @app.get("/i1b", response_model=_Safe)
    def h(bad: bool = False) -> Any:
        if bad:  # pragma: no cover
            enc = jsonable_encoder
            raise HTTPException(
                status_code=400,
                detail=enc(_PatientR11(patientEmail="nobody@example.invalid")),
            )
        return _Safe(id="ok")

    waivers = {f"GET /i1b {_HTTP_DETAIL_KEY}": "#96 bounded str(exc) on /i1b"}
    auditor = AUDIT.Auditor(waivers)
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic" and v.target == f"GET /i1b {_HTTP_STRUCTURED_KEY}"
        for v in auditor.violations
    )


# --- I1c: a handler returning jsonable_encoder(model) flags as raw-structured -----------
def test_r11_jsonable_encoder_return_flags_raw() -> None:
    app = FastAPI()

    @app.get("/i1c", response_model=_Safe)
    def h() -> Any:
        return jsonable_encoder(_PatientR11(patientEmail="nobody@example.invalid"))

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and v.target == "GET /i1c" for v in auditor.violations)


# --- I2a: a locally-aliased Response constructor return is caught by identity -----------
def test_r11_local_response_alias_return_flags_raw() -> None:
    app = FastAPI()

    @app.get("/i2a", response_model=_Safe)
    def h() -> Any:
        rt = JSONResponse
        return rt(content={"patientEmail": "nobody@example.invalid"})

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    i2a = [v for v in auditor.violations if v.target == "GET /i2a"]
    assert i2a and any("JSONResponse" in v.message for v in i2a)


# --- I2b: regression — a direct JSONResponse(content=...) return still flags ------------
def test_r11_direct_response_return_still_flags() -> None:
    app = FastAPI()

    @app.get("/i2b", response_model=_Safe)
    def h() -> Any:
        return JSONResponse(content={"patientEmail": "nobody@example.invalid"})

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and v.target == "GET /i2b" for v in auditor.violations)


# --- I2c: regression — a non-Response local alias is NOT treated as a raw Response ------
def test_r11_non_response_alias_not_treated_as_response() -> None:
    app = FastAPI()

    @app.get("/i2c", response_model=_Safe)
    def h() -> Any:
        coerce = str
        return coerce("ok")

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    i2c = [v for v in auditor.violations if v.target.startswith("GET /i2c")]
    assert not any("Response" in v.message for v in i2c)


# ======================================================================================
# R12 (J1/J2/J3): attribute-bound structure-encoder aliases, attribute-bound Response
# aliases, and dependency-function RETURN auditing (one level). Synthetic fake data only.
# ======================================================================================


def _j3a_response_dependency() -> Any:
    # J3a: a dependency that RETURNS a raw structured Response bypasses response_model.
    return responses.JSONResponse(content={"patientEmail": "patient@example.invalid"})


def _j3b_safe_dependency() -> Any:
    # J3b: a dependency returning a bounded model must NOT false-positive.
    return _Safe(id="ok")


_J3A_DEP = Depends(_j3a_response_dependency)
_J3B_DEP = Depends(_j3b_safe_dependency)


# --- J1a: an attribute-bound jsonable_encoder alias detail is unwaivable structured -----
def test_r12_attribute_bound_encoder_alias_detail_is_unwaivable() -> None:
    app = FastAPI()

    @app.get("/j1a", response_model=_Safe)
    def h(bad: bool = False) -> Any:
        if bad:  # pragma: no cover - only the static shape matters
            encode = encoders.jsonable_encoder
            raise HTTPException(
                status_code=400,
                detail=encode(_PatientR11(patientEmail="patient@example.invalid")),
            )
        return _Safe(id="ok")

    waivers = {f"GET /j1a {_HTTP_DETAIL_KEY}": "#96 bounded str(exc) on /j1a"}
    auditor = AUDIT.Auditor(waivers)
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic" and v.target == f"GET /j1a {_HTTP_STRUCTURED_KEY}"
        for v in auditor.violations
    )


# --- J2a: an attribute-bound Response alias return is caught by identity ----------------
def test_r12_attribute_bound_response_alias_return_flags_raw() -> None:
    app = FastAPI()

    @app.get("/j2a", response_model=_Safe)
    def h() -> Any:
        rt = responses.JSONResponse
        return rt(content={"patientEmail": "patient@example.invalid"})

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    j2a = [v for v in auditor.violations if v.target == "GET /j2a"]
    assert j2a and any("JSONResponse" in v.message for v in j2a)


# --- J2b: a non-Response attribute alias is NOT treated as a raw Response ---------------
def test_r12_non_response_attribute_alias_not_treated_as_response() -> None:
    app = FastAPI()

    @app.get("/j2b", response_model=_Safe)
    def h() -> Any:
        cwd = os.getcwd
        return cwd()

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    j2b = [v for v in auditor.violations if v.target.startswith("GET /j2b")]
    assert not any("Response" in v.message for v in j2b)


# --- J3a: a dependency RETURNING a raw structured Response is flagged at its source -----
def test_r12_dependency_return_raw_response_flags() -> None:
    app = FastAPI()

    @app.get("/j3a", response_model=_Safe)
    def h(value: Any = _J3A_DEP) -> Any:
        return value

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic"
        and v.target == "GET /j3a <dependency _j3a_response_dependency raw return>"
        for v in auditor.violations
    )


# --- J3b: a dependency returning a bounded model does NOT false-positive ----------------
def test_r12_dependency_return_bounded_model_no_false_positive() -> None:
    app = FastAPI()

    @app.get("/j3b", response_model=_Safe)
    def h(value: Any = _J3B_DEP) -> Any:
        return value

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert not any(v.target.startswith("GET /j3b") for v in auditor.violations)


# ======================================================================================
# R13 (K1): may-reach / UNION resolution of branch-conditional local assignments. A raw or
# structured value reachable on ANY branch of a returned/detail name must be flagged; a name
# is scalar only if ALL its assignments are provably-string. Synthetic fake data only.
# ======================================================================================


def _k1a_branch_dep(leak: bool = False) -> Any:
    # K1a: raw Response in the `if` branch, safe model in `else` — union must flag it.
    if leak:  # noqa: SIM108 — explicit branches exercise may-reach union, not a ternary
        result = JSONResponse({"patientEmail": "patient@example.invalid"})
    else:
        result = _Safe(id="ok")
    return result


def _k1b_branch_dep(leak: bool = False) -> Any:
    # K1b: same as K1a with branch order swapped (raw in the `else`).
    if leak:  # noqa: SIM108 — explicit branches exercise may-reach union, not a ternary
        result = _Safe(id="ok")
    else:
        result = JSONResponse({"patientEmail": "patient@example.invalid"})
    return result


_K1A_DEP = Depends(_k1a_branch_dep)
_K1B_DEP = Depends(_k1b_branch_dep)


# --- K1a: a dependency whose `if` branch binds a raw Response is flagged (union) --------
def test_r13_dependency_branch_raw_in_if_flags() -> None:
    app = FastAPI()

    @app.get("/k1a", response_model=_Safe)
    def h(value: Any = _K1A_DEP) -> Any:
        return value

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic"
        and v.target == "GET /k1a <dependency _k1a_branch_dep raw return>"
        for v in auditor.violations
    )


# --- K1b: the same with branch order swapped (raw in the `else`) is also flagged --------
def test_r13_dependency_branch_raw_in_else_flags() -> None:
    app = FastAPI()

    @app.get("/k1b", response_model=_Safe)
    def h(value: Any = _K1B_DEP) -> Any:
        return value

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic"
        and v.target == "GET /k1b <dependency _k1b_branch_dep raw return>"
        for v in auditor.violations
    )


# --- K1c: a HANDLER-side branch-conditional raw Response return is flagged (union) -----
def test_r13_handler_branch_raw_return_flags() -> None:
    app = FastAPI()

    @app.get("/k1c", response_model=_Safe)
    def h(cond: bool = False) -> Any:
        if cond:
            result = JSONResponse({"patientEmail": "patient@example.invalid"})
        else:
            result = _Safe(id="ok")
        return result

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and v.target == "GET /k1c" for v in auditor.violations)


# --- K1d: a branch-conditional structured detail is UNWAIVABLE (any-structured wins) ----
def test_r13_detail_branch_structured_is_unwaivable() -> None:
    app = FastAPI()

    @app.get("/k1d", response_model=_Safe)
    def h(cond: bool = False) -> Any:
        if cond:  # pragma: no cover - only the static shape matters
            detail = jsonable_encoder(_PatientR11(patientEmail="patient@example.invalid"))
        else:
            detail = "safe"
        raise HTTPException(status_code=400, detail=detail)

    waivers = {f"GET /k1d {_HTTP_DETAIL_KEY}": "#96 scalar on /k1d"}
    auditor = AUDIT.Auditor(waivers)
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic" and v.target == f"GET /k1d {_HTTP_STRUCTURED_KEY}"
        for v in auditor.violations
    )


# --- K1e: REGRESSION — all-non-structured (f-string / str()) branches stay scalar -------
def test_r13_detail_branch_all_string_stays_scalar() -> None:
    app = FastAPI()

    @app.get("/k1e", response_model=_Safe)
    def h(cond: bool = False, x: str = "y") -> Any:
        if cond:  # noqa: SIM108 — explicit branches exercise may-reach union, not a ternary
            detail = f"a {x}"
        else:
            detail = str(cond)
        raise HTTPException(status_code=400, detail=detail)

    # With only the SCALAR waiver present, a scalar detail is silenced; a structured
    # escalation would key to the (unwaived) structured suffix and surface as a violation.
    waivers = {f"GET /k1e {_HTTP_DETAIL_KEY}": "#96 scalar on /k1e"}
    auditor = AUDIT.Auditor(waivers)
    auditor.audit_app(app)
    assert not any(v.target.startswith("GET /k1e") for v in auditor.violations)


# --- K1f: REGRESSION — a straight-line single safe assignment is NOT flagged ------------
def test_r13_handler_single_safe_assignment_no_false_positive() -> None:
    app = FastAPI()

    @app.get("/k1f", response_model=_Safe)
    def h() -> Any:
        result = _Safe(id="ok")
        return result

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert not any(v.target.startswith("GET /k1f") for v in auditor.violations)


# ======================================================================================
# R14 (L1): walrus (``:=`` / ``ast.NamedExpr``) bindings must be visible to resolution. A
# name bound by a walrus, or a value node that IS a walrus, classifies by its value (one
# level). Synthetic fake data only.
# ======================================================================================


# --- L1a: a walrus-bound structured detail (walrus in the `if` test) is unwaivable ------
def test_r14_walrus_bound_detail_in_if_test_is_unwaivable() -> None:
    app = FastAPI()

    @app.get("/l1a", response_model=_Safe)
    def h() -> Any:
        if detail := jsonable_encoder(_PatientR11(patientEmail="patient@example.invalid")):
            raise HTTPException(status_code=400, detail=detail)
        return _Safe(id="ok")  # pragma: no cover - only the static shape matters

    waivers = {f"GET /l1a {_HTTP_DETAIL_KEY}": "#96 scalar on /l1a"}
    auditor = AUDIT.Auditor(waivers)
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic" and v.target == f"GET /l1a {_HTTP_STRUCTURED_KEY}"
        for v in auditor.violations
    )


# --- L1b: a walrus directly in the detail arg classifies by its value (unwaivable) ------
def test_r14_walrus_inline_detail_arg_is_unwaivable() -> None:
    app = FastAPI()

    @app.get("/l1b", response_model=_Safe)
    def h(bad: bool = False) -> Any:
        pt = _PatientR11(patientEmail="patient@example.invalid")
        if bad:  # pragma: no cover
            raise HTTPException(status_code=400, detail=(d := jsonable_encoder(pt)))  # noqa: F841
        return _Safe(id="ok")

    waivers = {f"GET /l1b {_HTTP_DETAIL_KEY}": "#96 scalar on /l1b"}
    auditor = AUDIT.Auditor(waivers)
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic" and v.target == f"GET /l1b {_HTTP_STRUCTURED_KEY}"
        for v in auditor.violations
    )


# --- L1c: a walrus raw-Response return classifies by its value (flagged raw) ------------
def test_r14_walrus_raw_return_flags() -> None:
    app = FastAPI()

    @app.get("/l1c", response_model=_Safe)
    def h() -> Any:
        return (x := JSONResponse({"patientEmail": "patient@example.invalid"}))  # noqa: F841

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and v.target == "GET /l1c" for v in auditor.violations)


# --- L1d: REGRESSION — a walrus bound to a plain bool + string detail stays clean -------
def test_r14_walrus_bool_with_string_detail_no_false_positive() -> None:
    app = FastAPI()

    @app.get("/l1d", response_model=_Safe)
    def h(x: int = 0) -> Any:
        if ok := bool(x):  # pragma: no cover - only the static shape matters
            raise HTTPException(status_code=400, detail="static string")
        return _Safe(id=str(ok))

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert not any(v.target.startswith("GET /l1d") for v in auditor.violations)


# ======================================================================================
# R15 (M1): tuple/list UNPACKING targets must be captured by ``build_assignment_map``. A
# statically pairable ``(a, b) = (x, y)`` binds each name element-wise; an unpairable RHS
# (non-literal, arity mismatch or any ``*``) FAILS CLOSED, binding every unpacked name to
# the whole RHS so it inherits that RHS's raw/structured classification. Synthetic data.
# ======================================================================================


def _returns_tuple() -> Any:
    # M1c: a module function returning a raw dict-bearing tuple. Because the RHS is a Call
    # (not a literal Tuple/List), an unpacking assignment cannot be paired element-wise, so
    # every unpacked name fails closed to this whole call (surfaced, never silently scalar).
    return (JSONResponse({"patientEmail": "tuple@example.invalid"}), 400)


# --- M1a: a pairable tuple whose detail element is structured is UNWAIVABLE --------------
def test_r15_pairable_tuple_structured_detail_is_unwaivable() -> None:
    app = FastAPI()

    @app.get("/m1a", response_model=_Safe)
    def h() -> Any:
        detail, status = (jsonable_encoder(_PatientR11(patientEmail="tuple@example.invalid")), 400)
        raise HTTPException(status_code=status, detail=detail)

    # A route-level scalar waiver must NOT silence the structured (encoded) detail element.
    waivers = {f"GET /m1a {_HTTP_DETAIL_KEY}": "#96 scalar on /m1a"}
    auditor = AUDIT.Auditor(waivers)
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic" and v.target == f"GET /m1a {_HTTP_STRUCTURED_KEY}"
        for v in auditor.violations
    )
    assert not any(v.target == f"GET /m1a {_HTTP_DETAIL_KEY}" for v in auditor.violations)


# --- M1b: a pairable list whose element is a raw Response bypasses the model (raw) -------
def test_r15_pairable_list_raw_return_flags() -> None:
    app = FastAPI()

    @app.get("/m1b", response_model=_Safe)
    def h() -> Any:
        [a, _b] = [JSONResponse({"patientEmail": "tuple@example.invalid"}), 1]
        return a

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and v.target == "GET /m1b" for v in auditor.violations)


# --- M1c: an unpairable call RHS fails closed — the name is surfaced (never silent) ------
def test_r15_failclosed_unpairable_call_detail_is_flagged() -> None:
    app = FastAPI()

    @app.get("/m1c", response_model=_Safe)
    def h() -> Any:
        detail, status = _returns_tuple()
        raise HTTPException(status_code=status, detail=detail)

    # Fail closed: ``detail`` binds to the whole unknowable call, so it is flagged (as an
    # opaque scalar requiring an explicit human waiver) rather than silently passed.
    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.target.startswith("GET /m1c") for v in auditor.violations)


# --- M1e: an unpairable arity mismatch fails closed to the whole (structured) RHS --------
def test_r15_failclosed_arity_mismatch_binds_whole_rhs_structured() -> None:
    app = FastAPI()

    @app.get("/m1e", response_model=_Safe)
    def h() -> Any:  # pragma: no cover - only the static shape matters
        detail, _extra = (jsonable_encoder(_PatientR11(patientEmail="tuple@example.invalid")),)
        raise HTTPException(status_code=400, detail=detail)

    # Arity mismatch (2 names, 1-tuple) is unpairable → every name binds to the whole tuple
    # literal, which is structured → UNWAIVABLE (a scalar waiver must not silence it).
    waivers = {f"GET /m1e {_HTTP_DETAIL_KEY}": "#96 scalar on /m1e"}
    auditor = AUDIT.Auditor(waivers)
    auditor.audit_app(app)
    assert any(
        v.kind == "dynamic" and v.target == f"GET /m1e {_HTTP_STRUCTURED_KEY}"
        for v in auditor.violations
    )


# --- M1d: REGRESSION — a pairable all-scalar tuple stays clean (no new waiver) -----------
def test_r15_pairable_scalar_tuple_no_false_positive() -> None:
    app = FastAPI()

    @app.get("/m1d", response_model=_Safe)
    def h() -> Any:
        a, b = ("static", 200)
        raise HTTPException(status_code=b, detail=a)

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert not any(v.target.startswith("GET /m1d") for v in auditor.violations)


# --- M1-inv: the real tree stays EXIT-0-equivalent with EXACTLY 11 tracked waivers -------
def test_r15_real_tree_invariant_waivers_intact() -> None:
    auditor = AUDIT.run_audit(_REPO_ROOT)
    assert auditor.violations == []
    assert len(auditor.waived) == 11


# ======================================================================================
# R16 (N1): a helper returning a literal tuple/list hides a raw element from an unpacking
# caller. R15 fail-closes the unpack (binding each name to the whole ``make_pair()`` call),
# and the one-level helper-return classifier now inspects a directly-returned literal
# tuple/list element-wise — a raw element (any unpack position) fails closed. Synthetic data.
# ======================================================================================


def _n1_make_pair() -> Any:
    # N1a: a literal TUPLE whose first element is a raw Response — invisible to a bare-return
    # classifier until its elements are inspected one level.
    return (JSONResponse({"patientEmail": "r16@example.invalid"}), 200)


def _n1_make_pair_list() -> Any:
    # N1b: the same shape via a literal LIST return.
    return [JSONResponse({"patientEmail": "r16@example.invalid"}), 200]


def _n1_make_scalar_pair() -> Any:
    # N1d: an all-scalar pair — no raw element, must stay clean.
    return ("static", 200)


# --- N1a: unpacking a helper-returned raw-tuple element is detected ----------------------
def test_r16_helper_tuple_element_raw_unpack_flags() -> None:
    app = FastAPI()

    @app.get("/n1a", response_model=_Safe)
    def h() -> Any:
        response, status = _n1_make_pair()
        return response

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and v.target == "GET /n1a" for v in auditor.violations)


# --- N1b: the same, via a helper returning a literal LIST --------------------------------
def test_r16_helper_list_element_raw_unpack_flags() -> None:
    app = FastAPI()

    @app.get("/n1b", response_model=_Safe)
    def h() -> Any:
        response, status = _n1_make_pair_list()
        return response

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and v.target == "GET /n1b" for v in auditor.violations)


# --- N1c: the raw element in the OTHER unpack position is still detected -----------------
def test_r16_helper_tuple_raw_element_swapped_order_flags() -> None:
    app = FastAPI()

    @app.get("/n1c", response_model=_Safe)
    def h() -> Any:
        status, response = _n1_make_pair()
        return response

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert any(v.kind == "dynamic" and v.target == "GET /n1c" for v in auditor.violations)


# --- N1d: REGRESSION — an all-scalar helper pair stays clean (no new waiver) -------------
def test_r16_helper_scalar_pair_no_false_positive() -> None:
    app = FastAPI()

    @app.get("/n1d", response_model=_Safe)
    def h() -> Any:
        response, status = _n1_make_scalar_pair()
        return response

    auditor = AUDIT.Auditor({})
    auditor.audit_app(app)
    assert not any(v.target.startswith("GET /n1d") for v in auditor.violations)


# --- N1e: the real tree stays EXIT-0-equivalent with EXACTLY 11 tracked waivers ----------
def test_r16_real_tree_invariant_waivers_intact() -> None:
    auditor = AUDIT.run_audit(_REPO_ROOT)
    assert auditor.violations == []
    assert len(auditor.waived) == 11


# ======================================================================================
# R17 (#91 R2): the handler-bypass detector no longer trusts an ARBITRARY attribute call for a
# route whose response_model transitively contains a redaction-required model (ResourceNode /
# ModuleRunResult). Such a route MUST route through a reviewed egress projection
# (``_estate_egress.redact`` / ``redact_node_tags`` / ``redact_tree`` /
# ``_redact_run_result_for_egress``); a raw ``return store.get_estate(...)`` is failed closed so it
# cannot ride the model-wide ``ResourceNode.tags`` / ``ModuleRunResult.extra`` waiver. Synthetic.
# ======================================================================================
from shared.contracts import ResourceNode as _RN  # noqa: E402
from shared.contracts import redact_node_tags as _redact_node_tags  # noqa: E402


class _FakeEstateStore:
    def get_estate(self, workload: str) -> list[_RN]:
        return [_RN(id="n", name="n", type="t", tags={"patientName": "AliceSmith"})]


class _FakeEstateEgress:
    """Mirrors ``_EstateEgress`` — a reviewed ``.redact`` projection the boundary trusts."""

    @staticmethod
    def redact(nodes: list[_RN]) -> list[_RN]:
        return [_redact_node_tags(n) for n in nodes]


_fake_estate_store = _FakeEstateStore()
_fake_estate_egress = _FakeEstateEgress()


def test_r17_raw_return_of_redaction_required_model_fails_closed() -> None:
    app = FastAPI()

    @app.get("/raw", response_model=list[_RN])
    def raw() -> Any:
        # Rides the model-wide ResourceNode.tags waiver but applies NO redaction — must FAIL.
        return _fake_estate_store.get_estate("w")

    # Waive the open-key-type ResourceNode.tags exactly like the real tree does.
    auditor = AUDIT.Auditor({"ResourceNode.tags": "#91"})
    auditor.audit_app(app)
    targets = [v.target for v in auditor.violations]
    assert "GET /raw <unredacted egress>" in targets, targets


def test_r17_sanitized_projection_passes() -> None:
    app = FastAPI()

    @app.get("/sanitized", response_model=list[_RN])
    def sanitized() -> Any:
        # Routes through the reviewed ``.redact`` projection (like ``_estate_egress.redact``) —
        # must PASS.
        return _fake_estate_egress.redact(_fake_estate_store.get_estate("w"))

    auditor = AUDIT.Auditor({"ResourceNode.tags": "#91"})
    auditor.audit_app(app)
    assert not any(v.target.startswith("GET /sanitized") for v in auditor.violations), (
        auditor.violations
    )


def test_r17_unredacted_egress_is_unwaivable() -> None:
    # Even a route-scoped waiver cannot silence the raw-egress finding (a model-wide waiver must
    # never hide a NEW unsanitized endpoint).
    app = FastAPI()

    @app.get("/raw2", response_model=list[_RN])
    def raw2() -> Any:
        return _fake_estate_store.get_estate("w")

    auditor = AUDIT.Auditor(
        {"ResourceNode.tags": "#91", "GET /raw2 <unredacted egress>": "#91"}
    )
    auditor.audit_app(app)
    assert any(v.target == "GET /raw2 <unredacted egress>" for v in auditor.violations)


def test_r17_real_tree_invariant_waivers_intact() -> None:
    auditor = AUDIT.run_audit(_REPO_ROOT)
    assert auditor.violations == []
    assert len(auditor.waived) == 11


# ======================================================================================
# R18 (#91 R3, finding 3): the trusted-projection detector resolves calls to their EXACT reviewed
# definitions (by identity / structural proof), so a DECOY ``.redact`` and a PARTIALLY-sanitized
# collection FAIL, a genuinely-sanitized route PASSES, and the fail-closed redaction check runs even
# when the route is covered by a route-level unbounded-mapping waiver. Synthetic.
# ======================================================================================
class _DecoyLog:
    """A decoy whose ``redact`` is an IDENTITY wrapper — it sanitizes nothing."""

    @staticmethod
    def redact(value: Any) -> Any:
        return value


_decoy_log = _DecoyLog()


class _FakeGraphResponse(BaseModel):
    """Mirrors the real ``GraphResponse`` wrapper — a bounded model whose ``nodes`` field carries
    the redaction-required ``ResourceNode`` surface."""

    nodes: list[_RN]
    graphRevision: int = 0


def test_r18_decoy_redact_wrapper_fails() -> None:
    app = FastAPI()

    @app.get("/decoy", response_model=list[_RN])
    def decoy() -> Any:
        # A call named ``.redact`` that is NOT a reviewed projection (an identity decoy) must not be
        # trusted merely because its simple name matches — must FAIL.
        return _decoy_log.redact(_fake_estate_store.get_estate("w"))

    auditor = AUDIT.Auditor({"ResourceNode.tags": "#91"})
    auditor.audit_app(app)
    assert any(v.target == "GET /decoy <unredacted egress>" for v in auditor.violations), (
        auditor.violations
    )


def test_r18_partially_sanitized_collection_fails() -> None:
    app = FastAPI()

    @app.get("/partial", response_model=list[_RN])
    def partial() -> Any:
        # The first list is genuinely sanitized, but concatenating the RAW estate leaves unsanitized
        # nodes in the returned collection — must FAIL (EVERY returned element must be sanitized).
        return _fake_estate_egress.redact(
            _fake_estate_store.get_estate("w")
        ) + _fake_estate_store.get_estate("w")

    auditor = AUDIT.Auditor({"ResourceNode.tags": "#91"})
    auditor.audit_app(app)
    assert any(v.target == "GET /partial <unredacted egress>" for v in auditor.violations), (
        auditor.violations
    )


def test_r18_genuinely_sanitized_route_passes() -> None:
    app = FastAPI()

    @app.get("/clean", response_model=_FakeGraphResponse)
    def clean() -> Any:
        # Every ``ResourceNode`` in the wrapper's redaction-required ``nodes`` field flows through
        # the reviewed ``redact_node_tags`` projection (mirrors the real ``get_graph``) — PASS.
        return _FakeGraphResponse(
            nodes=[_redact_node_tags(n) for n in _fake_estate_store.get_estate("w")],
            graphRevision=1,
        )

    auditor = AUDIT.Auditor({"ResourceNode.tags": "#91"})
    auditor.audit_app(app)
    assert not any(v.target.startswith("GET /clean") for v in auditor.violations), (
        auditor.violations
    )


def test_r18_redaction_check_runs_under_route_unbounded_waiver() -> None:
    app = FastAPI()

    @app.get("/mapping", response_model=dict[str, _RN])
    def mapping() -> Any:
        # The response_model is itself an unbounded mapping (a route-level unbounded waiver), yet a
        # raw ``ResourceNode`` value must STILL be caught by the fail-closed redaction check.
        return {"a": _fake_estate_store.get_estate("w")[0]}

    auditor = AUDIT.Auditor({
        "GET /mapping": "#91",  # route-level unbounded-mapping waiver
        "ResourceNode.tags": "#91",
    })
    auditor.audit_app(app)
    # The unbounded surface itself is waived...
    assert any(k == "GET /mapping" for k, _i, _n in auditor.waived)
    # ...but the redaction check STILL fires (unwaivable) even under the route-level waiver.
    assert any(v.target == "GET /mapping <unredacted egress>" for v in auditor.violations), (
        auditor.violations
    )


# ======================================================================================
# R18 (#91 R4, FIX 3): the constructor-sanitization check maps a redaction-required field to EVERY
# accepted input name (its ``validation_alias`` / ``alias`` / ``AliasChoices`` members), so a
# wrapper populated through a validation alias (``Model(items=raw_nodes)`` for field ``nodes``)
# cannot smuggle RAW nodes past the field-name match. Synthetic.
# ======================================================================================
class _AliasedGraphResponse(BaseModel):
    """A wrapper whose redaction-required ``nodes`` field is POPULATED via the ``items`` alias."""

    nodes: list[_RN] = Field(validation_alias=AliasChoices("items", "nodes"))
    graphRevision: int = 0


def test_r18_aliased_field_raw_nodes_fails() -> None:
    app = FastAPI()

    @app.get("/aliased-raw", response_model=_AliasedGraphResponse)
    def aliased_raw() -> Any:
        # Field ``nodes`` populated through its ``items`` validation alias with RAW nodes — the
        # audit must map ``items`` back to the redaction-required field and FAIL closed.
        return _AliasedGraphResponse(items=_fake_estate_store.get_estate("w"), graphRevision=1)

    auditor = AUDIT.Auditor({"ResourceNode.tags": "#91"})
    auditor.audit_app(app)
    assert any(v.target == "GET /aliased-raw <unredacted egress>" for v in auditor.violations), (
        auditor.violations
    )


def test_r18_aliased_field_sanitized_passes() -> None:
    app = FastAPI()

    @app.get("/aliased-clean", response_model=_AliasedGraphResponse)
    def aliased_clean() -> Any:
        # Same alias, but every node flows through the reviewed ``redact_node_tags`` projection.
        return _AliasedGraphResponse(
            items=[_redact_node_tags(n) for n in _fake_estate_store.get_estate("w")],
            graphRevision=1,
        )

    auditor = AUDIT.Auditor({"ResourceNode.tags": "#91"})
    auditor.audit_app(app)
    assert not any(v.target.startswith("GET /aliased-clean") for v in auditor.violations), (
        auditor.violations
    )


# ======================================================================================
# R18 (#91 R4, FIX 4): a ``response_model=None`` route still egresses whatever the handler returns.
# The route-level "no response_model" flag is waivable, but a raw ResourceNode/ModuleRunResult
# egress must NEVER ride a waiver — the fail-closed ``<unredacted egress>`` check runs even here.
# Synthetic.
# ======================================================================================
def test_r18_response_model_none_raw_nodes_flagged_even_with_route_waiver() -> None:
    app = FastAPI()

    @app.get("/rawnone")
    def rawnone() -> list[_RN]:
        # No response_model; annotated return is redaction-required and NOT projected — must FAIL
        # even though the route's no-response_model flag is waived.
        return _fake_estate_store.get_estate("w")

    auditor = AUDIT.Auditor({
        "GET /rawnone": "#91",  # route-level "no response_model" waiver
        "ResourceNode.tags": "#91",
    })
    auditor.audit_app(app)
    assert any(v.target == "GET /rawnone <unredacted egress>" for v in auditor.violations), (
        auditor.violations
    )


def test_r18_response_model_none_sanitized_passes() -> None:
    app = FastAPI()

    @app.get("/cleannone")
    def cleannone() -> list[_RN]:
        # No response_model, but every node flows through the reviewed projection — PASS (only the
        # waivable no-response_model flag remains).
        return _fake_estate_egress.redact(_fake_estate_store.get_estate("w"))

    auditor = AUDIT.Auditor({"GET /cleannone": "#91", "ResourceNode.tags": "#91"})
    auditor.audit_app(app)
    assert not any(v.target.endswith("<unredacted egress>") for v in auditor.violations), (
        auditor.violations
    )


def test_r18_response_model_none_response_annotation_raw_nodes_flagged() -> None:
    # R5 (issue #91): an opaque Response/JSONResponse return annotation on a response_model=None
    # route must NOT let a raw redaction-required egress ride a route waiver — the unwaivable
    # redaction check must still fire because a Response body is opaque to static type analysis.
    app = FastAPI()

    @app.get("/rawresp")
    def rawresp() -> JSONResponse:  # Response subclass — was previously treated as "bounded"
        return _fake_estate_store.get_estate("w")  # type: ignore[return-value]

    auditor = AUDIT.Auditor({"GET /rawresp": "#91", "ResourceNode.tags": "#91"})
    auditor.audit_app(app)
    assert any(v.target == "GET /rawresp <unredacted egress>" for v in auditor.violations), (
        auditor.violations
    )


def test_r18_response_model_none_response_annotation_sanitized_passes() -> None:
    # Guards against the R5 fix over-flagging: a Response-annotated route whose body flows through
    # the reviewed projection must still PASS (only the waivable no-response_model flag remains).
    app = FastAPI()

    @app.get("/cleanresp")
    def cleanresp() -> JSONResponse:  # Response subclass, but data is projected
        return _fake_estate_egress.redact(_fake_estate_store.get_estate("w"))  # type: ignore[return-value]

    auditor = AUDIT.Auditor({"GET /cleanresp": "#91", "ResourceNode.tags": "#91"})
    auditor.audit_app(app)
    assert not any(v.target.endswith("<unredacted egress>") for v in auditor.violations), (
        auditor.violations
    )