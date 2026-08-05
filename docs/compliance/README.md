# Compliance

HITRUST CSF alignment and the automated, in-boundary compliance guardrails for the Workloads
Platform. Everything here is **keyless, in-boundary, fail-closed**, and contains **no** customer
data or PII.

## Contents

- **[`hitrust-control-map.md`](hitrust-control-map.md)** — maps HITRUST CSF control domains to the
  platform's **implemented** controls, each with a concrete evidence reference and an honest
  **Implemented / Partial / Planned** status. Includes the **egress-boundary field inventory**.

## Enforced in CI

Two static, dependency-light checks run on every pull request (job **`compliance`** in
[`.github/workflows/security.yml`](../../.github/workflows/security.yml)):

| Check | Script | HITRUST domain | What it guarantees |
|-------|--------|----------------|--------------------|
| No-PII egress | [`scripts/audit_no_pii_egress.py`](../../scripts/audit_no_pii_egress.py) | 09 / 13 — transmission & privacy | Imports the FastAPI app and enumerates the **real** response models from every route (`response_model` + declared `responses`), then **recursively** walks the whole serialized schema graph (nested models, `list`/`dict`/`Optional`/`Union`, `RootModel`, computed fields; cycle-guarded). Fails closed on a PII field name **or any Pydantic alias** (`serialization_alias`/`alias`/`AliasChoices`), an **inherited** PII field, an **unclassified** field, a route with **no** `response_model`, or an **unbounded open mapping** (`extra="allow"`, `dict[str, Any]`/`Mapping`, `{**x}`/computed dict keys). Pre-existing open mappings are allowed only via a **loud, issue-tracked waiver** (`TRACKED WAIVER (#91)`), never a silent pass. |
| Data residency | [`scripts/check_data_residency.py`](../../scripts/check_data_residency.py) | 07 — data residency | Resolves `var`/`param` indirection and object spreads over bicep and validates **module call-site bindings** across files, failing closed unless every resource `location` provably resolves to `resourceGroup().location` (or a permitted-region literal). A **defaultless** `location` param, a foreign/dynamic value, or an unvalidated call-site binding is a violation. |

Run them locally (the no-PII audit imports the platform's Pydantic models, so install the package
or set `PYTHONPATH=src`; the residency check is stdlib-only):

```bash
pip install -e .                              # or: export PYTHONPATH=src
python scripts/audit_no_pii_egress.py
python scripts/check_data_residency.py
```

Both exit non-zero on a violation and print the exact contract/field or file/line that tripped.

## Known static-analysis limitations

The no-PII-egress auditor is a **static** detector; it over-approximates and fails closed, but a
few dynamic patterns cannot be resolved from source alone and are tracked (not silently ignored):

- **Unresolvable attribute-call returns.** A route declaring a bounded `response_model` whose
  handler does `return service.emit()` bypasses the model only if `service.emit()` returns a
  `Response`/`JSONResponse`. The return type of an arbitrary attribute call (`x.y()`) cannot be
  resolved statically, and blanket-flagging every attribute-call return would false-positive on the
  common **safe** pattern `return store.get_findings()` (a value FastAPI coerces through the declared
  model). The auditor therefore flags only the *resolvable* bypasses (a direct `Response`
  construction, a local name bound to one, or a one-level module-global helper that returns/forwards
  a `Response`). The residual — an *unresolvable* attribute call that happens to return a raw
  `Response` — is left as a **known limitation**, with two compensating controls: (a) returning a
  bare `Response` from a route that declares a bounded `response_model` is an anti-pattern caught in
  review, and (b) the explicit egress allow-list (e.g. the alerts `_notification_payload`) is the
  real transmission boundary. Tracked under **#91**.

## Scope note

Per issue **#63**, this delivers the control mapping + the two CI audits **now**. **Formal HITRUST
certification is deferred to GA.** Documented fast-follows (opaque finding ids #78, bound/redact
free-form egress mappings & raw-dict endpoints #91, per-component identities #79, audit-store WORM
#81, mandatory pack signing) are listed at the end of the control map.
