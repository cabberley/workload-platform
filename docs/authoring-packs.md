# Authoring content packs (workflow guide)

Packs are the **only inbound artifact** in the Workloads Platform — they carry domain knowledge
into a customer boundary as **content, not code** (guardrail #6). This guide walks the end-to-end
authoring workflow: **author → validate → test → sign → export** via the packs studio.

New knowledge belongs in a pack under `content/`, **not** in a Python branch. If you find yourself
editing a module to add a check, signal, dependency, classification, or notification route, stop —
author a pack instead.

## The five pack types and their consuming modules

| Type | Directory | Consumed by | Body schema (authority) |
|------|-----------|-------------|-------------------------|
| workload | `content/workloads` | **Discovery** (`src/modules/discovery/module.py`) — classifies estate resources into workload/tier/role | `src/packs_engine/schemas/workload.schema.json` |
| rule | `content/rules` | **Quality Checks** (`src/modules/quality_checks/module.py`) — applies WAF/WARA/APRL-style checks, emits PASS/FAIL findings | `src/packs_engine/schemas/rule.schema.json` |
| telemetry | `content/telemetry` | **AIOps** (`src/modules/aiops/module.py`) — role-scoped threshold signals feed detection | `src/packs_engine/schemas/telemetry.schema.json` |
| dependency | `content/dependencies` | **Dependency & Blast Radius** (`src/modules/dependency_graph/module.py`) — typed edges merge into the graph, drive blast radius | `src/packs_engine/schemas/dependency.schema.json` |
| ops | `content/ops` | **Alerts & Notifications** (`src/modules/alerts/module.py`) — severity → channel routing | `src/packs_engine/schemas/ops.schema.json` |

The five draft-2020-12 JSON Schemas are the **authority** on valid pack shape (required vs nullable
fields, patterns, enums). Field-by-field docs live in
[`content/templates/README.md`](../content/templates/README.md).

## Where templates live

Starter scaffolds — one per type — are under [`content/templates/<type>/`](../content/templates):

```
content/templates/
  README.md                                  # field-by-field guide (required/optional/enums)
  workload/example-workload-pack.json
  rule/example-rule-pack.json
  telemetry/example-telemetry-pack.json
  dependency/example-dependency-pack.json
  ops/example-ops-pack.json
```

Templates are **scaffolds, not released packs**: `content/templates/` is a **reserved, non-runtime
directory**. The runtime `PacksEngine` skips the whole subtree
(`packs_engine.engine.RESERVED_NONRUNTIME_DIR`), so templates are **never loaded or executed**
against a customer estate — even with `targets: []` they cannot override alert routing, emit false
detections, inject dependency edges, or misclassify resources. They are still **schema-validated in
CI** (`scripts/validate_packs.py` enumerates them independently) and are kept out of the registry
index (`content/registry/index.json`). To DEPLOY a pack you **copy it OUT of `templates/`** into its
by-type directory — a pack left under `templates/` will never run.

## 1. Author — copy and edit a template

1. Copy the template for your type **out of `templates/`** into the real content directory and
   rename it (a pack left under `content/templates/` is a reserved scaffold and will never be
   loaded at runtime):

   ```powershell
   Copy-Item content/templates/rule/example-rule-pack.json content/rules/my-new-rule-pack.json
   ```

2. Edit the copy:
   - Give the `manifest.id` a **unique, stable, kebab-case** id (must not collide with any other
     pack id under `content/`).
   - Set a real `manifest.name`, start `manifest.version` at `1.0.0`, and set `manifest.targets`
     to the workload kinds it applies to (`[]` = all workloads).
   - Replace every `REPLACE ME` / `example-*` placeholder in the `body`. Consult
     [`content/templates/README.md`](../content/templates/README.md) for what each field means and
     which are required vs optional/nullable.
   - Leave `sha256` / `signature` unset — the signing step adds them at release time.

Real, non-placeholder examples to model on:
[`content/rules/waf-security-baseline.json`](../content/rules/waf-security-baseline.json) (a
WAF-Security-derived rule pack, global `targets: []` like `waf-reliability-baseline`) and
[`content/dependencies/multi-tier-web-app.json`](../content/dependencies/multi-tier-web-app.json)
(a reusable web→app→db dependency pack with a mix of redundant/non-redundant edges).

> **Reusable dependency packs are assigned per-workload, not shipped `targets: []`.** A global
> dependency pack would inject invented edges and a fabricated SPOF into *any* unrelated workload
> that reuses generic role names (`web`/`app`/`db`), corrupting its blast-radius. So the example
> above targets the synthetic `multi-tier-demo` workload (`"targets": ["multi-tier-demo"]`) rather
> than `[]` — it demonstrates the capability safely until per-workload pack assignment
> (issue #37) is wired. Global scope stays acceptable for rule baselines, whose per-node tag
> checks are inert on resources that don't carry the tag.

## 2. Validate (schema gate)

Run the same validator CI runs. It enumerates **every** `.json`/`.yaml` under the content root and
validates each against its type schema (fail-closed):

```powershell
python scripts/validate_packs.py content
```

Exit code `0` = all packs valid. A malformed body, a missing/misspelled `manifest`, an unknown
type, or a non-finite telemetry threshold fails the build. **If validation rejects your pack, fix
the pack — never the schema.** Schema changes go through the Architect and an ADR.

## 3. Test through the consuming module

A pack is only "done" when it actually produces the output its module consumes. Add a unit test
that feeds your pack + a **synthetic, clearly-fake** estate into the module and asserts the
expected findings — mirroring the existing module tests
(`tests/unit/test_quality_checks.py`, `tests/unit/test_dependency_graph.py`) and the template
tests in `tests/unit/test_pack_templates.py`. Use a fake `ReadableState` + the real `PacksEngine`
(or a fake packs source) injected via `ModuleContext`; **no real Azure calls**.

```powershell
python -m pytest tests/unit/test_pack_templates.py
```

For example, `test_pack_templates.py` schema-validates every template, then drives
`waf-security-baseline` through Quality Checks (asserting the expected FAIL/PASS findings) and
`multi-tier-web-app` through Dependency & Blast Radius (asserting a non-redundant critical edge
yields a larger blast radius than a redundant one).

## 4. Versioning (semver — never mutate a released version)

- `manifest.version` is **semantic** (`MAJOR.MINOR.PATCH`).
- Bump the version on **every** change: patch for fixes, minor for additive content, major for a
  breaking shape change.
- **Never mutate a released version in place.** Consumers, the registry, and signatures are keyed
  by `id@version`; changing content under an existing version breaks provenance and cache integrity.
  Ship a new version instead.

## 5. Sign (detached signature, verified before execute)

Packs are the trust boundary, so they are signed before release:

- The signer computes **SHA-256** over the pack body and an **HMAC signature** over that hash,
  writing them into `manifest.sha256` / `manifest.signature`.
- The signing secret comes from the **boundary (Key Vault) by managed identity** — never hard-code
  a secret, key, or connection string in a pack, config, or test (guardrail #3, keyless).
- At runtime the **Packs Engine verifies the hash/signature before a pack is allowed to execute**.
  An invalid or missing signature ⇒ **fail closed** (refuse to run — guardrail #4).

To validate with signature verification on (release-time), set the signing secret and re-run the
validator:

```powershell
$env:WP_PACK_SIGNING_SECRET = "<from Key Vault, not committed>"
python scripts/validate_packs.py content
```

## 6. Export via the packs studio

Once validated, tested and signed, export/publish the pack through the packs studio, which adds the
signed pack to the registry index (`content/registry/index.json`, keyed by `id@version`, no
duplicates) so the platform can discover and load it. Templates are **never** exported to the
registry — they are scaffolds only.

## No PHI/PII rule (non-negotiable)

- **No PHI/PII, no customer data, no proprietary IP** in any pack (guardrail #2). Use synthetic,
  clearly-fake fixtures and public WAF/WARA/APRL guidance only. Do not vendor Epic/SAP/Citrix/F5
  proprietary schemas.
- Packs flow **in**; only opt-in, aggregated, **PII-free** findings may flow out (guardrail #1).
- Every finding a pack produces **cites its evidence** (resource id, metric, pack id + version) —
  provenance is automatic when you set a stable `manifest.id`/`version` (guardrail #8).

## Definition of done (per pack)

- [ ] Schema-valid (`python scripts/validate_packs.py content` → exit 0)
- [ ] `manifest.targets` set; `manifest.id` unique; semver `version` bumped (never mutated in place)
- [ ] Synthetic fixtures only — no PHI/PII/proprietary IP
- [ ] A `tests/` addition drives the pack through its consuming module
- [ ] Signed before release; the Packs Engine verifies before execute
