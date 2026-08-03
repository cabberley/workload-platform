# Pack templates — field-by-field authoring guide

Starter (scaffold) packs for each of the five signed content types live one directory down, one
per type:

| Type | Template file | Consuming module | Body schema (the authority) |
|------|---------------|------------------|-----------------------------|
| workload | [`workload/example-workload-pack.json`](workload/example-workload-pack.json) | Discovery (`src/modules/discovery/module.py`) | [`src/packs_engine/schemas/workload.schema.json`](../../src/packs_engine/schemas/workload.schema.json) |
| rule | [`rule/example-rule-pack.json`](rule/example-rule-pack.json) | Quality Checks (`src/modules/quality_checks/module.py`) | [`src/packs_engine/schemas/rule.schema.json`](../../src/packs_engine/schemas/rule.schema.json) |
| telemetry | [`telemetry/example-telemetry-pack.json`](telemetry/example-telemetry-pack.json) | AIOps (`src/modules/aiops/module.py`) | [`src/packs_engine/schemas/telemetry.schema.json`](../../src/packs_engine/schemas/telemetry.schema.json) |
| dependency | [`dependency/example-dependency-pack.json`](dependency/example-dependency-pack.json) | Dependency & Blast Radius (`src/modules/dependency_graph/module.py`) | [`src/packs_engine/schemas/dependency.schema.json`](../../src/packs_engine/schemas/dependency.schema.json) |
| ops | [`ops/example-ops-pack.json`](ops/example-ops-pack.json) | Alerts & Notifications (`src/modules/alerts/module.py`) | [`src/packs_engine/schemas/ops.schema.json`](../../src/packs_engine/schemas/ops.schema.json) |

> These templates are **scaffolds, not released packs.** `content/templates/` is a **reserved,
> non-runtime directory**: the runtime `PacksEngine` skips the entire subtree
> (`packs_engine.engine.RESERVED_NONRUNTIME_DIR`), so templates are **never loaded or executed**
> against a customer estate — they cannot override alert routing, emit false detections, inject
> dependency edges, or misclassify resources, even though they use `targets: []`. They are still
> **schema-validated in CI** (`scripts/validate_packs.py` enumerates them independently), and are
> deliberately kept out of the registry index (`content/registry/index.json`).
>
> **To DEPLOY a pack, copy it OUT of `templates/`** into its by-type directory (e.g.
> `content/rules/`), give it a unique id, replace every `REPLACE ME` / `example-*` / `Example.*`
> placeholder, then validate, test and sign it (see
> [`docs/authoring-packs.md`](../../docs/authoring-packs.md)). A pack left under `templates/` will
> never run.

Because JSON carries no comments, this file documents every field. The **schema is the authority**
— if this guide and a `*.schema.json` disagree, the schema wins. Every file under `content/`
(templates included) is validated in CI by `python scripts/validate_packs.py content`.

---

## Shared: the `manifest` (every pack)

Defined by `PackManifest` in [`src/shared/contracts.py`](../../src/shared/contracts.py). Present in
every pack, whatever its type.

| Field | Required | Type | Placeholder in templates | How to replace |
|-------|----------|------|--------------------------|----------------|
| `id` | **yes** | string | `example-<type>-pack` | A stable, unique, kebab-case id. Must not collide with any other pack id under `content/`. Never reuse another pack's id. |
| `type` | **yes** | enum | the pack's type | One of `workload` \| `rule` \| `telemetry` \| `dependency` \| `ops`. Do **not** change this — it selects the body schema. |
| `name` | **yes** | string | `Example <Type> pack — REPLACE ME` | A short human-readable display name. |
| `version` | **yes** | string (semver) | `0.1.0` | Semantic version `MAJOR.MINOR.PATCH`. Bump on every change; **never mutate a released version in place** (see the authoring guide's versioning section). |
| `targets` | optional | string[] | `[]` | Workload kinds this pack applies to, e.g. `["epic"]`. **Empty = applies to all workloads.** |
| `sha256` | optional | string \| null | absent | Content hash; **set by the signing step at release time**, not by hand. Verified before execute. |
| `signature` | optional | string \| null | absent | HMAC signature over `sha256`; **set by signing**. The Packs Engine verifies it before a pack executes (fail-closed). |
| `author` | optional | string | `your-org` (templates) / `microsoft` (shipped) | Your org/team identifier. |

Leave `sha256`/`signature` out while authoring — the release-time signer adds them.

---

## `workload` — Workload Definition pack

Body classifies discovered estate resources into `workload` / `tier` / `role`. Consumed by
Discovery. Authority: `workload.schema.json`.

Top-level body:

| Field | Required | Type | Notes |
|-------|----------|------|-------|
| `workload` | optional | string (min length 1) | Default workload kind that definitions inherit when they omit their own. **If you omit this pack-level `workload`, every definition MUST assign at least one of `workload` / `tier` / `role`** (a label-less, selector-only entry would inherit nothing — a no-op that can shadow later definitions, so the schema rejects it). |
| `definitions` | **yes** | array (min 1) | Selector → label entries; see below. |

Each `definitions[]` entry (`additionalProperties: false` — no extra keys allowed):

| Field | Required | Type | Notes |
|-------|----------|------|-------|
| `resourceType` | see below | string | Azure resource type matched case-insensitively, e.g. `Microsoft.Compute/virtualMachines`. |
| `tagKey` | see below | string | Tag key selector. **Must appear together with `tagValue`.** |
| `tagValue` | see below | string | Tag value selector. **Must appear together with `tagKey`.** |
| `workload` | optional | string | Label to assign (overrides the pack-level default for matched nodes). |
| `tier` | optional | string | Tier label, e.g. `database`, `application`, `presentation`. |
| `role` | optional | string | Role label, e.g. `db`, `app`, `web`, `lb`. Roles are what dependency & telemetry packs reference via `role:<name>`. |

Selector rule (`anyOf`): each entry must carry **either** a `resourceType` **or** a `tagKey`+`tagValue`
pair (or both). An entry with no meaningful selector is rejected.

Replace: set a real `workload` kind (or drop it and label every definition), and replace the
placeholder `Example.ResourceProvider/replaceMeType` resourceType and `example-role` tag selector
(chosen so the scaffold matches nothing real) with your estate's actual Azure types/tags and
`tier`/`role` labels. Real, non-placeholder shape to model on:
[`content/workloads/epic-core.json`](../workloads/epic-core.json).

---

## `rule` — Rule pack

Body is a list of WAF/WARA/APRL-style checks applied to estate nodes by Quality Checks. Authority:
`rule.schema.json`. Rules are forward-compatible (`additionalProperties: true`) — unknown keys are
ignored by `RuleSpec`, so richer future predicates won't fail CI.

Top-level body: `rules` — **required** array (min 1).

Each `rules[]` entry. Note `RuleSpec` **defaults every field**, so none is strictly required, but a
useful rule needs a supported predicate:

| Field | Required | Type | Notes |
|-------|----------|------|-------|
| `id` | recommended | string (non-null, min length 1) | Stable rule id carried into `Finding` provenance. Defaults to `"rule"` if omitted — always set a real one. |
| `title` | optional | string \| null | Human-readable statement of what must be true. |
| `resourceType` | optional | string \| null | Azure resource type filter. **`null`/absent ⇒ the rule applies to every node.** |
| `requiredTag` | optional | string \| null | The **only currently supported predicate**: the tag that must be present on the node. Missing tag ⇒ FAIL (fail-closed). A rule that declares no supported predicate is valid content but produces a fail-closed "unsupported/unevaluable" FAILURE — never a silent PASS. |
| `severity` | optional | enum \| null | One of `info` \| `low` \| `medium` \| `high` \| `critical`. **`null` is normalised to `medium`.** A non-null value must be a valid severity. |
| `description` | optional | string (**non-nullable**) | Free text; cite the WAF/WARA/APRL guidance. **Must not be `null`** — a null description makes the loader drop the rule at runtime, and the schema rejects it. Omit the key entirely rather than setting `null`. |
| `packId` | optional | string \| null | Leave unset — stamped automatically from the manifest at load time. |
| `packVersion` | optional | string \| null | Leave unset — stamped automatically from the manifest at load time. |

Replace: pick the `resourceType` you want to check (the template ships the inert placeholder
`Example.ResourceProvider/replaceMeType` so it matches nothing real), the `requiredTag` that must
be present, a real `severity`, and a `description` that cites the guidance. See
[`content/rules/waf-security-baseline.json`](../rules/waf-security-baseline.json) for a real,
multi-rule example.

---

## `telemetry` — Telemetry pack

Body is a list of role-scoped threshold signals consumed by AIOps (`fuse_detections`). Authority:
`telemetry.schema.json`. Signals are forward-compatible (`additionalProperties: true`).

Top-level body:

| Field | Required | Type | Notes |
|-------|----------|------|-------|
| `signals` | **yes** | array (min 1) | Threshold rules; see below. |
| `logAnalysis` | optional | object | `{ "enabled": bool, "note": string }` — advisory AI log-analysis hint. Optional; extra keys allowed. |

Each `signals[]` entry — **all known fields are required**:

| Field | Required | Type | Notes |
|-------|----------|------|-------|
| `name` | **yes** | string (min length 1) | Metric name, e.g. `example_latency_ms`. |
| `op` | **yes** | enum | Breach direction: `gt` (value greater than threshold) or `lt` (less than). Only these two. |
| `threshold` | **yes** | number | Numeric breach threshold. **Booleans are rejected; non-finite `nan`/`inf` are rejected** by the finite-value check. |
| `severity` | **yes** | enum | `info` \| `low` \| `medium` \| `high` \| `critical`. |
| `nodeId` | **yes** | string | Role selector `role:<name>` — pattern `^role:\s*\S.*$`. The role name must be non-whitespace. This binds the signal to nodes carrying that `role` (from a workload pack). |

Replace: set a real metric `name`, `op`, `threshold`, `severity`, and point `nodeId` at a real
`role:<name>` from your workload pack.

---

## `dependency` — Dependency pack

Body is a list of typed dependency edges merged into the workload graph by the Dependency & Blast
Radius module. Authority: `dependency.schema.json`. Edges are strict (`additionalProperties: false`).

Top-level body: `edges` — **required** array (min 1).

Each `edges[]` entry:

| Field | Required | Type | Notes |
|-------|----------|------|-------|
| `source` | **yes** | string | Namespaced endpoint that **depends on** the target. Pattern `^(role\|id\|type):.+` — one of `role:<name>` (every node carrying that role), `id:<resourceId>` (one concrete node), or `type:<azureType>` (every node of that Azure type). |
| `target` | **yes** | string | Namespaced endpoint that is **depended upon**. Same namespaced form as `source`. |
| `type` | optional | enum \| null | `depends_on` \| `load_balances` \| `replicates_to` \| `routes_to`. **`null`/absent ⇒ `depends_on`.** |
| `redundant` | optional | boolean \| null | `true` when the source has redundant peers for the target (loss **degrades**, not downs). **`null`/absent ⇒ `false`.** Non-redundant edges drive larger blast radius; redundant ones only degrade. |

Bare/unnamespaced endpoints (e.g. `db` instead of `role:db`) are rejected — always namespace them.
Replace: point `source`/`target` at real `role:`/`id:`/`type:` endpoints and set `redundant`
honestly per tier. See
[`content/dependencies/multi-tier-web-app.json`](../dependencies/multi-tier-web-app.json) for a
reusable web→app→db example with a mix of redundant/non-redundant edges.

> **Scope reusable dependency packs per-workload — never ship `targets: []`.** A dependency pack
> with global scope executes against *every* workload, so an unrelated real workload that merely
> reuses generic role names (`web`/`app`/`db`) would receive **invented** edges and a fabricated
> SPOF finding — corrupting its blast-radius. Reusable dependency packs must therefore be
> **assigned per-workload** (forward-reference: issue #37's per-workload pack assignment). Until
> that wiring lands, the example above targets the synthetic `multi-tier-demo` workload kind
> (`"targets": ["multi-tier-demo"]`) so it demonstrates the capability safely without applying to
> any real estate. (Contrast global rule baselines like `waf-reliability-baseline` /
> `waf-security-baseline`, where `targets: []` is the accepted pattern — a per-node tag check is
> inert on resources that don't carry the tag, whereas a dependency edge invents topology.)

---

## `ops` — Ops pack

Body is a notification routing table consumed by Alerts & Notifications. Authority:
`ops.schema.json`. **At least one of `default` or `routes` must be present** (`anyOf`); both may be.

| Field | Required | Type | Notes |
|-------|----------|------|-------|
| `default` | one of default/routes | string (min length 1) | Fallback channel when a severity has no explicit route, e.g. `ticket`. |
| `routes` | one of default/routes | object (min 1 property) | Map of `Severity → channel`. Keys must be from `info` \| `low` \| `medium` \| `high` \| `critical`; each value a non-empty channel string (e.g. `none` \| `ticket` \| `email` \| `page`). |
| `runbook` | optional | string \| null | Runbook link surfaced with routed notifications. `null`/absent is skipped. |

Replace: choose a real `default` channel, map the severities you route in `routes`, and set a real
`runbook` URL (or drop it).

---

## Guardrails (apply to every template you copy)

- **No PHI/PII, no customer data, no proprietary IP.** Synthetic, clearly-fake fixtures and
  public WAF/WARA/APRL guidance only.
- **No secrets/keys/connection strings** in a pack — signing secrets come from the boundary
  (Key Vault) at release time.
- **Give every pack a unique `id`**; never reuse a released `id@version`.
- Validate with `python scripts/validate_packs.py content` before you commit.
