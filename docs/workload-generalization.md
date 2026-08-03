# Workload generalization — the platform is workload-agnostic

The Workloads Platform is **not an Epic tool**. Epic on Azure is the flagship *reference* workload,
but SAP, Citrix, and bespoke line-of-business estates are **first-class**. The design proves this
concretely: a new workload type is onboarded by shipping **content packs**, with **no platform code
change** (guardrail #6 — *content over code*).

This document is the evidence, using a synthetic **generic multi-tier** workload as the worked
example alongside Epic.

## How a workload is onboarded — content only

A workload is fully described to the platform by two signed, versioned packs:

| Pack type | Directory | Consuming module | Role |
|-----------|-----------|------------------|------|
| **Workload Definition** | `content/workloads/` | Discovery (`classify` / `definitions_from_packs`) | Classifies estate resources into `workload → tier → role` from resource-type + tag selectors |
| **Dependency** | `content/dependencies/` | Dependency & Blast Radius (`DependencyGraphModule`) | Declares typed `role:`-based edges that merge into the `WorkloadGraph` and drive smart blast radius |

That is the whole contract. Discovery reads *any* Workload Definition pack; the Dependency & Blast
Radius module resolves *any* Dependency pack's `role:` edges against the classified estate; the pure
`shared.blast_radius` math ranks single points of failure for *any* topology. None of these paths
branch on a workload name — the workload kind is data (`manifest.targets` + `body.workload`), never
a Python `if`.

## Worked example: a generic bespoke multi-tier workload (synthetic)

The example is deliberately **synthetic and clearly-fake** — no customer data, no proprietary
schema, no Epic/SAP/Citrix SDKs. It targets the synthetic workload kind `multi-tier-demo`.

### The packs

- **Workload Definition** — [`content/workloads/acme-bespoke-multitier.json`](../content/workloads/acme-bespoke-multitier.json)
  - `id: acme-bespoke-multitier`, `type: workload`, `targets: ["multi-tier-demo"]`
  - Four tag-scoped definitions (every selector requires the `acme-tier` tag, so the pack never
    misclassifies resources outside its own estate):

    | Resource type | Tag | Tier | Role |
    |---------------|-----|------|------|
    | `Microsoft.Compute/virtualMachines` | `acme-tier=web` | presentation | `web` |
    | `Microsoft.Compute/virtualMachines` | `acme-tier=app` | application | `app` |
    | `Microsoft.Compute/virtualMachines` | `acme-tier=db` | database | `db` |
    | `Microsoft.Network/loadBalancers` | `acme-tier=lb` | presentation | `lb` |

- **Dependency (companion)** — [`content/dependencies/multi-tier-web-app.json`](../content/dependencies/multi-tier-web-app.json)
  - `id: multi-tier-web-app`, `type: dependency`, `targets: ["multi-tier-demo"]` — the coherent
    companion to the Workload Definition above (matching `targets` and roles).

    | Edge | Type | Redundant | Meaning |
    |------|------|-----------|---------|
    | `role:web → role:lb` | `load_balances` | **true** | web tier reaches the shared LB redundantly |
    | `role:web → role:app` | `depends_on` | **true** | web depends on the app tier, redundant across ≥2 app nodes |
    | `role:app → role:db` | `depends_on` | **false** | app tier depends hard on the single data tier — **the SPOF** |

### The single point of failure

The **`db` (data) tier is the modeled SPOF**: it is the only non-redundant target. Losing it takes
the **application tier down** and **degrades** the redundant presentation/web tier, leaving the
workload **severely impaired** — its application tier is fully unavailable — which is exactly why
the `db` ranks as the top single point of failure. The load balancer, by contrast, is modeled
redundant, so losing it only **degrades** the presentation tier. This is the smart-blast-radius
distinction the platform surfaces for every workload.

### Proof (blast-radius test)

[`tests/unit/test_bespoke_multitier_generalization.py`](../tests/unit/test_bespoke_multitier_generalization.py)
builds the `WorkloadGraph` the **same way the platform does** — it classifies a synthetic estate
through the real Discovery `classify` path using the shipped Workload Definition pack, then feeds
the classified nodes to the real `DependencyGraphModule.run`, which resolves the companion
Dependency pack's edges. It then asserts the SPOF story with the canonical, pure
`shared.blast_radius` module (never a reimplementation):

- **SPOF:** `rank_spofs` puts `fake-db1` first; `compute_impact(graph, "fake-db1")` marks both app
  nodes `down` (`blast_radius >= 2`) and **degrades both web nodes** — the application tier is
  fully down and the presentation tier degraded.
- **Redundant nodes stay functional:** losing one `app` node leaves the other `app` node `up`, the
  `db` `up`, and only degrades the web tier (`blast_radius == 0`); losing one `web` node or the
  shared `lb` downs nothing else (`blast_radius == 0`). The db SPOF's blast radius is strictly
  larger than the redundant lb's.

Epic provides the second data point:
[`tests/unit/test_dependency_graph.py::test_run_drives_real_content_dependency_pack_end_to_end`](../tests/unit/test_dependency_graph.py)
drives the shipped `epic-core` + `epic-core-deps` packs through the identical module path, where the
Operational Database (`odb`) is the SPOF. **Same code, two very different workloads** — the
generalization holds.

### Known limitation — per-edge (not group) redundancy

The shared blast-radius engine (`src/shared/blast_radius.py`) models redundancy **per-edge**: a
dependent is marked `degraded` (not `down`) whenever the dependencies that failed are on *redundant*
edges — even if **every** replica in that redundant group is down. So losing `fake-db1` leaves both
web nodes `degraded` (their `web→app` / `web→lb` edges are redundant), not `down`, even though the
whole app tier they depend on is gone. True **group-redundancy** semantics — "every replica in a
redundant group has failed ⇒ the dependent goes `down`" — is a future enhancement to
`src/shared/blast_radius.py`, tracked separately. The demo reflects the engine's real behavior today
and does not imply a cascade to a fully-`down` workload.

## Was any code change required? (finding)

**No production/`src` code change was required** to onboard the generic bespoke workload — it is
100% content (two packs under `content/`). The Discovery `classify` / `definitions_from_packs`
logic, the `DependencyGraphModule` edge resolver, and the pure `shared.blast_radius` math are all
workload-agnostic and were untouched. The pack schemas were **not** weakened — both new/companion
packs validate against the existing strict `workload.schema.json` and `dependency.schema.json`
as-is, so no ADR was needed.

The only change **outside `content/`** was a **test-robustness fix**, not a code change:
`tests/unit/test_discovery.py::test_definitions_from_packs_inherits_pack_workload` had hard-coded
the assumption that Epic is the *only* workload pack (`assert all(d.workload == "epic")` across
*every* loaded workload pack). It is now scoped to the `epic-core` pack it is actually asserting
about. This over-specified test — not any platform code — was the sole thing that "knew" there was
only one workload; the production onboarding path needed nothing.

## Extending to SAP and Citrix

The same two-pack recipe applies to SAP and Citrix — author a Workload Definition pack (resource
types + tag selectors → tiers/roles) and a companion Dependency pack (typed `role:` edges), both
targeting the new workload kind. No module code changes.

> **TODO(human):** the SAP and Citrix domain specifics — the real entity/resource types, tier/role
> taxonomy, and dependency-edge semantics (e.g. SAP ASCS/ERS enqueue-replication and HANA
> primary/secondary; Citrix Delivery Controllers, StoreFront, VDA, and the SQL site database as a
> SPOF) — need SME input before authoring shippable packs. Do **not** vendor any proprietary
> SAP/Citrix schema or invent real product internals to fill this in; keep every fixture synthetic
> and clearly-fake until an SME confirms the taxonomy.
