# Workloads Platform — codename *Aegis*

An **in‑boundary, AI‑native platform** that discovers, validates, and observes a customer's
critical **multi‑layer Azure workloads** — Epic (flagship reference), SAP, Citrix, or any
bespoke n‑tier app — **entirely inside the customer's own Azure subscription**. It answers the
one question that matters during an incident — *"is this Azure, or is this the application?"* —
**without a single byte of sensitive data (PHI/PII) ever leaving the customer's boundary.**

> This repository is the **buildable scaffold** for the platform described in the
> *Workloads Platform Blueprint* (16 docs). It is designed to be built by a **small senior core
> directing GitHub Copilot coding agents** via an issue → agent → PR → review → merge loop.
> Start with [`AGENTS.md`](AGENTS.md), the [`.github/copilot-instructions.md`](.github/copilot-instructions.md),
> and the [`skills/`](skills/) catalog.

---

## Why this exists

- **Trust is the product.** Everything runs in the customer's subscription; only signed content
  (packs, images) flows *in*. Data does not egress.
- **Everything is a versioned, signed pack.** Workload definitions, rules, telemetry, dependency
  edges and ops policies are **content, not code**.
- **Modular and independently scalable.** Each capability is a **module** that can be turned
  on/off and **scaled independently** (see [Independently scalable modules](#independently-scalable-modules)).
- **Proactive and dependency‑aware.** A typed dependency graph drives **smart blast radius**;
  continuous detection drives **auto‑RCA and guided remediation**.

## The six modules

| Module | Directory | Kind | What it does |
|--------|-----------|------|--------------|
| **Discovery** | `src/modules/discovery` | job | Classify the estate into workload → tier → role via Workload Definition Packs |
| **Quality Checks** | `src/modules/quality_checks` | job | Run versioned Rule Packs (WAF/WARA/APRL/app); PASS/FAIL + evidence |
| **Reassessments** | `src/modules/reassessments` | job (cron) | Re‑run checks/discovery; drift + trend |
| **Dependency & Blast Radius** | `src/modules/dependency_graph` | job | Build the dependency graph (auto + Dependency Packs); Up/Degraded/Down + SPOFs |
| **AIOps** | `src/modules/aiops` | service | Fuse telemetry; proactive detect (metrics + AI logs); auto‑RCA; guided remediation |
| **Alerts & Notifications** | `src/modules/alerts` | service | Route findings/incidents; blast‑radius‑weighted severity |

## Repository layout

```
workloads-platform/
├── .github/                # copilot-instructions, agents team, workflows, templates, CODEOWNERS
├── skills/                 # GitHub Copilot build skills (the multi-agent dev team's tools)
├── src/
│   ├── api/                # FastAPI core: module registry, health, REST surface, orchestrator
│   ├── modules/            # the six independently-scalable capability modules
│   ├── packs_engine/       # load / verify signature / execute packs
│   ├── shared/             # domain contracts (Pydantic), Module base, AgentResponse
│   ├── cli/                # worker entrypoint (runs a module as an ACA Job)
│   └── web/                # React + Vite SPA
├── content/                # pack source of truth (workloads, rules, telemetry, dependencies, ops)
├── infra/
│   ├── bicep/              # main + per-module app/job templates with KEDA scale rules
│   ├── docker/             # Dockerfiles (api / worker / web)
│   └── local/              # docker-compose for local all-up
├── tests/                  # pytest (pure logic, no Azure needed)
└── docs/                   # pointers to the Blueprint + ADRs
```

## Independently scalable modules

Each module declares a **scale profile** in its `manifest.yaml` (kind, min/max replicas, KEDA
triggers, resources). Modules are deployed as **separate Azure Container Apps** (services) or
**Container Apps Jobs** (batch), each with its **own scale rules**, so a large workload can scale
`quality_checks` to 30 parallel replicas while `alerts` stays at 1 — and everything scales to
zero when idle. See [`ARCHITECTURE.md`](ARCHITECTURE.md#independent-scaling) and
`infra/bicep/modules/`.

### Per-module deploy model (Bicep ⇄ manifest)

`infra/bicep/main.bicep` stamps one deployment per module, **mirroring** each
`src/modules/<name>/manifest.yaml` `scaleProfile` (the manifest is the source of truth). Service
modules become their own Azure Container App (running the persistent `python -m cli.serve`
entrypoint, which stays alive and dispatches the module named by `WP_MODULE`); job modules become
their own Container Apps Job (running `python -m cli.worker`, run-once). Queue triggers are keyless
KEDA `azure-queue` scalers that authenticate with the shared user-assigned Managed Identity (no
connection strings; `queueLength` is left at KEDA's default of 5). Schedule jobs use the native cron
trigger, and their `maxReplicas` maps to the ACA job **parallelism** (replicas per scheduled run);
`minReplicas` is not applicable to schedule jobs (they scale to zero between runs). The values below
are exactly what the Bicep stamps:

| Module | Kind | Scale (min → max / parallelism) | Trigger(s) as stamped |
|--------|------|---------------------------------|-----------------------|
| `discovery` | job (Schedule) | parallelism 10 | native cron (`0 */6 * * *`) + `api-invoked` on-demand (see note) |
| `quality_checks` | job (Event) | executions 0 → 30 | KEDA `azure-queue` (`assessments`) |
| `reassessments` | job (Schedule) | parallelism 5 | native cron (`0 3 * * *`) |
| `dependency_graph` | job (Event) | executions 0 → 10 | KEDA `azure-queue` (`dependency`) |
| `aiops` | service | replicas 1 → 20 | KEDA `azure-queue` (`telemetry`) + `cpu` (Utilization 70) |
| `alerts` | service | replicas 1 → 10 | KEDA `azure-queue` (`findings`) |

`discovery`'s manifest declares a **cron** trigger and an **`api-invoked`** (on-demand) trigger —
not a queue. It is deployed as a native **Schedule** job for its periodic 0 */6 cadence; on-demand
runs are started by the API core invoking the Job (control-plane `job start`), to be wired in a
later issue (see the `TODO(human)` in `main.bicep`). There is deliberately **no** `discovery` queue
or KEDA queue scaler, so no declared trigger is silently dropped.

The API core and web are deployed alongside the modules but are **not** modules: the API core is
the single writer and stays modest (1 → 3, http-concurrency scaling). The shared platform
(`infra/bicep/modules/core.bicep`) provisions the Azure Container Registry, Log Analytics + the
Container Apps managed environment (app logs go to Azure Monitor and are routed to Log Analytics via
a diagnostic setting — **no shared key is read**), a Storage account (shared-key access disabled)
with the queues the triggers reference (`dependency`, `assessments`, `telemetry`, `findings`), a Key
Vault, the user-assigned Managed Identity, and its keyless role assignments (AcrPull, Storage Queue
Data Contributor, Key Vault Secrets User). No keys or connection strings are emitted as outputs.

## Release & deployment (keyless OIDC)

The [`release`](.github/workflows/release.yml) workflow runs three jobs — `bootstrap` (ensures the
resource group + ACR exist, so a fresh environment doesn't fail on the first push), `build-images`
(builds/pushes `api` / `worker` / `web` to ACR), then `deploy-infra` (deploys
`infra/bicep/main.bicep` with the just-built tags) — all authenticated by **OIDC federation** (no
cloud secrets in GitHub). Configure these **variables** first (repository-scoped, or scoped to the
`production` environment that all three jobs use); none are secrets:

| Variable | Purpose |
|----------|---------|
| `AZURE_CLIENT_ID` | App/Managed Identity client id federated for OIDC login |
| `AZURE_TENANT_ID` | Entra tenant id for the login |
| `AZURE_SUBSCRIPTION_ID` | Target subscription for the deployment |
| `AZURE_RESOURCE_GROUP` | Resource group the deployment targets (created if absent) |
| `AZURE_LOCATION` | Azure region for the resource group and resources |
| `ACR_NAME` | Azure Container Registry name (without `.azurecr.io`) images push/pull from |

All three jobs run in the `production` environment, so the federated credential for
`AZURE_CLIENT_ID` must trust that environment (and the release event), and the six variables must be
visible to every job (repository-scoped or `production`-environment-scoped). Cloud auth uses OIDC
only — do **not** add Azure credentials to GitHub secrets.

## Getting started (developers)

```bash
# Python 3.11+
python -m venv .venv && . .venv/Scripts/activate      # Windows: .venv\Scripts\Activate.ps1
pip install -e .[dev]
export PYTHONPATH=src                                  # PowerShell: $env:PYTHONPATH="src"
pytest -q                                              # pure-logic tests, no Azure needed

# Run the API locally
uvicorn api.app.main:app --reload --app-dir src
# Run a single module as a worker (what an ACA Job runs)
python -m cli.worker --module discovery

# Full local stack
docker compose -f infra/local/docker-compose.yml up --build

# Deploy in-boundary
azd up
```

## Contributing

This repo is built by **Copilot agents under human direction**. Read
[`.github/copilot-instructions.md`](.github/copilot-instructions.md), pick an issue, and let the
right **skill** (in `skills/`) do the work. Every change is an issue → PR → review → merge.

## License / IP

Internal Microsoft. No customer data, no PHI/PII, and **no Epic/SAP proprietary IP** in this
repository (see [`SECURITY.md`](SECURITY.md) and the guardrails in copilot‑instructions).
