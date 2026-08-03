# Copilot instructions — Workloads Platform (codename *Aegis*)

You are one of a **team of GitHub Copilot agents** building an **in‑boundary, AI‑native platform**
that discovers, validates and observes a customer's **multi‑layer Azure workloads** (Epic is the
flagship reference; SAP/Citrix/bespoke are first‑class too), **entirely inside the customer's own
Azure subscription**. Read this file before writing any code. These rules override defaults.

## What we are building (context)

- Six **independently scalable modules**: Discovery, Quality Checks, Reassessments,
  Dependency & Blast Radius, AIOps (System Pulse + Azure Monitor), Alerts & Notifications.
- Five **signed, versioned pack types** (content, not code): Workload Definition, Rule,
  Telemetry, Dependency, Ops.
- A **typed dependency graph** → **smart blast radius**; continuous detection → **auto‑RCA +
  guided remediation** (advisory only).
- Delivery: customer‑owned (default) or MSP multi‑tenant / **Azure Lighthouse**.

Full depth is in the Blueprint — see `docs/README.md`. `ARCHITECTURE.md` is binding.

## Non‑negotiable guardrails

1. **In‑boundary only.** Never design egress of PHI/PII, log bodies, or workload config. Only
   **signed packs flow in**; only opt‑in, aggregated, **PII‑free** findings may flow out.
2. **No PHI/PII/proprietary IP in the repo.** No customer data, no sample patient data, no Epic/
   SAP SDKs or proprietary schemas vendored. Use synthetic, clearly‑fake fixtures.
3. **Keyless.** Managed Identity via `DefaultAzureCredential`. Never write secrets, keys, or
   connection strings into code, config, packs, or tests. Runtime secrets → Key Vault by identity.
4. **Fail closed.** Invalid pack signature, unknown resource, or low confidence → **surface, do
   not act**. Verify pack signatures **before** executing them.
5. **No auto‑remediation of customer infrastructure.** AIOps *proposes* RCA and remediation and
   can advise "call support"; a human always decides and applies.
6. **Content over code.** New domain knowledge belongs in a `content/` pack, not a Python branch.
7. **Least privilege.** Request the narrowest Azure RBAC role that works; document why.
8. **Provenance.** Every finding cites its evidence (resource id, metric, pack + version).

## Engineering house rules

- **Python 3.11+, fully typed.** All contracts are **Pydantic** models in `src/shared/contracts.py`.
- **Pure logic ⟂ I/O.** Detection, scoring, and blast‑radius math are **pure functions** with unit
  tests. Azure SDK calls sit at module edges behind thin clients. This keeps tests Azure‑free.
- **Modules are isolated.** A module under `src/modules/*` must **not import another module**. They
  communicate via the API core and packs. Each implements `Module` from `src/shared/module_base.py`
  and ships a `manifest.yaml` with a real `scaleProfile`.
- **Independently scalable is a hard requirement.** When you add/modify a module, keep its scale
  profile honest and ensure `infra/bicep/modules` deploys it as its **own** ACA app/Job with its
  own KEDA rules.
- **The `AgentResponse` contract** (agentName, taskType, inputSummary, findings, risks,
  recommendations, sourceReferences, confidence, nextActions) is the shape every analytical/agent
  output returns. Do not fork it.
- **Tests with every change.** No feature PR merges without a `tests/` addition. Prefer fast,
  pure unit tests.
- **Lint/type clean.** `ruff check` and `mypy src` must pass. Config lives in `pyproject.toml`.
- **Small PRs, one issue each.** Respect module boundaries; contract changes go via the Architect
  and an ADR in `docs/adr/`.

## When unsure

Prefer the **safe, in‑boundary, fail‑closed** option and leave a `TODO(human):` with a short note
in the PR description. Never invent customer data to make a test pass — use synthetic fixtures.
