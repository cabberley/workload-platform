# AGENTS.md — how this repository is built

This repo is built by a **small senior human core directing GitHub Copilot coding agents**. The
work model is a tight loop:

```
issue (well-scoped)  →  the right skill/agent picks it up  →  branch + PR
     →  CI: lint · types · tests · pack-validate · security review  →  human review  →  merge
```

Humans set direction, review PRs, and own architecture/security. **Agents do the typing.** Every
change lands as a reviewable PR — never a direct push to `main`.

## The multi‑agent dev team (roles)

See [`.github/agents/team.md`](.github/agents/team.md) for the full charter. In brief:

| Agent role | Owns | Primary skills (`skills/`) |
|------------|------|----------------------------|
| **Architect** | Contracts in `src/shared`, ADRs, module boundaries | `docs-author` |
| **Module Engineer** | A single module under `src/modules/*` | `test-gen`, `detector-author` |
| **Pack Author** | Content in `content/*` | `pack-author`, `workload-author`, `dependency-author` |
| **Connector Engineer** | Read‑only integrations (System Pulse, Kuiper, Citrix, F5) | `connector-author` |
| **Platform/Infra** | `infra/*`, workflows, scaling profiles | `iac-deploy` |
| **AIOps Engineer** | Detection + RCA in `src/modules/aiops` | `detector-author` |
| **UX Engineer** | `src/web`, dashboards | `dashboard-author` |
| **Security/Release** | Guardrails, signing, releases | `security-review`, `release` |

## Ground rules for every agent

1. **Read the guardrails first** — [`.github/copilot-instructions.md`](.github/copilot-instructions.md).
2. **Stay in your module.** Cross‑module changes go through the Architect and a contract change.
3. **Pure logic is separate from I/O.** Detection, scoring, and blast‑radius math are pure
   functions with unit tests; Azure calls live at the edges.
4. **No PHI/PII, ever.** No customer data, secrets, or Epic/SAP proprietary IP in the repo.
5. **Content over code.** New knowledge → a pack in `content/`, not a Python branch.
6. **Ship a test with every change.** No feature PR without a `tests/` addition.
7. **Fail closed.** Unknown/low‑confidence → surface, don't act. No auto‑remediation of customer
   infrastructure.

## Definition of done (per PR)

- [ ] Scope matches one issue; module boundary respected
- [ ] `pytest -q` green; new/changed logic covered
- [ ] `ruff` + `mypy` clean
- [ ] Packs changed? `pack-validate` green (schema + signature)
- [ ] Security review workflow green; no new high/critical findings
- [ ] Docs/ADR updated if a contract or decision changed
