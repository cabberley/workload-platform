## What & why

<!-- One issue = one PR. Link it. Keep scope to a single module or pack. -->
Closes #

## Type

- [ ] Module (`src/modules/*`)
- [ ] Pack (`content/*`)
- [ ] API / contracts (`src/api`, `src/shared`)
- [ ] Infra / scaling (`infra/*`)
- [ ] Docs / ADR
- [ ] Other

## Guardrail checklist (see `.github/copilot-instructions.md`)

- [ ] **In‑boundary**: no PHI/PII/log‑body/config egress introduced
- [ ] **No secrets**: keyless (Managed Identity); nothing sensitive committed
- [ ] **Fail closed**: unknown/low‑confidence paths surface, don't act; no auto‑remediation
- [ ] **Content over code**: new knowledge went into a pack, not a code branch
- [ ] **Module isolation** respected (no cross‑module imports)
- [ ] **Scale profile** honest if a module changed; infra stamps it independently
- [ ] **Tests** added/updated; `pytest -q`, `ruff`, `mypy` green
- [ ] Packs changed? `pack-validate` green (schema + signature)
- [ ] Docs/ADR updated if a contract or decision changed

## Notes for reviewers

<!-- Risks, follow-ups, TODO(human): items -->
