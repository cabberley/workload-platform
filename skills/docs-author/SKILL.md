---
name: docs-author
description: Write and maintain architecture docs, ADRs, module/pack READMEs and the contract reference. Use when a decision or contract changes. Keeps docs/ and ARCHITECTURE.md truthful and links back to the Blueprint.
---

# Skill: docs-author

Keep the written record honest and small. Docs exist so agents and humans can build without
re-deriving decisions.

## What to maintain
- **`ARCHITECTURE.md`** — binding architecture; update when structure/scaling changes.
- **ADRs** (`docs/adr/NNNN-title.md`) — one decision each: context, decision, consequences.
  Required for any contract change in `src/shared` or a new module boundary.
- **Module/pack READMEs** — short, purpose + contract + scale profile.
- **`docs/README.md`** — pointer to the full Blueprint (source of intent).

## ADR template
```markdown
# NNNN. <decision title>
Date: YYYY-MM-DD · Status: proposed | accepted | superseded
## Context
## Decision
## Consequences
```

## Rules
- Docs describe **current** reality — no aspirational claims presented as done.
- Link to code (`src/...`) and the Blueprint rather than duplicating.
- No PHI/PII, no customer specifics, no proprietary IP.

## Definition of done
- [ ] Decision captured as an ADR if a contract/boundary changed
- [ ] `ARCHITECTURE.md` still matches the code
- [ ] Links valid; no duplication of the Blueprint
