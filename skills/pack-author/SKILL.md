---
name: pack-author
description: Author or version any signed content pack (workload, rule, telemetry, dependency, ops). Use when adding knowledge to content/ — never as Python code. Enforces schema, targets, versioning and signing.
---

# Skill: pack-author

Author **content, not code**. Packs are the only inbound artifact and carry knowledge into a
customer boundary. Everything you produce here is versioned and signed.

## When to use
- A new check, signal, dependency rule, workload definition, or notification policy.
- Bumping a pack version.

## The five pack types
| Type | Directory | Consumed by |
|------|-----------|-------------|
| workload | `content/workloads` | Discovery |
| rule | `content/rules` | Quality Checks |
| telemetry | `content/telemetry` | AIOps |
| dependency | `content/dependencies` | Dependency Graph |
| ops | `content/ops` | Alerts |

## Anatomy
Every pack file has a `manifest` (see `src/shared/contracts.py::PackManifest`) and a `body`:
```json
{ "manifest": { "id": "...", "type": "rule", "name": "...", "version": "1.0.0",
                "targets": ["epic"], "author": "microsoft" },
  "body": { ... type-specific ... } }
```

## Rules
- **No PHI/PII, no customer data, no proprietary IP.** Synthetic, clearly-fake fixtures only.
- Set `targets` to the workload kinds it applies to (empty = all).
- Validate: `python scripts/validate_packs.py content`.
- Sign before release (SHA-256 + HMAC); the Packs Engine verifies before execute.
- Bump `version` (semver) on any change; never mutate a released version in place.

## Definition of done
- [ ] Schema-valid, targets set, semver bumped
- [ ] Synthetic fixtures only
- [ ] `pack-validate` workflow green
