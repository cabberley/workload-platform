---
name: connector-author
description: Build read-only integrations into application/control planes (Epic System Pulse, Kuiper, Citrix, NetScaler, F5 BIG-IP, Entra, Azure Monitor/Resource Graph). Use when a module needs external signal. Enforces read-only, keyless, fail-closed, PII-safe.
---

# Skill: connector-author

Bring external signal **in-boundary** through a thin edge client. Connectors are how modules see
the application/control planes without embedding vendor logic in core code.

## Hard rules
- **Read-only.** Never write to the external system.
- **Keyless.** Managed Identity where possible; customer-supplied read tokens live in Key Vault,
  referenced by identity — never in code, config, or packs.
- **PII-safe / in-boundary.** Pull only what's needed; keep bodies in-boundary; normalize to the
  platform's domain models.
- **Fail-closed.** If the connector is unavailable, surface it — never fabricate signal.

## Shape
- Put the client at the module edge: `src/modules/<m>/connectors/<system>.py`.
- Expose a pure mapping function `raw -> domain model` (ResourceNode / signal dict / DependencyEdge)
  and unit-test the mapping with a synthetic raw payload.
- Keep the network call isolated so tests don't touch the network.

## Systems & typical output
| System | Feeds | Output |
|--------|-------|--------|
| System Pulse | AIOps | telemetry signals (read-only) |
| Kuiper | Discovery | classification hints |
| Citrix / NetScaler / F5 | Dependency, AIOps | topology + filtered LB logs |
| Entra | Discovery/Alerts | identity context |
| Azure Monitor / Resource Graph | Discovery, AIOps | resources + metrics/logs |

## Definition of done
- [ ] Read-only, keyless, fail-closed
- [ ] Pure mapping unit-tested with synthetic payloads
- [ ] No secrets; no PII egress
