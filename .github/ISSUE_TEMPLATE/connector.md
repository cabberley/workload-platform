---
name: New connector
about: Read-only integration into an application/control plane
title: "[connector] <system>: <summary>"
labels: ["connector", "agent:connector-engineer"]
---

## System
- [ ] Epic System Pulse (telemetry, read-only)
- [ ] Epic Kuiper (discovery assist)
- [ ] Citrix control plane
- [ ] NetScaler
- [ ] F5 BIG-IP
- [ ] Microsoft Entra (identity)
- [ ] Azure Monitor / Resource Graph
- [ ] Other

## Access model
- **Read-only** confirmed:
- Auth (keyless / Managed Identity / customer-supplied read token in Key Vault):
- Data pulled (must be PII-free or stay in-boundary):

## Contract
- Normalized output (which domain model / signal shape):
- Which module consumes it:

## Definition of done
- [ ] Thin client at module edge; pure mapping unit-tested
- [ ] No secrets in code; keyless or Key Vault reference
- [ ] Graceful, fail-closed on connector unavailability
