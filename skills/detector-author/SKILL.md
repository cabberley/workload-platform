---
name: detector-author
description: Author AIOps detection + auto-RCA logic and the Telemetry Packs that drive it (metric thresholds, AI log analysis). Use for proactive detection, root-cause correlation and advisory remediation in src/modules/aiops. Enforces confidence gating and no auto-remediation.
---

# Skill: detector-author

Make the platform **proactive**: detect issues from telemetry, correlate to a likely root cause
using the dependency graph, and **advise** remediation — never auto-apply it.

## Two parts
1. **Telemetry Pack** (`content/telemetry`) — declares what to watch:
   ```json
   { "manifest": { "type": "telemetry", "id": "sp-core", "version": "1.0.0", "targets": ["epic"] },
     "body": { "signals": [
       { "name": "odb_latency_ms", "op": "gt", "threshold": 500, "severity": "high", "nodeId": "role:odb" }
     ] } }
   ```
2. **Detection logic** (`src/modules/aiops/module.py`) — pure functions:
   - `detect_metric_breach(signal)` for thresholds.
   - AI log analysis returns candidate findings with confidence.
   - `correlate_rca(finding, blast_radius_of)` localizes root cause via blast radius.

## Guardrails
- **Confidence-gated.** Below `RCA_CONFIDENCE_FLOOR` → recommend "contact support", don't assert.
- **No auto-remediation** of customer infrastructure. Output is advisory `recommendations` +
  `nextActions` only.
- **Cite evidence** (`sourceReferences`) on every detection/RCA.
- Keep detection pure and unit-tested; the network/log fetch is at the edge.

## Definition of done
- [ ] Telemetry pack validated + versioned
- [ ] Pure detection + RCA unit-tested (including the low-confidence → support path)
- [ ] No remediation is auto-applied
