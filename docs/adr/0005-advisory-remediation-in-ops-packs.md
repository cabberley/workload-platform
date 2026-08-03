# 0005. Advisory remediation lives in Ops packs (additive, routing-vs-remediation split)

Date: 2026-08-04 · Status: accepted

## Context

Auto-RCA (issue #50) turns a set of active detections into a confidence-gated root-cause
`AgentResponse`: below `RCA_CONFIDENCE_FLOOR` it asserts no root cause and advises contacting
support; at or above the floor it names the probable root-cause node with cited provenance. Issue
#52 asks us to turn that RCA into **advisory** remediation *proposals* plus an explicit "call
support" path — with the hard, non-negotiable guardrail that **there is never an auto-remediation
or infrastructure-mutation code path** (guardrail 5). A human always decides and applies.

That raises two design questions:

1. **Where does the remediation KNOWLEDGE live?** Baking "if the root cause is a database, do X"
   into Python branches violates content-over-code (guardrail 6) and would make every new workload
   type a code change.
2. **What content type carries it?** The five signed, versioned pack types already exist. Ops packs
   are the operational-response content: today a **notification routing table** (`default`,
   `routes`, `runbook`) consumed by the Alerts module. Remediation is operational-response
   knowledge of the same family — "when this fails, here is the advised human response" — so it
   belongs alongside routing in the Ops pack, not in a new pack type or in code.

## Decision

Extend the **Ops pack** additively with an OPTIONAL `remediations` section, keeping routing and
remediation as an independent split within one signed content artifact.

- **Schema (additive, backward-compatible).** `ops.schema.json` keeps `additionalProperties:false`
  and adds `remediations` as a known optional property. The top-level `anyOf` is broadened to
  `default` OR `routes` OR `remediations`, so a **remediation-only** Ops pack validates while an
  existing **routing-only** pack still validates unchanged. The Alerts routing consumers
  (`load_ops_routing`/`route`) read `default`/`routes`/`runbook` independently and are entirely
  unaffected — they never look at `remediations`.
- **Shape.** `remediations` maps a stable, low-cardinality **root-cause category** (the node's
  classified Discovery **role**, e.g. `odb`, `ecp`, `web`, `lb`, or the documented `*`/`default`
  catch-all) to an ordered list of advisory steps. Each step is a short human-readable
  `description` plus an OPTIONAL `runbook` (citation URL) and OPTIONAL `escalateSeverity` (an
  escalation hint). **No field may encode an executable action, script, command, or API call** —
  descriptions are advisory text only. Sizes are bounded (max categories, steps per category,
  string lengths) and parsing is **all-or-nothing** (any invalid value rejects the whole table) to
  stay fail-closed.
- **Routing-vs-remediation split.** Routing answers "who is notified, on which channel, with which
  runbook link"; remediation answers "what should a human consider doing about this root cause".
  They are consumed by different modules (Alerts vs. AIOps) and are deliberately independent groups
  in the same body so a pack may carry either or both.
- **Category key.** We key on the node's **classified `role`** — the low-cardinality Discovery
  classification that workload-definition packs assign (and the same field the AIOps `role:`
  telemetry selectors resolve against) — normalized (trim/lowercase), NOT on the raw Azure resource
  `type` (e.g. `Microsoft.Compute/virtualMachines`), which is high-cardinality and would never
  match an authored role category, and NOT on a resource id. A node with no classified role fails
  closed to no category (⇒ "call support"). A `*`/`default` catch-all covers matched-but-unmapped
  categories. A richer cross-workload taxonomy, if ever needed, is left as future signed *content*
  (a taxonomy pack), never a Python branch (see `TODO(human)` in
  `modules/aiops/remediation.py`).

## Consequences

- **Advisory-only invariant.** The AIOps edge loads Ops packs through the same verified packs-engine
  path the Alerts module uses (signatures verified BEFORE use; fail-closed on invalid/absent), then
  a **pure** lookup (`modules/aiops/remediation.py`) maps category -> steps and enforces the
  confidence + verification + no-match gates. Python only maps and gates; it never applies anything.
  There is no `apply`, no exec, no Azure write client on this path — reviewers can grep for it.
- **Fail-closed.** Below the RCA confidence floor, or when no verified Ops-pack remediation matches
  the root-cause category (including when Ops packs are absent or fail verification), the enriched
  response's `nextActions` is the explicit "call support" action and NO guessed remediation is
  emitted.
- **Provenance.** Every emitted advisory step cites its source Ops pack id + version in
  `sourceReferences` (`kind="pack"`), and the RCA's root-cause node reference is preserved.
- **Runtime bounds are enforced in code too.** The JSON Schema gate runs at CI, but at runtime only
  the pack signature is verified — so the pure parser independently rejects malformed/oversized
  `remediations` (defense in depth), keeping the same bounds as the schema.
- **Content, not code.** New remediation knowledge for a new workload/category is a signed Ops-pack
  edit, not a code change.
