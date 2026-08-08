# 0020. Grounded RCA explanation via an in-boundary LLM (advisory)

Date: 2026-08-07 · Status: accepted

## Context

Issue #54 (the last of Epic #20) adds an **advisory, natural-language explanation** of an existing
auto-RCA result to the console. The RCA itself is already produced by `modules.aiops.rca`
(`correlate_root_cause`) as a `shared.contracts.AgentResponse` — the console-facing analytical
output that already cites its evidence (`findings` / `risks` / `recommendations` /
`sourceReferences` / `confidence`). This work does NOT re-derive root cause; it *explains* an
existing one in plain language for an operator.

The decision is **accepted** and recorded on the issue by the owner (not re-litigated here):

- **Model/endpoint:** Azure OpenAI deployed **in the customer's own subscription** (in-boundary),
  reached **keyless** via Managed Identity (`DefaultAzureCredential`), region = the customer's
  deployment region.
- **Thin, pluggable in-boundary LLM client** — the concrete model/deployment is **configuration**
  (env-var *names*), never code.
- **Advisory-only**, grounded strictly on cited evidence; grounding/no-hallucination and no-PII are
  enforced **in code**, not by prompt alone; low confidence ⇒ advisory "call support"; fail-closed.
- **Feature-flagged now; GO-LIVE gated on CELA/HiTrust sign-off** of this in-boundary,
  no-Microsoft-processing pattern (an external legal gate, tracked as a `TODO(human)`, NOT a code
  blocker).

This directly **productizes the in-boundary LLM edge that #53 built and explicitly left reusable**
(see ADR 0019 §5 and `openai_enrichment.py`'s module docstring).

## Decision

**1. Reuse the #53 AOAI seam via a shared helper — no duplicated guardrails.** The trusted-host
suffixes, endpoint validation (SSRF/token-replay guard), region-pin check, the lazy SDK transport
builder, and `COGNITIVE_SCOPE` were factored out of `openai_enrichment.py` into a new
`shared/connectors/aoai.py`. **Both** the #53 enrichment edge and the new #54 explanation edge
import it, eliminating duplication. `openai_enrichment.py` was refactored onto the shared helper
**without any behavior change** — its error class *names* are preserved (fail-closed surfaces
`type(exc).__name__`), so all #53 tests stay green. Module isolation is absolute: the new edge
imports only `shared.*` and same-module `modules.aiops.*` — never another `src/modules/*`.

**2. A new keyless, fail-closed explanation edge.** `modules/aiops/connectors/rca_explanation.py`
(`RcaExplanationClient.explain(response)`) mirrors ALL of the #53 guardrails: an injected
`credential_provider` (keyless, Managed Identity), env-*name* configuration (no hard-coded
endpoint/region/secret), **region-pin BEFORE any credential use**, endpoint host validation
**before** minting a token, a bounded advisory length, a **no-op when UNCONFIGURED**, and
exception → fail-closed (class-name-only error; the pure RCA result stands).

- **Only cited evidence is sent.** `grounding_payload(response)` sends ONLY the RCA's already
  egress-classified cited fields — `findings` / `risks` / `recommendations` /
  `sourceReferences{kind,id,detail}` / `confidence`. It deliberately OMITS `agentName` / `taskType`
  / `inputSummary` / `nextActions` / `generatedAt` so no non-evidence field can seed a fabricated
  fact. The system instruction constrains the model to explain ONLY that evidence and forbids any
  new resource id, metric, node id, or number.
- **Confidence gate.** Below `RCA_CONFIDENCE_FLOOR` (0.6, from `rca.py`) the edge asserts **no**
  explanation and surfaces the support path — mirroring #53's confidence-floor discipline.

**3. Grounding / no-hallucination is enforced in pure code.** `modules/aiops/rca_grounding.py` is a
pure, deterministic, I/O-free post-generation gate. It first **Unicode-hardens** the model output
(NFKC-normalise, strip zero-width / format `Cf` characters, fold Unicode dashes and the math-minus
to ASCII `-`) so an evasion cannot smuggle a fabricated entity past the tokenizer. It then extracts
*entity-like* candidate tokens — resource-id / nodeId / metric-name shapes (a token with a letter
AND a `/`, `_`, `-`, or internal digit), **dotted FQDN / host / email-domain / dotted-quad IPv4
shapes** (so a pure-dotted hostname like `patchserver.example.com` or an email domain is treated as
an entity), and **any token carrying a non-ASCII letter/digit** (which must match a cited token
EXACTLY). Ordinary prose abbreviations (`e.g.`, `i.e.`, `etc.`, `vs.`, `a.k.a.`, …) and a small
benign-hyphenated allow-list (`z-score`, `end-to-end`, …) are exempt so faithful prose stays
grounded. Every candidate must appear in the RCA's cited corpus (`findings` / `risks` /
`recommendations` / `sourceReferences`). The corpus is built from the cited text INCLUDING `/`-split
segments, so a faithful summary naming a single cited segment (e.g. `widget-01`) still grounds — but
a **multi-segment path must match a cited path token EXACTLY** (there is no per-segment
recombination, so a fabricated full id whose segments are each cited across DIFFERENT references is
rejected). If the cited corpus is **empty**, the gate grounds **nothing** (you cannot ground on
nothing). If the output references any un-cited entity, the gate **fails closed**
(`ground_or_reject` returns `None`), the explanation is dropped, and the console surfaces the
"review the cited evidence / call support" path. The gate runs on the **full** model text BEFORE the
envelope truncation (so truncation can never split a token into a spurious pass/fail). This is
unit-tested hard: a hallucinated resource id / FQDN / IPv4 / Unicode-evasion / recombined path ⇒
rejected; a faithful summary and prose with `e.g.`/`i.e.` ⇒ accepted; an empty corpus grounds
nothing.

**4. Advisory rides the redact-on-egress `extra` surface — no new egress field.** The module
attaches the advisory at `ModuleRunResult.extra["rcaExplanation"]` (a list index-aligned with
`extra["rca"]`, each `{"advisory": <text-or-empty>}`), mirroring how #53's advisory rides
`extra["logAnomalyEnrichment"]`. `extra` is an already-tracked issue-#91 waiver that
`_redact_run_result_for_egress` runs `redact_tree` over, so the free text is neutralized on the
`POST .../run` egress path by construction. For the **read-only console** the advisory additionally
travels a dedicated in-boundary read path (see 6): `commit_run` derives a BOUNDED, typed
`shared.contracts.RcaAdvisory` read model from the run's grounded `extra["rcaExplanation"]` +
`extra["rca"]` (persisting ONLY grounded/non-empty entries — fail-closed by absence), served by an
authenticated `GET`. Because `RcaAdvisory` is a bounded model (only scalars + the already-egress-
classified `SourceReference`, no open `dict[str, Any]`), `scripts/audit_no_pii_egress.py` stays
**green with no new waiver** (now 31 bounded response models / 4 tracked #91 waivers — the +1 is the
new bounded read model, not a waiver). The explanation is NEVER a finding, risk, recommendation,
remediation, or nextAction, and is never auto-applied — a human disposes.

**5. Behind a feature flag; GO-LIVE gated externally.** The composition root
(`cli/wiring.py::_add_rca_explanation`) registers the edge ONLY when an explicit flag
(`$AIOPS_RCA_EXPLAIN_ENABLED`) is truthy AND the same in-boundary AOAI config the #53 edge uses is
fully present AND a keyless credential exists. Absent any of these the client key is simply absent
and the pure RCA result stands unchanged — **the no-op IS the off state of the flag**. A
`TODO(human)` in both the wiring builder and the module records that GO-LIVE awaits CELA/HiTrust
sign-off (external legal gate, not a code blocker).

**6. Console UX (read-only, in-boundary read path).** A dedicated read path carries the advisory to
the SPA without crossing the trust boundary (the console is authenticated + in-boundary):
`commit_run` persists the bounded `RcaAdvisory` read model per workload (only grounded/non-empty
entries), an authenticated `GET /api/workloads/{workload}/rca-explanations` (same `ReaderDep`
principal as findings/graph/drift) returns `list[RcaAdvisory]` as an EXPLICIT PII-safe projection
(NOT the blanket `redact_tree` egress projection), and `client.ts::fetchRcaExplanations` reads it.
`web/src/panels/RcaExplanation.tsx` renders each advisory CLEARLY labelled as an AI advisory
grounded on cited evidence ("AI proposes, a human disposes"), showing the cited `sourceReferences`
alongside it, and **renders nothing** when none is available. `App.tsx` fetches the advisories for
the selected workload and passes them (via the pure `advisoriesToViews` adapter) into
`FindingsView`. The SPA stays strictly read-only (GET only) — no secret, key, external endpoint, or
POST is introduced.

## Consequences

- **+** The #53 in-boundary AOAI guardrails (keyless, region-pin, endpoint-trust, lazy SDK,
  fail-closed) are now shared by both edges from one audited helper — no drift, no duplication.
- **+** No-hallucination is a **provable** pure gate, not prompt hope: an explanation that names any
  un-cited entity cannot be surfaced.
- **+** The advisory is PII-safe by construction (rides the redacted `extra` surface); the auditor
  stays green with no new waiver, and the pure RCA result is unaffected when the edge is off/absent.
- **+** Ships dark: default-off behind a flag, so CELA/HiTrust sign-off can flip it on with no code
  change.
- **−** The grounding gate is deliberately conservative: a legitimate but truncated (bounded)
  advisory whose last token is cut mid-identifier can read as ungrounded and be dropped. That is the
  intended fail-closed bias — we drop rather than assert an ungrounded narrative. (The gate now runs
  on the FULL text before truncation, so this only bites when the grounded advisory itself is
  legitimately over the envelope bound.)
- **−** The console read path persists an extra bounded read model (`rca_advisories`) and adds a GET
  endpoint; this is deliberate (mirrors findings/graph/drift) and keeps the advisory PII-safe by
  typed projection, at the cost of one more read model the auditor now counts (31, still 4 waivers).

## Residual limitation & future hardening

Entity-grounding is a **necessary but not sufficient** no-hallucination control. It proves that
every *entity-shaped* token in the advisory is cited — resource id, nodeId, metric,
FQDN/host/email-domain, **IPv4 and IPv6 literal** (detected structurally with the stdlib
`ipaddress` module and compared in canonical/compressed form), **numeric quantity** (every number in
the output must appear in the cited numeric set — cited text plus the RCA `confidence` — so a
fabricated `97 percent across 12 nodes` fails closed), and non-ASCII/homoglyph token. But two
classes of evasion are **intrinsically beyond a lexical gate** and are accepted as residual risk:

- **A fabricated non-entity prose claim** when the corpus is non-empty — an invented causal
  narrative that names only cited entities but asserts an unsupported relationship between them.
- **A single-label bare-word hostname** (`patchserver`) or an **allow-listed word used as a host**
  (`root-cause`). A bare word with no dot, slash, digit, or hyphen is indistinguishable from
  ordinary prose by token shape; treating every lowercase word as a candidate host would reject all
  natural-language advisories. No lexical/shape gate can close this without destroying the feature.

The fully-robust answer is to stop free-texting at all: have the model emit **structured/extractive**
output that references cited evidence **by id/index** (not by re-typing it as free text), and render
that through **backend fixed templates**, so the surfaced text is composed from vetted fragments and
free generation can never reach the operator. That is captured as future work; it is **not**
implemented now. Until then the residual risk is kept low by construction: the explanation is
**advisory-only** (never a finding/remediation and never auto-applied — a human disposes), the
**cited evidence is always shown alongside** it so an operator can verify the narrative against the
sources, the gate is **re-run at the durable persistence boundary** (`build_rca_advisories`) so a
worker/operator token cannot inject ungrounded text that is served as "grounded", and the whole
feature ships **dark behind a flag**. GO-LIVE is gated on the **CELA/HiTrust sign-off** that owns
acceptance of exactly this residual (`TODO(human)`), on this in-boundary, no-Microsoft-processing
pattern.
