# 0019. PII-free log AI analysis + statistical anomaly detection (advisory)

Date: 2026-08-06 · Status: accepted

## Context

Issue #53 adds log AI analysis with statistical anomaly detection to the AIOps module. The product
owner has approved the posture; this ADR records the design that satisfies it and the contract
additions it required.

The hard constraint is **data handling** (pending formal CELA/HiTrust sign-off, so it must be
**safe by construction**, not merely by policy): only **aggregate, PII-free** log-derived features
may ever leave the log boundary. Raw log bodies, messages, identifiers, and any PII must NEVER
egress — not to storage, not across a module boundary, and not to any model/LLM endpoint. The
feature is **advisory only** and must **fail closed** everywhere: low confidence, unknown, or a
short baseline surfaces a "contact support" note and asserts nothing.

Two existing invariants shape the design:

- The **no-PII-egress auditor** (`scripts/audit_no_pii_egress.py`) and the egress redaction choke
  point (`_redact_run_result_for_egress`) already police what leaves a run. Any new response shape
  must be provably PII-free.
- **Finding provenance** (ADR 0013) requires every pack-derived finding to cite a non-blank
  `packId`/`packVersion`; the telemetry-pack trust gate (signature verification, issue #51) already
  gates detector compilation.

## Decision

**1. Three additive, aggregate-only contracts in `shared/contracts.py`.** The `AgentResponse` /
`Finding` shapes are NOT forked. We add:

- `LogLevel` — a **closed** `StrEnum` (`debug|info|warn|error|critical|other`). Because it is closed,
  the keys of `LogFeatures.countsByLevel` are statically enumerable and auditor-safe, and an
  arbitrary level token (which could smuggle text) can never be retained; any unknown/absent level
  normalizes to `other`.
- `TemplateFrequency` — one structural template's `signature` + `count` + `fraction`. The
  `signature` is a **one-way SHA-256 hex digest** (64-char, pattern-pinned) of a message's
  structural *shape* after every value token was stripped to a class placeholder. `extra="forbid"`.
- `LogFeatures` — the SOLE log-derived payload allowed to cross the log boundary: counts by level,
  error/warning rates, total volume, distinct-template count, top-template frequencies (signatures
  only), and duration percentiles when a numeric duration field is present. `extra="forbid"` blocks
  any raw-payload passthrough.

**2. PII-freeness is by construction, not by review.** The pure extractor
(`modules.aiops.log_features.extract_log_features`) is provably incapable of emitting raw text:

- **Allowlist read.** Only the fields NAMED in the injected `LogFeatureExtractionSpec` (level /
  message / duration / timestamp) are ever read; every other key is ignored by construction. Field
  NAMES are a deployment/connector concern supplied by **env-var names**, never pack content or raw
  values.
- **One-way structural signature.** A message is used in-boundary ONLY to compute the SHA-256 of its
  value-stripped shape (numbers, GUIDs, emails, IPs, timestamps, paths, urls, quoted strings, long
  hex/ids → placeholders) BEFORE hashing. The raw message is never stored; a hash cannot be reversed
  and cannot carry a residual literal the stripper missed. This makes the "a message/id/PII in the
  input never appears in the features" test trivially true.
- **Aggregates only + default-DENY.** Everything emitted is a count, rate, one-way hash, or numeric
  percentile. A non-mapping record or an unexpected leaf contributes nothing free-text.

The extractor is a **pure function** (no I/O, no Azure, no network), unit-tested, and bounded
(`MAX_SAMPLE_RECORDS`).

**3. Robust, deterministic anomaly scoring; advisory + fail-closed.**
`modules.aiops.log_anomaly.score_log_anomalies` scores the current window against a baseline of
prior windows' `LogFeatures` using **median + MAD** (or **EWMA + z-score**) — robust statistics, no
ML training, no external call, deterministic. Guardrails:

- **Confidence floor.** `LOG_ANOMALY_CONFIDENCE_FLOOR` mirrors `modules.aiops.rca.RCA_CONFIDENCE_FLOOR`
  (ADR/issue #50). Below the floor — or when the robust scale is degenerate (all-equal baseline) —
  we do NOT assert a finding; we surface an advisory "contact support" note.
- **Short/empty baseline ⇒ no detection.** Fewer than the pack's `minBaseline` usable prior windows
  yields NO finding for that feature (fail-closed by absence), never a fabricated one.
- **Provenance.** Every emitted `Finding` cites its telemetry pack (id + version) and the observation
  window via `SourceReference` (kinds `pack` + `log`), satisfying ADR 0013.

**4. Content over code.** WHICH features to watch and the z-score→severity bands are driven by the
VERIFIED **Telemetry Pack**, not a Python branch. `telemetry.schema.json` gains an optional
`logAnalysis.anomaly` section (feature list, method, `minBaseline`, per-band `z`/severity,
`ewmaAlpha`, `advisoryZScore`); `schema.py` adds finite-number validation for its float leaves so
JSON's `nan`/`inf` are rejected fail-closed. `compile_log_anomaly_specs` compiles the verified pack
body into pure specs downstream of the existing signature-verification trust gate. A synthetic,
clearly-fake signed pack fixture (`content/telemetry/synthetic-log-anomaly.json`) exercises it.

**5. Keyless in-boundary LLM enrichment is optional and fail-closed.** A thin Azure OpenAI edge
(`modules/aiops/connectors/openai_enrichment.py`), built on the shared connector base, is configured
purely by **env-var NAMES** (endpoint/deployment/region) and resolves credentials via
`DefaultAzureCredential` (keyless, Managed Identity) — no key/secret/connection string anywhere. It:
region-pins, sends ONLY the already-computed PII-free features (never raw logs/PII), returns
advisory-only enrichment, and **no-ops / degrades gracefully to the pure statistical result when
UNCONFIGURED**. The pure core (deliverables 1–3) is fully valuable with NO endpoint configured — the
LLM is enrichment, not a dependency. Free-text enrichment is placed in `extra["logAnomalyEnrichment"]`,
which the egress choke point redacts via `redact_tree`, so it is fail-closed safe by design.

**5a. Structural-template signatures NEVER egress (enrichment projection).** The one-way structural
signature is honest about a residual risk: value-token stripping removes quoted strings, numbers,
GUIDs, emails, IPs, paths, and urls, but a **bare unquoted lexical token** (a username, hostname, or
opaque identifier that fits none of those classes) can survive into the hash *preimage*. Because a
low-entropy preimage is brute-forceable offline, the signature is treated as an **internal,
in-boundary-only structural correlation key**, not a PII-free value. Two defenses make this safe:
(a) `structural_signature` additionally neutralizes residual identifier-like tokens (anything with a
digit/underscore, any mixed/upper case, or longer than 20 chars) to a bare `<tok>` placeholder
before hashing, keeping only short lowercase keyword words; and (b) — the definitive control — the
LLM edge sends `LogFeatures.enrichment_payload()`, a projection that **drops every
`topTemplates[].signature`** (keeping `distinctTemplateCount` and each template's `count`/`fraction`
plus all numeric/level/duration aggregates). An opaque hash gives the model no value anyway, so the
signature simply never crosses to the model. The over-claiming "cannot carry a residual literal"
docstrings were corrected to state this explicitly: the no-egress guarantee is enforced by the
projection, not by asserting the preimage is literal-free.

## Consequences

- **+** Log anomaly detection ships with **zero** raw-log/PII egress risk that depends on reviewer
  vigilance: the boundary is a closed enum + one-way hash + aggregate numerics, so the auditor and
  egress redaction stay green by construction.
- **+** The pure extractor and scorer are deterministic, unit-tested, and independent of Azure/LLM —
  they run and are correct with no endpoint configured.
- **+** Detection knowledge lives in the telemetry pack (content over code); new features/bands need
  no Python change, only signed pack content.
- **+** Additive to `shared/contracts.py` (three new models); `AgentResponse`/`Finding` unchanged.
- **−** The structural signature is a hash, so an operator cannot read the offending message text
  from a finding — by design. Root-cause drill-down that needs the raw line must stay in-boundary via
  the support path; the advisory surfaces the template's identity + frequency, not its text.
- **−** A new telemetry-pack section (`logAnalysis.anomaly`) adds schema surface that must be kept in
  sync between `telemetry.schema.json`, `schema.py` finite validation, and `compile_log_anomaly_specs`.
