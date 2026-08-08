# Connectors

Read-only **edge connectors** feed the AIOps module telemetry. Every connector is **read-only,
keyless, fail-closed, bounded, and free of any Azure/vendor SDK at import time**. The shared base
lives in [`src/shared/connectors`](../src/shared/connectors); see
[ADR 0004](adr/0004-connector-framework.md) for the rationale.

**Connectors:**

- **System Pulse** — Epic telemetry over HTTP (this document).
- **[Azure Monitor](azure-monitor.md)** — read-only metrics (`azure-monitor-querymetrics`) +
  aggregated, PII-safe logs (`azure-monitor-query`), keyless via Managed Identity. See that page
  for the least-privilege RBAC (Monitoring Reader / Log Analytics Reader), config env vars, and the
  no-raw-log-egress guarantee.
- **Log Sample** — in-boundary PII-free **log-feature** assist for AIOps log-anomaly detection
  (issue #53); returns only aggregate `LogFeatures`, never a raw log body (see below).
- **Azure OpenAI enrichment** — thin, keyless, in-boundary **LLM enrichment** edge (issue #53);
  advisory-only, sends only PII-free `LogFeatures`, no-ops when unconfigured (see below).
- **RCA explanation** — thin, keyless, in-boundary **LLM edge** that gives an advisory, **grounded**
  natural-language explanation of an existing auto-RCA (issue #54); reuses the #53 AOAI seam, sends
  only the RCA's already-cited fields, enforces a pure grounding gate, feature-flagged (see below).
- **Kuiper** — Epic *Kuiper* **discovery assist** (`src/modules/discovery/connectors/kuiper.py`).
  Unlike the AIOps telemetry connectors, Kuiper feeds the **Discovery** module. It is
  **fail-closed by default**: the concrete Kuiper endpoint, payload contract, and auth scheme are an
  external dependency owned by the product team (`TODO(human):` seams), so until a human wires an
  **approved `https` endpoint** the connector stays *unavailable* and never resolves a credential or
  makes a request. The endpoint is validated **before** any credential is resolved — it must be
  `https`, carry no userinfo/query/fragment, have a real (non-placeholder) host, carry **no explicit
  port**, not be an **IP literal** (loopback/link-local, and legacy octal/hex/integer/short numeric
  forms such as `0177.0.0.1`/`0x7f.0.0.1`/`2130706433`/`127.1`, included), and — after host
  canonicalization using the **same IDNA implementation HTTPX uses** (`idna.encode`, trailing dot
  stripped, lower-cased; a non-encodable host fails **closed**) — appear in an explicit
  operator-configured **approved-host allowlist** (there is **no** default host); otherwise it fails
  closed (credential-exfil safe). The request target is then **rebuilt from the validated canonical
  host** (never the raw `base_url`), so the host that was allowlist-checked is byte-for-byte the host
  HTTPX requests — a unicode-confusable host that canonicalizes differently under the legacy stdlib
  `idna` codec can never send a bearer to a different domain.
  - **Supplement-only, never authoritative.** Kuiper may only **annotate a resource ARG has already
    discovered**: a hint is accepted solely when its `resourceId` **exactly matches** an existing
    ARG node id, and then a bounded, fixed-vocabulary supplemental tag (`aegis:source=kuiper`, plus
    an optional closed-allowlist `aegis:kuiper-signal`) is added to that node. Kuiper **never**
    creates a node, **never** overrides/replaces/mutates an ARG field, and a hint matching no ARG
    node is dropped. ARG **always** wins an id collision.
  - **No graph emitted.** Discovery deliberately returns `graph=None`. The state writer
    UPSERT-**replaces** a workload's whole graph (`shared/state.py` `_write_graph`), so a
    Kuiper-derived graph from Discovery would wipe the authoritative `dependency_graph` edges.
    Kuiper therefore contributes supplemental **estate-node annotations only**.
  - **PII-safe & atomic.** The hint schema is a **closed** key set (`kind`/`resourceId`/`signal`);
    any unexpected key, charset/length-invalid `resourceId`, or non-allowlisted `signal` **rejects
    the entire fetch** (atomic — never a partially-fabricated topology). No free-form Kuiper string
    is ever copied into persisted state. The `KuiperHint` model **self-validates** (bounded-length,
    charset-restricted `resource_id`; `signal` ∈ a closed vocabulary) so the invariant holds no
    matter how a hint is constructed — Discovery treats **any** injected connector's `FetchResult`
    as untrusted and **re-validates** it before applying, failing closed on the whole batch.
    Because `model_construct`/`model_copy(update=...)` bypass pydantic validators, `apply_supplemental`
    **re-validates every hint at the persistence-adjacent boundary** (the last step before a tag is
    written) and drops any charset/vocabulary violation — the write boundary itself is the
    enforcement point, independent of how the `KuiperHint` was built.
  - **Bounded.** TLS verify on, a finite timeout, a **streamed**, size- AND time-bounded response
    body (an over-limit `Content-Length` is rejected before reading; the stream is aborted as soon
    as the running byte total exceeds the ceiling — never buffered whole; and the remaining overall
    deadline is checked on **every chunk** so a slow-drip body — HTTPX read timeouts are
    per-inactivity, not a total ceiling — is aborted mid-stream rather than drained), a max record
    count, a max per-field length, capped retries/delays, and an overall elapsed-time deadline
    enforced **before every attempt and sleep** (a slow attempt, slow stream, or slow success past
    the deadline fails closed). `httpx` is imported **lazily inside the edge**, so importing the
    connector (or Discovery) never imports `httpx` when Kuiper is absent.
  - Optional (injected via `ctx.clients["kuiper"]`); absent or failing closed, Discovery output is
    byte-for-byte identical to ARG-only (including `graph=None`). Everything is exercised with
    synthetic fixtures — no real Kuiper schema or endpoint is baked in.
  - **Deferred (TODO(human) / ADR needed):** Kuiper *dependency-edge* hints are intentionally **not**
    integrated in this issue. A future **merge-aware, non-destructive** edge integration is owned by
    the `dependency_graph` module (which holds the authoritative graph) and requires an Architect
    ADR — Discovery must not emit edges into the persisted graph. See the `TODO(human):` notes in
    `kuiper.py`.
- **Citrix** — Citrix control-plane **health + dependency assist**
  (`src/modules/dependency_graph/connectors/citrix.py`). A defensive twin of Kuiper that feeds the
  **Dependency & Blast Radius** module. Like Kuiper it is **fail-closed by default**: the concrete
  Citrix endpoint, payload contract, and auth scheme are an external dependency owned by the product
  team (`TODO(human):` seams, [ADR 0015](adr/0015-citrix-dependency-edge-merge-deferred.md)), so
  until a human wires an **approved `https` endpoint** the connector stays *unavailable*, resolves
  **no** credential, builds **no** `Authorization` header, and makes **no** network call. Endpoint
  validation runs **before** any credential is resolved with the same guarantees as Kuiper —
  `https`-only; no userinfo/query/fragment; a real (non-placeholder) host; **no** explicit port; not
  an **IP literal** (loopback/link-local and legacy octal/hex/integer/short numeric forms such as
  `0177.0.0.1`/`0x7f.0.0.1`/`2130706433`/`127.1` included); host canonicalized with the **same IDNA
  implementation HTTPX uses** (`idna.encode`, non-encodable host fails **closed**); and then present
  in an explicit operator-configured **approved-host allowlist** (**no** default host). The request
  target is **rebuilt from the validated canonical host**, never the raw `base_url`.
  - **Keyless via a `TokenProvider` abstraction.** The bearer is resolved (keyless order) via an
    injected `TokenProvider` → a Key Vault `SecretProvider` → a documented local-dev env-var
    fallback (`CITRIX_READ_TOKEN`), using the shared `resolve_bearer_token`. A **contract-mock**
    `MockCitrixTokenProvider` plus synthetic health/dependency payloads exercise the whole path
    without any real Citrix — no schema or endpoint is baked in.
  - **Supplement-only, never authoritative.** Citrix emits a **closed two-kind** signal model:
    `host-health` maps to a bounded, fixed-vocabulary supplemental **node tag**
    (`aegis:citrix-health` ∈ `{healthy, degraded, unreachable, maintenance}`, plus its provenance in
    `aegis:source`) applied **only** when its `resourceId` **exactly matches** an existing estate
    node id (via `apply_supplemental`). Provenance is **additive**: `aegis:source` is treated as a
    sorted, comma-joined **set** of contributing connectors, so a node already annotated by Kuiper
    (`aegis:source=kuiper`) becomes `aegis:source=citrix,kuiper` — Citrix **never clobbers** another
    connector's provenance (Kuiper's own tags are untouched). Citrix **never** creates, renames,
    retypes, or removes a node; a signal matching no node id is **dropped**; the estate always wins.
  - **Dependency edges parsed but NOT persisted (deferred).** `session-dependency` signals are
    validated and mapped to `DependencyEdge` objects by a **pure** `dependency_edges(...)` function
    (origin `connector:citrix`), but this mapping is **never merged into the returned graph** and
    never reaches the state writer. The module UPSERT-**replaces** a workload's whole graph, so a
    naive edge merge would wipe authoritative auto/pack edges — exactly the hazard Kuiper deferred.
    The non-destructive merge is owned by the `dependency_graph` module as a documented
    `TODO(human)` + [ADR 0015](adr/0015-citrix-dependency-edge-merge-deferred.md).
  - **PII-safe & atomic.** Each signal kind has a **closed** key set; any unexpected key,
    charset/length-invalid id, or non-allowlisted health token **rejects the entire fetch**. Only
    fixed constants / closed-vocabulary tokens are ever written; no free-form Citrix string is
    persisted. Both hint models **self-validate**, and — because `model_construct`/`model_copy`
    bypass validators — `apply_supplemental` **re-validates every signal at the persistence-adjacent
    boundary**. The module also treats any injected connector `FetchResult` as untrusted and
    re-validates it (`signals_from_result`) before applying, failing closed on the whole batch.
  - **Bounded.** TLS verify on, finite timeout, a **streamed** size- AND time-bounded response body
    (over-limit `Content-Length` rejected before reading; the running byte total checked **before**
    each append so a decompression bomb is aborted, never buffered whole; non-identity
    `Content-Encoding` refused), a max record count, a max per-field length, capped retries/delays,
    and an overall elapsed deadline checked **before every attempt and sleep** and on **every**
    chunk. `httpx` is imported **lazily inside the edge**, so importing the connector (or the
    `dependency_graph` module) never imports `httpx` when Citrix is absent.
  - **Off by default.** Optional, injected via `ctx.clients["citrix"]`; when absent — the default —
    the `dependency_graph` module runs **exactly as today** (byte-for-byte identical graph). A
    fail-closed, failing, or empty/unusable connector is swallowed as "estate-only graph" with a
    bounded, PII-free note (error **class name only**) — a Citrix problem can never break the module.
- **NetScaler & F5 (load-balancer connectors)** — two read-only **backend-pool + health assist**
  connectors that feed **smart blast-radius** via dependency edges
  ([`src/shared/connectors/netscaler.py`](../src/shared/connectors/netscaler.py) — Citrix NetScaler
  over **NITRO REST**; [`src/shared/connectors/f5.py`](../src/shared/connectors/f5.py) — F5 BIG-IP
  over **iControl REST**). Both are thin edges over the **shared LB machinery**: an
  [`edge.py`](../src/shared/connectors/edge.py) HTTPS edge (endpoint validation + streamed,
  size/time-bounded JSON reader + generic `HttpEdgeClient`) and a **vendor-neutral pure transform**
  [`lb.py`](../src/shared/connectors/lb.py). Like Kuiper/Citrix they are **fail-closed by default**:
  the concrete vendor endpoint, payload contract, and auth scheme are external dependencies owned by
  the product team (`TODO(human):` seams — the real NITRO/iControl schemas are not baked in), so
  until a human wires an **approved `https` endpoint** the connector stays *unavailable*, resolves
  **no** credential, builds **no** `Authorization` header, and makes **no** network call. Endpoint
  validation runs **before** any credential is resolved with the same guarantees as the sibling
  connectors — `https`-only; no userinfo/query/fragment; a real (non-placeholder) host; **no**
  explicit port; not an **IP literal** (loopback/link-local and legacy octal/hex/integer/short
  numeric forms included); host canonicalized with the **same IDNA implementation HTTPX uses**
  (`idna.encode`, non-encodable host fails **closed**); and then present in an explicit
  operator-configured **approved-host allowlist** (**no** default host). The request target is
  **rebuilt from the validated canonical host**, never the raw `base_url`.
  - **Keyless via a KV-backed token env name.** The bearer resolves (keyless order) via an injected
    `CredentialProvider`/`TokenProvider` → a Key Vault `SecretProvider` → a documented local-dev
    env-var fallback — `NETSCALER_READ_TOKEN` / `F5_READ_TOKEN` — using the shared
    `resolve_bearer_token`. No secret literal ever appears in code, config, or tests; the env var
    holds only a **name**. A contract-mock `MockLbTokenProvider` plus synthetic NITRO / iControl
    payloads exercise the whole path without any real vendor — no schema or endpoint is baked in.
  - **Backend-pool membership → dependency edges.** The pure `dependency_edges(...)` maps each
    `backend-member` signal to an `EdgeType.load_balances` edge (`source=lbId → target=memberId`,
    origin `connector:netscaler` / `connector:f5`, `redundant` set when a pool has more than one
    distinct member). **Both** endpoints must already exist in the estate id set — an edge touching
    an unknown id, a self-edge, a duplicate, or a bypass-constructed (`model_construct`) invalid id
    is **dropped**. These edges land in the exact shape smart blast-radius / the dependency graph
    already consumes (matching #47/#48).
  - **Aggregate health, never per-request bodies.** `aggregate_health(...)` reduces each LB's
    distinct member-health token set to a single `HealthState` (`{up}`→up, `{down}`→down,
    `{unknown}`→unknown, any other mix→degraded); `apply_health(...)` writes it as a bounded
    supplemental tag (`aegis:lb-health`) and **additively** unions the connector into the existing
    `aegis:source` set (never clobbering another connector's provenance). Only aggregate health and
    fixed-vocabulary **filtered-log-derived signals** (`log_signals` → closed metric allowlist
    `{error_rate, reset_rate, conn_drops}`) leave the boundary — **never a raw log body**; expected
    PII egress is **NONE**.
  - **PII-safe & atomic.** The common signal model is a **closed** two-kind key set
    (`backend-member` / `log-signal`); the vendor parsers **project only known fields**, so any
    unexpected vendor key is **dropped** (never copied into a signal, so it can never ride the
    boundary), while a charset/length-invalid id or non-allowlisted health/metric token in a field
    that *is* read **rejects the entire fetch** (atomic — never a partially-fabricated topology).
    Both hint models **self-validate**, and — because `model_construct`/`model_copy` bypass
    validators — `signals_from_result` **re-validates** every injected `FetchResult` as untrusted
    before use, failing closed on the whole batch.
  - **Bounded & SDK-free.** TLS verify on, finite timeout, a **streamed** size- AND time-bounded
    response body (over-limit `Content-Length` rejected before reading; running byte total checked
    per chunk; non-identity `Content-Encoding` refused), a max record count, a max per-field length,
    capped retries/delays with jitter, and an overall elapsed deadline checked **before every
    attempt and sleep** and on **every** chunk. Malformed payloads are **not** retried (mapping runs
    once, outside the retry loop). `httpx` is imported **lazily inside the edge**, so importing
    either connector never imports `httpx` when the vendor is absent.
  - **Off by default.** Optional; with no approved endpoint / no credential the connector is inert
    (`available=False`) and emits nothing. Everything is exercised with synthetic fixtures only —
    no real NITRO/iControl schema or endpoint is baked in.
- **Log Sample** — in-boundary **PII-free log-feature assist** for AIOps log-anomaly detection
  ([`src/modules/aiops/connectors/log_sample.py`](../src/modules/aiops/connectors/log_sample.py),
  issue #53). Fetches a bounded in-boundary log sample per resource window and returns **only**
  `shared.contracts.LogFeatures` — aggregate counts/rates, one-way structural-template hashes, and
  numeric duration percentiles. **The raw log body never leaves the edge:** the pure extractor
  (`modules.aiops.log_features.extract_log_features`) is applied *inside* the connector, so what
  crosses the boundary (and what the module ever sees) is the aggregate feature contract, never a
  message/id/PII. Keyless via `DefaultAzureCredential`; field NAMES (level/message/duration/
  timestamp) come from **env-var names**, never pack content. Off by default: the real SDK backend
  raises `LogSampleSdkNotWired` until a human wires it, so absent config the connector is inert and
  log-anomaly detection simply does not run (fail-closed by absence). Expected PII egress is
  **NONE**; exercised with synthetic fixtures only.
- **Azure OpenAI enrichment** — thin **keyless, in-boundary LLM enrichment edge**
  ([`src/modules/aiops/connectors/openai_enrichment.py`](../src/modules/aiops/connectors/openai_enrichment.py),
  issue #53, reusable by #54). Built on the shared connector base; configured **purely by env-var
  NAMES** (endpoint/deployment/region). It sends **only** the already-computed PII-free
  `LogFeatures` (never raw logs/PII), **region-pins** (deployment region must match the platform
  region), validates the endpoint (SSRF guard, `https`-only) **before** resolving a credential via
  `DefaultAzureCredential`, and returns **advisory-only** enrichment. **No-ops / degrades
  gracefully** to the pure statistical result when UNCONFIGURED — the pure anomaly core is fully
  valuable with **no** endpoint configured; the LLM is enrichment, not a dependency. Free-text
  enrichment lands in `extra["logAnomalyEnrichment"]`, which the egress choke point redacts. See
  [ADR 0019](adr/0019-pii-free-log-anomaly-advisory.md).
- **RCA explanation** — thin **keyless, in-boundary LLM edge** that produces an **advisory,
  grounded natural-language explanation** of an existing auto-RCA
  ([`src/modules/aiops/connectors/rca_explanation.py`](../src/modules/aiops/connectors/rca_explanation.py),
  issue #54). It **reuses the #53 AOAI seam** via the shared
  [`src/shared/connectors/aoai.py`](../src/shared/connectors/aoai.py) helper (trusted-host suffixes,
  endpoint validation, region-pin, lazy SDK transport, `COGNITIVE_SCOPE`), so it inherits ALL the
  #53 guardrails: configured **purely by env-var NAMES**, **region-pins** and validates the endpoint
  **before** resolving a credential via `DefaultAzureCredential` (keyless), and **no-ops when
  UNCONFIGURED**. It sends **only** the RCA `AgentResponse`'s already-cited fields
  (`findings`/`risks`/`recommendations`/`sourceReferences`/`confidence`) — never new data — and a
  **pure grounding gate** ([`src/modules/aiops/rca_grounding.py`](../src/modules/aiops/rca_grounding.py))
  rejects any explanation that introduces an un-cited resource id / nodeId / metric (fail-closed).
  Below `RCA_CONFIDENCE_FLOOR` it asserts nothing and surfaces the support path. The advisory is
  **advisory-only** (never a finding/remediation/nextAction) and lands in
  `extra["rcaExplanation"]`, which the egress choke point redacts. **Feature-flagged**
  (`$AIOPS_RCA_EXPLAIN_ENABLED`); GO-LIVE awaits CELA/HiTrust sign-off (`TODO(human)`). Expected PII
  egress is **NONE**; exercised with synthetic fixtures only. See
  [ADR 0020](adr/0020-grounded-rca-explanation-in-boundary-llm.md).

## The pattern

A connector is a thin client whose **only** I/O is one `fetch_raw()` edge method. Pure mapping
(raw payload → PII-safe signals) is a separate, unit-tested function. Compose the shared helpers —
don't re-derive them:

| Helper (`shared.connectors`) | Responsibility |
|------------------------------|----------------|
| `FetchResult` | The single fetch envelope: `available` / `raw` / `error` (error **class name only**). |
| `TokenProvider` / `CredentialProvider` | Keyless seams — an injected Managed-Identity provider, or a Key Vault-backed token **env var name**. |
| `SecretProvider` | Keyless seam — a Key Vault-backed provider (`get_secret(name)`) resolving secrets by Managed Identity at composition/fetch time ([`shared/secret_provider.py`](../src/shared/secret_provider.py)). |
| `resolve_bearer_token(provider, token_env, *, secret_provider, secret_name)` | Canonical order: injected Managed-Identity provider wins → Key Vault `secret_provider.get_secret(secret_name)` (authoritative, fail-closed) → `os.environ[token_env]` (local-dev fallback) → `None`. |
| `run_with_retries(fn, *, attempts, base_delay_s, max_delay_s, sleep, rng, retry_on)` | Bounded exponential backoff **with jitter**; retries only `retry_on` exceptions; deterministic via injected `sleep`/`rng`. |
| `fail_closed(fn)` | Converts **any** exception into `FetchResult(available=False, error=type(exc).__name__)`; passes a success through. |

## Rules

- **Fail closed.** No credential → `error="NoCredential"` and **no** network call. Any error →
  `available=False`, error **class name only** — never a body, message, or token.
- **Keyless.** Never embed a secret/key/connection string. In Azure, secrets/tokens resolve from
  **Key Vault by Managed Identity** (fail-closed via the `SecretProvider`); env vars hold **names**
  and serve only as a documented **local-dev fallback** when no Key Vault URI is configured
  (see [ADR 0012](adr/0012-key-vault-secret-injection.md)), or use an injected Managed-Identity provider.
- **Bounded.** TLS verify on, a finite timeout, and bounded retry (`attempts` exhausted ⇒ still
  fails closed). Retry only *transient* transport errors; a 5xx or malformed payload fails closed
  at once.
- **PII-safe mapping.** The raw→signal mapping keeps a strict allowlist of detection fields and
  drops every free-text / body / patient / user / message field by construction.
- **SDK-free at import.** Any Azure/vendor SDK is imported lazily *inside* `fetch_raw`, never at
  module top level, so `mypy src` and unit tests stay Azure-free.

## Testing

Drive connectors with the synthetic-payload harness in
[`tests/support/connectors.py`](../tests/support/connectors.py) — obviously-fake resource ids,
metrics and payloads (no PII/PHI, no real endpoints). Inject `sleep`/`rng` (e.g.
`RecordingSleep()` + a seeded `random.Random`) so retry tests are deterministic and never sleep for
real. See [`tests/unit/test_connector_base.py`](../tests/unit/test_connector_base.py) for examples.
