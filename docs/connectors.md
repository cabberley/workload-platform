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
