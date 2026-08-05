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
