# Connectors

Read-only **edge connectors** feed the AIOps module telemetry. Every connector is **read-only,
keyless, fail-closed, bounded, and free of any Azure/vendor SDK at import time**. The shared base
lives in [`src/shared/connectors`](../src/shared/connectors); see
[ADR 0004](adr/0004-connector-framework.md) for the rationale.

## The pattern

A connector is a thin client whose **only** I/O is one `fetch_raw()` edge method. Pure mapping
(raw payload → PII-safe signals) is a separate, unit-tested function. Compose the shared helpers —
don't re-derive them:

| Helper (`shared.connectors`) | Responsibility |
|------------------------------|----------------|
| `FetchResult` | The single fetch envelope: `available` / `raw` / `error` (error **class name only**). |
| `TokenProvider` / `CredentialProvider` | Keyless seams — an injected Managed-Identity provider, or a Key Vault-backed token **env var name**. |
| `resolve_bearer_token(provider, token_env)` | Canonical order: injected provider wins → `os.environ[token_env]` → `None`. |
| `run_with_retries(fn, *, attempts, base_delay_s, max_delay_s, sleep, rng, retry_on)` | Bounded exponential backoff **with jitter**; retries only `retry_on` exceptions; deterministic via injected `sleep`/`rng`. |
| `fail_closed(fn)` | Converts **any** exception into `FetchResult(available=False, error=type(exc).__name__)`; passes a success through. |

## Rules

- **Fail closed.** No credential → `error="NoCredential"` and **no** network call. Any error →
  `available=False`, error **class name only** — never a body, message, or token.
- **Keyless.** Never embed a secret/key/connection string. Env vars hold **names**, resolved to
  Key Vault-backed values at runtime, or use an injected Managed-Identity provider.
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
