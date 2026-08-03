# 0004. Connector framework: shared fail-closed thin-client base

Date: 2026-08-04 · Status: accepted

## Context

The AIOps module reads telemetry through **read-only edge connectors** — today System Pulse
(HTTP) and Azure Monitor (SDK/backend), tomorrow Kuiper/Citrix/F5. Each connector had independently
reimplemented the same edge machinery: a `FetchResult` envelope, the keyless credential-resolution
order (injected Managed-Identity provider wins, else a Key Vault-backed token **env var name**,
else fail closed with no network call), strict payload coercion, TLS-verified bounded transport,
and the `except Exception: return FetchResult(available=False, error=type(exc).__name__)` fail-closed
block. Azure Monitor already imported `FetchResult` from System Pulse, so a generic connector
contract was leaking into an AIOps-domain module.

Duplicated edge code drifts. It also left one genuinely missing capability unaddressed: a **bounded
retry with jitter** for transient transport blips, without which a single dropped packet reads as a
full source outage.

## Decision

Introduce a shared, reusable connector base at **`src/shared/connectors`** (contracts live in
`src/shared`, per the guardrails) providing small, composable, SDK-free helpers:

- **`FetchResult`** — the single shared fetch envelope. It **moves** here from
  `modules.aiops.connectors.system_pulse` and is **re-exported** from `system_pulse` and
  `modules/aiops/connectors/__init__.py` for backward compatibility, so existing imports and the
  AIOps module keep working unchanged.
- **`TokenProvider` / `CredentialProvider`** — the keyless credential seams (injected callables).
- **`resolve_bearer_token(provider, token_env)`** — the connectors' canonical resolution order.
- **`run_with_retries(fn, *, attempts, base_delay_s, max_delay_s, sleep, rng, retry_on)`** — the
  new bounded **exponential backoff with full jitter**: it sleeps uniformly in
  `[0, min(max_delay_s, base_delay_s * 2**(n-1)))` (i.e. `capped * rng.random()`), so a delay never
  exceeds `max_delay_s`. `sleep` and `rng` are injected so the schedule is fully deterministic and
  unit tests never sleep for real; both default to the real `time.sleep` / a fresh `random.Random`
  in production.
- **`fail_closed(fn)`** — converts **any** exception from an edge callable into
  `FetchResult(available=False, error=type(exc).__name__)` (error **class name only** — never a
  body, message, or token) and passes a successful result through unchanged.

Both connectors are rebased onto these helpers (behaviour-preserving) and now retry only *transient*
failures before failing closed: System Pulse retries `httpx.TransportError` (a 5xx or malformed
payload fails closed at once); Azure Monitor retries transient backend/transport errors matched by
class name (the not-wired SDK stub, credential errors and malformed payloads do not). Each connector
Config gained `retries` / `base_delay_s` / `max_delay_s` (defaults 3 / 0.2s / 2.0s) that never
change the fail-closed outcome — after the attempts are exhausted the edge still fails closed.

**AIOps-domain shapes stay put.** `Signal`, `SignalSource`, `map_signal`, `SignalMappingError`,
`to_signals`, and `to_source_reference` remain in `system_pulse` — they are AIOps detection
contracts, not generic connector machinery, and moving them would widen this contract change
unnecessarily.

No Azure or vendor SDK is imported at connector/base import time; any SDK stays lazy inside a
connector's edge method, keeping `mypy src` and unit tests Azure-free.

## Consequences

- **+** One tested home for the edge envelope, keyless resolution, retry, and fail-closed wrapper;
  new connectors compose the helpers instead of re-deriving them.
- **+** Transient transport blips no longer read as outages, yet every failure still fails closed
  with a class-name-only error — no PHI/PII/token egress.
- **+** Retry is fully deterministic and instant under test via injected `sleep`/`rng`.
- **−** `FetchResult` now has two import paths (the shared home + the compat re-export) until callers
  migrate to `shared.connectors`.
- **−** Connectors that share the same injected `httpx.Client`/backend across retries rely on that
  transport being safe to re-invoke; the bounded attempt count caps the blast radius.
