# 0016. Entra (Azure AD) auth for console/API — keyless JWKS validation + least-privilege app-role RBAC

Date: 2026-08-14 · Status: accepted

## Context

The FastAPI core ([`src/api/app/main.py`](../../src/api/app/main.py)) exposed **state-mutating
`POST` endpoints** (run a module, submit results/estate/graph/findings/snapshot) with **no
authentication or authorization** at the application layer. Anything that could reach the API could
mutate platform state. Worse, the audit **actor** was resolved from a *raw request header*
(`resolve_actor(request.headers)` → `PRINCIPAL_ID_HEADER`, [`src/shared/audit.py`](../../src/shared/audit.py)) —
an unauthenticated caller could **spoof the audit subject** by setting a header, defeating the
provenance guarantee ([ADR 0006](0006-audit-trail-and-provenance.md)).

The per-component **managed identities** (#79, [rbac-matrix](../security/rbac-matrix.md)) give the
platform least-privilege at the **Azure control/data plane** (which identity may read ARG, write
Blob/Table, etc.). But that is orthogonal to **who may call the API and what they may do** — an
*application-layer* authN/authZ concern for human/console and service-to-service callers. Issue #64
(epic #17, M4) owns closing that gap, keyless and fail-closed, consistent with the platform's
established guardrails: no shared secrets ([ADR 0012](0012-key-vault-secret-injection.md)), public-key-only
trust ([ADR 0010](0010-pack-signing-trust-root.md)), fail-closed emission ([ADR 0014](0014-fail-closed-audit-emission.md)),
and no-PII-egress.

## Decision

**Protect the API (and gate the console) with Entra ID OIDC bearer tokens, validated KEYLESSLY
against the tenant's JWKS public keys, and authorize every state-mutating request against a
least-privilege app-role model — deny-by-default, fail-closed. The audit actor for an
authenticated request derives from the *validated* `oid` claim, never a header.**

### 1. Keyless token-validation seam — `src/shared/auth/`

A small, SDK-light, self-contained validator ([`src/shared/auth/`](../../src/shared/auth/)):

- **Public-key-only signature verification.** RS256 is verified with the `cryptography` library
  (already a direct dependency, via `azure-identity`): the RSA public key is reconstructed from the
  JWKS `n`/`e` and the signature checked with PKCS1v15 + SHA-256
  ([`validator.py`](../../src/shared/auth/validator.py), [`jwks.py`](../../src/shared/auth/jwks.py)).
  **No client secret exists anywhere** — validation needs only the tenant's published *public* keys.
  We deliberately do **not** add PyJWT or a server-side MSAL dependency for validation; the RS256
  verify is a few lines against a dependency we already ship.
- **JWKS fetched from OIDC discovery, cached with a bounded TTL, refreshed on unknown `kid`**
  ([`JwksKeyProvider`](../../src/shared/auth/jwks.py)). The HTTP fetch (lazy `httpx`, already a
  dependency) and the clock are **injectable**, so unit tests are network-free and keyless.
- **`alg` is pinned to RS256.** `alg: none` and HMAC (`HS256`, which would require a shared secret)
  are rejected before any signature check.
- **Config-driven, fail-closed by default, reusing the existing env/config idiom** (mirrors
  `build_secret_provider` / `build_state_store`): [`build_auth_config`](../../src/shared/auth/config.py)
  reads `WP_AUTH_TENANT_ID`, `WP_AUTH_AUDIENCE`, optional `WP_AUTH_ALLOWED_ISSUERS`, optional
  `WP_AUTH_JWKS_URI`; the canonical Entra v2.0 issuer/JWKS are derived from the tenant when not
  overridden. Auth is governed by an **explicit** `WP_AUTH_MODE ∈ {required, disabled}` that
  **defaults to `required`** (fail-closed) — a missing/blank config no longer means "no auth". Under
  `required` the tenant+audience MUST be present and valid or the API **refuses to serve** (a
  startup guard aborts); under `disabled` (the ONLY, deliberate no-auth opt-out for local
  dev / CI / tests) `build_token_validator()` returns `None` and logs a prominent warning. A
  **partial** config (one of tenant id / audience present, the other blank) is always a hard error,
  in any mode — a misconfiguration can never silently disable auth. See the mode precedence table
  below.
- **Claims checked:** issuer, audience (string or list), `exp`, `nbf` (60 s leeway, injectable
  clock). From the *validated* claims it extracts a **non-PII principal id** — the `oid` (object id),
  never name/email — and the **`roles`** claim.
- **Fail closed, PII-free.** Every failure (bad signature, unknown `kid`, wrong `aud`/`iss`, expired,
  malformed) raises a typed `AuthenticationError` carrying a **generic reason code only** — never the
  token, claims, or any PII ([`errors.py`](../../src/shared/auth/errors.py)) — mirroring the
  connector `FetchResult.error` = class-name-only discipline. The API maps it to 401; an authorized
  token with an insufficient role maps to 403.

### 2. Least-privilege app-role model + deny-by-default RBAC — `src/api/app/main.py`

- **Three app roles**, table-driven ([`roles.py`](../../src/shared/auth/roles.py)):
  **`Workloads.Reader`** (read/GET), **`Workloads.Operator`** (run modules; submit
  results/estate/graph/findings/snapshot), **`Workloads.Admin`** (Operator ⊇ Reader, plus future
  admin actions). Grants are an explicit closure (`admin ⊃ operator ⊃ reader`); **deny-by-default** —
  a caller with none of these roles is authorized for nothing.
- **A FastAPI `require_role(...)` dependency** validates the bearer token via the seam, stashes the
  validated `Principal` on `request.state`, then authorizes the request's required role. It is
  enforced on **all six state-mutating `POST` endpoints** (Operator): `/api/modules/{name}/run`,
  `/api/workloads/{workload}/results|estate|graph|findings|snapshot`; and on the **read `GET`
  data endpoints** (Reader) when auth is enabled. **`/api/health*` and `/` stay unauthenticated**
  (liveness/readiness probes).
- **Auth is fail-closed by default (`WP_AUTH_MODE`).** `require_role` sees a `None` validator
  **only** under the deliberate `WP_AUTH_MODE=disabled` opt-out (local-dev/worker path) and permits
  then; a misconfigured deployment can never reach that branch because the **startup guard**
  (`_enforce_auth_startup`) eagerly builds the validator and aborts start-up on a missing/partial
  `required`-mode config. **When auth IS enabled it is fail-closed:** missing/invalid token →
  **401**; valid token, insufficient role → **403**; it **never** falls open to the `system` actor
  for a mutating request.

### 3. Audit actor from the *validated* claim

The mutating endpoints resolve the audit actor via a new `_request_actor(request)` that reads the
validated `Principal.oid` off `request.state`. `resolve_actor` ([`audit.py`](../../src/shared/audit.py))
gained an optional `principal_id` parameter: **a validated principal id takes precedence over the
`PRINCIPAL_ID_HEADER`**, and the header is consulted **only** on the documented no-auth
local/dev/worker path (when no validated principal is present). This closes the spoofable-actor gap:
a request bearing a valid token but an attacker-supplied `PRINCIPAL_ID_HEADER` audits the token's
`oid`, not the header.

### 4. Console sign-in (React SPA) — config-flagged, keyless (PKCE)

The console ([`src/web/`](../../src/web/)) gains an **optional** Entra sign-in via
`@azure/msal-browser` (public client, **PKCE — no secret**), behind a config flag
([`auth/config.ts`](../../src/web/src/auth/config.ts) reads `VITE_AUTH_*`; returns `null` ⇒ the
console runs locally without auth, like the backend). When configured, [`AuthProvider`](../../src/web/src/auth/AuthProvider.tsx)
gates the app behind a sign-in prompt and registers a token getter with the API client
([`api/client.ts`](../../src/web/src/api/client.ts) `setAuthTokenProvider`), which attaches a **fresh**
`Authorization: Bearer` on every `/api/*` request. Tokens are acquired silently per request and never
stored by our code or logged.

### 5. App-registration provisioning — a documented deploy step

Two Entra **app registrations** are provisioned out of band (never committed; no secret):

1. **API app registration** — *Expose an API*: set the Application ID URI (`api://<api-app-id>`) and
   define **app roles** `Workloads.Reader`, `Workloads.Operator`, `Workloads.Admin` (assignable to
   users and/or applications). Set the API's env: `WP_AUTH_TENANT_ID`, `WP_AUTH_AUDIENCE`
   (the Application ID URI or client id).
2. **Console SPA app registration** — a **public client** (SPA platform, PKCE, no secret) with the
   SPA origin as a **redirect URI**, and delegated permission to the API scope. Set the SPA build
   env: `VITE_AUTH_CLIENT_ID`, `VITE_AUTH_TENANT_ID` (or `VITE_AUTH_AUTHORITY`),
   `VITE_AUTH_API_SCOPE` (`api://<api-app-id>/.default`).
3. **Service-to-service (worker → API) — keyless, wired in code.** The worker
   ([`src/cli/worker.py`](../../src/cli/worker.py)) authenticates with **its own managed identity**
   (#79): [`build_api_token_provider`](../../src/shared/auth/token_source.py) reads the same
   `WP_AUTH_MODE` config as the server and, under `required`, mints a token for the API's
   `<WP_AUTH_AUDIENCE>/.default` scope via `DefaultAzureCredential` and attaches it as
   `Authorization: Bearer` on the worker→API submit; under `disabled` it sends no header (matching a
   server that is not enforcing). The `azure-identity` credential is kept at an **injectable edge**
   (a `TokenProvider`-style callable, mirroring `shared.connectors`) so unit tests stay keyless and
   network-free; inability to mint **fails closed** (raises — the worker never falls back to an
   unauthenticated write). **No shared key.** The `Workloads.Operator` **app role** must be assigned
   to `identityWorker` — an Entra app-role assignment (Microsoft Graph `appRoleAssignedTo`), which
   is **not** ARM/Bicep-expressible, so it is a documented `az rest`/Graph **deploy step** (see
   "Wiring status" and [rbac-matrix](../security/rbac-matrix.md)).

All three reference the **per-component identities** of #79 — least privilege is real because each
component presents a **distinct** identity, and the API authorizes each by app role.

## Auth mode precedence (fail-closed by default)

`WP_AUTH_MODE` is resolved first; `build_auth_config` validates the tenant/audience shape. A
**partial** config always wins as a hard error, so a half-provisioned deployment can never run
wide-open.

| `WP_AUTH_MODE` | tenant + audience | Result |
| --- | --- | --- |
| unset / `required` (default) | both present & valid | **Enforced** — every request authenticated + authorized |
| unset / `required` (default) | both absent | **Startup refuses to serve** (`AuthConfigError`) — never permit-all |
| unset / `required` (default) | exactly one present (partial) | **Startup refuses to serve** (`AuthConfigError`) |
| `disabled` | any (incl. partial ⇒ still error) | **No auth** — deliberate local/CI/test opt-out; logs a prominent warning; validator is `None` |
| unknown value | — | **`AuthConfigError`** (fail closed) |

The worker's [`build_api_token_provider`](../../src/shared/auth/token_source.py) obeys the **same**
table: `disabled` ⇒ no bearer; `required` + configured ⇒ mint & attach; `required` + missing/partial
⇒ fail closed. Local dev / CI / tests set `WP_AUTH_MODE=disabled` explicitly (the test suite does so
in [`tests/conftest.py`](../../tests/conftest.py)); production leaves the default `required` and
provides the (non-secret) `WP_AUTH_TENANT_ID` / `WP_AUTH_AUDIENCE`.

## Wiring status (honest)

- **Wired in code & tested:** the keyless validator; the **fail-closed `WP_AUTH_MODE` default** and
  the **startup guard** that refuses to serve on missing/partial `required` config; deny-by-default
  `require_role` on all six POST endpoints and the GET data endpoints; health carve-out;
  audit-actor-from-validated-`oid`; the console token-attachment seam and config-flagged MSAL
  sign-in; and the **worker's keyless bearer** via the injectable `DefaultAzureCredential` seam.
  Bicep threads the non-secret `WP_AUTH_MODE` / `WP_AUTH_TENANT_ID` / `WP_AUTH_AUDIENCE` env into the
  API and job containers (`module-app.bicep`, `module-job.bicep`, `main.bicep`) with `authMode`
  defaulting to `required`. Unit + integration tests cover the full fail-closed matrix (including
  the mode precedence table, the startup-refuses cases, and the worker bearer attachment), using
  injected key/claims/credential seams — no network, no real Entra.
- **`TODO(human)` — deploy-time, out of band:** create the two app registrations, define the app
  roles, **assign `Workloads.Operator` to `identityWorker`** and the appropriate roles to
  human/console principals (Entra app-role assignment via Microsoft Graph `appRoleAssignedTo` — an
  `az rest` step, not ARM/Bicep), set the deployment values for the API `WP_AUTH_TENANT_ID` /
  `WP_AUTH_AUDIENCE` params and the SPA `VITE_AUTH_*` env, and add the SPA redirect URI. Until the
  API is provisioned with tenant+audience under the default `required` mode, **the API refuses to
  start** — the fail-closed default means a forgotten var is a loud startup failure, not a silent
  wide-open deployment.

## Consequences

- **+** Keyless in fact: token validation uses only tenant **public** keys; the console is a PKCE
  public client. No secret in code, config defaults, or tests.
- **+** Fail-closed, deny-by-default: with auth configured, unauthenticated mutations get 401 and
  under-privileged ones 403; the actor can no longer be spoofed via a header.
- **+** No new heavyweight dependency server-side (reuses `cryptography` + `httpx`); one small,
  well-scoped SPA dependency (`@azure/msal-browser`).
- **+** Injectable crypto/JWKS/clock edges keep the security-critical tests network-free and keyless.
- **−** With the fail-closed `required` default, a deployment that forgets `WP_AUTH_TENANT_ID` /
  `WP_AUTH_AUDIENCE` **fails to start** (a loud, safe failure) rather than serving unauthenticated.
  Running without auth is possible **only** by the deliberate `WP_AUTH_MODE=disabled` opt-out, which
  logs a prominent warning. Enforcement is still inert until the app registrations + role
  assignments are provisioned (the documented deploy step), but the API will not serve mutations
  wide-open in the meantime.
- **−** The GET-endpoint "Reader" gate and the worker app-role assignment tighten the model further
  than the strict issue-#64 minimum; they are included for a coherent deny-by-default surface. The
  worker now mints its bearer in code, but the `Workloads.Operator` **assignment** to
  `identityWorker` remains a Graph deploy action (not ARM/Bicep-expressible), not code.
