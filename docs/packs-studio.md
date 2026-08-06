# Packs Studio (`wp-packs`)

A **Microsoft-internal**, CLI-first workbench for authoring the platform's five signed, versioned
content pack types (Workload, Rule, Telemetry, Dependency, Ops). It drives the whole authoring
lifecycle from a single command surface and is a thin composition root over already-merged shared
code — it reuses, and never re-implements, the schema gate, registry, signing provider, and the
real capability modules.

> **Internal only.** Packs Studio is authoring tooling for the pack team. It is **keyless** (no
> secret, no network) and **fail-closed** at every step. It never touches customer infrastructure
> and never makes an Azure call.

## Lifecycle

```
new  →  validate  →  test  →  sign  →  export
```

| Step | Command | What it does |
|------|---------|--------------|
| **author** | `wp-packs new <type> [--id ID] [--name NAME] [--out PATH]` | Scaffold a **schema-valid** starter pack of the given type (`workload`\|`rule`\|`telemetry`\|`dependency`\|`ops`). The body is generated self-contained; it is validated on the way out so a scaffold is always born valid. |
| **validate** | `wp-packs validate <path>` | Run the shared `validate_pack` JSON-Schema gate (#33). Prints each error and exits non-zero if invalid (**fail closed**). |
| **test** | `wp-packs test <path> [--estate FIXTURE]` | Load the pack and run it through its **real** capability module against a bundled **deterministic, synthetic** estate — **no Azure**. Prints the resulting findings/detections. |
| **sign** | `wp-packs sign <path> [--out PATH]` | Sign the pack's canonical bytes with an **ephemeral in-process Ed25519 key** and attach the detached signature at `manifest.pack_signature`. Also writes a `<pack>.pubkey` sidecar with the base64 raw **public** key (verification material — never a secret). Defaults to signing in place. |
| **export** | `wp-packs export <path> [--dist DIR] [--public-key B64]` | Validate (body **and** manifest) + **cryptographically verify** the detached signature, write a versioned bundle + provenance sidecar (both carrying the public key), and register the version in the registry (#34). **Fail-closed** on an unsigned/invalid/**forged**/tampered pack. |

### Which pack types are runnable under `test`?

Only the two types that have a consuming capability module:

* **`rule`** → `quality_checks` module (PASS/FAIL findings over the estate).
* **`telemetry`** → `aiops` module (threshold detections fused with synthetic observations).

`workload`, `dependency`, and `ops` packs have no standalone runnable module in the studio; `test`
**fails closed** for them with a clear message rather than pretending to exercise them.

### The synthetic estate

`test` runs against a bundled, clearly-fake estate (`epic-sandbox`) — two synthetic VMs
(`vm-app-01`, `vm-web-01`), a `web → app` dependency edge (for blast radius), and one synthetic
`cpu_percent` observation. There is **no real subscription id and no customer data**. The default
scaffolds line up with this estate so a fresh pack produces a finding out of the box:

* the starter **rule** requires an `owner` tag that `vm-app-01` lacks → a FAIL finding;
* the starter **telemetry** signal (`cpu_percent > 90`, `role:app`) trips on the 97% observation
  → one detection.

Supply your own with `--estate FIXTURE`, a JSON file shaped as:

```json
{
  "workload": "epic-sandbox",
  "nodes":   [ { "id": "...", "name": "...", "type": "...", "role": "app", "tags": {} } ],
  "edges":   [ { "source": "...", "target": "...", "type": "depends_on" } ],
  "signals": [ { "metric": "cpu_percent", "value": 97, "unit": "percent",
                 "timestamp": "2026-08-03T04:00:00Z", "resourceId": "..." } ]
}
```

## Bundle format (`.wpack`)

`export` emits a self-describing **JSON envelope** (`<id>-<version>.wpack`) plus a provenance
**sidecar** (`<id>-<version>.manifest.json`) into the dist dir (default `dist/`). JSON — not a zip
— keeps the provenance greppable and diffable in review.

```json
{
  "schema": "aegis.pack-bundle/1",
  "provenance": {
    "id": "exportable",
    "version": "0.1.0",
    "type": "rule",
    "digest": "<sha256 canonical-bytes hex>",
    "algorithm": "ed25519",
    "keyId": "ephemeral-ed25519",
    "createdAt": "2026-...Z",
    "publicKey": "<base64 raw Ed25519 public key>"
  },
  "pack": { "manifest": { "...": "...", "pack_signature": { "...": "..." } }, "body": { "...": "..." } }
}
```

* `digest` is the registry's **version-identity** digest (`canonical_digest`) — a SHA-256 over the
  whole pack excluding volatile integrity fields, so signing never changes a pack's identity.
* The signed pack is carried **verbatim**, including its detached `pack_signature`.
* `publicKey` is the base64 raw Ed25519 **public** key — provenance, not a secret — so a downstream
  importer (issue #37) can independently verify the detached signature with **no external state**.

## Signature verification (keyless, fail-closed)

`export` does **not** trust a pack just because its signature envelope is internally consistent.
It runs two gates and fails closed (non-zero exit, nothing written) if either fails:

1. **Structural pre-check** (`verify_signature_structure`) — cheap, keyless: right algorithm,
   well-formed base64, and the envelope's covered digest matches the pack's canonical bytes. This
   alone is **never** sufficient (a forged signature can carry the correct digest).
2. **Real cryptographic verification** (`verify_pack`) against **public-key material** — the raw
   Ed25519 public key resolved from, in order: `--public-key <b64>`, then `$WP_PACK_PUBLIC_KEY`,
   then the `<pack>.pubkey` sidecar written by `sign`. If no key resolves, or the signature does
   not verify, export fails closed.

The **private** key is ephemeral and never written (keyless guardrail). The Azure Key Vault signer
remains the real trust root `TODO(human)`.

## Registry + immutability

`export` registers the version via `PackRegistry.publish` into `<dist>/registry/index.json` (kept
separate from shipped `content/` so authoring never mutates released content). Versions are
**immutable**: re-exporting the same `id@version` with **different** content is rejected with a
non-zero exit. Re-exporting identical content is idempotent.

## Guardrails

* **In-boundary / keyless.** Signing uses an ephemeral Ed25519 key held only in process memory.
* **Fail closed.** Invalid schema (body **or** manifest), an unsigned/forged/tampered pack, a
  non-runnable type, or a mutated re-publish all exit non-zero and surface the reason.
* **Contained output.** The pack id used in output filenames must match a safe grammar
  (`^[a-z0-9][a-z0-9._-]*$`, no path separators or `..`). This is enforced by **`new`** (before it
  writes any scaffold) and by **`export`**, and every written path is additionally asserted to stay
  beneath its output/dist dir — so a hostile id can never write outside the target directory.
* **Semver enforced.** `manifest.version` must be valid semver; `validate`/`sign`/`test`/`export`
  all reject a non-semver version cleanly (non-zero, no artifact written), so `export` never crashes
  inside the registry.
* **ASCII-safe output.** All CLI help and messages are ASCII (no Unicode glyphs), so a CP1252
  Windows console never raises `UnicodeEncodeError`.
* **No Azure in `test`.** The real modules run against an in-process synthetic estate and an
  in-process telemetry source — no `DefaultAzureCredential`, no SDK call.
* **No PHI/PII.** Every fixture is synthetic and obviously fake.
* **Pure ⟂ I/O.** Body generation, the synthetic estate, and the bundle envelope are pure; file
  reads/writes happen only at the CLI edge.

## `TODO(human)`

* **Real signing key (offline, Microsoft-side).** The studio signs with an ephemeral Ed25519 key.
  Per [ADR 0010](adr/0010-pack-signing-trust-root.md), production packs are signed **OFFLINE** with
  Microsoft's Ed25519 private key held in Microsoft's own signing infrastructure — **outside** the
  customer deployment (there is no Key Vault signing provider; Ed25519 is not a KV Keys algorithm).
  Wire this offline signer into the pack-authoring/export pipeline so exported bundles carry a
  durable, org-trusted signature; the customer platform then only VERIFIES with the pinned public
  keys in `config/trust-bundle.json` (issue #89).
