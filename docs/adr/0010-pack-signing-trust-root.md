# 0010. Pack-signing trust root: offline Microsoft Ed25519 signing + customer-side, keyless, verification-only trust bundle

Date: 2026-08-05 · Status: accepted

## Context

Packs are the only inbound artifact (content, not code) and the packs engine is the trust gate:
an unverified pack must never be trusted or activated (guardrail 4, fail-closed). The detached
**Ed25519** provenance signature over a pack's *canonical bytes* is implemented
([`shared/signing.py`](../../src/shared/signing.py), issue #35) and #44 added digest-addressed
imported-pack content storage with load-time digest re-verification
([`packs_engine/engine.py`](../../src/packs_engine/engine.py)). But the **trust root itself was
unresolved and mis-recorded**, and no verifier was wired into an import path:

- The prior design (issues #61/#89 framing) assumed a runtime **Azure Key Vault** signing key
  ("KV Ed25519, keyless"). This is **not viable: Azure Key Vault Keys does not support Ed25519.**
- `signing.py` shipped `KeyVaultSigner`/`KeyVaultVerifier` **stubs** that raised
  `NotImplementedError`, and the RBAC/threat-model docs mis-attributed the (nonexistent) signing-key
  wiring to #44. #44 delivered digest-addressed storage — it never provisioned a signing key or a
  verifier trust root.
- Nothing verified a pack **signature** at admission; imported packs were trusted purely by the
  recorded digest, with no evidence the digest ever corresponded to a signature-verified pack.

We must choose a trust model that is in-boundary, keyless, and fail-closed, and wire a real verifier.

## Decision

**The pack-signing trust model is offline Microsoft signing + customer-side, verification-only,
keyless verification, using detached Ed25519 and a bundled trust root of pinned PUBLIC keys.**

1. **Algorithm: keep detached Ed25519.** The pack signature stays Ed25519 over canonical bytes
   (#35). Key Vault Keys' lack of Ed25519 support is **irrelevant** because the customer side never
   signs and never performs a KV key operation.

2. **Microsoft signs packs OFFLINE.** The Ed25519 **private** key lives in Microsoft's own
   pack-authoring/export signing infrastructure, entirely **outside** the customer deployment. The
   MS-side signer is **out of scope** for this platform; only the ephemeral in-process
   `Ed25519Signer` (test/offline release tooling — [`cli/packs_studio.py`](../../src/cli/packs_studio.py))
   lives in this repo.

3. **The customer platform only VERIFIES — keyless.** It holds distributed/pinned Ed25519 **PUBLIC**
   keys (a **trust bundle**) and verifies detached signatures. No customer-held private key, no KV
   key op, no secret material: Ed25519 verification is keyless. New
   [`TrustBundleVerifier`](../../src/shared/signing.py) selects the public key whose `key_id`
   matches the pack signature's `key_id` and verifies.

4. **Trust bundle: bundled `{ key_id -> Ed25519 public key }` set.** Modelled as the Pydantic
   [`TrustBundle`](../../src/shared/contracts.py) contract and loaded from
   `config/trust-bundle.json` (override `$WP_TRUST_BUNDLE_PATH`) by
   [`build_pack_import_verifier`](../../src/cli/wiring.py) in the composition root. Each pack
   manifest's signature carries the signing `key_id`; the verifier selects the matching public key.
   **Rotation/pinning** = publish a new `key_id` + public key into the bundle (overlap window), then
   remove the retired one. A future "bundle refreshed via **signed** pack-registry metadata" path is
   a documented extension **hook** — remote fetch is deliberately **not** built now.

5. **Enforced fail-closed at every registry/store WRITE (admission), not at runtime load.** The
   pinned trust root gates **every path that records a registry digest** the runtime later trusts:
   - **Export / registry-write (live today):** [`cli.packs_studio.cmd_export`](../../src/cli/packs_studio.py)
     loads the pinned bundle via [`build_pack_import_verifier`](../../src/cli/wiring.py) (honouring
     `$WP_TRUST_BUNDLE_PATH`, overridable per-run with `--trust-bundle`) and verifies the pack
     against it **before** `registry.publish` + `content_store.put`. A caller-supplied
     `--public-key` is only an optional, non-authoritative self-consistency pre-check — it can
     **never** substitute for the pinned-bundle verification. Default (no bundle) = empty =
     reject-all, so an untrusted/unpinned pack can never be written into a runtime-trusted registry.
   - **Customer import (#37, parked):** [`PacksEngine.verify_pack_for_import`](../../src/packs_engine/engine.py)
     is the SAME fail-closed gate (same `TrustBundleVerifier`), ready for the #37 import subsystem to
     call at admission before it publishes/stores.

   This closes the reviewer-found bypass where `cmd_export` verified against a **caller-supplied**
   key (an attacker could sign with their own key, export, and produce a runtime-trusted registry).
   The #44 store deliberately holds *signature-excluded* canonical bytes and re-verifies them by
   digest at load time; that digest is trustworthy **only because** admission verified the signature
   at the write boundary — so signature verification belongs at admission, not at load.
   `build_pack_import_verifier` **always** returns a verifier (never `None`): an empty/missing/corrupt
   bundle yields a **reject-all** verifier, so admission is fail-closed *by construction* until real
   Microsoft public keys are pinned. Fail-closed on: no/empty/unavailable bundle, malformed manifest
   or signature, a blank/unknown/unpinned `key_id`, or a signature that does not verify.

6. **Removed the misleading KV *signing* stubs.** `KeyVaultSigner`/`KeyVaultVerifier` are deleted
   from `signing.py`. No Key Vault signing-key provisioning is introduced. The verification-only
   provider abstraction that remains (`Verifier`, new `PackVerifier`, `TrustBundleVerifier`) is
   minimal and keyless.

### Alternative considered and NOT chosen: ECDSA P-256 for Key Vault HSM signing

Switching the algorithm to **ECDSA P-256** would let a **runtime Key Vault key** sign (KV supports
P-256), with **Key Vault Crypto User** as the narrowest role. **Rejected** because:

- It would put a **signing key operation inside the customer runtime**, contradicting the model that
  packs are signed **offline by Microsoft**; the customer platform should never hold signing
  capability for Microsoft-authored packs.
- It adds a **runtime KV key dependency and RBAC role** (Crypto User) that the verification-only
  model does not need — verification with distributed public keys requires **no KV key op and no KV
  role at runtime**, which is strictly less privilege and stays keyless.
- It would churn the already-implemented Ed25519 signature format for no security gain; Ed25519
  verification is keyless and self-contained.

The only real limitation cited for Ed25519 — "Key Vault Keys can't do Ed25519" — evaporates once we
accept that the **customer side never signs**.

## Consequences

- **+** In-boundary, **keyless**, fail-closed trust root: the customer platform holds only public
  keys, performs no KV signing op, and rejects every unverified import by construction.
- **+** The trust root is now **real and enforced at the registry/store write boundary**
  (`cmd_export` today via `build_pack_import_verifier`; #37's customer import path will reuse
  `verify_pack_for_import`), not a `NotImplementedError` stub. Runtime activation trusts the
  registry digest **because admission verified the signature against the pinned bundle** — the
  earlier caller-supplied-key bypass at export is closed. Docs are corrected (#44 no longer credited
  with signing-key wiring). No runtime Key Vault role is required for pack signing.
- **+** Rotation is a data change (publish a public key into the bundle), not a code/redeploy of a
  key provider; a remote signed-metadata refresh is a forward-compatible extension hook.
- **−** Until Microsoft publishes real signing **public** keys into `config/trust-bundle.json`, the
  bundle is empty and **all** imports are rejected (correct fail-closed, but the import path is inert
  until keys are pinned — acceptable because the #37 import subsystem is itself still parked).
- **−** Trust in Microsoft's **offline** signing infrastructure (private-key custody, HSM,
  rotation cadence) is out of this repo's scope — an organizational control, not a code control.
- **TODO(human):** (a) publish Microsoft's real Ed25519 signing public key(s) into the bundle when
  the offline signer is provisioned; (b) #37 must call `verify_pack_for_import` at admission and
  audit `pack.import`/`pack.assign`; (c) optionally implement the signed pack-registry-metadata
  bundle-refresh path (the documented hook).
