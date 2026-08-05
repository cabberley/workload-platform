# Pack-signing trust bundle (`trust-bundle.json`)

This directory holds the platform's **pinned trust root** for verifying imported content packs
(issue #89). It is the customer-side, **verification-only, keyless** half of the pack-signing trust
model recorded in [ADR 0010](../docs/adr/0010-pack-signing-trust-root.md):

- **Microsoft signs packs OFFLINE** with an Ed25519 **private** key held in Microsoft's own signing
  infrastructure — entirely outside the customer deployment.
- **The customer platform only VERIFIES**, using the Ed25519 **PUBLIC** keys pinned in this bundle.
  No private key, no Key Vault key operation, no secret material is ever present here — Ed25519
  verification is keyless. Everything in this file is **public** (provenance, safe to publish).

## Format

```jsonc
{
  "schema_version": 1,
  "keys": [
    {
      "key_id": "ms-pack-signing-2026a",       // matches PackSignature.key_id in a pack manifest
      "algorithm": "ed25519",                    // only ed25519 is supported
      "public_key": "<base64 raw 32-byte Ed25519 PUBLIC key>"
    }
  ]
}
```

At import, the verifier selects the `keys` entry whose `key_id` equals the pack signature's
`key_id` and checks the detached signature with that public key.

## Fail-closed default

The shipped bundle has **`"keys": []`** (empty). With no keys pinned, **every pack import is
rejected** — the correct fail-closed state until Microsoft's real signing public keys are published
into this file. A missing, malformed, or schema-invalid bundle degrades to the same reject-all
behaviour (see `build_pack_import_verifier` in `src/cli/wiring.py`).

## Rotation & pinning

- **Rotate:** publish a new `{ key_id, public_key }` entry (new `key_id`) alongside the old one, so
  packs signed with either key verify during the overlap window.
- **Retire:** remove the old entry once no in-flight pack references its `key_id`.
- **Never** commit a private key. Only 32-byte raw Ed25519 **public** keys belong here.

## Loading & override

`build_pack_import_verifier` loads `$WP_TRUST_BUNDLE_PATH` (default `config/trust-bundle.json`).
A future "bundle refreshed via **signed** pack-registry metadata" path is a deliberate, documented
extension hook — remote fetch is **not** implemented today; the bundled file is the pinned root.
