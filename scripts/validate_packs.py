#!/usr/bin/env python
"""Validate content packs: schema-correctness, HMAC (optional), and detached signatures.

Usage:
    python scripts/validate_packs.py content

Exit code is non-zero if any pack is invalid, so CI (pack-validate.yml) fails closed.

## Verification passes (all fail closed)

1. **Signature/hash trust gate** — via :class:`packs_engine.engine.PacksEngine`. Legacy HMAC
   signature verification is skipped unless ``WP_PACK_SIGNING_SECRET`` is set (release-time
   signing).
2. **Schema gate** — enumerates EVERY candidate pack file under the content root directly (not just
   the ones the engine's loader returns), so a file with a missing or misspelled top-level
   ``manifest`` key — which the loader silently skips — still FAILS closed here. The pristine
   registry index (issue #34) is the only structural exemption (it carries no ``manifest`` and is
   never executed as a pack).
3. **Detached asymmetric signature (issue #35)** — for every pack that carries a
   ``manifest.pack_signature`` envelope, first run a cheap structural pre-check (algorithm known,
   base64 well-formed, and the covered ``canonical_digest`` matches the digest recomputed from the
   pack's canonical bytes), THEN **cryptographically verify** the signature against a configured
   trusted public key (``WP_PACK_PUBLIC_KEY``, base64 raw Ed25519). **A present signature must be
   cryptographically proven or the build fails** — structural self-consistency is never accepted on
   its own (an attacker can recompute a matching digest and supply junk signature bytes). If a pack
   carries a signature but no trusted public key is configured, that pack FAILS CLOSED.

## Unsigned-seed-pack policy

The currently-shipped seed packs are unsigned. To avoid breaking them, packs that OMIT the
``pack_signature`` field entirely are treated as unsigned and allowed UNLESS
``WP_REQUIRE_PACK_SIGNATURES=1`` (mandatory signing), in which case an unsigned pack FAILS. This
"unsigned" policy applies ONLY to packs that omit the field: presence is tested structurally, so a
``pack_signature`` that is present but explicitly ``null`` (or otherwise malformed) FAILS CLOSED
regardless of ``WP_REQUIRE_PACK_SIGNATURES`` — a present-but-null signature is never downgraded to
"unsigned". A pack that carries a real signature value is always subject to mandatory cryptographic
verification above.

TODO(human): once the Key Vault signing key + public trust root are provisioned, provide
``WP_PACK_PUBLIC_KEY`` (the KV signing key's public bytes) and set ``WP_REQUIRE_PACK_SIGNATURES=1``
in the pack-validate workflow to make detached signing mandatory for all published packs.
"""
from __future__ import annotations

import base64
import json
import os
import sys
from collections.abc import Iterator
from pathlib import Path

import yaml

# Allow running without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from packs_engine.engine import PacksEngine, PackVerificationError  # noqa: E402
from packs_engine.registry import (  # noqa: E402
    CorruptRegistryError,
    parse_registry_index,
)
from packs_engine.schema import validate_pack  # noqa: E402
from shared.contracts import PackSignature  # noqa: E402
from shared.signing import (  # noqa: E402
    Ed25519Verifier,
    Verifier,
    verify_pack,
    verify_signature_structure,
)

_PACK_SUFFIXES = {".json", ".yaml", ".yml"}


def _candidate_pack_files(root: Path) -> list[Path]:
    """Every JSON/YAML file under ``root`` — exactly what ``PacksEngine`` would discover.

    No path is excluded: whatever the engine can load and execute must also pass the schema gate,
    so a valid-manifest/invalid-body pack placed anywhere under the content root fails closed.
    """
    return sorted(
        p
        for p in root.rglob("*")
        if p.is_file() and p.suffix in _PACK_SUFFIXES
    )


def _parse(path: Path) -> object:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        return json.loads(text)
    return yaml.safe_load(text)


def _is_registry_index(raw: dict[str, object]) -> bool:
    """True iff ``raw`` is a *pristine, valid* pack registry index (issue #34), not a pack.

    The registry index lives under ``content/registry/`` and has EXACTLY the shape
    ``{"version": <int == INDEX_SCHEMA_VERSION>, "entries": [<valid entry>, ...]}`` with **no**
    ``manifest``. It is managed by the registry engine (which enforces its own integrity,
    fail-closed) and is never executed as a pack.

    The exemption is deliberately TIGHT and cannot become a hiding spot or swallow authoring
    mistakes:

    - It is *structural*, not path-based — any file carrying a ``manifest`` (i.e. anything
      ``PacksEngine`` would actually execute) is never exempted, wherever it sits.
    - The key set must be EXACTLY ``{"version", "entries"}``, so a mis-authored pack that merely
      *also* happens to carry ``version``/``entries`` (e.g. a misspelled ``manifest`` key plus a
      ``body``) is NOT exempted and still fails closed.
    - Semantic validity is delegated to :func:`packs_engine.registry.parse_registry_index` — the
      registry's OWN single-source-of-truth parser (schema version, entry shape, and no duplicate
      ``id@version``) — so this gate can never diverge from ``PackRegistry._load``.
    """
    if "manifest" in raw or set(raw) != {"version", "entries"}:
        return False
    try:
        parse_registry_index(raw)
    except CorruptRegistryError:
        return False
    return True


def _iter_raw_packs(root: str) -> Iterator[tuple[Path, dict]]:
    """Yield ``(path, raw)`` for every pack file (a dict with a ``manifest``) under ``root``."""
    for path in sorted(Path(root).rglob("*")):
        if path.suffix not in _PACK_SUFFIXES or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        raw = json.loads(text) if path.suffix == ".json" else yaml.safe_load(text)
        if isinstance(raw, dict) and "manifest" in raw:
            yield path, raw


def _load_trust_root() -> Verifier | None:
    """Build an Ed25519 verifier from ``WP_PACK_PUBLIC_KEY`` (base64 raw key), or ``None``.

    No private key is ever read here — only a public trust root, and only if explicitly configured.

    TODO(human): point ``WP_PACK_PUBLIC_KEY`` at the real Azure Key Vault public trust root (export
    the KV signing key's public bytes into the workflow via ``vars``/OIDC) so CI verifies against
    the same key the release pipeline signs with. Until then a signed pack cannot be verified in CI
    and — per the security invariant below — fails closed.
    """
    b64 = os.environ.get("WP_PACK_PUBLIC_KEY")
    if not b64:
        return None
    return Ed25519Verifier.from_public_bytes(base64.b64decode(b64))


def _verify_signatures(root: str) -> int:
    """Detached-signature pass. Returns the number of failures (0 = all good). Fail closed.

    Security invariant: **a signature that is present must be cryptographically proven, or the
    build fails.** Structural self-consistency (:func:`verify_signature_structure`) is only an
    early, cheap pre-check — never a substitute for cryptographic verification. Concretely:

    * pack carries a ``pack_signature`` ⇒ it MUST verify cryptographically against a configured
      trusted verifier. If no trusted public key is configured, that pack FAILS CLOSED (we never
      downgrade to a structural-only pass, and never print ``SIG OK``);
    * ``pack_signature`` is present but explicitly ``null`` ⇒ MALFORMED ⇒ FAILS CLOSED, regardless
      of ``WP_REQUIRE_PACK_SIGNATURES`` (a present-but-null signature is never downgraded to
      "unsigned" — that would be a verification bypass);
    * pack OMITS ``pack_signature`` entirely ⇒ treated as unsigned: allowed, UNLESS
      ``WP_REQUIRE_PACK_SIGNATURES=1`` (mandatory signing), in which case an unsigned pack FAILS.
    """
    verifier = _load_trust_root()
    require = os.environ.get("WP_REQUIRE_PACK_SIGNATURES") == "1"
    failures = 0
    for path, raw in _iter_raw_packs(root):
        manifest = raw.get("manifest", {})
        manifest = manifest if isinstance(manifest, dict) else {}
        # Presence-based, NOT truthiness-based: an OMITTED field is "unsigned", but an explicit
        # null (or other malformed value) is a hard failure — never conflate the two.
        has_field = "pack_signature" in manifest
        sig_data = manifest.get("pack_signature")

        if not has_field:
            if require:
                print(
                    f"FAIL: {path.name}: mandatory signing is ON but pack is unsigned",
                    file=sys.stderr,
                )
                failures += 1
            continue

        if sig_data is None:
            print(
                f"FAIL: {path.name}: pack_signature is present but null — malformed signature, "
                "failing closed (a present-but-null signature is never treated as unsigned)",
                file=sys.stderr,
            )
            failures += 1
            continue

        try:
            signature = PackSignature(**sig_data)
        except (TypeError, ValueError) as exc:
            print(f"FAIL: {path.name}: malformed pack_signature: {exc}", file=sys.stderr)
            failures += 1
            continue

        # Early, cheap fail-closed pre-check — NOT a substitute for cryptographic verification.
        if not verify_signature_structure(raw, signature):
            print(
                f"FAIL: {path.name}: detached signature structure/self-consistency check "
                "failed (unknown algorithm, bad base64, or tampered canonical digest)",
                file=sys.stderr,
            )
            failures += 1
            continue

        # A PRESENT signature must be cryptographically verified. No trusted verifier configured
        # => fail closed for this pack (never accept a present-but-unverifiable signature).
        if verifier is None:
            print(
                f"FAIL: {path.name}: pack carries a detached signature but no trusted public key "
                "is configured (set WP_PACK_PUBLIC_KEY); a present signature must be "
                "cryptographically verified — failing closed",
                file=sys.stderr,
            )
            failures += 1
            continue

        if not verify_pack(raw, signature, verifier):
            print(
                f"FAIL: {path.name}: detached signature cryptographic verification failed",
                file=sys.stderr,
            )
            failures += 1
            continue

        print(f"SIG OK  {path.name}  alg={signature.algorithm} keyid={signature.key_id}")
    return failures


def main(argv: list[str]) -> int:
    root = Path(argv[1] if len(argv) > 1 else "content")
    secret = os.environ.get("WP_PACK_SIGNING_SECRET")
    verify_sig = secret is not None

    # 1) Signature/hash trust gate via the engine (unchanged behavior — fail closed on a bad sig).
    engine = PacksEngine(root, signing_secret=secret.encode() if secret else None)
    try:
        engine.load_all(verify_sig=verify_sig)
    except PackVerificationError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - surface parse/manifest errors clearly
        print(f"FAIL: could not load packs under {root}: {exc}", file=sys.stderr)
        return 1

    # 2) Schema gate over EVERY candidate pack file (fail closed on a missing/misspelled manifest,
    #    which the engine loader skips) — a malformed body or absent manifest fails the build.
    files = _candidate_pack_files(root)
    if not files:
        print(f"WARNING: no pack files found under {root}")

    failures = 0
    for path in files:
        rel = path.relative_to(root)
        try:
            raw = _parse(path)
        except Exception as exc:  # noqa: BLE001 - a malformed pack file must fail closed
            failures += 1
            print(f"FAIL: {rel}: could not parse ({exc})", file=sys.stderr)
            continue
        if not isinstance(raw, dict):
            failures += 1
            print(f"FAIL: {rel}: not a pack object (top-level must be a mapping)", file=sys.stderr)
            continue
        if _is_registry_index(raw):
            # The registry index is infrastructure, not a pack — the registry engine owns its
            # integrity. Skip pack-schema validation (it carries no manifest and never executes).
            print(f"--  registry index (not a pack): {rel}")
            continue
        errors = validate_pack(raw)
        if errors:
            failures += 1
            print(f"FAIL: {rel}: pack failed schema:", file=sys.stderr)
            for err in errors:
                print(f"        - {err}", file=sys.stderr)
        else:
            m = raw["manifest"]
            print(
                f"OK  {str(m.get('type', '')):<10} {str(m.get('id', '')):<28} "
                f"v{m.get('version', '?')}  targets={m.get('targets') or ['*']}"
            )

    if failures:
        print(f"\nFAIL: {failures} pack file(s) failed validation.", file=sys.stderr)
        return 1

    print(
        f"\nValidated {len(files)} pack file(s); signature check {'ON' if verify_sig else 'OFF'}."
    )

    # 3) Detached asymmetric signature gate (issue #35) — a present signature must cryptographically
    #    verify or the build fails closed.
    sig_failures = _verify_signatures(str(root))
    if sig_failures:
        print(f"\n{sig_failures} pack(s) failed detached-signature verification.", file=sys.stderr)
        return 1
    print("Detached-signature check passed (present signatures verified; fail-closed on tamper).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
