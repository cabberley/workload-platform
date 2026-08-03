"""Packs engine — load, verify signature, and hand packs to modules.

Packs are the only inbound artifact (content, not code). This engine is the trust gate:
it computes SHA-256 over pack content and verifies the HMAC signature **before** a pack is
allowed to execute. Unknown/invalid signature => fail closed (refuse).

## Two independent, separately-documented trust gates

1. **Legacy HMAC (symmetric)** — :func:`verify` checks the body-only ``sha256`` and an HMAC over it
   using an injected ``signing_secret`` (Key Vault at the boundary). Active when a secret is set and
   ``verify_sig`` is on. Unchanged behavior; existing packs/tests rely on it.
2. **Detached asymmetric signature (issue #35)** — when a :class:`~shared.signing.Verifier` is
   injected, each pack's :attr:`~shared.contracts.PackManifest.pack_signature` is verified against
   the pack's *canonical bytes* via :func:`shared.signing.verify_pack`. A missing or invalid
   detached signature fails closed (:class:`PackVerificationError`).

The two gates are deliberately kept separate: HMAC is a body-integrity MAC; the detached signature
is an asymmetric provenance signature over canonical (version-identity) bytes. When **no** verifier
is injected, gate (2) is inert and today's behavior is preserved exactly.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import yaml

from shared.contracts import PackManifest, PackType
from shared.signing import Verifier, verify_pack


class PackVerificationError(RuntimeError):
    """Raised when a pack's hash or signature does not verify. Fail closed."""


# Reserved top-level subtree under the content root that is NEVER loaded or executed at runtime.
#
# ``content/templates/`` holds authoring SCAFFOLDS (starter packs for humans to copy). They are
# schema-valid on purpose (so CI can validate their shape via ``scripts/validate_packs.py``), but
# they must NEVER be loaded by this engine or handed to a module against a real customer estate:
# a scaffold with ``targets: []`` (all workloads) would otherwise OVERRIDE alert routing (ops),
# emit FALSE detections (telemetry), inject phantom dependency EDGES (dependency), and misclassify
# resources (workload). Excluding the whole subtree here is a fail-safe reserved-directory
# convention — to deploy a pack you copy it OUT of ``templates/`` into its by-type directory
# (e.g. ``content/rules/``) and sign it. The schema gate in ``scripts/validate_packs.py`` keeps
# its own enumeration, so templates stay validated in CI even though they are not runtime packs.
RESERVED_NONRUNTIME_DIR = "templates"


def compute_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sign(sha256_hex: str, secret: bytes) -> str:
    """HMAC-SHA256 over the content hash. Secret is provided by the boundary (Key Vault)."""
    return hmac.new(secret, sha256_hex.encode(), hashlib.sha256).hexdigest()


def verify(manifest: PackManifest, content: bytes, secret: bytes | None) -> None:
    """Verify hash and (if a secret is configured) signature. Raise to fail closed."""
    actual = compute_sha256(content)
    if manifest.sha256 and not hmac.compare_digest(actual, manifest.sha256):
        raise PackVerificationError(f"Pack {manifest.id}: content hash mismatch")
    if secret is not None:
        if not manifest.signature:
            raise PackVerificationError(f"Pack {manifest.id}: missing signature")
        expected = sign(manifest.sha256 or actual, secret)
        if not hmac.compare_digest(expected, manifest.signature):
            raise PackVerificationError(f"Pack {manifest.id}: signature invalid")


class Pack:
    """A loaded, parsed pack: manifest + body."""

    def __init__(self, manifest: PackManifest, body: dict[str, Any]) -> None:
        self.manifest = manifest
        self.body = body


class PacksEngine:
    """Discovers packs under a content root and returns verified packs on demand."""

    def __init__(
        self,
        content_root: str | Path,
        *,
        signing_secret: bytes | None = None,
        signature_verifier: Verifier | None = None,
    ) -> None:
        self.root = Path(content_root)
        self._secret = signing_secret
        # Optional, independent detached-signature gate (issue #35). Inert when None: today's
        # HMAC-only behavior is preserved exactly.
        self._verifier = signature_verifier

    def _iter_pack_files(self) -> list[Path]:
        return sorted(
            p for p in self.root.rglob("*")
            if p.suffix in {".json", ".yaml", ".yml"}
            and p.is_file()
            and not self._is_reserved_nonruntime(p)
        )

    def _is_reserved_nonruntime(self, path: Path) -> bool:
        """True if ``path`` lives under the reserved, non-runtime ``templates/`` subtree.

        Any file whose first path component under the content root is ``RESERVED_NONRUNTIME_DIR``
        is an authoring scaffold and must never be discovered/executed as a runtime pack (see the
        constant's docstring). Fail-safe: a path outside the root is not treated as reserved.
        """
        try:
            rel = path.relative_to(self.root)
        except ValueError:
            return False
        return len(rel.parts) > 0 and rel.parts[0] == RESERVED_NONRUNTIME_DIR

    @staticmethod
    def _parse(path: Path) -> dict[str, Any]:
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".json":
            return json.loads(text)
        return yaml.safe_load(text)

    def load_all(self, *, pack_type: PackType | None = None, verify_sig: bool = True) -> list[Pack]:
        packs: list[Pack] = []
        for path in self._iter_pack_files():
            raw = self._parse(path)
            if "manifest" not in raw:
                continue  # not a pack file
            manifest = PackManifest(**raw["manifest"])
            if pack_type and manifest.type != pack_type:
                continue
            if verify_sig:
                body_bytes = json.dumps(raw.get("body", {}), sort_keys=True).encode()
                verify(manifest, body_bytes, self._secret)
            # Independent detached-signature gate (issue #35): only active when a verifier is
            # injected, so no-verifier callers keep today's behavior unchanged. Fail closed.
            if self._verifier is not None:
                self._verify_detached(manifest, raw, self._verifier)
            packs.append(Pack(manifest=manifest, body=raw.get("body", {})))
        return packs

    @staticmethod
    def _verify_detached(manifest: PackManifest, raw: dict[str, Any], verifier: Verifier) -> None:
        """Refuse to load a pack whose detached signature is missing or does not verify.

        The signature covers ``canonical_bytes(raw)`` (the same canonicalizer the registry uses),
        so a tampered byte or a missing ``pack_signature`` fails closed here before the pack is
        handed to any module.
        """
        signature = manifest.pack_signature
        if signature is None:
            raise PackVerificationError(
                f"Pack {manifest.id}: missing detached signature (fail closed)"
            )
        if not verify_pack(raw, signature, verifier):
            raise PackVerificationError(
                f"Pack {manifest.id}: detached signature failed verification (fail closed)"
            )

    def load_for_workload(self, workload: str, pack_type: PackType) -> list[Pack]:
        """Return verified packs of a type that target the given workload kind."""
        return [
            p for p in self.load_all(pack_type=pack_type)
            if not p.manifest.targets or workload in p.manifest.targets
        ]
