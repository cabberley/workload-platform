"""Packs engine — load, verify signature, and hand packs to modules.

Packs are the only inbound artifact (content, not code). This engine is the trust gate:
it computes SHA-256 over pack content and verifies the HMAC signature **before** a pack is
allowed to execute. Unknown/invalid signature => fail closed (refuse).
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import yaml

from shared.contracts import PackManifest, PackType


class PackVerificationError(RuntimeError):
    """Raised when a pack's hash or signature does not verify. Fail closed."""


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

    def __init__(self, content_root: str | Path, *, signing_secret: bytes | None = None) -> None:
        self.root = Path(content_root)
        self._secret = signing_secret

    def _iter_pack_files(self) -> list[Path]:
        return sorted(
            p for p in self.root.rglob("*")
            if p.suffix in {".json", ".yaml", ".yml"} and p.is_file()
        )

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
            packs.append(Pack(manifest=manifest, body=raw.get("body", {})))
        return packs

    def load_for_workload(self, workload: str, pack_type: PackType) -> list[Pack]:
        """Return verified packs of a type that target the given workload kind."""
        return [
            p for p in self.load_all(pack_type=pack_type)
            if not p.manifest.targets or workload in p.manifest.targets
        ]
