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
from typing import TYPE_CHECKING, Any

import yaml

from shared.contracts import AuditAction, AuditResult, PackManifest, PackType, is_audit_safe
from shared.signing import Verifier, verify_pack

if TYPE_CHECKING:  # pragma: no cover - typing-only import; avoids runtime coupling to the emitter
    from shared.audit import AuditEmitter


class PackVerificationError(RuntimeError):
    """Raised when a pack's hash or signature does not verify. Fail closed."""


def _audit_safe_identifier(value: str) -> str:
    """Return an audit-safe identifier for ``value`` for use in a ``pack.verify`` failure event.

    When ``value`` is already audit-safe (see :func:`shared.contracts.is_audit_safe`) it is used
    verbatim so normal rejections stay human-readable. When it is NOT (a malicious pack carrying
    PII, control chars, an Azure resource *path*, or an oversized id/version), it is replaced with
    an opaque, deterministic SHA-256 hex digest — always bounded (64 hex chars), control-free, and
    PII-free — so the rejection is still audited WITHOUT ever copying or leaking the raw value.

    The digest input uses ``errors="surrogatepass"`` so encoding is TOTAL, deterministic AND
    injective for ANY ``str`` — including a lone surrogate (e.g. ``chr(0xD800)`` from ``json.loads``
    /``yaml.safe_load``), which strict UTF-8 cannot encode. Without a total encoding, hashing a
    lone-surrogate pack id would raise ``UnicodeEncodeError``, both suppressing the required failure
    audit and masking the expected ``PackVerificationError``. ``surrogatepass`` is a bijection with
    the ``str`` (unlike ``backslashreplace``, which would collapse a lone surrogate and its literal
    escape text to identical bytes), so distinct unsafe identifiers never collide to one digest.
    """
    if is_audit_safe(value):
        return value
    return hashlib.sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()


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
    """Verify hash and (if a secret is configured) signature. Raise to fail closed.

    A real content hash / HMAC signature is always ASCII (hex / base64). A non-ASCII value in
    ``sha256``/``signature`` — e.g. a lone surrogate smuggled through the JSON manifest — can never
    verify, so we treat it as a fail-closed MISMATCH. Guarding ``hmac.compare_digest`` with
    ``.isascii()`` avoids the ``TypeError`` it raises on non-ASCII input (and the strict-encode
    ``UnicodeEncodeError`` inside :func:`sign`), either of which would otherwise escape as a
    non-``PackVerificationError`` — masking the expected error type AND evading the fail-closed
    ``pack.verify`` audit that the loader emits on ``PackVerificationError``.
    """
    actual = compute_sha256(content)
    if manifest.sha256 and not (
        manifest.sha256.isascii() and hmac.compare_digest(actual, manifest.sha256)
    ):
        raise PackVerificationError(f"Pack {manifest.id}: content hash mismatch")
    if secret is not None:
        if not manifest.signature:
            raise PackVerificationError(f"Pack {manifest.id}: missing signature")
        expected = sign(manifest.sha256 or actual, secret)
        if not (
            manifest.signature.isascii() and hmac.compare_digest(expected, manifest.signature)
        ):
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
        audit_emitter: AuditEmitter | None = None,
    ) -> None:
        self.root = Path(content_root)
        self._secret = signing_secret
        # Optional, independent detached-signature gate (issue #35). Inert when None: today's
        # HMAC-only behavior is preserved exactly.
        self._verifier = signature_verifier
        # Optional audit emitter (issue #59). Inert when None. When set (the API injects a
        # store-backed emitter — the single writer), a pack whose signature/hash verification FAILS
        # is recorded as a fail-closed ``pack.verify`` audit event before the failure propagates.
        self._audit_emitter = audit_emitter

    def attach_audit_emitter(self, emitter: AuditEmitter) -> None:
        """Attach a store-backed audit emitter after construction (used by the API composition)."""
        self._audit_emitter = emitter

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
            try:
                if verify_sig:
                    try:
                        body_bytes = json.dumps(raw.get("body", {}), sort_keys=True).encode()
                    except (TypeError, ValueError) as exc:
                        # A YAML-authored pack can carry a non-JSON-native body (e.g. ``!!set`` →
                        # a Python ``set``). Serializing it here raised before any audit was
                        # written — masking the rejection with a TypeError AND emitting zero
                        # pack.verify events. Convert to the fail-closed PackVerificationError so
                        # the except-clause below audits exactly one pack.verify/failure event.
                        raise PackVerificationError(
                            f"Pack {manifest.id}: body is not JSON-serializable"
                        ) from exc
                    verify(manifest, body_bytes, self._secret)
                # Independent detached-signature gate (issue #35): only active when a verifier is
                # injected, so no-verifier callers keep today's behavior unchanged. Fail closed.
                if self._verifier is not None:
                    self._verify_detached(manifest, raw, self._verifier)
            except PackVerificationError:
                # Audit the fail-closed rejection of a tampered/invalid pack (issue #59), then
                # re-raise so verification still fails closed exactly as before.
                self._emit_verify_failure(manifest)
                raise
            packs.append(Pack(manifest=manifest, body=raw.get("body", {})))
        return packs

    def _emit_verify_failure(self, manifest: PackManifest) -> None:
        """Record a ``pack.verify`` failure event (no-op when no audit emitter is injected).

        Emission is best-effort and never raises (the emitter swallows its own errors), so auditing
        a rejected pack can never turn a fail-closed verification into a crash.

        A malicious pack may carry a non-audit-safe ``id``/``version`` (PII, control chars, an
        Azure resource *path*, or an oversized value). Copying those raw into the audit fields would
        make the ``AuditEvent`` itself fail ``is_audit_safe`` and be silently dropped — so the
        rejection of the WORST packs would go unaudited. We instead pass every identifier through
        :func:`_audit_safe_identifier`, which keeps a readable value when it is already safe but
        substitutes an opaque SHA-256 digest otherwise. The raw unsafe value is never copied into
        (or leaked by) the event, yet the rejection is ALWAYS audited.
        """
        if self._audit_emitter is None:
            return
        pack_id = _audit_safe_identifier(manifest.id)
        pack_version = _audit_safe_identifier(manifest.version)
        self._audit_emitter.emit(
            actor="system",
            action=AuditAction.pack_verify,
            subject=pack_id,
            result=AuditResult.failure,
            pack_id=pack_id,
            pack_version=pack_version,
        )

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
