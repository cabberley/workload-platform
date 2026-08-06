"""Detached pack signing + fail-closed verification (issue #35).

Published packs are signed with a **detached** asymmetric signature over the pack's *canonical
bytes* (:func:`packs_engine.canonical.canonical_bytes`) — the same bytes the registry (#34) uses
for version identity, which deliberately exclude the volatile integrity fields (``sha256``,
``signature`` and this envelope, ``pack_signature``). Signing therefore never changes a pack's
version identity, and verification is self-describing: the :class:`~shared.contracts.PackSignature`
envelope carries the algorithm, the base64 signature, a key-id hint, and the canonical digest it
covers.

## Keyless by design

This module hardcodes **no key**. Callers inject a :class:`Signer` / :class:`Verifier` provider:

* :class:`Ed25519Signer` / :class:`Ed25519Verifier` — an ephemeral in-process Ed25519 provider
  (via the ``cryptography`` library) so tests and the **offline** authoring/release tooling need
  **no secret and no network**. The customer platform NEVER signs — signing is done OFFLINE in
  Microsoft's own infrastructure — so no Key Vault signing provider exists here (issue #89).
* :class:`TrustBundleVerifier` — the **customer-side, verification-only, keyless** trust root
  (issue #89). It holds a set of pinned Ed25519 **PUBLIC** keys (a :class:`~shared.contracts.
  TrustBundle`), selects the key whose ``key_id`` matches a pack signature's ``key_id``, and
  verifies the detached signature — **no private key, no Key Vault key op, no secret material**.
  Fail-closed: an unknown/unpinned key id or an empty bundle rejects the pack.

## Fail closed

:func:`verify_pack` returns ``bool`` and is **fail-closed**: any mismatch — unknown/wrong
algorithm, malformed base64, a covered digest that does not match the recomputed canonical digest
(tamper), or a bad signature — yields ``False``. The packs-engine loader treats an unverifiable or
missing signature as *refuse-to-load*. Missing a signature is handled by the caller/loader because
:func:`verify_pack` requires a concrete :class:`~shared.contracts.PackSignature`.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from collections.abc import Mapping
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from shared.contracts import PackSignature, TrustBundle

# Algorithm identifiers understood by this module. The detached ephemeral/test provider is
# Ed25519; a real Key Vault provider will extend this set once wired.
ED25519_ALG = "ed25519"
SUPPORTED_ALGORITHMS: frozenset[str] = frozenset({ED25519_ALG})


class PackSignatureError(RuntimeError):
    """Raised on a signing-side misconfiguration (e.g. a provider that produces no signature).

    Verification never raises this — it fails closed by returning ``False`` — so the two paths stay
    unambiguous: *producing* a signature may raise; *checking* one is boolean and fail-closed.
    """


# --------------------------------------------------------------------------------------
# Injected provider protocols — keyless by design; this module hardcodes no key.
# --------------------------------------------------------------------------------------
@runtime_checkable
class Signer(Protocol):
    """A detached-signature producer. ``sign`` returns the raw signature over ``data``.

    ``algorithm`` and ``key_id`` are provenance attributes copied verbatim into the emitted
    :class:`~shared.contracts.PackSignature` so verification is self-describing.
    """

    algorithm: str
    key_id: str

    def sign(self, data: bytes) -> bytes: ...


@runtime_checkable
class Verifier(Protocol):
    """A detached-signature checker. Returns ``True`` iff ``signature`` is valid for ``data``."""

    def verify(self, data: bytes, signature: bytes) -> bool: ...


@runtime_checkable
class PackVerifier(Protocol):
    """A **key-id-aware**, keyless pack-signature verifier backed by a pinned trust root.

    Unlike the low-level :class:`Verifier` (which is handed a specific key's raw bytes), a
    :class:`PackVerifier` selects the right public key from a trust bundle using the signature's
    ``key_id`` before verifying. Fail-closed: an unknown/unpinned key id yields ``False``.
    """

    def verify_pack(self, pack: dict[str, object], signature: PackSignature) -> bool: ...


# --------------------------------------------------------------------------------------
# Pure sign / verify over canonical bytes — Azure-free, deterministic, fail-closed.
# --------------------------------------------------------------------------------------
def _canonical(pack: dict[str, object]) -> bytes:
    """Canonical bytes for ``pack``, imported lazily to avoid an import cycle.

    ``packs_engine.engine`` imports this module at top level; importing ``packs_engine.canonical``
    lazily here keeps ``import shared.signing`` from triggering the ``packs_engine`` package import
    (and its ``engine`` -> ``shared.signing`` edge) regardless of import order.
    """
    from packs_engine.canonical import canonical_bytes

    return canonical_bytes(pack)


def sign_pack(pack: dict[str, object], signer: Signer) -> PackSignature:
    """Sign the **canonical bytes** of ``pack`` with ``signer`` and return a typed envelope.

    The signature covers :func:`packs_engine.canonical.canonical_bytes` (which excludes the volatile
    integrity fields), so attaching the returned :class:`~shared.contracts.PackSignature` to the
    pack does not change what was signed or the pack's version identity.
    """
    data = _canonical(pack)
    raw = signer.sign(data)
    if not raw:
        raise PackSignatureError(
            f"Signer {signer.algorithm!r}/{signer.key_id!r} produced an empty signature"
        )
    return PackSignature(
        algorithm=signer.algorithm,
        signature=base64.b64encode(raw).decode("ascii"),
        key_id=signer.key_id,
        canonical_digest=hashlib.sha256(data).hexdigest(),
    )


def verify_signature_structure(pack: dict[str, object], signature: PackSignature) -> bool:
    """Self-consistency check requiring **no** private/public key — for CI's structural gate.

    Fail-closed ``True`` only when: the algorithm is known, the base64 signature is well-formed, and
    the envelope's ``canonical_digest`` matches the digest recomputed from the pack's canonical
    bytes (so flipping any covered byte is rejected here even before cryptographic verification).
    """
    if signature.algorithm not in SUPPORTED_ALGORITHMS:
        return False
    try:
        base64.b64decode(signature.signature, validate=True)
    except (binascii.Error, ValueError):
        return False
    try:
        recomputed = hashlib.sha256(_canonical(pack)).hexdigest()
    except (TypeError, ValueError):
        return False
    # A real canonical digest is ASCII hex; a non-ASCII value (e.g. a lone surrogate smuggled via
    # JSON) can never match and would make ``hmac.compare_digest`` raise ``TypeError``. Guard with
    # ``.isascii()`` so it fails closed (``False``) instead of raising out of the fail-closed path.
    return signature.canonical_digest.isascii() and hmac.compare_digest(
        recomputed, signature.canonical_digest
    )


def verify_pack(pack: dict[str, object], signature: PackSignature, verifier: Verifier) -> bool:
    """Recompute canonical bytes and verify the detached ``signature``. Fail-closed ``bool``.

    Returns ``False`` on any of: unknown/wrong algorithm, malformed base64, a covered digest that
    does not match the recomputed canonical digest (tamper), or an invalid cryptographic signature.
    The loader treats ``False`` as refuse-to-load.
    """
    if not verify_signature_structure(pack, signature):
        return False
    try:
        raw = base64.b64decode(signature.signature, validate=True)
    except (binascii.Error, ValueError):
        return False
    try:
        data = _canonical(pack)
    except (TypeError, ValueError):
        return False
    return verifier.verify(data, raw)


# --------------------------------------------------------------------------------------
# Ephemeral Ed25519 provider — no secret, no network. For tests + local release tooling.
# --------------------------------------------------------------------------------------
class Ed25519Signer:
    """In-process Ed25519 :class:`Signer`. Generate an ephemeral keypair with :meth:`generate`."""

    algorithm = ED25519_ALG

    def __init__(self, private_key: ed25519.Ed25519PrivateKey, key_id: str) -> None:
        self._private_key = private_key
        self.key_id = key_id

    @classmethod
    def generate(cls, key_id: str = "ephemeral-ed25519") -> Ed25519Signer:
        """Mint a fresh, in-memory Ed25519 keypair — no secret is read, written, or persisted."""
        return cls(ed25519.Ed25519PrivateKey.generate(), key_id)

    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data)

    def verifier(self) -> Ed25519Verifier:
        """Return the matching public-key :class:`Verifier` for round-trip verification."""
        return Ed25519Verifier(self._private_key.public_key(), self.key_id)


class Ed25519Verifier:
    """Public-key Ed25519 :class:`Verifier`. Fail-closed: any error verifying yields ``False``."""

    algorithm = ED25519_ALG

    def __init__(self, public_key: ed25519.Ed25519PublicKey, key_id: str = "ed25519") -> None:
        self._public_key = public_key
        self.key_id = key_id

    @classmethod
    def from_public_bytes(cls, raw: bytes, key_id: str = "ed25519") -> Ed25519Verifier:
        """Build a verifier from a 32-byte raw Ed25519 public key (e.g. a configured trust root)."""
        return cls(ed25519.Ed25519PublicKey.from_public_bytes(raw), key_id)

    def public_bytes(self) -> bytes:
        """Return the 32-byte raw Ed25519 public key.

        A public key is provenance, not a secret: it is safe to persist/publish so a downstream
        importer can verify a pack's detached signature. The *private* key is never exposed.
        """
        return self._public_key.public_bytes_raw()

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            self._public_key.verify(signature, data)
        except (InvalidSignature, ValueError, TypeError):
            return False
        return True


# --------------------------------------------------------------------------------------
# Trust bundle verifier — the customer-side, verification-only, KEYLESS trust root (issue #89).
# --------------------------------------------------------------------------------------
class TrustBundleVerifier:
    """Verify a pack's detached signature against a set of PINNED Ed25519 **PUBLIC** keys.

    This is the customer-side trust root: Microsoft signs packs **offline**; this platform only
    **verifies**. It is **keyless** — it holds only public keys (provenance, never secrets) — and
    **fail-closed**: an unknown/unpinned ``key_id``, an EMPTY bundle, or a wrong/tampered/malformed
    signature all yield ``False`` (:meth:`verify_pack`). It selects the public key whose ``key_id``
    matches the :class:`~shared.contracts.PackSignature` and delegates to :func:`verify_pack`.

    Rotation/pinning: publish a new ``key_id`` + public key into the :class:`~shared.contracts.
    TrustBundle` and retire an old one by removing it. Remote/refreshable bundle distribution (e.g.
    via signed pack-registry metadata) is a deliberate, documented **future** extension — this class
    verifies against whatever pinned set it is constructed with and does no fetching.
    """

    def __init__(self, verifiers: Mapping[str, Ed25519Verifier]) -> None:
        # A copy so the pinned set cannot be mutated after construction.
        self._by_key_id: dict[str, Ed25519Verifier] = dict(verifiers)

    @classmethod
    def from_bundle(cls, bundle: TrustBundle) -> TrustBundleVerifier:
        """Build a verifier from a :class:`~shared.contracts.TrustBundle`. Fail-closed per entry.

        An entry with an unsupported algorithm, a malformed base64 key, or a non-32-byte key is
        skipped (that key simply cannot verify anything). A **duplicate ``key_id``** is ambiguous —
        two different public keys claiming one id — so it is rejected with
        :class:`PackSignatureError` rather than silently resolving to one of them. An EMPTY result
        set is valid and rejects every pack (the fail-closed default until real Microsoft keys are
        pinned).
        """
        by_key_id: dict[str, Ed25519Verifier] = {}
        for entry in bundle.keys:
            if entry.algorithm != ED25519_ALG:
                continue  # only Ed25519 is supported; skip -> this key verifies nothing
            if entry.key_id in by_key_id:
                raise PackSignatureError(
                    f"Trust bundle has a duplicate key id {entry.key_id!r} (fail closed)"
                )
            try:
                raw = base64.b64decode(entry.public_key, validate=True)
            except (binascii.Error, ValueError):
                continue  # malformed key material -> skip (fail closed for this key)
            if len(raw) != 32:
                continue  # not a raw Ed25519 public key -> skip
            try:
                by_key_id[entry.key_id] = Ed25519Verifier.from_public_bytes(raw, entry.key_id)
            except (ValueError, TypeError):
                continue  # cryptography rejects the bytes -> skip
        return cls(by_key_id)

    @classmethod
    def reject_all(cls) -> TrustBundleVerifier:
        """An empty, pin-nothing verifier that rejects every pack — the fail-closed default."""
        return cls({})

    def key_ids(self) -> frozenset[str]:
        """The set of pinned key ids (for diagnostics/tests). Never exposes key material."""
        return frozenset(self._by_key_id)

    def public_bytes_for(self, key_id: str) -> bytes | None:
        """Return the pinned 32-byte raw Ed25519 PUBLIC key for ``key_id``, or ``None`` if absent.

        Exposes only PUBLIC key material (never a secret), so a caller that has already verified a
        pack against this trust root can record the exact pinned key as provenance. Returns ``None``
        when the ``key_id`` is not pinned (the caller must have fail-closed before reaching here).
        """
        verifier = self._by_key_id.get(key_id)
        return verifier.public_bytes() if verifier is not None else None

    def verify_pack(self, pack: dict[str, object], signature: PackSignature) -> bool:
        """Select the public key by ``signature.key_id`` and verify. Fail-closed ``bool``.

        Returns ``False`` when the ``key_id`` is not pinned in the bundle (unknown/unavailable trust
        root), and otherwise defers to :func:`verify_pack` (which fails closed on a wrong algorithm,
        malformed base64, a tampered digest, or a bad cryptographic signature).
        """
        verifier = self._by_key_id.get(signature.key_id)
        if verifier is None:
            return False  # unknown / unpinned key id -> fail closed
        return verify_pack(pack, signature, verifier)


__all__ = [
    "ED25519_ALG",
    "SUPPORTED_ALGORITHMS",
    "Ed25519Signer",
    "Ed25519Verifier",
    "PackSignatureError",
    "PackVerifier",
    "Signer",
    "TrustBundleVerifier",
    "Verifier",
    "sign_pack",
    "verify_pack",
    "verify_signature_structure",
]
