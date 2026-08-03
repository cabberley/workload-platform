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
  (via the ``cryptography`` library) so tests need **no secret and no network**.
* :class:`KeyVaultSigner` / :class:`KeyVaultVerifier` — a **fail-closed** Azure Key Vault stub
  (keyless via ``DefaultAzureCredential``). The azure SDK is imported **lazily inside the method**
  (mirroring ``modules.aiops.connectors.azure_monitor``) so importing this module — and
  ``mypy src`` — stays azure-free. Until the KV key is provisioned it raises ``NotImplementedError``
  with a ``TODO(human):`` note.

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
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from shared.contracts import PackSignature

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
    return hmac.compare_digest(recomputed, signature.canonical_digest)


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

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            self._public_key.verify(signature, data)
        except (InvalidSignature, ValueError, TypeError):
            return False
        return True


# --------------------------------------------------------------------------------------
# Azure Key Vault provider — fail-closed stub, keyless, guarded/lazy azure import.
# --------------------------------------------------------------------------------------
def _import_keyvault_crypto() -> None:
    """Guarded, lazy import of the Azure Key Vault crypto SDK (mirrors aiops azure_monitor edge).

    Azure imports live inside the method so importing this module — and ``mypy src`` — stays
    azure-free WITHOUT the Azure SDK installed. A missing SDK is tolerated because the KV providers
    are fail-closed stubs that raise ``NotImplementedError`` regardless of SDK presence.
    """
    try:
        from azure.identity import DefaultAzureCredential  # noqa: F401
        from azure.keyvault.keys.crypto import (  # noqa: F401
            CryptographyClient,
            SignatureAlgorithm,
        )
    except ImportError:
        return


class KeyVaultSigner:
    """Fail-closed Azure Key Vault :class:`Signer` stub (keyless via ``DefaultAzureCredential``).

    A real, typed provider — not a dead import. It satisfies the :class:`Signer` protocol but
    refuses to sign until the KV key is provisioned.
    """

    def __init__(self, key_id: str, *, algorithm: str = ED25519_ALG) -> None:
        self.key_id = key_id
        self.algorithm = algorithm

    def sign(self, data: bytes) -> bytes:
        _import_keyvault_crypto()
        raise NotImplementedError(
            "TODO(human): Azure Key Vault signing is not provisioned. Once the KV key exists, "
            "build a keyless CryptographyClient(self.key_id, DefaultAzureCredential()) and return "
            "client.sign(SignatureAlgorithm.eddsa, data).signature. Fail closed until then."
        )


class KeyVaultVerifier:
    """Fail-closed Azure Key Vault :class:`Verifier` stub (keyless via ``DefaultAzureCredential``).

    A real, typed provider — not a dead import. It satisfies the :class:`Verifier` protocol but
    refuses to verify until the KV key / public trust root is provisioned.
    """

    def __init__(self, key_id: str, *, algorithm: str = ED25519_ALG) -> None:
        self.key_id = key_id
        self.algorithm = algorithm

    def verify(self, data: bytes, signature: bytes) -> bool:
        _import_keyvault_crypto()
        raise NotImplementedError(
            "TODO(human): Azure Key Vault verification is not provisioned. Once the KV key / "
            "public trust root exists, build a keyless CryptographyClient(self.key_id, "
            "DefaultAzureCredential()) and return client.verify(SignatureAlgorithm.eddsa, data, "
            "signature).is_valid. Fail closed until then."
        )


__all__ = [
    "ED25519_ALG",
    "SUPPORTED_ALGORITHMS",
    "Ed25519Signer",
    "Ed25519Verifier",
    "KeyVaultSigner",
    "KeyVaultVerifier",
    "PackSignatureError",
    "Signer",
    "Verifier",
    "sign_pack",
    "verify_pack",
    "verify_signature_structure",
]
