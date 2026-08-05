"""Unit tests for detached pack signing + fail-closed verification (issue #35).

Pure, Azure-free, secret-free: the ephemeral Ed25519 provider generates its keypair in-process.
All packs here are synthetic, clearly-fake fixtures — no customer/Epic data.
"""
from __future__ import annotations

import base64
import copy
from pathlib import Path

import pytest

from packs_engine.canonical import canonical_digest
from packs_engine.engine import PacksEngine, PackVerificationError
from shared.contracts import PackSignature, TrustBundle, TrustedPublicKey
from shared.signing import (
    ED25519_ALG,
    Ed25519Signer,
    Ed25519Verifier,
    PackSignatureError,
    PackVerifier,
    Signer,
    TrustBundleVerifier,
    Verifier,
    sign_pack,
    verify_pack,
    verify_signature_structure,
)


def _pack(pack_id: str = "fake-pack", *, body_x: int = 1) -> dict:
    return {
        "manifest": {
            "id": pack_id,
            "type": "rule",
            "name": "Synthetic fake pack",
            "version": "1.0.0",
            "targets": ["epic"],
            "author": "microsoft",
        },
        "body": {"x": body_x, "note": "synthetic"},
    }


# --------------------------------------------------------------------------------------
# Protocol conformance + provenance
# --------------------------------------------------------------------------------------
def test_providers_satisfy_protocols():
    signer = Ed25519Signer.generate("kid-1")
    assert isinstance(signer, Signer)
    assert isinstance(signer.verifier(), Verifier)
    assert isinstance(TrustBundleVerifier.reject_all(), PackVerifier)


def test_sign_pack_envelope_is_self_describing():
    pack = _pack()
    signer = Ed25519Signer.generate("release-key-2026")
    sig = sign_pack(pack, signer)
    assert isinstance(sig, PackSignature)
    assert sig.algorithm == ED25519_ALG
    assert sig.key_id == "release-key-2026"
    assert sig.canonical_digest == canonical_digest(pack)
    # base64 signature is well-formed and non-empty.
    assert base64.b64decode(sig.signature, validate=True)


# --------------------------------------------------------------------------------------
# Round-trip + tamper / fail-closed
# --------------------------------------------------------------------------------------
def test_sign_verify_roundtrip():
    pack = _pack()
    signer = Ed25519Signer.generate()
    sig = sign_pack(pack, signer)
    assert verify_pack(pack, sig, signer.verifier()) is True


def test_tamper_body_byte_fails_closed():
    pack = _pack(body_x=1)
    signer = Ed25519Signer.generate()
    sig = sign_pack(pack, signer)

    tampered = copy.deepcopy(pack)
    tampered["body"]["x"] = 2  # flip one covered value
    assert verify_pack(tampered, sig, signer.verifier()) is False


def test_signing_does_not_change_version_identity():
    """Attaching the detached signature must not change canonical (version-identity) bytes."""
    pack = _pack()
    before = canonical_digest(pack)
    signer = Ed25519Signer.generate()
    sig = sign_pack(pack, signer)
    signed = copy.deepcopy(pack)
    signed["manifest"]["pack_signature"] = sig.model_dump()
    assert canonical_digest(signed) == before
    # And the attached signature still verifies against the signed pack.
    assert verify_pack(signed, sig, signer.verifier()) is True


def test_wrong_key_verifier_rejects():
    pack = _pack()
    signer = Ed25519Signer.generate()
    sig = sign_pack(pack, signer)
    other_verifier = Ed25519Signer.generate().verifier()  # unrelated key
    assert verify_pack(pack, sig, other_verifier) is False


def test_canonical_digest_binding_mismatch_fails_closed():
    pack = _pack()
    signer = Ed25519Signer.generate()
    sig = sign_pack(pack, signer)
    forged = sig.model_copy(update={"canonical_digest": "0" * 64})
    assert verify_pack(pack, forged, signer.verifier()) is False
    assert verify_signature_structure(pack, forged) is False


def test_wrong_algorithm_fails_closed():
    pack = _pack()
    signer = Ed25519Signer.generate()
    sig = sign_pack(pack, signer)
    wrong = sig.model_copy(update={"algorithm": "rsa-pss"})
    assert verify_pack(pack, wrong, signer.verifier()) is False
    assert verify_signature_structure(pack, wrong) is False


def test_malformed_base64_signature_fails_closed():
    pack = _pack()
    sig = PackSignature(
        algorithm=ED25519_ALG,
        signature="not!base64!",
        key_id="k",
        canonical_digest=canonical_digest(pack),
    )
    verifier = Ed25519Signer.generate().verifier()
    assert verify_signature_structure(pack, sig) is False
    assert verify_pack(pack, sig, verifier) is False


def test_structure_check_passes_for_valid_signature():
    pack = _pack()
    sig = sign_pack(pack, Ed25519Signer.generate())
    assert verify_signature_structure(pack, sig) is True


def test_verify_pack_does_not_trust_carried_digest():
    """A forged envelope digest (matching a tampered body) must NOT make verify_pack pass.

    Proves verify_pack recomputes canonical_bytes and does a real cryptographic verify — structural
    self-consistency (digest match) is not proof of authenticity.
    """
    pack = _pack(body_x=1)
    signer = Ed25519Signer.generate()

    tampered = copy.deepcopy(pack)
    tampered["body"]["x"] = 999  # attacker changes the body
    forged = PackSignature(
        algorithm=ED25519_ALG,
        signature=base64.b64encode(b"junk-signature-bytes").decode("ascii"),
        key_id="attacker",
        canonical_digest=canonical_digest(tampered),  # recomputed to match the tampered body
    )
    # Structural self-consistency passes (digest matches) ...
    assert verify_signature_structure(tampered, forged) is True
    # ... but the real cryptographic verify still fails closed.
    assert verify_pack(tampered, forged, signer.verifier()) is False


def test_empty_signature_provider_raises():
    class _EmptySigner:
        algorithm = ED25519_ALG
        key_id = "empty"

        def sign(self, data: bytes) -> bytes:
            return b""

    with pytest.raises(PackSignatureError):
        sign_pack(_pack(), _EmptySigner())


# --------------------------------------------------------------------------------------
# Loader fail-closed enforcement (engine)
# --------------------------------------------------------------------------------------
def _write_pack(directory: Path, name: str, pack: dict) -> Path:
    import json

    path = directory / name
    path.write_text(json.dumps(pack), encoding="utf-8")
    return path


def test_loader_unchanged_when_no_verifier(tmp_path: Path):
    """No verifier injected => today's behavior preserved: unsigned packs load fine."""
    _write_pack(tmp_path, "p.json", _pack())
    engine = PacksEngine(tmp_path)
    packs = engine.load_all(verify_sig=False)
    assert len(packs) == 1
    assert packs[0].manifest.pack_signature is None


def test_loader_accepts_signed_pack_with_verifier(tmp_path: Path):
    pack = _pack()
    signer = Ed25519Signer.generate()
    sig = sign_pack(pack, signer)
    pack["manifest"]["pack_signature"] = sig.model_dump()
    _write_pack(tmp_path, "p.json", pack)

    engine = PacksEngine(tmp_path, signature_verifier=signer.verifier())
    packs = engine.load_all(verify_sig=False)
    assert len(packs) == 1
    assert packs[0].manifest.pack_signature is not None


def test_loader_refuses_unsigned_pack_when_verifier_injected(tmp_path: Path):
    _write_pack(tmp_path, "p.json", _pack())  # no pack_signature
    engine = PacksEngine(tmp_path, signature_verifier=Ed25519Signer.generate().verifier())
    with pytest.raises(PackVerificationError, match="missing detached signature"):
        engine.load_all(verify_sig=False)


def test_loader_refuses_tampered_pack_when_verifier_injected(tmp_path: Path):
    pack = _pack(body_x=1)
    signer = Ed25519Signer.generate()
    sig = sign_pack(pack, signer)
    pack["manifest"]["pack_signature"] = sig.model_dump()
    pack["body"]["x"] = 999  # tamper AFTER signing
    _write_pack(tmp_path, "p.json", pack)

    engine = PacksEngine(tmp_path, signature_verifier=signer.verifier())
    with pytest.raises(PackVerificationError, match="failed verification"):
        engine.load_all(verify_sig=False)


def test_loader_refuses_wrong_key_when_verifier_injected(tmp_path: Path):
    pack = _pack()
    sig = sign_pack(pack, Ed25519Signer.generate())
    pack["manifest"]["pack_signature"] = sig.model_dump()
    _write_pack(tmp_path, "p.json", pack)

    wrong_verifier = Ed25519Signer.generate().verifier()
    engine = PacksEngine(tmp_path, signature_verifier=wrong_verifier)
    with pytest.raises(PackVerificationError):
        engine.load_all(verify_sig=False)


# --------------------------------------------------------------------------------------
# Trust bundle verifier (issue #89) — customer-side, keyless, verification-only, fail-closed.
# --------------------------------------------------------------------------------------
def _bundle_entry(signer: Ed25519Signer, key_id: str) -> TrustedPublicKey:
    pub = signer._private_key.public_key().public_bytes_raw()  # 32-byte raw public key
    return TrustedPublicKey(
        key_id=key_id, algorithm=ED25519_ALG, public_key=base64.b64encode(pub).decode("ascii")
    )


def test_trust_bundle_verifier_happy_path_known_key_verifies():
    signer = Ed25519Signer.generate("ms-pack-signing-2026a")
    pack = _pack()
    sig = sign_pack(pack, signer)
    bundle = TrustBundle(keys=[_bundle_entry(signer, "ms-pack-signing-2026a")])
    verifier = TrustBundleVerifier.from_bundle(bundle)
    assert verifier.key_ids() == frozenset({"ms-pack-signing-2026a"})
    assert verifier.verify_pack(pack, sig) is True


def test_trust_bundle_verifier_unknown_key_id_rejects():
    signer = Ed25519Signer.generate("known")
    pack = _pack()
    sig = sign_pack(pack, signer)  # signature.key_id == "known"
    other = Ed25519Signer.generate("other")
    bundle = TrustBundle(keys=[_bundle_entry(other, "other")])  # "known" not pinned
    assert TrustBundleVerifier.from_bundle(bundle).verify_pack(pack, sig) is False


def test_trust_bundle_verifier_empty_bundle_rejects():
    signer = Ed25519Signer.generate("k")
    pack = _pack()
    sig = sign_pack(pack, signer)
    assert TrustBundleVerifier.from_bundle(TrustBundle(keys=[])).verify_pack(pack, sig) is False
    assert TrustBundleVerifier.reject_all().verify_pack(pack, sig) is False


def test_trust_bundle_verifier_wrong_key_for_id_rejects():
    """A pinned key under the RIGHT id but the WRONG key material must reject (fail closed)."""
    signer = Ed25519Signer.generate("kid")
    pack = _pack()
    sig = sign_pack(pack, signer)  # signed by `signer`, key_id == "kid"
    impostor = Ed25519Signer.generate("kid")  # different key, SAME id
    bundle = TrustBundle(keys=[_bundle_entry(impostor, "kid")])
    assert TrustBundleVerifier.from_bundle(bundle).verify_pack(pack, sig) is False


def test_trust_bundle_verifier_tampered_pack_rejects():
    signer = Ed25519Signer.generate("kid")
    pack = _pack(body_x=1)
    sig = sign_pack(pack, signer)
    bundle = TrustBundle(keys=[_bundle_entry(signer, "kid")])
    verifier = TrustBundleVerifier.from_bundle(bundle)
    tampered = copy.deepcopy(pack)
    tampered["body"]["x"] = 999
    assert verifier.verify_pack(tampered, sig) is False


def test_trust_bundle_verifier_malformed_or_unsupported_entries_are_skipped():
    good = Ed25519Signer.generate("good")
    pack = _pack()
    sig = sign_pack(pack, good)
    bundle = TrustBundle(
        keys=[
            TrustedPublicKey(key_id="bad-b64", algorithm=ED25519_ALG, public_key="not!base64!"),
            TrustedPublicKey(key_id="short", algorithm=ED25519_ALG, public_key=base64.b64encode(
                b"too-short").decode("ascii")),
            TrustedPublicKey(key_id="wrong-alg", algorithm="rsa-pss", public_key=base64.b64encode(
                b"\x00" * 32).decode("ascii")),
            _bundle_entry(good, "good"),
        ]
    )
    verifier = TrustBundleVerifier.from_bundle(bundle)
    # Only the well-formed ed25519 entry survives; the rest are skipped (fail closed per key).
    assert verifier.key_ids() == frozenset({"good"})
    assert verifier.verify_pack(pack, sig) is True


def test_trust_bundle_verifier_duplicate_key_id_is_rejected():
    a = Ed25519Signer.generate("dup")
    b = Ed25519Signer.generate("dup")
    bundle = TrustBundle(keys=[_bundle_entry(a, "dup"), _bundle_entry(b, "dup")])
    with pytest.raises(PackSignatureError, match="duplicate key id"):
        TrustBundleVerifier.from_bundle(bundle)


def test_ed25519_verifier_from_public_bytes_roundtrip():
    signer = Ed25519Signer.generate()
    pack = _pack()
    sig = sign_pack(pack, signer)
    pub = signer._private_key.public_key().public_bytes_raw()  # 32-byte raw key
    verifier = Ed25519Verifier.from_public_bytes(pub)
    assert verify_pack(pack, sig, verifier) is True
