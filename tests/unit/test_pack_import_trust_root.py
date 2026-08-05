"""Trust-root pack-IMPORT admission gate (issue #89) — fail-closed, keyless, verification-only.

Proves the customer-side trust root: Microsoft signs packs OFFLINE (here, a synthetic in-test
Ed25519 keypair stands in), the platform VERIFIES against pinned PUBLIC keys, and every fail-closed
path rejects the import. All keys are ephemeral/synthetic and generated in-test — NO private key is
committed. Packs are synthetic, clearly-fake fixtures.
"""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import pytest

from cli.wiring import ENV_TRUST_BUNDLE_PATH, build_pack_import_verifier, build_packs_engine
from packs_engine.engine import PacksEngine, PackVerificationError
from shared.contracts import TrustBundle, TrustedPublicKey
from shared.signing import ED25519_ALG, Ed25519Signer, TrustBundleVerifier, sign_pack


def _pack(pack_id: str = "imported-pack", *, body_x: int = 1) -> dict:
    return {
        "manifest": {
            "id": pack_id,
            "type": "rule",
            "name": "Synthetic imported pack",
            "version": "1.0.0",
            "targets": ["epic"],
            "author": "microsoft",
        },
        "body": {"x": body_x, "note": "synthetic"},
    }


def _signed_pack(signer: Ed25519Signer, **kwargs) -> dict:
    pack = _pack(**kwargs)
    pack["manifest"]["pack_signature"] = sign_pack(pack, signer).model_dump()
    return pack


def _entry(signer: Ed25519Signer, key_id: str) -> TrustedPublicKey:
    pub = signer._private_key.public_key().public_bytes_raw()
    return TrustedPublicKey(
        key_id=key_id, algorithm=ED25519_ALG, public_key=base64.b64encode(pub).decode("ascii")
    )


def _engine(verifier: TrustBundleVerifier | None) -> PacksEngine:
    # A content root is required to construct the engine, but verify_pack_for_import never touches
    # the filesystem — it operates on the in-memory candidate pack.
    return PacksEngine("content", import_verifier=verifier)


# --------------------------------------------------------------------------------------
# Happy path
# --------------------------------------------------------------------------------------
def test_import_admits_pack_signed_by_pinned_key() -> None:
    signer = Ed25519Signer.generate("ms-2026a")
    verifier = TrustBundleVerifier.from_bundle(TrustBundle(keys=[_entry(signer, "ms-2026a")]))
    engine = _engine(verifier)
    # Does not raise: the detached signature verifies against the pinned public key.
    engine.verify_pack_for_import(_signed_pack(signer))


# --------------------------------------------------------------------------------------
# Fail-closed rejection paths (each raises PackVerificationError)
# --------------------------------------------------------------------------------------
def test_import_rejected_when_no_trust_root_wired() -> None:
    signer = Ed25519Signer.generate("k")
    engine = _engine(None)  # no trust root configured
    with pytest.raises(PackVerificationError, match="no trust root configured"):
        engine.verify_pack_for_import(_signed_pack(signer))


def test_import_rejected_on_empty_bundle() -> None:
    signer = Ed25519Signer.generate("k")
    engine = _engine(TrustBundleVerifier.reject_all())
    with pytest.raises(PackVerificationError, match="did not verify"):
        engine.verify_pack_for_import(_signed_pack(signer))


def test_import_rejected_on_unknown_key_id() -> None:
    signer = Ed25519Signer.generate("known")
    other = Ed25519Signer.generate("other")
    verifier = TrustBundleVerifier.from_bundle(TrustBundle(keys=[_entry(other, "other")]))
    with pytest.raises(PackVerificationError, match="did not verify"):
        _engine(verifier).verify_pack_for_import(_signed_pack(signer))


def test_import_rejected_on_wrong_key_for_id() -> None:
    signer = Ed25519Signer.generate("kid")
    impostor = Ed25519Signer.generate("kid")  # same id, different key material
    verifier = TrustBundleVerifier.from_bundle(TrustBundle(keys=[_entry(impostor, "kid")]))
    with pytest.raises(PackVerificationError, match="did not verify"):
        _engine(verifier).verify_pack_for_import(_signed_pack(signer))


def test_import_rejected_on_missing_signature() -> None:
    signer = Ed25519Signer.generate("kid")
    verifier = TrustBundleVerifier.from_bundle(TrustBundle(keys=[_entry(signer, "kid")]))
    with pytest.raises(PackVerificationError, match="no detached signature"):
        _engine(verifier).verify_pack_for_import(_pack())  # unsigned


def test_import_rejected_on_tampered_pack() -> None:
    signer = Ed25519Signer.generate("kid")
    verifier = TrustBundleVerifier.from_bundle(TrustBundle(keys=[_entry(signer, "kid")]))
    signed = _signed_pack(signer, body_x=1)
    tampered = copy.deepcopy(signed)
    tampered["body"]["x"] = 999  # flip a covered byte AFTER signing
    with pytest.raises(PackVerificationError, match="did not verify"):
        _engine(verifier).verify_pack_for_import(tampered)


def test_import_rejected_on_malformed_manifest() -> None:
    signer = Ed25519Signer.generate("kid")
    verifier = TrustBundleVerifier.from_bundle(TrustBundle(keys=[_entry(signer, "kid")]))
    with pytest.raises(PackVerificationError, match="malformed manifest"):
        _engine(verifier).verify_pack_for_import({"manifest": {"id": "x"}})  # missing fields
    with pytest.raises(PackVerificationError, match="missing or malformed manifest"):
        _engine(verifier).verify_pack_for_import({"body": {}})  # no manifest at all


# --------------------------------------------------------------------------------------
# Composition-root loader: build_pack_import_verifier is ALWAYS fail-closed by construction.
# --------------------------------------------------------------------------------------
def _write_bundle(path: Path, bundle: dict) -> None:
    path.write_text(json.dumps(bundle), encoding="utf-8")


def test_build_import_verifier_loads_pinned_key(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate("file-key")
    bundle_path = tmp_path / "trust-bundle.json"
    _write_bundle(
        bundle_path,
        {"schema_version": 1, "keys": [_entry(signer, "file-key").model_dump()]},
    )
    verifier = build_pack_import_verifier(config={ENV_TRUST_BUNDLE_PATH: str(bundle_path)})
    assert verifier.key_ids() == frozenset({"file-key"})
    _engine(verifier).verify_pack_for_import(_signed_pack(signer))  # admits


def test_build_import_verifier_missing_file_rejects_all(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate("k")
    missing = tmp_path / "nope.json"
    verifier = build_pack_import_verifier(config={ENV_TRUST_BUNDLE_PATH: str(missing)})
    assert verifier.key_ids() == frozenset()
    with pytest.raises(PackVerificationError):
        _engine(verifier).verify_pack_for_import(_signed_pack(signer))


def test_build_import_verifier_corrupt_file_rejects_all(tmp_path: Path) -> None:
    bundle_path = tmp_path / "trust-bundle.json"
    bundle_path.write_text("{ not valid json", encoding="utf-8")
    verifier = build_pack_import_verifier(config={ENV_TRUST_BUNDLE_PATH: str(bundle_path)})
    assert verifier.key_ids() == frozenset()


def test_build_import_verifier_duplicate_key_id_rejects_all(tmp_path: Path) -> None:
    a = Ed25519Signer.generate("dup")
    b = Ed25519Signer.generate("dup")
    bundle_path = tmp_path / "trust-bundle.json"
    keys = [_entry(a, "dup").model_dump(), _entry(b, "dup").model_dump()]
    _write_bundle(bundle_path, {"schema_version": 1, "keys": keys})
    verifier = build_pack_import_verifier(config={ENV_TRUST_BUNDLE_PATH: str(bundle_path)})
    # A duplicate/ambiguous bundle is refused wholesale -> reject-all (fail closed).
    assert verifier.key_ids() == frozenset()


def test_build_import_verifier_empty_default_bundle_is_reject_all(tmp_path: Path) -> None:
    bundle_path = tmp_path / "trust-bundle.json"
    _write_bundle(bundle_path, {"schema_version": 1, "keys": []})
    verifier = build_pack_import_verifier(config={ENV_TRUST_BUNDLE_PATH: str(bundle_path)})
    assert verifier.key_ids() == frozenset()


def test_build_packs_engine_wires_fail_closed_import_verifier(monkeypatch, tmp_path: Path) -> None:
    """The composition root wires a fail-closed import trust root into the engine (issue #89)."""
    (tmp_path / "content").mkdir()
    monkeypatch.setenv("WP_CONTENT_ROOT", str(tmp_path / "content"))
    # Point at an empty bundle so the wired verifier is reject-all regardless of the repo default.
    empty = tmp_path / "trust-bundle.json"
    _write_bundle(empty, {"schema_version": 1, "keys": []})
    monkeypatch.setenv(ENV_TRUST_BUNDLE_PATH, str(empty))

    engine = build_packs_engine()
    assert engine is not None
    signer = Ed25519Signer.generate("k")
    # Import admission fails closed: nothing is pinned, so a validly-signed pack is still rejected.
    with pytest.raises(PackVerificationError):
        engine.verify_pack_for_import(_signed_pack(signer))
