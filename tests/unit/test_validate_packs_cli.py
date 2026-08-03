"""Tests for the CI detached-signature pass in scripts/validate_packs.py (issue #35, round-2).

Security invariant under test: a pack that CARRIES a ``pack_signature`` must be cryptographically
proven against a configured trusted public key, or the CI build FAILS CLOSED. Structural
self-consistency alone must NEVER pass. Packs are synthetic, secret-free fixtures.
"""
from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path

import pytest

from packs_engine.canonical import canonical_digest
from shared.contracts import PackSignature
from shared.signing import ED25519_ALG, Ed25519Signer, sign_pack

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "validate_packs.py"


def _load_cli():
    spec = importlib.util.spec_from_file_location("validate_packs_cli", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CLI = _load_cli()


def _pack(pack_id: str = "fake-pack", *, body_x: int = 1) -> dict:
    # A schema-valid `rule` body (issue #33's schema gate now runs in the same CLI): the rule item
    # allows additionalProperties, so `x` varies the canonical bytes while staying schema-valid.
    return {
        "manifest": {
            "id": pack_id,
            "type": "rule",
            "name": "Synthetic fake pack",
            "version": "1.0.0",
            "targets": ["epic"],
            "author": "microsoft",
        },
        "body": {
            "rules": [
                {
                    "id": "synthetic-rule-01",
                    "title": "Synthetic fake rule",
                    "resourceType": "Microsoft.Compute/virtualMachines",
                    "requiredTag": "synthetic-tag",
                    "severity": "medium",
                    "description": "Synthetic, secret-free fixture rule.",
                    "x": body_x,
                }
            ]
        },
    }


def _write(directory: Path, name: str, pack: dict) -> None:
    (directory / name).write_text(json.dumps(pack), encoding="utf-8")


def _pubkey_b64(signer: Ed25519Signer) -> str:
    raw = signer._private_key.public_key().public_bytes_raw()
    return base64.b64encode(raw).decode("ascii")


def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("WP_PACK_PUBLIC_KEY", "WP_REQUIRE_PACK_SIGNATURES", "WP_PACK_SIGNING_SECRET"):
        monkeypatch.delenv(var, raising=False)


def test_valid_signature_with_pubkey_passes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _clear_env(monkeypatch)
    pack = _pack()
    signer = Ed25519Signer.generate()
    pack["manifest"]["pack_signature"] = sign_pack(pack, signer).model_dump()
    _write(tmp_path, "p.json", pack)

    monkeypatch.setenv("WP_PACK_PUBLIC_KEY", _pubkey_b64(signer))
    assert CLI._verify_signatures(str(tmp_path)) == 0
    assert CLI.main(["validate_packs.py", str(tmp_path)]) == 0


def test_tampered_body_with_matching_digest_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The reported bypass: matching digest + junk signature must FAIL even with a pubkey set."""
    _clear_env(monkeypatch)
    signer = Ed25519Signer.generate()
    tampered = _pack(body_x=999)
    forged = PackSignature(
        algorithm=ED25519_ALG,
        signature=base64.b64encode(b"junk-signature-bytes").decode("ascii"),
        key_id="attacker",
        canonical_digest=canonical_digest(tampered),  # attacker recomputes to match
    )
    tampered["manifest"]["pack_signature"] = forged.model_dump()
    _write(tmp_path, "p.json", tampered)

    monkeypatch.setenv("WP_PACK_PUBLIC_KEY", _pubkey_b64(signer))
    assert CLI._verify_signatures(str(tmp_path)) == 1
    assert CLI.main(["validate_packs.py", str(tmp_path)]) == 1


def test_present_signature_without_pubkey_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A present (even valid) signature with NO trusted verifier configured must fail closed."""
    _clear_env(monkeypatch)
    pack = _pack()
    signer = Ed25519Signer.generate()
    pack["manifest"]["pack_signature"] = sign_pack(pack, signer).model_dump()
    _write(tmp_path, "p.json", pack)

    # No WP_PACK_PUBLIC_KEY configured.
    assert CLI._verify_signatures(str(tmp_path)) == 1
    assert CLI.main(["validate_packs.py", str(tmp_path)]) == 1


def test_require_flag_fails_unsigned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _clear_env(monkeypatch)
    _write(tmp_path, "p.json", _pack())  # no pack_signature
    monkeypatch.setenv("WP_REQUIRE_PACK_SIGNATURES", "1")
    assert CLI._verify_signatures(str(tmp_path)) == 1
    assert CLI.main(["validate_packs.py", str(tmp_path)]) == 1


def test_unsigned_allowed_by_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Regression: unsigned seed packs with no signature and no require flag still pass."""
    _clear_env(monkeypatch)
    _write(tmp_path, "p.json", _pack())
    assert CLI._verify_signatures(str(tmp_path)) == 0
    assert CLI.main(["validate_packs.py", str(tmp_path)]) == 0


def test_explicit_null_signature_json_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """An explicit `"pack_signature": null` (JSON) is malformed, not "unsigned" — fail closed."""
    _clear_env(monkeypatch)
    pack = _pack()
    pack["manifest"]["pack_signature"] = None  # explicit null, field PRESENT
    _write(tmp_path, "p.json", pack)

    # Fails closed whether or not mandatory signing is on.
    assert CLI._verify_signatures(str(tmp_path)) == 1
    assert CLI.main(["validate_packs.py", str(tmp_path)]) == 1
    monkeypatch.setenv("WP_REQUIRE_PACK_SIGNATURES", "1")
    assert CLI._verify_signatures(str(tmp_path)) == 1
    assert CLI.main(["validate_packs.py", str(tmp_path)]) == 1


def test_explicit_null_signature_yaml_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Same presence-based rule for a YAML manifest with an explicit null signature."""
    _clear_env(monkeypatch)
    yaml_text = (
        "manifest:\n"
        "  id: fake-pack\n"
        "  type: rule\n"
        "  name: Synthetic fake pack\n"
        "  version: 1.0.0\n"
        "  targets: [epic]\n"
        "  author: microsoft\n"
        "  pack_signature: null\n"
        "body:\n"
        "  rules:\n"
        "    - id: synthetic-rule-01\n"
        "      title: Synthetic fake rule\n"
        "      resourceType: Microsoft.Compute/virtualMachines\n"
        "      requiredTag: synthetic-tag\n"
        "      severity: medium\n"
        "      description: Synthetic, secret-free fixture rule.\n"
    )
    (tmp_path / "p.yaml").write_text(yaml_text, encoding="utf-8")

    assert CLI._verify_signatures(str(tmp_path)) == 1
    assert CLI.main(["validate_packs.py", str(tmp_path)]) == 1
    monkeypatch.setenv("WP_REQUIRE_PACK_SIGNATURES", "1")
    assert CLI._verify_signatures(str(tmp_path)) == 1
    assert CLI.main(["validate_packs.py", str(tmp_path)]) == 1


def test_omitted_signature_yaml_unsigned_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Regression: a YAML manifest that OMITS pack_signature is unsigned; passes when flag off."""
    _clear_env(monkeypatch)
    yaml_text = (
        "manifest:\n"
        "  id: fake-pack\n"
        "  type: rule\n"
        "  name: Synthetic fake pack\n"
        "  version: 1.0.0\n"
        "  targets: [epic]\n"
        "  author: microsoft\n"
        "body:\n"
        "  rules:\n"
        "    - id: synthetic-rule-01\n"
        "      title: Synthetic fake rule\n"
        "      resourceType: Microsoft.Compute/virtualMachines\n"
        "      requiredTag: synthetic-tag\n"
        "      severity: medium\n"
        "      description: Synthetic, secret-free fixture rule.\n"
    )
    (tmp_path / "p.yaml").write_text(yaml_text, encoding="utf-8")

    assert CLI._verify_signatures(str(tmp_path)) == 0
    assert CLI.main(["validate_packs.py", str(tmp_path)]) == 0
