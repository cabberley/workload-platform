"""Packs studio (``wp-packs``) tests — one per subcommand, deterministic and Azure-free.

Every fixture is synthetic and clearly fake (guardrail 2). The studio reuses the shared schema
gate (#33), registry (#34), signing (#35), and the real capability modules; these tests assert the
CLI wiring — exit codes and key on-disk/observable effects — not the internals of that shared code.
No network, no Azure SDK, no secret is touched.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

from cli.packs_studio import main
from packs_engine import canonical_digest, validate_pack
from shared.contracts import PackSignature
from shared.signing import (
    Ed25519Signer,
    Ed25519Verifier,
    verify_pack,
    verify_signature_structure,
)


def _scaffold(tmp_path: Path, pack_type: str, pack_id: str) -> Path:
    out = tmp_path / f"{pack_id}.json"
    assert main(["new", pack_type, "--id", pack_id, "--out", str(out)]) == 0
    return out


def _sign(path: Path) -> None:
    assert main(["sign", str(path)]) == 0


def _trust_bundle_from_sidecar(pack_path: Path, dest: Path) -> Path:
    """Pin the PUBLIC key ``sign`` wrote (its ``.pubkey`` sidecar) into a synthetic trust bundle.

    Mirrors real Microsoft authoring: sign OFFLINE, publish the PUBLIC key + key_id into the pinned
    trust bundle, then export/verify against it. NO private key is ever written to disk.
    """
    sidecar = json.loads(pack_path.with_name(pack_path.name + ".pubkey").read_text("utf-8"))
    dest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "keys": [
                    {
                        "key_id": sidecar["keyId"],
                        "algorithm": sidecar["algorithm"],
                        "public_key": sidecar["publicKey"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return dest


def _export(path: Path, dist: Path, *, trust_bundle: Path) -> int:
    return main(["export", str(path), "--dist", str(dist), "--trust-bundle", str(trust_bundle)])


# --------------------------------------------------------------------------------------
# new
# --------------------------------------------------------------------------------------
def test_new_scaffolds_a_schema_valid_pack_of_every_type(tmp_path: Path) -> None:
    for pack_type in ("workload", "rule", "telemetry", "dependency", "ops"):
        out = tmp_path / f"{pack_type}.json"
        assert main(["new", pack_type, "--out", str(out)]) == 0
        pack = json.loads(out.read_text(encoding="utf-8"))
        assert pack["manifest"]["type"] == pack_type
        assert validate_pack(pack) == []  # born valid


def test_new_defaults_id_and_name_when_omitted(tmp_path: Path) -> None:
    out = tmp_path / "scaffold.json"
    assert main(["new", "rule", "--out", str(out)]) == 0
    pack = json.loads(out.read_text(encoding="utf-8"))
    assert pack["manifest"]["id"] == "starter-rule"
    assert pack["manifest"]["name"]


# --------------------------------------------------------------------------------------
# validate
# --------------------------------------------------------------------------------------
def test_validate_accepts_a_scaffold_and_rejects_a_bad_pack(tmp_path: Path) -> None:
    good = _scaffold(tmp_path, "rule", "good-rule")
    assert main(["validate", str(good)]) == 0

    bad = tmp_path / "bad.json"
    # Rule body requires a non-empty 'rules' array — an empty body is schema-invalid.
    bad.write_text(
        json.dumps({"manifest": {"id": "bad", "type": "rule", "name": "bad", "version": "1.0.0"},
                    "body": {}}),
        encoding="utf-8",
    )
    assert main(["validate", str(bad)]) == 1


def test_incomplete_manifest_is_rejected_by_validate_sign_and_export(tmp_path: Path) -> None:
    # Body is schema-valid, but the manifest is missing the required 'name' field — so only the
    # PackManifest contract check can catch it. validate/sign/export must all fail closed.
    path = tmp_path / "nomanifestname.json"
    path.write_text(
        json.dumps({
            "manifest": {"id": "no-name", "type": "rule", "version": "1.0.0"},
            "body": {"rules": [{"id": "r", "requiredTag": "owner", "description": "d"}]},
        }),
        encoding="utf-8",
    )
    # Sanity: the body alone IS schema-valid, isolating the manifest as the failure cause.
    assert validate_pack(json.loads(path.read_text(encoding="utf-8"))) == []
    assert main(["validate", str(path)]) == 1
    assert main(["sign", str(path)]) == 1
    assert main(["export", str(path), "--dist", str(tmp_path / "dist")]) == 1


# --------------------------------------------------------------------------------------
# test
# --------------------------------------------------------------------------------------
def test_test_runs_rule_pack_through_quality_checks(tmp_path: Path, capsys) -> None:
    path = _scaffold(tmp_path, "rule", "owner-rule")
    assert main(["test", str(path)]) == 0
    out = capsys.readouterr().out
    assert "quality_checks" in out
    # The synthetic app node lacks the required 'owner' tag → a FAIL finding is surfaced.
    assert "FAIL" in out


def test_test_runs_telemetry_pack_through_aiops(tmp_path: Path, capsys) -> None:
    path = _scaffold(tmp_path, "telemetry", "cpu-telemetry")
    assert main(["test", str(path)]) == 0
    out = capsys.readouterr().out
    assert "aiops" in out
    # cpu_percent 97 > 90 on the app node → one detection.
    assert "1 detections" in out


def test_test_fails_closed_for_a_non_runnable_type(tmp_path: Path) -> None:
    path = _scaffold(tmp_path, "ops", "notify")
    assert main(["test", str(path)]) == 1  # ops has no runnable module


# --------------------------------------------------------------------------------------
# sign
# --------------------------------------------------------------------------------------
def test_sign_attaches_a_structurally_verifiable_signature(tmp_path: Path) -> None:
    path = _scaffold(tmp_path, "rule", "sign-me")
    _sign(path)
    pack = json.loads(path.read_text(encoding="utf-8"))
    raw_sig = pack["manifest"]["pack_signature"]
    assert raw_sig["algorithm"] == "ed25519"
    signature = PackSignature(**raw_sig)
    # Keyless self-consistency: the covered digest matches the pack's canonical bytes.
    assert verify_signature_structure(pack, signature) is True
    assert signature.canonical_digest == canonical_digest(pack)


def test_sign_refuses_an_invalid_pack(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(
        json.dumps({"manifest": {"id": "bad", "type": "rule", "name": "bad", "version": "1.0.0"},
                    "body": {}}),
        encoding="utf-8",
    )
    assert main(["sign", str(bad)]) == 1


# --------------------------------------------------------------------------------------
# export
# --------------------------------------------------------------------------------------
def test_export_writes_bundle_and_registers_version(tmp_path: Path) -> None:
    path = _scaffold(tmp_path, "rule", "exportable")
    _sign(path)
    dist = tmp_path / "dist"
    tb = _trust_bundle_from_sidecar(path, tmp_path / "trust-bundle.json")
    assert _export(path, dist, trust_bundle=tb) == 0

    bundle = dist / "exportable-0.1.0.wpack"
    sidecar = dist / "exportable-0.1.0.manifest.json"
    index = dist / "registry" / "index.json"
    assert bundle.is_file() and sidecar.is_file() and index.is_file()

    envelope = json.loads(bundle.read_text(encoding="utf-8"))
    assert envelope["schema"] == "aegis.pack-bundle/1"
    assert envelope["provenance"]["id"] == "exportable"
    assert envelope["provenance"]["algorithm"] == "ed25519"
    assert envelope["pack"]["manifest"]["pack_signature"]

    registry = json.loads(index.read_text(encoding="utf-8"))
    refs = {(e["id"], e["version"]) for e in registry["entries"]}
    assert ("exportable", "0.1.0") in refs


def test_exported_bundle_is_independently_verifiable_with_its_public_key(tmp_path: Path) -> None:
    path = _scaffold(tmp_path, "rule", "verifiable")
    _sign(path)
    dist = tmp_path / "dist"
    tb = _trust_bundle_from_sidecar(path, tmp_path / "trust-bundle.json")
    assert _export(path, dist, trust_bundle=tb) == 0

    envelope = json.loads((dist / "verifiable-0.1.0.wpack").read_text(encoding="utf-8"))
    # The bundle carries the signer's PUBLIC key, so a downstream importer can verify with no
    # external state and no private key.
    raw_pub = base64.b64decode(envelope["provenance"]["publicKey"], validate=True)
    signature = PackSignature(**envelope["pack"]["manifest"]["pack_signature"])
    assert verify_pack(envelope["pack"], signature, Ed25519Verifier.from_public_bytes(raw_pub))


def test_export_fails_closed_on_forged_signature_and_writes_nothing(tmp_path: Path) -> None:
    # Reproduce the reviewer's bypass: a correct canonical_digest paired with a junk 64-byte
    # signature passes the STRUCTURAL pre-check but must fail real cryptographic verification.
    path = _scaffold(tmp_path, "rule", "forged")
    _sign(path)
    pack = json.loads(path.read_text(encoding="utf-8"))
    forged = base64.b64encode(b"\x00" * 64).decode("ascii")  # valid base64, valid Ed25519 length
    pack["manifest"]["pack_signature"]["signature"] = forged
    path.write_text(json.dumps(pack), encoding="utf-8")

    # Structural self-consistency still passes (digest untouched) — proving it is insufficient.
    reloaded = json.loads(path.read_text(encoding="utf-8"))
    assert verify_signature_structure(
        reloaded, PackSignature(**reloaded["manifest"]["pack_signature"])
    )

    dist = tmp_path / "dist"
    assert main(["export", str(path), "--dist", str(dist)]) == 1
    assert list(dist.rglob("*.wpack")) == []  # nothing written


def test_new_rejects_unsafe_pack_ids(tmp_path: Path) -> None:
    # ``new`` must reject a traversal id BEFORE constructing any output path (fail closed).
    for bad in ["../../escaped", "with/slash", "..", "back\\slash"]:
        out = tmp_path / "safe.json"
        assert main(["new", "rule", "--id", bad, "--out", str(out)]) == 1
        assert not out.exists()
    # Nothing was written anywhere under the tree for a traversal id.
    assert list(tmp_path.rglob("*escaped*")) == []
    # A safe id still scaffolds normally.
    good = tmp_path / "good.json"
    assert main(["new", "rule", "--id", "good-rule", "--out", str(good)]) == 0
    assert good.is_file()


def test_export_blocks_pack_id_path_traversal(tmp_path: Path) -> None:
    # ``new`` refuses an unsafe id, so craft the malicious pack by mutating a valid scaffold's id;
    # ``sign`` does not gate on the id, so export must be the one to fail closed on traversal.
    path = _scaffold(tmp_path, "rule", "evil")
    pack = json.loads(path.read_text(encoding="utf-8"))
    pack["manifest"]["id"] = "../../escaped"
    path.write_text(json.dumps(pack), encoding="utf-8")
    _sign(path)
    dist = tmp_path / "sub" / "dist"
    assert main(["export", str(path), "--dist", str(dist)]) == 1
    # Nothing was written outside (or inside) dist for the traversal id.
    assert list(tmp_path.rglob("*escaped*.wpack")) == []


def test_non_semver_version_is_rejected_by_validate_sign_and_export(tmp_path: Path) -> None:
    # A body+manifest-valid pack whose version is not semver must fail cleanly (no crash) at
    # validate, sign, AND export, and export must write no bundle/sidecar.
    path = _scaffold(tmp_path, "rule", "badver")
    pack = json.loads(path.read_text(encoding="utf-8"))
    pack["manifest"]["version"] = "not-semver"
    path.write_text(json.dumps(pack), encoding="utf-8")

    assert main(["validate", str(path)]) == 1
    assert main(["sign", str(path)]) == 1
    dist = tmp_path / "dist"
    assert main(["export", str(path), "--dist", str(dist)]) == 1
    assert list(dist.rglob("*.wpack")) == []
    assert list(dist.rglob("*.manifest.json")) == []


def test_export_refuses_an_unsigned_pack(tmp_path: Path) -> None:
    path = _scaffold(tmp_path, "rule", "unsigned")
    assert main(["export", str(path), "--dist", str(tmp_path / "dist")]) == 1


def test_export_enforces_version_immutability_on_mutated_republish(tmp_path: Path) -> None:
    path = _scaffold(tmp_path, "rule", "immutable")
    _sign(path)
    dist = tmp_path / "dist"
    tb = tmp_path / "trust-bundle.json"
    _trust_bundle_from_sidecar(path, tb)
    assert _export(path, dist, trust_bundle=tb) == 0

    # Mutate the body at the SAME id@version and re-sign so the signature matches the new content,
    # then re-export: the registry must reject the differing digest (fail closed).
    pack = json.loads(path.read_text(encoding="utf-8"))
    pack["body"]["rules"][0]["requiredTag"] = "cost-center"
    pack["manifest"].pop("pack_signature", None)
    path.write_text(json.dumps(pack), encoding="utf-8")
    _sign(path)
    _trust_bundle_from_sidecar(path, tb)  # re-pin the freshly re-signed key so admission passes

    assert _export(path, dist, trust_bundle=tb) == 1


# --------------------------------------------------------------------------------------
# export trust-root ADMISSION (issue #89): the PINNED bundle — not a caller-supplied key —
# gates every registry/store write, so the runtime's "registry digest => trusted" invariant holds.
# --------------------------------------------------------------------------------------
def _ms_trust_bundle(dest: Path, *, key_id: str = "ms-root-2026") -> Path:
    """Write a synthetic 'Microsoft' trust bundle pinning ONE ephemeral PUBLIC key (keyless)."""
    signer = Ed25519Signer.generate(key_id)
    pub = base64.b64encode(signer.verifier().public_bytes()).decode("ascii")
    dest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "keys": [{"key_id": key_id, "algorithm": "ed25519", "public_key": pub}],
            }
        ),
        encoding="utf-8",
    )
    return dest


def test_export_rejects_pack_signed_by_key_not_in_pinned_bundle(tmp_path: Path) -> None:
    # The reviewer's bypass: an attacker signs a pack with their OWN key and exports it. The pinned
    # bundle holds only Microsoft's key, so the attacker's key_id is not pinned => reject, and
    # NOTHING is written into the runtime-trusted registry/store (fail closed).
    path = _scaffold(tmp_path, "rule", "attacker")
    _sign(path)  # attacker key, key_id 'ephemeral-ed25519' — NOT in the Microsoft bundle
    dist = tmp_path / "dist"
    tb = _ms_trust_bundle(tmp_path / "ms-bundle.json")
    assert main(["export", str(path), "--dist", str(dist), "--trust-bundle", str(tb)]) == 1
    assert list(dist.rglob("*.wpack")) == []
    assert not (dist / "registry" / "index.json").exists()
    assert not (dist / "store").exists()


def test_export_accepts_pack_signed_by_a_pinned_key(tmp_path: Path) -> None:
    # key_id flows end to end: sign --key-id -> signature.key_id -> pinned bundle key_id -> verify.
    path = _scaffold(tmp_path, "rule", "trusted")
    assert main(["sign", str(path), "--key-id", "ms-root-2026"]) == 0
    dist = tmp_path / "dist"
    tb = _trust_bundle_from_sidecar(path, tmp_path / "trust-bundle.json")
    assert _export(path, dist, trust_bundle=tb) == 0
    assert (dist / "trusted-0.1.0.wpack").is_file()
    # Provenance records the PINNED public key that authorised admission.
    envelope = json.loads((dist / "trusted-0.1.0.wpack").read_text(encoding="utf-8"))
    assert envelope["provenance"]["keyId"] == "ms-root-2026"


def test_export_rejects_all_when_bundle_missing(tmp_path: Path) -> None:
    # An empty/unavailable trust bundle is reject-all: a validly self-signed pack still cannot be
    # admitted to a runtime-trusted registry (fail closed by construction).
    path = _scaffold(tmp_path, "rule", "nobundle")
    _sign(path)
    dist = tmp_path / "dist"
    missing = tmp_path / "does-not-exist.json"
    assert main(["export", str(path), "--dist", str(dist), "--trust-bundle", str(missing)]) == 1
    assert list(dist.rglob("*.wpack")) == []


def test_export_rejects_signed_pack_with_blank_key_id(tmp_path: Path) -> None:
    # Blank the key_id AFTER signing. canonical_bytes exclude pack_signature, so the structural
    # digest still matches — proving the key_id guard (not the digest) is what rejects it: a
    # signature the trust root cannot attribute to any pinned key can never be admitted.
    path = _scaffold(tmp_path, "rule", "nokeyid")
    _sign(path)
    tb = _trust_bundle_from_sidecar(path, tmp_path / "trust-bundle.json")
    pack = json.loads(path.read_text(encoding="utf-8"))
    pack["manifest"]["pack_signature"]["key_id"] = ""
    path.write_text(json.dumps(pack), encoding="utf-8")
    dist = tmp_path / "dist"
    assert main(["export", str(path), "--dist", str(dist), "--trust-bundle", str(tb)]) == 1
    assert list(dist.rglob("*.wpack")) == []
