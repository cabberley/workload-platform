"""Issue #82 — require integrity fields on shipped packs + reconcile pack-integrity docs.

Two guarantees, both fail-closed:

* **Loader boundary.** A shipped/first-party pack that OMITS its ``sha256`` content-hash integrity
  field is REJECTED at load (fail closed); the shipped runtime packs (which now carry the hash)
  still load. The detached signature is deferred for first-party packs (see the ``TODO(human)``
  hook in ``packs_engine.engine``); imported/third-party packs are held to the stricter
  signature bar by ``_resolve_imported_packs`` (issue #89, covered elsewhere).
* **Docs.** ``ARCHITECTURE.md`` / ``SECURITY.md`` no longer make the stale "SHA-256 + HMAC"
  pack-integrity claim and instead describe the IMPLEMENTED detached-Ed25519 scheme.

All packs here are synthetic, clearly-fake fixtures — no customer/Epic data.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from packs_engine.canonical import canonical_digest
from packs_engine.engine import PacksEngine, PackVerificationError
from shared.contracts import PackType

_REPO_ROOT = Path(__file__).resolve().parents[2]
CONTENT = _REPO_ROOT / "content"

# Runtime (loadable) pack subtrees — excludes the reserved, non-runtime ``templates/`` scaffolds
# and the registry index, neither of which is loaded/executed as a pack.
_RUNTIME_SUBDIRS = ("dependencies", "ops", "rules", "telemetry", "workloads")


def _rule_pack(*, with_hash: bool) -> dict:
    body = {
        "rules": [
            {
                "id": "syn-01",
                "title": "Synthetic rule",
                "resourceType": "Microsoft.Compute/virtualMachines",
                "requiredTag": "backup",
                "severity": "high",
                "description": "Synthetic fake rule — no customer data.",
            }
        ]
    }
    manifest = {
        "id": "syn-rule",
        "type": "rule",
        "name": "Synthetic rule pack",
        "version": "1.0.0",
        "targets": ["epic"],
        "author": "microsoft",
    }
    pack = {"manifest": manifest, "body": body}
    if with_hash:
        # MEDIUM-2: the required hash covers the pack's CANONICAL bytes (whole manifest + body),
        # the same canonicalization ``shared.signing`` signs over — not the body alone.
        manifest["sha256"] = canonical_digest(pack)
    return pack


def _write(directory: Path, name: str, pack: dict) -> None:
    (directory / name).write_text(json.dumps(pack), encoding="utf-8")


# --------------------------------------------------------------------------------------
# Loader fail-closed: a shipped pack MISSING the content-hash integrity field is rejected.
# --------------------------------------------------------------------------------------
def test_shipped_pack_missing_content_hash_is_rejected(tmp_path: Path) -> None:
    _write(tmp_path, "p.json", _rule_pack(with_hash=False))  # no sha256
    engine = PacksEngine(tmp_path)  # require_integrity defaults to True
    with pytest.raises(PackVerificationError, match="content-hash integrity field"):
        engine.load_all()


def test_shipped_pack_with_content_hash_loads(tmp_path: Path) -> None:
    _write(tmp_path, "p.json", _rule_pack(with_hash=True))
    engine = PacksEngine(tmp_path)
    packs = engine.load_all()
    assert [p.manifest.id for p in packs] == ["syn-rule"]
    assert packs[0].manifest.sha256 is not None
    assert packs[0].imported is False  # first-party / shipped provenance


def test_require_integrity_escape_hatch_allows_hashless_pack(tmp_path: Path) -> None:
    # The opt-out exists only for in-memory/synthetic fixtures; production keeps it ON.
    _write(tmp_path, "p.json", _rule_pack(with_hash=False))
    engine = PacksEngine(tmp_path, require_integrity=False)
    assert [p.manifest.id for p in engine.load_all()] == ["syn-rule"]


def test_verify_sig_false_skips_the_integrity_requirement(tmp_path: Path) -> None:
    # ``verify_sig=False`` is an explicit no-verification path (used by tooling/tests), so the
    # content-hash requirement — part of the verified load — does not apply.
    _write(tmp_path, "p.json", _rule_pack(with_hash=False))
    engine = PacksEngine(tmp_path)
    assert [p.manifest.id for p in engine.load_all(verify_sig=False)] == ["syn-rule"]


# --------------------------------------------------------------------------------------
# MEDIUM-1 (fail-closed authenticity): a PRESENT detached signature must be cryptographically
# verified. With no trust root/verifier wired we cannot verify it, so a present-but-unverifiable
# signature is REJECTED — never silently accepted (which would let a FORGED envelope load).
# --------------------------------------------------------------------------------------
def test_present_forged_signature_rejected_without_verifier(tmp_path: Path) -> None:
    pack = _rule_pack(with_hash=True)
    # A structurally-valid but FORGED detached-signature envelope (junk base64, wrong key).
    pack["manifest"]["pack_signature"] = {
        "algorithm": "ed25519",
        "signature": "Zm9yZ2VkLXNpZ25hdHVyZS1ub3QtcmVhbA==",  # "forged-signature-not-real"
        "key_id": "attacker-key",
        "canonical_digest": canonical_digest(pack),  # correct digest can't launder a forged sig
    }
    # Recompute the required content hash AFTER attaching the envelope (canonical_bytes strips
    # volatile integrity fields, so the value is unchanged) — the body hash is intentionally VALID
    # to prove the rejection comes from the unverifiable signature, not a hash mismatch.
    pack["manifest"]["sha256"] = canonical_digest(pack)
    _write(tmp_path, "p.json", pack)
    engine = PacksEngine(tmp_path)  # no signature_verifier — production first-party wiring
    with pytest.raises(PackVerificationError, match="present signature must be verified"):
        engine.load_all()


# --------------------------------------------------------------------------------------
# MEDIUM-2 (whole-manifest coverage): the required hash is over CANONICAL bytes, so tampering with
# a security-sensitive MANIFEST field (e.g. ``targets`` → global) invalidates the hash fail-closed.
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("field", "tampered_value"),
    [
        ("targets", []),        # widen scope from a specific workload to GLOBAL
        ("type", "workload"),   # change the pack kind
        ("id", "evil-rule"),    # change identity
        ("version", "9.9.9"),   # change version identity
    ],
)
def test_manifest_tamper_invalidates_hash(
    tmp_path: Path, field: str, tampered_value: object
) -> None:
    pack = _rule_pack(with_hash=True)  # sha256 == canonical_digest of the pristine pack
    pack["manifest"][field] = tampered_value  # tamper a manifest field WITHOUT re-hashing
    _write(tmp_path, "p.json", pack)
    engine = PacksEngine(tmp_path)
    with pytest.raises(PackVerificationError, match="content hash mismatch"):
        engine.load_all()


# --------------------------------------------------------------------------------------
# Shipped runtime packs all carry the required integrity field and load fail-closed-clean.
# --------------------------------------------------------------------------------------
def test_all_shipped_runtime_packs_carry_content_hash() -> None:
    for subdir in _RUNTIME_SUBDIRS:
        for path in sorted((CONTENT / subdir).glob("*.json")):
            raw = json.loads(path.read_text(encoding="utf-8"))
            manifest = raw.get("manifest", {})
            assert manifest.get("sha256"), f"{path.name}: shipped pack missing sha256 (issue #82)"


def test_shipped_content_loads_under_required_integrity() -> None:
    engine = PacksEngine(CONTENT)  # require_integrity=True, verify_sig=True by default
    types = {p.manifest.type for p in engine.load_all()}
    assert {
        PackType.workload,
        PackType.rule,
        PackType.telemetry,
        PackType.dependency,
        PackType.ops,
    }.issubset(types)


# --------------------------------------------------------------------------------------
# Doc reconciliation: no stale "SHA-256 + HMAC" pack-integrity claim; Ed25519 described.
# --------------------------------------------------------------------------------------
# Matches "SHA-256 + HMAC" tolerant of case, ASCII/non-breaking hyphens, and spacing.
_STALE_CLAIM = re.compile(r"sha[\-\u2011 ]?256\s*\+\s*hmac", re.IGNORECASE)


@pytest.mark.parametrize("doc", ["ARCHITECTURE.md", "SECURITY.md"])
def test_docs_do_not_repeat_stale_pack_integrity_claim(doc: str) -> None:
    text = (_REPO_ROOT / doc).read_text(encoding="utf-8")
    match = _STALE_CLAIM.search(text)
    assert match is None, f"{doc} still asserts the stale '{match.group() if match else ''}' claim"


@pytest.mark.parametrize("doc", ["ARCHITECTURE.md", "SECURITY.md"])
def test_docs_describe_implemented_ed25519_scheme(doc: str) -> None:
    low = (_REPO_ROOT / doc).read_text(encoding="utf-8").lower()
    assert "ed25519" in low, f"{doc} does not describe the implemented Ed25519 signature scheme"
