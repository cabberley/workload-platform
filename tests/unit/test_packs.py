"""Packs engine — loads the shipped example packs and fails closed on a bad signature."""
from pathlib import Path

import pytest

from packs_engine.engine import PacksEngine, PackVerificationError, compute_sha256, sign, verify
from shared.contracts import PackManifest, PackType

CONTENT = Path(__file__).resolve().parents[2] / "content"


def test_loads_all_example_packs_unsigned():
    engine = PacksEngine(CONTENT)
    packs = engine.load_all(verify_sig=False)
    types = {p.manifest.type for p in packs}
    assert {
        PackType.workload,
        PackType.rule,
        PackType.telemetry,
        PackType.dependency,
        PackType.ops,
    }.issubset(types)


def test_load_for_workload_filters_targets():
    engine = PacksEngine(CONTENT)
    epic_rules = engine.load_for_workload("epic", PackType.dependency)
    assert any(p.manifest.id == "epic-core-deps" for p in epic_rules)


def test_signature_verify_roundtrip_and_fail_closed():
    secret = b"unit-test-secret"
    content = b'{"body":{"x":1}}'
    digest = compute_sha256(content)
    good = PackManifest(id="p", type=PackType.rule, name="p", version="1.0.0",
                        sha256=digest, signature=sign(digest, secret))
    verify(good, content, secret)  # should not raise

    bad = good.model_copy(update={"signature": "deadbeef"})
    with pytest.raises(PackVerificationError):
        verify(bad, content, secret)
