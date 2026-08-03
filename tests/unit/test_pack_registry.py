"""Unit tests for the pack registry + versioning model (issue #34).

Pure, Azure-free. Covers canonicalization determinism, semver ordering (incl.
prerelease), immutability, idempotent re-publish, corrupt-index fail-closed, and latest().
"""
from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from packs_engine.canonical import (
    EXCLUDED_MANIFEST_FIELDS,
    canonical_bytes,
    canonical_digest,
)
from packs_engine.registry import (
    CorruptRegistryError,
    ImmutableVersionError,
    InvalidVersionError,
    PackRef,
    PackRegistry,
    RegistryEntry,
    RegistryLockError,
    SemVer,
)
from shared.contracts import PackType


def _pack(pack_id: str = "epic-core", version: str = "1.0.0", *, body_x: int = 1) -> dict:
    return {
        "manifest": {
            "id": pack_id,
            "type": "workload",
            "name": "Epic core",
            "version": version,
            "targets": ["epic"],
            "author": "microsoft",
        },
        "body": {"workload": "epic", "x": body_x},
    }


# --------------------------------------------------------------------------------------
# Canonicalization
# --------------------------------------------------------------------------------------
def test_canonical_bytes_independent_of_key_order():
    a = {"manifest": {"id": "p", "type": "rule", "version": "1.0.0"}, "body": {"a": 1, "b": 2}}
    b = {"body": {"b": 2, "a": 1}, "manifest": {"version": "1.0.0", "type": "rule", "id": "p"}}
    assert canonical_bytes(a) == canonical_bytes(b)
    assert canonical_digest(a) == canonical_digest(b)


def test_canonical_bytes_excludes_signing_fields():
    base = _pack()
    signed = _pack()
    signed["manifest"]["sha256"] = "a" * 64
    signed["manifest"]["signature"] = "deadbeef"
    signed["manifest"]["pack_signature"] = {
        "algorithm": "ed25519",
        "signature": "Zm9v",
        "key_id": "ephemeral",
        "canonical_digest": "b" * 64,
    }
    assert set(EXCLUDED_MANIFEST_FIELDS) == {"sha256", "signature", "pack_signature"}
    assert canonical_digest(base) == canonical_digest(signed)


def test_canonical_bytes_changes_with_content():
    assert canonical_digest(_pack(body_x=1)) != canonical_digest(_pack(body_x=2))


def test_canonical_bytes_is_utf8_and_compact():
    raw = canonical_bytes({"manifest": {"name": "café"}})
    assert isinstance(raw, bytes)
    assert raw.decode("utf-8")  # valid utf-8
    assert b", " not in raw and b": " not in raw  # compact separators


def test_canonical_bytes_rejects_non_json_values():
    with pytest.raises(TypeError):
        canonical_bytes({"manifest": {"when": datetime.now(UTC)}})


# --- FIX 1: strict canonicalization (no silent coercion / digest collisions) ----------
def test_canonical_rejects_non_str_mapping_key():
    # An int key must RAISE — never stringify (so {1:..} and {"1":..} cannot collapse).
    with pytest.raises(TypeError):
        canonical_bytes({"body": {1: "x"}})


def test_canonical_int_and_str_keys_do_not_collapse():
    # The int-keyed variant is rejected; the str-keyed variant serializes fine.
    with pytest.raises(TypeError):
        canonical_digest({"body": {1: "x"}})
    assert canonical_digest({"body": {"1": "x"}})  # str key is valid & distinct


def test_canonical_rejects_tuple():
    with pytest.raises(TypeError):
        canonical_bytes({"body": {"vals": (1, 2)}})


def test_canonical_rejects_non_finite_floats():
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError):
            canonical_bytes({"body": {"n": bad}})


def test_canonical_accepts_bool_and_finite_float():
    raw = canonical_bytes({"body": {"flag": True, "ratio": 0.5, "none": None}})
    assert b"true" in raw and b"0.5" in raw and b"null" in raw


def test_canonical_semantic_change_changes_digest():
    base = canonical_digest({"body": {"a": 1, "b": [1, 2]}})
    assert base != canonical_digest({"body": {"a": 1, "b": [1, 3]}})
    assert base != canonical_digest({"body": {"a": 2, "b": [1, 2]}})
    assert base != canonical_digest({"body": {"a": 1, "b": [1, 2], "c": 0}})


# --------------------------------------------------------------------------------------
# SemVer
# --------------------------------------------------------------------------------------
def test_semver_parse_basic():
    v = SemVer.parse("1.2.3")
    assert (v.major, v.minor, v.patch, v.prerelease) == (1, 2, 3, ())


def test_semver_parse_prerelease():
    v = SemVer.parse("1.2.3-alpha.1")
    assert v.prerelease == ("alpha", "1")


def test_semver_invalid_raises():
    for bad in ["1.2", "1.2.3.4", "v1.2.3", "1.2.x", ""]:
        with pytest.raises(InvalidVersionError):
            SemVer.parse(bad)


# --- FIX 2: strict semver parse (no alias bypass of immutability) ----------------------
def test_semver_rejects_surrounding_whitespace():
    for bad in [" 1.0.0", "1.0.0 ", " 1.0.0 ", "1.0.0\n", "1.0.0\t"]:
        with pytest.raises(InvalidVersionError):
            SemVer.parse(bad)


def test_semver_rejects_leading_zero_core():
    for bad in ["01.0.0", "1.02.0", "1.0.03"]:
        with pytest.raises(InvalidVersionError):
            SemVer.parse(bad)


# --- FIX 5: ASCII-only semver (no unicode-digit aliases) -------------------------------
def test_semver_rejects_non_ascii_digits():
    # Arabic-Indic and Devanagari digits must NOT parse to an ASCII-equivalent.
    for bad in ["1\u0662.0.0", "\u0661.0.0", "1.0.\u0969", "1.0.0-\u0662"]:
        with pytest.raises(InvalidVersionError):
            SemVer.parse(bad)


def test_semver_rejects_leading_zero_prerelease():
    with pytest.raises(InvalidVersionError):
        SemVer.parse("1.0.0-01")
    with pytest.raises(InvalidVersionError):
        SemVer.parse("1.0.0-alpha.01")
    # A lone zero identifier is valid semver.
    assert SemVer.parse("1.0.0-0").prerelease == ("0",)


def test_semver_rejects_empty_prerelease_identifier():
    for bad in ["1.0.0-", "1.0.0-a..b", "1.0.0-.a"]:
        with pytest.raises(InvalidVersionError):
            SemVer.parse(bad)


def test_semver_alias_cannot_split_a_ref(tmp_path: Path):
    # A whitespace-padded "alias" can never be published, so it cannot become a second
    # ref holding different content for the same logical version.
    reg = _registry(tmp_path)
    reg.publish(_pack(version="1.0.0", body_x=1))
    with pytest.raises(InvalidVersionError):
        reg.publish(_pack(version=" 1.0.0 ", body_x=2))


def test_semver_prerelease_less_than_release():
    assert SemVer.parse("1.0.0-alpha") < SemVer.parse("1.0.0")
    assert SemVer.parse("1.0.0") > SemVer.parse("1.0.0-rc.1")


def test_semver_prerelease_ordering_spec():
    # From semver.org §11 precedence example.
    order = [
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
    ]
    parsed = [SemVer.parse(s) for s in order]
    assert parsed == sorted(parsed)


def test_semver_numeric_ordering_not_lexical():
    assert SemVer.parse("1.0.0-alpha.2") < SemVer.parse("1.0.0-alpha.11")
    assert SemVer.parse("1.2.0") < SemVer.parse("1.11.0")


# --------------------------------------------------------------------------------------
# PackRef
# --------------------------------------------------------------------------------------
def test_pack_ref_parse_and_format():
    ref = PackRef.parse("epic-core@1.2.3")
    assert ref == PackRef("epic-core", "1.2.3")
    assert ref.format() == "epic-core@1.2.3"
    assert str(ref) == "epic-core@1.2.3"


def test_pack_ref_parse_invalid():
    for bad in ["epic-core", "@1.0.0", "epic-core@", ""]:
        with pytest.raises(ValueError):
            PackRef.parse(bad)


def test_pack_ref_hashable_and_ordered():
    refs = {PackRef("b", "1.0.0"), PackRef("a", "2.0.0"), PackRef("a", "1.0.0")}
    assert len(refs) == 3
    ordered = sorted(refs)
    assert [r.format() for r in ordered] == ["a@1.0.0", "a@2.0.0", "b@1.0.0"]


# --------------------------------------------------------------------------------------
# PackRegistry
# --------------------------------------------------------------------------------------
def _registry(tmp_path: Path) -> PackRegistry:
    return PackRegistry(index_path=tmp_path / "registry" / "index.json")


def test_publish_and_get(tmp_path: Path):
    reg = _registry(tmp_path)
    entry = reg.publish(_pack(version="1.0.0"))
    assert isinstance(entry, RegistryEntry)
    assert entry.ref == PackRef("epic-core", "1.0.0")
    assert entry.type == PackType.workload
    assert reg.get(PackRef("epic-core", "1.0.0")) == entry
    assert reg.get(PackRef("epic-core", "9.9.9")) is None


def test_publish_persists_to_disk(tmp_path: Path):
    path = tmp_path / "registry" / "index.json"
    PackRegistry(index_path=path).publish(_pack())
    assert path.exists()
    # A fresh registry over the same file sees the entry.
    assert PackRegistry(index_path=path).get(PackRef("epic-core", "1.0.0")) is not None


def test_publish_uses_provided_created_at(tmp_path: Path):
    reg = _registry(tmp_path)
    ts = datetime(2026, 1, 1, tzinfo=UTC)
    entry = reg.publish(_pack(), created_at=ts)
    assert entry.createdAt == ts


def test_publish_idempotent_same_digest(tmp_path: Path):
    reg = _registry(tmp_path)
    first = reg.publish(_pack(version="1.0.0", body_x=1))
    # Re-publish identical content, even with signing fields added (excluded from digest).
    again_pack = _pack(version="1.0.0", body_x=1)
    again_pack["manifest"]["signature"] = "sig"
    second = reg.publish(again_pack)
    assert first.digest == second.digest
    assert len(reg.list()) == 1


def test_publish_immutable_version_conflict(tmp_path: Path):
    reg = _registry(tmp_path)
    reg.publish(_pack(version="1.0.0", body_x=1))
    with pytest.raises(ImmutableVersionError):
        reg.publish(_pack(version="1.0.0", body_x=999))


def test_publish_invalid_semver_fails_closed(tmp_path: Path):
    reg = _registry(tmp_path)
    with pytest.raises(InvalidVersionError):
        reg.publish(_pack(version="not-semver"))


def test_list_filters_by_type(tmp_path: Path):
    reg = _registry(tmp_path)
    reg.publish(_pack(pack_id="w1", version="1.0.0"))
    rule = _pack(pack_id="r1", version="1.0.0")
    rule["manifest"]["type"] = "rule"
    reg.publish(rule)
    assert {e.ref.id for e in reg.list()} == {"w1", "r1"}
    assert [e.ref.id for e in reg.list(PackType.rule)] == ["r1"]
    assert [e.ref.id for e in reg.list(PackType.workload)] == ["w1"]


def test_latest_returns_highest_semver(tmp_path: Path):
    reg = _registry(tmp_path)
    for v in ["1.0.0", "1.2.0", "1.11.0", "1.11.1"]:
        reg.publish(_pack(version=v, body_x=hash(v) % 1000))
    latest = reg.latest("epic-core")
    assert latest is not None
    # 1.11.1 beats 1.2.0 numerically (not lexically).
    assert latest.ref.version == "1.11.1"
    # A higher major (even a prerelease of it) becomes the new latest.
    reg.publish(_pack(version="2.0.0-rc.1", body_x=42))
    assert reg.latest("epic-core").ref.version == "2.0.0-rc.1"


def test_latest_prerelease_below_release(tmp_path: Path):
    reg = _registry(tmp_path)
    reg.publish(_pack(version="1.0.0-rc.1", body_x=1))
    reg.publish(_pack(version="1.0.0", body_x=2))
    assert reg.latest("epic-core").ref.version == "1.0.0"


def test_latest_unknown_id(tmp_path: Path):
    reg = _registry(tmp_path)
    assert reg.latest("nope") is None


def test_missing_index_is_empty_not_corrupt(tmp_path: Path):
    reg = _registry(tmp_path)
    assert reg.list() == []
    assert reg.latest("x") is None


def test_corrupt_index_raises(tmp_path: Path):
    path = tmp_path / "registry" / "index.json"
    path.parent.mkdir(parents=True)
    path.write_text("{ this is not json", encoding="utf-8")
    with pytest.raises(CorruptRegistryError):
        PackRegistry(index_path=path).list()


def test_wrong_shape_index_raises(tmp_path: Path):
    path = tmp_path / "registry" / "index.json"
    path.parent.mkdir(parents=True)
    path.write_text('{"version": 1, "entries": {"not": "a list"}}', encoding="utf-8")
    with pytest.raises(CorruptRegistryError):
        PackRegistry(index_path=path).list()


def test_bad_entry_in_index_raises(tmp_path: Path):
    path = tmp_path / "registry" / "index.json"
    path.parent.mkdir(parents=True)
    path.write_text('{"version": 1, "entries": [{"id": "p"}]}', encoding="utf-8")
    with pytest.raises(CorruptRegistryError):
        PackRegistry(index_path=path).list()


# --- FIX 3: strict on-disk index validation (no malformed-as-empty) --------------------
def _valid_entry(**overrides) -> dict:
    entry = {
        "id": "epic-core",
        "version": "1.0.0",
        "type": "workload",
        "digest": "a" * 64,
        "createdAt": "2026-01-01T00:00:00+00:00",
        "signature": None,
    }
    entry.update(overrides)
    return entry


def _write_index(path: Path, doc: object) -> PackRegistry:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")
    return PackRegistry(index_path=path)


def test_index_missing_version_raises(tmp_path: Path):
    path = tmp_path / "registry" / "index.json"
    reg = _write_index(path, {"entries": []})
    with pytest.raises(CorruptRegistryError):
        reg.list()


def test_index_wrong_version_raises(tmp_path: Path):
    path = tmp_path / "registry" / "index.json"
    reg = _write_index(path, {"version": 999, "entries": []})
    with pytest.raises(CorruptRegistryError):
        reg.list()


# --- FIX 6: schema version must be a real int (not bool/float/str) ----------------------
def test_index_non_int_version_raises(tmp_path: Path):
    for bad_version in (True, 1.0, "1"):
        path = tmp_path / "registry" / "index.json"
        reg = _write_index(path, {"version": bad_version, "entries": []})
        with pytest.raises(CorruptRegistryError):
            reg.list()


def test_index_entry_bad_digest_raises(tmp_path: Path):
    path = tmp_path / "registry" / "index.json"
    reg = _write_index(path, {"version": 1, "entries": [_valid_entry(digest="nothex")]})
    with pytest.raises(CorruptRegistryError):
        reg.list()


def test_index_entry_bad_semver_raises(tmp_path: Path):
    path = tmp_path / "registry" / "index.json"
    reg = _write_index(path, {"version": 1, "entries": [_valid_entry(version="1.0")]})
    with pytest.raises(CorruptRegistryError):
        reg.list()


def test_index_entry_bad_type_raises(tmp_path: Path):
    path = tmp_path / "registry" / "index.json"
    reg = _write_index(path, {"version": 1, "entries": [_valid_entry(type="bogus")]})
    with pytest.raises(CorruptRegistryError):
        reg.list()


def test_index_entry_bad_timestamp_raises(tmp_path: Path):
    path = tmp_path / "registry" / "index.json"
    reg = _write_index(path, {"version": 1, "entries": [_valid_entry(createdAt="not-a-date")]})
    with pytest.raises(CorruptRegistryError):
        reg.list()


def test_index_duplicate_refs_raises(tmp_path: Path):
    path = tmp_path / "registry" / "index.json"
    reg = _write_index(path, {"version": 1, "entries": [_valid_entry(), _valid_entry()]})
    with pytest.raises(CorruptRegistryError):
        reg.list()


def test_index_valid_entry_loads(tmp_path: Path):
    path = tmp_path / "registry" / "index.json"
    reg = _write_index(path, {"version": 1, "entries": [_valid_entry()]})
    entries = reg.list()
    assert len(entries) == 1
    assert entries[0].ref == PackRef("epic-core", "1.0.0")


# --- FIX 4: locked publish (race-safe read-check-write) --------------------------------
def test_publish_releases_lock(tmp_path: Path):
    reg = _registry(tmp_path)
    reg.publish(_pack())
    lock = reg.index_path.with_name(reg.index_path.name + ".lock")
    assert not lock.exists()  # lock released after publish


def test_publish_reloads_under_lock_across_instances(tmp_path: Path):
    # Two separate registry objects over the same file. The second must see the first's
    # entry (reload-under-lock) and reject a conflicting republish of the same ref.
    path = tmp_path / "registry" / "index.json"
    PackRegistry(index_path=path).publish(_pack(version="1.0.0", body_x=1))
    with pytest.raises(ImmutableVersionError):
        PackRegistry(index_path=path).publish(_pack(version="1.0.0", body_x=2))


def test_publish_times_out_when_lock_held(tmp_path: Path):
    path = tmp_path / "registry" / "index.json"
    path.parent.mkdir(parents=True)
    lock = path.with_name(path.name + ".lock")
    fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    try:
        reg = PackRegistry(index_path=path, lock_timeout=0.2, lock_poll=0.02)
        with pytest.raises(RegistryLockError):
            reg.publish(_pack())
    finally:
        os.close(fd)
        os.unlink(str(lock))


def test_publish_unique_tempfile_leaves_no_residue(tmp_path: Path):
    reg = _registry(tmp_path)
    reg.publish(_pack(version="1.0.0"))
    reg.publish(_pack(version="1.1.0"))
    residue = list(reg.index_path.parent.glob("*.tmp"))
    assert residue == []  # unique temp files are atomically replaced away


def test_seed_index_is_valid_empty_registry():
    seed = Path(__file__).resolve().parents[2] / "content" / "registry" / "index.json"
    assert seed.exists()
    reg = PackRegistry(index_path=seed)
    assert reg.list() == []
