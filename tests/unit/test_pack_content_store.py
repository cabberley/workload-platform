"""Unit tests for the digest-addressed pack content store (issue #44).

Pure, Azure-free. Covers the local backend round-trip, digest validation (fail closed), the
backend selector (unknown backend fails closed), and the Azure backend's import-guard invariant:
importing the module and deriving a local path/blob name must work with NO azure packages
installed (the azure SDK import is deferred inside the methods).
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from packs_engine.content_store import (
    AzurePackContentStore,
    LocalPackContentStore,
    PackContentStore,
    PackContentStoreError,
    build_pack_content_store,
)

_DIGEST = hashlib.sha256(b"a pack").hexdigest()
_OTHER = hashlib.sha256(b"another pack").hexdigest()


def test_local_store_put_get_has_roundtrip(tmp_path: Path) -> None:
    store = LocalPackContentStore(tmp_path / "store")
    assert store.has(_DIGEST) is False
    assert store.get(_DIGEST) is None

    store.put(_DIGEST, b"verified-bytes")
    assert store.has(_DIGEST) is True
    assert store.get(_DIGEST) == b"verified-bytes"
    # A different digest is independent (content-addressed namespace).
    assert store.has(_OTHER) is False


def test_local_store_put_is_idempotent(tmp_path: Path) -> None:
    store = LocalPackContentStore(tmp_path / "store")
    store.put(_DIGEST, b"bytes")
    store.put(_DIGEST, b"bytes")  # re-put identical content-addressed bytes
    assert store.get(_DIGEST) == b"bytes"


def test_local_store_satisfies_protocol(tmp_path: Path) -> None:
    store: PackContentStore = LocalPackContentStore(tmp_path)
    assert isinstance(store, PackContentStore)


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "not-hex",
        "abc",  # too short
        _DIGEST.upper(),  # uppercase is rejected (registry digests are lowercase)
        _DIGEST + "0",  # too long
        "../" + _DIGEST,  # path-escape attempt
    ],
)
def test_local_store_rejects_non_sha256_digest(tmp_path: Path, bad: str) -> None:
    store = LocalPackContentStore(tmp_path)
    # Fail closed on any address that is not a lowercase sha256 hex — never touch the filesystem
    # outside the content-addressed namespace.
    with pytest.raises(PackContentStoreError):
        store.get(bad)
    with pytest.raises(PackContentStoreError):
        store.put(bad, b"x")
    with pytest.raises(PackContentStoreError):
        store.has(bad)


def test_build_selector_defaults_to_local(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("WORKLOADS_PACK_STORE_BACKEND", raising=False)
    monkeypatch.setenv("WORKLOADS_PACK_STORE_DIR", str(tmp_path / "store"))
    store = build_pack_content_store()
    assert isinstance(store, LocalPackContentStore)


def test_build_selector_local_explicit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("WORKLOADS_PACK_STORE_BACKEND", "local")
    monkeypatch.setenv("WORKLOADS_PACK_STORE_DIR", str(tmp_path / "store"))
    assert isinstance(build_pack_content_store(), LocalPackContentStore)


def test_build_selector_unknown_backend_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WORKLOADS_PACK_STORE_BACKEND", "s3")
    with pytest.raises(ValueError, match="Unknown WORKLOADS_PACK_STORE_BACKEND"):
        build_pack_content_store()


def test_azure_backend_import_guard_defers_sdk_import() -> None:
    """The module imports and the Azure blob name derives with NO azure SDK installed.

    Constructing ``AzurePackContentStore`` with a fake container and deriving a blob name must not
    require any ``azure.*`` package — the SDK import is deferred inside the methods.
    """

    class _FakeContainer:
        def __init__(self) -> None:
            self.blobs: dict[str, bytes] = {}

        def upload_blob(self, name: str, data: bytes, *, overwrite: bool = False) -> None:
            self.blobs[name] = data

    store = AzurePackContentStore(container=_FakeContainer())  # type: ignore[arg-type]
    # ``_blob_name`` derives the content address purely (no azure import), and validates the digest.
    assert AzurePackContentStore._blob_name(_DIGEST) == f"{_DIGEST}.pack"
    with pytest.raises(PackContentStoreError):
        AzurePackContentStore._blob_name("not-a-digest")
    # ``put`` goes straight to the (fake) container client — no azure import on the write path.
    store.put(_DIGEST, b"bytes")
