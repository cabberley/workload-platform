"""Digest-addressed content store for verified imported pack bytes (issue #44).

The pack **registry** (:mod:`packs_engine.registry`) is a metadata-only, content-addressed
*index*: it records ``{id, version, digest, signature}`` per published version but NEVER stores the
pack bytes. A pack that is imported (signature-verified) but was never shipped inside the
content-root image therefore has no bytes to load at runtime — it is unresolvable.

This module fills that gap with a **content-addressed content store** whose sole address is the
pack's registry ``digest`` (the SHA-256 over :func:`packs_engine.canonical.canonical_bytes`). The
verified canonical bytes are persisted on import (the single writer) and re-loaded at runtime BY
digest, where the engine re-verifies ``canonical_digest(loaded) == registry.digest`` before the
pack is allowed to execute. A missing digest or a mismatch fails closed — the pack resolves to
nothing and is never executed.

It deliberately MIRRORS the shape of :mod:`shared.state`:

* :class:`PackContentStore` — a minimal, ``runtime_checkable`` ``Protocol`` (``put``/``get``/
  ``has``), content-addressed by digest.
* :class:`LocalPackContentStore` — filesystem-backed, digest-addressed, deterministic, Azure-free.
  Used in dev/CI. Store dir is configurable via ``WORKLOADS_PACK_STORE_DIR`` (default under the OS
  temp dir), exactly like ``LocalStateStore``.
* :class:`AzurePackContentStore` — Azure Blob Storage, keyless via Managed Identity
  (``DefaultAzureCredential``); the blob name is derived from the digest. Every ``azure`` SDK import
  is guarded inside a method (or :data:`typing.TYPE_CHECKING`), so importing this module never
  requires azure packages and ``mypy src`` passes with no azure SDK installed — mirroring
  ``AzureStateStore``.
* :func:`build_pack_content_store` — selects a backend from ``WORKLOADS_PACK_STORE_BACKEND``
  (``local`` (default) | ``azure``). Any other value fails closed (raises).

See ADR ``docs/adr/0008-pack-content-store-backend.md`` for the Azure Blob decision and rejected
alternatives (Azure Files, Table Storage's 64KB/property cap).
"""
from __future__ import annotations

import contextlib
import os
import re
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable
from uuid import uuid4

if TYPE_CHECKING:  # pragma: no cover - typing-only imports, never needed at runtime
    from azure.storage.blob import ContainerClient

__all__ = [
    "AzurePackContentStore",
    "LocalPackContentStore",
    "PackContentStore",
    "PackContentStoreError",
    "build_pack_content_store",
]

_ENV_BACKEND = "WORKLOADS_PACK_STORE_BACKEND"
_ENV_STORE_DIR = "WORKLOADS_PACK_STORE_DIR"
_ENV_BLOB_ENDPOINT = "WORKLOADS_PACK_STORE_BLOB_ENDPOINT"
_ENV_CONTAINER = "WORKLOADS_PACK_STORE_CONTAINER"
_DEFAULT_DIR_NAME = "workloads-platform-packs"
_DEFAULT_CONTAINER = "packs"

# A content-address digest is a lowercase hex SHA-256 (64 hex chars), matching the registry.
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


class PackContentStoreError(RuntimeError):
    """Raised on an invalid content-address digest or a store misconfiguration. Fail closed."""


def _require_digest(digest: str) -> str:
    """Return ``digest`` iff it is a lowercase sha256 hex; otherwise raise. Fail closed.

    The digest is the ONLY address into the store, and it is also used to derive a filesystem
    path / blob name. Validating it up front keeps the address free of path separators, ``..`` and
    any character that could escape the store dir or the container — a malformed digest can never
    read or write outside the content-addressed namespace.
    """
    if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
        raise PackContentStoreError(f"Not a lowercase sha256 hex digest: {digest!r}")
    return digest


# --------------------------------------------------------------------------------------
# Protocol — the typed surface. Content-addressed by digest; minimal by design.
# --------------------------------------------------------------------------------------
@runtime_checkable
class PackContentStore(Protocol):
    """Content-addressed store of verified pack bytes, keyed by the registry ``digest``."""

    def put(self, digest: str, data: bytes) -> None:
        """Persist ``data`` under ``digest`` (single-writer, import-only). Idempotent."""
        ...

    def get(self, digest: str) -> bytes | None:
        """Return the bytes stored under ``digest``, or ``None`` if absent (fail closed)."""
        ...

    def has(self, digest: str) -> bool:
        """Return whether bytes are stored under ``digest``."""
        ...


# --------------------------------------------------------------------------------------
# Local backend — filesystem, digest-addressed. Deterministic, Azure-free, dev/CI.
# --------------------------------------------------------------------------------------
def _default_store_dir() -> Path:
    return Path(tempfile.gettempdir()) / _DEFAULT_DIR_NAME


class LocalPackContentStore:
    """Local, deterministic ``PackContentStore`` storing each pack at ``<dir>/<digest>.pack``."""

    def __init__(self, store_dir: str | Path | None = None) -> None:
        base = Path(store_dir) if store_dir else _default_store_dir()
        base.mkdir(parents=True, exist_ok=True)
        self._dir = base

    def _path(self, digest: str) -> Path:
        return self._dir / f"{_require_digest(digest)}.pack"

    def put(self, digest: str, data: bytes) -> None:
        path = self._path(digest)
        # Atomic publish via a per-writer unique temp file + os.replace, so a concurrent reader
        # never observes a half-written pack (mirrors PackRegistry._save / AzureStateStore).
        tmp = path.with_name(f"{path.name}.{os.getpid()}.{uuid4().hex}.tmp")
        tmp.write_bytes(data)
        os.replace(str(tmp), str(path))

    def get(self, digest: str) -> bytes | None:
        try:
            return self._path(digest).read_bytes()
        except FileNotFoundError:
            return None

    def has(self, digest: str) -> bool:
        return self._path(digest).exists()


# --------------------------------------------------------------------------------------
# Azure backend — Azure Blob Storage, keyless via Managed Identity. Guarded SDK imports.
# --------------------------------------------------------------------------------------
class AzurePackContentStore:
    """Azure Blob ``PackContentStore``: blob name = ``<digest>.pack``; keyless MI.

    Content-addressed: because the blob name is the SHA-256 digest, re-``put`` of the same digest
    always carries identical bytes, so ``overwrite=True`` is idempotent. All ``azure`` imports are
    deferred into methods (or :data:`typing.TYPE_CHECKING`) so importing this module never requires
    the azure SDK — exactly like :class:`shared.state.AzureStateStore`.
    """

    def __init__(self, *, container: ContainerClient) -> None:
        self._container = container

    @classmethod
    def from_env(cls) -> AzurePackContentStore:
        """Construct a container client from env using ``DefaultAzureCredential`` (keyless).

        Required env: ``WORKLOADS_PACK_STORE_BLOB_ENDPOINT``. Optional:
        ``WORKLOADS_PACK_STORE_CONTAINER`` (default ``packs``). No secrets — Managed Identity only.

        The azure SDKs are optional (see the ``azure`` extra in ``pyproject.toml``). If they are not
        installed we fail closed with an actionable message rather than a bare ``ImportError``.
        """
        try:
            from azure.core.exceptions import ResourceExistsError
            from azure.identity import DefaultAzureCredential
            from azure.storage.blob import BlobServiceClient
        except ImportError as exc:
            raise RuntimeError(
                "The 'azure' pack content store needs optional dependencies that are not "
                "installed. Install them with:  pip install .[azure]"
            ) from exc

        credential = DefaultAzureCredential()
        blob_endpoint = os.environ[_ENV_BLOB_ENDPOINT]
        container_name = os.environ.get(_ENV_CONTAINER, _DEFAULT_CONTAINER)

        blob_service = BlobServiceClient(account_url=blob_endpoint, credential=credential)
        container = blob_service.get_container_client(container_name)
        with contextlib.suppress(ResourceExistsError):
            container.create_container()
        return cls(container=container)

    @staticmethod
    def _blob_name(digest: str) -> str:
        return f"{_require_digest(digest)}.pack"

    def put(self, digest: str, data: bytes) -> None:
        self._container.upload_blob(self._blob_name(digest), data, overwrite=True)

    def get(self, digest: str) -> bytes | None:
        from azure.core.exceptions import ResourceNotFoundError

        try:
            downloader = self._container.download_blob(self._blob_name(digest))
        except ResourceNotFoundError:
            return None
        return bytes(downloader.readall())

    def has(self, digest: str) -> bool:
        from azure.core.exceptions import ResourceNotFoundError

        blob = self._container.get_blob_client(self._blob_name(digest))
        try:
            blob.get_blob_properties()
        except ResourceNotFoundError:
            return False
        return True


# --------------------------------------------------------------------------------------
# Factory.
# --------------------------------------------------------------------------------------
def build_pack_content_store() -> PackContentStore:
    """Select and construct the ``PackContentStore`` from config.

    ``WORKLOADS_PACK_STORE_BACKEND`` = ``local`` (default) | ``azure``. Any other value fails
    closed (raises), mirroring :func:`shared.state.build_state_store`.
    """
    backend = os.environ.get(_ENV_BACKEND, "local").strip().lower()
    if backend == "local":
        return LocalPackContentStore(os.environ.get(_ENV_STORE_DIR))
    if backend == "azure":
        return AzurePackContentStore.from_env()
    raise ValueError(f"Unknown {_ENV_BACKEND}={backend!r}; expected 'local' or 'azure'")
