"""Pack registry + versioning model (issue #34).

An **immutable, content-addressed index** of published pack versions, so a specific
version can be pinned per workload. Design principles (see ``.github/copilot-instructions``):

- **Immutable versions.** Re-publishing the same ``id@version`` with *different* content
  (a differing :func:`~packs_engine.canonical.canonical_digest`) is rejected. Publishing
  identical content again is idempotent.
- **Fail closed.** A corrupt/unparseable on-disk index raises a typed error rather than
  silently resetting to empty — we never lose the immutability record.
- **Pure ⟂ I/O.** Semver, :class:`PackRef`, and digest comparison are pure; the only I/O
  is reading/writing the JSON index file (path injected).

## Version identity vs. body integrity

The registry's ``digest`` is the pack's **version identity** — a SHA-256 over the whole
pack (manifest + body) *excluding* volatile integrity fields — computed by
:mod:`packs_engine.canonical`. This is intentionally separate from the engine's
body-only ``sha256`` integrity/trust hash. See :mod:`packs_engine.canonical`.

## On-disk index shape (``content/registry/index.json``)

```json
{
  "version": 2,
  "entries": [
    {
      "id": "epic-core",
      "version": "1.0.0",
      "type": "workload",
      "digest": "<sha256-hex>",
      "createdAt": "2026-01-01T00:00:00+00:00",
      "signature": "<compact-json serialized PackSignature, or null>",
      "keyId": "<signing key id, or null>"
    }
  ]
}
```

``signature`` is the deterministically-serialized detached
:class:`~shared.contracts.PackSignature` that was verified against the pinned trust bundle at
admission (issue #89, R2), and ``keyId`` selects the pinned public key at runtime. A ``null``
``signature``/``keyId`` (or a v1 index) is a legacy-untrusted entry the runtime resolver fails
closed.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import time
import uuid
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from pydantic import ValidationError

from packs_engine.canonical import canonical_digest
from shared.contracts import PackSignature, PackType

if TYPE_CHECKING:  # pragma: no cover - typing-only import; avoids a runtime import cycle
    from shared.contracts import ImportedPack

DEFAULT_INDEX_PATH = Path("content/registry/index.json")
# Bumped 1 -> 2 for issue #89 (R2): a v2 entry additionally persists the detached Ed25519 pack
# signature + its ``key_id`` so the runtime resolver can INDEPENDENTLY re-verify the signature
# against the pinned trust bundle (digest match alone is integrity, not trust). A v1 (pre-#89)
# index is still parseable for backward compatibility, but every v1 entry is flagged
# legacy-untrusted (no verifiable detached signature) so the runtime fails it closed.
INDEX_SCHEMA_VERSION = 2
# Index schema versions this build can parse. Only the current version writes a trustworthy
# detached signature; older versions parse but resolve fail-closed (legacy-untrusted).
SUPPORTED_INDEX_VERSIONS: frozenset[int] = frozenset({1, 2})

# A registry digest is a lowercase hex SHA-256 (64 hex chars).
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


class RegistryError(RuntimeError):
    """Base class for registry failures."""


class ImmutableVersionError(RegistryError):
    """Raised when re-publishing an existing ``id@version`` with a different digest."""


class CorruptRegistryError(RegistryError):
    """Raised when the on-disk index is present but unparseable/invalid. Fail closed."""


class InvalidVersionError(RegistryError):
    """Raised when a version string is not valid semver."""


class RegistryLockError(RegistryError):
    """Raised when the inter-process registry write lock cannot be acquired in time."""


# --------------------------------------------------------------------------------------
# Semver — pure parse + compare (major.minor.patch with optional prerelease).
# --------------------------------------------------------------------------------------
_SEMVER_RE = re.compile(
    r"^(?P<major>0|[1-9][0-9]*)"
    r"\.(?P<minor>0|[1-9][0-9]*)"
    r"\.(?P<patch>0|[1-9][0-9]*)"
    r"(?:-(?P<prerelease>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$",
    re.ASCII,
)


@dataclass(frozen=True, order=False)
class SemVer:
    """A parsed semantic version. Prerelease sorts *before* the matching release."""

    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()

    @classmethod
    def parse(cls, text: str) -> SemVer:
        if not isinstance(text, str):
            raise InvalidVersionError(f"Version must be a string, got {type(text).__name__!r}")
        # Exact match — NO trimming, so whitespace-padded aliases (" 1.0.0 ") are rejected
        # and cannot become a separate ref holding different content.
        m = _SEMVER_RE.fullmatch(text)
        if m is None:
            raise InvalidVersionError(f"Not a valid semver: {text!r}")
        pre_raw = m.group("prerelease")
        prerelease = tuple(pre_raw.split(".")) if pre_raw else ()
        for ident in prerelease:
            if ident.isdigit() and len(ident) > 1 and ident[0] == "0":
                raise InvalidVersionError(
                    f"Leading zero in numeric prerelease identifier: {ident!r} in {text!r}"
                )
        return cls(
            major=int(m.group("major")),
            minor=int(m.group("minor")),
            patch=int(m.group("patch")),
            prerelease=prerelease,
        )

    @staticmethod
    def _identifier_key(identifier: str) -> tuple[int, int, str]:
        """Order key for a prerelease identifier: numeric < alphanumeric (semver §11)."""
        if identifier.isdigit():
            return (0, int(identifier), "")
        return (1, 0, identifier)

    @property
    def _sort_key(self) -> tuple[Any, ...]:
        # A version with NO prerelease outranks one that has a prerelease, so map
        # "has prerelease" -> 0 and "no prerelease" -> 1.
        has_no_prerelease = 0 if self.prerelease else 1
        pre_key = tuple(self._identifier_key(i) for i in self.prerelease)
        return (self.major, self.minor, self.patch, has_no_prerelease, pre_key)

    def __lt__(self, other: SemVer) -> bool:
        if not isinstance(other, SemVer):
            return NotImplemented
        return self._sort_key < other._sort_key

    def __le__(self, other: SemVer) -> bool:
        if not isinstance(other, SemVer):
            return NotImplemented
        return self._sort_key <= other._sort_key

    def __gt__(self, other: SemVer) -> bool:
        if not isinstance(other, SemVer):
            return NotImplemented
        return self._sort_key > other._sort_key

    def __ge__(self, other: SemVer) -> bool:
        if not isinstance(other, SemVer):
            return NotImplemented
        return self._sort_key >= other._sort_key


# --------------------------------------------------------------------------------------
# PackRef — a pinnable ``id@version`` reference.
# --------------------------------------------------------------------------------------
@dataclass(frozen=True, order=False)
class PackRef:
    """A reference to a specific pack version. Hashable; ordered by (id, semver)."""

    id: str
    version: str

    @property
    def semver(self) -> SemVer:
        return SemVer.parse(self.version)

    @classmethod
    def parse(cls, text: str) -> PackRef:
        pack_id, sep, version = text.partition("@")
        if not sep or not pack_id or not version:
            raise ValueError(f"Not a valid pack ref (expected 'id@version'): {text!r}")
        return cls(id=pack_id, version=version)

    def format(self) -> str:
        return f"{self.id}@{self.version}"

    def __str__(self) -> str:
        return self.format()

    def _order_key(self) -> tuple[str, SemVer]:
        return (self.id, self.semver)

    def __lt__(self, other: PackRef) -> bool:
        if not isinstance(other, PackRef):
            return NotImplemented
        return self._order_key() < other._order_key()

    def __le__(self, other: PackRef) -> bool:
        if not isinstance(other, PackRef):
            return NotImplemented
        return self._order_key() <= other._order_key()

    def __gt__(self, other: PackRef) -> bool:
        if not isinstance(other, PackRef):
            return NotImplemented
        return self._order_key() > other._order_key()

    def __ge__(self, other: PackRef) -> bool:
        if not isinstance(other, PackRef):
            return NotImplemented
        return self._order_key() >= other._order_key()


# --------------------------------------------------------------------------------------
# RegistryEntry — one immutable published version.
# --------------------------------------------------------------------------------------
@dataclass(frozen=True)
class RegistryEntry:
    """A single published, content-addressed pack version.

    ``signature`` holds the deterministically-serialized detached :class:`PackSignature` that was
    verified against the pinned trust bundle at admission (issue #89, R2); ``key_id`` names the
    signing key so the runtime can select the pinned PUBLIC key and INDEPENDENTLY re-verify the
    signature. A ``None`` ``signature``/``key_id`` marks a legacy-untrusted entry (a v1 index, or a
    pre-#89/hand-crafted entry) which the runtime resolver fails closed.
    """

    ref: PackRef
    type: PackType
    digest: str
    createdAt: datetime
    signature: str | None = None
    key_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.ref.id,
            "version": self.ref.version,
            "type": self.type.value,
            "digest": self.digest,
            "createdAt": self.createdAt.isoformat(),
            "signature": self.signature,
            "keyId": self.key_id,
        }

    def detached_signature(self) -> PackSignature | None:
        """Reconstruct the persisted detached :class:`PackSignature`, or ``None`` if untrusted.

        Fail-closed: returns ``None`` (so the runtime resolver SKIPS the entry) when the entry
        carries no persisted detached signature or ``key_id`` (a legacy/pre-#89 or hand-crafted
        entry), or when the stored ``signature`` string is not a well-formed serialized
        :class:`PackSignature`. A returned envelope is re-verified against the pinned trust bundle
        by the caller — reconstruction here is NOT itself a trust decision.
        """
        if self.signature is None or self.key_id is None:
            return None
        try:
            data = json.loads(self.signature)
        except (json.JSONDecodeError, ValueError, TypeError):
            return None
        if not isinstance(data, dict):
            return None
        try:
            return PackSignature(**data)
        except (ValidationError, TypeError):
            return None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RegistryEntry:
        try:
            pack_id = data["id"]
            version = data["version"]
            if not isinstance(pack_id, str) or not isinstance(version, str):
                raise ValueError("entry 'id' and 'version' must be strings")
            SemVer.parse(version)  # strict semver; raises InvalidVersionError if malformed
            digest = data["digest"]
            if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
                raise ValueError(f"entry 'digest' is not a lowercase sha256 hex: {digest!r}")
            pack_type = PackType(data["type"])
            created_raw = data["createdAt"]
            if not isinstance(created_raw, str):
                raise ValueError("entry 'createdAt' must be an ISO-8601 string")
            created = datetime.fromisoformat(created_raw)
            signature = data.get("signature")
            if signature is not None and not isinstance(signature, str):
                raise ValueError("entry 'signature' must be a string or null")
            key_id = data.get("keyId")
            if key_id is not None and not isinstance(key_id, str):
                raise ValueError("entry 'keyId' must be a string or null")
            return cls(
                ref=PackRef(id=pack_id, version=version),
                type=pack_type,
                digest=digest,
                createdAt=created,
                signature=signature,
                key_id=key_id,
            )
        except (KeyError, ValueError, TypeError, InvalidVersionError) as exc:
            raise CorruptRegistryError(f"Invalid registry entry: {data!r} ({exc})") from exc


def _serialize_pack_signature(signature: PackSignature) -> str:
    """Serialize a :class:`PackSignature` deterministically for on-disk persistence.

    Compact, key-sorted JSON so an identical signature always serializes to identical bytes (stable
    diffs, and a byte-for-byte idempotent re-publish of the same content+signature).
    """
    return json.dumps(signature.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def serialize_pack_signature(signature: PackSignature) -> str:
    """Public deterministic serializer for a detached :class:`PackSignature` (issue #68).

    The per-tenant import path (``api.app.main.import_pack``) persists the verified detached
    signature on its tenant-scoped :class:`~shared.contracts.ImportedPack` record using the SAME
    deterministic serialization the on-disk registry uses, so the runtime resolver reconstructs and
    re-verifies the identical envelope (via :meth:`RegistryEntry.detached_signature`).
    """
    return _serialize_pack_signature(signature)


def _normalize_publish_signature(
    signature: PackSignature | str | None,
) -> tuple[str | None, str | None]:
    """Return the ``(serialized detached signature, key_id)`` to persist on a registry entry.

    ``None`` -> a legacy/untrusted entry (both fields ``None``): the runtime resolver fails such an
    entry closed because it carries no verifiable detached signature. A :class:`PackSignature` (or
    its already-serialized compact JSON) is stored deterministically together with its ``key_id`` so
    the runtime can select the pinned public key and re-verify the signature against the trust root.
    """
    if signature is None:
        return None, None
    if isinstance(signature, str):
        try:
            sig = PackSignature(**json.loads(signature))
        except (json.JSONDecodeError, ValueError, TypeError, ValidationError) as exc:
            raise ValueError(
                f"publish: signature string is not a serialized PackSignature ({exc})"
            ) from exc
    else:
        sig = signature
    return _serialize_pack_signature(sig), sig.key_id


def parse_registry_index(
    raw: object, *, source: str = "registry index"
) -> dict[PackRef, RegistryEntry]:
    """Validate a JSON-parsed registry index and return its entries keyed by ref. Fail closed.

    Single source of truth for what a *valid* pack registry index is: object shape, ``int`` schema
    ``version`` in :data:`SUPPORTED_INDEX_VERSIONS`, a list of well-formed entries, and no duplicate
    ``id@version`` ref. Reused by :meth:`PackRegistry._load` AND the pack-validate CI gate
    (``scripts/validate_packs.py``) so the two can never diverge on what counts as a valid index.
    Raises :class:`CorruptRegistryError` on any violation.

    Backward compatibility (issue #89, R2): a pre-#89 v1 index still parses, but every v1 entry is
    flagged legacy-untrusted — its ``signature``/``key_id`` are cleared to ``None`` (a v1
    ``signature`` is the legacy HMAC, never a trust-bundle-verifiable detached signature) so the
    runtime resolver fails it closed rather than mistaking legacy data for a verified import.
    """
    if not isinstance(raw, dict):
        raise CorruptRegistryError(f"{source} is not a JSON object")
    version = raw.get("version")
    if type(version) is not int or version not in SUPPORTED_INDEX_VERSIONS:
        raise CorruptRegistryError(
            f"{source} has missing/unsupported schema version {version!r} "
            f"(expected int in {sorted(SUPPORTED_INDEX_VERSIONS)})"
        )
    if not isinstance(raw.get("entries"), list):
        raise CorruptRegistryError(f"{source} has a non-list 'entries'")
    is_legacy_index = version < INDEX_SCHEMA_VERSION
    entries: dict[PackRef, RegistryEntry] = {}
    for item in raw["entries"]:
        if not isinstance(item, dict):
            raise CorruptRegistryError(f"Registry entry is not an object: {item!r}")
        entry = RegistryEntry.from_dict(item)
        if is_legacy_index:
            # A v1 (pre-#89) index predates persisted detached signatures: strip any recorded
            # signature/key_id so the entry is treated as legacy-untrusted and fails closed at
            # runtime resolution (never activated on a digest match alone).
            entry = replace(entry, signature=None, key_id=None)
        if entry.ref in entries:
            raise CorruptRegistryError(f"Duplicate registry entry for {entry.ref}")
        entries[entry.ref] = entry
    return entries


# --------------------------------------------------------------------------------------
# PackRegistryReader — the READ surface consumers (engine resolver, per-workload pinning) need.
# --------------------------------------------------------------------------------------
@runtime_checkable
class PackRegistryReader(Protocol):
    """The minimal, read-only registry surface the runtime resolver + pinning depend on (#68).

    Both the on-disk :class:`PackRegistry` and the in-memory :class:`InMemoryPackRegistry` satisfy
    it, so the engine can be handed a PER-TENANT view of imported packs (issue #68) without knowing
    which concrete registry backs it — the tenant's imports are resolved exactly like the shared
    on-disk index, keeping cross-tenant isolation at the registry boundary.
    """

    def get(self, ref: PackRef) -> RegistryEntry | None:
        """Return the entry for an exact ``id@version`` ref, or ``None``."""
        ...

    def list(self, pack_type: PackType | None = None) -> list[RegistryEntry]:
        """List entries (optionally filtered by type), ordered by (id, semver)."""
        ...

    def latest(self, pack_id: str) -> RegistryEntry | None:
        """Return the highest-semver entry for ``pack_id``, or ``None`` if unknown."""
        ...


def imported_pack_to_entry(pack: ImportedPack) -> RegistryEntry:
    """Project a persisted per-tenant :class:`~shared.contracts.ImportedPack` into a RegistryEntry.

    The tenant-scoped imported-pack record carries the SAME verified identity the on-disk registry
    would (``id``/``version``/``type``/``digest`` + the serialized detached signature and its
    ``key_id``), so the runtime resolver re-verifies it against the pinned trust bundle exactly like
    a shared-registry entry — trust is never inherited from the fact that it was imported.
    """
    return RegistryEntry(
        ref=PackRef(id=pack.packId, version=pack.version),
        type=pack.packType,
        digest=pack.digest,
        createdAt=pack.importedAt,
        signature=pack.signature,
        key_id=pack.keyId,
    )


@dataclass
class InMemoryPackRegistry:
    """An in-memory, read-only :class:`PackRegistryReader` over a fixed set of entries (issue #68).

    Used to hand the engine a PER-TENANT registry of the caller tenant's imported packs (and, where
    a caller needs it, the shared built-in entries merged in) WITHOUT persisting anything or
    touching the shared on-disk index. It is deliberately read-only: imports are recorded in the
    tenant-scoped state store (the single writer), and this view is rebuilt per request from that
    state, so it can never leak one tenant's imports into another's resolution.
    """

    entries: dict[PackRef, RegistryEntry] = field(default_factory=dict)

    @classmethod
    def from_entries(cls, entries: Iterable[RegistryEntry]) -> InMemoryPackRegistry:
        """Build a registry from ``entries`` (later entries win on a duplicate ref)."""
        return cls(entries={entry.ref: entry for entry in entries})

    def get(self, ref: PackRef) -> RegistryEntry | None:
        return self.entries.get(ref)

    def list(self, pack_type: PackType | None = None) -> list[RegistryEntry]:
        selected = [e for e in self.entries.values() if pack_type is None or e.type == pack_type]
        return sorted(selected, key=lambda e: e.ref)

    def latest(self, pack_id: str) -> RegistryEntry | None:
        candidates = [e for e in self.entries.values() if e.ref.id == pack_id]
        if not candidates:
            return None
        return max(candidates, key=lambda e: e.ref.semver)


# --------------------------------------------------------------------------------------
# PackRegistry — the on-disk index.
# --------------------------------------------------------------------------------------
@dataclass
class PackRegistry:
    """An immutable, content-addressed index of published pack versions.

    Writes (``publish``) are serialized by a dependency-free inter-process lock: an
    ``O_CREAT | O_EXCL`` sentinel lock file next to the index (``<index>.lock``). The
    whole load → conflict-check → atomic-replace sequence runs while the lock is held and
    re-loads the latest state *inside* the lock, so concurrent publishers cannot both miss
    an existing ref or clobber each other. The index itself is swapped in atomically via
    ``os.replace`` from a per-writer unique temp file (pid + uuid), never a shared name.
    """

    index_path: Path = field(default=DEFAULT_INDEX_PATH)
    lock_timeout: float = 10.0
    lock_poll: float = 0.05

    def __post_init__(self) -> None:
        self.index_path = Path(self.index_path)

    # ---- locking ----------------------------------------------------------------------
    @contextlib.contextmanager
    def _lock(self) -> Iterator[None]:
        lock_path = self.index_path.with_name(self.index_path.name + ".lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self.lock_timeout
        fd: int | None = None
        while True:
            try:
                fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                break
            except FileExistsError:
                if time.monotonic() >= deadline:
                    raise RegistryLockError(
                        f"Could not acquire registry lock {lock_path} within "
                        f"{self.lock_timeout}s"
                    ) from None
                time.sleep(self.lock_poll)
        try:
            os.write(fd, str(os.getpid()).encode())
            yield
        finally:
            os.close(fd)
            with contextlib.suppress(FileNotFoundError):
                os.unlink(str(lock_path))

    # ---- loading / saving -------------------------------------------------------------
    def _load(self) -> dict[PackRef, RegistryEntry]:
        if not self.index_path.exists():
            return {}
        try:
            raw = json.loads(self.index_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
            raise CorruptRegistryError(
                f"Registry index unreadable at {self.index_path}: {exc}"
            ) from exc
        return parse_registry_index(raw, source=f"Registry index at {self.index_path}")

    def _save(self, entries: dict[PackRef, RegistryEntry]) -> None:
        ordered = sorted(entries.values(), key=lambda e: e.ref)
        document = {
            "version": INDEX_SCHEMA_VERSION,
            "entries": [e.to_dict() for e in ordered],
        }
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.index_path.with_name(
            f"{self.index_path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
        )
        tmp.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(str(tmp), str(self.index_path))

    # ---- public API -------------------------------------------------------------------
    def publish(
        self,
        pack: dict[str, Any],
        *,
        created_at: datetime | None = None,
        signature: PackSignature | str | None = None,
    ) -> RegistryEntry:
        """Publish a pack version. Immutable: same ref + different digest raises.

        Returns the (new or existing) entry. Re-publishing identical content is a no-op.

        ``signature`` is the detached :class:`PackSignature` that was verified against the pinned
        trust bundle at admission (issue #89, R2). It is persisted (deterministically serialized,
        with its ``key_id``) on the entry so the runtime resolver can INDEPENDENTLY re-verify the
        signature against the pinned trust root. ``None`` (the default) records a legacy-untrusted
        entry that the runtime fails closed — callers on a trusted admission path (e.g.
        ``cli.packs_studio.cmd_export``) MUST pass the verified signature.
        """
        manifest = pack.get("manifest")
        if not isinstance(manifest, dict):
            raise ValueError("Pack has no 'manifest' object")
        try:
            pack_id = manifest["id"]
            version = manifest["version"]
            pack_type = PackType(manifest["type"])
        except (KeyError, ValueError) as exc:
            raise ValueError(f"Pack manifest missing/invalid id/version/type: {exc}") from exc

        ref = PackRef(id=str(pack_id), version=str(version))
        SemVer.parse(ref.version)  # fail closed on non-semver versions
        digest = canonical_digest(pack)
        stored_signature, key_id = _normalize_publish_signature(signature)

        # Serialize the whole read-check-write under an inter-process lock, and RE-LOAD the
        # latest state inside the lock so a concurrent publisher's entry is always seen.
        with self._lock():
            entries = self._load()
            existing = entries.get(ref)
            if existing is not None:
                if existing.digest != digest:
                    raise ImmutableVersionError(
                        f"{ref} already published with a different digest "
                        f"(stored={existing.digest[:12]}…, incoming={digest[:12]}…); "
                        "published versions are immutable"
                    )
                return existing  # idempotent re-publish of identical content

            entry = RegistryEntry(
                ref=ref,
                type=pack_type,
                digest=digest,
                createdAt=created_at or datetime.now(UTC),
                signature=stored_signature,
                key_id=key_id,
            )
            entries[ref] = entry
            self._save(entries)
            return entry

    def get(self, ref: PackRef) -> RegistryEntry | None:
        """Return the entry for an exact ``id@version`` ref, or ``None``."""
        return self._load().get(ref)

    def list(self, pack_type: PackType | None = None) -> list[RegistryEntry]:
        """List entries (optionally filtered by type), ordered by (id, semver)."""
        entries = self._load().values()
        selected = [e for e in entries if pack_type is None or e.type == pack_type]
        return sorted(selected, key=lambda e: e.ref)

    def latest(self, pack_id: str) -> RegistryEntry | None:
        """Return the highest-semver entry for ``pack_id``, or ``None`` if unknown."""
        candidates = [e for e in self._load().values() if e.ref.id == pack_id]
        if not candidates:
            return None
        return max(candidates, key=lambda e: e.ref.semver)
