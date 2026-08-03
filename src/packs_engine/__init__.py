"""Packs engine — load, verify (SHA-256 + HMAC), and serve content packs."""
from packs_engine.canonical import canonical_bytes, canonical_digest
from packs_engine.engine import Pack, PacksEngine, PackVerificationError
from packs_engine.registry import (
    CorruptRegistryError,
    ImmutableVersionError,
    InvalidVersionError,
    PackRef,
    PackRegistry,
    RegistryEntry,
    RegistryError,
    RegistryLockError,
    SemVer,
)

__all__ = [
    "Pack",
    "PacksEngine",
    "PackVerificationError",
    # Pack registry + versioning model (issue #34).
    "canonical_bytes",
    "canonical_digest",
    "CorruptRegistryError",
    "ImmutableVersionError",
    "InvalidVersionError",
    "PackRef",
    "PackRegistry",
    "RegistryEntry",
    "RegistryError",
    "RegistryLockError",
    "SemVer",
]
