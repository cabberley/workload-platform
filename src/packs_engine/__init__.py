"""Packs engine — load, verify (SHA-256 + HMAC), and serve content packs."""
from packs_engine.canonical import canonical_bytes, canonical_digest
from packs_engine.content_store import (
    AzurePackContentStore,
    LocalPackContentStore,
    PackContentStore,
    PackContentStoreError,
    build_pack_content_store,
)
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

# Schema validation is a DEV/CI + studio-time gate (jsonschema-backed, guarded import); it does not
# affect the runtime signature trust gate in engine.py.
from packs_engine.schema import validate_pack

__all__ = [
    "Pack",
    "PacksEngine",
    "PackVerificationError",
    # Pack registry + versioning model (issue #34).
    "canonical_bytes",
    "canonical_digest",
    # Digest-addressed content store for imported pack bytes (issue #44).
    "AzurePackContentStore",
    "LocalPackContentStore",
    "PackContentStore",
    "PackContentStoreError",
    "build_pack_content_store",
    "CorruptRegistryError",
    "ImmutableVersionError",
    "InvalidVersionError",
    "PackRef",
    "PackRegistry",
    "RegistryEntry",
    "RegistryError",
    "RegistryLockError",
    "SemVer",
    # Per-type JSON-Schema validation (issue #33).
    "validate_pack",
]
