"""Canonical serialization + digest for pack *version identity*.

This module answers one question deterministically: **"what bytes uniquely identify
this pack version?"** It underpins the registry's immutability guarantee (issue #34) —
re-publishing the same ``id@version`` with different content must be detectable.

## Distinct from the engine's ``sha256`` (deliberately)

``packs_engine.engine`` computes a SHA-256 over the pack **body only**
(``json.dumps(raw.get("body", {}), sort_keys=True)``) as its signature/integrity trust
gate before execution. That is a *body-integrity* hash.

The **canonical digest** here is a *version-identity* hash over the **whole pack**
(manifest + body), and it deliberately **excludes volatile integrity fields** so that
signing a pack does not change its version identity. The two hashes serve different
purposes and are intentionally not interchangeable — do not conflate them.

## What ``canonical_bytes`` includes / excludes

Included: every field of the pack dict (manifest and body, recursively), EXCEPT the
volatile integrity fields listed in :data:`EXCLUDED_MANIFEST_FIELDS`.

Excluded (from ``manifest``): ``sha256`` and ``signature``. These are computed/attached
at signing time and say nothing about *which version* the content is; excluding them
keeps the digest stable whether the pack is unsigned, signed, or re-signed.

Determinism is guaranteed by: recursively sorting all mapping keys, compact separators
(no insignificant whitespace), ``ensure_ascii=False`` with a UTF-8 encode, and rejecting
non-JSON-native values. The result is therefore independent of input key order.
"""
from __future__ import annotations

import hashlib
import json
import math
from typing import Any

# Volatile integrity fields on ``manifest`` excluded from version identity.
EXCLUDED_MANIFEST_FIELDS: frozenset[str] = frozenset({"sha256", "signature"})


def _normalize(value: Any) -> Any:
    """Recursively produce a strict, JSON-native, order-independent structure.

    Fails closed on anything that could make two *distinct* packs collide to one digest
    or make the output insertion-order-dependent:

    - Mapping keys MUST be ``str`` (a non-``str`` key RAISES — we never stringify, so
      ``{1: ...}`` and ``{"1": ...}`` cannot collapse to the same key).
    - Only ``list`` is an accepted sequence; ``tuple`` (and any other container) RAISES.
    - ``float`` must be finite; ``nan``/``inf``/``-inf`` RAISE.

    ``bool`` is intentionally accepted (JSON-native) and, being an ``int`` subclass, is
    handled before the plain-``int`` branch is reached.
    """
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise TypeError(
                    f"canonical_bytes: mapping keys must be str, got {type(key).__name__!r}"
                )
        return {key: _normalize(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"canonical_bytes: non-finite float not allowed: {value!r}")
        return value
    if isinstance(value, (str, int)):
        return value
    raise TypeError(f"canonical_bytes: unsupported value of type {type(value).__name__!r}")


def _strip_volatile(pack: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow copy of ``pack`` with volatile manifest integrity fields removed."""
    result = dict(pack)
    manifest = result.get("manifest")
    if isinstance(manifest, dict):
        result["manifest"] = {
            k: v for k, v in manifest.items() if k not in EXCLUDED_MANIFEST_FIELDS
        }
    return result


def canonical_bytes(pack: dict[str, Any]) -> bytes:
    """Return a stable UTF-8 serialization of ``pack`` for version identity.

    Recursively sorts keys, uses compact separators, and excludes the volatile
    integrity fields (:data:`EXCLUDED_MANIFEST_FIELDS`) so the output depends only on
    the pack's *content*, not on key order or signing state.
    """
    normalized = _normalize(_strip_volatile(pack))
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_digest(pack: dict[str, Any]) -> str:
    """SHA-256 hex digest over :func:`canonical_bytes` — a pack version's identity."""
    return hashlib.sha256(canonical_bytes(pack)).hexdigest()
