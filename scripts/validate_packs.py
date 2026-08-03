#!/usr/bin/env python
"""Validate content packs: schema-correctness and (optionally) signatures.

Usage:
    python scripts/validate_packs.py content

Exit code is non-zero if any pack is invalid, so CI (pack-validate.yml) fails closed.
Signature verification is skipped unless WP_PACK_SIGNING_SECRET is set (release-time signing).

The schema gate enumerates EVERY candidate pack file under the content root directly (not just the
ones the engine's loader returns), so a file with a missing or misspelled top-level ``manifest``
key — which the loader silently skips — still FAILS closed here.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import yaml

# Allow running without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from packs_engine.engine import PacksEngine, PackVerificationError  # noqa: E402
from packs_engine.registry import (  # noqa: E402
    CorruptRegistryError,
    parse_registry_index,
)
from packs_engine.schema import validate_pack  # noqa: E402

_PACK_SUFFIXES = {".json", ".yaml", ".yml"}


def _candidate_pack_files(root: Path) -> list[Path]:
    """Every JSON/YAML file under ``root`` — exactly what ``PacksEngine`` would discover.

    No path is excluded: whatever the engine can load and execute must also pass the schema gate,
    so a valid-manifest/invalid-body pack placed anywhere under the content root fails closed.
    """
    return sorted(
        p
        for p in root.rglob("*")
        if p.is_file() and p.suffix in _PACK_SUFFIXES
    )


def _parse(path: Path) -> object:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        return json.loads(text)
    return yaml.safe_load(text)


def _is_registry_index(raw: dict[str, object]) -> bool:
    """True iff ``raw`` is a *pristine, valid* pack registry index (issue #34), not a pack.

    The registry index lives under ``content/registry/`` and has EXACTLY the shape
    ``{"version": <int == INDEX_SCHEMA_VERSION>, "entries": [<valid entry>, ...]}`` with **no**
    ``manifest``. It is managed by the registry engine (which enforces its own integrity,
    fail-closed) and is never executed as a pack.

    The exemption is deliberately TIGHT and cannot become a hiding spot or swallow authoring
    mistakes:

    - It is *structural*, not path-based — any file carrying a ``manifest`` (i.e. anything
      ``PacksEngine`` would actually execute) is never exempted, wherever it sits.
    - The key set must be EXACTLY ``{"version", "entries"}``, so a mis-authored pack that merely
      *also* happens to carry ``version``/``entries`` (e.g. a misspelled ``manifest`` key plus a
      ``body``) is NOT exempted and still fails closed.
    - Semantic validity is delegated to :func:`packs_engine.registry.parse_registry_index` — the
      registry's OWN single-source-of-truth parser (schema version, entry shape, and no duplicate
      ``id@version``) — so this gate can never diverge from ``PackRegistry._load``.
    """
    if "manifest" in raw or set(raw) != {"version", "entries"}:
        return False
    try:
        parse_registry_index(raw)
    except CorruptRegistryError:
        return False
    return True


def main(argv: list[str]) -> int:
    root = Path(argv[1] if len(argv) > 1 else "content")
    secret = os.environ.get("WP_PACK_SIGNING_SECRET")
    verify_sig = secret is not None

    # 1) Signature/hash trust gate via the engine (unchanged behavior — fail closed on a bad sig).
    engine = PacksEngine(root, signing_secret=secret.encode() if secret else None)
    try:
        engine.load_all(verify_sig=verify_sig)
    except PackVerificationError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - surface parse/manifest errors clearly
        print(f"FAIL: could not load packs under {root}: {exc}", file=sys.stderr)
        return 1

    # 2) Schema gate over EVERY candidate pack file (fail closed on a missing/misspelled manifest,
    #    which the engine loader skips) — a malformed body or absent manifest fails the build.
    files = _candidate_pack_files(root)
    if not files:
        print(f"WARNING: no pack files found under {root}")

    failures = 0
    for path in files:
        rel = path.relative_to(root)
        try:
            raw = _parse(path)
        except Exception as exc:  # noqa: BLE001 - a malformed pack file must fail closed
            failures += 1
            print(f"FAIL: {rel}: could not parse ({exc})", file=sys.stderr)
            continue
        if not isinstance(raw, dict):
            failures += 1
            print(f"FAIL: {rel}: not a pack object (top-level must be a mapping)", file=sys.stderr)
            continue
        if _is_registry_index(raw):
            # The registry index is infrastructure, not a pack — the registry engine owns its
            # integrity. Skip pack-schema validation (it carries no manifest and never executes).
            print(f"--  registry index (not a pack): {rel}")
            continue
        errors = validate_pack(raw)
        if errors:
            failures += 1
            print(f"FAIL: {rel}: pack failed schema:", file=sys.stderr)
            for err in errors:
                print(f"        - {err}", file=sys.stderr)
        else:
            m = raw["manifest"]
            print(
                f"OK  {str(m.get('type', '')):<10} {str(m.get('id', '')):<28} "
                f"v{m.get('version', '?')}  targets={m.get('targets') or ['*']}"
            )

    if failures:
        print(f"\nFAIL: {failures} pack file(s) failed validation.", file=sys.stderr)
        return 1

    print(
        f"\nValidated {len(files)} pack file(s); signature check {'ON' if verify_sig else 'OFF'}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
