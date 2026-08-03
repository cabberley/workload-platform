#!/usr/bin/env python
"""Validate content packs: schema-correctness and (optionally) signatures.

Usage:
    python scripts/validate_packs.py content

Exit code is non-zero if any pack is invalid, so CI (pack-validate.yml) fails closed.
Signature verification is skipped unless WP_PACK_SIGNING_SECRET is set (release-time signing).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Allow running without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from packs_engine.engine import PacksEngine, PackVerificationError  # noqa: E402


def main(argv: list[str]) -> int:
    root = argv[1] if len(argv) > 1 else "content"
    secret = os.environ.get("WP_PACK_SIGNING_SECRET")
    engine = PacksEngine(root, signing_secret=secret.encode() if secret else None)

    verify_sig = secret is not None
    try:
        packs = engine.load_all(verify_sig=verify_sig)
    except PackVerificationError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - surface schema errors clearly
        print(f"FAIL: could not parse packs under {root}: {exc}", file=sys.stderr)
        return 1

    if not packs:
        print(f"WARNING: no packs found under {root}")
    for p in packs:
        m = p.manifest
        print(f"OK  {m.type.value:<10} {m.id:<28} v{m.version}  targets={m.targets or ['*']}")
    print(f"\nValidated {len(packs)} pack(s); signature check {'ON' if verify_sig else 'OFF'}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
