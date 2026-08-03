"""Worker entrypoint — **COMPUTE ONLY**. Runs a single module by name, then hands its result to
the API (the single writer) over HTTP. The worker never constructs a writable state store and
never writes shared state — that invariant is what lets many worker replicas run safely.

This is what an Azure Container Apps **Job** executes (one module per Job). Because each module is
its own Job with its own KEDA scale rule, modules scale independently:

    python -m cli.worker --module quality_checks --scope workload=epic

Exit code is non-zero if the module reports failure, so the Job surfaces failures to the platform.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import httpx

from shared.module_base import build_default_registry, run_module

# Internal, in-boundary base URL of the API service (compose/ACA service name). Override per env.
DEFAULT_API_BASE_URL = "http://api:8000"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="wp-worker", description="Run a Workloads Platform module (compute only)"
    )
    parser.add_argument("--module", required=True, help="Module name, e.g. discovery")
    parser.add_argument(
        "--scope",
        action="append",
        default=[],
        metavar="key=value",
        help="Scope key=value (repeatable), e.g. --scope workload=epic",
    )
    args = parser.parse_args(argv)

    scope: dict[str, str] = {}
    for item in args.scope:
        if "=" not in item:
            parser.error(f"--scope expects key=value, got: {item}")
        key, value = item.split("=", 1)
        scope[key] = value

    registry = build_default_registry()
    try:
        module = registry.get(args.module)
    except KeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print(f"available: {', '.join(registry.names())}", file=sys.stderr)
        return 2

    # COMPUTE ONLY — no writable state store here. The module is run with no writable state; it
    # returns a ModuleRunResult. The API is the ONLY code path that commits it.
    result = run_module(module, scope=scope)

    workload = scope.get("workload")
    if workload:
        base_url = os.environ.get("WP_API_BASE_URL", DEFAULT_API_BASE_URL).rstrip("/")
        # TODO(human): authenticate worker->API (Entra/mTLS) — M4. Keyless/internal for MVP.
        response = httpx.post(
            f"{base_url}/api/workloads/{workload}/results",
            json=result.model_dump(mode="json"),
            timeout=30.0,
        )
        response.raise_for_status()

    print(json.dumps(result.model_dump(), default=str, indent=2))
    return 0 if result.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
