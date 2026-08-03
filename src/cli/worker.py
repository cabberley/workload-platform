"""Worker entrypoint — runs a single module by name.

This is what an Azure Container Apps **Job** executes (one module per Job). Because each module
is its own Job with its own KEDA scale rule, modules scale independently:

    python -m cli.worker --module quality_checks --scope workload=epic

Exit code is non-zero if the module reports failure, so the Job surfaces failures to the platform.
"""
from __future__ import annotations

import argparse
import json
import sys

from shared.module_base import ModuleContext, build_default_registry
from shared.state import ReadOnlyState, build_state_store, persist_run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="wp-worker", description="Run a Workloads Platform module"
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

    # The worker is a single-shot writer: it runs one module then exits. In production a module
    # deploys as its own ACA app and submits results to the API over HTTP; here the worker acts as
    # the writer for its one run. The module itself only gets a read-only view.
    store = build_state_store()
    ctx = ModuleContext(state=ReadOnlyState(store))
    result = module.run(ctx, scope=scope)
    workload = scope.get("workload")
    if workload:
        persist_run(store, workload, result)
    print(json.dumps(result.model_dump(), default=str, indent=2))
    return 0 if result.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
