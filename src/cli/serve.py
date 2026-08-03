"""Service entrypoint — runs a `kind: service` module as a long-running process.

Container Apps **services** (e.g. `aiops`, `alerts`) must stay alive and react to work as it
arrives, unlike **Jobs** (see `cli/worker.py`) which run one unit of work and exit. Pointing a
service at the Job entrypoint would run the wrong module once and then restart-loop, so services
use this entrypoint instead:

    WP_MODULE=aiops python -m cli.serve

The module to run is selected by the ``WP_MODULE`` environment variable (set per-app by the Bicep).
Selection is fail-closed: a missing/unknown module raises rather than silently defaulting.

TODO(human): real queue consumption / message dispatch for service modules lands with the module
runtime work in issues #6/#7. For now this is a liveness loop that resolves the selected module and
heartbeats its ``health()``; it does not yet pull messages off the queue.
"""
from __future__ import annotations

import os
import sys
import time
from collections.abc import Callable, Mapping

from shared.module_base import Module, ModuleRegistry, build_default_registry

WP_MODULE_ENV = "WP_MODULE"


def module_name_from_env(env: Mapping[str, str]) -> str:
    """Return the module name from ``WP_MODULE``; fail closed if absent/blank."""
    name = env.get(WP_MODULE_ENV, "").strip()
    if not name:
        raise ValueError(f"{WP_MODULE_ENV} is not set; a service must name its module")
    return name


def select_module(registry: ModuleRegistry, name: str) -> Module:
    """Resolve the named module from the registry (raises KeyError if unknown — fail closed)."""
    return registry.get(name)


def serve(
    *,
    env: Mapping[str, str] | None = None,
    registry: ModuleRegistry | None = None,
    poll_seconds: float = 15.0,
    max_iterations: int | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> Module:
    """Resolve the WP_MODULE-selected service module and run its liveness loop.

    ``max_iterations`` bounds the loop for tests; ``None`` runs until the process is stopped.
    Returns the selected module (useful for assertions in tests).
    """
    env = os.environ if env is None else env
    registry = build_default_registry() if registry is None else registry

    name = module_name_from_env(env)
    module = select_module(registry, name)

    iterations = 0
    while max_iterations is None or iterations < max_iterations:
        # Heartbeat only for now — see TODO(human) above.
        module.health()
        iterations += 1
        if max_iterations is not None and iterations >= max_iterations:
            break
        sleep(poll_seconds)
    return module


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - thin process wrapper
    try:
        module = serve()
    except (ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"served module: {module.name}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
