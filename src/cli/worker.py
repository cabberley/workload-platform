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

from cli.state_client import DEFAULT_API_BASE_URL, ApiStateReader
from cli.wiring import (
    build_client_registry,
    build_pack_registry,
    build_packs_engine,
    resolve_packs_for_workload,
)
from packs_engine.registry import InvalidVersionError, SemVer
from shared.auth.token_source import ApiTokenProvider, build_api_token_provider
from shared.module_base import build_default_registry, run_module

# `DEFAULT_API_BASE_URL` is defined in `cli.state_client` (the read client) and re-exported here so
# the worker's compute (read via HTTP) and write-back (POST results) agree on the API base URL.


def _fetch_assigned_versions(base_url: str, workload: str) -> dict[str, str]:
    """Read the workload's pack-version assignments over HTTP (read-only). **Fail-closed.**

    Returns a ``packId -> version`` map so the worker's compute resolves the ASSIGNED pack version
    (issue #37), mirroring the API ``/run`` endpoint.

    A *successful* read (HTTP 200 with a well-formed JSON list) is authoritative: an empty list
    means the workload is genuinely unassigned and returns ``{}`` — the resolver then falls back to
    the latest version per id (documented fallback), which is normal and proceeds. A *failure* —
    transport error, non-2xx status, or a malformed / wrong-shape / invalid-value body — is NOT the
    same as "no assignments": treating it as ``{}`` would silently run an unintended version. So on
    failure we fail closed and PROPAGATE (``httpx.HTTPError`` for transport/non-2xx, ``ValueError``
    for a bad body); ``main`` turns that into a non-zero exit so the ACA Job surfaces it for retry
    rather than running fallback packs.

    Row values are strictly validated (fail closed): each row's ``packId`` must be a NON-EMPTY
    string and ``version`` a NON-EMPTY string that parses as valid :class:`SemVer`; a non-string,
    empty, non-semver, or DUPLICATE ``packId`` is rejected (raises ``ValueError``). We never coerce
    ``null``/lists/dicts into strings — a malformed value must fail the worker, not silently pin an
    unintended reference.
    """
    response = httpx.get(
        f"{base_url}/api/workloads/{workload}/pack-assignments", timeout=30.0
    )
    response.raise_for_status()  # non-2xx ⇒ httpx.HTTPStatusError (fail closed)
    rows = response.json()  # malformed JSON ⇒ ValueError (fail closed)
    if not isinstance(rows, list):
        raise ValueError(f"expected a JSON list of assignments, got {type(rows).__name__}")
    out: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError(f"malformed pack-assignment row (not an object): {row!r}")
        pack_id = row.get("packId")
        version = row.get("version")
        if not isinstance(pack_id, str) or not pack_id:
            raise ValueError(f"pack-assignment row has a non-string/empty packId: {row!r}")
        if not isinstance(version, str) or not version:
            raise ValueError(f"pack-assignment row has a non-string/empty version: {row!r}")
        try:
            SemVer.parse(version)
        except InvalidVersionError as exc:
            raise ValueError(
                f"pack-assignment row has a non-semver version: {version!r}"
            ) from exc
        if pack_id in out:
            raise ValueError(f"duplicate packId in pack assignments: {pack_id!r}")
        out[pack_id] = version
    return out


def _submit_result(
    base_url: str,
    workload: str,
    payload: dict[str, object],
    *,
    token_provider: ApiTokenProvider | None,
    client: httpx.Client | None = None,
) -> None:
    """POST a module result to the API (the single writer), keylessly authenticated when enabled.

    When ``token_provider`` is set (auth enabled) a fresh bearer for the API audience is minted via
    the worker's Managed Identity (issue #64/#79) and attached as ``Authorization: Bearer`` — no
    shared key. Inability to mint fails closed inside the provider (raises), so the worker never
    falls back to an unauthenticated write. When ``token_provider`` is ``None`` (``WP_AUTH_MODE=
    disabled``) no header is sent, matching a server that is not enforcing. ``client`` is injectable
    so tests assert header attachment without any network or real Entra.
    """
    headers: dict[str, str] = {}
    if token_provider is not None:
        headers["Authorization"] = f"Bearer {token_provider()}"
    url = f"{base_url}/api/workloads/{workload}/results"
    if client is not None:
        response = client.post(url, json=payload, headers=headers, timeout=30.0)
    else:
        response = httpx.post(url, json=payload, headers=headers, timeout=30.0)
    response.raise_for_status()


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

    # COMPUTE ONLY — the worker never constructs a writable store. It builds the composition-root
    # dependencies at the process boundary and injects them: the verified packs engine, the keyless
    # edge-client registry, and a READ-ONLY `ApiStateReader` (HTTP reads, no write methods) so
    # prior state can be read without ever mutating it. The module returns a ModuleRunResult; the
    # API is the ONLY code path that commits it.
    base_url = os.environ.get("WP_API_BASE_URL", DEFAULT_API_BASE_URL).rstrip("/")
    packs = build_packs_engine()
    pack_registry = build_pack_registry()
    clients = build_client_registry()
    state = ApiStateReader(base_url=base_url)
    workload = scope.get("workload")
    # Resolve the packs the module sees to a SINGLE deterministic version per id (issue #37). The
    # resolver is ALWAYS applied — with or without a workload — so no run ever executes multiple
    # versions of one id. With a workload, a SUCCESSFUL read with no assignments yields `{}` and
    # each id falls back to its highest valid semver; an assigned id runs its exact version only if
    # a content pack's digest matches the registry's verified digest. If the assignments could not
    # be read (transport error, non-2xx, malformed/invalid body) we must NOT run fallback packs —
    # that could execute an unintended version. Fail closed: surface the error and exit non-zero so
    # the ACA Job retries, before any module code runs.
    assigned_versions: dict[str, str] = {}
    if workload:
        try:
            assigned_versions = _fetch_assigned_versions(base_url, workload)
        except (httpx.HTTPError, ValueError) as exc:
            print(
                f"error: could not read pack assignments for {workload!r}: {exc}",
                file=sys.stderr,
            )
            print(
                "failing closed: refusing to run with an unverified/unknown pack version",
                file=sys.stderr,
            )
            return 1
    resolved_packs = resolve_packs_for_workload(packs, assigned_versions, pack_registry)
    result = run_module(module, scope=scope, state=state, packs=resolved_packs, clients=clients)

    if workload:
        # Authenticate worker→API KEYLESSLY with the worker's own Managed Identity (issue #64/#79):
        # under `WP_AUTH_MODE=required` a bearer for the API audience is minted and attached;
        # inability to mint fails closed. Under `disabled` no token is sent (local/dev). No shared
        # key anywhere. `build_api_token_provider` reads the same auth config as the API server.
        token_provider = build_api_token_provider()
        _submit_result(
            base_url, workload, result.model_dump(mode="json"), token_provider=token_provider
        )

    print(json.dumps(result.model_dump(), default=str, indent=2))
    return 0 if result.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
