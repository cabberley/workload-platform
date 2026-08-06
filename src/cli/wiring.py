"""Composition root — the ONE place that knows concrete pack + edge-client types (issue #24).

The capability modules are pure by design: they look their dependencies up by well-known name in
``ModuleContext`` (``ctx.packs`` / ``ctx.clients[...]``) and never import a concrete Azure/edge
client. Something has to actually *build* those dependencies and inject them at the process
boundary — that is this file. It is deliberately the only module allowed to import the concrete
``AzureResourceGraphClient`` / ``AzureNetworkTopologyClient`` / ``WebhookChannel`` /
``SystemPulseClient`` classes and the packs engine, so ``shared`` and every module stay decoupled.

Guardrails honoured here:
  * **Keyless.** Every client authenticates with Managed Identity via ``DefaultAzureCredential``;
    no keys/secrets/connection strings are ever read or written. Only Key Vault-backed env var
    *names/values* (e.g. a webhook URL, a subscription id) are consumed.
  * **Guarded / lazy Azure imports.** Nothing Azure is imported at module import time. Every SDK
    import happens *inside* a function, so importing this composition root (and hence the API and
    worker) never requires an Azure SDK and ``mypy src`` stays clean without them installed.
  * **Fail closed.** A missing SDK, missing config, or missing content root leaves the pack/client
    simply **absent** — the module then fails closed on its own (packs=None / client lookup miss).
    None of these builders ever raise.
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

import httpx

from packs_engine.canonical import canonical_digest
from packs_engine.engine import Pack, PacksEngine
from packs_engine.registry import (
    DEFAULT_INDEX_PATH,
    InvalidVersionError,
    PackRef,
    PackRegistry,
    SemVer,
)

# Env var *names* the composition root reads. Values are supplied at runtime by identity / Key
# Vault — only the names live in code (keyless).
ENV_CONTENT_ROOT = "WP_CONTENT_ROOT"
ENV_REGISTRY_INDEX = "WP_REGISTRY_INDEX"
ENV_SUBSCRIPTION_ID = "WP_SUBSCRIPTION_ID"
ENV_ALERT_WEBHOOK_URL = "WP_ALERT_WEBHOOK_URL"
ENV_SYSTEM_PULSE_BASE_URL = "SYSTEM_PULSE_BASE_URL"
SYSTEM_PULSE_TOKEN_ENV = "SYSTEM_PULSE_READ_TOKEN"  # noqa: S105 - env var *name*, not a secret

_DEFAULT_CONTENT_ROOT = "content"
_WEBHOOK_TIMEOUT_S = 10.0


def build_packs_engine() -> PacksEngine | None:
    """Construct the :class:`PacksEngine` rooted at ``$WP_CONTENT_ROOT`` (default ``content``).

    Returns ``None`` (fail closed) when the content root does not exist — modules already treat
    ``packs=None`` as "no content, assess nothing", so an absent pack directory degrades safely
    rather than crashing. Never raises.

    TODO(human): source the pack signing secret from Key Vault (by identity) and pass it as
    ``PacksEngine(root, signing_secret=...)`` so signatures — not just content hashes — are
    verified before execution. Keep the secret out of code/config literals.
    """
    root = os.environ.get(ENV_CONTENT_ROOT, _DEFAULT_CONTENT_ROOT)
    try:
        if not Path(root).is_dir():
            return None
        return PacksEngine(root)
    except OSError:
        return None


def build_pack_registry() -> PackRegistry:
    """Construct the immutable pack registry the worker binds assigned resolution to (issue #37).

    Mirrors the API's ``get_pack_registry``: the on-disk index path is ``$WP_REGISTRY_INDEX`` (so a
    deployment can relocate it), falling back to :data:`DEFAULT_INDEX_PATH`. The registry is a pure
    metadata index (id@version -> verified digest); the worker reads it to confirm an assigned
    content pack's digest matches the verified import before running it.
    """
    index_path = os.environ.get(ENV_REGISTRY_INDEX)
    return PackRegistry(Path(index_path) if index_path else DEFAULT_INDEX_PATH)


class WorkloadPinnedPacks:
    """A packs view that resolves each pack id to a SINGLE, deterministic version for a workload.

    Wraps any packs engine (the real :class:`PacksEngine` or a test fake) and, per pack id:

    * **assigned** — keeps ONLY the assigned version AND only a content pack whose canonical
      *version-identity* digest equals the registry's VERIFIED digest for ``id@version`` (the
      digest recorded when the signed bundle was imported). This binds runtime execution to
      verified bytes: tampered/unrelated content-root bytes carrying the same ``id@version`` can
      NOT run under an assignment, and if no content pack matches the verified digest the assigned
      pack simply does not run (fail closed — an unverified substitute is NEVER executed). Exactly
      one pack survives per assigned ref (identical-digest duplicates dedupe to one).
    * **unassigned** — collapses to the HIGHEST *valid semver* among the id's available versions (a
      single deterministic pack), NEVER every version and NEVER a non-semver pack. Silently running
      multiple versions of one id — or a pack with an unparseable version — would be
      non-deterministic/unsafe.

    It never bypasses the underlying trust gate — the wrapped engine still verifies each pack's
    signature/hash before returning it, so this can only ever *narrow* an already-verified set
    (fail-closed content trust is preserved). ``_engine`` is intentionally ``Any``: modules already
    treat ``ctx.packs`` opaquely and cast to their own narrow Protocol, and this wrapper delegates
    any method it does not override.

    TODO(human): materialize verified imported pack bytes into a digest-addressed content store
    (ADR pending) so import->assign->run resolves NEW packs; today resolution fails closed if the
    assigned digest is not present in the content root (a just-imported pack whose bytes are not
    yet in the content root safely runs nothing under its assignment).
    """

    def __init__(
        self, engine: Any, assigned_versions: Mapping[str, str], registry: PackRegistry
    ) -> None:
        self._engine = engine
        self._assigned = dict(assigned_versions)
        self._registry = registry

    @staticmethod
    def _latest(group: list[Pack]) -> Pack | None:
        """Return the highest-*valid-semver* pack in ``group``, or ``None`` — fail closed.

        Considers ONLY packs whose version parses as a valid :class:`SemVer`. If none parse we
        return ``None`` (the id runs nothing) — we NEVER fall back to a lexicographic pick, so a
        pack with an unparseable version (``not-semver``) can never be selected/run.
        """
        best: Pack | None = None
        best_key: SemVer | None = None
        for pack in group:
            try:
                key = SemVer.parse(pack.manifest.version)
            except InvalidVersionError:
                continue
            if best_key is None or key > best_key:
                best, best_key = pack, key
        return best

    def _pin_assigned(self, pack_id: str, assigned: str, group: list[Pack]) -> Pack | None:
        """Return the ONE content pack for ``pack_id@assigned`` whose digest is registry-verified.

        Binds execution to the registry's VERIFIED digest: look up the immutable registry entry for
        ``id@version`` and keep a content pack ONLY if its canonical digest equals that entry's
        digest. Fail closed on every miss — absent entry, wrong version, digest mismatch, or an
        unhashable pack — so unverified/tampered bytes never run under an assignment. Identical-
        digest duplicates dedupe to exactly one.
        """
        entry = self._registry.get(PackRef(id=pack_id, version=assigned))
        if entry is None:
            return None  # not a verified registry entry ⇒ nothing runs (API blocks this at write)
        for pack in group:
            if pack.manifest.version != assigned:
                continue
            try:
                if canonical_digest(pack.source) == entry.digest:
                    return pack  # exactly one — verified bytes; ignore identical-digest duplicates
            except (TypeError, ValueError):
                continue  # unhashable/malformed pack ⇒ cannot verify ⇒ fail closed
        return None  # no content pack matches the verified digest ⇒ fail closed (run nothing)

    def _pin(self, packs: list[Pack]) -> list[Pack]:
        by_id: dict[str, list[Pack]] = {}
        for pack in packs:
            by_id.setdefault(pack.manifest.id, []).append(pack)
        out: list[Pack] = []
        for pack_id, group in by_id.items():
            assigned = self._assigned.get(pack_id)
            if assigned is not None:
                pinned = self._pin_assigned(pack_id, assigned, group)
                if pinned is not None:
                    out.append(pinned)
            else:
                # Unassigned: a single deterministic version — the highest valid semver.
                latest = self._latest(group)
                if latest is not None:
                    out.append(latest)
        return out

    def load_for_workload(self, workload: str, pack_type: Any) -> list[Pack]:
        return self._pin(self._engine.load_for_workload(workload, pack_type))

    def load_all(self, *, pack_type: Any = None, verify_sig: bool = True) -> list[Pack]:
        return self._pin(self._engine.load_all(pack_type=pack_type, verify_sig=verify_sig))

    def __getattr__(self, name: str) -> Any:
        # Delegate anything not overridden (e.g. future engine methods) to the wrapped engine.
        return getattr(self._engine, name)


def resolve_packs_for_workload(
    packs: object | None, assigned_versions: Mapping[str, str], registry: PackRegistry
) -> object | None:
    """Return a packs view that resolves each pack id to a SINGLE version for a workload (#37).

    Resolution is always deterministic — the returned view NEVER runs multiple versions of one
    pack id, and it is applied to EVERY run (workload-scoped or not; pass an empty
    ``assigned_versions`` when there is no workload) so no run can execute several versions of an
    id:

    * an id WITH an assignment runs EXACTLY the assigned version AND only a content pack whose
      canonical digest matches the registry's VERIFIED digest for that ``id@version`` (bytes-level
      binding to signature-verified content); if nothing matches, that id runs nothing (fail
      closed) — an unverified substitute is never run;
    * an id with NO assignment (the DOCUMENTED fallback) resolves to the HIGHEST *valid semver*
      among its available versions — a single deterministic pack, not every version, and never a
      non-semver pack.

    A run therefore never fails merely because nothing is assigned (a workload with zero
    assignments still runs the latest of each id), and it never silently runs several versions of
    one id. Content trust stays fail-closed in the underlying engine (each pack is signature-
    verified before it is returned; pinning can only narrow that verified set).

    ``packs`` is ``object | None`` (modules receive it opaquely and cast to their own Protocol);
    ``None`` (no content root) is returned as-is.

    TODO(human): materialize verified imported pack bytes into a digest-addressed content store
    (ADR pending) so import->assign->run resolves NEW packs; today resolution fails closed if the
    assigned digest is not present in the content root.
    """
    if packs is None:
        return packs
    return WorkloadPinnedPacks(packs, assigned_versions, registry)


def _build_credential() -> object | None:
    """Lazily build a keyless ``DefaultAzureCredential`` once, or ``None`` if unavailable.

    The ``azure-identity`` import is guarded and happens only here, inside the function, so this
    module imports with no Azure SDK present. On a missing SDK (or any construction error) we
    return ``None`` and the dependent clients are simply omitted (fail closed). No credential is
    ever constructed at import time.
    """
    try:
        from azure.identity import DefaultAzureCredential
    except ImportError:
        return None
    try:
        return DefaultAzureCredential()
    except Exception:  # noqa: BLE001 - never let credential construction crash wiring
        return None


def build_client_registry(*, config: Mapping[str, str] | None = None) -> dict[str, object]:
    """Build the keyless edge-client registry injected as ``ctx.clients`` at the boundary.

    Each client is constructed only when its config is present and its SDK imports; anything
    missing leaves that key **absent** so the consuming module fails closed on lookup. Never
    raises. Keys mirror what the modules read:

    * ``"resource_graph"`` (discovery) — needs ``azure-identity`` for a keyless credential.
    * ``"network"`` (dependency_graph) — needs ``$WP_SUBSCRIPTION_ID`` + ``azure-mgmt-network``.
    * ``"notifier"`` (alerts) — needs ``$WP_ALERT_WEBHOOK_URL`` (a Key Vault-backed value).
    * ``"system_pulse"`` (aiops) — needs ``$SYSTEM_PULSE_BASE_URL``; the read token is resolved at
      the edge from the Key Vault-backed ``$SYSTEM_PULSE_READ_TOKEN`` (never embedded here).

    ``config`` defaults to ``os.environ``; tests pass an explicit mapping.
    """
    cfg: Mapping[str, str] = config if config is not None else os.environ
    registry: dict[str, object] = {}
    credential = _build_credential()

    _add_resource_graph(registry, credential)
    _add_network(registry, cfg, credential)
    _add_notifier(registry, cfg)
    _add_system_pulse(registry, cfg)

    # TODO(human): azure_monitor extension point (issue #6). When #6 lands its keyless
    # AzureMonitorClient, wire it here in ~2 lines, guarded/fail-closed like the others, e.g.:
    #     if cfg.get("AZURE_MONITOR_WORKSPACE_ID") and credential is not None:
    #         from modules.aiops.connectors.azure_monitor import AzureMonitorClient
    #         registry["azure_monitor"] = AzureMonitorClient(credential=credential)
    # Do NOT import azure_monitor until #6 is on main.

    return registry


def _add_resource_graph(registry: dict[str, object], credential: object | None) -> None:
    """Discovery's keyless ARG client — omitted if no credential or the ARG SDK is absent.

    ``AzureResourceGraphClient`` defers its SDK import to query time, so constructing it can never
    signal a missing SDK on its own. We therefore PROBE ``azure.mgmt.resourcegraph`` here (guarded)
    before registering, so a missing SDK omits the key — consistent with this builder's documented
    fail-closed contract and with how the other builders behave.
    """
    if credential is None:
        return
    try:
        import azure.mgmt.resourcegraph  # noqa: F401 - probe SDK presence; fail closed if absent

        from modules.discovery.arg import AzureResourceGraphClient
    except ImportError:
        return
    registry["resource_graph"] = AzureResourceGraphClient(credential=credential)


def _add_network(
    registry: dict[str, object], cfg: Mapping[str, str], credential: object | None
) -> None:
    """dependency_graph's keyless network-topology client — needs a subscription id + SDK."""
    subscription_id = cfg.get(ENV_SUBSCRIPTION_ID)
    if not subscription_id or credential is None:
        return
    try:
        from modules.dependency_graph.topology import AzureNetworkTopologyClient

        # NOTE: this constructor imports azure-mgmt-network eagerly; a missing SDK raises
        # ImportError here and is caught below (fail closed → key absent).
        registry["network"] = AzureNetworkTopologyClient(
            subscription_id, credential=cast("Any", credential)
        )
    except Exception:  # noqa: BLE001 - missing azure-mgmt-network / any error → omit
        return


def _add_notifier(registry: dict[str, object], cfg: Mapping[str, str]) -> None:
    """alerts' webhook channel — the URL is a Key Vault-backed value, never a literal secret."""
    url = (cfg.get(ENV_ALERT_WEBHOOK_URL) or "").strip()
    if not url:
        return
    try:
        from modules.alerts.channels import WebhookChannel

        client = httpx.Client(timeout=_WEBHOOK_TIMEOUT_S, verify=True)
        registry["notifier"] = WebhookChannel(url, client)
    except Exception:  # noqa: BLE001 - fail closed: omit the channel, never crash wiring
        return


def _add_system_pulse(registry: dict[str, object], cfg: Mapping[str, str]) -> None:
    """aiops' System Pulse connector — read token resolved at the edge from a Key Vault env."""
    base_url = (cfg.get(ENV_SYSTEM_PULSE_BASE_URL) or "").strip()
    if not base_url:
        return
    try:
        from modules.aiops.connectors.system_pulse import SystemPulseClient, SystemPulseConfig

        registry["system_pulse"] = SystemPulseClient(
            SystemPulseConfig(base_url=base_url, token_env=SYSTEM_PULSE_TOKEN_ENV)
        )
    except Exception:  # noqa: BLE001 - fail closed: omit the connector, never crash wiring
        return
