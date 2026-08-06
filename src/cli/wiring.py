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
    These builders do not raise for absent/optional dependencies. The one deliberate exception is a
    security misconfiguration: a non-HTTPS outbound webhook URL is REJECTED at composition time
    (``InsecureWebhookError``) rather than silently accepted, so findings can never egress over
    cleartext.
"""
from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError

from packs_engine.canonical import canonical_digest
from packs_engine.content_store import PackContentStore, build_pack_content_store
from packs_engine.engine import Pack, PacksEngine
from packs_engine.registry import (
    DEFAULT_INDEX_PATH,
    InvalidVersionError,
    PackRef,
    PackRegistry,
    SemVer,
)
from shared.connectors import SecretProvider
from shared.contracts import TrustBundle
from shared.observability import connector_fail_closed_observer
from shared.secret_provider import build_secret_provider, resolve_secret
from shared.signing import TrustBundleVerifier

# Env var *names* the composition root reads. Values are supplied at runtime by identity / Key
# Vault — only the names live in code (keyless).
ENV_CONTENT_ROOT = "WP_CONTENT_ROOT"
ENV_REGISTRY_INDEX = "WP_REGISTRY_INDEX"
ENV_SUBSCRIPTION_ID = "WP_SUBSCRIPTION_ID"
ENV_ALERT_WEBHOOK_URL = "WP_ALERT_WEBHOOK_URL"
# Documented opt-out gating a loopback-ONLY cleartext webhook (a local test sink). Truthy permits
# http:// only to 127.0.0.0/8 / ::1 / localhost; cleartext to any non-loopback host is ALWAYS
# rejected, even with this set. Keyless — only the env var name lives in code.
ENV_ALERT_WEBHOOK_ALLOW_INSECURE_LOOPBACK = "WP_ALERT_WEBHOOK_ALLOW_INSECURE_LOOPBACK"
ENV_SYSTEM_PULSE_BASE_URL = "SYSTEM_PULSE_BASE_URL"
SYSTEM_PULSE_TOKEN_ENV = "SYSTEM_PULSE_READ_TOKEN"  # noqa: S105 - env var *name*, not a secret
# The Key Vault secret *name* the System Pulse read token is stored under (issue #85). Only the
# non-secret name lives in code; the value is read BY the Managed Identity from Key Vault at
# composition time (keyless). Matches the secretRef wired in
# ``infra/bicep/modules/module-app.bicep``.
SYSTEM_PULSE_TOKEN_SECRET = "system-pulse-read-token"  # noqa: S105 - KV secret *name*, not a secret
# Azure Monitor connector (aiops). A Log Analytics workspace id gates the logs edge; the metrics
# edge additionally needs a regional endpoint + namespace. All are Key Vault-backed *values*; only
# the env var names live in code (keyless — Managed Identity supplies the credential).
ENV_AZURE_MONITOR_WORKSPACE_ID = "AZURE_MONITOR_WORKSPACE_ID"
ENV_AZURE_MONITOR_RESOURCE_IDS = "AZURE_MONITOR_RESOURCE_IDS"
ENV_AZURE_MONITOR_METRICS_ENDPOINT = "AZURE_MONITOR_METRICS_ENDPOINT"
ENV_AZURE_MONITOR_METRIC_NAMESPACE = "AZURE_MONITOR_METRIC_NAMESPACE"
# Telemetry export write edge (telemetry_export module, issue #86). The Logs Ingestion API needs a
# Data Collection Endpoint URI + a Data Collection Rule *immutable id* (both non-secret Azure ids
# from the deploy outputs). Absent either ⇒ the exporter is inert (opt-in). Keyless — Managed
# Identity supplies the credential; only the env var names live in code.
ENV_TELEMETRY_EXPORT_DCE_ENDPOINT = "TELEMETRY_EXPORT_DCE_ENDPOINT"
ENV_TELEMETRY_EXPORT_DCR_IMMUTABLE_ID = "TELEMETRY_EXPORT_DCR_IMMUTABLE_ID"

_DEFAULT_CONTENT_ROOT = "content"
_WEBHOOK_TIMEOUT_S = 10.0
# Bundled trust root (issue #89): the pinned Ed25519 PUBLIC keys used to verify imported packs.
# A file path (overridable by env for a future signed-metadata refresh path); its VALUE is public
# key material only — never a secret. Absent/empty/corrupt ⇒ a reject-all verifier (fail closed).
ENV_TRUST_BUNDLE_PATH = "WP_TRUST_BUNDLE_PATH"
_DEFAULT_TRUST_BUNDLE_PATH = "config/trust-bundle.json"


def build_pack_import_verifier(*, config: Mapping[str, str] | None = None) -> TrustBundleVerifier:
    """Load the pinned trust bundle and build the keyless, fail-closed pack-import verifier (#89).

    This is the customer-side, **verification-only** trust root: it loads a bundled set of trusted
    Ed25519 **PUBLIC** keys (``$WP_TRUST_BUNDLE_PATH``, default ``config/trust-bundle.json``) and
    returns a :class:`~shared.signing.TrustBundleVerifier` that the engine's import-admission gate
    (:meth:`packs_engine.engine.PacksEngine.verify_pack_for_import`) uses to verify a pack's
    detached signature before it is registered/stored (#44) and activated.

    **Always returns a verifier — never ``None``** — so import is *fail-closed by construction*: a
    missing, empty, or corrupt bundle yields a reject-all verifier
    (:meth:`~shared.signing.TrustBundleVerifier.reject_all`) that rejects every pack until
    Microsoft's public keys are pinned into the bundle. The bundle holds only public key material
    (no secret is ever read here), keeping the platform keyless.

    TODO(human): a future "bundle refreshed via **signed** pack-registry metadata" path is a clean
    extension — resolve/verify an updated bundle from the registry and rebuild this verifier. Remote
    fetch is deliberately NOT built here; the bundled file remains the pinned trust root today.
    """
    cfg: Mapping[str, str] = config if config is not None else os.environ
    path = Path(cfg.get(ENV_TRUST_BUNDLE_PATH, _DEFAULT_TRUST_BUNDLE_PATH))
    bundle = _load_trust_bundle_or_empty(path)
    try:
        return TrustBundleVerifier.from_bundle(bundle)
    except Exception:  # noqa: BLE001 - any malformed bundle (e.g. duplicate key id) -> reject all
        return TrustBundleVerifier.reject_all()


def _load_trust_bundle_or_empty(path: Path) -> TrustBundle:
    """Read + validate the trust bundle file, or an EMPTY (reject-all) bundle on any problem.

    Fail-closed: a missing file, unreadable bytes, non-JSON content, or a schema-invalid bundle all
    degrade to an empty :class:`~shared.contracts.TrustBundle` (trusts nothing) rather than raising,
    so a misconfigured trust root rejects every import instead of crashing wiring or trusting packs.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return TrustBundle(keys=[])
    try:
        return TrustBundle.model_validate(raw)
    except ValidationError:
        return TrustBundle(keys=[])


def build_packs_engine() -> PacksEngine | None:
    """Construct the :class:`PacksEngine` rooted at ``$WP_CONTENT_ROOT`` (default ``content``).

    Returns ``None`` (fail closed) when the content root does not exist — modules already treat
    ``packs=None`` as "no content, assess nothing", so an absent pack directory degrades safely
    rather than crashing. Never raises.

    TODO(human): source the pack signing secret from Key Vault (by identity) and pass it as
    ``PacksEngine(root, signing_secret=...)`` so the legacy HMAC gate — not just content hashes —
    is verified before execution. Keep the secret out of code/config literals. (The #89 trust root
    is keyless and needs NO Key Vault key: the customer platform only VERIFIES imported packs with
    pinned Ed25519 PUBLIC keys — see ``build_pack_import_verifier`` below.)

    TODO(human): audit ``pack.import`` and ``pack.assign`` (issue #59) and emit their audit events.
    The #89 trust root is now ENFORCED at admission: the registry/store WRITE boundary
    (``cli.packs_studio.cmd_export`` today) verifies every pack against the pinned trust bundle via
    ``build_pack_import_verifier`` BEFORE ``registry.publish`` + ``store.put`` — so the runtime's
    "registry digest => trusted" invariant (:meth:`PacksEngine._resolve_imported_packs`) holds
    because admission proved the signature. What remains HELD behind #37 is the customer-facing
    import/assign SUBSYSTEM (nothing to emit from yet): when #37 lands, construct the import
    service with a store-backed ``AuditEmitter`` (as the API does via
    ``PacksEngine.attach_audit_emitter``), call ``engine.verify_pack_for_import(pack)`` (the SAME
    fail-closed trust-root gate wired below, reusing the SAME ``TrustBundleVerifier``) before
    ``registry.publish`` + ``store.put`` on the customer import path, and emit
    ``AuditAction.pack_import`` on admission (with the success-path ``pack.verify``) and
    ``AuditAction.pack_assign`` when a pack is bound to a workload. Do NOT build the held subsystem
    here just to emit.
    """
    root = os.environ.get(ENV_CONTENT_ROOT, _DEFAULT_CONTENT_ROOT)
    try:
        if not Path(root).is_dir():
            return None
        # Issue #44: wire the metadata registry + the digest-addressed content store so the engine
        # can resolve IMPORTED packs (never shipped in the image) by their verified registry digest,
        # re-verifying ``canonical_digest == registry.digest`` before execution (fail closed). The
        # content-root filesystem stays the source for shipped packs; the store is additive. Both
        # are optional — if the store cannot be built from optional Azure deps, the engine still
        # serves shipped packs (fail closed for imports). An UNKNOWN backend still fails closed
        # (the selector raises) — a misconfiguration we refuse rather than silently downgrade.
        registry = PackRegistry(index_path=Path(root) / "registry" / "index.json")
        content_store = _build_pack_content_store_or_none()
        # Issue #89: the customer-side, keyless trust root for imported packs. Always present and
        # fail-closed (reject-all until real Microsoft public keys are pinned), so the import
        # admission gate never silently trusts an unverified pack.
        import_verifier = build_pack_import_verifier()
        return PacksEngine(
            root,
            registry=registry,
            content_store=content_store,
            import_verifier=import_verifier,
        )
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


def _build_pack_content_store_or_none() -> PackContentStore | None:
    """Build the pack content store, or ``None`` when its optional Azure deps are unavailable.

    Mirrors the fail-closed-but-non-crashing contract of the other builders here: a missing Azure
    SDK / endpoint config leaves the store absent so the engine simply serves shipped packs and
    fails closed for imported ones. An UNKNOWN ``WORKLOADS_PACK_STORE_BACKEND`` is NOT swallowed —
    :func:`build_pack_content_store` raises ``ValueError`` and it propagates, so a misconfigured
    backend fails closed rather than silently degrading to the filesystem.
    """
    try:
        return build_pack_content_store()
    except (ImportError, RuntimeError, OSError):
        return None


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
    missing leaves that key **absent** so the consuming module fails closed on lookup. Does not
    raise for absent/optional dependencies — the one exception is a security misconfiguration: a
    non-HTTPS ``$WP_ALERT_WEBHOOK_URL`` is rejected fail-closed (``InsecureWebhookError``). Keys
    mirror what the modules read:

    * ``"resource_graph"`` (discovery) — needs ``azure-identity`` for a keyless credential.
    * ``"network"`` (dependency_graph) — needs ``$WP_SUBSCRIPTION_ID`` + ``azure-mgmt-network``.
    * ``"notifier"`` (alerts) — needs ``$WP_ALERT_WEBHOOK_URL`` (a Key Vault-backed value); the URL
      MUST be ``https://`` (cleartext rejected unless it is a loopback sink and
      ``$WP_ALERT_WEBHOOK_ALLOW_INSECURE_LOOPBACK`` is set).
    * ``"system_pulse"`` (aiops) — needs ``$SYSTEM_PULSE_BASE_URL``; the read token is resolved
      keyless BY identity from Key Vault (secret ``system-pulse-read-token``) when
      ``$WP_KEY_VAULT_URI`` is configured, else from the documented local-dev
      ``$SYSTEM_PULSE_READ_TOKEN`` env fallback. **Fail closed:** a configured vault that cannot
      supply the required token REFUSES to start (issue #85).
    * ``"azure_monitor"`` (aiops) — needs ``$AZURE_MONITOR_WORKSPACE_ID`` (Log Analytics workspace,
      for the aggregated logs edge) **and** a keyless credential; optional
      ``$AZURE_MONITOR_RESOURCE_IDS`` / ``$AZURE_MONITOR_METRICS_ENDPOINT`` /
      ``$AZURE_MONITOR_METRIC_NAMESPACE`` enable the metrics edge. The SDK imports lazily at the
      edge, so a missing package leaves the key absent (fail closed) rather than crashing.
    * ``"telemetry_exporter"`` (telemetry_export, #86) — the keyless Logs Ingestion **write** edge.
      Registered only when ``$TELEMETRY_EXPORT_DCE_ENDPOINT`` +
      ``$TELEMETRY_EXPORT_DCR_IMMUTABLE_ID`` (both non-secret Azure ids) **and** a keyless
      credential are present; otherwise the key is
      absent and the module runs inert (opt-in). The SDK imports lazily at the edge.

    ``config`` defaults to ``os.environ``; tests pass an explicit mapping.
    """
    cfg: Mapping[str, str] = config if config is not None else os.environ
    registry: dict[str, object] = {}
    credential = _build_credential()
    # Keyless runtime-secret resolver (issue #85): a Key Vault provider when ``$WP_KEY_VAULT_URI``
    # is configured (secrets read BY Managed Identity), else ``None`` so connectors use the
    # documented local-dev env-var fallback. Built once and injected where a secret/token is used.
    secret_provider = build_secret_provider(config=cfg)

    _add_resource_graph(registry, credential)
    _add_network(registry, cfg, credential)
    _add_notifier(registry, cfg)
    _add_system_pulse(registry, cfg, secret_provider)
    _add_azure_monitor(registry, cfg, credential)
    _add_telemetry_exporter(registry, cfg, credential)

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
    """alerts' webhook channel — the URL is a Key Vault-backed value, never a literal secret.

    Fails closed at composition time on a non-HTTPS webhook URL: a misconfigured cleartext
    ``http://`` endpoint is REJECTED (via :class:`InsecureWebhookError`) rather than silently
    accepted, so findings can never egress over the wire in the clear. Cleartext is tolerated only
    for an explicit loopback test sink gated behind
    ``$WP_ALERT_WEBHOOK_ALLOW_INSECURE_LOOPBACK``. The shared validator carries only scheme/host in
    its message, so no token in the URL path/query leaks (no-PII). An empty URL still leaves the
    key simply absent (module fails closed on lookup).
    """
    from modules.alerts.channels import WebhookChannel, require_https_webhook

    url = (cfg.get(ENV_ALERT_WEBHOOK_URL) or "").strip()
    if not url:
        return
    allow_insecure_loopback = (
        cfg.get(ENV_ALERT_WEBHOOK_ALLOW_INSECURE_LOOPBACK) or ""
    ).strip().lower() in {"1", "true", "yes", "on"}
    # Fail closed at composition time: a cleartext egress URL is a security misconfiguration we
    # refuse here (the channel re-validates as defense in depth).
    require_https_webhook(url, allow_insecure_loopback=allow_insecure_loopback)
    # The channel OWNS its hardened client (env proxies ignored + redirects not followed), so the
    # loopback cleartext exception cannot be routed off-box or TLS-downgraded via a 307 (issue #84).
    registry["notifier"] = WebhookChannel(
        url, timeout=_WEBHOOK_TIMEOUT_S, allow_insecure_loopback=allow_insecure_loopback
    )


def _add_system_pulse(
    registry: dict[str, object],
    cfg: Mapping[str, str],
    secret_provider: SecretProvider | None,
) -> None:
    """aiops' System Pulse connector — read token resolved keyless from Key Vault (issue #85).

    The read token is resolved BY identity through the injected ``secret_provider`` when a Key Vault
    URI is configured (``$WP_KEY_VAULT_URI``), else from the documented local-dev
    ``$SYSTEM_PULSE_READ_TOKEN`` env fallback. **Fail closed at composition (guardrail #4):** when a
    vault IS configured but cannot supply the required token, this REFUSES to start
    (``SecretResolutionError`` propagates) rather than wiring a connector that would silently fail
    closed at every fetch. An absent base URL leaves the key absent (module fails closed on lookup);
    a missing/unimportable SDK omits the connector (fail soft).
    """
    base_url = (cfg.get(ENV_SYSTEM_PULSE_BASE_URL) or "").strip()
    if not base_url:
        return
    # Fail closed at composition when a vault is configured: prove the required token is resolvable
    # NOW, so a misconfigured/inaccessible vault refuses to start rather than degrading silently at
    # runtime. Deliberately OUTSIDE the try/except below so ``SecretResolutionError`` propagates.
    if secret_provider is not None:
        resolve_secret(
            secret_provider,
            SYSTEM_PULSE_TOKEN_SECRET,
            SYSTEM_PULSE_TOKEN_ENV,
            config=cfg,
            required=True,
        )
    try:
        from modules.aiops.connectors.system_pulse import SystemPulseClient, SystemPulseConfig

        registry["system_pulse"] = SystemPulseClient(
            SystemPulseConfig(
                base_url=base_url,
                token_env=SYSTEM_PULSE_TOKEN_ENV,
                # Route the token through Key Vault (by identity) only when a vault is wired; else
                # the connector uses the local-dev ``token_env`` fallback.
                token_secret_name=(
                    SYSTEM_PULSE_TOKEN_SECRET if secret_provider is not None else None
                ),
            ),
            secret_provider=secret_provider,
            # Keyless observer (issue #60): a real fail-closed fetch increments
            # connector_fail_closed_total{module="aiops"} on the process registry the API exposes.
            fail_closed_observer=connector_fail_closed_observer("aiops"),
        )
    except Exception:  # noqa: BLE001 - fail closed: omit the connector, never crash wiring
        return


def _add_azure_monitor(
    registry: dict[str, object], cfg: Mapping[str, str], credential: object | None
) -> None:
    """aiops' Azure Monitor connector — keyless, read-only, guarded, fail-closed.

    Registered ONLY when a Log Analytics workspace id (``$AZURE_MONITOR_WORKSPACE_ID``, gating the
    aggregated logs edge) **and** a keyless credential are both present. A ``credential_provider``
    closure over the wiring credential keeps the connector keyless (Managed Identity via
    ``DefaultAzureCredential``) — no key/secret/connection string is ever read here. Optional
    ``$AZURE_MONITOR_RESOURCE_IDS`` (comma-separated) plus a regional metrics endpoint + namespace
    enable the metrics edge. The connector imports its Azure SDKs lazily at the edge, so a missing
    SDK simply fails closed at query time; this builder never raises — a missing workspace or
    credential leaves the key **absent** so the module fails closed on lookup.
    """
    workspace_id = (cfg.get(ENV_AZURE_MONITOR_WORKSPACE_ID) or "").strip()
    if not workspace_id or credential is None:
        return
    resource_ids = [
        rid.strip()
        for rid in (cfg.get(ENV_AZURE_MONITOR_RESOURCE_IDS) or "").split(",")
        if rid.strip()
    ]
    metrics_endpoint = (cfg.get(ENV_AZURE_MONITOR_METRICS_ENDPOINT) or "").strip() or None
    metric_namespace = (cfg.get(ENV_AZURE_MONITOR_METRIC_NAMESPACE) or "").strip() or None
    try:
        from modules.aiops.connectors.azure_monitor import (
            AzureMonitorClient,
            AzureMonitorConfig,
        )

        registry["azure_monitor"] = AzureMonitorClient(
            AzureMonitorConfig(
                workspace_id=workspace_id,
                resource_ids=resource_ids,
                metrics_endpoint=metrics_endpoint,
                metric_namespace=metric_namespace,
            ),
            credential_provider=lambda: credential,
            # Keyless observer (issue #60): a real fail-closed fetch increments
            # connector_fail_closed_total{module="aiops"} on the process registry the API exposes.
            fail_closed_observer=connector_fail_closed_observer("aiops"),
        )
    except Exception:  # noqa: BLE001 - fail closed: omit the connector, never crash wiring
        return


def _add_telemetry_exporter(
    registry: dict[str, object], cfg: Mapping[str, str], credential: object | None
) -> None:
    """telemetry_export's keyless Logs Ingestion **write** edge (issue #86) — opt-in, fail-closed.

    Registered ONLY when a Data Collection Endpoint URI (``$TELEMETRY_EXPORT_DCE_ENDPOINT``) **and**
    a Data Collection Rule immutable id (``$TELEMETRY_EXPORT_DCR_IMMUTABLE_ID``) **and** a keyless
    credential are all present — otherwise the key is absent and the module runs inert (opt-in). A
    ``credential_provider`` closure over the wiring credential keeps the export keyless (Managed
    Identity via ``DefaultAzureCredential``); no key/SAS/connection string is ever read here. The
    ``azure-monitor-ingestion`` SDK imports lazily at the edge, so a missing package fails closed at
    upload time; this builder never raises — a missing id or credential leaves the key absent.
    """
    endpoint = (cfg.get(ENV_TELEMETRY_EXPORT_DCE_ENDPOINT) or "").strip()
    rule_id = (cfg.get(ENV_TELEMETRY_EXPORT_DCR_IMMUTABLE_ID) or "").strip()
    if not endpoint or not rule_id or credential is None:
        return
    try:
        from modules.telemetry_export.exporter import (
            LogsIngestionClient,
            LogsIngestionConfig,
        )
        from modules.telemetry_export.module import CLIENT_KEY

        registry[CLIENT_KEY] = LogsIngestionClient(
            LogsIngestionConfig(endpoint=endpoint, rule_id=rule_id),
            credential_provider=lambda: credential,
            # Keyless observer (issue #60): a fail-closed export increments
            # connector_fail_closed_total{module="telemetry_export"} on the process registry.
            fail_closed_observer=connector_fail_closed_observer("telemetry_export"),
        )
    except Exception:  # noqa: BLE001 - fail closed: omit the exporter, never crash wiring
        return
