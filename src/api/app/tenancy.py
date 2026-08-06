"""Tenant context resolution + pure partition-key logic for the API core (issue #65).

This is the tenancy DECISION layer. It resolves the single :class:`~shared.contracts.TenantContext`
a request may act within (fail-closed, deny-by-default) and derives the PURE, storage-safe partition
keys the state layer uses to namespace every write and filter every read. It is **Azure-free and
I/O-free** — every function here is pure and unit-tested; the storage calls stay behind the
unchanged :class:`~shared.state.StateStore` backends at the edge (pure logic ⟂ I/O).

Two delivery modes (ADR 0017), each resolving to exactly one tenant per request:

* ``single`` (DEFAULT) — a customer-owned single-tenant instance: one configured tenant id. A
  request whose validated token asserts a DIFFERENT tenant is denied (fail closed); a request that
  asserts none is served as the single configured tenant (the keyless local/dev path).
* ``multi`` (opt-in MSP overlay via Azure Lighthouse — ADR 0011) — several client tenants share one
  instance: the caller's tenant is taken from its validated token and MUST be on the configured
  allowlist. A missing/ambiguous tenant is denied — never a guessed default.

Keyless: only env-var *names* live here; every value is a non-secret directory identifier supplied
at runtime. There is no secret anywhere in tenancy resolution.
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

from shared.contracts import TenancyMode, TenantContext, is_tenant_id_safe

__all__ = [
    "DEFAULT_TENANT_ID",
    "ENV_ALLOWED_TENANTS",
    "ENV_TENANCY_MODE",
    "ENV_TENANT_ID",
    "TenancyConfig",
    "TenantResolutionError",
    "build_tenancy_config",
    "partition_belongs_to",
    "partition_prefix",
    "resolve_tenant",
    "split_partition_key",
    "tenant_partition_key",
    "workload_of",
]

# Env var *names* only (keyless). Values are non-secret directory identifiers set at runtime.
ENV_TENANCY_MODE = "WP_TENANCY_MODE"
# single mode: the one configured tenant id for this instance (optional — see DEFAULT_TENANT_ID).
ENV_TENANT_ID = "WP_TENANT_ID"
# multi mode: comma-separated allowlist of the client tenant ids this MSP instance may serve.
ENV_ALLOWED_TENANTS = "WP_ALLOWED_TENANTS"
# Reused from the auth config so a single-tenant deployment need not repeat its tenant guid.
_ENV_AUTH_TENANT_ID = "WP_AUTH_TENANT_ID"

# The implicit tenant id for a single-tenant instance that configures none (keyless local/dev/CI).
# Keeps the customer-owned DEFAULT working out of the box; documented in ADR 0017.
DEFAULT_TENANT_ID = "default"

# The delimiter between the (hex-encoded) tenant prefix and the logical workload in a partition key.
# The tenant id is hex-encoded to a fixed ``[0-9a-f]`` charset that can NEVER contain this char, so
# splitting on the first occurrence unambiguously and reversibly recovers ``(tenant_id, workload)``
# even when the workload name itself contains the delimiter.
_PARTITION_SEPARATOR = "."


# --------------------------------------------------------------------------------------
# Pure partition-key logic (Azure-free, deterministic, unit-tested).
# --------------------------------------------------------------------------------------
def partition_prefix(tenant_id: str) -> str:
    """Return the storage-key prefix that identifies ``tenant_id`` (pure). Fail closed if unsafe."""
    if not is_tenant_id_safe(tenant_id):
        raise ValueError("partition_prefix: tenant_id is not storage-safe (fail closed)")
    return f"{tenant_id.encode('utf-8').hex()}{_PARTITION_SEPARATOR}"


def tenant_partition_key(tenant_id: str, workload: str) -> str:
    """Return the partition key that namespaces ``workload`` under ``tenant_id`` (pure).

    The tenant id is hex-encoded (fixed ``[0-9a-f]`` charset — no separator, quote, or OData
    operator) and prefixed onto the logical workload with a delimiter the hex can never contain. The
    result is deterministic and reversible (:func:`split_partition_key`), so a write and a later
    read derive the SAME physical key, while two tenants sharing a workload NAME map to DISJOINT
    keys — the isolation invariant. The state backends hex-encode this whole value again for Azure
    Table/Blob safety; this prefix guarantees the tenant is part of the physical key on BOTH
    backends (the local sqlite ``workload`` column and the Azure partition/row keys + blob paths).
    """
    return f"{partition_prefix(tenant_id)}{workload}"


def partition_belongs_to(partition_key: str, tenant_id: str) -> bool:
    """Return ``True`` iff ``partition_key`` is namespaced under ``tenant_id`` (pure)."""
    return partition_key.startswith(partition_prefix(tenant_id))


def split_partition_key(partition_key: str) -> tuple[str, str]:
    """Reverse :func:`tenant_partition_key` into ``(tenant_id, workload)`` (pure). Fail closed."""
    prefix, sep, workload = partition_key.partition(_PARTITION_SEPARATOR)
    if not sep:
        raise ValueError("split_partition_key: not a tenant-scoped key (fail closed)")
    try:
        tenant_id = bytes.fromhex(prefix).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("split_partition_key: malformed tenant prefix (fail closed)") from exc
    return tenant_id, workload


def workload_of(partition_key: str, tenant_id: str) -> str | None:
    """Return the logical workload iff ``partition_key`` belongs to ``tenant_id``, else ``None``.

    Deny-by-default filter for read models: a partition key from ANOTHER tenant yields ``None`` and
    is dropped, so a cross-tenant key can never surface as one of this tenant's workloads.
    """
    prefix = partition_prefix(tenant_id)
    if not partition_key.startswith(prefix):
        return None
    return partition_key[len(prefix):]


# --------------------------------------------------------------------------------------
# Tenancy configuration + fail-closed resolution.
# --------------------------------------------------------------------------------------
class TenantResolutionError(Exception):
    """A request's tenant could not be resolved unambiguously — deny-by-default (issue #65).

    Carries a short, fixed reason CODE only (never the token, claims, tenant id, or any PII), so a
    resolution failure can never itself leak identity material.
    """


@dataclass(frozen=True)
class TenancyConfig:
    """Immutable, keyless tenancy configuration (all values are non-secret directory identifiers).

    * ``mode`` — :class:`~shared.contracts.TenancyMode` (``single`` default, or ``multi`` overlay).
    * ``default_tenant_id`` — the one configured tenant in ``single`` mode; ``None`` in ``multi``.
    * ``allowed_tenants`` — the set of tenant ids this instance may serve. In ``single`` mode it is
      exactly ``{default_tenant_id}``; in ``multi`` mode it is the configured allowlist.
    """

    mode: TenancyMode
    default_tenant_id: str | None
    allowed_tenants: frozenset[str]


def build_tenancy_config(config: Mapping[str, str] | None = None) -> TenancyConfig:
    """Resolve the :class:`TenancyConfig` from env (keyless). Fail closed on invalid config.

    * ``WP_TENANCY_MODE`` unset/blank ⇒ ``single`` (the customer-owned default). An unrecognized
      value fails closed (never silently multi-tenant).
    * ``single`` ⇒ the configured tenant is ``WP_TENANT_ID`` (else the auth tenant
      ``WP_AUTH_TENANT_ID``, else :data:`DEFAULT_TENANT_ID` so the default works out of the box).
    * ``multi`` ⇒ ``WP_ALLOWED_TENANTS`` (comma-separated) MUST be non-empty — an overlay with no
      allowlist would admit any tenant, so it fails closed.

    ``config`` defaults to ``os.environ``; tests pass an explicit mapping.
    """
    cfg: Mapping[str, str] = config if config is not None else os.environ
    raw_mode = (cfg.get(ENV_TENANCY_MODE) or "").strip().lower()
    if not raw_mode:
        mode = TenancyMode.single
    else:
        try:
            mode = TenancyMode(raw_mode)
        except ValueError as exc:
            raise TenantResolutionError("invalid_tenancy_mode") from exc

    if mode is TenancyMode.single:
        configured = (cfg.get(ENV_TENANT_ID) or cfg.get(_ENV_AUTH_TENANT_ID) or "").strip()
        default_tenant_id = configured or DEFAULT_TENANT_ID
        if not is_tenant_id_safe(default_tenant_id):
            raise TenantResolutionError("invalid_configured_tenant")
        return TenancyConfig(
            mode=mode,
            default_tenant_id=default_tenant_id,
            allowed_tenants=frozenset({default_tenant_id}),
        )

    raw_allowed = (cfg.get(ENV_ALLOWED_TENANTS) or "").strip()
    allowed = frozenset(part.strip() for part in raw_allowed.split(",") if part.strip())
    if not allowed:
        raise TenantResolutionError("multi_mode_requires_allowlist")
    if not all(is_tenant_id_safe(tenant) for tenant in allowed):
        raise TenantResolutionError("invalid_allowed_tenant")
    return TenancyConfig(mode=mode, default_tenant_id=None, allowed_tenants=allowed)


def resolve_tenant(
    *, claim_tenant_id: str | None, config: TenancyConfig
) -> TenantContext:
    """Resolve the one :class:`TenantContext` a request may act within — fail closed (issue #65).

    ``claim_tenant_id`` is the caller's tenant from its VALIDATED token (the Entra ``tid`` claim),
    or ``None`` on the deliberate no-auth local/dev path.

    * ``single`` mode — resolves to the configured tenant. A present claim MUST equal it (a token
      minted for a different directory is denied, ``tenant_mismatch``); an absent claim is served as
      the single configured tenant.
    * ``multi`` mode — the claim is REQUIRED (an absent/ambiguous tenant is denied, never guessed)
      and MUST be on the allowlist (``tenant_not_allowed`` otherwise).

    Raises :class:`TenantResolutionError` (reason code only) on any ambiguity — the API maps it to a
    fail-closed 403.
    """
    if config.mode is TenancyMode.single:
        default = config.default_tenant_id
        if default is None:  # pragma: no cover - build_tenancy_config always sets it in single mode
            raise TenantResolutionError("single_mode_unconfigured")
        if claim_tenant_id is not None and claim_tenant_id != default:
            raise TenantResolutionError("tenant_mismatch")
        return TenantContext(tenant_id=default, mode=TenancyMode.single)

    if claim_tenant_id is None:
        raise TenantResolutionError("tenant_required")
    if claim_tenant_id not in config.allowed_tenants:
        raise TenantResolutionError("tenant_not_allowed")
    return TenantContext(tenant_id=claim_tenant_id, mode=TenancyMode.multi)
