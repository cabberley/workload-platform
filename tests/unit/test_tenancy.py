"""Pure unit tests for the tenant partition-key logic + fail-closed resolution (issue #65).

Everything here is Azure-free, I/O-free, and keyless — it exercises ONLY the pure functions and the
config/resolution decision layer in :mod:`api.app.tenancy`. No storage, no network, no real Entra.
Tenant ids used are clearly-fake directory identifiers, never PHI/PII.
"""
from __future__ import annotations

import pytest

from api.app.tenancy import (
    DEFAULT_TENANT_ID,
    ENV_ALLOWED_TENANTS,
    ENV_TENANCY_MODE,
    ENV_TENANT_ID,
    TenantResolutionError,
    build_tenancy_config,
    partition_belongs_to,
    partition_prefix,
    resolve_tenant,
    split_partition_key,
    tenant_partition_key,
    workload_of,
)
from shared.contracts import TenancyMode, TenantContext

TENANT_A = "00000000-0000-0000-0000-00000000000a"
TENANT_B = "00000000-0000-0000-0000-00000000000b"


# --------------------------------------------------------------------------------------
# Pure partition-key logic — deterministic, reversible, isolating.
# --------------------------------------------------------------------------------------
def test_partition_key_is_deterministic() -> None:
    assert tenant_partition_key(TENANT_A, "epic") == tenant_partition_key(TENANT_A, "epic")


def test_partition_key_round_trips() -> None:
    key = tenant_partition_key(TENANT_A, "epic")
    assert split_partition_key(key) == (TENANT_A, "epic")


def test_round_trip_survives_workload_with_dots() -> None:
    """The workload name may itself contain the delimiter; the split must still be unambiguous."""
    workload = "epic.prod.v2"
    key = tenant_partition_key(TENANT_A, workload)
    assert split_partition_key(key) == (TENANT_A, workload)


def test_two_tenants_same_workload_are_disjoint() -> None:
    """The core isolation invariant: a shared workload NAME maps to DISJOINT physical keys."""
    a = tenant_partition_key(TENANT_A, "epic")
    b = tenant_partition_key(TENANT_B, "epic")
    assert a != b
    assert not partition_belongs_to(a, TENANT_B)
    assert not partition_belongs_to(b, TENANT_A)
    assert partition_belongs_to(a, TENANT_A)


def test_prefix_is_hex_and_contains_no_separator() -> None:
    prefix = partition_prefix(TENANT_A)
    assert prefix.endswith(".")
    hex_part = prefix[:-1]
    assert all(ch in "0123456789abcdef" for ch in hex_part)


def test_workload_of_returns_logical_for_owning_tenant() -> None:
    key = tenant_partition_key(TENANT_A, "epic")
    assert workload_of(key, TENANT_A) == "epic"


def test_workload_of_denies_other_tenant_by_default() -> None:
    """A key from another tenant yields None (deny-by-default read filter)."""
    key = tenant_partition_key(TENANT_A, "epic")
    assert workload_of(key, TENANT_B) is None


def test_partition_prefix_fails_closed_on_unsafe_tenant() -> None:
    with pytest.raises(ValueError):
        partition_prefix("bad/tenant")  # path separator is not storage-safe


def test_split_fails_closed_on_non_scoped_key() -> None:
    with pytest.raises(ValueError):
        split_partition_key("nodelimiterhere")


def test_split_fails_closed_on_malformed_hex_prefix() -> None:
    with pytest.raises(ValueError):
        split_partition_key("zz.epic")  # 'zz' is not valid hex


# --------------------------------------------------------------------------------------
# build_tenancy_config — keyless, fail-closed.
# --------------------------------------------------------------------------------------
def test_config_defaults_to_single_default_tenant() -> None:
    cfg = build_tenancy_config({})
    assert cfg.mode is TenancyMode.single
    assert cfg.default_tenant_id == DEFAULT_TENANT_ID
    assert cfg.allowed_tenants == frozenset({DEFAULT_TENANT_ID})


def test_config_single_uses_configured_tenant() -> None:
    cfg = build_tenancy_config({ENV_TENANT_ID: TENANT_A})
    assert cfg.mode is TenancyMode.single
    assert cfg.default_tenant_id == TENANT_A


def test_config_single_falls_back_to_auth_tenant() -> None:
    cfg = build_tenancy_config({"WP_AUTH_TENANT_ID": TENANT_A})
    assert cfg.default_tenant_id == TENANT_A


def test_config_multi_reads_allowlist() -> None:
    cfg = build_tenancy_config(
        {ENV_TENANCY_MODE: "multi", ENV_ALLOWED_TENANTS: f"{TENANT_A}, {TENANT_B}"}
    )
    assert cfg.mode is TenancyMode.multi
    assert cfg.default_tenant_id is None
    assert cfg.allowed_tenants == frozenset({TENANT_A, TENANT_B})


def test_config_multi_without_allowlist_fails_closed() -> None:
    with pytest.raises(TenantResolutionError):
        build_tenancy_config({ENV_TENANCY_MODE: "multi"})


def test_config_multi_with_blank_allowlist_fails_closed() -> None:
    with pytest.raises(TenantResolutionError):
        build_tenancy_config({ENV_TENANCY_MODE: "multi", ENV_ALLOWED_TENANTS: " , "})


def test_config_unknown_mode_fails_closed() -> None:
    with pytest.raises(TenantResolutionError):
        build_tenancy_config({ENV_TENANCY_MODE: "wide-open"})


def test_config_rejects_unsafe_configured_tenant() -> None:
    with pytest.raises(TenantResolutionError):
        build_tenancy_config({ENV_TENANT_ID: "bad/tenant"})


def test_config_multi_rejects_unsafe_allowed_tenant() -> None:
    with pytest.raises(TenantResolutionError):
        build_tenancy_config({ENV_TENANCY_MODE: "multi", ENV_ALLOWED_TENANTS: "bad/tenant"})


# --------------------------------------------------------------------------------------
# resolve_tenant — the fail-closed matrix.
# --------------------------------------------------------------------------------------
def test_single_absent_claim_resolves_to_default() -> None:
    """No token (local/dev path) is served AS the one configured tenant."""
    cfg = build_tenancy_config({ENV_TENANT_ID: TENANT_A})
    ctx = resolve_tenant(claim_tenant_id=None, config=cfg)
    assert ctx == TenantContext(tenant_id=TENANT_A, mode=TenancyMode.single)


def test_single_matching_claim_is_allowed() -> None:
    cfg = build_tenancy_config({ENV_TENANT_ID: TENANT_A})
    ctx = resolve_tenant(claim_tenant_id=TENANT_A, config=cfg)
    assert ctx.tenant_id == TENANT_A


def test_single_mismatched_claim_fails_closed() -> None:
    """A token minted for a DIFFERENT directory is denied in single mode."""
    cfg = build_tenancy_config({ENV_TENANT_ID: TENANT_A})
    with pytest.raises(TenantResolutionError):
        resolve_tenant(claim_tenant_id=TENANT_B, config=cfg)


def test_multi_requires_claim() -> None:
    """multi overlay: an absent tenant is denied — never guessed as a default."""
    cfg = build_tenancy_config(
        {ENV_TENANCY_MODE: "multi", ENV_ALLOWED_TENANTS: f"{TENANT_A},{TENANT_B}"}
    )
    with pytest.raises(TenantResolutionError, match="^tenant_required$"):
        resolve_tenant(claim_tenant_id=None, config=cfg)


def test_multi_allowed_claim_is_resolved() -> None:
    cfg = build_tenancy_config(
        {ENV_TENANCY_MODE: "multi", ENV_ALLOWED_TENANTS: f"{TENANT_A},{TENANT_B}"}
    )
    ctx = resolve_tenant(claim_tenant_id=TENANT_B, config=cfg)
    assert ctx == TenantContext(tenant_id=TENANT_B, mode=TenancyMode.multi)


def test_multi_offlist_claim_fails_closed() -> None:
    cfg = build_tenancy_config({ENV_TENANCY_MODE: "multi", ENV_ALLOWED_TENANTS: TENANT_A})
    with pytest.raises(TenantResolutionError, match="^tenant_not_allowed$"):
        resolve_tenant(claim_tenant_id=TENANT_B, config=cfg)


def test_multi_host_tenant_token_is_denied() -> None:
    """A shared-worker/host-identity token (host tid NOT on the allowlist) is denied (issue #65).

    Regression guard for the multi-overlay worker path (ADR 0017 "Known limitation", follow-up
    #122): the worker runs as the platform identity, so its ``tid`` is the deployment/host tenant.
    If that host tenant is not on ``WP_ALLOWED_TENANTS`` (the enforced default), resolution FAILS
    CLOSED — the worker can never silently write into a client tenant's partition.
    """
    host_tenant = "00000000-0000-0000-0000-0000000000ff"
    cfg = build_tenancy_config(
        {ENV_TENANCY_MODE: "multi", ENV_ALLOWED_TENANTS: f"{TENANT_A},{TENANT_B}"}
    )
    assert host_tenant not in cfg.allowed_tenants
    with pytest.raises(TenantResolutionError, match="^tenant_not_allowed$"):
        resolve_tenant(claim_tenant_id=host_tenant, config=cfg)


def test_resolution_error_carries_no_pii() -> None:
    """A resolution failure exposes a fixed reason code only — never the tenant id."""
    cfg = build_tenancy_config({ENV_TENANT_ID: TENANT_A})
    try:
        resolve_tenant(claim_tenant_id=TENANT_B, config=cfg)
    except TenantResolutionError as exc:
        assert TENANT_B not in str(exc)
        assert str(exc) == "tenant_mismatch"
    else:  # pragma: no cover
        pytest.fail("expected TenantResolutionError")
