"""Tests for the service entrypoint's WP_MODULE dispatch selection (pure, Azure-free)."""
import pytest

from cli.serve import module_name_from_env, select_module, serve
from shared.module_base import build_default_registry


def test_module_name_from_env_reads_wp_module():
    assert module_name_from_env({"WP_MODULE": "aiops"}) == "aiops"


def test_module_name_from_env_fails_closed_when_missing():
    with pytest.raises(ValueError):
        module_name_from_env({})


def test_module_name_from_env_fails_closed_when_blank():
    with pytest.raises(ValueError):
        module_name_from_env({"WP_MODULE": "   "})


def test_select_module_resolves_service_module():
    reg = build_default_registry()
    module = select_module(reg, "alerts")
    assert module.name == "alerts"


def test_select_module_unknown_fails_closed():
    reg = build_default_registry()
    with pytest.raises(KeyError):
        select_module(reg, "does-not-exist")


def test_serve_dispatches_to_wp_module_and_is_bounded():
    calls: list[float] = []
    module = serve(
        env={"WP_MODULE": "aiops"},
        poll_seconds=0.0,
        max_iterations=2,
        sleep=calls.append,
    )
    assert module.name == "aiops"
    # One sleep between the two iterations; the loop terminates without blocking.
    assert len(calls) == 1
