"""Unit tests for the read-only HTTP state client and worker wiring (issue #24, round 2).

Covers the fail-closed guardrail: an API OUTAGE must NOT be read as "empty" (which would let a
reassessment report every prior failure as recovered). Uses ``httpx.MockTransport`` so no network
or server is needed. All fixtures are synthetic (no PHI/PII, no secrets).
"""
from __future__ import annotations

import httpx
import pytest

from cli.state_client import DEFAULT_API_BASE_URL, ApiStateReader, StateUnavailableError
from modules.reassessments.module import ReassessmentsModule
from shared.contracts import Finding, Severity
from shared.module_base import ModuleContext
from shared.state import ReadableState


def _reader_returning(handler) -> ApiStateReader:
    """Build an ApiStateReader whose injected client routes every GET to ``handler``."""
    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://api")
    return ApiStateReader(base_url="http://api", client=client)


# --------------------------------------------------------------------------------------
# FIX 1 — base URL comes from WP_API_BASE_URL (not a silently-wrong default).
# --------------------------------------------------------------------------------------
def test_reader_honors_wp_api_base_url_env(monkeypatch):
    monkeypatch.setenv("WP_API_BASE_URL", "https://wp-api.internal.example/")
    reader = ApiStateReader()
    # Trailing slash stripped; the deployed internal FQDN is honored (not the compose default).
    assert reader._base_url == "https://wp-api.internal.example"
    assert reader._base_url != DEFAULT_API_BASE_URL


def test_worker_composition_uses_wp_api_base_url(monkeypatch):
    import cli.worker as worker

    captured: dict[str, str | None] = {}

    class _FakeReader:
        def __init__(self, *, base_url: str | None = None, **_kw: object) -> None:
            captured["base_url"] = base_url

    def _fake_run_module(module, *, scope=None, state=None, packs=None, clients=None):
        from shared.contracts import ModuleRunResult

        return ModuleRunResult(module=module.name, ok=True)

    monkeypatch.setenv("WP_API_BASE_URL", "https://wp-api.internal.example")
    monkeypatch.setattr(worker, "ApiStateReader", _FakeReader)
    monkeypatch.setattr(worker, "build_packs_engine", lambda: None)
    monkeypatch.setattr(worker, "build_client_registry", lambda: {})
    monkeypatch.setattr(worker, "run_module", _fake_run_module)

    # No scope ⇒ no result POST; we only assert the reader was built with the env base URL.
    rc = worker.main(["--module", "discovery"])
    assert rc == 0
    assert captured["base_url"] == "https://wp-api.internal.example"


# --------------------------------------------------------------------------------------
# FIX 2 — 200 empty is EMPTY; transport/5xx is UNAVAILABLE (raises), never coerced to [].
# --------------------------------------------------------------------------------------
def test_findings_200_empty_is_empty_list():
    reader = _reader_returning(lambda req: httpx.Response(200, json=[]))
    assert reader.get_findings("epic") == []
    assert reader.get_previous_findings("epic") == []


def test_findings_5xx_raises_state_unavailable():
    reader = _reader_returning(lambda req: httpx.Response(503))
    with pytest.raises(StateUnavailableError):
        reader.get_findings("epic")
    with pytest.raises(StateUnavailableError):
        reader.get_previous_findings("epic")


def test_findings_connection_error_raises_state_unavailable():
    def _boom(_req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    reader = _reader_returning(_boom)
    with pytest.raises(StateUnavailableError):
        reader.get_findings("epic")


def test_graph_404_is_none_but_5xx_raises():
    absent = _reader_returning(lambda req: httpx.Response(404))
    assert absent.get_graph("epic") is None  # absent = no graph persisted

    down = _reader_returning(lambda req: httpx.Response(503))
    with pytest.raises(StateUnavailableError):
        down.get_graph("epic")


def test_estate_and_node_ids_5xx_raise_state_unavailable():
    reader = _reader_returning(lambda req: httpx.Response(500))
    with pytest.raises(StateUnavailableError):
        reader.get_estate("epic")
    with pytest.raises(StateUnavailableError):
        reader.get_previous_node_ids("epic")
    with pytest.raises(StateUnavailableError):
        reader.list_workloads()


# --------------------------------------------------------------------------------------
# FIX 2 (end-to-end) — a reassessment over UNAVAILABLE current-findings ABORTS, does NOT
# report false recovery. The reviewer's exact proof: previous f1 present + current outage.
# --------------------------------------------------------------------------------------
def _failing_finding() -> Finding:
    return Finding(id="f1", module="quality_checks", title="zone", passed=False,
                   severity=Severity.high, nodeId="vm1")


class _PrevFailingState:
    """Read-only state: a prior failing finding exists; the *current* findings read is UNAVAILABLE
    unless ``current`` is provided (to contrast the legitimately-empty path)."""

    def __init__(self, *, current: list[Finding] | None) -> None:
        self._current = current

    def list_workloads(self) -> list[str]:
        return ["epic"]

    def get_estate(self, workload: str):
        return []

    def get_graph(self, workload: str):
        return None

    def get_findings(self, workload: str, module: str | None = None) -> list[Finding]:
        if self._current is None:
            raise StateUnavailableError("current findings unavailable (simulated outage)")
        return self._current

    def get_previous_findings(self, workload: str) -> list[Finding]:
        return [_failing_finding()]

    def get_previous_node_ids(self, workload: str) -> list[str]:
        return ["vm1"]


def test_reassessment_aborts_when_current_findings_unavailable():
    # previous f1 failing + current-findings outage ⇒ must NOT compute "recovered=1"; it aborts.
    ctx = ModuleContext(state=_PrevFailingState(current=None))
    with pytest.raises(StateUnavailableError):
        ReassessmentsModule().run(ctx, scope={"workload": "epic"})


def test_reassessment_reports_recovery_only_on_genuinely_empty_current():
    # A genuine 200-empty current (everything fixed) DOES legitimately count as recovered.
    ctx = ModuleContext(state=_PrevFailingState(current=[]))
    result = ReassessmentsModule().run(ctx, scope={"workload": "epic"})
    summary = result.extra["summary"]
    assert summary["recovered"] == 1
    assert summary["stillFailing"] == 0


def test_state_unavailable_error_is_not_swallowed_as_readable_state():
    # Sanity: the fake satisfies the read Protocol (all six methods present).
    assert isinstance(_PrevFailingState(current=[]), ReadableState)
