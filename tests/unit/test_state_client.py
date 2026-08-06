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


# --------------------------------------------------------------------------------------
# FIX 3 (issue #37) — the worker's pack-assignment fetch is FAIL-CLOSED. A SUCCESSFUL read
# (200 + a well-formed JSON list) is authoritative — an empty list means "genuinely unassigned"
# and the run proceeds (resolver falls back to latest per id). A FAILURE (transport error,
# non-2xx, or a malformed/wrong-shape body) must NOT be read as "unassigned": the worker fails
# closed (exits non-zero) rather than silently running fallback packs of an unintended version.
# --------------------------------------------------------------------------------------
def _wire_worker(monkeypatch, get_handler):
    """Patch the worker's boundary deps and its HTTP GET/POST, recording whether a module ran."""
    import cli.worker as worker

    calls: dict[str, object] = {"run": 0, "post": 0}

    class _FakeReader:
        def __init__(self, *, base_url: str | None = None, **_kw: object) -> None:
            pass

    def _fake_run_module(module, *, scope=None, state=None, packs=None, clients=None):
        from shared.contracts import ModuleRunResult

        calls["run"] = int(calls["run"]) + 1  # type: ignore[arg-type]
        return ModuleRunResult(module=module.name, ok=True)

    def _fake_post(url, *, json=None, timeout=None):
        calls["post"] = int(calls["post"]) + 1  # type: ignore[arg-type]
        return httpx.Response(200, request=httpx.Request("POST", url))

    monkeypatch.setenv("WP_API_BASE_URL", "http://api")
    monkeypatch.setattr(worker, "ApiStateReader", _FakeReader)
    monkeypatch.setattr(worker, "build_packs_engine", lambda: object())
    monkeypatch.setattr(worker, "build_client_registry", lambda: {})
    monkeypatch.setattr(worker, "run_module", _fake_run_module)
    monkeypatch.setattr(httpx, "get", get_handler)
    monkeypatch.setattr(httpx, "post", _fake_post)
    return worker, calls


def test_worker_proceeds_when_assignments_200_empty(monkeypatch):
    # 200 + [] ⇒ genuinely unassigned ⇒ the run proceeds (resolver falls back to latest per id).
    worker, calls = _wire_worker(
        monkeypatch,
        lambda url, timeout=None: httpx.Response(200, json=[], request=httpx.Request("GET", url)),
    )
    rc = worker.main(["--module", "quality_checks", "--scope", "workload=epic"])
    assert rc == 0
    assert calls["run"] == 1  # the module ran normally
    assert calls["post"] == 1  # and its result was posted back


def test_worker_fails_closed_on_connection_error(monkeypatch):
    def _boom(url, timeout=None):
        raise httpx.ConnectError("connection refused")

    worker, calls = _wire_worker(monkeypatch, _boom)
    rc = worker.main(["--module", "quality_checks", "--scope", "workload=epic"])
    assert rc != 0  # non-zero ⇒ the ACA Job surfaces the failure for retry
    assert calls["run"] == 0  # fail closed: NO fallback packs ran
    assert calls["post"] == 0


def test_worker_fails_closed_on_non_2xx(monkeypatch):
    worker, calls = _wire_worker(
        monkeypatch,
        lambda url, timeout=None: httpx.Response(503, request=httpx.Request("GET", url)),
    )
    rc = worker.main(["--module", "quality_checks", "--scope", "workload=epic"])
    assert rc != 0
    assert calls["run"] == 0
    assert calls["post"] == 0


def test_worker_fails_closed_on_malformed_body(monkeypatch):
    # 200 but the body is not a list of assignment rows ⇒ malformed ⇒ fail closed.
    worker, calls = _wire_worker(
        monkeypatch,
        lambda url, timeout=None: httpx.Response(
            200, json={"not": "a list"}, request=httpx.Request("GET", url)
        ),
    )
    rc = worker.main(["--module", "quality_checks", "--scope", "workload=epic"])
    assert rc != 0
    assert calls["run"] == 0
    assert calls["post"] == 0


def test_worker_proceeds_on_valid_assignment_list(monkeypatch):
    # A well-formed 200 list of valid rows ⇒ the run proceeds (resolution happens, module runs).
    rows = [{"packId": "waf-reliability-baseline", "version": "1.0.0"}]
    worker, calls = _wire_worker(
        monkeypatch,
        lambda url, timeout=None: httpx.Response(200, json=rows, request=httpx.Request("GET", url)),
    )
    rc = worker.main(["--module", "quality_checks", "--scope", "workload=epic"])
    assert rc == 0
    assert calls["run"] == 1
    assert calls["post"] == 1


@pytest.mark.parametrize(
    "rows",
    [
        pytest.param([{"packId": None, "version": "1.0.0"}], id="null-packId"),
        pytest.param([{"packId": "waf", "version": None}], id="null-version"),
        pytest.param([{"packId": ["a"], "version": "1.0.0"}], id="list-valued-packId"),
        pytest.param([{"packId": "waf", "version": {"v": 1}}], id="dict-valued-version"),
        pytest.param([{"packId": "", "version": "1.0.0"}], id="empty-packId"),
        pytest.param([{"packId": "waf", "version": ""}], id="empty-version"),
        pytest.param([{"packId": "waf", "version": "banana"}], id="non-semver-version"),
        pytest.param(
            [
                {"packId": "waf", "version": "1.0.0"},
                {"packId": "waf", "version": "2.0.0"},
            ],
            id="duplicate-packId",
        ),
    ],
)
def test_worker_fails_closed_on_invalid_assignment_rows(monkeypatch, rows):
    # Strict row-value validation: null/empty/container/non-semver/duplicate values must FAIL the
    # worker closed (non-zero) and NEVER coerce into a silently-pinned reference — no module runs.
    worker, calls = _wire_worker(
        monkeypatch,
        lambda url, timeout=None: httpx.Response(200, json=rows, request=httpx.Request("GET", url)),
    )
    rc = worker.main(["--module", "quality_checks", "--scope", "workload=epic"])
    assert rc != 0
    assert calls["run"] == 0
    assert calls["post"] == 0
