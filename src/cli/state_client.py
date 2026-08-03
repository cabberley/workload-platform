"""Read-only HTTP state client — how the worker reads shared state without ever writing it.

The worker is **compute-only**: it must never hold a writable ``StateStore`` (that is the API's
exclusive job — the single-writer invariant). But some modules (reassessments, aiops, quality_
checks) need to *read* prior state — the estate, graph, findings, and the previous snapshot — to
do their work. :class:`ApiStateReader` gives them exactly that: it implements the full read-only
:class:`~shared.state.ReadableState` Protocol by GETting the API's read endpoints over HTTP.

It exposes **no write methods** by construction, so injecting it into ``run_module(state=...)`` in
the worker cannot mutate shared state — the single-writer guarantee is preserved on the worker
side purely structurally (there is nothing to write with).

Fail-closed reads (the key correctness property): a read distinguishes **UNAVAILABLE** from
**empty**. A transport/connection failure or a non-2xx (esp. 5xx) response raises
:class:`StateUnavailableError` so the caller ABORTS rather than mistaking an outage for "empty"
and fabricating false recovery in drift. A **200 with an empty list** is a legitimate empty read
and returns ``[]``. The one "absent" special case is :meth:`ApiStateReader.get_graph`: a **404**
means "no graph persisted yet" and returns ``None`` (a 5xx/transport failure still raises). No
customer data or token is ever logged — only the failing path and the error class name.
"""
from __future__ import annotations

import logging
import os
from urllib.parse import quote

import httpx

from shared.contracts import Finding, ResourceNode, WorkloadGraph

logger = logging.getLogger(__name__)

# Local-dev / docker-compose ONLY fallback: the compose service is named ``api`` on :8000
# (see infra/local/docker-compose.yml). In production the ACA app is ``wp-api`` and the worker
# job MUST have ``WP_API_BASE_URL`` set to its internal ingress FQDN by infra (module-job.bicep) —
# production never relies on this default. Kept here (not in cli.worker) so ``cli.worker`` can
# import it without a circular dependency.
DEFAULT_API_BASE_URL = "http://api:8000"

_DEFAULT_TIMEOUT_S = 30.0


class StateUnavailableError(RuntimeError):
    """A read could not be completed because the API/state was UNAVAILABLE (not merely empty).

    Raised on a transport/connection failure or a non-2xx (esp. 5xx) response for reads whose
    result feeds drift/decisions. This is the fail-closed guardrail: callers (e.g. reassessments)
    must ABORT and surface rather than mistake an outage for "empty" and fabricate false recovery.
    A **200 with an empty list is NOT** unavailable — it is a legitimate empty result.
    """


class ApiStateReader:
    """Read-only :class:`~shared.state.ReadableState` served by the API's HTTP read endpoints.

    Construct with an explicit ``base_url`` (defaults to ``$WP_API_BASE_URL`` /
    :data:`DEFAULT_API_BASE_URL`). Inject an ``httpx.Client`` (e.g. a FastAPI ``TestClient`` or a
    client on ``httpx.MockTransport``) to test without touching the network; production leaves it
    ``None`` and a short-lived TLS-verified client is created per request.

    Fail-closed contract (see :class:`StateUnavailableError`): a transport error or non-2xx
    response raises rather than fabricating an empty result; a **200 with an empty list** is a
    legitimate empty read. The sole "absent" special case is :meth:`get_graph` — a **404** means
    "no graph persisted yet" and returns ``None`` (a 5xx/transport failure still raises).
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        client: httpx.Client | None = None,
        timeout: float = _DEFAULT_TIMEOUT_S,
    ) -> None:
        resolved = base_url or os.environ.get("WP_API_BASE_URL", DEFAULT_API_BASE_URL)
        self._base_url = resolved.rstrip("/")
        self._client = client
        self._timeout = timeout

    # -- HTTP plumbing -----------------------------------------------------------------
    def _request(self, path: str, *, params: dict[str, str] | None = None) -> httpx.Response:
        """GET ``path`` (URL-safe). Raise :class:`StateUnavailableError` on a transport failure."""
        url = f"{self._base_url}{path}"
        try:
            if self._client is not None:
                # The injected client carries its own timeout/transport config.
                return self._client.get(url, params=params)
            with httpx.Client(timeout=self._timeout, verify=True) as client:
                return client.get(url, params=params)
        except httpx.HTTPError as exc:
            logger.warning("ApiStateReader GET %s unavailable: %s", path, type(exc).__name__)
            raise StateUnavailableError(
                f"state read unavailable: GET {path} failed ({type(exc).__name__})"
            ) from exc

    def _read_json(self, path: str, *, params: dict[str, str] | None = None) -> object:
        """Return the decoded body of a 2xx response.

        Raises :class:`StateUnavailableError` on any non-2xx status (a 5xx outage, a 4xx, etc.) or
        an undecodable body — an unavailable/corrupt read must never be coerced into "empty".
        """
        response = self._request(path, params=params)
        if not (200 <= response.status_code < 300):
            raise StateUnavailableError(
                f"state read unavailable: GET {path} -> HTTP {response.status_code}"
            )
        try:
            return response.json()
        except ValueError as exc:
            raise StateUnavailableError(
                f"state read returned an undecodable body: GET {path}"
            ) from exc

    # -- ReadableState -----------------------------------------------------------------
    def list_workloads(self) -> list[str]:
        """List known workloads. Raises :class:`StateUnavailableError` if the API is unavailable."""
        data = self._read_json("/api/workloads")
        if not isinstance(data, list):
            raise StateUnavailableError("state read unavailable: /api/workloads was not a list")
        return [str(item) for item in data]

    def get_estate(self, workload: str) -> list[ResourceNode]:
        """Latest estate for ``workload`` (200 empty ⇒ ``[]``). Raises if the API is unavailable."""
        data = self._read_json(f"/api/workloads/{quote(workload, safe='')}/estate")
        if not isinstance(data, list):
            raise StateUnavailableError("state read unavailable: estate was not a list")
        try:
            return [ResourceNode.model_validate(item) for item in data]
        except Exception as exc:  # noqa: BLE001 - corrupt 200 body is unavailable, not empty
            raise StateUnavailableError(
                f"state read returned an unparseable estate for {workload!r}"
            ) from exc

    def get_graph(self, workload: str) -> WorkloadGraph | None:
        """Latest dependency graph, or ``None`` if none persisted.

        Only a **404** maps to ``None`` (absent = no graph). A transport error or any other non-2xx
        (esp. 5xx) raises :class:`StateUnavailableError` — an outage is not "no graph".
        """
        response = self._request(f"/api/workloads/{quote(workload, safe='')}/graph")
        if response.status_code == 404:
            return None
        if not (200 <= response.status_code < 300):
            raise StateUnavailableError(
                f"state read unavailable: graph -> HTTP {response.status_code}"
            )
        try:
            data = response.json()
        except ValueError as exc:
            raise StateUnavailableError("state read returned an undecodable graph body") from exc
        if not isinstance(data, dict):
            raise StateUnavailableError("state read unavailable: graph was not an object")
        try:
            return WorkloadGraph.model_validate(data)
        except Exception as exc:  # noqa: BLE001 - corrupt 200 body is unavailable, not "no graph"
            raise StateUnavailableError(
                f"state read returned an unparseable graph for {workload!r}"
            ) from exc

    def get_findings(self, workload: str, module: str | None = None) -> list[Finding]:
        """Current findings (200 empty ⇒ ``[]``). Raises if the API is unavailable.

        Distinguishing unavailable from empty is critical: a 5xx here must NOT be read as "no
        findings", or a reassessment would report every prior failure as recovered during an
        outage (false recovery). See :class:`StateUnavailableError`.
        """
        params = {"module": module} if module else None
        data = self._read_json(
            f"/api/workloads/{quote(workload, safe='')}/findings", params=params
        )
        return self._parse_findings(data, workload)

    def get_previous_findings(self, workload: str) -> list[Finding]:
        """Snapshot findings; 200-empty -> []; raises StateUnavailableError on an outage."""
        path = f"/api/workloads/{quote(workload, safe='')}/previous-findings"
        return self._parse_findings(self._read_json(path), workload)

    def get_previous_node_ids(self, workload: str) -> list[str]:
        """Snapshot estate node ids (200 empty ⇒ ``[]``). Raises if the API is unavailable."""
        data = self._read_json(f"/api/workloads/{quote(workload, safe='')}/previous-node-ids")
        if not isinstance(data, list):
            raise StateUnavailableError("state read unavailable: previous-node-ids was not a list")
        return [str(item) for item in data]

    @staticmethod
    def _parse_findings(data: object, workload: str) -> list[Finding]:
        if not isinstance(data, list):
            raise StateUnavailableError("state read unavailable: findings was not a list")
        try:
            return [Finding.model_validate(item) for item in data]
        except Exception as exc:  # noqa: BLE001 - corrupt 200 body is unavailable, not empty
            raise StateUnavailableError(
                f"state read returned unparseable findings for {workload!r}"
            ) from exc
