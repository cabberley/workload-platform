"""Azure Resource Graph (ARG) edge client for the Discovery module.

This is the *only* place in Discovery that touches the Azure SDK. Everything above it
(``classify`` and the row → :class:`ResourceNode` mapping) is a **pure function** that is fully
unit-tested without Azure. The module looks its client up by the well-known name
``"resource_graph"`` in ``ctx.clients`` and casts to the :class:`ResourceGraphClient` Protocol here,
so ``shared`` never learns about ARG and pure logic never does I/O.

Guardrails honored:

* **Keyless.** The real client authenticates with ``DefaultAzureCredential`` (Managed Identity in
  Azure; developer identity locally). No keys, secrets, or connection strings anywhere.
* **Least privilege.** ARG is read-only; the client's identity needs only the **Reader** role on
  the queried scope (subscription / management group). It never writes to customer infrastructure.
* **Guarded import.** The ``azure-mgmt-resourcegraph`` / ``azure-identity`` SDKs are imported
  **lazily inside** the constructor/method (mirroring ``shared.state``). Importing this module
  therefore never requires the azure packages, so ``mypy src`` and the pure unit tests stay green
  without the SDK installed. Fail closed with an actionable message if it is missing.
* **Fail closed.** Malformed rows are surfaced by the caller (skipped, never guessed at); the pure
  mapping raises rather than fabricating a node.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, Protocol, cast, runtime_checkable

from shared.contracts import ResourceNode

# A page-fetcher: given the current ``skip_token`` (``None`` for the first page), return that page's
# rows plus the NEXT ``skip_token`` (``None``/empty when the last page has been reached). The real
# client implements this over azure-mgmt-resourcegraph; tests implement it with synthetic pages —
# so the paging loop below is fully unit-testable without the Azure SDK.
PageFetcher = Callable[[str | None], "tuple[list[Mapping[str, Any]], str | None]"]

# ARG caps a single response page at 1,000 rows; a hard ceiling on loop iterations is a defensive
# guard against a backend that never clears ``skip_token`` (fail closed rather than loop forever).
_MAX_PAGES = 10_000

# The KQL projection we ask ARG for. We deliberately request only id/name/type/tags — no bodies,
# no configuration, no PII — so nothing sensitive is ever pulled across the edge.
DEFAULT_ARG_QUERY = "Resources | project id, name, type, tags"

# Scope keys understood by the real client. Values are Azure ids (subscription GUID / management
# group id). Absent/empty scope ⇒ tenant-wide (subject to the identity's Reader assignments).
SCOPE_SUBSCRIPTION = "subscription"
SCOPE_MANAGEMENT_GROUP = "managementGroup"


@runtime_checkable
class ResourceGraphClient(Protocol):
    """Narrow read-only seam over Azure Resource Graph.

    A single method returns raw resource rows (``id``, ``name``, ``type``, ``tags``). The concrete
    implementation is injected at the process boundary via ``ctx.clients["resource_graph"]``; unit
    tests inject a fake that returns synthetic rows. Keeping the surface this small is what lets the
    module stay Azure-free and fully unit-tested.
    """

    def query(self, scope: Mapping[str, str]) -> list[Mapping[str, Any]]:
        """Return raw resource rows for ``scope``. Implementations must not raise on empty scope."""
        ...


class RowMappingError(ValueError):
    """Raised when a raw ARG row cannot be mapped to a node — surfaced, never fabricated over."""


class ResourceGraphPagingError(RuntimeError):
    """Raised when ARG paging cannot complete — refuse a partial estate (fail closed).

    A partial page set flows to ``run()`` as a truthy list and could OVERWRITE the complete
    persisted estate. Treating incomplete paging as a failure lets ``run()``'s handler return
    ``estate=None`` (don't clobber) instead of silently truncating the estate.
    """


def _coerce_tags(value: Any) -> dict[str, str]:
    """Best-effort normalize an ARG ``tags`` value to ``dict[str, str]``.

    ARG returns ``tags`` as an object or ``null``. Non-dict/absent ⇒ ``{}`` (a resource with no
    tags is valid, not malformed). Tag keys/values are stringified defensively.
    """
    if not isinstance(value, Mapping):
        return {}
    return {str(k): str(v) for k, v in value.items() if v is not None}


def row_to_node(row: Mapping[str, Any]) -> ResourceNode:
    """Pure map: one raw ARG row → an **unclassified** :class:`ResourceNode`.

    Requires ``id``, ``name`` and ``type`` (ARG always projects these for a real resource). A row
    missing any of them, or with a blank id/type, is malformed and raises :class:`RowMappingError`
    so the caller can fail closed (skip + surface) rather than emit a junk node. ``workload`` /
    ``tier`` / ``role`` are intentionally left ``None`` here — classification is applied later by
    the pure ``classify`` step using Workload Definition packs. Unknown resource types therefore
    still become nodes; they simply stay unclassified.
    """
    if not isinstance(row, Mapping):
        raise RowMappingError(f"row is not a mapping: {type(row).__name__}")
    try:
        rid = row["id"]
        name = row["name"]
        rtype = row["type"]
    except KeyError as exc:
        raise RowMappingError(f"missing required field: {exc.args[0]}") from exc
    if not isinstance(rid, str) or not rid.strip():
        raise RowMappingError(f"invalid resource id: {rid!r}")
    if not isinstance(rtype, str) or not rtype.strip():
        raise RowMappingError(f"invalid resource type: {rtype!r}")
    if name is None:
        raise RowMappingError("missing resource name")
    return ResourceNode(id=rid, name=str(name), type=rtype, tags=_coerce_tags(row.get("tags")))


def rows_to_nodes(rows: list[Mapping[str, Any]]) -> tuple[list[ResourceNode], list[str]]:
    """Pure map a batch of raw rows → (nodes, skipped) — malformed rows are skipped and reported.

    Returns the successfully mapped nodes plus a list of human-readable reasons for each skipped
    row (fail closed: a bad row never becomes a node and never crashes the run). No row content is
    echoed into the reasons beyond the error class message, keeping the surface PII-free.
    """
    nodes: list[ResourceNode] = []
    skipped: list[str] = []
    for index, row in enumerate(rows):
        try:
            nodes.append(row_to_node(row))
        except RowMappingError as exc:
            skipped.append(f"row[{index}]: {exc}")
    return nodes, skipped


def collect_pages(fetch_page: PageFetcher) -> list[Mapping[str, Any]]:
    """Pure paging loop: drive ``fetch_page`` until the ``skip_token`` is exhausted.

    Aggregates rows across every ARG page (ARG caps a page at 1,000 rows) so a large estate is
    never truncated. Kept free of the Azure SDK so the loop is unit-testable with a synthetic
    fetcher. Non-mapping rows are filtered defensively.

    Fails closed by raising :class:`ResourceGraphPagingError` rather than returning a partial
    estate when (a) ``_MAX_PAGES`` is reached with a ``skip_token`` still present, or (b) the
    backend returns the **same** ``skip_token`` twice (a non-advancing/stuck loop). Either way the
    caller must treat the run as failed (``estate=None``), never overwrite state with partial rows.
    """
    rows: list[Mapping[str, Any]] = []
    skip_token: str | None = None
    seen_tokens: set[str] = set()
    for _ in range(_MAX_PAGES):
        page, skip_token = fetch_page(skip_token)
        rows.extend(row for row in page if isinstance(row, Mapping))
        if not skip_token:
            return rows
        if skip_token in seen_tokens:
            raise ResourceGraphPagingError(
                "ARG paging returned a repeating skip_token — refusing partial estate"
            )
        seen_tokens.add(skip_token)
    raise ResourceGraphPagingError(
        "ARG paging exceeded _MAX_PAGES with token still present — refusing partial estate"
    )


class AzureResourceGraphClient:
    """Real keyless ARG client. All SDK access is lazily imported inside methods (guarded import).

    RBAC: the injected identity needs only **Reader** on the queried scope — ARG is read-only and
    this client never mutates customer infrastructure (least privilege).

    The ``azure-mgmt-resourcegraph`` / ``azure-identity`` SDKs are optional at import time: nothing
    is imported until :meth:`query` runs, so ``import modules.discovery.arg`` (and hence the module
    and its pure tests) never needs them. If they are absent we fail closed with an actionable
    message instead of a bare ``ImportError``.
    """

    def __init__(self, *, credential: object | None = None, client: object | None = None) -> None:
        # ``credential``/``client`` are injectable purely so an integration test can pass mocked
        # SDK objects; production leaves them ``None`` and resolves Managed Identity lazily.
        self._credential = credential
        self._client = client

    def _ensure_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.resourcegraph import ResourceGraphClient as _ArgSdkClient
        except ImportError as exc:  # pragma: no cover - exercised only without the optional SDK
            raise RuntimeError(
                "Azure Resource Graph discovery needs 'azure-mgmt-resourcegraph' and "
                "'azure-identity'. Install them (they ship with the base image) or inject a "
                "ResourceGraphClient fake in tests."
            ) from exc
        credential = self._credential or DefaultAzureCredential()
        self._client = _ArgSdkClient(cast(Any, credential))
        return self._client

    def _make_fetch_page(self, scope: Mapping[str, str]) -> PageFetcher:
        """Build the real page-fetcher over azure-mgmt-resourcegraph (azure imports stay lazy).

        TODO(human): honor 429/``Retry-After`` throttling back-off inside this fetcher for very
        large estates; the paging loop itself is already complete.
        """
        from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions

        client = self._ensure_client()
        subscriptions: list[str] | None = None
        management_groups: list[str] | None = None
        if scope.get(SCOPE_SUBSCRIPTION):
            subscriptions = [scope[SCOPE_SUBSCRIPTION]]
        if scope.get(SCOPE_MANAGEMENT_GROUP):
            management_groups = [scope[SCOPE_MANAGEMENT_GROUP]]

        def fetch_page(skip_token: str | None) -> tuple[list[Mapping[str, Any]], str | None]:
            request = QueryRequest(
                query=DEFAULT_ARG_QUERY,
                subscriptions=subscriptions,
                management_groups=management_groups,
                options=QueryRequestOptions(result_format="objectArray", skip_token=skip_token),
            )
            response = client.resources(request)
            data = getattr(response, "data", None) or []
            next_token = getattr(response, "skip_token", None) or None
            return list(data), next_token

        return fetch_page

    def query(self, scope: Mapping[str, str]) -> list[Mapping[str, Any]]:
        """Run the read-only ARG projection for ``scope``, paging through **all** results.

        Loops on the response ``skip_token`` so a large estate (>1,000 rows) is returned in full
        rather than truncated to the first page.
        """
        return collect_pages(self._make_fetch_page(scope))
