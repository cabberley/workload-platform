"""Read-only edge connectors that *supplement* the Dependency & Blast Radius module.

The dependency_graph module's source of truth is the authoritative estate (Azure Resource Graph via
Discovery) plus auto-derived (network topology) and signed **Dependency Pack** edges. A connector in
this package only **augments** that graph with clearly-marked, non-authoritative *supplemental*
signals — and only by **annotating resources the estate already discovered**, never by creating
nodes. Each connector is **read-only**, **keyless**, **fail-closed-by-default**, **bounded**, and
free of any Azure/vendor SDK at import time — built on the shared base in :mod:`shared.connectors`.

* **Citrix** — Citrix control-plane **health + dependency** signals (this package's :mod:`citrix`).
  Fail-closed by default: the concrete Citrix endpoint/payload/auth are an external dependency owned
  by the product team (issue #48), so the connector stays unavailable until a human wires an
  APPROVED https endpoint. Even once wired it only adds a bounded, fixed-vocabulary supplemental
  **health** tag to an existing node; Citrix **dependency edges** are parsed into a pure,
  un-persisted mapping and deliberately DEFERRED (the module's graph is UPSERT-REPLACED, so a naive
  edge merge would wipe authoritative edges —
  see :func:`~modules.dependency_graph.connectors.citrix.dependency_edges`).
"""
from __future__ import annotations

from modules.dependency_graph.connectors.citrix import (
    ALLOWED_HEALTH,
    DEFAULT_TOKEN_ENV,
    DEPENDENCY_KIND,
    EDGE_ORIGIN,
    HEALTH_KIND,
    MAX_RESOURCE_ID_LEN,
    SUPPLEMENTAL_HEALTH_TAG,
    SUPPLEMENTAL_SOURCE,
    SUPPLEMENTAL_SOURCE_TAG,
    CitrixClient,
    CitrixConfig,
    CitrixConnector,
    CitrixDeadlineExceeded,
    CitrixDependencyHint,
    CitrixEndpointError,
    CitrixEndpointNotApproved,
    CitrixHealthHint,
    CitrixResponseTooLarge,
    CitrixSignalError,
    CitrixSignals,
    InvalidCitrixEndpoint,
    InvalidCitrixResponse,
    SupplementalResult,
    apply_supplemental,
    dependency_edges,
    parse_signals_atomic,
    signals_from_result,
    to_source_reference,
    validate_dependency_hint,
    validate_endpoint,
    validate_health_hint,
)

__all__ = [
    "ALLOWED_HEALTH",
    "DEFAULT_TOKEN_ENV",
    "DEPENDENCY_KIND",
    "EDGE_ORIGIN",
    "HEALTH_KIND",
    "MAX_RESOURCE_ID_LEN",
    "SUPPLEMENTAL_HEALTH_TAG",
    "SUPPLEMENTAL_SOURCE",
    "SUPPLEMENTAL_SOURCE_TAG",
    "CitrixClient",
    "CitrixConfig",
    "CitrixConnector",
    "CitrixDeadlineExceeded",
    "CitrixDependencyHint",
    "CitrixEndpointError",
    "CitrixEndpointNotApproved",
    "CitrixHealthHint",
    "CitrixResponseTooLarge",
    "CitrixSignalError",
    "CitrixSignals",
    "InvalidCitrixEndpoint",
    "InvalidCitrixResponse",
    "SupplementalResult",
    "apply_supplemental",
    "dependency_edges",
    "parse_signals_atomic",
    "signals_from_result",
    "to_source_reference",
    "validate_dependency_hint",
    "validate_endpoint",
    "validate_health_hint",
]
