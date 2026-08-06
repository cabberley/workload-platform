"""Read-only edge connectors that *assist* Discovery (never authoritative over ARG).

Discovery's source of truth is Azure Resource Graph (see ``modules.discovery.arg``). A connector in
this package only **augments** that estate with clearly-marked, non-authoritative *supplemental*
signals — and only by **annotating resources ARG already discovered**, never by creating nodes or
edges. Each connector is **read-only**, **keyless**, **fail-closed-by-default**, **bounded**, and
free of any Azure/vendor SDK at import time — built on the shared base in :mod:`shared.connectors`.

* **Kuiper** — Epic *Kuiper* discovery assist (this package's :mod:`kuiper`). Fail-closed by
  default: the concrete Kuiper endpoint/payload/auth are an external dependency owned by the product
  team, so the connector stays unavailable until a human wires an APPROVED https endpoint. Even once
  wired it only adds a bounded, fixed-vocabulary supplemental tag to an existing ARG node.
"""
from __future__ import annotations

from modules.discovery.connectors.kuiper import (
    ALLOWED_SIGNALS,
    DEFAULT_TOKEN_ENV,
    HINT_KIND,
    MAX_RESOURCE_ID_LEN,
    SUPPLEMENTAL_SIGNAL_TAG,
    SUPPLEMENTAL_SOURCE,
    SUPPLEMENTAL_SOURCE_TAG,
    InvalidKuiperEndpoint,
    KuiperClient,
    KuiperConfig,
    KuiperConnector,
    KuiperDeadlineExceeded,
    KuiperEndpointError,
    KuiperEndpointNotApproved,
    KuiperHint,
    KuiperHintError,
    KuiperResponseTooLarge,
    SupplementalResult,
    apply_supplemental,
    hints_from_result,
    parse_hints_atomic,
    to_source_reference,
    validate_endpoint,
    validate_hint,
)

__all__ = [
    "ALLOWED_SIGNALS",
    "DEFAULT_TOKEN_ENV",
    "HINT_KIND",
    "MAX_RESOURCE_ID_LEN",
    "SUPPLEMENTAL_SIGNAL_TAG",
    "SUPPLEMENTAL_SOURCE",
    "SUPPLEMENTAL_SOURCE_TAG",
    "InvalidKuiperEndpoint",
    "KuiperClient",
    "KuiperConfig",
    "KuiperConnector",
    "KuiperDeadlineExceeded",
    "KuiperEndpointError",
    "KuiperEndpointNotApproved",
    "KuiperHint",
    "KuiperHintError",
    "KuiperResponseTooLarge",
    "SupplementalResult",
    "apply_supplemental",
    "hints_from_result",
    "parse_hints_atomic",
    "to_source_reference",
    "validate_endpoint",
    "validate_hint",
]
