"""Read-only connectors that feed the AIOps module.

Connectors isolate all network I/O behind a thin edge and expose a **pure** mapping from a raw
provider payload to a compact, PII-safe :class:`Signal`. They never import sibling modules and
never carry free-text / body fields across the boundary.
"""
from __future__ import annotations

from modules.aiops.connectors.system_pulse import (
    FetchResult,
    Signal,
    SignalMappingError,
    SignalSource,
    SystemPulseClient,
    SystemPulseConfig,
    map_signal,
    to_signals,
    to_source_reference,
)

__all__ = [
    "FetchResult",
    "Signal",
    "SignalMappingError",
    "SignalSource",
    "SystemPulseClient",
    "SystemPulseConfig",
    "map_signal",
    "to_signals",
    "to_source_reference",
]
