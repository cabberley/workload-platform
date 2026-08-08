"""Re-export of the shared pure grounding gate (issue #54; MED-2 durable-boundary hardening).

The grounding gate itself lives in :mod:`shared.rca_grounding` so the persistence boundary
(:func:`shared.contracts.build_rca_advisories`) can RE-RUN the exact same no-hallucination check
when materialising a worker-supplied advisory - a caller/worker token must never inject ungrounded
text that is then persisted and served as "grounded". ``shared`` cannot import a module, so the gate
was moved there and this module simply re-exports it.

The aiops edge (:mod:`modules.aiops.connectors.rca_explanation`) and its tests keep importing
``ground_or_reject`` (etc.) from THIS module - module isolation holds because importing ``shared.*``
from a module is allowed, and ``shared.rca_grounding`` imports no module.
"""
from __future__ import annotations

from shared.rca_grounding import (
    MAX_ADVISORY_CHARS,
    MAX_RCA_ADVISORIES,
    MAX_SOURCE_REFERENCES,
    candidate_entity_tokens,
    evidence_corpus,
    ground_or_reject,
    is_grounded,
)

__all__ = [
    "MAX_ADVISORY_CHARS",
    "MAX_RCA_ADVISORIES",
    "MAX_SOURCE_REFERENCES",
    "candidate_entity_tokens",
    "evidence_corpus",
    "ground_or_reject",
    "is_grounded",
]
