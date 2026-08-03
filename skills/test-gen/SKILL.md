---
name: test-gen
description: Generate fast, Azure-free unit tests for module logic, pack evaluation, blast-radius math and contracts. Use with every feature PR. Enforces pure-logic testing with synthetic fixtures only.
---

# Skill: test-gen

No feature merges without a test. Tests are **pure and fast** — they never touch Azure or the
network, because module logic is separated from I/O.

## What to test
- **Pure functions**: `classify`, `evaluate_rule`, `compute_impact` / `blast_radius`,
  `detect_metric_breach`, `correlate_rca`, `weight_by_blast_radius`, `route`, `diff_findings`.
- **Contracts**: `AgentResponse` and pack/manifest models round-trip and reject bad input.
- **Packs**: schema validity + signature verify/fail-closed.

## Conventions
- Location: `tests/unit/test_<area>.py`; `PYTHONPATH=src` (configured in `pyproject.toml`).
- **Synthetic fixtures only** — clearly-fake ids/names, never PHI/PII or customer data.
- Cover the **fail-closed** branch (invalid signature, low confidence, missing evidence), not just
  the happy path.
- Keep each test deterministic and independent.

## Example
```python
from shared.contracts import WorkloadGraph, ResourceNode, DependencyEdge, EdgeType
from shared.blast_radius import blast_radius

def test_odb_is_spof():
    g = WorkloadGraph(
        nodes=[ResourceNode(id="odb", name="odb", type="vm"),
               ResourceNode(id="ecp1", name="ecp1", type="vm")],
        edges=[DependencyEdge(source="ecp1", target="odb", type=EdgeType.depends_on)],
    )
    assert blast_radius(g, "odb") == 1
```

## Definition of done
- [ ] New/changed logic covered, incl. a fail-closed case
- [ ] `pytest -q` green; no network/Azure calls
