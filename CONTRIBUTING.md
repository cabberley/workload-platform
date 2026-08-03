# Contributing

## Workflow

1. **One issue = one PR.** Pick or file an issue using a template in
   `.github/ISSUE_TEMPLATE/`. Keep scope to a single module or pack.
2. **Branch** from `main` as `chabberl/<topic>` (or `<agent>/<topic>` for agent branches).
3. **Let the right skill do the work** — see `skills/`. Each skill encodes house style and
   guardrails for its area (packs, modules, infra, tests, dashboards, security, docs, release).
4. **Open a PR** using the template. CI must be green and a human must approve before merge.
5. **Squash‑merge** with a clean title; delete the branch.

## Local development

```bash
python -m venv .venv
. .venv/Scripts/activate                 # PowerShell: .venv\Scripts\Activate.ps1
pip install -e .[dev]
$env:PYTHONPATH = "src"                   # bash: export PYTHONPATH=src

ruff check src tests                       # lint
mypy src                                   # types
pytest -q                                  # tests (pure logic, no Azure needed)
python scripts/validate_packs.py content   # pack schema + signature
```

Run the whole stack locally:

```bash
docker compose -f infra/local/docker-compose.yml up --build
# API on http://localhost:8000/api/health, Web on http://localhost:5173
```

## Coding standards

- **Python 3.11+**, typed everywhere; Pydantic models for all contracts.
- **Pure logic ⟂ I/O**: detection/scoring/graph math are pure and unit‑tested; Azure SDK calls
  are isolated at module edges behind small clients.
- **Keyless**: use `DefaultAzureCredential` / Managed Identity; never read secrets from code.
- **`ruff`** for lint+format, **`mypy`** for types, **`pytest`** for tests. Config in
  `pyproject.toml`.
- Modules must not import each other; they communicate through the API core and packs.

## Commit messages

Conventional style (`feat:`, `fix:`, `docs:`, `infra:`, `pack:`…). Agent commits include:

```
Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>
```

## Adding a module

1. Copy an existing skeleton under `src/modules/`.
2. Implement `Module` from `src/shared/module_base.py`.
3. Author `manifest.yaml` with a real `scaleProfile`.
4. Register it in the API module registry.
5. Add unit tests and an infra entry so it deploys as its own scalable ACA resource.

## Adding a pack

Use the `pack-author` (or `workload-author` / `dependency-author`) skill. Validate with
`scripts/validate_packs.py` and sign before release. Never embed customer data.
