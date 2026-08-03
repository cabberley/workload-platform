"""API core — FastAPI app exposing health, the module registry, and cycle orchestration.

The API is the **single writer** of shared state; modules submit results here rather than writing
concurrently. This keeps `api` at low replica counts while compute-heavy modules scale freely.
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from shared.module_base import ModuleContext, build_default_registry

app = FastAPI(
    title="Workloads Platform API",
    version="0.1.0",
    description="In-boundary control plane for discovery, quality, dependency, AIOps and alerts.",
)

registry = build_default_registry()


@app.get("/api/health")
def health() -> dict[str, object]:
    """Liveness + per-module health. Used by CI smoke and platform probes."""
    return {
        "status": "ok",
        "service": "workloads-platform-api",
        "modules": [m.health() for m in registry.enabled_modules()],
    }


@app.get("/api/modules")
def list_modules() -> list[dict[str, object]]:
    """Enumerate modules and their scale profiles (drives infra + the web console)."""
    return [m.model_dump() for m in registry.manifests()]


class RunRequest(BaseModel):
    scope: dict[str, str] = {}


@app.post("/api/modules/{name}/run")
def run_module(name: str, req: RunRequest) -> dict[str, object]:
    """Run a single module by name (also how the ACA Job worker invokes work)."""
    try:
        module = registry.get(name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    ctx = ModuleContext()
    result = module.run(ctx, scope=req.scope)
    return result.model_dump()


@app.get("/")
def root() -> dict[str, str]:
    return {"name": "workloads-platform", "docs": "/docs", "health": "/api/health"}
