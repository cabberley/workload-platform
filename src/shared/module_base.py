"""Base class + registry for independently-scalable capability modules.

A `Module` is the unit of capability *and* of scale. Each module:
  * implements `run()` (its work) and `health()`,
  * exposes a `ModuleManifest` (including a `ScaleProfile`) via `manifest`,
  * is deployed as its own ACA app/Job so it scales independently.

Modules must not import one another; they talk through the API core and packs.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from shared.contracts import ModuleManifest, ModuleRunResult
from shared.state import ReadableState


class ModuleContext:
    """Runtime services handed to a module (Azure clients, packs engine, read-only state).

    Kept intentionally small; concrete clients are injected at the edge so pure logic
    stays Azure-free and unit-testable.

    ``state`` is a **read-only** ``ReadableState`` view: modules never write shared state
    directly. They submit their ``ModuleRunResult`` to the API core, which is the single writer.
    """

    def __init__(self, *, packs: object | None = None, state: ReadableState | None = None,
                 config: dict[str, str] | None = None) -> None:
        self.packs = packs
        self.state = state
        self.config = config or {}


class Module(ABC):
    """Abstract capability module."""

    @property
    @abstractmethod
    def manifest(self) -> ModuleManifest:
        """Static declaration of identity, packs consumed/produced, and scale profile."""

    @property
    def name(self) -> str:
        return self.manifest.name

    @property
    def enabled(self) -> bool:
        return self.manifest.enabled

    @abstractmethod
    def run(self, ctx: ModuleContext, *, scope: dict[str, str] | None = None) -> ModuleRunResult:
        """Do one unit of the module's work and return a uniform result envelope."""

    def health(self) -> dict[str, str]:
        """Cheap liveness signal for the API/registry."""
        return {"module": self.name, "status": "ok"}


def run_module(
    module: Module,
    *,
    scope: dict[str, str] | None = None,
    state: ReadableState | None = None,
) -> ModuleRunResult:
    """**Compute-only**: run ``module`` and return its ``ModuleRunResult``. Never persists.

    Persistence is the exclusive job of the API core (the single writer); this helper only does
    the compute half so the split is explicit. Both the API ``/run`` endpoint (which then commits)
    and the ACA worker (which then POSTs the result to the API) call this — neither writes state
    from inside the compute step. Modules receive a read-only ``state`` view (or ``None``).
    """
    ctx = ModuleContext(state=state)
    return module.run(ctx, scope=scope)


class ModuleRegistry:
    """Discovers and holds the enabled modules; used by the API core and worker."""

    def __init__(self) -> None:
        self._modules: dict[str, Module] = {}

    def register(self, module: Module) -> None:
        self._modules[module.name] = module

    def get(self, name: str) -> Module:
        if name not in self._modules:
            raise KeyError(f"Unknown module: {name}")
        return self._modules[name]

    def enabled_modules(self) -> list[Module]:
        return [m for m in self._modules.values() if m.enabled]

    def manifests(self) -> list[ModuleManifest]:
        return [m.manifest for m in self._modules.values()]

    def names(self) -> list[str]:
        return list(self._modules.keys())


def build_default_registry() -> ModuleRegistry:
    """Register the six shipped modules. Import locally to keep modules decoupled."""
    from modules.aiops.module import AiopsModule
    from modules.alerts.module import AlertsModule
    from modules.dependency_graph.module import DependencyGraphModule
    from modules.discovery.module import DiscoveryModule
    from modules.quality_checks.module import QualityChecksModule
    from modules.reassessments.module import ReassessmentsModule

    registry = ModuleRegistry()
    for mod in (
        DiscoveryModule(),
        QualityChecksModule(),
        ReassessmentsModule(),
        DependencyGraphModule(),
        AiopsModule(),
        AlertsModule(),
    ):
        registry.register(mod)
    return registry
