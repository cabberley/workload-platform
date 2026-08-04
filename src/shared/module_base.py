"""Base class + registry for independently-scalable capability modules.

A `Module` is the unit of capability *and* of scale. Each module:
  * implements `run()` (its work) and `health()`,
  * exposes a `ModuleManifest` (including a `ScaleProfile`) via `manifest`,
  * is deployed as its own ACA app/Job so it scales independently.

Modules must not import one another; they talk through the API core and packs.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping

from shared.contracts import ModuleManifest, ModuleRunResult
from shared.provenance import enforce_finding_provenance
from shared.state import ReadableState


class ModuleContext:
    """Runtime services handed to a module (Azure clients, packs engine, read-only state).

    Kept intentionally small; concrete clients are injected at the edge so pure logic
    stays Azure-free and unit-testable.

    ``state`` is a **read-only** ``ReadableState`` view: modules never write shared state
    directly. They submit their ``ModuleRunResult`` to the API core, which is the single writer.

    ``clients`` is an **edge-client registry** keyed by well-known names (e.g. ``"resource_graph"``,
    ``"network"``, ``"notifier"``). The worker/API injects concrete, keyless Azure/edge clients at
    the process boundary; a module looks its client up by name and casts to its own local Protocol,
    so ``shared`` stays decoupled from module-specific client types and pure logic never does I/O.
    In unit tests, inject fakes via ``ModuleContext(clients={"resource_graph": FakeArg()})``.
    """

    def __init__(self, *, packs: object | None = None, state: ReadableState | None = None,
                 config: dict[str, str] | None = None,
                 clients: Mapping[str, object] | None = None) -> None:
        self.packs = packs
        self.state = state
        self.config = config or {}
        self.clients: Mapping[str, object] = clients or {}


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
    packs: object | None = None,
    clients: Mapping[str, object] | None = None,
) -> ModuleRunResult:
    """**Compute-only**: run ``module`` and return its ``ModuleRunResult``. Never persists.

    Persistence is the exclusive job of the API core (the single writer); this helper only does
    the compute half so the split is explicit. Both the API ``/run`` endpoint (which then commits)
    and the ACA worker (which then POSTs the result to the API) call this — neither writes state
    from inside the compute step. Modules receive a read-only ``state`` view (or ``None``), the
    verified ``packs`` engine (or ``None``), and the edge-client registry ``clients`` injected at
    the process boundary (or ``None``). ``packs`` is forwarded verbatim so quality_checks/aiops/
    dependency_graph actually see the content they consume (previously dropped here — issue #24).
    """
    ctx = ModuleContext(packs=packs, state=state, clients=clients)
    result = module.run(ctx, scope=scope)
    # Provenance completeness (issue #59): a module must not emit a finding without evidence.
    # Enforced here at the emission boundary so an un-provenanced finding fails closed BEFORE it
    # can reach the API single writer / durable state.
    enforce_finding_provenance(result.findings)
    return result


class ModuleRegistry:
    """Discovers and holds the enabled modules; used by the API core and worker.

    TODO(human): audit ``module.enabled`` / ``module.disabled`` (issue #59). A module's
    ``enabled`` state is today a STATIC field on its ``ModuleManifest`` (read at
    :meth:`enabled_modules`); there is no runtime enable/disable *toggle* path to emit from. When a
    toggle is introduced (a registry mutator or an API endpoint that flips a module on/off), emit
    an ``AuditAction.module_enabled`` / ``module_disabled`` event through a store-backed
    ``AuditEmitter`` at that mutation — actor = the operator's principal id, subject = the module
    name, result = success/failure. Do NOT invent a toggle subsystem here just to emit.
    """

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
    """Register the shipped capability modules. Import locally to keep modules decoupled.

    The six core modules plus ``telemetry_export`` (issue #86) — an opt-in, independently-scalable
    ACA Job that emits the platform's PII-free app-signals to Log Analytics for the baseline boards.
    """
    from modules.aiops.module import AiopsModule
    from modules.alerts.module import AlertsModule
    from modules.dependency_graph.module import DependencyGraphModule
    from modules.discovery.module import DiscoveryModule
    from modules.quality_checks.module import QualityChecksModule
    from modules.reassessments.module import ReassessmentsModule
    from modules.telemetry_export.module import TelemetryExportModule

    registry = ModuleRegistry()
    for mod in (
        DiscoveryModule(),
        QualityChecksModule(),
        ReassessmentsModule(),
        DependencyGraphModule(),
        AiopsModule(),
        AlertsModule(),
        TelemetryExportModule(),
    ):
        registry.register(mod)
    return registry
