"""``wp-packs`` - the Microsoft-**internal** packs studio (issue #36).

A CLI-first authoring workbench that drives the full pack lifecycle end to end:

    new  ->  validate  ->  test  ->  sign  ->  export

It is a thin **composition root** over already-merged shared code - it reuses, and never
re-implements, the schema gate (#33 ``validate_pack``), the registry (#34 ``PackRegistry``),
the signing provider (#35 ``sign_pack`` / ``Ed25519Signer``) and the real capability modules
(``quality_checks`` / ``aiops``) run against a *synthetic, clearly-fake* estate.

Guardrails honoured here:

* **In-boundary / keyless.** Signing uses an ephemeral in-process :class:`Ed25519Signer` - no
  secret, no network. The customer platform NEVER signs (Microsoft signs OFFLINE); there is no Key
  Vault signing key, and ``export`` verifies packs against the pinned, verification-only trust
  bundle (public keys only) — see issue #89 / ADR 0010.
* **Fail closed.** ``validate`` exits non-zero on any schema error; ``test`` refuses a pack type
  with no runnable module; ``export`` refuses an invalid or unsigned pack, refuses a pack whose
  signature does not verify against the **pinned trust bundle** (never a caller-supplied key), and
  lets the registry's immutability guard reject a mutated re-publish of an existing ``id@version``.
* **No Azure in ``test``.** The real modules run against an in-process synthetic estate and an
  in-process telemetry source - there is no ``DefaultAzureCredential`` and no SDK call anywhere.
* **Pure vs I/O.** Starter-body generation, the synthetic estate, and the bundle envelope are pure
  functions; file reads/writes happen only in the ``cmd_*`` handlers (the CLI edge).
* **No PHI/PII.** Every fixture is synthetic and obviously fake (``vm-app-01`` / ``epic-sandbox``).
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import sys
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from cli.wiring import ENV_TRUST_BUNDLE_PATH, build_pack_import_verifier
from packs_engine import (
    ImmutableVersionError,
    InvalidVersionError,
    PackRegistry,
    SemVer,
    canonical_digest,
    validate_pack,
)
from packs_engine.canonical import canonical_bytes
from packs_engine.content_store import LocalPackContentStore
from packs_engine.engine import Pack
from shared.contracts import (
    DependencyEdge,
    Finding,
    PackManifest,
    PackSignature,
    PackType,
    ResourceNode,
    WorkloadGraph,
)
from shared.module_base import Module, run_module
from shared.signing import (
    Ed25519Signer,
    Ed25519Verifier,
    sign_pack,
    verify_pack,
    verify_signature_structure,
)

# The bundle container is a self-describing JSON envelope. ``.wpack`` is JSON (not a zip) so the
# provenance stays greppable and diffable in review; the version schema lets the format evolve.
BUNDLE_SCHEMA = "aegis.pack-bundle/1"

# Sidecar suffix + env var carrying the base64 raw Ed25519 PUBLIC key (never a secret) that makes an
# exported bundle independently verifiable. ``sign`` writes the sidecar; ``export`` reads it (or an
# explicit --public-key / $WP_PACK_PUBLIC_KEY) and cryptographically verifies before bundling.
_PUBKEY_SUFFIX = ".pubkey"
_PUBLIC_KEY_ENV = "WP_PACK_PUBLIC_KEY"

# A pack id used in an output filename must match this safe grammar: lowercase alphanumeric start,
# then alphanumerics / dot / underscore / hyphen. No path separators, no traversal (fail closed).
_SAFE_PACK_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")

# Pack types that have a runnable capability module in ``test`` (rule->quality_checks,
# telemetry->aiops). Every other type is documented as not-yet-runnable and fails closed.
_RUNNABLE_TYPES: frozenset[str] = frozenset({"rule", "telemetry"})

# Synthetic, clearly-fake estate scope used by ``test``. No real subscription id, no customer data.
_SANDBOX_WORKLOAD = "epic-sandbox"
_SANDBOX_APP_NODE = "/subscriptions/00000000-0000-0000-0000-000000000000/rg/sandbox/vm-app-01"
_SANDBOX_WEB_NODE = "/subscriptions/00000000-0000-0000-0000-000000000000/rg/sandbox/vm-web-01"
_VM_TYPE = "Microsoft.Compute/virtualMachines"


# --------------------------------------------------------------------------------------
# Pure scaffolding - a SCHEMA-VALID starter body per pack type (self-contained, no #38).
# --------------------------------------------------------------------------------------
def _starter_body(pack_type: PackType) -> dict[str, Any]:
    """Return a schema-valid starter ``body`` for ``pack_type`` (pure).

    Each body is the minimal shape that passes ``packs_engine/schemas/<type>.schema.json`` and
    exercises the consuming module - e.g. the rule body's ``requiredTag`` and the telemetry body's
    ``role:app`` selector line up with the ``test`` synthetic estate so a fresh scaffold produces a
    finding out of the box.
    """
    if pack_type is PackType.rule:
        return {
            "rules": [
                {
                    "id": "starter-require-owner-tag",
                    "title": "VMs carry an owner tag",
                    "resourceType": _VM_TYPE,
                    "requiredTag": "owner",
                    "severity": "medium",
                    "description": "Starter rule: every VM should declare an owner tag.",
                }
            ]
        }
    if pack_type is PackType.telemetry:
        return {
            "signals": [
                {
                    "name": "cpu_percent",
                    "op": "gt",
                    "threshold": 90,
                    "severity": "high",
                    "nodeId": "role:app",
                }
            ],
            "logAnalysis": {
                "enabled": True,
                "note": "AI log analysis is advisory; detections are confidence-gated.",
            },
        }
    if pack_type is PackType.workload:
        return {
            "workload": "epic",
            "definitions": [
                {
                    "resourceType": _VM_TYPE,
                    "tagKey": "app-role",
                    "tagValue": "app",
                    "tier": "application",
                    "role": "app",
                }
            ],
        }
    if pack_type is PackType.dependency:
        return {
            "edges": [
                {
                    "source": "role:app",
                    "target": "role:db",
                    "type": "depends_on",
                    "redundant": False,
                }
            ]
        }
    # PackType.ops
    return {
        "default": "ticket",
        "routes": {"info": "none", "high": "email", "critical": "page"},
        "runbook": None,
    }


def starter_pack(pack_type: PackType, *, pack_id: str, name: str) -> dict[str, Any]:
    """Build a complete, schema-valid, unsigned starter pack dict (pure).

    ``targets`` is empty so the scaffold applies to every workload (including the ``test``
    sandbox); ``version`` is a valid semver seed. No signature is attached - signing is a later,
    explicit lifecycle step.
    """
    return {
        "manifest": {
            "id": pack_id,
            "type": pack_type.value,
            "name": name,
            "version": "0.1.0",
            "targets": [],
            "author": "microsoft",
        },
        "body": _starter_body(pack_type),
    }


# --------------------------------------------------------------------------------------
# Pure synthetic estate - deterministic, clearly-fake, Azure-free (for ``test``).
# --------------------------------------------------------------------------------------
class _SyntheticState:
    """An in-process, read-only ``ReadableState`` over one synthetic workload.

    Implements the full read surface modules may touch; only estate/graph carry data. It is
    read-only by construction - there is no write method, upholding the single-writer invariant.
    """

    def __init__(
        self,
        *,
        workload: str,
        estate: list[ResourceNode],
        graph: WorkloadGraph | None,
    ) -> None:
        self._workload = workload
        self._estate = estate
        self._graph = graph

    def list_workloads(self) -> list[str]:
        return [self._workload]

    def get_estate(self, workload: str) -> list[ResourceNode]:
        return list(self._estate) if workload == self._workload else []

    def get_graph(self, workload: str) -> WorkloadGraph | None:
        return self._graph if workload == self._workload else None

    def get_findings(self, workload: str, module: str | None = None) -> list[Finding]:
        return []

    def get_previous_findings(self, workload: str) -> list[Finding]:
        return []

    def get_previous_node_ids(self, workload: str) -> list[str]:
        return []


class _SinglePackEngine:
    """A packs-engine stand-in exposing exactly the ``load_for_workload`` slice modules read.

    Mirrors :meth:`packs_engine.engine.PacksEngine.load_for_workload` filtering (by type and by
    ``manifest.targets``) so the real module sees the pack-under-test exactly as it would in
    production, but sourced from the single authored file rather than a content root.
    """

    def __init__(self, pack: Pack) -> None:
        self._pack = pack

    def load_for_workload(self, workload: str, pack_type: PackType) -> list[Pack]:
        manifest = self._pack.manifest
        if manifest.type != pack_type:
            return []
        if manifest.targets and workload not in manifest.targets:
            return []
        return [self._pack]


class _SyntheticSignalSource:
    """An in-process telemetry edge client returning a fixed, synthetic ``FetchResult``.

    Satisfies the ``fetch_raw`` shape the aiops module calls. Importing ``FetchResult`` lazily
    keeps this module import-light and avoids pulling connector code unless ``test`` runs a
    telemetry pack.
    """

    def __init__(self, raw: list[dict[str, Any]]) -> None:
        self._raw = raw

    def fetch_raw(self, *, metric_names: Sequence[str] | None = None) -> Any:
        from modules.aiops.connectors.system_pulse import FetchResult

        return FetchResult(available=True, raw=list(self._raw))


def _default_estate() -> tuple[list[ResourceNode], WorkloadGraph, list[dict[str, Any]]]:
    """Build the deterministic default synthetic estate + graph + telemetry observations (pure).

    * ``vm-app-01`` - a VM in ``role:app`` **without** an ``owner`` tag -> the starter rule FAILS.
    * ``vm-web-01`` - a VM in ``role:web`` **with** an ``owner`` tag -> the starter rule PASSES.
    * graph edge web->app so the app node has a positive blast radius (drives high-confidence RCA).
    * one ``cpu_percent`` observation of 97 on the app node -> the starter telemetry rule detects.
    """
    nodes = [
        ResourceNode(
            id=_SANDBOX_APP_NODE, name="vm-app-01", type=_VM_TYPE,
            workload=_SANDBOX_WORKLOAD, role="app", tags={},
        ),
        ResourceNode(
            id=_SANDBOX_WEB_NODE, name="vm-web-01", type=_VM_TYPE,
            workload=_SANDBOX_WORKLOAD, role="web", tags={"owner": "team-sandbox"},
        ),
    ]
    graph = WorkloadGraph(
        nodes=nodes,
        edges=[DependencyEdge(source=_SANDBOX_WEB_NODE, target=_SANDBOX_APP_NODE)],
    )
    signals = [
        {
            "metric": "cpu_percent",
            "value": 97.0,
            "unit": "percent",
            "timestamp": "2026-08-03T04:00:00Z",
            "resourceId": _SANDBOX_APP_NODE,
        }
    ]
    return nodes, graph, signals


def _load_estate_fixture(
    path: Path,
) -> tuple[str, list[ResourceNode], WorkloadGraph, list[dict[str, Any]]]:
    """Load a synthetic estate fixture from JSON. Fail closed on a malformed fixture.

    Shape: ``{"workload": str, "nodes": [ResourceNode...], "edges": [DependencyEdge...],
    "signals": [{metric,value,unit,timestamp,resourceId}...]}``. ``nodes``/``edges`` are parsed
    through the typed contracts so a bad fixture surfaces as an error, never a silent empty run.
    """
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("estate fixture must be a JSON object")
    workload = raw.get("workload", _SANDBOX_WORKLOAD)
    if not isinstance(workload, str) or not workload:
        raise ValueError("estate fixture 'workload' must be a non-empty string")
    nodes = [ResourceNode.model_validate(n) for n in raw.get("nodes", [])]
    edges = [DependencyEdge.model_validate(e) for e in raw.get("edges", [])]
    signals = raw.get("signals", [])
    if not isinstance(signals, list):
        raise ValueError("estate fixture 'signals' must be a list")
    return workload, nodes, WorkloadGraph(nodes=nodes, edges=edges), signals


# --------------------------------------------------------------------------------------
# Pure bundle envelope - the ``.wpack`` container + provenance sidecar.
# --------------------------------------------------------------------------------------
def build_bundle(
    pack: dict[str, Any], *, digest: str, created_at: datetime, public_key: str
) -> dict[str, Any]:
    """Build the ``.wpack`` JSON envelope for a signed ``pack`` (pure).

    Carries the signed pack verbatim plus a provenance block (id, version, type, digest,
    algorithm, keyId, createdAt, publicKey) so a downstream importer (issue #37) can pin the exact
    version AND independently verify the detached signature: ``publicKey`` is the base64 raw
    Ed25519 PUBLIC key (never a secret). The ``digest`` is the registry's version-identity digest
    (:func:`canonical_digest`).
    """
    manifest = pack["manifest"]
    signature = manifest.get("pack_signature") or {}
    provenance = {
        "id": manifest["id"],
        "version": manifest["version"],
        "type": manifest["type"],
        "digest": digest,
        "algorithm": signature.get("algorithm"),
        "keyId": signature.get("key_id"),
        "createdAt": created_at.isoformat(),
        "publicKey": public_key,
    }
    return {"schema": BUNDLE_SCHEMA, "provenance": provenance, "pack": pack}


# --------------------------------------------------------------------------------------
# I/O helpers (CLI edge only).
# --------------------------------------------------------------------------------------
def _read_pack(path: Path) -> dict[str, Any]:
    """Read + JSON-parse a pack file. Raises on unreadable/non-object input (fail closed)."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: pack file is not a JSON object")
    return raw


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _pack_from_dict(raw: dict[str, Any]) -> Pack:
    """Build a verified-shape :class:`Pack` (typed manifest + body) from a raw pack dict."""
    manifest = PackManifest(**raw["manifest"])
    body = raw.get("body", {})
    return Pack(manifest=manifest, body=body if isinstance(body, dict) else {})


def _validate_pack_full(pack: dict[str, Any]) -> list[str]:
    """Validate the body schema (#33 ``validate_pack``) AND the manifest contract. Fail closed.

    ``validate_pack`` only checks the ``body`` against its type schema, so a pack whose ``manifest``
    is missing a required field (e.g. ``name``) would still pass. We additionally validate the
    manifest through the :class:`~shared.contracts.PackManifest` Pydantic contract so a
    contract-invalid pack can never be validated, signed, tested, or exported.
    """
    errors = list(validate_pack(pack))
    manifest = pack.get("manifest")
    if not isinstance(manifest, dict):
        errors.append("pack is missing a 'manifest' object")
        return errors
    try:
        PackManifest.model_validate(manifest)
    except ValidationError as exc:
        for err in exc.errors():
            loc = "/".join(str(part) for part in err["loc"]) or "<manifest>"
            errors.append(f"manifest/{loc}: {err['msg']}")
    # PackManifest.version is only str-typed; the registry requires strict semver. Parse it here so
    # a non-semver version is rejected cleanly by validate/sign/test/export instead of crashing
    # later inside PackRegistry.publish (fail closed, identical everywhere).
    version = manifest.get("version")
    if isinstance(version, str):
        try:
            SemVer.parse(version)
        except (InvalidVersionError, ValueError) as exc:
            errors.append(f"manifest/version: {exc}")
    return errors


def _is_safe_pack_id(pack_id: object) -> bool:
    """True iff ``pack_id`` is safe to interpolate into an output filename (no traversal)."""
    if not isinstance(pack_id, str) or ".." in pack_id or "/" in pack_id or "\\" in pack_id:
        return False
    return _SAFE_PACK_ID.fullmatch(pack_id) is not None


def _is_contained(path: Path, base: Path) -> bool:
    """True iff the resolved ``path`` stays beneath the resolved ``base`` directory."""
    try:
        path.resolve().relative_to(base.resolve())
    except ValueError:
        return False
    return True


def _resolve_public_key(explicit: str | None, pack_path: Path) -> tuple[bytes | None, str | None]:
    """Resolve an OPTIONAL base64 raw Ed25519 public key for a self-consistency pre-check.

    Resolution order: an explicit ``--public-key`` / ``$WP_PACK_PUBLIC_KEY`` value wins, else the
    ``<pack>.pubkey`` sidecar written by ``sign``. This key is **never** the admission trust root
    (the PINNED trust bundle is — see :func:`cmd_export`); it is only an early cross-check. Returns
    ``(raw_bytes, None)`` when a key resolves, ``(None, None)`` when none is available (skip the
    optional check), or ``(None, error)`` when a provided key is malformed (fail closed).
    """
    source = explicit or os.environ.get(_PUBLIC_KEY_ENV)
    if source:
        b64 = source
    else:
        sidecar = pack_path.with_name(pack_path.name + _PUBKEY_SUFFIX)
        if not sidecar.is_file():
            return None, None  # no optional key available -> skip the non-authoritative pre-check
        try:
            data = json.loads(sidecar.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return None, f"unreadable public-key sidecar {sidecar}: {exc}"
        candidate = data.get("publicKey") if isinstance(data, dict) else None
        if not isinstance(candidate, str):
            return None, f"public-key sidecar {sidecar} is missing a string 'publicKey'"
        b64 = candidate
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        return None, f"invalid base64 public key: {exc}"
    if len(raw) != 32:
        return None, f"invalid Ed25519 public key length {len(raw)} (expected 32 bytes)"
    return raw, None


def _module_for_type(pack_type: PackType) -> Module:
    """Return the real capability module that consumes ``pack_type`` (rule/telemetry only)."""
    if pack_type is PackType.rule:
        from modules.quality_checks.module import QualityChecksModule

        return QualityChecksModule()
    from modules.aiops.module import AiopsModule

    return AiopsModule()


def _print_findings(result_findings: list[Finding]) -> None:
    for finding in result_findings:
        status = "FAIL" if finding.passed is False else ("PASS" if finding.passed else "OBSERVE")
        node = finding.nodeId or "-"
        print(f"  [{status}] {finding.severity.value:8} {finding.title}  (node={node})")
        if finding.detail:
            print(f"           {finding.detail}")


# --------------------------------------------------------------------------------------
# Subcommand handlers.
# --------------------------------------------------------------------------------------
def cmd_new(args: argparse.Namespace) -> int:
    pack_type = PackType(args.type)
    pack_id = args.id or f"starter-{pack_type.value}"
    if not _is_safe_pack_id(pack_id):
        print(
            f"error: unsafe pack id {pack_id!r}: must match {_SAFE_PACK_ID.pattern} and contain "
            "no path separators or '..' (fail closed)",
            file=sys.stderr,
        )
        return 1
    name = args.name or f"Starter {pack_type.value} pack"
    pack = starter_pack(pack_type, pack_id=pack_id, name=name)

    errors = _validate_pack_full(pack)
    if errors:
        # A scaffold must be born valid; if not, fail closed rather than emit broken content.
        print(f"error: generated scaffold is not schema-valid ({pack_id}):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    if args.out:
        out = Path(args.out)
        out_dir = out.parent if str(out.parent) else Path(".")
    else:
        out_dir = Path(".")
        out = out_dir / f"{pack_id}.json"
    # Defense in depth mirroring export: the resolved output path must stay under its directory.
    if not _is_contained(out, out_dir):
        print(
            f"error: refusing to write scaffold outside {out_dir} (path traversal blocked)",
            file=sys.stderr,
        )
        return 1
    _write_json(out, pack)
    print(f"scaffolded {pack_type.value} pack '{pack_id}' -> {out}")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    path = Path(args.path)
    try:
        pack = _read_pack(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    errors = _validate_pack_full(pack)
    if errors:
        print(f"INVALID: {path} ({len(errors)} error(s))", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    print(f"VALID: {path}")
    return 0


def cmd_test(args: argparse.Namespace) -> int:
    path = Path(args.path)
    try:
        raw = _read_pack(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    errors = _validate_pack_full(raw)
    if errors:
        print(f"error: pack is not schema-valid; fix it before testing ({path}):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    pack = _pack_from_dict(raw)
    pack_type = pack.manifest.type
    if pack_type.value not in _RUNNABLE_TYPES:
        print(
            f"error: pack type '{pack_type.value}' has no runnable module in the studio "
            f"(runnable: {', '.join(sorted(_RUNNABLE_TYPES))}) - fail closed",
            file=sys.stderr,
        )
        return 1

    # Build the synthetic estate (bundled default or an injected fixture). Azure-free.
    try:
        if args.estate:
            workload, nodes, graph, signals = _load_estate_fixture(Path(args.estate))
        else:
            nodes, graph, signals = _default_estate()
            workload = _SANDBOX_WORKLOAD
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: bad estate fixture: {exc}", file=sys.stderr)
        return 1

    state = _SyntheticState(workload=workload, estate=nodes, graph=graph)
    packs = _SinglePackEngine(pack)
    clients: dict[str, object] = {}
    if pack_type is PackType.telemetry:
        clients["system_pulse"] = _SyntheticSignalSource(signals)

    module = _module_for_type(pack_type)
    result = run_module(module, scope={"workload": workload}, state=state, packs=packs,
                        clients=clients)

    label = "findings" if pack_type is PackType.rule else "detections"
    print(
        f"ran {pack.manifest.id}@{pack.manifest.version} ({pack_type.value}) through "
        f"'{module.name}' against synthetic estate '{workload}' - "
        f"{len(result.findings)} {label}:"
    )
    _print_findings(result.findings)
    return 0 if result.ok else 1


def cmd_sign(args: argparse.Namespace) -> int:
    path = Path(args.path)
    try:
        pack = _read_pack(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    errors = _validate_pack_full(pack)
    if errors:
        print(f"error: refusing to sign an invalid pack ({path}):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    # Keyless, ephemeral in-process Ed25519 signer - no secret, no network. ``--key-id`` names the
    # signing key so the SAME id is recorded in the signature and pinned (as a PUBLIC key) in the
    # trust bundle the exporter/runtime verify against; the private key is ephemeral, never written.
    signer = Ed25519Signer.generate(args.key_id)
    signature = sign_pack(pack, signer)
    pack.setdefault("manifest", {})["pack_signature"] = signature.model_dump(mode="json")
    # The PUBLIC key is provenance, not a secret: persist it (base64 raw) so 'export' and any
    # downstream importer can cryptographically verify the detached signature. The PRIVATE key is
    # ephemeral and never written (keyless guardrail).
    public_b64 = base64.b64encode(signer.verifier().public_bytes()).decode("ascii")

    out = Path(args.out) if args.out else path
    _write_json(out, pack)
    pubkey_path = out.with_name(out.name + _PUBKEY_SUFFIX)
    _write_json(
        pubkey_path,
        {"algorithm": signature.algorithm, "keyId": signature.key_id, "publicKey": public_b64},
    )
    print(
        f"signed {pack['manifest']['id']}@{pack['manifest']['version']} "
        f"(alg={signature.algorithm}, keyId={signature.key_id}) -> {out}\n"
        f"  public key (verify material) -> {pubkey_path}"
    )
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    path = Path(args.path)
    try:
        pack = _read_pack(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    errors = _validate_pack_full(pack)
    if errors:
        print(f"error: refusing to export an invalid pack ({path}):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    manifest = pack.get("manifest", {})
    pack_id = manifest.get("id")
    if not _is_safe_pack_id(pack_id):
        print(
            f"error: unsafe pack id {pack_id!r}: must match {_SAFE_PACK_ID.pattern} and contain "
            "no path separators or '..' (fail closed)",
            file=sys.stderr,
        )
        return 1

    raw_sig = manifest.get("pack_signature")
    if not isinstance(raw_sig, dict):
        print(
            f"error: refusing to export an unsigned pack ({path}); run 'wp-packs sign' first "
            "(fail closed)",
            file=sys.stderr,
        )
        return 1
    signature = PackSignature(**raw_sig)
    # A signed pack MUST name its signing key so the PINNED trust bundle can select the matching
    # PUBLIC key. A blank key_id can never be pinned -> reject before any registry/store write.
    if not signature.key_id.strip():
        print(
            f"error: signed pack {pack_id!r} carries no key_id; the trust root cannot select a "
            "verification key (fail closed)",
            file=sys.stderr,
        )
        return 1
    # Structural self-consistency is only a cheap pre-check (right algorithm, well-formed base64,
    # covered digest matches the pack's canonical bytes) - NEVER sufficient on its own.
    if not verify_signature_structure(pack, signature):
        print(
            f"error: pack signature does not match its content ({path}); re-sign before export "
            "(fail closed)",
            file=sys.stderr,
        )
        return 1
    # OPTIONAL, non-authoritative self-consistency: if a --public-key / $WP_PACK_PUBLIC_KEY / pubkey
    # sidecar is available, cross-check the signature against it. This can NEVER substitute for the
    # PINNED-bundle verification below; it only catches an obviously mismatched sidecar early.
    raw_pub, key_err = _resolve_public_key(args.public_key, path)
    if key_err is not None:
        print(f"error: {key_err} (fail closed)", file=sys.stderr)
        return 1
    if raw_pub is not None and not verify_pack(
        pack, signature, Ed25519Verifier.from_public_bytes(raw_pub)
    ):
        print(
            f"error: pack signature failed the optional --public-key self-consistency check "
            f"({path}); re-sign before export (fail closed)",
            file=sys.stderr,
        )
        return 1
    # AUTHORITATIVE trust-root admission (issue #89): verify the detached signature against the
    # PINNED trust bundle - the SAME trust root the runtime relies on. The runtime's
    # "registry digest => trusted" invariant (see PacksEngine._resolve_imported_packs) holds ONLY
    # because admission verified the signature here, at the registry/store write boundary. The
    # bundle is loaded via the composition-root seam (honouring $WP_TRUST_BUNDLE_PATH; overridable
    # per-run with --trust-bundle). Default (no bundle configured) = empty = reject-all, so an
    # untrusted/unpinned pack can never be written into a runtime-trusted registry/store. Fail
    # closed on an unknown/unpinned key_id, an empty/missing/corrupt bundle, or a bad signature.
    trust_config = {ENV_TRUST_BUNDLE_PATH: args.trust_bundle} if args.trust_bundle else None
    import_verifier = build_pack_import_verifier(config=trust_config)
    if not import_verifier.verify_pack(pack, signature):
        print(
            f"error: pack {pack_id!r} signature did not verify against the PINNED trust bundle "
            f"(key id {signature.key_id!r}); refusing to admit it to a runtime-trusted registry "
            "(fail closed)",
            file=sys.stderr,
        )
        return 1
    # Provenance records the exact PINNED public key that AUTHORISED admission (selected from the
    # trust bundle by key_id), never a caller-supplied key.
    pinned_pub = import_verifier.public_bytes_for(signature.key_id)
    if pinned_pub is None:  # unreachable after a successful verify_pack; fail closed regardless
        print(
            f"error: no pinned public key for {signature.key_id!r} in the trust bundle "
            "(fail closed)",
            file=sys.stderr,
        )
        return 1
    public_b64 = base64.b64encode(pinned_pub).decode("ascii")

    dist = Path(args.dist) if args.dist else Path("dist")
    # Contain output paths BENEATH dist before any write (defence in depth over the id grammar).
    stem = f"{pack_id}-{manifest.get('version')}"
    bundle_path = dist / f"{stem}.wpack"
    sidecar_path = dist / f"{stem}.manifest.json"
    for out_path in (bundle_path, sidecar_path):
        if not _is_contained(out_path, dist):
            print(
                f"error: refusing to write outside dist dir: {out_path} (fail closed)",
                file=sys.stderr,
            )
            return 1

    registry = PackRegistry(index_path=dist / "registry" / "index.json")
    try:
        entry = registry.publish(pack)
    except (ImmutableVersionError, InvalidVersionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    digest = canonical_digest(pack)
    # Issue #44: persist the VERIFIED canonical bytes into the digest-addressed content store keyed
    # by the registry digest, so an imported pack that was never shipped in the content-root image
    # is resolvable at runtime. We store exactly ``canonical_bytes(pack)`` — the same bytes the
    # digest was computed over — so the runtime resolver can re-verify
    # ``canonical_digest(loaded) == registry.digest`` before execution (fail closed). The store is
    # colocated with the dist registry so a distribution is self-contained (registry + bytes).
    content_store = LocalPackContentStore(dist / "store")
    content_store.put(digest, canonical_bytes(pack))
    bundle = build_bundle(pack, digest=digest, created_at=entry.createdAt, public_key=public_b64)
    _write_json(bundle_path, bundle)
    _write_json(sidecar_path, bundle["provenance"])

    print(
        f"exported {entry.ref.format()} ({entry.type.value}) -> {bundle_path}\n"
        f"  registered digest {digest[:12]}... in {registry.index_path}\n"
        f"  stored verified pack bytes -> {dist / 'store'}\n"
        f"  provenance sidecar (incl. public key) -> {sidecar_path}"
    )
    return 0


# --------------------------------------------------------------------------------------
# argparse wiring - mirrors cli/worker.py conventions.
# --------------------------------------------------------------------------------------
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wp-packs",
        description="Microsoft-internal packs studio: author->test->sign->export (keyless, "
                    "in-boundary, fail-closed)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_new = sub.add_parser("new", help="scaffold a schema-valid starter pack of a type")
    p_new.add_argument("type", choices=[t.value for t in PackType], help="pack type to scaffold")
    p_new.add_argument("--id", help="pack id (default: starter-<type>)")
    p_new.add_argument("--name", help="human-readable pack name")
    p_new.add_argument("--out", help="output file (default: <id>.json)")
    p_new.set_defaults(func=cmd_new)

    p_validate = sub.add_parser("validate", help="schema-validate a pack (fail closed)")
    p_validate.add_argument("path", help="path to the pack JSON file")
    p_validate.set_defaults(func=cmd_validate)

    p_test = sub.add_parser(
        "test", help="run a rule/telemetry pack through its real module on a synthetic estate"
    )
    p_test.add_argument("path", help="path to the pack JSON file")
    p_test.add_argument("--estate", help="optional JSON estate fixture (default: bundled sandbox)")
    p_test.set_defaults(func=cmd_test)

    p_sign = sub.add_parser("sign", help="sign a pack with an ephemeral Ed25519 key (keyless)")
    p_sign.add_argument("path", help="path to the pack JSON file")
    p_sign.add_argument("--out", help="output file (default: sign in place)")
    p_sign.add_argument(
        "--key-id",
        dest="key_id",
        default="ephemeral-ed25519",
        help="signing key id recorded in the signature and pinned (as a PUBLIC key) in the trust "
             "bundle the exporter/runtime verify against (default: ephemeral-ed25519)",
    )
    p_sign.set_defaults(func=cmd_sign)

    p_export = sub.add_parser(
        "export", help="validate+require signature, bundle, and register a versioned pack"
    )
    p_export.add_argument("path", help="path to the signed pack JSON file")
    p_export.add_argument(
        "--dist", help="output directory for the bundle + registry (default: dist)"
    )
    p_export.add_argument(
        "--public-key",
        dest="public_key",
        help="OPTIONAL base64 raw Ed25519 public key for a non-authoritative self-consistency "
             f"pre-check (else ${_PUBLIC_KEY_ENV} or the <pack>.pubkey sidecar); NEVER the "
             "admission trust root",
    )
    p_export.add_argument(
        "--trust-bundle",
        dest="trust_bundle",
        help="path to the PINNED Ed25519 PUBLIC-key trust bundle the signature is verified against "
             f"(else ${ENV_TRUST_BUNDLE_PATH} or config/trust-bundle.json; empty/missing = reject "
             "all — fail closed)",
    )
    p_export.set_defaults(func=cmd_export)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    func = args.func
    result: int = func(args)
    return result


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
