"""Packs engine — load, verify integrity, and hand packs to modules.

Packs are the only inbound artifact (content, not code). This engine is the trust gate: it verifies
a pack's **SHA-256 content hash** and, where a verifier is wired, a detached **Ed25519** signature
over the pack's canonical bytes (``shared.signing`` — the direction of record) **before** a pack is
allowed to execute. A legacy symmetric HMAC remains an independent, optional gate. Missing/invalid
integrity => fail closed (refuse). A SHIPPED first-party pack that OMITS its content-hash integrity
field is refused at the load boundary (issue #82, :meth:`PacksEngine._require_shipped_integrity`);
its detached signature is enforced once the offline signing key / pinned trust root land (#37/#44).

## Trust gates

0. **Content-hash requirement (issue #82)** — a shipped first-party pack MUST carry ``sha256`` under
   a verified load; :func:`verify` then proves it is correct. Fail-closed on a missing hash.
1. **Legacy HMAC (symmetric)** — :func:`verify` checks the ``sha256`` computed over the pack's
   CANONICAL bytes (whole manifest + body — issue #82 MEDIUM-2; previously body-only) and an HMAC
   over it using an injected ``signing_secret`` (Key Vault at the boundary). Active when a secret is
   set and ``verify_sig`` is on. Existing packs/tests rely on it.
2. **Detached asymmetric signature (issue #35)** — when a :class:`~shared.signing.Verifier` is
   injected, each pack's :attr:`~shared.contracts.PackManifest.pack_signature` is verified against
   the pack's *canonical bytes* via :func:`shared.signing.verify_pack`. A missing or invalid
   detached signature fails closed (:class:`PackVerificationError`).
3. **Trust-root import admission + runtime re-verification (issue #89)** —
   :meth:`PacksEngine.verify_pack_for_import` is the customer-side, verification-only, **keyless**
   trust root for IMPORTED packs. Microsoft signs packs OFFLINE; this platform only verifies,
   selecting a pinned Ed25519 **PUBLIC** key from a trust bundle
   (:class:`~shared.signing.PackVerifier`) by the signature's ``key_id``. The import/assign
   subsystem (#37) calls it BEFORE a pack enters the registry/content store (#44). **R2
   (defence-in-depth):** :meth:`PacksEngine._resolve_imported_packs` no longer trusts the recorded
   digest transitively — it INDEPENDENTLY re-verifies each imported pack's persisted detached
   signature against the SAME pinned bundle at load time (digest match is integrity, not trust), so
   a legacy/pre-fix or attacker-crafted ``dist`` that recorded a digest without a pinned-verified
   signature is rejected fail-closed. Fail-closed everywhere: unknown key id / empty bundle / bad
   signature / signature-less legacy entry / no trust root wired => reject.

Gates (1)/(2) apply to packs loaded from the content-root filesystem; gate (3) guards the import
path. When **no** verifier is injected for a gate, that gate is inert and today's behavior is
preserved exactly.
"""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from pydantic import ValidationError

from packs_engine.canonical import canonical_bytes, canonical_digest
from shared.contracts import AuditAction, AuditResult, PackManifest, PackType, is_audit_safe
from shared.signing import PackVerifier, Verifier, verify_pack

if TYPE_CHECKING:  # pragma: no cover - typing-only import; avoids runtime coupling to the emitter
    from packs_engine.content_store import PackContentStore
    from packs_engine.registry import PackRegistryReader, RegistryEntry
    from shared.audit import AuditEmitter


class PackVerificationError(RuntimeError):
    """Raised when a pack's hash or signature does not verify. Fail closed."""


def _audit_safe_identifier(value: str) -> str:
    """Return an audit-safe identifier for ``value`` for use in a ``pack.verify`` failure event.

    When ``value`` is already audit-safe (see :func:`shared.contracts.is_audit_safe`) it is used
    verbatim so normal rejections stay human-readable. When it is NOT (a malicious pack carrying
    PII, control chars, an Azure resource *path*, or an oversized id/version), it is replaced with
    an opaque, deterministic SHA-256 hex digest — always bounded (64 hex chars), control-free, and
    PII-free — so the rejection is still audited WITHOUT ever copying or leaking the raw value.

    The digest input uses ``errors="surrogatepass"`` so encoding is TOTAL, deterministic AND
    injective for ANY ``str`` — including a lone surrogate (e.g. ``chr(0xD800)`` from ``json.loads``
    /``yaml.safe_load``), which strict UTF-8 cannot encode. Without a total encoding, hashing a
    lone-surrogate pack id would raise ``UnicodeEncodeError``, both suppressing the required failure
    audit and masking the expected ``PackVerificationError``. ``surrogatepass`` is a bijection with
    the ``str`` (unlike ``backslashreplace``, which would collapse a lone surrogate and its literal
    escape text to identical bytes), so distinct unsafe identifiers never collide to one digest.
    """
    if is_audit_safe(value):
        return value
    return hashlib.sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()


# Reserved top-level subtree under the content root that is NEVER loaded or executed at runtime.
#
# ``content/templates/`` holds authoring SCAFFOLDS (starter packs for humans to copy). They are
# schema-valid on purpose (so CI can validate their shape via ``scripts/validate_packs.py``), but
# they must NEVER be loaded by this engine or handed to a module against a real customer estate:
# a scaffold with ``targets: []`` (all workloads) would otherwise OVERRIDE alert routing (ops),
# emit FALSE detections (telemetry), inject phantom dependency EDGES (dependency), and misclassify
# resources (workload). Excluding the whole subtree here is a fail-safe reserved-directory
# convention — to deploy a pack you copy it OUT of ``templates/`` into its by-type directory
# (e.g. ``content/rules/``) and sign it. The schema gate in ``scripts/validate_packs.py`` keeps
# its own enumeration, so templates stay validated in CI even though they are not runtime packs.
RESERVED_NONRUNTIME_DIR = "templates"


def compute_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sign(sha256_hex: str, secret: bytes) -> str:
    """HMAC-SHA256 over the content hash. Secret is provided by the boundary (Key Vault)."""
    return hmac.new(secret, sha256_hex.encode(), hashlib.sha256).hexdigest()


def verify(manifest: PackManifest, content: bytes, secret: bytes | None) -> None:
    """Verify hash and (if a secret is configured) signature. Raise to fail closed.

    A real content hash / HMAC signature is always ASCII (hex / base64). A non-ASCII value in
    ``sha256``/``signature`` — e.g. a lone surrogate smuggled through the JSON manifest — can never
    verify, so we treat it as a fail-closed MISMATCH. Guarding ``hmac.compare_digest`` with
    ``.isascii()`` avoids the ``TypeError`` it raises on non-ASCII input (and the strict-encode
    ``UnicodeEncodeError`` inside :func:`sign`), either of which would otherwise escape as a
    non-``PackVerificationError`` — masking the expected error type AND evading the fail-closed
    ``pack.verify`` audit that the loader emits on ``PackVerificationError``.
    """
    actual = compute_sha256(content)
    if manifest.sha256 and not (
        manifest.sha256.isascii() and hmac.compare_digest(actual, manifest.sha256)
    ):
        raise PackVerificationError(f"Pack {manifest.id}: content hash mismatch")
    if secret is not None:
        if not manifest.signature:
            raise PackVerificationError(f"Pack {manifest.id}: missing signature")
        expected = sign(manifest.sha256 or actual, secret)
        if not (
            manifest.signature.isascii() and hmac.compare_digest(expected, manifest.signature)
        ):
            raise PackVerificationError(f"Pack {manifest.id}: signature invalid")


class Pack:
    """A loaded, parsed pack: manifest + body.

    ``source`` is the raw pack dict the pack was parsed from (``{"manifest": ..., "body": ...}``),
    retained so a consumer can recompute the pack's *version-identity* digest with
    :func:`packs_engine.canonical.canonical_digest` — the SAME canonicalizer the registry hashes
    with at import. Issue #37's assigned-pack resolution uses it to bind an assignment to the
    registry's VERIFIED digest (run a content-root pack under an assigned ref ONLY if its canonical
    digest matches the registry entry). It defaults to a manifest+body reconstruction so callers
    that build a ``Pack`` directly still expose a canonical source.

    ``imported`` marks provenance: ``False`` for platform-shipped packs loaded from the content-root
    filesystem, ``True`` for signed packs resolved from the digest-addressed content store (issue
    #44). Consumers that merge pack bodies last-wins (e.g. alerts ``load_ops_routing``) rely on this
    flag to keep SHIPPED policy authoritative per key — an imported pack may only ADD keys shipped
    does not define, never override a shipped route/default/runbook (e.g. suppress critical paging).
    """

    def __init__(
        self,
        manifest: PackManifest,
        body: dict[str, Any],
        *,
        source: dict[str, Any] | None = None,
        imported: bool = False,
    ) -> None:
        self.manifest = manifest
        self.body = body
        self.source = source if source is not None else {
            "manifest": manifest.model_dump(mode="json"),
            "body": body,
        }
        self.imported = imported


class PacksEngine:
    """Discovers packs under a content root and returns verified packs on demand."""

    def __init__(
        self,
        content_root: str | Path,
        *,
        signing_secret: bytes | None = None,
        signature_verifier: Verifier | None = None,
        import_verifier: PackVerifier | None = None,
        audit_emitter: AuditEmitter | None = None,
        registry: PackRegistryReader | None = None,
        content_store: PackContentStore | None = None,
        require_integrity: bool = True,
    ) -> None:
        self.root = Path(content_root)
        self._secret = signing_secret
        # Fail-closed integrity requirement for SHIPPED (first-party) packs (issue #82). When True
        # (the default and the production posture), a pack loaded from the content-root filesystem
        # under a verified load MUST carry its ``sha256`` content-hash integrity field, so a
        # bundled pack that omits integrity is REFUSED rather than silently loaded. Correctness of
        # the hash is still checked by :func:`verify`. Set False only for in-memory/synthetic
        # fixtures that deliberately ship a hash-less pack; the detached SIGNATURE remains deferred
        # for first-party packs (see the TODO(human) hook in :meth:`load_all`).
        self._require_integrity = require_integrity
        # Optional, independent detached-signature gate (issue #35). Inert when None: today's
        # HMAC-only behavior is preserved exactly.
        self._verifier = signature_verifier
        # Customer-side, verification-only, keyless TRUST ROOT for IMPORTED packs (issue #89). This
        # is a key-id-aware pack verifier (typically a ``TrustBundleVerifier`` over pinned Ed25519
        # PUBLIC keys) used by :meth:`verify_pack_for_import` — the fail-closed admission gate the
        # import/assign subsystem (#37) MUST call before a pack is registered/stored (#44) and
        # activated. Inert when None ONLY for callers that never import (e.g. shipped-pack tests);
        # :meth:`verify_pack_for_import` itself fails closed when no trust root is wired.
        self._import_verifier = import_verifier
        # Optional audit emitter (issue #59). Inert when None. When set (the API injects a
        # store-backed emitter — the single writer), a pack whose signature/hash verification FAILS
        # is recorded as a fail-closed ``pack.verify`` audit event before the failure propagates.
        self._audit_emitter = audit_emitter
        # Optional digest-addressed content store + registry (issue #44). Inert when either is None:
        # the engine then serves ONLY packs shipped on the content-root filesystem, exactly as
        # before. When both are set, imported packs that were never shipped in the image are
        # resolved from the store BY the registry's verified digest and re-verified before use.
        self._registry = registry
        self._content_store = content_store

    def attach_audit_emitter(self, emitter: AuditEmitter) -> None:
        """Attach a store-backed audit emitter after construction (used by the API composition)."""
        self._audit_emitter = emitter

    def with_import_registry(self, registry: PackRegistryReader | None) -> PacksEngine:
        """Return a shallow clone that resolves IMPORTED packs from ``registry`` (issue #68).

        The clone shares this engine's content root, trust gates, content store, and audit emitter
        but swaps the registry used by :meth:`_resolve_imported_packs`, so the API can hand a run a
        PER-TENANT view of only the caller tenant's imported packs. Cross-tenant isolation is
        preserved at the registry boundary: another tenant's imports are simply not in ``registry``,
        so they can never be resolved or executed. Shipped content-root packs are unaffected (they
        are loaded from the filesystem, not the registry), and every trust gate still applies —
        each imported pack is re-verified against the pinned bundle before use (fail closed).
        """
        clone = PacksEngine.__new__(PacksEngine)
        clone.__dict__.update(self.__dict__)
        clone._registry = registry
        return clone

    def reserved_pack_ids(self) -> set[str]:
        """Pack ids owned by platform-shipped/shared packs — reserved against tenant imports (#68).

        The union of (a) the shared REGISTRY entries the catalogue surfaces as built-in and (b) the
        pack ids shipped on the content-root filesystem — the SAME ids :meth:`load_all` records in
        ``shipped_ids`` and :meth:`_resolve_imported_packs` reserves (a shipped id owns that id at
        EVERY version and is never shadowed by an import). A tenant import whose id lands in this
        set would be admitted+assignable yet silently resolve to NOTHING at runtime (the runtime
        skips it); :func:`api.app.main.import_pack` rejects such a collision up front (409, fail
        closed) so the tenant-import id-space stays DISJOINT from shipped/shared. Enumeration is
        id-only (no signature verification) — a BROADER reserved set is the safe direction.
        """
        ids: set[str] = {entry.ref.id for entry in self.registry_entries()}
        for path in self._iter_pack_files():
            with contextlib.suppress(Exception):
                raw = self._parse(path)
                if not isinstance(raw, dict):
                    continue
                manifest_raw = raw.get("manifest")
                if isinstance(manifest_raw, dict):
                    pack_id = manifest_raw.get("id")
                    if isinstance(pack_id, str) and pack_id:
                        ids.add(pack_id)
        return ids

    def registry_entries(self, pack_type: PackType | None = None) -> list[RegistryEntry]:
        """Read-only listing of published pack versions in the wired registry (issue #57).

        A thin, keyless, PII-free projection of the registry index (:meth:`PackRegistry.list`) so
        the control-plane API can surface the pack-version catalogue to the console WITHOUT exposing
        the engine internals or the content store. Returns ``[]`` when no registry is wired (no
        content root / import subsystem) — fail-closed: absence of a catalogue is an empty list,
        never an error or a fabricated entry. This does NOT verify or activate anything; it only
        reads what the registry already recorded at admission.
        """
        if self._registry is None:
            return []
        return self._registry.list(pack_type)

    def _iter_pack_files(self) -> list[Path]:
        return sorted(
            p for p in self.root.rglob("*")
            if p.suffix in {".json", ".yaml", ".yml"}
            and p.is_file()
            and not self._is_reserved_nonruntime(p)
        )

    def _is_reserved_nonruntime(self, path: Path) -> bool:
        """True if ``path`` lives under the reserved, non-runtime ``templates/`` subtree.

        Any file whose first path component under the content root is ``RESERVED_NONRUNTIME_DIR``
        is an authoring scaffold and must never be discovered/executed as a runtime pack (see the
        constant's docstring). Fail-safe: a path outside the root is not treated as reserved.
        """
        try:
            rel = path.relative_to(self.root)
        except ValueError:
            return False
        return len(rel.parts) > 0 and rel.parts[0] == RESERVED_NONRUNTIME_DIR

    @staticmethod
    def _parse(path: Path) -> dict[str, Any]:
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".json":
            return json.loads(text)
        return yaml.safe_load(text)

    def load_all(self, *, pack_type: PackType | None = None, verify_sig: bool = True) -> list[Pack]:
        """Load verified packs: platform-shipped (content-root) then imported (content store).

        Provenance is explicit, NOT positional: every returned :class:`Pack` carries ``imported``
        (``False`` for content-root packs, ``True`` for store-resolved ones). Last-wins consumers
        that merge pack bodies (e.g. alerts ``load_ops_routing``) MUST keep SHIPPED policy
        authoritative per key by reading ``pack.imported`` — an imported pack may only ADD keys the
        shipped policy does not define, never override a shipped route/default/runbook. Returning
        shipped packs first is a convenience only; correctness relies on the ``imported`` flag so it
        holds regardless of iteration order.

        Security gates (fail-closed): a store pack is re-verified against the registry digest and
        bound to the registry ref; and an imported pack may never share a SHIPPED pack id (shipped
        packs are authoritative at every version — see :meth:`_resolve_imported_packs`).
        """
        packs: list[Pack] = []
        # Canonical digests of packs shipped on the content-root filesystem — an identical import
        # (same digest) is not loaded twice. This is a de-dup optimization, NOT the security gate.
        shipped_digests: set[str] = set()
        # The ``id@version`` refs shipped on the content-root filesystem. This IS the security gate:
        # a shipped pack is AUTHORITATIVE for its ref, so an imported store pack sharing that ref
        # (even with different content ⇒ different digest) must NEVER be resolved alongside it and
        # shadow/override the shipped policy. Digest de-dup alone cannot prevent this — the whole
        # point of the attack is that the digests DIFFER — so we exclude colliding refs explicitly.
        shipped_refs: set[tuple[str, str]] = set()
        # The pack IDS shipped on the content-root filesystem. This is the PRIMARY security gate: a
        # shipped pack id is authoritative at EVERY version, so an imported pack sharing a shipped
        # id is never resolved — even at a HIGHER version. Without this, a signed import of
        # ``default-notify@1.0.1`` (a different ref than shipped ``@1.0.0`` ⇒ passes the ref gate)
        # is merged last-wins by consumers (alerts ``routes.update``) and can reroute/suppress the
        # ``critical`` paging route — a fail-open. Platform packs upgrade via the content-root
        # (releases), NOT the import path; imports are customer/third-party packs in their OWN id
        # namespace, so an imported id may never equal a shipped id.
        shipped_ids: set[str] = set()
        for path in self._iter_pack_files():
            raw = self._parse(path)
            if "manifest" not in raw:
                continue  # not a pack file
            manifest = PackManifest(**raw["manifest"])
            if pack_type and manifest.type != pack_type:
                continue
            try:
                if verify_sig:
                    try:
                        pack_bytes = canonical_bytes(raw)
                    except (TypeError, ValueError) as exc:
                        # A YAML-authored pack can carry a non-JSON-native body (e.g. ``!!set`` →
                        # a Python ``set``). Canonicalizing it here raised before any audit was
                        # written — masking the rejection with a TypeError AND emitting zero
                        # pack.verify events. Convert to the fail-closed PackVerificationError so
                        # the except-clause below audits exactly one pack.verify/failure event.
                        raise PackVerificationError(
                            f"Pack {manifest.id}: not canonicalizable (non-JSON-native content)"
                        ) from exc
                    # Fail-closed integrity requirement (issue #82): a SHIPPED first-party pack must
                    # carry its ``sha256`` content-hash integrity field, so a bundled pack that
                    # OMITS integrity is REFUSED here rather than silently loaded.
                    if self._require_integrity:
                        self._require_shipped_integrity(manifest)
                    # ``verify`` proves the content hash is CORRECT over the pack's CANONICAL bytes
                    # (issue #82, MEDIUM-2) — the SAME canonicalization ``shared.signing`` signs
                    # over. Hashing canonical bytes (whole manifest + body, volatile integrity
                    # fields excluded) means tampering with ANY security-sensitive manifest field
                    # (``targets``/``type``/``id``/``version``) OR the body invalidates the hash and
                    # fails closed — a body-only hash left the manifest tamperable.
                    verify(manifest, pack_bytes, self._secret)
                    # A PRESENT detached signature is an AUTHENTICITY claim that MUST be
                    # cryptographically verified — never silently ignored (issue #82, MEDIUM-1;
                    # aligns with the invariant in ``scripts/validate_packs.py``). If a signature
                    # is present but no trust root/verifier is wired we CANNOT verify it, so we
                    # fail closed. Only an ABSENT signature receives the documented first-party
                    # HASH-ONLY exemption (authenticity DEFERRED to #37/#44 — see the TODO below).
                    if manifest.pack_signature is not None and self._verifier is None:
                        raise PackVerificationError(
                            f"Pack {manifest.id}: carries a detached signature but no trust root "
                            f"is configured to verify it — a present signature must be verified, "
                            f"not ignored (fail closed, issue #82)"
                        )
                    # TODO(human): turn ON first-party AUTHENTICITY by default here once the
                    # OFFLINE signing key + pinned trust root land (#37/#44): construct the engine
                    # with a ``signature_verifier`` and REQUIRE shipped packs to carry a
                    # ``pack_signature`` that cryptographically verifies against the pinned root
                    # (the same bar IMPORTED packs already meet in
                    # ``_resolve_imported_packs``/``verify_pack_for_import``, issue #89). Until
                    # then shipped first-party packs get HASH-ONLY integrity (tamper-evidence in
                    # transit, NOT authenticity); a PRESENT signature is already verified/failed-
                    # closed by the gate just above plus ``_verify_detached`` below.
                # Independent detached-signature gate (issue #35): only active when a verifier is
                # injected, so no-verifier callers keep today's behavior unchanged. Fail closed.
                if self._verifier is not None:
                    self._verify_detached(manifest, raw, self._verifier)
            except PackVerificationError:
                # Audit the fail-closed rejection of a tampered/invalid pack (issue #59), then
                # re-raise so verification still fails closed exactly as before.
                self._emit_verify_failure(manifest)
                raise
            packs.append(Pack(manifest=manifest, body=raw.get("body", {}), source=raw))
            shipped_refs.add((manifest.id, manifest.version))
            shipped_ids.add(manifest.id)
            with contextlib.suppress(TypeError, ValueError):
                # Record the shipped pack's version identity so its imported twin (same digest) is
                # not also resolved from the store. A non-JSON-native pack that cannot be
                # canonicalized simply is not deduped — harmless, since a store entry could never
                # match a digest we could not compute.
                shipped_digests.add(canonical_digest(raw))
        # Issue #44: additionally resolve imported packs from the digest-addressed content store.
        # Each is re-verified (``canonical_digest(loaded) == registry.digest``) before use and fails
        # closed on a miss/mismatch. Shipped packs are appended FIRST and win by ref — a store pack
        # can never shadow a shipped one. Inert unless BOTH a registry and a store are injected.
        packs.extend(
            self._resolve_imported_packs(
                pack_type=pack_type,
                shipped_digests=shipped_digests,
                shipped_refs=shipped_refs,
                shipped_ids=shipped_ids,
            )
        )
        return packs

    def _resolve_imported_packs(
        self,
        *,
        pack_type: PackType | None,
        shipped_digests: set[str],
        shipped_refs: set[tuple[str, str]],
        shipped_ids: set[str],
    ) -> list[Pack]:
        """Resolve imported packs from the content store BY the registry's verified digest.

        This is the runtime read side of issue #44: a pack that was signature-verified on import
        and recorded in the registry — but never shipped on the content-root filesystem — is loaded
        from the content store keyed by the registry ``digest`` and re-verified before execution.

        **Shipped packs are authoritative and win by pack ID (at EVERY version).** A store-resolved
        pack whose ``id`` matches ANY shipped pack id is NEVER appended — regardless of version or
        digest. Platform packs are upgraded through the content-root (platform releases), not the
        import/store path; imports are customer/third-party packs, which MUST use their OWN pack id
        namespace. This closes the fail-open where a validly-signed HIGHER-version import
        (``default-notify@1.0.1`` vs shipped ``@1.0.0`` — a different ref, so the (id,version) gate
        alone would pass it) is merged last-wins by a consumer (alerts ``routes.update``) and
        reroutes/suppresses the ``critical`` paging route. The (id,version) ref exclusion and digest
        de-dup are kept as (harmless) subsets of this id gate.

        **Fail closed at every step** — the pack resolves to NOTHING (is silently skipped, never
        executed) when:

        * no registry/store is wired (nothing to resolve);
        * a shipped pack owns the entry's ``id`` at any version (shipped wins by id);
        * the digest's bytes are absent from the store (missing digest);
        * the stored bytes are not parseable JSON, or cannot be canonicalized;
        * ``canonical_digest(loaded) != registry.digest`` (tampered/mismatched bytes);
        * the loaded manifest's ``id``/``version`` does not match the registry entry's ref (the
          bytes claim a different identity than the entry that authorized them);
        * the loaded manifest is malformed or its type does not match the entry;
        * **no trust root is wired** (``self._import_verifier is None``), the entry carries **no
          persisted detached signature/key_id** (a legacy/pre-#89 or hand-crafted entry), the
          signature's ``key_id`` is **not pinned** in the trust bundle, or the **signature does not
          verify** against the pinned public key (issue #89, R2).

        The digest re-verification proves **integrity** (the stored bytes ARE the recorded content),
        but integrity is not trust. The runtime therefore INDEPENDENTLY re-verifies the persisted
        detached signature against the **pinned trust bundle** (``self._import_verifier``) — the
        SAME trust root the exporter/import-admission gate uses — instead of transitively trusting
        the registry digest. This closes the reviewer-found bypass where a legacy/pre-fix or
        attacker-crafted ``dist`` (a ``registry/index.json`` + ``store/`` written WITHOUT the
        pinned admission gate) would be activated on a digest match alone, even though the pinned
        trust root rejects the signer. A signature-less (legacy) entry stays fail-closed until it
        is re-exported through the pinned admission gate.

        Two store entries can never share one ``id@version`` with differing content: the registry
        rejects a re-publish of an existing ``id@version`` under a different digest
        (``ImmutableVersionError``), so imported-vs-imported shadowing cannot arise. Shipped packs
        are appended before these, giving a deterministic, shipped-first authoritative order.

        TODO(human): precedence AMONG multiple imported packs (two imported packs of the same id
        would be merged last-wins by consumers) and an explicit per-workload pack ASSIGNMENT/pinning
        model (so only assigned imported refs resolve) are deferred to a follow-up — they need a
        product decision on whether signed imports may ever override shipped/critical policy. This
        method only makes shipped-wins-by-id airtight; it does NOT implement an assignment model.
        """
        registry = self._registry
        store = self._content_store
        if registry is None or store is None:
            return []
        resolved: list[Pack] = []
        for entry in registry.list(pack_type):
            if entry.ref.id in shipped_ids:
                continue  # a shipped pack owns this id at every version -> never shadow/override it
            if (entry.ref.id, entry.ref.version) in shipped_refs:
                continue  # a shipped pack owns this ref and is authoritative -> never shadow it
            if entry.digest in shipped_digests:
                continue  # already served from the content-root image; do not double-load
            data = store.get(entry.digest)
            if data is None:
                continue  # missing digest -> fail closed (resolve nothing)
            try:
                raw = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                continue  # unparseable stored bytes -> fail closed
            if not isinstance(raw, dict):
                continue
            try:
                recomputed = canonical_digest(raw)
            except (TypeError, ValueError):
                continue  # non-canonicalizable -> fail closed
            # Constant-time compare of two 64-char hex digests; a mismatch means the stored bytes do
            # not match the verified registry identity, so we NEVER execute them (fail closed).
            if not (recomputed.isascii() and hmac.compare_digest(recomputed, entry.digest)):
                continue
            manifest_raw = raw.get("manifest")
            if not isinstance(manifest_raw, dict):
                continue
            try:
                manifest = PackManifest(**manifest_raw)
            except ValidationError:
                continue  # malformed manifest -> fail closed
            # Bind the loaded bytes to the registry reference that authorized them: the manifest's
            # id AND version must equal the entry's ref, so store bytes can never claim a different
            # id@version than the entry that admitted them (fail closed on any mismatch).
            if manifest.id != entry.ref.id or manifest.version != entry.ref.version:
                continue
            if manifest.type != entry.type:
                continue  # registry type must match the loaded manifest -> fail closed
            # Runtime trust-root re-verification (issue #89, R2). The digest match above is
            # INTEGRITY, not trust: a legacy/pre-fix or attacker-crafted dist could carry a digest
            # that was never backed by a signature verified against the pinned bundle. Re-verify the
            # persisted detached signature against the pinned trust root INDEPENDENTLY, and fail
            # closed (skip, never execute) on any of: no trust root wired, a legacy/signature-less
            # entry, an unpinned key_id, or a signature that does not verify.
            if self._import_verifier is None:
                continue  # no trust root -> cannot verify imports -> fail closed
            signature = entry.detached_signature()
            if signature is None:
                continue  # legacy/untrusted entry (no verifiable detached signature) -> fail closed
            if not self._import_verifier.verify_pack(raw, signature):
                continue  # signature does not verify against the pinned bundle -> fail closed
            resolved.append(
                Pack(manifest=manifest, body=raw.get("body", {}), source=raw, imported=True)
            )
        return resolved

    def _emit_verify_failure(self, manifest: PackManifest) -> None:
        """Record a ``pack.verify`` failure event (no-op when no audit emitter is injected).

        Emission is best-effort and never raises (the emitter swallows its own errors), so auditing
        a rejected pack can never turn a fail-closed verification into a crash.

        A malicious pack may carry a non-audit-safe ``id``/``version`` (PII, control chars, an
        Azure resource *path*, or an oversized value). Copying those raw into the audit fields would
        make the ``AuditEvent`` itself fail ``is_audit_safe`` and be silently dropped — so the
        rejection of the WORST packs would go unaudited. We instead pass every identifier through
        :func:`_audit_safe_identifier`, which keeps a readable value when it is already safe but
        substitutes an opaque SHA-256 digest otherwise. The raw unsafe value is never copied into
        (or leaked by) the event, yet the rejection is ALWAYS audited.
        """
        if self._audit_emitter is None:
            return
        pack_id = _audit_safe_identifier(manifest.id)
        pack_version = _audit_safe_identifier(manifest.version)
        self._audit_emitter.emit(
            actor="system",
            action=AuditAction.pack_verify,
            subject=pack_id,
            result=AuditResult.failure,
            pack_id=pack_id,
            pack_version=pack_version,
        )

    def _require_shipped_integrity(self, manifest: PackManifest) -> None:
        """Fail closed if a SHIPPED (first-party) pack omits its content-hash integrity field (#82).

        A bundled/first-party pack loaded from the content-root filesystem MUST carry a ``sha256``
        content hash so it can never silently load WITHOUT an integrity field; :func:`verify` then
        proves that hash is CORRECT over the pack's CANONICAL bytes (whole manifest + body, issue
        #82 MEDIUM-2). A missing hash is refuse-to-load (fail closed).

        First-party vs imported (the deliberate, documented distinction):

        * **First-party / shipped** (``Pack.imported is False``, content-root filesystem): the
          content hash is REQUIRED now; the detached Ed25519 SIGNATURE is DEFERRED because offline
          signing keys / the pinned trust root are a parked decision (issues #37/#44). See the
          ``TODO(human)`` hook in :meth:`load_all` for where signature enforcement will be turned
          on for first-party packs.
        * **Imported / third-party** (``Pack.imported is True``, content store): held to the
          STRICTER bar — a detached signature that VERIFIES against the pinned trust root is
          required, enforced in :meth:`_resolve_imported_packs` and :meth:`verify_pack_for_import`
          (issue #89). An imported pack that omits a verifiable signature is already rejected.
        """
        if not manifest.sha256:
            raise PackVerificationError(
                f"Pack {manifest.id}: missing required content-hash integrity field 'sha256' "
                f"(fail closed, issue #82)"
            )

    @staticmethod
    def _verify_detached(manifest: PackManifest, raw: dict[str, Any], verifier: Verifier) -> None:
        """Refuse to load a pack whose detached signature is missing or does not verify.

        The signature covers ``canonical_bytes(raw)`` (the same canonicalizer the registry uses),
        so a tampered byte or a missing ``pack_signature`` fails closed here before the pack is
        handed to any module.
        """
        signature = manifest.pack_signature
        if signature is None:
            raise PackVerificationError(
                f"Pack {manifest.id}: missing detached signature (fail closed)"
            )
        if not verify_pack(raw, signature, verifier):
            raise PackVerificationError(
                f"Pack {manifest.id}: detached signature failed verification (fail closed)"
            )

    def verify_pack_for_import(self, pack: dict[str, Any]) -> None:
        """Fail-closed **trust-root admission gate** for an IMPORTED pack (issue #89).

        This is the customer-side, verification-only, keyless trust root. Microsoft signs packs
        **offline** in its own infrastructure; this platform only **verifies**, using the pinned
        Ed25519 **PUBLIC** keys of the injected :class:`~shared.signing.PackVerifier` (a
        ``TrustBundleVerifier``). The verifier selects the public key whose id matches the pack
        signature's ``key_id`` and checks the detached signature over the pack's canonical bytes.

        Call this **BEFORE** a pack is admitted to the registry/content store (#44) and activated —
        it is the clean extension hook the import/assign subsystem (#37) will call at admission, and
        it does NOT depend on #37's parked WIP. The #44 store deliberately holds *signature-free*
        canonical bytes; the detached signature verified here is persisted on the registry entry so
        the runtime resolver can INDEPENDENTLY re-verify it against the same pinned bundle at load
        time (issue #89, R2 — :meth:`_resolve_imported_packs`). Admission verifies the signature at
        the write boundary; the runtime re-verifies it at read time — digest match is integrity, not
        trust.

        Fail closed (raises :class:`PackVerificationError`) when: no trust root is wired, the
        manifest is malformed, the detached signature is missing, the ``key_id`` is not pinned in
        the trust bundle (unknown key / empty-or-unavailable bundle), or the signature does not
        verify against the selected public key.
        """
        if self._import_verifier is None:
            raise PackVerificationError(
                "pack import rejected: no trust root configured to verify signatures (fail closed)"
            )
        manifest_raw = pack.get("manifest") if isinstance(pack, dict) else None
        if not isinstance(manifest_raw, dict):
            raise PackVerificationError(
                "pack import rejected: missing or malformed manifest (fail closed)"
            )
        try:
            manifest = PackManifest(**manifest_raw)
        except ValidationError as exc:
            raise PackVerificationError(
                "pack import rejected: malformed manifest (fail closed)"
            ) from exc
        signature = manifest.pack_signature
        if signature is None:
            raise PackVerificationError(
                f"pack import rejected: {manifest.id} carries no detached signature (fail closed)"
            )
        if not self._import_verifier.verify_pack(pack, signature):
            raise PackVerificationError(
                f"pack import rejected: {manifest.id} signature did not verify against the trust "
                f"bundle key {signature.key_id!r} (fail closed)"
            )

    def load_for_workload(self, workload: str, pack_type: PackType) -> list[Pack]:
        """Return verified packs of a type that target the given workload kind."""
        return [
            p for p in self.load_all(pack_type=pack_type)
            if not p.manifest.targets or workload in p.manifest.targets
        ]
