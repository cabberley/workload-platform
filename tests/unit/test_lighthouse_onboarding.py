"""Guardrail tests for the Azure Lighthouse delegation IaC (issue #66).

These are pure, Azure-free file assertions over ``infra/bicep/lighthouse`` — no deployment, no
credentials. They lock in the security invariants of the MSP-at-scale delegation:

  * **Least privilege, fail-CLOSED (guardrail #7):** the delegated ``authorizations`` are built
    INTERNALLY from a hardcoded allowlist — the ONLY delegated role is the built-in read-only
    **Reader**. There is no free-form ``authorizations`` array parameter, so no write-capable role
    (Owner / Contributor / User Access Administrator) can be injected at deploy time.
  * **In-boundary (guardrail #1):** **Monitoring Reader must NOT be delegated** — it would broaden
    the grant with further data-plane monitoring actions on top of Reader. (Reader's own ``*/read``
    is NOT telemetry-free; that residual is accepted under ADR-0011 Option B and compensated by
    auditing — see ``test_option_b_reader_acceptance_and_activity_log_audit_are_documented``.)
  * **Keyless / residency (guardrails #1, #3):** no keys/secrets/connection strings, and the
    templates carry no ``location`` (Lighthouse resources are tenant-level; no regional data
    placement).
  * **No real identifiers:** example params use only clearly-fake placeholder GUIDs.
  * **Correct Lighthouse shape:** both registrationDefinition and registrationAssignment present.
  * **Correct role GUIDs:** every kept built-in role GUID is the correct well-known Azure value.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_LIGHTHOUSE = _REPO_ROOT / "infra" / "bicep" / "lighthouse"
_ADR_0011 = _REPO_ROOT / "docs" / "adr" / "0011-msp-delivery-via-azure-lighthouse.md"
_ONBOARDING_DOC = _REPO_ROOT / "docs" / "delivery" / "lighthouse-onboarding.md"

# The ONLY built-in role GUID delegated here — the correct well-known Azure Reader value.
_READER_ROLE_ID = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
_ALLOWED_ROLE_IDS = {_READER_ROLE_ID}

# Monitoring Reader must appear NOWHERE in the Lighthouse templates — the broader Monitoring Reader
# role is deliberately not delegated (it adds data-plane monitoring actions on top of Reader). The
# REAL well-known Monitoring Reader GUID is the one that matters; the earlier fabricated literal is
# also barred so it can never regress in.
_MONITORING_READER_ROLE_IDS = {
    "43d0d8ad-25c7-4714-9337-8ba259a9fe05",  # REAL well-known Monitoring Reader — must be excluded
    "43d0d8ad-b133-4885-9d43-cae8c4b0b7d4",  # earlier fabricated literal — must not regress in
}

# Fabricated role GUID literals that a prior build invented; they must never come back into any
# Lighthouse file. (The REAL Azure GUIDs are the ones we KEEP — see the constants above/below.)
_INCORRECT_ROLE_IDS = {
    "acdd72a7-3625-48e6-95eb-b45f9d75f2f6": "fabricated Reader GUID",
    "91c1777a-40b2-4c6e-b0b5-0b8f0a8fc0a1": "fabricated MSR assignment Delete Role GUID",
    "43d0d8ad-b133-4885-9d43-cae8c4b0b7d4": "fabricated Monitoring Reader GUID",
}

# If the Managed Services Registration assignment Delete Role is referenced anywhere (docs), it must
# use the correct well-known Azure GUID.
_MSR_DELETE_ROLE_ID = "91c1777a-f3dc-4fae-b103-61d183457e46"

# Roles that must NEVER be granted via a Lighthouse authorization here.
_FORBIDDEN_ROLE_IDS = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
}

# A GUID is a "placeholder" only if every hex digit in it is the same character (0000…, 1111…, …).
_PLACEHOLDER_GUID_RE = re.compile(r"^([0-9a-f])\1{7}-\1{4}-\1{4}-\1{4}-\1{12}$", re.IGNORECASE)

_ENTRY_TEMPLATES = ("subscription.bicep", "resource-group.bicep")
_PARAM_FILES = ("subscription.parameters.json", "resource-group.parameters.json")


def _read(name: str) -> str:
    return (_LIGHTHOUSE / name).read_text(encoding="utf-8")


def test_lighthouse_dir_exists() -> None:
    assert _LIGHTHOUSE.is_dir(), f"missing Lighthouse IaC dir: {_LIGHTHOUSE}"


def test_entry_templates_have_lighthouse_resources() -> None:
    """Each entry template declares the offer (definition) and applies it (assignment)."""
    for name in _ENTRY_TEMPLATES:
        text = _read(name)
        assert "Microsoft.ManagedServices/registrationDefinitions@" in text, name
        assert "registrationAssignment" in text, name  # inline (sub) or nested module (rg)
        assert "targetScope = 'subscription'" in text, name
        assert "managedByTenantId" in text, name


def test_no_location_property_keeps_residency_clean() -> None:
    """Lighthouse resources are tenant-level: no ``location`` => no regional data placement."""
    for name in (*_ENTRY_TEMPLATES, "modules/registration-assignment.bicep"):
        text = _read(name)
        assert not re.search(r"(?<![\w.])location\s*:", text, re.IGNORECASE), (
            f"{name} unexpectedly sets a location"
        )


def test_templates_are_keyless_no_secrets() -> None:
    """No keys, secrets, or connection strings anywhere in the templates or params."""
    secret_markers = (
        "AccountKey=",
        "SharedAccessKey=",
        "DefaultEndpointsProtocol=",
        "AccountEndpoint=",
        "Endpoint=sb://",
        "BEGIN RSA PRIVATE KEY",
        "listKeys(",
    )
    for name in (*_ENTRY_TEMPLATES, "modules/registration-assignment.bicep", *_PARAM_FILES):
        text = _read(name)
        for marker in secret_markers:
            assert marker not in text, f"{name} contains secret-like marker {marker!r}"
        assert not re.search(r"password\s*[:=]\s*['\"][^'\"]+", text, re.IGNORECASE), name


def test_no_forbidden_roles_anywhere() -> None:
    """Owner / Contributor / User Access Administrator must not appear in any Lighthouse file."""
    for path in _LIGHTHOUSE.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8").lower()
        for guid, role in _FORBIDDEN_ROLE_IDS.items():
            assert guid not in text, f"{path.name} grants forbidden role {role} ({guid})"


def test_monitoring_reader_is_excluded_everywhere() -> None:
    """Monitoring Reader (data-plane Log Analytics query) must NOT be delegated (guardrail #1)."""
    for path in _LIGHTHOUSE.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8").lower()
        for guid in _MONITORING_READER_ROLE_IDS:
            assert guid not in text, (
                f"{path.name} references Monitoring Reader ({guid}); it must be excluded"
            )


def test_no_incorrect_role_guids_anywhere() -> None:
    """Previously-shipped wrong role GUID literals must not regress into any Lighthouse file."""
    for path in _LIGHTHOUSE.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8").lower()
        for guid, why in _INCORRECT_ROLE_IDS.items():
            assert guid not in text, f"{path.name} contains {why} ({guid})"


def test_msr_delete_role_guid_is_correct_when_referenced() -> None:
    """If the Managed Services Registration Delete Role is named, it uses the correct GUID."""
    for path in _LIGHTHOUSE.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        low = text.lower()
        if "registration assignment delete role" in low:
            assert _MSR_DELETE_ROLE_ID in low, (
                f"{path.name} names the Delete Role but not with the correct GUID "
                f"{_MSR_DELETE_ROLE_ID}"
            )


def test_authorizations_are_not_a_free_form_parameter() -> None:
    """Fail-closed: no ``param authorizations`` — the array is built internally, never supplied."""
    for name in _ENTRY_TEMPLATES:
        text = _read(name)
        assert not re.search(r"^\s*param\s+authorizations\b", text, re.MULTILINE), (
            f"{name} exposes a free-form authorizations parameter (fail-open)"
        )
        assert not re.search(r"^\s*param\s+eligibleAuthorizations\b", text, re.MULTILINE), (
            f"{name} exposes an eligibleAuthorizations parameter (PIM must be gated/omitted)"
        )
        # The authorizations array is constructed by mapping the allowlist onto the principal.
        assert re.search(r"var\s+authorizations\s*=\s*\[for\b", text), (
            f"{name} does not build authorizations internally from the allowlist"
        )
        assert "approvedRoleDefinitionIds" in text, (
            f"{name} has no hardcoded approved-role allowlist"
        )
        # FIX 4: the loop must iterate the allowlist and BIND roleDefinitionId to the loop variable
        # (not a literal/param), and set principalId to the single supplied principal — so no role
        # or extra principal can be injected.
        assert re.search(
            r"var\s+authorizations\s*=\s*\[for\s+roleDefinitionId\s+in\s+approvedRoleDefinitionIds\s*:",
            text,
        ), f"{name} does not iterate the allowlist with a bound loop variable"
        assert re.search(r"roleDefinitionId:\s*roleDefinitionId", text), (
            f"{name} does not bind the authorization roleDefinitionId to the loop variable"
        )
        assert re.search(r"principalId:\s*principalId", text), (
            f"{name} does not bind the authorization principalId to the single supplied principal"
        )
        # FIX 5: the registrationDefinition resource must consume the safe ``authorizations`` var
        # DIRECTLY — not wrapped in union()/concat() (which would let an injected array be merged
        # in). Assert the deployed property is EXACTLY the internally-built var.
        assert re.search(r"authorizations:\s*authorizations\b", text), (
            f"{name} does not set registrationDefinition.authorizations to the safe internal var"
        )
        assert not re.search(r"authorizations:\s*union\s*\(", text), (
            f"{name} wraps authorizations in union() — allows privileged-role injection"
        )
        assert not re.search(r"authorizations:\s*concat\s*\(", text), (
            f"{name} wraps authorizations in concat() — allows privileged-role injection"
        )


def test_only_reader_role_is_delegated_in_templates() -> None:
    """The only built-in role GUID in each entry template's allowlist is the correct Reader GUID."""
    role_guid_re = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
    for name in _ENTRY_TEMPLATES:
        text = _read(name)
        assert _READER_ROLE_ID in text, f"{name} must delegate the Reader role"
        # Extract the hardcoded allowlist block and check it holds ONLY the Reader GUID.
        block = re.search(r"var\s+approvedRoleDefinitionIds\s*=\s*\[(.*?)\]", text, re.DOTALL)
        assert block is not None, f"{name} has no approvedRoleDefinitionIds allowlist"
        guids = {g.lower() for g in role_guid_re.findall(block.group(1))}
        assert guids == _ALLOWED_ROLE_IDS, (
            f"{name} allowlist must contain ONLY the Reader GUID, found {guids}"
        )


def test_example_params_expose_principal_not_roles() -> None:
    """Example params supply only identity inputs — no roleDefinitionId / raw authorizations."""
    for param_file in _PARAM_FILES:
        data = json.loads(_read(param_file))
        params = data["parameters"]
        assert "authorizations" not in params, f"{param_file}: must not parameterize authorizations"
        assert "eligibleAuthorizations" not in params, f"{param_file}: must not expose PIM param"
        assert "principalId" in params, f"{param_file}: missing principalId"
        assert "managedByTenantId" in params, f"{param_file}: missing managedByTenantId"
        # No role GUID may be supplied anywhere in the params values.
        blob = json.dumps(params).lower()
        assert "roledefinitionid" not in blob, f"{param_file}: roles must not be a parameter"
        for guid in _FORBIDDEN_ROLE_IDS:
            assert guid not in blob, f"{param_file}: forbidden role {guid} present"
        for guid in _MONITORING_READER_ROLE_IDS:
            assert guid not in blob, f"{param_file}: Monitoring Reader {guid} present"


def test_example_params_use_only_placeholder_guids() -> None:
    """Tenant + principal ids in the example params must be clearly-fake placeholder GUIDs."""
    for param_file in _PARAM_FILES:
        data = json.loads(_read(param_file))
        params = data["parameters"]
        tenant = params["managedByTenantId"]["value"]
        assert _PLACEHOLDER_GUID_RE.match(tenant), (
            f"{param_file}: managedByTenantId {tenant} not a clearly-fake placeholder GUID"
        )
        principal = params["principalId"]["value"]
        assert _PLACEHOLDER_GUID_RE.match(principal), (
            f"{param_file}: principalId {principal} is not a clearly-fake placeholder GUID"
        )


def test_reader_role_is_documented_in_templates() -> None:
    """The delegated Reader role GUID is referenced (with an inline comment) in every template."""
    for name in _ENTRY_TEMPLATES:
        text = _read(name).lower()
        assert _READER_ROLE_ID in text, (
            f"{name} does not document the Reader role {_READER_ROLE_ID}"
        )


def test_option_b_reader_acceptance_and_activity_log_audit_are_documented() -> None:
    """ADR-0011 + the onboarding doc lock in the accepted-Reader **Option B** decision AND an
    HONEST compensating control (Finding1: Reader's ``*/read`` telemetry residual is knowingly
    accepted and audited via the RIGHT surface — LA queries via ``LAQueryLogs``, admin writes via
    Activity Log which does NOT log reads, metric-read residual disclosed as unmonitored)."""
    adr = _ADR_0011.read_text(encoding="utf-8")
    onboarding = _ONBOARDING_DOC.read_text(encoding="utf-8")
    for doc, text in (("ADR-0011", adr), ("onboarding", onboarding)):
        # Normalise whitespace so multi-word phrases still match across markdown line wraps.
        low = re.sub(r"\s+", " ", text).lower()
        assert "option b" in low, f"{doc}: does not record the Option B decision"
        assert "activity log" in low, f"{doc}: does not mention the Activity Log audit trail"
        assert "compensating control" in low, f"{doc}: does not name the compensating control"
        # The built-in Reader role is knowingly ACCEPTED (not claimed telemetry-isolated).
        assert "accept" in low, f"{doc}: does not document accepting the built-in Reader role"
        assert "reader" in low, f"{doc}: does not mention the Reader role"
        # HONEST audit surface: LA queries are audited via LAQueryLogs (not Activity Log).
        assert "laquerylogs" in low, f"{doc}: does not cite LAQueryLogs (LA-query audit control)"
        # Metric-read residual disclosed as not individually auditable.
        assert "not individually auditable" in low, (
            f"{doc}: does not disclose the metric-read residual as not individually auditable"
        )
    # The residual being compensated is telemetry read via Reader's */read.
    assert "telemetry" in adr.lower(), "ADR-0011 does not acknowledge the telemetry-read residual"
    # The debunked false claims (Activity Log logs reads) must NOT reappear in either doc.
    combined = re.sub(r"\s+", " ", adr + "\n" + onboarding).lower()
    for bad in (
        "every read",
        "audit trail should show only",
        "every delegated action lands in",
        "every action** a managing-tenant",
    ):
        assert bad not in combined, f"docs contain a debunked false audit claim: {bad!r}"


def test_no_fabricated_role_guids_in_docs() -> None:
    """FIX 3: the fabricated ROLE GUIDs must not regress into the ADR or onboarding docs either.

    Only the fabricated *role* GUIDs are barred — the onboarding doc legitimately uses clearly-fake
    placeholder tenant/principal GUIDs (0000…, 1111…), which are fine.
    """
    for doc in (_ADR_0011, _ONBOARDING_DOC):
        text = doc.read_text(encoding="utf-8").lower()
        for guid, why in _INCORRECT_ROLE_IDS.items():
            assert guid not in text, f"{doc.name} contains {why} ({guid})"


def test_no_false_isolation_claims_in_deployables() -> None:
    """FIX 2/5: no deployable template, params file, README, ADR, or onboarding doc may claim
    telemetry isolation the delegation does not provide. Lighthouse does no BULK copy/export (true),
    but Reader's ``*/read`` DOES let the MSP read telemetry (accepted Option B residual) — so
    unconditional ``workload data never leaves`` / ``no workload data egress`` phrasings are barred.
    Whitespace is normalised first so markdown line-wrapping cannot hide a banned phrase."""
    banned = (
        "no data-plane",
        "no workload data leaves the customer boundary",
        "no workload data egress",
        "workload data never leave",
        "configuration ever leaves the customer boundary",
    )
    files = (
        _LIGHTHOUSE / "subscription.bicep",
        _LIGHTHOUSE / "resource-group.bicep",
        _LIGHTHOUSE / "subscription.parameters.json",
        _LIGHTHOUSE / "resource-group.parameters.json",
        _LIGHTHOUSE / "README.md",
        _ONBOARDING_DOC,
        _ADR_0011,
    )
    for path in files:
        norm = re.sub(r"\s+", " ", path.read_text(encoding="utf-8")).lower()
        for phrase in banned:
            assert phrase not in norm, f"{path.name} contains false-isolation claim {phrase!r}"
