"""Static delivery/infra invariants for issue #67 (customer deployment made real).

These guard the four deployment-blocking fixes applied under #67. The parsing is deliberately
lightweight (text/substring over the real infra tree), matching the pattern of
``tests/unit/test_check_data_residency.py`` / ``test_worker_rbac_api_only_writer.py``. No secrets or
PHI in fixtures — every assertion reads the committed infra/docs.

Fixes under test:
  1. ACA resource NAMES derived from a module id are hyphenated (underscores are illegal in
     ``Microsoft.App/{jobs,containerApps}`` names and container labels), while the REAL module id
     (``WP_MODULE`` env / ``--module`` arg) keeps its underscore so the worker still dispatches.
  2. The azd preprovision hook fails closed with an actionable message when ``AZURE_RESOURCE_GROUP``
     is unset, and the customer-deployment doc instructs the customer to set it.
  3. The web image reverse-proxies same-origin ``/api/*`` to the API's INTERNAL ingress (the browser
     never reaches the internal-only API directly); the target is threaded keylessly by main.bicep.
  4. The marketplace location selector constrains regions to those supporting Managed Grafana.

Follow-up (review-67-v3, PM-adjudicated Phase-1 scope — Option 3):
  A. deploy.sh short-circuits ``--what-if`` BEFORE any mutation (no RG/ACR create, no image
     build/push) so a preview has zero side effects.
  B. The marketplace ``mainTemplate.json`` is regenerated from ``mainTemplate.bicep`` and contains
     no underscore-named Container Apps/jobs resources (only hyphen-sanitized names).
  C. The DELIVERED default ``authMode`` is ``disabled`` (Phase-1 Option 3, issue #127 — safe only
     because the API is internal-only), while ``main.bicep``'s OWN parameter default stays
     ``required`` (fail-closed) for anyone deploying it directly.

Follow-up (review-67-v4, PM-adjudicated HIGH — close the public-exposure path):
  The public web front door is only ever open when the API enforces required auth. The API app is
  ALWAYS internal; the web app's external ingress is gated on an ``ingressExternal`` param that
  ``main.bicep`` couples to ``authMode == 'required'``. So the delivered ``disabled`` default yields
  a FULLY internal deployment (no public endpoint), making disabled-auth genuinely safe.
"""
from __future__ import annotations

import json
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_MODULE_JOB = _REPO_ROOT / "infra" / "bicep" / "modules" / "module-job.bicep"
_MODULE_APP = _REPO_ROOT / "infra" / "bicep" / "modules" / "module-app.bicep"
_MAIN_BICEP = _REPO_ROOT / "infra" / "bicep" / "main.bicep"
_MAIN_PARAMS = _REPO_ROOT / "infra" / "bicep" / "main.parameters.json"
_NGINX_TEMPLATE = _REPO_ROOT / "infra" / "docker" / "nginx.conf.template"
_DOCKERFILE_WEB = _REPO_ROOT / "infra" / "docker" / "Dockerfile.web"
_PREPROVISION = _REPO_ROOT / "infra" / "deploy" / "azd-hooks" / "preprovision.sh"
_DEPLOY_SH = _REPO_ROOT / "infra" / "deploy" / "deploy.sh"
_DEPLOY_DOC = _REPO_ROOT / "docs" / "delivery" / "customer-deployment.md"
_CREATE_UI = _REPO_ROOT / "infra" / "marketplace" / "createUiDefinition.json"
_MAIN_TEMPLATE_JSON = _REPO_ROOT / "infra" / "marketplace" / "mainTemplate.json"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# --------------------------------------------------------------------------------------
# FIX 1 — ACA resource names must not contain underscores (deployment blocker).
# --------------------------------------------------------------------------------------
def test_job_resource_name_is_hyphenated_but_module_id_preserved() -> None:
    text = _read(_MODULE_JOB)
    # The Azure name is sanitized...
    assert "var resourceName = replace(moduleName, '_', '-')" in text
    assert "name: 'wp-${resourceName}'" in text
    assert "name: 'wp-${moduleName}'" not in text  # the raw (underscore) id never names a resource
    # ...but the real module identity is untouched (the worker dispatches on it).
    assert "{ name: 'WP_MODULE', value: moduleName }" in text
    assert "args: ['--module', moduleName]" in text


def test_app_resource_name_is_hyphenated_but_module_id_preserved() -> None:
    text = _read(_MODULE_APP)
    assert "var resourceName = replace(moduleName, '_', '-')" in text
    assert "name: 'wp-${resourceName}'" in text
    assert "name: 'wp-${moduleName}'" not in text
    assert "{ name: 'WP_MODULE', value: moduleName }" in text


def test_container_labels_use_sanitized_name_not_raw_module_id() -> None:
    # The container label inside the template is also a name with the lowercase-alnum-hyphen rule.
    for path in (_MODULE_JOB, _MODULE_APP):
        text = _read(path)
        assert "name: resourceName" in text
        assert "name: moduleName" not in text


# --------------------------------------------------------------------------------------
# FIX 2 — preprovision hook + doc require AZURE_RESOURCE_GROUP.
# --------------------------------------------------------------------------------------
def test_preprovision_requires_resource_group_with_actionable_message() -> None:
    text = _read(_PREPROVISION)
    assert (
        ': "${AZURE_RESOURCE_GROUP:?set it first: azd env set AZURE_RESOURCE_GROUP '
        '<resource-group-name>}"' in text
    )
    # The misleading "azd sets this during provisioning" claim is gone.
    assert "azd sets this during provisioning" not in text


def test_deploy_doc_instructs_setting_resource_group() -> None:
    text = _read(_DEPLOY_DOC)
    assert "azd env set AZURE_RESOURCE_GROUP" in text


# --------------------------------------------------------------------------------------
# FIX 3 — web reverse-proxies same-origin /api/* to the API's INTERNAL ingress (keyless).
# --------------------------------------------------------------------------------------
def test_nginx_template_reverse_proxies_api_to_injected_internal_target() -> None:
    text = _read(_NGINX_TEMPLATE)
    assert "location /api/" in text
    assert "proxy_pass" in text
    assert "${WP_API_BASE_URL}" in text
    # Keyless: nginx must not set a hardcoded Authorization/credential header of its own — the API
    # enforces its own auth and the caller's bearer is forwarded unchanged.
    for line in text.splitlines():
        low = line.lower().strip()
        if low.startswith("proxy_set_header") and "authorization" in low:
            raise AssertionError(f"nginx must not inject an Authorization header: {line!r}")
    assert "secret" not in text.lower()


def test_web_dockerfile_installs_the_nginx_template() -> None:
    text = _read(_DOCKERFILE_WEB)
    assert "infra/docker/nginx.conf.template /etc/nginx/templates/default.conf.template" in text


def test_main_bicep_threads_api_base_url_into_web_from_api_fqdn() -> None:
    text = _read(_MAIN_BICEP)
    # The web app gets the API's ingress FQDN as WP_API_BASE_URL — never a hardcoded host. The
    # object is split across lines (see main.bicep) so assert the two properties independently.
    assert "name: 'WP_API_BASE_URL'" in text
    assert "value: 'https://${apiApp.outputs.fqdn}'" in text
    # And the API is deployed as its own module the web app can depend on.
    assert "module apiApp 'modules/module-app.bicep'" in text
    assert "module webApp 'modules/module-app.bicep'" in text


def test_api_ingress_stays_internal_only() -> None:
    # review-67-v4: the API is ALWAYS internal (external:false); the web app's external ingress is
    # gated on the ingressExternal param (which main.bicep couples to authMode == 'required').
    text = _read(_MODULE_APP)
    assert "external: moduleName == 'web' ? ingressExternal : false" in text
    assert "param ingressExternal bool = false" in text
    # The old unconditional "web is always external" form must be gone.
    assert "external: moduleName == 'web'\n" not in text


def test_main_bicep_gates_web_public_ingress_on_required_auth() -> None:
    # The structural invariant: the public web front door opens ONLY when the API enforces required
    # auth. main.bicep derives webIngressExternal from authMode and passes it to the web module; the
    # API app is pinned internal (ingressExternal:false).
    text = _read(_MAIN_BICEP)
    assert "var webIngressExternal = authMode == 'required'" in text
    assert "ingressExternal: webIngressExternal" in text
    assert "ingressExternal: false" in text  # the API app is always internal


def test_delivered_disabled_default_yields_no_public_ingress() -> None:
    # End-to-end of the delivered default: main.parameters.json ships authMode=disabled, and
    # main.bicep only makes web external when authMode=='required' — so the delivered deployment has
    # NO public (external) ingress at all (fully internal, review-67-v4).
    params = json.loads(_read(_MAIN_PARAMS))
    assert params["parameters"]["authMode"]["value"] == "disabled"
    main = _read(_MAIN_BICEP)
    assert "var webIngressExternal = authMode == 'required'" in main
    # disabled != 'required' ⇒ webIngressExternal is false ⇒ web internal. And the API is pinned
    # internal in module-app.bicep regardless of authMode.
    module = _read(_MODULE_APP)
    assert "external: moduleName == 'web' ? ingressExternal : false" in module


# --------------------------------------------------------------------------------------
# FIX 4 — location selector constrains regions to those supporting Managed Grafana.
# --------------------------------------------------------------------------------------
def test_create_ui_location_selector_includes_grafana() -> None:
    ui = json.loads(_read(_CREATE_UI))
    resource_types = ui["parameters"]["config"]["basics"]["location"]["resourceTypes"]
    assert "Microsoft.Dashboard/grafana" in resource_types
    # The pre-existing region-constrained types remain.
    assert "Microsoft.App/containerApps" in resource_types
    assert "Microsoft.Storage/storageAccounts" in resource_types


# --------------------------------------------------------------------------------------
# Follow-up A — deploy.sh short-circuits --what-if BEFORE any mutation (no side effects).
# --------------------------------------------------------------------------------------
def test_deploy_sh_what_if_short_circuits_before_any_mutation() -> None:
    text = _read(_DEPLOY_SH)
    idx_whatif = text.find('if [[ "$WHAT_IF" == "true" ]]')
    assert idx_whatif != -1, "deploy.sh must branch on the --what-if flag"
    # The what-if preview + its exit must appear BEFORE the first mutating operation.
    idx_exit = text.find("exit 0", idx_whatif)
    assert idx_exit != -1
    idx_rg_create = text.find('az group create --name "$RESOURCE_GROUP"')
    idx_acr_create = text.find('az acr create \\')
    idx_build = text.find('az acr build \\')
    for label, idx_mut in (
        ("az group create", idx_rg_create),
        ("az acr create", idx_acr_create),
        ("az acr build", idx_build),
    ):
        assert idx_mut != -1, f"expected {label} in deploy.sh"
        assert idx_whatif < idx_mut, f"--what-if branch must precede {label}"
        assert idx_exit < idx_mut, f"--what-if must exit before {label}"
    # And the what-if branch must only run the preview (a group what-if), never a create.
    idx_whatif_cmd = text.find("az deployment group what-if", idx_whatif)
    assert idx_whatif_cmd != -1 and idx_whatif_cmd < idx_exit


# --------------------------------------------------------------------------------------
# Follow-up B — regenerated marketplace mainTemplate.json has no underscore-named ACA resources.
# --------------------------------------------------------------------------------------
def _walk_resources(obj: object):
    """Yield every ARM resource object (dicts with a 'type' + 'name') anywhere in the template."""
    if isinstance(obj, dict):
        if "type" in obj and "name" in obj:
            yield obj
        for value in obj.values():
            yield from _walk_resources(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk_resources(item)


def test_main_template_json_has_no_underscore_named_container_apps_or_jobs() -> None:
    template = json.loads(_read(_MAIN_TEMPLATE_JSON))
    aca_types = {"Microsoft.App/containerApps", "Microsoft.App/jobs"}
    saw_aca = False
    for resource in _walk_resources(template):
        if resource.get("type") in aca_types:
            saw_aca = True
            name = resource.get("name", "")
            # ACA resource names are compiled expressions over a sanitized resourceName; a literal
            # underscore in the NAME is exactly the deployment-blocking bug this guards against.
            assert isinstance(name, str)
            if not name.startswith("["):  # a literal (non-expression) name must be hyphen-only
                assert "_" not in name, f"underscore in ACA resource name: {name!r}"
            else:  # an expression must not embed a raw underscore literal in the name itself
                assert "'wp-{0}'" in name or "format('wp-" in name, name
    assert saw_aca, "expected the marketplace template to deploy Container Apps/jobs"
    # The generated template must carry the sanitization expression that hyphenates the module id.
    assert "replace(parameters('moduleName'), '_', '-')" in _read(_MAIN_TEMPLATE_JSON)


# --------------------------------------------------------------------------------------
# Follow-up C — Phase-1 delivered authMode=disabled, while main.bicep code default stays required.
# --------------------------------------------------------------------------------------
def test_delivered_params_default_auth_mode_disabled() -> None:
    params = json.loads(_read(_MAIN_PARAMS))
    assert params["parameters"]["authMode"]["value"] == "disabled"


def test_main_bicep_auth_mode_code_default_stays_required() -> None:
    text = _read(_MAIN_BICEP)
    # The fail-closed code default must remain, so direct main.bicep deployers still get required.
    assert "param authMode string = 'required'" in text
    assert "param authMode string = 'disabled'" not in text
