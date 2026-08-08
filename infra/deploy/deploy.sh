#!/usr/bin/env bash
#
# deploy.sh — guided, keyless, reproducible deploy of the Workloads Platform (Aegis) into the
# customer's OWN Azure subscription. This is the field / FastTrack fast path (issue #67, Phase 1):
# it mirrors the .github/workflows/release.yml pipeline exactly, but runs from a workstation or
# Azure Cloud Shell instead of GitHub Actions.
#
# What it does (all keyless — Managed Identity / your `az login`, NO secrets, keys, or admin creds):
#   1. Preflight  — confirm az is present and you are logged in to the intended subscription.
#   2. Bootstrap  — ensure the resource group and Azure Container Registry exist (admin DISABLED).
#   3. Build      — build the three images (api · worker · web) with `az acr build` (server-side ACR
#                   Tasks — no local Docker, keyless push). Skippable with --skip-build to redeploy
#                   already-published tags.
#   4. Deploy     — `az deployment group create` over infra/bicep/main.bicep, stamping every module
#                   as its own scalable ACA app/Job (the manifest scaleProfiles are the source
#                   of truth mirrored in main.bicep).
#   5. Enforce    — run scripts/cleanup_verify_state_writers.py to guarantee the API identity is the
#                   ONLY state-store writer (fail-closed brownfield gate, issues #79/#97).
#   6. Report     — print the api / web / Grafana endpoints.
#
# Everything is parameterized — NO subscription, tenant, resource group, or region is hardcoded.
#
# Usage (long or short flags):
#   ./deploy.sh -s <subscription-id> -g <resource-group> -l <location> -r <acr-name> \
#               [-t <image-tag>] [--auth-tenant-id <guid>] [--auth-audience <app-id-uri-or-clientid>] \
#               [--auth-mode required|disabled] [--manage-worm true|false] [--skip-build] [--what-if]
#
# Minimal example:
#   ./deploy.sh -s 00000000-0000-0000-0000-000000000000 -g rg-aegis -l australiaeast -r acraegis01 \
#               --auth-tenant-id <tenant-guid> --auth-audience api://aegis-workloads-platform
#
set -euo pipefail

# ---------------------------------------------------------------------------------------------------
# Resolve repo root from this script's location so it runs from anywhere (repo/infra/deploy/deploy.sh)
# ---------------------------------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# ---- Defaults (non-secret) ----
SUBSCRIPTION=""
RESOURCE_GROUP=""
LOCATION=""
ACR_NAME=""
IMAGE_TAG=""
AUTH_TENANT_ID=""
AUTH_AUDIENCE=""
AUTH_MODE="disabled"           # Phase-1 DELIVERED default (Option 3, #127): safe ONLY because the API
                               # is internal-only (network-isolated, not publicly exposed). Pass
                               # --auth-mode required (with tenant+audience) to harden. main.bicep's
                               # OWN code default stays 'required' (fail-closed) for direct deploys.
MANAGE_WORM="true"             # manage the state-container WORM policy from IaC (set false once LOCKED)
SKIP_BUILD="false"
WHAT_IF="false"

die() { echo "ERROR: $*" >&2; exit 1; }

usage() { sed -n '2,29p' "${BASH_SOURCE[0]}" | sed 's/^#\{0,1\} \{0,1\}//'; exit "${1:-0}"; }

# ---- Parse args ----
while [[ $# -gt 0 ]]; do
  case "$1" in
    -s|--subscription)     SUBSCRIPTION="$2"; shift 2;;
    -g|--resource-group)   RESOURCE_GROUP="$2"; shift 2;;
    -l|--location)         LOCATION="$2"; shift 2;;
    -r|--acr|--acr-name)   ACR_NAME="$2"; shift 2;;
    -t|--image-tag)        IMAGE_TAG="$2"; shift 2;;
    --auth-tenant-id)      AUTH_TENANT_ID="$2"; shift 2;;
    --auth-audience)       AUTH_AUDIENCE="$2"; shift 2;;
    --auth-mode)           AUTH_MODE="$2"; shift 2;;
    --manage-worm)         MANAGE_WORM="$2"; shift 2;;
    --skip-build)          SKIP_BUILD="true"; shift;;
    --what-if)             WHAT_IF="true"; shift;;
    -h|--help)             usage 0;;
    *) die "unknown argument: $1 (use --help)";;
  esac
done

# Default the image tag to a UTC timestamp so every deploy is uniquely, reproducibly identifiable.
IMAGE_TAG="${IMAGE_TAG:-$(date -u +%Y%m%d%H%M%S)}"

# ---- Validate required inputs (fail-closed) ----
[[ -n "$SUBSCRIPTION"   ]] || die "--subscription is required"
[[ -n "$RESOURCE_GROUP" ]] || die "--resource-group is required"
[[ -n "$LOCATION"       ]] || die "--location is required"
[[ -n "$ACR_NAME"       ]] || die "--acr-name is required"
case "$AUTH_MODE" in required|disabled) ;; *) die "--auth-mode must be 'required' or 'disabled'";; esac
case "$MANAGE_WORM" in true|false) ;; *) die "--manage-worm must be 'true' or 'false'";; esac

if [[ "$AUTH_MODE" == "required" && ( -z "$AUTH_TENANT_ID" || -z "$AUTH_AUDIENCE" ) ]]; then
  cat >&2 <<'WARN'
WARNING: --auth-mode is 'required' (the fail-closed default) but --auth-tenant-id / --auth-audience
         were not both supplied. The platform will DEPLOY, but the API core will REFUSE TO SERVE
         until a bearer-token tenant + audience are configured (issue #64). Supply both now, or pass
         --auth-mode disabled ONLY for a deliberate no-auth trial environment.
WARN
fi

# ---------------------------------------------------------------------------------------------------
# 1. Preflight — keyless: rely on the caller's existing `az login` (device code / MI / OIDC). We do
#    NOT log in for you and NEVER read a secret.
# ---------------------------------------------------------------------------------------------------
command -v az >/dev/null 2>&1 || die "Azure CLI (az) not found on PATH. Install: https://aka.ms/azcli"
az account show >/dev/null 2>&1 || die "Not logged in. Run 'az login' (keyless) first."

echo "==> Selecting subscription ${SUBSCRIPTION}"
az account set --subscription "$SUBSCRIPTION"

echo "==> Deploy plan"
echo "    subscription : ${SUBSCRIPTION}"
echo "    resourceGroup: ${RESOURCE_GROUP}"
echo "    location     : ${LOCATION}"
echo "    acr          : ${ACR_NAME} (admin disabled — keyless)"
echo "    imageTag     : ${IMAGE_TAG}"
echo "    authMode     : ${AUTH_MODE}"
echo "    manageWorm   : ${MANAGE_WORM}"
echo "    skipBuild    : ${SKIP_BUILD}"

# ---------------------------------------------------------------------------------------------------
# what-if SHORT-CIRCUIT (Finding 5): a preview must have NO side effects. Evaluate --what-if BEFORE
# any mutation (RG create, ACR create, image build/push) and, when set, run ONLY the deployment
# what-if preview and exit 0. The normal (non-what-if) path below is unchanged.
# ---------------------------------------------------------------------------------------------------
DEPLOY_NAME="wp-${IMAGE_TAG}"
COMMON_PARAMS=(
  location="$LOCATION"
  containerRegistry="$ACR_NAME"
  imageTag="$IMAGE_TAG"
  manageStateImmutabilityPolicy="$MANAGE_WORM"
  authMode="$AUTH_MODE"
  authTenantId="$AUTH_TENANT_ID"
  authAudience="$AUTH_AUDIENCE"
)

if [[ "$WHAT_IF" == "true" ]]; then
  echo "==> what-if (preview only — no RG/ACR create, no image build/push, no changes applied)"
  az deployment group what-if \
    --resource-group "$RESOURCE_GROUP" \
    --template-file "${REPO_ROOT}/infra/bicep/main.bicep" \
    --parameters "${COMMON_PARAMS[@]}"
  echo "==> what-if complete (nothing created, built, or deployed)."
  exit 0
fi

# ---------------------------------------------------------------------------------------------------
# 2. Bootstrap — ensure RG + ACR (idempotent). ACR admin account stays DISABLED (keyless pulls via
#    the per-component Managed Identities' AcrPull role, granted by core.bicep).
# ---------------------------------------------------------------------------------------------------
echo "==> Ensuring resource group ${RESOURCE_GROUP}"
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --only-show-errors >/dev/null

echo "==> Ensuring Azure Container Registry ${ACR_NAME} (admin disabled)"
az acr create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$ACR_NAME" \
  --sku Basic \
  --admin-enabled false \
  --location "$LOCATION" \
  --only-show-errors >/dev/null

# ---------------------------------------------------------------------------------------------------
# 3. Build & push images — server-side with `az acr build` (no local Docker daemon; keyless push
#    under your `az login`). Same image path the Bicep references: workloads-platform/<image>:<tag>.
# ---------------------------------------------------------------------------------------------------
if [[ "$SKIP_BUILD" == "true" ]]; then
  echo "==> Skipping image build (--skip-build); deploying existing tag ${IMAGE_TAG}"
else
  for img in api worker web; do
    echo "==> Building & pushing image workloads-platform/${img}:${IMAGE_TAG}"
    az acr build \
      --registry "$ACR_NAME" \
      --image "workloads-platform/${img}:${IMAGE_TAG}" \
      --image "workloads-platform/${img}:latest" \
      --file "${REPO_ROOT}/infra/docker/Dockerfile.${img}" \
      "${REPO_ROOT}"
  done
fi

# ---------------------------------------------------------------------------------------------------
# 4. Deploy the platform Bicep. (--what-if was already handled up-front, before any mutation.)
# ---------------------------------------------------------------------------------------------------
echo "==> Deploying ${DEPLOY_NAME}"
az deployment group create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEPLOY_NAME" \
  --template-file "${REPO_ROOT}/infra/bicep/main.bicep" \
  --parameters "${COMMON_PARAMS[@]}"

# ---------------------------------------------------------------------------------------------------
# 5. Enforce the API-only-writer boundary (issues #79/#97). No-op on a fresh environment; on a
#    brownfield redeploy it removes any legacy shared-identity state-writer and FAILS CLOSED if any
#    principal other than the api identity still holds a state-write role at the storage account.
# ---------------------------------------------------------------------------------------------------
echo "==> Enforcing API-only-writer boundary"
OUTPUTS="$(az deployment group show \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEPLOY_NAME" \
  --query properties.outputs -o json)"

SA_ID="$(echo "$OUTPUTS"  | python3 -c 'import json,sys;print(json.load(sys.stdin)["storageAccountId"]["value"])')"
API_PID="$(echo "$OUTPUTS" | python3 -c 'import json,sys;print(json.load(sys.stdin)["apiIdentityPrincipalId"]["value"])')"

PYTHONPATH="${REPO_ROOT}/src" python3 "${REPO_ROOT}/scripts/cleanup_verify_state_writers.py" \
  --scope "$SA_ID" \
  --resource-group "$RESOURCE_GROUP" \
  --allow "$API_PID" \
  --cleanup

# ---------------------------------------------------------------------------------------------------
# 6. Report endpoints.
# ---------------------------------------------------------------------------------------------------
echo "==> Deployed endpoints"
API_FQDN="$(echo "$OUTPUTS"  | python3 -c 'import json,sys;print(json.load(sys.stdin).get("apiFqdn",{}).get("value","(none)"))')"
WEB_FQDN="$(echo "$OUTPUTS"  | python3 -c 'import json,sys;print(json.load(sys.stdin).get("webFqdn",{}).get("value","(none)"))')"
GRAFANA="$(echo "$OUTPUTS"   | python3 -c 'import json,sys;print(json.load(sys.stdin).get("grafanaEndpoint",{}).get("value","(none)"))')"
echo "  API (internal): https://${API_FQDN}"
echo "  Web           : https://${WEB_FQDN}"
echo "  Grafana       : ${GRAFANA}"

echo "==> Done. See docs/delivery/customer-deployment.md for post-deploy verification."
