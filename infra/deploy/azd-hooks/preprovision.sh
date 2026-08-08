#!/bin/sh
# azd preprovision hook (POSIX sh) — stage container images so the Bicep the platform provisions can
# actually pull them. This mirrors the scripted deploy path (infra/deploy/deploy.sh): it ensures the
# ACR that core.bicep will manage exists (idempotent, admin DISABLED — keyless) and builds ALL THREE
# images (api, worker, web) server-side with `az acr build`. The `worker` image the ACA Jobs depend
# on is built here too, closing the gap where `azd` alone never stages it.
#
# Keyless throughout (your `azd`/`az` login; no secrets). Images are tagged :latest to match
# main.bicep's default imageTag (so the provisioned apps/jobs resolve them); WP_IMAGE_TAG, if set,
# is applied as an additional traceability tag.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd)

: "${AZURE_CONTAINER_REGISTRY_NAME:?set it first: azd env set AZURE_CONTAINER_REGISTRY_NAME <acr-name>}"
: "${AZURE_RESOURCE_GROUP:?set it first: azd env set AZURE_RESOURCE_GROUP <resource-group-name>}"
: "${AZURE_LOCATION:?set it first: azd env set AZURE_LOCATION <region>}"
TAG="${WP_IMAGE_TAG:-latest}"

echo "==> [preprovision] Ensuring resource group ${AZURE_RESOURCE_GROUP} in ${AZURE_LOCATION}"
az group create \
  --name "$AZURE_RESOURCE_GROUP" \
  --location "$AZURE_LOCATION" \
  --only-show-errors >/dev/null

echo "==> [preprovision] Ensuring ACR ${AZURE_CONTAINER_REGISTRY_NAME} (admin disabled)"
az acr create \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --name "$AZURE_CONTAINER_REGISTRY_NAME" \
  --sku Basic \
  --admin-enabled false \
  --location "$AZURE_LOCATION" \
  --only-show-errors >/dev/null

for img in api worker web; do
  echo "==> [preprovision] Building & pushing workloads-platform/${img} (:latest, :${TAG})"
  az acr build \
    --registry "$AZURE_CONTAINER_REGISTRY_NAME" \
    --image "workloads-platform/${img}:latest" \
    --image "workloads-platform/${img}:${TAG}" \
    --file "${REPO_ROOT}/infra/docker/Dockerfile.${img}" \
    "${REPO_ROOT}"
done

echo "==> [preprovision] All images staged."
