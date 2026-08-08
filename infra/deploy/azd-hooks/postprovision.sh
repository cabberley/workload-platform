#!/bin/sh
# azd postprovision hook (POSIX sh) — enforce the API-only-writer boundary (issues #79/#97), the same
# fail-closed gate the scripted deploy runs. No-op on a fresh environment; removes any legacy
# shared-identity state-writer and FAILS the provision if any principal other than the api identity
# holds a state-write role at the storage account.
#
# The storage-account id and api identity principal id come from main.bicep's provisioning outputs,
# which azd captures into the environment. We read them via `azd env get-values` (robust regardless
# of how output names are surfaced as OS env vars). Keyless — no secrets.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd)

: "${AZURE_RESOURCE_GROUP:?azd sets this during provisioning}"

VALUES=$(azd env get-values --output json)
SA_ID=$(printf '%s' "$VALUES"  | python3 -c 'import json,sys;print(json.load(sys.stdin).get("storageAccountId",""))')
API_PID=$(printf '%s' "$VALUES" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("apiIdentityPrincipalId",""))')

if [ -z "$SA_ID" ] || [ -z "$API_PID" ]; then
  echo "==> [postprovision] ERROR: could not resolve storageAccountId / apiIdentityPrincipalId from azd outputs" >&2
  exit 1
fi

echo "==> [postprovision] Enforcing API-only-writer boundary"
PYTHONPATH="${REPO_ROOT}/src" python3 "${REPO_ROOT}/scripts/cleanup_verify_state_writers.py" \
  --scope "$SA_ID" \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --allow "$API_PID" \
  --cleanup

echo "==> [postprovision] Writer boundary verified."
