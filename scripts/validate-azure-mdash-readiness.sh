#!/usr/bin/env bash
#
# validate-azure-mdash-readiness.sh
#
# Read-only readiness check for running Codename MDASH (agentic code scanning) against
# Azure Support Agent, using an EXISTING Microsoft Foundry project.
#
# SAFETY: every Azure call is a GET/list. This script never creates, updates, or deletes
# an Azure resource, never creates a Foundry project, and never prints secret values.
#
# Exit codes:
#   0  all required checks passed (warnings allowed)
#   1  at least one required check failed
#   2  the script could not run (missing tooling, not logged in)
#
# Companion document: docs/azure-validation.md
# Companion script:   scripts/validate-azure-mdash-readiness.ps1

set -euo pipefail

# ---------------------------------------------------------------------------- defaults

SUBSCRIPTION_NAME="${SUBSCRIPTION_NAME:-MCAPS-Hybrid-rafaelcas}"
RESOURCE_GROUP="${RESOURCE_GROUP:-rg-ip-mdash-AzureSupportAgent}"
FOUNDRY_ACCOUNT_NAME=""
FOUNDRY_PROJECT_NAME=""
SET_CONTEXT=0
SKIP_RBAC=0
NO_COLOUR=0

# Models MDASH requires in the connected Foundry project.
# Source: https://learn.microsoft.com/en-us/security-exposure-management/mdash-foundry-integration
REQUIRED_MODELS=("gpt-5.4" "gpt-5.3-codex" "gpt-5.4-mini")

# Minimum tokens-per-minute per deployment required by MDASH.
REQUIRED_TPM=1000000
# Azure reports Cognitive Services quota in thousands of TPM.
REQUIRED_QUOTA_UNITS=$((REQUIRED_TPM / 1000))

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
SKIP_COUNT=0
BLOCKERS=()

# ------------------------------------------------------------------------------- usage

usage() {
    cat <<'EOF'
Usage: validate-azure-mdash-readiness.sh [OPTIONS]

Read-only validation of the Azure environment required for Codename MDASH
agentic code scanning of Azure Support Agent.

Options:
  -s, --subscription NAME     Azure subscription display name.
                              Default: MCAPS-Hybrid-rafaelcas
  -g, --resource-group NAME   Resource group holding the existing Foundry resources.
                              Default: rg-ip-mdash-AzureSupportAgent
  -a, --foundry-account NAME  Pin the check to a specific Foundry (AIServices) account.
  -p, --foundry-project NAME  Pin the check to a specific Foundry project.
  -c, --set-context           Set the active az CLI subscription to the resolved ID.
                              Changes local CLI state only, never a cloud resource.
      --skip-rbac             Skip role-assignment enumeration (needs directory read).
      --no-colour             Disable ANSI colour output.
  -h, --help                  Show this help and exit.

Examples:
  ./scripts/validate-azure-mdash-readiness.sh
  ./scripts/validate-azure-mdash-readiness.sh --set-context
  ./scripts/validate-azure-mdash-readiness.sh -s "MCAPS-Hybrid-rafaelcas" -g "rg-ip-mdash-AzureSupportAgent"

Exit codes: 0 ready (warnings allowed) | 1 blocking failure | 2 cannot run
EOF
}

# ----------------------------------------------------------------------- argument parse

while [[ $# -gt 0 ]]; do
    case "$1" in
        -s|--subscription)
            [[ $# -ge 2 && -n "${2:-}" ]] || { echo "error: $1 requires a value" >&2; exit 2; }
            SUBSCRIPTION_NAME="$2"; shift 2 ;;
        -g|--resource-group)
            [[ $# -ge 2 && -n "${2:-}" ]] || { echo "error: $1 requires a value" >&2; exit 2; }
            RESOURCE_GROUP="$2"; shift 2 ;;
        -a|--foundry-account)
            [[ $# -ge 2 && -n "${2:-}" ]] || { echo "error: $1 requires a value" >&2; exit 2; }
            FOUNDRY_ACCOUNT_NAME="$2"; shift 2 ;;
        -p|--foundry-project)
            [[ $# -ge 2 && -n "${2:-}" ]] || { echo "error: $1 requires a value" >&2; exit 2; }
            FOUNDRY_PROJECT_NAME="$2"; shift 2 ;;
        -c|--set-context) SET_CONTEXT=1; shift ;;
        --skip-rbac)      SKIP_RBAC=1; shift ;;
        --no-colour|--no-color) NO_COLOUR=1; shift ;;
        -h|--help)        usage; exit 0 ;;
        *) echo "error: unknown option '$1'" >&2; usage >&2; exit 2 ;;
    esac
done

[[ -n "$SUBSCRIPTION_NAME" ]] || { echo "error: subscription name must not be empty" >&2; exit 2; }
[[ -n "$RESOURCE_GROUP"   ]] || { echo "error: resource group name must not be empty" >&2; exit 2; }

# --------------------------------------------------------------------- output helpers

if [[ $NO_COLOUR -eq 1 || ! -t 1 ]]; then
    C_RESET=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""; C_GREY=""
else
    C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'; C_CYAN=$'\033[36m'; C_GREY=$'\033[90m'
fi

header() { printf '\n%s── %s %s\n' "$C_CYAN" "$1" "$C_RESET"; }

# result <id> <status:pass|fail|warn|skip> <name> [detail] [remediation]
result() {
    local id="$1" status="$2" name="$3" detail="${4:-}" remediation="${5:-}"
    local glyph colour

    case "$status" in
        pass) glyph="[ PASS ]"; colour="$C_GREEN";  PASS_COUNT=$((PASS_COUNT + 1)) ;;
        fail) glyph="[ FAIL ]"; colour="$C_RED";    FAIL_COUNT=$((FAIL_COUNT + 1))
              BLOCKERS+=("[$id] $name${remediation:+ -> $remediation}") ;;
        warn) glyph="[ WARN ]"; colour="$C_YELLOW"; WARN_COUNT=$((WARN_COUNT + 1)) ;;
        skip) glyph="[ SKIP ]"; colour="$C_GREY";   SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
        *)    glyph="[ ???? ]"; colour="$C_RESET" ;;
    esac

    printf '%s%s %-4s %s%s\n' "$colour" "$glyph" "$id" "$name" "$C_RESET"
    [[ -n "$detail"      ]] && printf '%s            %s%s\n' "$C_GREY" "$detail" "$C_RESET"
    if [[ -n "$remediation" && ( "$status" == "fail" || "$status" == "warn" ) ]]; then
        printf '%s            -> %s%s\n' "$C_YELLOW" "$remediation" "$C_RESET"
    fi
    return 0
}

# az_json <args...> - run az and echo JSON, or echo nothing on failure. Never aborts.
az_json() {
    local out
    if out="$(az "$@" --only-show-errors 2>/dev/null)"; then
        printf '%s' "$out"
    else
        printf ''
    fi
}

has_tool() { command -v "$1" >/dev/null 2>&1; }

# ------------------------------------------------------------------------------ banner

printf '\n%s===========================================================%s\n' "$C_CYAN" "$C_RESET"
printf '%s Azure Support Agent - MDASH readiness validation%s\n' "$C_CYAN" "$C_RESET"
printf '%s===========================================================%s\n' "$C_CYAN" "$C_RESET"
printf ' Subscription  : %s\n' "$SUBSCRIPTION_NAME"
printf ' ResourceGroup : %s\n' "$RESOURCE_GROUP"
printf ' Mode          : read-only (no resource is created or modified)\n'

# ----------------------------------------------------------------------- 1. tooling

header "Tooling"

if has_tool az; then
    AZ_VERSION="$(az version --query '"azure-cli"' -o tsv 2>/dev/null || echo unknown)"
    result T1 pass "Azure CLI available" "az ${AZ_VERSION}"
else
    result T1 fail "Azure CLI available" "az was not found on PATH." \
        "Install: https://learn.microsoft.com/cli/azure/install-azure-cli"
    exit 2
fi

if has_tool jq; then
    result T2 pass "jq available"
else
    result T2 fail "jq available" "jq was not found on PATH." \
        "Install jq (apt install jq / brew install jq). This script parses JSON with it."
    exit 2
fi

if has_tool git; then
    result T3 pass "git available"
else
    result T3 warn "git available" "git was not found; repository checks are limited." \
        "Install git to enable the GitHub readiness checks."
fi

# ----------------------------------------------------------------- 2. login context

header "Azure login context"

ACCOUNT_JSON="$(az_json account show -o json)"
if [[ -z "$ACCOUNT_JSON" ]]; then
    result A1 fail "Signed in to Azure CLI" "No active az CLI session." \
        "Run: az login --tenant <tenant-id>"
    exit 2
fi

SIGNED_IN_USER="$(jq -r '.user.name // "unknown"' <<<"$ACCOUNT_JSON")"
SIGNED_IN_TYPE="$(jq -r '.user.type // "unknown"' <<<"$ACCOUNT_JSON")"
CURRENT_TENANT="$(jq -r '.tenantId // "unknown"' <<<"$ACCOUNT_JSON")"

result A1 pass "Signed in to Azure CLI" "${SIGNED_IN_USER} (type: ${SIGNED_IN_TYPE})"
result A2 pass "Current tenant resolved" "tenantId ${CURRENT_TENANT}"

# ------------------------------------------------------------------- 3. subscription

header "Subscription"

# --all so subscriptions in non-default tenants are visible too.
SUBS_JSON="$(az_json account list --all -o json)"
if [[ -z "$SUBS_JSON" ]]; then
    result S1 fail "Subscription list retrieved" "az account list returned nothing." \
        "Re-authenticate: az login --tenant <tenant-id>"
    exit 1
fi

SUB_JSON="$(jq -c --arg n "$SUBSCRIPTION_NAME" 'map(select(.name == $n)) | .[0] // empty' <<<"$SUBS_JSON")"
if [[ -z "$SUB_JSON" ]]; then
    VISIBLE="$(jq -r 'length' <<<"$SUBS_JSON")"
    result S1 fail "Subscription '${SUBSCRIPTION_NAME}' visible" \
        "Not present in ${VISIBLE} visible subscription(s)." \
        "The subscription may live in another tenant. Run: az login --tenant <tenant-id>"
    exit 1
fi

SUBSCRIPTION_ID="$(jq -r '.id'       <<<"$SUB_JSON")"
SUBSCRIPTION_STATE="$(jq -r '.state' <<<"$SUB_JSON")"
SUBSCRIPTION_TENANT="$(jq -r '.tenantId' <<<"$SUB_JSON")"

result S1 pass "Subscription '${SUBSCRIPTION_NAME}' visible"
result S2 pass "Subscription ID resolved from name" "${SUBSCRIPTION_ID}"

if [[ "$SUBSCRIPTION_STATE" == "Enabled" ]]; then
    result S3 pass "Subscription enabled" "tenant ${SUBSCRIPTION_TENANT}"
else
    result S3 fail "Subscription enabled" "state: ${SUBSCRIPTION_STATE}" \
        "A disabled subscription cannot host MDASH Foundry inference."
fi

if [[ $SET_CONTEXT -eq 1 ]]; then
    az account set --subscription "$SUBSCRIPTION_ID" --only-show-errors 2>/dev/null || true
fi

ACTIVE_ID="$(az_json account show -o json | jq -r '.id // empty')"
if [[ "$ACTIVE_ID" == "$SUBSCRIPTION_ID" ]]; then
    result S4 pass "Active subscription context" "${SUBSCRIPTION_ID}"
else
    result S4 warn "Active subscription context" \
        "Active context is ${ACTIVE_ID:-unknown}; checks below target ${SUBSCRIPTION_ID} explicitly." \
        "Re-run with --set-context, or run: az account set --subscription ${SUBSCRIPTION_ID}"
fi

# ----------------------------------------------------------------- 4. resource group

header "Resource group"

RG_JSON="$(az_json group show --name "$RESOURCE_GROUP" --subscription "$SUBSCRIPTION_ID" -o json)"
RG_FOUND=0
if [[ -z "$RG_JSON" ]]; then
    result R1 fail "Resource group '${RESOURCE_GROUP}' exists" "Not found, or no read permission." \
        "Verify the name, or grant Reader on the resource group. This script never creates it."
else
    RG_FOUND=1
    RG_LOCATION="$(jq -r '.location' <<<"$RG_JSON")"
    RG_STATE="$(jq -r '.properties.provisioningState' <<<"$RG_JSON")"
    result R1 pass "Resource group '${RESOURCE_GROUP}' exists" \
        "location ${RG_LOCATION}, provisioning ${RG_STATE}"
fi

# ------------------------------------------------------- 5. Foundry account + project

FOUNDRY_FOUND=0
FOUNDRY_NAME=""
FOUNDRY_LOCATION=""
PROJECT_JSON=""

if [[ $RG_FOUND -eq 1 ]]; then
    header "Microsoft Foundry account (existing)"

    # A Microsoft Foundry resource is Microsoft.CognitiveServices/accounts with kind AIServices.
    ACCOUNTS_JSON="$(az_json cognitiveservices account list \
        --resource-group "$RESOURCE_GROUP" --subscription "$SUBSCRIPTION_ID" -o json)"

    FOUNDRY_LIST='[]'
    if [[ -n "$ACCOUNTS_JSON" ]]; then
        FOUNDRY_LIST="$(jq -c 'map(select(.kind == "AIServices"))' <<<"$ACCOUNTS_JSON")"
    fi
    if [[ -n "$FOUNDRY_ACCOUNT_NAME" ]]; then
        FOUNDRY_LIST="$(jq -c --arg n "$FOUNDRY_ACCOUNT_NAME" 'map(select(.name == $n))' <<<"$FOUNDRY_LIST")"
    fi

    FOUNDRY_COUNT="$(jq -r 'length' <<<"$FOUNDRY_LIST")"

    if [[ "$FOUNDRY_COUNT" -eq 0 ]]; then
        result F1 fail "Foundry (AIServices) account discovered" \
            "No AIServices account in '${RESOURCE_GROUP}'." \
            "MDASH requires a dedicated Foundry resource. Create it in the portal (out of scope for this read-only script), then re-run."

        # Surface hub-based workspaces so the operator knows what does exist.
        ML_JSON="$(az_json resource list --resource-group "$RESOURCE_GROUP" \
            --resource-type Microsoft.MachineLearningServices/workspaces \
            --subscription "$SUBSCRIPTION_ID" -o json)"
        ML_COUNT="$(jq -r 'length' <<<"${ML_JSON:-[]}")"
        if [[ "$ML_COUNT" -gt 0 ]]; then
            result F1b warn "Legacy ML workspace present" \
                "Found ${ML_COUNT} Microsoft.MachineLearningServices/workspaces resource(s)." \
                "MDASH expects a Microsoft Foundry (AIServices) resource, not a hub-based ML workspace."
        fi
    else
        if [[ "$FOUNDRY_COUNT" -gt 1 ]]; then
            NAMES="$(jq -r 'map(.name) | join(", ")' <<<"$FOUNDRY_LIST")"
            result F1 warn "Foundry (AIServices) account discovered" \
                "Found ${FOUNDRY_COUNT}: ${NAMES}. Using the first." \
                "Pin one with --foundry-account to make this deterministic."
        fi

        FOUNDRY_JSON="$(jq -c '.[0]' <<<"$FOUNDRY_LIST")"
        FOUNDRY_NAME="$(jq -r '.name'     <<<"$FOUNDRY_JSON")"
        FOUNDRY_LOCATION="$(jq -r '.location' <<<"$FOUNDRY_JSON")"
        FOUNDRY_SKU="$(jq -r '.sku.name // "unknown"' <<<"$FOUNDRY_JSON")"
        FOUNDRY_FOUND=1

        if [[ "$FOUNDRY_COUNT" -eq 1 ]]; then
            result F1 pass "Foundry (AIServices) account discovered" \
                "${FOUNDRY_NAME} | ${FOUNDRY_LOCATION} | sku ${FOUNDRY_SKU}"
        fi

        # ------------------------------------------------------------ project discovery
        header "Microsoft Foundry project (existing)"

        SCOPE="/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.CognitiveServices/accounts/${FOUNDRY_NAME}/projects"

        PROJECTS_JSON="$(az_json resource list \
            --resource-type Microsoft.CognitiveServices/accounts/projects \
            --resource-group "$RESOURCE_GROUP" --subscription "$SUBSCRIPTION_ID" -o json)"

        MATCHED='[]'
        if [[ -n "$PROJECTS_JSON" ]]; then
            MATCHED="$(jq -c --arg s "$SCOPE" 'map(select(.id | startswith($s + "/")))' <<<"$PROJECTS_JSON")"
        fi
        if [[ -n "$FOUNDRY_PROJECT_NAME" ]]; then
            MATCHED="$(jq -c --arg n "$FOUNDRY_PROJECT_NAME" \
                'map(select(.id | endswith("/" + $n)))' <<<"$MATCHED")"
        fi

        PROJECT_COUNT="$(jq -r 'length' <<<"$MATCHED")"
        if [[ "$PROJECT_COUNT" -eq 0 ]]; then
            result F2 fail "Foundry project discovered" \
                "No project under account '${FOUNDRY_NAME}'." \
                "Create the project in the Foundry portal (out of scope for this read-only script), then re-run."
        else
            PROJECT_ID="$(jq -r '.[0].id' <<<"$MATCHED")"
            # The list API returns a thin projection; fetch the full resource for endpoints.
            PROJECT_JSON="$(az_json resource show --ids "$PROJECT_ID" --api-version 2025-06-01 -o json)"
            [[ -z "$PROJECT_JSON" ]] && PROJECT_JSON="$(jq -c '.[0]' <<<"$MATCHED")"

            PROJECT_NAME="${PROJECT_ID##*/}"
            PROJECT_ENDPOINT="$(jq -r '.properties.endpoints."AI Foundry API" // empty' <<<"$PROJECT_JSON")"

            result F2 pass "Foundry project discovered" \
                "${PROJECT_NAME}${PROJECT_ENDPOINT:+ | ${PROJECT_ENDPOINT}}"

            if [[ -n "$PROJECT_ENDPOINT" ]]; then
                result F3 pass "Foundry project endpoint resolved" \
                    "Use this as the Project endpoint during MDASH portal onboarding."
            else
                result F3 warn "Foundry project endpoint resolved" \
                    "Endpoint not present on the project resource." \
                    "Copy the Project endpoint from the Foundry portal instead."
            fi
        fi

        # --------------------------------------------------------- model deployments
        header "MDASH model deployments"

        DEPLOY_JSON="$(az_json cognitiveservices account deployment list \
            --name "$FOUNDRY_NAME" --resource-group "$RESOURCE_GROUP" \
            --subscription "$SUBSCRIPTION_ID" -o json)"
        [[ -z "$DEPLOY_JSON" ]] && DEPLOY_JSON='[]'

        for model in "${REQUIRED_MODELS[@]}"; do
            HIT="$(jq -c --arg m "$model" \
                'map(select(.properties.model.name == $m)) | .[0] // empty' <<<"$DEPLOY_JSON")"

            if [[ -z "$HIT" ]]; then
                result "M-${model}" fail "Model deployed: ${model}" \
                    "Not deployed in this Foundry account." \
                    "Deploy '${model}' in the Foundry portal (Build > Deployments), then set TPM to ${REQUIRED_TPM}."
                continue
            fi

            # Cognitive Services reports deployment capacity in thousands of TPM.
            CAPACITY="$(jq -r '.sku.capacity // 0' <<<"$HIT")"
            if [[ "$CAPACITY" -ge "$REQUIRED_QUOTA_UNITS" ]]; then
                result "M-${model}" pass "Model deployed: ${model}" \
                    "capacity ${CAPACITY}K TPM (>= ${REQUIRED_QUOTA_UNITS}K required)"
            else
                result "M-${model}" warn "Model deployed: ${model}" \
                    "capacity ${CAPACITY}K TPM is below the ${REQUIRED_QUOTA_UNITS}K TPM MDASH minimum." \
                    "Raise Tokens per Minute Rate Limit to ${REQUIRED_TPM} on this deployment."
            fi
        done

        # Regional availability, so a missing deployment can be told apart from a model
        # that simply is not offered in this region.
        CATALOGUE_JSON="$(az_json cognitiveservices model list \
            --location "$FOUNDRY_LOCATION" --subscription "$SUBSCRIPTION_ID" -o json)"
        if [[ -n "$CATALOGUE_JSON" ]]; then
            MISSING=()
            for model in "${REQUIRED_MODELS[@]}"; do
                if ! jq -e --arg m "$model" 'any(.[]; .model.name == $m)' <<<"$CATALOGUE_JSON" >/dev/null; then
                    MISSING+=("$model")
                fi
            done
            if [[ ${#MISSING[@]} -gt 0 ]]; then
                result M-REGION fail "Required models offered in region" \
                    "Not offered in ${FOUNDRY_LOCATION}: ${MISSING[*]}" \
                    "Use a Foundry resource in a region that offers all three MDASH models."
            else
                result M-REGION pass "Required models offered in region" \
                    "All ${#REQUIRED_MODELS[@]} available in ${FOUNDRY_LOCATION}."
            fi
        else
            result M-REGION skip "Required models offered in region" "Model catalogue could not be read."
        fi

        # ------------------------------------------------------- auth + network posture
        header "Foundry authentication and network"

        # MDASH portal onboarding asks for a Project endpoint AND an API key. When local
        # auth is disabled no API key can be issued, so onboarding cannot complete as
        # documented.
        LOCAL_AUTH_DISABLED="$(jq -r '.properties.disableLocalAuth // false' <<<"$FOUNDRY_JSON")"
        if [[ "$LOCAL_AUTH_DISABLED" == "true" ]]; then
            result F4 fail "Foundry API key auth available" \
                "disableLocalAuth = true, so no API key can be issued for this account." \
                "MDASH onboarding requires a Project endpoint + API key. Either enable local auth on this dedicated MDASH resource, or confirm with the MDASH team that Entra-only onboarding is supported."
        else
            result F4 pass "Foundry API key auth available" \
                "Local (key) auth is enabled; an API key can be retrieved for onboarding."
        fi

        PUBLIC_ACCESS="$(jq -r '.properties.publicNetworkAccess // "Unknown"' <<<"$FOUNDRY_JSON")"
        if [[ "$PUBLIC_ACCESS" == "Enabled" ]]; then
            result F5 pass "MDASH can reach the Foundry endpoint" \
                'publicNetworkAccess = Enabled (equivalent to "All networks"); no IP allow-list needed.'
        else
            result F5 warn "MDASH can reach the Foundry endpoint" \
                "publicNetworkAccess = ${PUBLIC_ACCESS}." \
                'With "Selected networks and private endpoints", add the documented MDASH service IP ranges or onboarding validation will fail. See docs/mdash-readiness.md.'
        fi
    fi

    # ------------------------------------------------------------- managed identity
    header "Managed identity"

    if [[ $FOUNDRY_FOUND -eq 1 ]]; then
        ID_TYPE="$(jq -r '.identity.type // empty' <<<"$FOUNDRY_JSON")"
        if [[ -n "$ID_TYPE" ]]; then
            result I1 pass "Foundry account managed identity" "type ${ID_TYPE}"
        else
            result I1 warn "Foundry account managed identity" "No managed identity assigned." \
                "Assign a managed identity to prefer Entra auth over keys."
        fi
    else
        result I1 skip "Foundry account managed identity" "Resource not discovered."
    fi

    if [[ -n "$PROJECT_JSON" ]]; then
        P_ID_TYPE="$(jq -r '.identity.type // empty' <<<"$PROJECT_JSON")"
        if [[ -n "$P_ID_TYPE" ]]; then
            result I2 pass "Foundry project managed identity" "type ${P_ID_TYPE}"
        else
            result I2 warn "Foundry project managed identity" "No managed identity assigned." \
                "Assign a managed identity to prefer Entra auth over keys."
        fi
    else
        result I2 skip "Foundry project managed identity" "Resource not discovered."
    fi

    UAMI_JSON="$(az_json identity list --resource-group "$RESOURCE_GROUP" \
        --subscription "$SUBSCRIPTION_ID" -o json)"
    UAMI_COUNT="$(jq -r 'length' <<<"${UAMI_JSON:-[]}")"
    result I3 pass "User-assigned managed identities in resource group" "${UAMI_COUNT} found"

    # ------------------------------------------------------------------- Key Vault
    header "Key Vault"

    KV_JSON="$(az_json keyvault list --resource-group "$RESOURCE_GROUP" \
        --subscription "$SUBSCRIPTION_ID" -o json)"
    KV_COUNT="$(jq -r 'length' <<<"${KV_JSON:-[]}")"

    if [[ "$KV_COUNT" -eq 0 ]]; then
        result K1 warn "Key Vault present" "No Key Vault in '${RESOURCE_GROUP}'." \
            "Azure Support Agent reads SECRETS_ENCRYPTION_KEY from the environment. A Key Vault is recommended to source it. See docs/security-review.md."
    else
        KV_NAMES="$(jq -r 'map(.name) | join(", ")' <<<"$KV_JSON")"
        result K1 pass "Key Vault present" "${KV_NAMES}"

        while IFS= read -r vault; do
            [[ -z "$vault" ]] && continue
            KV_DETAIL="$(az_json keyvault show --name "$vault" --subscription "$SUBSCRIPTION_ID" -o json)"
            [[ -z "$KV_DETAIL" ]] && continue
            RBAC_ON="$(jq -r '.properties.enableRbacAuthorization // false' <<<"$KV_DETAIL")"
            if [[ "$RBAC_ON" == "true" ]]; then
                result "K2-${vault}" pass "Key Vault '${vault}' uses Azure RBAC"
            else
                result "K2-${vault}" warn "Key Vault '${vault}' uses Azure RBAC" \
                    "Still using legacy access policies." \
                    "Enable Azure RBAC authorization for consistent, auditable access control."
            fi
        done < <(jq -r '.[].name' <<<"$KV_JSON")
    fi
fi

# --------------------------------------------------------------------------- 6. RBAC

header "RBAC and permissions"

if [[ $SKIP_RBAC -eq 1 ]]; then
    result P1 skip "Role assignments for signed-in principal" "--skip-rbac was supplied."
else
    SIGNED_IN_ID="$(az_json ad signed-in-user show -o json | jq -r '.id // empty')"
    if [[ -z "$SIGNED_IN_ID" ]]; then
        result P1 skip "Role assignments for signed-in principal" \
            "Directory read unavailable (service principal login, or Graph blocked)." \
            "Re-run as a user principal, or verify role assignments in the portal."
    else
        SCOPE="/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}"
        ASSIGN_JSON="$(az_json role assignment list --assignee "$SIGNED_IN_ID" \
            --scope "$SCOPE" --include-inherited --subscription "$SUBSCRIPTION_ID" -o json)"
        ROLES="$(jq -r 'map(.roleDefinitionName) | unique | join(", ")' <<<"${ASSIGN_JSON:-[]}")"

        if [[ -z "$ROLES" ]]; then
            result P1 warn "Role assignments for signed-in principal" \
                "No direct or inherited assignments found at the resource group scope." \
                "Access may be granted through a group. Confirm in the portal."
        else
            result P1 pass "Role assignments for signed-in principal" "${ROLES}"

            # Reader (or higher) is enough for everything this script does.
            if jq -e 'any(.[]; .roleDefinitionName == "Reader" or .roleDefinitionName == "Contributor" or .roleDefinitionName == "Owner")' \
                <<<"$ASSIGN_JSON" >/dev/null; then
                result P2 pass "Permission to validate (read)"
            else
                result P2 warn "Permission to validate (read)" \
                    "No Reader/Contributor/Owner at this scope." \
                    "Grant Reader on the resource group to run validation."
            fi

            # Deploying Foundry model deployments needs write access.
            if jq -e 'any(.[]; .roleDefinitionName == "Contributor" or .roleDefinitionName == "Owner" or .roleDefinitionName == "Cognitive Services Contributor")' \
                <<<"$ASSIGN_JSON" >/dev/null; then
                result P3 pass "Permission to deploy models"
            else
                result P3 warn "Permission to deploy models" \
                    "No Contributor/Owner/Cognitive Services Contributor at this scope." \
                    "Required only when you deploy the three MDASH models. Validation itself needs just Reader."
            fi
        fi
    fi
fi

# ------------------------------------------------------------- 7. Defender prereqs

header "Defender for Cloud prerequisites"

PROVIDERS_JSON="$(az_json provider list --subscription "$SUBSCRIPTION_ID" -o json)"

check_provider() {
    local ns="$1" severity="$2"
    local state
    state="$(jq -r --arg n "$ns" 'map(select(.namespace == $n)) | .[0].registrationState // "unknown"' \
        <<<"${PROVIDERS_JSON:-[]}")"
    if [[ "$state" == "Registered" ]]; then
        result "D-${ns}" pass "Provider registered: ${ns}"
    else
        result "D-${ns}" "$severity" "Provider registered: ${ns}" "state: ${state}" \
            "Run: az provider register --namespace ${ns} --subscription ${SUBSCRIPTION_ID}"
    fi
}

check_provider "Microsoft.Security"          fail
check_provider "Microsoft.CognitiveServices" fail
# Deploying Azure Support Agent itself needs the Postgres provider.
check_provider "Microsoft.DBforPostgreSQL"   warn

PRICING_JSON="$(az_json security pricing list --subscription "$SUBSCRIPTION_ID" -o json)"
if [[ -z "$PRICING_JSON" ]]; then
    result D1 skip "Defender for Cloud plans readable" \
        "Could not read pricing (needs Security Reader)." \
        "Grant Security Reader, or check Defender for Cloud in the portal."
else
    for plan in CloudPosture AI; do
        TIER="$(jq -r --arg p "$plan" \
            '.value | map(select(.name == $p)) | .[0].pricingTier // "NotFound"' <<<"$PRICING_JSON")"
        if [[ "$TIER" == "Standard" ]]; then
            result "D2-${plan}" pass "Defender plan enabled: ${plan}"
        else
            result "D2-${plan}" warn "Defender plan enabled: ${plan}" "tier: ${TIER}" \
                "Enable the ${plan} plan in Defender for Cloud for full Exposure Management context."
        fi
    done
fi

# ---------------------------------------------------------------- 8. GitHub readiness

header "GitHub integration readiness"

if ! has_tool git; then
    result G1 skip "Repository detected" "git unavailable."
else
    GIT_REMOTE="$(git remote get-url origin 2>/dev/null || true)"
    if [[ -z "$GIT_REMOTE" ]]; then
        result G1 warn "Repository detected" \
            "No origin remote; run from inside the repository clone." \
            "MDASH remote scanning connects a GitHub organization, so the code must live in GitHub."
    else
        result G1 pass "Repository detected" "${GIT_REMOTE}"

        if [[ "$GIT_REMOTE" == *github.com* ]]; then
            result G2 pass "Hosted on GitHub" "Eligible for the MDASH GitHub connector (remote scan)."
        else
            result G2 warn "Hosted on GitHub" "Origin is not github.com." \
                "Use the Defender CLI scanning path instead of the GitHub connector."
        fi

        REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
        if [[ -n "$REPO_ROOT" ]]; then
            if [[ -d "${REPO_ROOT}/.github/workflows" ]]; then
                WF_COUNT="$(find "${REPO_ROOT}/.github/workflows" -name '*.yml' -type f 2>/dev/null | wc -l | tr -d ' ')"
                result G3 pass "GitHub Actions workflows present" "${WF_COUNT} workflow file(s)"
            else
                result G3 warn "GitHub Actions workflows present" "No .github/workflows directory." \
                    "Add CodeQL and dependency-review workflows so MDASH findings sit alongside GHAS results."
            fi
        fi
    fi
fi

# ------------------------------------------------------------------------- 9. summary

header "Summary"
printf ' %sPassed   : %s%s\n' "$C_GREEN"  "$PASS_COUNT" "$C_RESET"
printf ' %sFailed   : %s%s\n' "$C_RED"    "$FAIL_COUNT" "$C_RESET"
printf ' %sWarnings : %s%s\n' "$C_YELLOW" "$WARN_COUNT" "$C_RESET"
printf ' %sSkipped  : %s%s\n' "$C_GREY"   "$SKIP_COUNT" "$C_RESET"

if [[ ${#BLOCKERS[@]} -gt 0 ]]; then
    printf '\n%sBlocking issues:%s\n' "$C_RED" "$C_RESET"
    for b in "${BLOCKERS[@]}"; do
        printf '%s  - %s%s\n' "$C_RED" "$b" "$C_RESET"
    done
fi

printf '\n'
[[ $FAIL_COUNT -gt 0 ]] && exit 1
exit 0
