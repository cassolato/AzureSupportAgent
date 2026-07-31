---
layout: default
title: Azure validation
nav_exclude: true
---

# Azure validation — MDASH readiness scripts

How to run, read, and extend the two environment validation scripts that verify the Azure
prerequisites for Codename MDASH agentic code scanning of Azure Support Agent.

| Script | Platform | Prerequisites |
|---|---|---|
| `scripts/validate-azure-mdash-readiness.ps1` | PowerShell 7+ (Windows, Linux, macOS) | Azure CLI |
| `scripts/validate-azure-mdash-readiness.sh` | Bash 4+ (Linux, macOS, WSL, Git Bash) | Azure CLI, `jq` |

Both perform the same 17 grouped checks and produce the same verdicts. Pick whichever
fits your shell.

---

## 1. Safety guarantees

These scripts are intended to be run against a production subscription without a change
window. They are constrained accordingly.

| Guarantee | How it is enforced |
|---|---|
| No resource is created | Every Azure call is `show`, `list`, or `get`. No `create`, `update`, `delete`, or `deploy` verb appears in either script. |
| **No Foundry project is created** | Discovery filters existing resources. When nothing is found the script fails the check and prints guidance; it never provisions. |
| No secrets are printed | The scripts never call `az cognitiveservices account keys list`, `az keyvault secret show`, or any other secret-reading command. |
| No hardcoded secrets | The only literals are a subscription **name**, a resource group **name**, and public model identifiers. |
| Fails gracefully | Every Azure call is wrapped. A failure records a `FAIL`/`WARN`/`SKIP` and execution continues, so one pass reports every problem. |
| Only local state changes | `--set-context` / `-SetContext` runs `az account set`, which changes the local CLI profile, never a cloud resource. It is opt-in. |

The single mutating command in either file is `az account set`, and it is guarded behind
an explicit flag.

---

## 2. Quick start

```powershell
# PowerShell
cd <repo-root>
./scripts/validate-azure-mdash-readiness.ps1 -SetContext
```

```bash
# Bash
cd <repo-root>
chmod +x scripts/validate-azure-mdash-readiness.sh
./scripts/validate-azure-mdash-readiness.sh --set-context
```

If the subscription is not visible, sign in to the correct tenant first:

```bash
az login --tenant 16b3c013-d300-468d-ac64-7eda0820b6d3
```

---

## 3. Parameters

### PowerShell

| Parameter | Type | Default | Purpose |
|---|---|---|---|
| `-SubscriptionName` | string | `MCAPS-Hybrid-rafaelcas` | Subscription **display name**; the ID is resolved from it |
| `-ResourceGroupName` | string | `rg-ip-mdash-AzureSupportAgent` | Resource group holding the Foundry resources |
| `-FoundryAccountName` | string | *(discovered)* | Pin a specific Foundry account |
| `-FoundryProjectName` | string | *(discovered)* | Pin a specific Foundry project |
| `-SetContext` | switch | off | Set the active CLI subscription |
| `-SkipRbac` | switch | off | Skip role-assignment enumeration |
| `-Json` | switch | off | Emit a JSON summary on stdout; diagnostics go to stderr |

`-SubscriptionName` and `-ResourceGroupName` are `[ValidateNotNullOrEmpty()]`.

Full comment-based help:

```powershell
Get-Help ./scripts/validate-azure-mdash-readiness.ps1 -Full
```

### Bash

| Option | Default | Purpose |
|---|---|---|
| `-s`, `--subscription NAME` | `MCAPS-Hybrid-rafaelcas` | Subscription display name |
| `-g`, `--resource-group NAME` | `rg-ip-mdash-AzureSupportAgent` | Resource group |
| `-a`, `--foundry-account NAME` | *(discovered)* | Pin a specific Foundry account |
| `-p`, `--foundry-project NAME` | *(discovered)* | Pin a specific Foundry project |
| `-c`, `--set-context` | off | Set the active CLI subscription |
| `--skip-rbac` | off | Skip role-assignment enumeration |
| `--no-colour` | auto | Disable ANSI colour (also auto-disabled when not a TTY) |
| `-h`, `--help` | — | Usage and exit |

Options that take a value are validated; a missing value or an unknown flag exits `2`.
`SUBSCRIPTION_NAME` and `RESOURCE_GROUP` may also be supplied as environment variables.

```bash
./scripts/validate-azure-mdash-readiness.sh --help
```

---

## 4. Exit codes

| Code | Meaning | CI behaviour |
|---|---|---|
| `0` | All required checks passed. Warnings may be present | Proceed |
| `1` | At least one required check failed | Block |
| `2` | The script could not run — missing tooling or not signed in | Investigate the runner |

Warnings never change the exit code: they flag recommended hardening or optional
components, not MDASH blockers.

---

## 5. What is checked

### Tooling — `T*`

| ID | Check | Failure impact |
|---|---|---|
| `T1` | Azure CLI on PATH | Exit `2` |
| `T2` | `jq` on PATH *(Bash only)* | Exit `2` |
| `T2`/`T3` | `git` on PATH | Warning — GitHub checks limited |

### Azure login context — `A*`

| ID | Check | Notes |
|---|---|---|
| `A1` | An `az` session exists | Prints UPN and principal type; never a token |
| `A2` | Current tenant resolved | Prints `tenantId` |

### Subscription — `S*`

| ID | Check | Notes |
|---|---|---|
| `S1` | Subscription visible **by name** | Uses `az account list --all` so subscriptions in non-default tenants are seen |
| `S2` | Subscription ID resolved from the name | The core requirement — nothing is hardcoded |
| `S3` | Subscription state is `Enabled` | |
| `S4` | Active context matches the resolved ID | Warning only: every later call passes `--subscription` explicitly |

Resolution logic:

```bash
az account list --all --query "[?name=='MCAPS-Hybrid-rafaelcas'].id" -o tsv
```

### Resource group — `R1`

Confirms the group exists and reports location plus provisioning state.

### Microsoft Foundry — `F*`

| ID | Check | Notes |
|---|---|---|
| `F1` | Foundry account discovered | `Microsoft.CognitiveServices/accounts` with `kind == AIServices` |
| `F1b` | Legacy ML workspace present | Warning; a hub-based workspace is not a substitute |
| `F2` | Foundry project discovered | Child `.../projects` resource |
| `F3` | Project endpoint resolved | The value needed for portal onboarding |
| `F4` | API key auth available | Fails when `disableLocalAuth: true` |
| `F5` | MDASH can reach the endpoint | Passes on `publicNetworkAccess: Enabled` |

Discovery is by **resource type and kind**, not by name, so renaming the resource does not
break validation. When several Foundry accounts exist the script warns and uses the first;
`-FoundryAccountName` / `--foundry-account` makes it deterministic.

### Model deployments — `M*`

| ID | Check |
|---|---|
| `M-gpt-5.4` | `gpt-5.4` deployed, capacity ≥ 1,000 K TPM |
| `M-gpt-5.3-codex` | `gpt-5.3-codex` deployed, capacity ≥ 1,000 K TPM |
| `M-gpt-5.4-mini` | `gpt-5.4-mini` deployed, capacity ≥ 1,000 K TPM |
| `M-REGION` | All three offered in the Foundry account's region |

Azure reports Cognitive Services capacity in **thousands of TPM**, so MDASH's 1,000,000
TPM minimum is `capacity >= 1000`. The scripts encode this conversion explicitly:

```powershell
$script:RequiredTpm = 1000000
$script:RequiredQuotaUnits = $script:RequiredTpm / 1000   # capacity is in K TPM
```

`M-REGION` exists so a missing deployment can be distinguished from a model that is not
offered in the region at all — very different remediation.

### Managed identity — `I*`

| ID | Check |
|---|---|
| `I1` | Foundry account identity type |
| `I2` | Foundry project identity type |
| `I3` | Count of user-assigned identities in the resource group |

### Key Vault — `K*`

| ID | Check | Notes |
|---|---|---|
| `K1` | A Key Vault exists in the resource group | Warning if absent — recommended for `SECRETS_ENCRYPTION_KEY` |
| `K2-<name>` | Vault uses Azure RBAC rather than access policies | Warning if legacy |

### RBAC — `P*`

| ID | Check | Notes |
|---|---|---|
| `P1` | Role assignments for the signed-in principal | `SKIP` when signed in as a service principal |
| `P2` | Read permission to validate | Reader / Contributor / Owner |
| `P3` | Write permission to deploy models | Contributor / Owner / Cognitive Services Contributor |

Reader is enough to run the script. `P3` matters only when you deploy the MDASH models.

### Defender prerequisites — `D*`

| ID | Check | Severity |
|---|---|---|
| `D-Microsoft.Security` | Provider registered | Fail |
| `D-Microsoft.CognitiveServices` | Provider registered | Fail |
| `D-PG` | `Microsoft.DBforPostgreSQL` registered | Warn — blocks `deploy/main.bicep`, not MDASH |
| `D2-CloudPosture` | Defender CSPM on Standard | Warn |
| `D2-AI` | Defender for AI on Standard | Warn |

### GitHub readiness — `G*`

| ID | Check |
|---|---|
| `G1` | Run from inside a git clone; origin remote reported |
| `G2` | Origin is GitHub — required for the MDASH GitHub connector |
| `G3` | `.github/workflows` exists |

---

## 6. Expected output

Recorded against `MCAPS-Hybrid-rafaelcas` / `rg-ip-mdash-AzureSupportAgent` on
**2026-07-31**. Abridged.

```text
===========================================================
 Azure Support Agent - MDASH readiness validation
===========================================================
 Subscription  : MCAPS-Hybrid-rafaelcas
 ResourceGroup : rg-ip-mdash-AzureSupportAgent
 Mode          : read-only (no resource is created or modified)

── Tooling
[ PASS ] T1   Azure CLI available
            az 2.80.0
[ PASS ] T2   git available

── Azure login context
[ PASS ] A1   Signed in to Azure CLI
            rafaelcas@microsoft.com (type: user)
[ PASS ] A2   Current tenant resolved
            tenantId 16b3c013-d300-468d-ac64-7eda0820b6d3

── Subscription
[ PASS ] S1   Subscription 'MCAPS-Hybrid-rafaelcas' visible
[ PASS ] S2   Subscription ID resolved from name
            4bd56768-1b2f-4c85-951f-68ce70b7c999
[ PASS ] S3   Subscription enabled
[ PASS ] S4   Active subscription context

── Resource group
[ PASS ] R1   Resource group 'rg-ip-mdash-AzureSupportAgent' exists
            location swedencentral, provisioning Succeeded

── Microsoft Foundry account (existing)
[ PASS ] F1   Foundry (AIServices) account discovered
            rafaelcas-msfoundry-resource-mda | swedencentral | sku S0

── Microsoft Foundry project (existing)
[ PASS ] F2   Foundry project discovered
            rafaelcas-msfoundry-project-mdash | https://rafaelcas-msfoundry-resource-mda.services.ai.azure.com/api/projects/rafaelcas-msfoundry-project-mdash
[ PASS ] F3   Foundry project endpoint resolved

── MDASH model deployments
[ PASS ] M-gpt-5.4 Model deployed: gpt-5.4
            capacity 1000K TPM (>= 1000K required)
[ PASS ] M-gpt-5.3-codex Model deployed: gpt-5.3-codex
            capacity 1000K TPM (>= 1000K required)
[ PASS ] M-gpt-5.4-mini Model deployed: gpt-5.4-mini
            capacity 1000K TPM (>= 1000K required)
[ PASS ] M-REGION Required models offered in region
            All 3 available in swedencentral.

── Foundry authentication and network
[ FAIL ] F4   Foundry API key auth available
            disableLocalAuth = true, so no API key can be issued for this account.
[ PASS ] F5   MDASH can reach the Foundry endpoint
            publicNetworkAccess = Enabled (equivalent to "All networks"); no IP allow-list needed.

── Managed identity
[ PASS ] I1   Foundry account managed identity   type SystemAssigned
[ PASS ] I2   Foundry project managed identity   type SystemAssigned
[ PASS ] I3   User-assigned managed identities in resource group   0 found

── Key Vault
[ WARN ] K1   Key Vault present
            No Key Vault in 'rg-ip-mdash-AzureSupportAgent'.

── RBAC and permissions
[ PASS ] P1   Role assignments for signed-in principal
            Foundry User, Owner
[ PASS ] P2   Permission to validate (read)
[ PASS ] P3   Permission to deploy models

── Defender for Cloud prerequisites
[ PASS ] D-Microsoft.Security Provider registered: Microsoft.Security
[ PASS ] D-Microsoft.CognitiveServices Provider registered: Microsoft.CognitiveServices
[ WARN ] D-PG Provider registered: Microsoft.DBforPostgreSQL
            state: NotRegistered. deploy/main.bicep provisions a PostgreSQL flexible server.
[ PASS ] D2-CloudPosture Defender plan enabled: CloudPosture
[ PASS ] D2-AI Defender plan enabled: AI

── GitHub integration readiness
[ PASS ] G1   Repository detected
            https://github.com/cassolato/AzureSupportAgent.git
[ PASS ] G2   Hosted on GitHub
[ WARN ] G3   GitHub Actions workflows present
            No .github/workflows directory.

── Summary
 Passed   : 30
 Failed   : 1
 Warnings : 2
 Skipped  : 0

Blocking issues:
  - [F4] Foundry API key auth available
```

Exit code `1`.

> Recorded **after** the three MDASH models were deployed and after this change added
> `.github/workflows`. The baseline run before any of that was 26 passed / 4 failed /
> 3 warnings.

---

## 7. Machine-readable output

The PowerShell script supports `-Json` for pipelines. Human-readable diagnostics move to
stderr so stdout stays parseable.

```powershell
$r = ./scripts/validate-azure-mdash-readiness.ps1 -Json | ConvertFrom-Json

$r.summary.failed                      # 1
$r.facts.subscriptionId                # 4bd56768-1b2f-4c85-951f-68ce70b7c999
$r.facts.foundryProjectEndpoint        # https://...
$r.checks | Where-Object status -eq 'Fail' | Select-Object id, name, remediation
```

Shape:

```jsonc
{
  "subscriptionName":  "MCAPS-Hybrid-rafaelcas",
  "resourceGroupName": "rg-ip-mdash-AzureSupportAgent",
  "facts": {
    "subscriptionId":         "4bd56768-1b2f-4c85-951f-68ce70b7c999",
    "foundryAccountName":     "rafaelcas-msfoundry-resource-mda",
    "foundryProjectName":     "rafaelcas-msfoundry-project-mdash",
    "foundryProjectEndpoint": "https://.../api/projects/...",
    "foundryLocalAuthDisabled": true,
    "deployedModels":         ["gpt-5.4", "gpt-5.3-codex", "gpt-5.4-mini"],
    "defenderStandardPlans":  ["CloudPosture", "AI", "..."]
  },
  "summary": { "passed": 30, "failed": 1, "warnings": 2, "skipped": 0 },
  "checks":  [ { "id": "F4", "name": "...", "status": "Fail",
                 "detail": "...", "remediation": "..." } ]
}
```

`facts` contains no secrets: names, IDs, endpoints, and booleans only.

---

## 8. Using the scripts in CI

```yaml
- name: Validate MDASH readiness
  shell: bash
  run: |
    ./scripts/validate-azure-mdash-readiness.sh \
      --subscription "MCAPS-Hybrid-rafaelcas" \
      --resource-group "rg-ip-mdash-AzureSupportAgent" \
      --skip-rbac \
      --no-colour
```

Notes:

- Use `--skip-rbac`. A federated/service-principal login cannot read `az ad signed-in-user`,
  so the check would `SKIP` anyway; passing the flag makes the intent explicit.
- Use `--no-colour` for clean logs (auto-detected when stdout is not a TTY).
- The job fails on exit `1`, which is the desired gate.
- Prefer OIDC federated credentials over a client secret for the Azure login step.

---

## 9. Manual verification

Every automated check has a manual equivalent, for spot-checking or when the scripts
cannot run.

```bash
SUB=$(az account list --all --query "[?name=='MCAPS-Hybrid-rafaelcas'].id" -o tsv)
RG=rg-ip-mdash-AzureSupportAgent

# Context
az account show --query "{name:name,id:id,tenant:tenantId,user:user.name}" -o json

# Resource group
az group show --name "$RG" --subscription "$SUB" --query "{location:location,state:properties.provisioningState}"

# Foundry account
az cognitiveservices account list -g "$RG" --subscription "$SUB" \
  --query "[?kind=='AIServices'].{name:name,location:location,sku:sku.name}" -o table

# Auth mode and network exposure
az cognitiveservices account show -n <account> -g "$RG" --subscription "$SUB" \
  --query "{disableLocalAuth:properties.disableLocalAuth,publicNetworkAccess:properties.publicNetworkAccess}"

# Foundry project + endpoint
az resource list --resource-type Microsoft.CognitiveServices/accounts/projects \
  -g "$RG" --subscription "$SUB" --query "[].name" -o tsv

# Model deployments
az cognitiveservices account deployment list -n <account> -g "$RG" --subscription "$SUB" \
  --query "[].{model:properties.model.name,capacityKTPM:sku.capacity}" -o table

# Regional model availability
az cognitiveservices model list --location swedencentral --subscription "$SUB" \
  --query "[].model.name" -o tsv | sort -u | grep -E 'gpt-5\.(4|3-codex)'

# Defender plans
az security pricing list --subscription "$SUB" \
  --query "value[?pricingTier=='Standard'].name" -o tsv

# Providers
az provider show --namespace Microsoft.CognitiveServices --subscription "$SUB" --query registrationState -o tsv
az provider show --namespace Microsoft.Security --subscription "$SUB" --query registrationState -o tsv
```

> On PowerShell, avoid `||` inside a `--query` expression: PowerShell parses it as the
> pipeline-chain operator before `az` sees it. Use separate queries or filter client-side.

---

## 10. Troubleshooting

| Symptom | Cause | Resolution |
|---|---|---|
| Exit `2`, "az was not found" | Azure CLI missing | `winget install -e --id Microsoft.AzureCLI` |
| Exit `2`, "jq was not found" | Bash prerequisite missing | `apt install jq` / `brew install jq`, or use the PowerShell script |
| Exit `2`, "No active az CLI session" | Not signed in / token expired | `az login --tenant 16b3c013-d300-468d-ac64-7eda0820b6d3` |
| `S1` FAIL | Wrong tenant | Sign in to `Microsoft Non-Production` |
| `S4` WARN | Context not switched | Add `-SetContext` / `--set-context` — cosmetic; later calls are explicit |
| `R1` FAIL | Wrong name, or no Reader | Verify the name; request Reader |
| `F1` FAIL but the portal shows a project | Hub-based ML workspace, not a Foundry `AIServices` account | See the `F1b` warning |
| `F1` WARN "Found 2" | Multiple Foundry accounts | Pass `-FoundryAccountName` / `--foundry-account` |
| `M-*` FAIL | Models not deployed | Foundry portal → Build → Deployments |
| `M-*` WARN, low capacity | TPM below 1,000,000 | Edit the deployment's rate limit |
| `M-REGION` FAIL | Region does not offer the models | Use a supported region |
| `F4` FAIL | `disableLocalAuth: true` | See [mdash-readiness.md](mdash-readiness.md) blocker 18 |
| `P1` SKIP | Service principal login | Expected; use `--skip-rbac` and verify in the portal |
| `D1` SKIP | No Security Reader | Grant Security Reader, or check the portal |
| PowerShell "running scripts is disabled" | Execution policy | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` |
| Bash "bad interpreter: ^M" | CRLF line endings | `dos2unix scripts/validate-azure-mdash-readiness.sh` |

---

## 11. Extending the scripts

Both share the same shape. To add a check:

1. Add a helper that returns a verdict, using `Invoke-Az` (PowerShell) or `az_json`
   (Bash). Both swallow errors and return empty on failure — never let a check abort the
   run.
2. Record the outcome with `Add-Result` / `result`, giving it a stable ID, a status, a
   detail line, and remediation guidance for `Fail`/`Warn`.
3. Call it from the main flow.
4. Choose severity deliberately: `Fail` only for a genuine MDASH blocker, `Warn` for
   recommended hardening, `Skip` when the check could not be evaluated.
5. Keep it read-only. Any `create`/`update`/`delete` verb belongs in a separate,
   clearly-named script.
6. Update section 5 of this document and the checklist in
   [mdash-readiness.md](mdash-readiness.md).

### Known limitations

- Directory-scoped prerequisites (Entra roles, Defender unified RBAC, the Microsoft
  Defender Code enterprise app) are not checked — they are tenant/portal concerns.
- Content-filter configuration on a model deployment is not checked; deployments must
  exist first.
- Group-inherited role assignments are not expanded. `P1` may warn when access is granted
  through a group; verify in the portal.
- `M-REGION` reads the regional catalogue, which reflects general availability, not your
  subscription's per-model enablement.
