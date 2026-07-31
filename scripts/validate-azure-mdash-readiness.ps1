<#
.SYNOPSIS
    Read-only readiness check for running Codename MDASH (agentic code scanning) against
    Azure Support Agent, using an existing Microsoft Foundry project.

.DESCRIPTION
    Validates the Azure environment that MDASH depends on, without changing anything.

    The script performs 17 grouped checks:

      1.  Required tooling (az CLI, git)
      2.  Azure CLI login context
      3.  Tenant identity
      4.  Subscription visibility by NAME
      5.  Subscription ID resolution
      6.  Active subscription context
      7.  Resource group existence
      8.  Microsoft Foundry account discovery (existing only - never created)
      9.  Microsoft Foundry project discovery (existing only - never created)
      10. Foundry model deployments required by MDASH
      11. Foundry authentication mode (local API key vs Entra-only)
      12. Foundry network exposure
      13. Managed identity configuration
      14. Key Vault discovery (optional component)
      15. RBAC assignments for the signed-in principal
      16. Defender for Cloud prerequisites
      17. GitHub / repository integration readiness

    SAFETY: every Azure call is a GET/list. The script never creates, updates, or deletes
    an Azure resource, never creates a Foundry project, and never prints secret values.

.PARAMETER SubscriptionName
    Azure subscription display name. The subscription ID is resolved from this name.
    Default: MCAPS-Hybrid-rafaelcas

.PARAMETER ResourceGroupName
    Resource group expected to hold the existing Foundry resources.
    Default: rg-ip-mdash-AzureSupportAgent

.PARAMETER FoundryAccountName
    Optional. Pin the check to a specific Microsoft Foundry (Cognitive Services / AIServices)
    account. When omitted, the script discovers accounts in the resource group.

.PARAMETER FoundryProjectName
    Optional. Pin the check to a specific Foundry project. When omitted, the script
    discovers projects under the discovered account.

.PARAMETER SetContext
    Switch the active az CLI subscription to the resolved subscription ID.
    This changes only local CLI state, never a cloud resource.

.PARAMETER SkipRbac
    Skip check 15. Role assignment enumeration needs directory read permission and can be
    slow or blocked in locked-down tenants.

.PARAMETER Json
    Emit a machine-readable JSON summary on stdout instead of the human-readable report.
    Useful for CI. All diagnostics go to stderr in this mode.

.OUTPUTS
    Exit code 0  - all required checks passed (warnings allowed)
    Exit code 1  - at least one required check failed
    Exit code 2  - the script could not run (missing tooling, not logged in)

.EXAMPLE
    ./scripts/validate-azure-mdash-readiness.ps1
    Run every check against the default subscription and resource group.

.EXAMPLE
    ./scripts/validate-azure-mdash-readiness.ps1 -SetContext
    Run every check and switch the active az CLI subscription first.

.EXAMPLE
    ./scripts/validate-azure-mdash-readiness.ps1 -Json | ConvertFrom-Json
    Run in CI and consume the structured result.

.NOTES
    Companion document: docs/azure-validation.md
    Companion script:   scripts/validate-azure-mdash-readiness.sh
#>

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string] $SubscriptionName = 'MCAPS-Hybrid-rafaelcas',

    [ValidateNotNullOrEmpty()]
    [string] $ResourceGroupName = 'rg-ip-mdash-AzureSupportAgent',

    [string] $FoundryAccountName,

    [string] $FoundryProjectName,

    [switch] $SetContext,

    [switch] $SkipRbac,

    [switch] $Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Models MDASH requires in the connected Foundry project.
# Source: https://learn.microsoft.com/en-us/security-exposure-management/mdash-foundry-integration
$script:RequiredModels = @('gpt-5.4', 'gpt-5.3-codex', 'gpt-5.4-mini')

# Minimum tokens-per-minute per deployment required by MDASH.
$script:RequiredTpm = 1000000

# Azure reports Cognitive Services quota in thousands of TPM.
$script:RequiredQuotaUnits = $script:RequiredTpm / 1000

$script:Results = [System.Collections.Generic.List[object]]::new()
$script:Facts = [ordered]@{}

#region Output helpers -----------------------------------------------------------------

function Write-Line {
    <#  .SYNOPSIS Emit a line to the correct stream for the current output mode. #>
    param([string] $Text = '', [string] $Colour)

    if ($Json) { [Console]::Error.WriteLine($Text); return }
    if ($Colour) { Write-Host $Text -ForegroundColor $Colour } else { Write-Host $Text }
}

function Write-Header {
    param([string] $Text)
    Write-Line ''
    Write-Line "── $Text " -Colour Cyan
}

function Add-Result {
    <#
        .SYNOPSIS
            Record one check outcome.
        .PARAMETER Status
            Pass    - requirement satisfied
            Fail    - required for MDASH, blocks readiness, sets exit code 1
            Warn    - recommended, or informational risk; does not block
            Skip    - not evaluated
    #>
    param(
        [Parameter(Mandatory)][string] $Id,
        [Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)][ValidateSet('Pass', 'Fail', 'Warn', 'Skip')][string] $Status,
        [string] $Detail = '',
        [string] $Remediation = ''
    )

    $script:Results.Add([pscustomobject]@{
            id          = $Id
            name        = $Name
            status      = $Status
            detail      = $Detail
            remediation = $Remediation
        })

    $glyph, $colour = switch ($Status) {
        'Pass' { '[ PASS ]', 'Green' }
        'Fail' { '[ FAIL ]', 'Red' }
        'Warn' { '[ WARN ]', 'Yellow' }
        'Skip' { '[ SKIP ]', 'DarkGray' }
    }

    Write-Line ("{0} {1,-4} {2}" -f $glyph, $Id, $Name) -Colour $colour
    if ($Detail) { Write-Line ("            {0}" -f $Detail) -Colour DarkGray }
    if ($Remediation -and $Status -in @('Fail', 'Warn')) {
        Write-Line ("            -> {0}" -f $Remediation) -Colour DarkYellow
    }
}

#endregion

#region Azure helpers ------------------------------------------------------------------

function Invoke-Az {
    <#
        .SYNOPSIS
            Run an az CLI command and return parsed JSON, or $null when it fails.
        .DESCRIPTION
            Never throws. Callers decide whether a failure is Fail, Warn, or Skip, which
            keeps the script running end to end so the operator gets the full picture in
            one pass instead of fixing one blocker at a time.
    #>
    param([Parameter(Mandatory)][string[]] $Arguments)

    try {
        $stdout = & az @Arguments --only-show-errors 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        if (-not $stdout) { return $null }
        return ($stdout | ConvertFrom-Json -ErrorAction Stop)
    }
    catch {
        return $null
    }
}

function Test-Tool {
    <#  .SYNOPSIS Return $true when a command is resolvable on PATH. #>
    param([Parameter(Mandatory)][string] $Name)
    return [bool] (Get-Command $Name -ErrorAction SilentlyContinue)
}

#endregion

#region Checks -------------------------------------------------------------------------

function Test-Tooling {
    Write-Header 'Tooling'

    if (Test-Tool 'az') {
        $ver = Invoke-Az @('version')
        $azVer = if ($ver -and $ver.'azure-cli') { $ver.'azure-cli' } else { 'unknown' }
        $script:Facts['azCliVersion'] = $azVer
        Add-Result -Id 'T1' -Name 'Azure CLI available' -Status Pass -Detail "az $azVer"
    }
    else {
        Add-Result -Id 'T1' -Name 'Azure CLI available' -Status Fail `
            -Detail 'az was not found on PATH.' `
            -Remediation 'Install: winget install -e --id Microsoft.AzureCLI'
        return $false
    }

    if (Test-Tool 'git') {
        Add-Result -Id 'T2' -Name 'git available' -Status Pass
    }
    else {
        Add-Result -Id 'T2' -Name 'git available' -Status Warn `
            -Detail 'git was not found; repository checks are limited.' `
            -Remediation 'Install git: winget install -e --id Git.Git'
    }

    return $true
}

function Test-LoginContext {
    Write-Header 'Azure login context'

    $account = Invoke-Az @('account', 'show', '-o', 'json')
    if (-not $account) {
        Add-Result -Id 'A1' -Name 'Signed in to Azure CLI' -Status Fail `
            -Detail 'No active az CLI session.' `
            -Remediation 'Run: az login --tenant <tenant-id>'
        return $null
    }

    $script:Facts['signedInUser'] = $account.user.name
    $script:Facts['currentTenantId'] = $account.tenantId
    Add-Result -Id 'A1' -Name 'Signed in to Azure CLI' -Status Pass `
        -Detail "$($account.user.name) (type: $($account.user.type))"

    Add-Result -Id 'A2' -Name 'Current tenant resolved' -Status Pass `
        -Detail "tenantId $($account.tenantId)"

    return $account
}

function Resolve-Subscription {
    Write-Header 'Subscription'

    # --all so subscriptions in non-default tenants are visible too.
    $subs = Invoke-Az @('account', 'list', '--all', '-o', 'json')
    if (-not $subs) {
        Add-Result -Id 'S1' -Name 'Subscription list retrieved' -Status Fail `
            -Detail 'az account list returned nothing.' `
            -Remediation 'Re-authenticate: az login --tenant <tenant-id>'
        return $null
    }

    $match = @($subs | Where-Object { $_.name -eq $SubscriptionName })
    if ($match.Count -eq 0) {
        Add-Result -Id 'S1' -Name "Subscription '$SubscriptionName' visible" -Status Fail `
            -Detail "Not present in $($subs.Count) visible subscription(s)." `
            -Remediation 'The subscription may live in another tenant. Run: az login --tenant <tenant-id>'
        return $null
    }

    $sub = $match[0]
    $script:Facts['subscriptionName'] = $sub.name
    $script:Facts['subscriptionId'] = $sub.id
    $script:Facts['subscriptionTenantId'] = $sub.tenantId

    Add-Result -Id 'S1' -Name "Subscription '$SubscriptionName' visible" -Status Pass
    Add-Result -Id 'S2' -Name 'Subscription ID resolved from name' -Status Pass -Detail $sub.id

    if ($sub.state -eq 'Enabled') {
        Add-Result -Id 'S3' -Name 'Subscription enabled' -Status Pass
    }
    else {
        Add-Result -Id 'S3' -Name 'Subscription enabled' -Status Fail `
            -Detail "state: $($sub.state)" `
            -Remediation 'A disabled subscription cannot host MDASH Foundry inference.'
    }

    if ($SetContext) {
        $null = Invoke-Az @('account', 'set', '--subscription', $sub.id)
    }

    $active = Invoke-Az @('account', 'show', '-o', 'json')
    if ($active -and $active.id -eq $sub.id) {
        Add-Result -Id 'S4' -Name 'Active subscription context' -Status Pass -Detail $sub.id
    }
    else {
        $activeName = if ($active) { $active.name } else { 'unknown' }
        Add-Result -Id 'S4' -Name 'Active subscription context' -Status Warn `
            -Detail "Active context is '$activeName'; checks below target $($sub.id) explicitly." `
            -Remediation "Re-run with -SetContext, or run: az account set --subscription $($sub.id)"
    }

    return $sub
}

function Test-ResourceGroup {
    param([Parameter(Mandatory)][string] $SubscriptionId)

    Write-Header 'Resource group'

    $rg = Invoke-Az @('group', 'show', '--name', $ResourceGroupName,
        '--subscription', $SubscriptionId, '-o', 'json')

    if (-not $rg) {
        Add-Result -Id 'R1' -Name "Resource group '$ResourceGroupName' exists" -Status Fail `
            -Detail 'Not found, or no read permission.' `
            -Remediation "Verify the name, or grant Reader on the resource group. This script never creates it."
        return $null
    }

    $script:Facts['resourceGroupLocation'] = $rg.location
    Add-Result -Id 'R1' -Name "Resource group '$ResourceGroupName' exists" -Status Pass `
        -Detail "location $($rg.location), provisioning $($rg.properties.provisioningState)"

    return $rg
}

function Find-FoundryAccount {
    <#
        .SYNOPSIS
            Discover an EXISTING Microsoft Foundry account. Never creates one.
        .DESCRIPTION
            A Microsoft Foundry resource is a Microsoft.CognitiveServices/accounts resource
            with kind 'AIServices'. Older hub-based projects are ML workspaces instead; the
            script reports those separately so the operator is not left guessing.
    #>
    param([Parameter(Mandatory)][string] $SubscriptionId)

    Write-Header 'Microsoft Foundry account (existing)'

    $accounts = Invoke-Az @('cognitiveservices', 'account', 'list',
        '--resource-group', $ResourceGroupName,
        '--subscription', $SubscriptionId, '-o', 'json')

    $foundry = @()
    if ($accounts) {
        $foundry = @($accounts | Where-Object { $_.kind -eq 'AIServices' })
    }

    if ($FoundryAccountName) {
        $foundry = @($foundry | Where-Object { $_.name -eq $FoundryAccountName })
    }

    if ($foundry.Count -eq 0) {
        Add-Result -Id 'F1' -Name 'Foundry (AIServices) account discovered' -Status Fail `
            -Detail "No AIServices account in '$ResourceGroupName'." `
            -Remediation 'MDASH requires a dedicated Foundry resource. Create it in the portal (out of scope for this read-only script), then re-run.'

        # Surface hub-based workspaces so the operator knows what does exist.
        $ml = Invoke-Az @('resource', 'list', '--resource-group', $ResourceGroupName,
            '--resource-type', 'Microsoft.MachineLearningServices/workspaces',
            '--subscription', $SubscriptionId, '-o', 'json')
        if ($ml -and @($ml).Count -gt 0) {
            Add-Result -Id 'F1b' -Name 'Legacy ML workspace present' -Status Warn `
                -Detail "Found $(@($ml).Count) Microsoft.MachineLearningServices/workspaces resource(s)." `
                -Remediation 'MDASH expects a Microsoft Foundry (AIServices) resource, not a hub-based ML workspace.'
        }
        return $null
    }

    if ($foundry.Count -gt 1) {
        Add-Result -Id 'F1' -Name 'Foundry (AIServices) account discovered' -Status Warn `
            -Detail "Found $($foundry.Count): $((($foundry | ForEach-Object { $_.name }) -join ', ')). Using the first." `
            -Remediation 'Pin one with -FoundryAccountName to make this deterministic.'
    }

    $account = $foundry[0]
    $script:Facts['foundryAccountName'] = $account.name
    $script:Facts['foundryEndpoint'] = $account.properties.endpoint
    $script:Facts['foundryLocation'] = $account.location

    Add-Result -Id 'F1' -Name 'Foundry (AIServices) account discovered' -Status Pass `
        -Detail "$($account.name) | $($account.location) | sku $($account.sku.name)"

    return $account
}

function Find-FoundryProject {
    <#  .SYNOPSIS Discover an EXISTING Foundry project under the account. Never creates one. #>
    param(
        [Parameter(Mandatory)][string] $SubscriptionId,
        [Parameter(Mandatory)][object] $Account
    )

    Write-Header 'Microsoft Foundry project (existing)'

    $scope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName" +
    "/providers/Microsoft.CognitiveServices/accounts/$($Account.name)/projects"

    $projects = Invoke-Az @('resource', 'list',
        '--resource-type', 'Microsoft.CognitiveServices/accounts/projects',
        '--resource-group', $ResourceGroupName,
        '--subscription', $SubscriptionId, '-o', 'json')

    $matched = @()
    if ($projects) {
        $matched = @($projects | Where-Object { $_.id -like "$scope/*" })
    }
    if ($FoundryProjectName) {
        $matched = @($matched | Where-Object { $_.id -like "*/$FoundryProjectName" })
    }

    if ($matched.Count -eq 0) {
        Add-Result -Id 'F2' -Name 'Foundry project discovered' -Status Fail `
            -Detail "No project under account '$($Account.name)'." `
            -Remediation 'Create the project in the Foundry portal (out of scope for this read-only script), then re-run.'
        return $null
    }

    # The list API returns a thin projection; fetch the full resource for endpoints/identity.
    $project = Invoke-Az @('resource', 'show', '--ids', $matched[0].id,
        '--api-version', '2025-06-01', '-o', 'json')
    if (-not $project) { $project = $matched[0] }

    $projectName = ($project.name -split '/')[-1]
    $script:Facts['foundryProjectName'] = $projectName

    $endpoint = $null
    if ($project.PSObject.Properties.Name -contains 'properties' -and
        $project.properties.PSObject.Properties.Name -contains 'endpoints') {
        $endpoint = $project.properties.endpoints.'AI Foundry API'
    }
    if ($endpoint) { $script:Facts['foundryProjectEndpoint'] = $endpoint }

    Add-Result -Id 'F2' -Name 'Foundry project discovered' -Status Pass `
        -Detail "$projectName$(if ($endpoint) { " | $endpoint" })"

    if ($endpoint) {
        Add-Result -Id 'F3' -Name 'Foundry project endpoint resolved' -Status Pass `
            -Detail 'Use this as the Project endpoint during MDASH portal onboarding.'
    }
    else {
        Add-Result -Id 'F3' -Name 'Foundry project endpoint resolved' -Status Warn `
            -Detail 'Endpoint not present on the project resource.' `
            -Remediation 'Copy the Project endpoint from the Foundry portal instead.'
    }

    return $project
}

function Test-FoundryModels {
    <#  .SYNOPSIS Verify the three model deployments MDASH requires, and their TPM. #>
    param(
        [Parameter(Mandatory)][string] $SubscriptionId,
        [Parameter(Mandatory)][object] $Account
    )

    Write-Header 'MDASH model deployments'

    $deployments = Invoke-Az @('cognitiveservices', 'account', 'deployment', 'list',
        '--name', $Account.name, '--resource-group', $ResourceGroupName,
        '--subscription', $SubscriptionId, '-o', 'json')

    $deployed = @()
    if ($deployments) {
        $deployed = @($deployments | ForEach-Object { $_.properties.model.name })
    }
    $script:Facts['deployedModels'] = $deployed

    foreach ($model in $script:RequiredModels) {
        $hit = $null
        if ($deployments) {
            $hit = @($deployments | Where-Object { $_.properties.model.name -eq $model })[0]
        }

        if (-not $hit) {
            Add-Result -Id "M-$model" -Name "Model deployed: $model" -Status Fail `
                -Detail 'Not deployed in this Foundry account.' `
                -Remediation "Deploy '$model' in the Foundry portal (Build > Deployments), then set TPM to $($script:RequiredTpm)."
            continue
        }

        # Cognitive Services reports deployment capacity in thousands of TPM.
        $capacity = 0
        if ($hit.sku -and $hit.sku.PSObject.Properties.Name -contains 'capacity') {
            $capacity = [int] $hit.sku.capacity
        }

        if ($capacity -ge $script:RequiredQuotaUnits) {
            Add-Result -Id "M-$model" -Name "Model deployed: $model" -Status Pass `
                -Detail "capacity ${capacity}K TPM (>= $($script:RequiredQuotaUnits)K required)"
        }
        else {
            Add-Result -Id "M-$model" -Name "Model deployed: $model" -Status Warn `
                -Detail "capacity ${capacity}K TPM is below the $($script:RequiredQuotaUnits)K TPM MDASH minimum." `
                -Remediation "Raise Tokens per Minute Rate Limit to $($script:RequiredTpm) on this deployment."
        }
    }

    # Regional model availability, so a missing deployment can be told apart from a
    # model that simply is not offered in this region.
    $catalogue = Invoke-Az @('cognitiveservices', 'model', 'list',
        '--location', $Account.location, '--subscription', $SubscriptionId, '-o', 'json')
    if ($catalogue) {
        $available = @($catalogue | ForEach-Object { $_.model.name }) | Sort-Object -Unique
        $missing = @($script:RequiredModels | Where-Object { $_ -notin $available })
        if ($missing.Count -gt 0) {
            Add-Result -Id 'M-REGION' -Name 'Required models offered in region' -Status Fail `
                -Detail "Not offered in $($Account.location): $($missing -join ', ')" `
                -Remediation 'Use a Foundry resource in a region that offers all three MDASH models.'
        }
        else {
            Add-Result -Id 'M-REGION' -Name 'Required models offered in region' -Status Pass `
                -Detail "All $($script:RequiredModels.Count) available in $($Account.location)."
        }
    }
    else {
        Add-Result -Id 'M-REGION' -Name 'Required models offered in region' -Status Skip `
            -Detail 'Model catalogue could not be read.'
    }
}

function Test-FoundryAuthAndNetwork {
    param([Parameter(Mandatory)][object] $Account)

    Write-Header 'Foundry authentication and network'

    # MDASH portal onboarding asks for a Project endpoint AND an API key. When local auth
    # is disabled, no API key can be issued, so onboarding cannot complete as documented.
    $localAuthDisabled = $false
    if ($Account.properties.PSObject.Properties.Name -contains 'disableLocalAuth') {
        $localAuthDisabled = [bool] $Account.properties.disableLocalAuth
    }
    $script:Facts['foundryLocalAuthDisabled'] = $localAuthDisabled

    if ($localAuthDisabled) {
        Add-Result -Id 'F4' -Name 'Foundry API key auth available' -Status Fail `
            -Detail 'disableLocalAuth = true, so no API key can be issued for this account.' `
            -Remediation 'MDASH onboarding requires a Project endpoint + API key. Either enable local auth on this dedicated MDASH resource, or confirm with the MDASH team that Entra-only onboarding is supported.'
    }
    else {
        Add-Result -Id 'F4' -Name 'Foundry API key auth available' -Status Pass `
            -Detail 'Local (key) auth is enabled; an API key can be retrieved for onboarding.'
    }

    $publicAccess = 'Unknown'
    if ($Account.properties.PSObject.Properties.Name -contains 'publicNetworkAccess') {
        $publicAccess = [string] $Account.properties.publicNetworkAccess
    }
    $script:Facts['foundryPublicNetworkAccess'] = $publicAccess

    if ($publicAccess -eq 'Enabled') {
        Add-Result -Id 'F5' -Name 'MDASH can reach the Foundry endpoint' -Status Pass `
            -Detail 'publicNetworkAccess = Enabled (equivalent to "All networks"); no IP allow-list needed.'
    }
    else {
        Add-Result -Id 'F5' -Name 'MDASH can reach the Foundry endpoint' -Status Warn `
            -Detail "publicNetworkAccess = $publicAccess." `
            -Remediation 'With "Selected networks and private endpoints", add the documented MDASH service IP ranges or onboarding validation will fail. See docs/mdash-readiness.md.'
    }
}

function Test-ManagedIdentity {
    param([Parameter(Mandatory)][string] $SubscriptionId, [object] $Account, [object] $Project)

    Write-Header 'Managed identity'

    foreach ($pair in @(@{ Label = 'Foundry account'; Res = $Account; Id = 'I1' },
            @{ Label = 'Foundry project'; Res = $Project; Id = 'I2' })) {

        $res = $pair.Res
        if (-not $res) {
            Add-Result -Id $pair.Id -Name "$($pair.Label) managed identity" -Status Skip `
                -Detail 'Resource not discovered.'
            continue
        }

        $identityType = $null
        if ($res.PSObject.Properties.Name -contains 'identity' -and $res.identity) {
            $identityType = $res.identity.type
        }

        if ($identityType) {
            Add-Result -Id $pair.Id -Name "$($pair.Label) managed identity" -Status Pass `
                -Detail "type $identityType"
        }
        else {
            Add-Result -Id $pair.Id -Name "$($pair.Label) managed identity" -Status Warn `
                -Detail 'No managed identity assigned.' `
                -Remediation 'Assign a managed identity to prefer Entra auth over keys.'
        }
    }

    # User-assigned identities in the resource group, for the app's own future use.
    $uami = Invoke-Az @('identity', 'list', '--resource-group', $ResourceGroupName,
        '--subscription', $SubscriptionId, '-o', 'json')
    $count = if ($uami) { @($uami).Count } else { 0 }
    Add-Result -Id 'I3' -Name 'User-assigned managed identities in resource group' -Status Pass `
        -Detail "$count found"
}

function Test-KeyVault {
    param([Parameter(Mandatory)][string] $SubscriptionId)

    Write-Header 'Key Vault'

    $vaults = Invoke-Az @('keyvault', 'list', '--resource-group', $ResourceGroupName,
        '--subscription', $SubscriptionId, '-o', 'json')

    if (-not $vaults -or @($vaults).Count -eq 0) {
        Add-Result -Id 'K1' -Name 'Key Vault present' -Status Warn `
            -Detail "No Key Vault in '$ResourceGroupName'." `
            -Remediation 'Azure Support Agent reads SECRETS_ENCRYPTION_KEY from the environment. A Key Vault is recommended to source it. See docs/security-review.md.'
        return
    }

    $names = (@($vaults) | ForEach-Object { $_.name }) -join ', '
    $script:Facts['keyVaults'] = @($vaults | ForEach-Object { $_.name })
    Add-Result -Id 'K1' -Name 'Key Vault present' -Status Pass -Detail $names

    foreach ($v in @($vaults)) {
        $detail = Invoke-Az @('keyvault', 'show', '--name', $v.name,
            '--subscription', $SubscriptionId, '-o', 'json')
        if (-not $detail) { continue }

        $rbacEnabled = $false
        if ($detail.properties.PSObject.Properties.Name -contains 'enableRbacAuthorization') {
            $rbacEnabled = [bool] $detail.properties.enableRbacAuthorization
        }
        if ($rbacEnabled) {
            Add-Result -Id "K2-$($v.name)" -Name "Key Vault '$($v.name)' uses Azure RBAC" -Status Pass
        }
        else {
            Add-Result -Id "K2-$($v.name)" -Name "Key Vault '$($v.name)' uses Azure RBAC" -Status Warn `
                -Detail 'Still using legacy access policies.' `
                -Remediation 'Enable Azure RBAC authorization for consistent, auditable access control.'
        }
    }
}

function Test-Rbac {
    param([Parameter(Mandatory)][string] $SubscriptionId)

    Write-Header 'RBAC and permissions'

    if ($SkipRbac) {
        Add-Result -Id 'P1' -Name 'Role assignments for signed-in principal' -Status Skip `
            -Detail '-SkipRbac was supplied.'
        return
    }

    $signedIn = Invoke-Az @('ad', 'signed-in-user', 'show', '-o', 'json')
    if (-not $signedIn) {
        Add-Result -Id 'P1' -Name 'Role assignments for signed-in principal' -Status Skip `
            -Detail 'Directory read unavailable (service principal login, or Graph blocked).' `
            -Remediation 'Re-run as a user principal, or verify role assignments in the portal.'
        return
    }

    $scope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"
    $assignments = Invoke-Az @('role', 'assignment', 'list',
        '--assignee', $signedIn.id, '--scope', $scope,
        '--include-inherited', '--subscription', $SubscriptionId, '-o', 'json')

    $roles = @()
    if ($assignments) { $roles = @($assignments | ForEach-Object { $_.roleDefinitionName }) | Sort-Object -Unique }
    $script:Facts['signedInRoles'] = $roles

    if ($roles.Count -eq 0) {
        Add-Result -Id 'P1' -Name 'Role assignments for signed-in principal' -Status Warn `
            -Detail 'No direct or inherited assignments found at the resource group scope.' `
            -Remediation 'Access may be granted through a group. Confirm in the portal.'
        return
    }

    Add-Result -Id 'P1' -Name 'Role assignments for signed-in principal' -Status Pass `
        -Detail ($roles -join ', ')

    # Reader (or higher) is enough for everything this script does.
    $canRead = @($roles | Where-Object { $_ -in @('Reader', 'Contributor', 'Owner') }).Count -gt 0
    if ($canRead) {
        Add-Result -Id 'P2' -Name 'Permission to validate (read)' -Status Pass
    }
    else {
        Add-Result -Id 'P2' -Name 'Permission to validate (read)' -Status Warn `
            -Detail 'No Reader/Contributor/Owner at this scope.' `
            -Remediation 'Grant Reader on the resource group to run validation.'
    }

    # Deploying Foundry model deployments needs write access.
    $canWrite = @($roles | Where-Object { $_ -in @('Contributor', 'Owner', 'Cognitive Services Contributor') }).Count -gt 0
    if ($canWrite) {
        Add-Result -Id 'P3' -Name 'Permission to deploy models' -Status Pass
    }
    else {
        Add-Result -Id 'P3' -Name 'Permission to deploy models' -Status Warn `
            -Detail 'No Contributor/Owner/Cognitive Services Contributor at this scope.' `
            -Remediation 'Required only when you deploy the three MDASH models. Validation itself needs just Reader.'
    }
}

function Test-DefenderPrerequisites {
    param([Parameter(Mandatory)][string] $SubscriptionId)

    Write-Header 'Defender for Cloud prerequisites'

    $providers = Invoke-Az @('provider', 'list', '--subscription', $SubscriptionId, '-o', 'json')
    foreach ($ns in @('Microsoft.Security', 'Microsoft.CognitiveServices')) {
        $p = $null
        if ($providers) { $p = @($providers | Where-Object { $_.namespace -eq $ns })[0] }

        if ($p -and $p.registrationState -eq 'Registered') {
            Add-Result -Id "D-$ns" -Name "Provider registered: $ns" -Status Pass
        }
        else {
            $state = if ($p) { $p.registrationState } else { 'unknown' }
            Add-Result -Id "D-$ns" -Name "Provider registered: $ns" -Status Fail `
                -Detail "state: $state" `
                -Remediation "Run: az provider register --namespace $ns --subscription $SubscriptionId"
        }
    }

    # Deploying Azure Support Agent itself needs the Postgres provider.
    $pg = $null
    if ($providers) { $pg = @($providers | Where-Object { $_.namespace -eq 'Microsoft.DBforPostgreSQL' })[0] }
    if ($pg -and $pg.registrationState -eq 'Registered') {
        Add-Result -Id 'D-PG' -Name 'Provider registered: Microsoft.DBforPostgreSQL' -Status Pass
    }
    else {
        $state = if ($pg) { $pg.registrationState } else { 'unknown' }
        Add-Result -Id 'D-PG' -Name 'Provider registered: Microsoft.DBforPostgreSQL' -Status Warn `
            -Detail "state: $state. deploy/main.bicep provisions a PostgreSQL flexible server." `
            -Remediation "Run: az provider register --namespace Microsoft.DBforPostgreSQL --subscription $SubscriptionId"
    }

    $pricings = Invoke-Az @('security', 'pricing', 'list', '--subscription', $SubscriptionId, '-o', 'json')
    if (-not $pricings) {
        Add-Result -Id 'D1' -Name 'Defender for Cloud plans readable' -Status Skip `
            -Detail 'Could not read pricing (needs Security Reader).' `
            -Remediation 'Grant Security Reader, or check Defender for Cloud in the portal.'
        return
    }

    $standard = @($pricings.value | Where-Object { $_.pricingTier -eq 'Standard' } |
        ForEach-Object { $_.name })
    $script:Facts['defenderStandardPlans'] = $standard

    foreach ($plan in @('CloudPosture', 'AI')) {
        if ($plan -in $standard) {
            Add-Result -Id "D2-$plan" -Name "Defender plan enabled: $plan" -Status Pass
        }
        else {
            Add-Result -Id "D2-$plan" -Name "Defender plan enabled: $plan" -Status Warn `
                -Detail 'Not on the Standard tier.' `
                -Remediation "Enable the $plan plan in Defender for Cloud for full Exposure Management context."
        }
    }
}

function Test-GitHubReadiness {
    Write-Header 'GitHub integration readiness'

    if (-not (Test-Tool 'git')) {
        Add-Result -Id 'G1' -Name 'Repository detected' -Status Skip -Detail 'git unavailable.'
        return
    }

    $remote = & git remote get-url origin 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $remote) {
        Add-Result -Id 'G1' -Name 'Repository detected' -Status Warn `
            -Detail 'No origin remote; run from inside the repository clone.' `
            -Remediation 'MDASH remote scanning connects a GitHub organization, so the code must live in GitHub.'
        return
    }

    $script:Facts['gitRemote'] = $remote.Trim()
    Add-Result -Id 'G1' -Name 'Repository detected' -Status Pass -Detail $remote.Trim()

    if ($remote -match 'github\.com') {
        Add-Result -Id 'G2' -Name 'Hosted on GitHub' -Status Pass `
            -Detail 'Eligible for the MDASH GitHub connector (remote scan).'
    }
    else {
        Add-Result -Id 'G2' -Name 'Hosted on GitHub' -Status Warn `
            -Detail 'Origin is not github.com.' `
            -Remediation 'Use the Defender CLI scanning path instead of the GitHub connector.'
    }

    $repoRoot = & git rev-parse --show-toplevel 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $repoRoot) { return }

    $workflowDir = Join-Path $repoRoot.Trim() '.github/workflows'
    if (Test-Path $workflowDir) {
        $count = @(Get-ChildItem $workflowDir -Filter '*.yml' -ErrorAction SilentlyContinue).Count
        Add-Result -Id 'G3' -Name 'GitHub Actions workflows present' -Status Pass -Detail "$count workflow file(s)"
    }
    else {
        Add-Result -Id 'G3' -Name 'GitHub Actions workflows present' -Status Warn `
            -Detail 'No .github/workflows directory.' `
            -Remediation 'Add CodeQL and dependency-review workflows so MDASH findings sit alongside GHAS results.'
    }
}

#endregion

#region Main ---------------------------------------------------------------------------

Write-Line ''
Write-Line '===========================================================' -Colour Cyan
Write-Line ' Azure Support Agent - MDASH readiness validation' -Colour Cyan
Write-Line '===========================================================' -Colour Cyan
Write-Line " Subscription  : $SubscriptionName"
Write-Line " ResourceGroup : $ResourceGroupName"
Write-Line " Mode          : read-only (no resource is created or modified)"

if (-not (Test-Tooling)) { exit 2 }
if (-not (Test-LoginContext)) { exit 2 }

$subscription = Resolve-Subscription
if (-not $subscription) {
    Write-Line ''
    Write-Line 'Cannot continue without a resolved subscription.' -Colour Red
    exit 1
}

$subId = $subscription.id
$account = $null
$project = $null

if (Test-ResourceGroup -SubscriptionId $subId) {
    $account = Find-FoundryAccount -SubscriptionId $subId
    if ($account) {
        $project = Find-FoundryProject -SubscriptionId $subId -Account $account
        Test-FoundryModels -SubscriptionId $subId -Account $account
        Test-FoundryAuthAndNetwork -Account $account
    }
    Test-ManagedIdentity -SubscriptionId $subId -Account $account -Project $project
    Test-KeyVault -SubscriptionId $subId
}

Test-Rbac -SubscriptionId $subId
Test-DefenderPrerequisites -SubscriptionId $subId
Test-GitHubReadiness

$pass = @($script:Results | Where-Object { $_.status -eq 'Pass' }).Count
$fail = @($script:Results | Where-Object { $_.status -eq 'Fail' }).Count
$warn = @($script:Results | Where-Object { $_.status -eq 'Warn' }).Count
$skip = @($script:Results | Where-Object { $_.status -eq 'Skip' }).Count

Write-Header 'Summary'
Write-Line " Passed   : $pass" -Colour Green
Write-Line " Failed   : $fail" -Colour $(if ($fail -gt 0) { 'Red' } else { 'DarkGray' })
Write-Line " Warnings : $warn" -Colour $(if ($warn -gt 0) { 'Yellow' } else { 'DarkGray' })
Write-Line " Skipped  : $skip" -Colour DarkGray

if ($fail -gt 0) {
    Write-Line ''
    Write-Line 'Blocking issues:' -Colour Red
    foreach ($r in $script:Results | Where-Object { $_.status -eq 'Fail' }) {
        Write-Line "  - [$($r.id)] $($r.name)" -Colour Red
        if ($r.remediation) { Write-Line "      $($r.remediation)" -Colour DarkYellow }
    }
}

if ($Json) {
    [pscustomobject]@{
        subscriptionName  = $SubscriptionName
        resourceGroupName = $ResourceGroupName
        facts             = $script:Facts
        summary           = [ordered]@{ passed = $pass; failed = $fail; warnings = $warn; skipped = $skip }
        checks            = $script:Results
    } | ConvertTo-Json -Depth 6
}

Write-Line ''
exit $(if ($fail -gt 0) { 1 } else { 0 })

#endregion
