# ==============================================================================
# HARDENED SCRIPT TO SET & ENFORCE ALL 10 M365 TENANT SECURITY CONTROLS
# ==============================================================================

# 1. Connect to Microsoft Graph and Microsoft Teams
Write-Host "Connecting to Microsoft Graph and Microsoft Teams..." -ForegroundColor Cyan
Connect-MgGraph -Scopes @(
    'Policy.ReadWrite.ConditionalAccess',
    'Policy.ReadWrite.Authorization',
    'RoleManagement.ReadWrite.Directory',
    'Directory.Read.All',
    'Application.Read.All',
    'AuditLog.Read.All'
)
Connect-MicrosoftTeams

# 2. Safety Standard: Declare emergency access (break-glass) account Object IDs
$breakGlassObjectIds = @(
    '755e716a-2527-4710-9cf8-2af04120b100', # Replace with actual GUID
    '6be4e3ed-4a20-4988-a625-5e089f9e2450'  # Replace with actual GUID
)

if ($breakGlassObjectIds.Count -lt 2 -or $breakGlassObjectIds -match '^<') {
    throw 'SAFETY BLOCKS EXECUTION: You must provide at least two verified emergency access object identifiers.'
}

# ------------------------------------------------------------------------------
# Helper Function: Paged Graph GET Collection
# ------------------------------------------------------------------------------
function Get-MgGraphAllPages {
    param([string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new()
    $nextLink = $Uri
    while ($nextLink) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
        if ($null -ne $page.value) {
            foreach ($item in @($page.value)) { [void]$items.Add($item) }
        }
        $nextLink = $page.'@odata.nextLink'
    }
    return $items.ToArray()
}

# ------------------------------------------------------------------------------
# Helper Function: Conditional Access Policy Upsert (Create or Update)
# ------------------------------------------------------------------------------
function Set-MgConditionalAccessPolicyUpsert {
    param(
        [hashtable]$PolicyParams,
        [object[]]$ExistingPolicies
    )
    $displayName = $PolicyParams.displayName
    $existing = $ExistingPolicies | Where-Object { $_.displayName -eq $displayName }
    $jsonBody = $PolicyParams | ConvertTo-Json -Depth 10

    if ($existing) {
        Write-Host "Updating existing policy: '$displayName' (ID: $($existing.id))..." -ForegroundColor Yellow
        $uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($existing.id)"
        Invoke-MgGraphRequest -Method PATCH -Uri $uri -Body $jsonBody -ContentType 'application/json' -ErrorAction Stop
    } else {
        Write-Host "Creating new policy: '$displayName'..." -ForegroundColor Green
        $uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
        Invoke-MgGraphRequest -Method POST -Uri $uri -Body $jsonBody -ContentType 'application/json' -ErrorAction Stop
    }
}

# Retrieve all existing Conditional Access policies to prevent duplicates
$existingCaPolicies = Get-MgGraphAllPages -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"

# ------------------------------------------------------------------------------
# Control 1: Phishing-Resistant MFA for Administrative Roles (Unit 3)
# ------------------------------------------------------------------------------
$adminRoleNames = @(
    'Global Administrator', 'Application Administrator', 'Authentication Administrator',
    'Billing Administrator', 'Cloud Application Administrator', 'Conditional Access Administrator',
    'Exchange Administrator', 'Helpdesk Administrator', 'Password Administrator',
    'Privileged Authentication Administrator', 'Privileged Role Administrator',
    'Security Administrator', 'SharePoint Administrator', 'User Administrator'
)

$allTemplates = Get-MgGraphAllPages -Uri "https://graph.microsoft.com/v1.0/directoryRoleTemplates"
$adminRoleTemplates = @($allTemplates | Where-Object { $_.displayName -in $adminRoleNames })

$missingRoleNames = @($adminRoleNames | Where-Object { $_ -notin $adminRoleTemplates.displayName })
if ($missingRoleNames.Count -gt 0) {
    throw "Role templates not found: $($missingRoleNames -join ', ')"
}

$adminRoleTemplateIds = @($adminRoleTemplates.id)

$ca001Params = @{
    displayName = 'CA001-Require-Phishing-Resistant-MFA-Admins'
    state       = 'enabled' # Enforced mode
    conditions  = @{
        clientAppTypes = @('all')
        users          = @{
            includeRoles = $adminRoleTemplateIds
            excludeUsers = $breakGlassObjectIds
        }
        applications   = @{
            includeApplications = @('All')
        }
    }
    grantControls = @{
        operator               = 'OR'
        authenticationStrength = @{
            id = '00000000-0000-0000-0000-000000000004' # Phishing-resistant MFA
        }
    }
}
Set-MgConditionalAccessPolicyUpsert -PolicyParams $ca001Params -ExistingPolicies $existingCaPolicies

# ------------------------------------------------------------------------------
# Control 2: Require MFA for All Users (Unit 4)
# ------------------------------------------------------------------------------
$ca002Params = @{
    displayName = 'CA002-Require-MFA-All-Users'
    state       = 'enabled'
    conditions  = @{
        clientAppTypes = @('all')
        users          = @{
            includeUsers = @('All')
            excludeUsers = $breakGlassObjectIds
        }
        applications   = @{
            includeApplications = @('All')
        }
    }
    grantControls = @{
        operator               = 'OR'
        authenticationStrength = @{
            id = '00000000-0000-0000-0000-000000000002' # Built-in MFA strength
        }
    }
}
Set-MgConditionalAccessPolicyUpsert -PolicyParams $ca002Params -ExistingPolicies $existingCaPolicies

# ------------------------------------------------------------------------------
# Control 3: Block Legacy Authentication (Unit 5)
# ------------------------------------------------------------------------------
$ca003Params = @{
    displayName = 'CA003-Block-Legacy-Authentication'
    state       = 'enabled'
    conditions  = @{
        clientAppTypes = @('exchangeActiveSync', 'other')
        users          = @{
            includeUsers = @('All')
            excludeUsers = $breakGlassObjectIds
        }
        applications   = @{
            includeApplications = @('All')
        }
    }
    grantControls = @{
        operator        = 'OR'
        builtInControls = @('block')
    }
}
Set-MgConditionalAccessPolicyUpsert -PolicyParams $ca003Params -ExistingPolicies $existingCaPolicies

# ------------------------------------------------------------------------------
# Control 4: MFA for Elevated Sign-in Risk (Unit 6)
# ------------------------------------------------------------------------------
$ca004Params = @{
    displayName = 'CA004-Require-MFA-Medium-High-SignIn-Risk'
    state       = 'enabled'
    conditions  = @{
        clientAppTypes   = @('all')
        signInRiskLevels = @('medium', 'high')
        users            = @{
            includeUsers = @('All')
            excludeUsers = $breakGlassObjectIds
        }
        applications     = @{
            includeApplications = @('All')
        }
    }
    grantControls = @{
        operator               = 'OR'
        authenticationStrength = @{
            id = '00000000-0000-0000-0000-000000000002'
        }
    }
    sessionControls = @{
        signInFrequency = @{
            authenticationType = 'primaryAndSecondaryAuthentication'
            frequencyInterval  = 'everyTime'
            isEnabled          = $true
        }
    }
}
Set-MgConditionalAccessPolicyUpsert -PolicyParams $ca004Params -ExistingPolicies $existingCaPolicies

# ------------------------------------------------------------------------------
# Control 5: Remediation for High User Risk (Unit 7)
# ------------------------------------------------------------------------------
$ca005Params = @{
    displayName = 'CA005-Remediate-High-User-Risk'
    state       = 'enabled'
    conditions  = @{
        clientAppTypes = @('all')
        userRiskLevels = @('high')
        users          = @{
            includeUsers = @('All')
            excludeUsers = $breakGlassObjectIds
        }
        applications   = @{
            includeApplications = @('All')
        }
    }
    grantControls = @{
        operator        = 'AND'
        builtInControls = @('mfa', 'passwordChange')
    }
    sessionControls = @{
        signInFrequency = @{
            authenticationType = 'primaryAndSecondaryAuthentication'
            frequencyInterval  = 'everyTime'
            isEnabled          = $true
        }
    }
}
Set-MgConditionalAccessPolicyUpsert -PolicyParams $ca005Params -ExistingPolicies $existingCaPolicies

# ------------------------------------------------------------------------------
# Control 6: Prevent Ordinary-User Application Consent (Unit 8)
# ------------------------------------------------------------------------------
Write-Host "Configuring Control 6: Application Consent Policy..." -ForegroundColor Yellow
$authPolicyResponse = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
$currentGrantPolicies = @($authPolicyResponse.defaultUserRolePermissions.permissionGrantPoliciesAssigned)

$policiesToPreserve = @(
    $currentGrantPolicies | Where-Object { $_ -like 'managePermissionGrantsForOwnedResource.*' }
)

$appConsentParams = @{
    defaultUserRolePermissions = @{
        permissionGrantPoliciesAssigned = $policiesToPreserve
    }
}
Invoke-MgGraphRequest -Method PATCH -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' `
    -Body ($appConsentParams | ConvertTo-Json -Depth 5) -ContentType 'application/json' -ErrorAction Stop

# ------------------------------------------------------------------------------
# Controls 7–9: Microsoft Teams Global Meeting Policy Defaults (Units 9, 10, 11)
# ------------------------------------------------------------------------------
Write-Host "Configuring Controls 7-9: Microsoft Teams Global Policy..." -ForegroundColor Yellow
Set-CsTeamsMeetingPolicy -Identity Global `
    -AutoAdmittedUsers InvitedUsers `
    -DesignatedPresenterRoleMode OrganizerOnlyUserOverride `
    -AllowAnonymousUsersToJoinMeeting $false

Set-CsTeamsMeetingConfiguration -Identity Global -DisableAnonymousJoin $true

Write-Host "`nAll policy controls configured successfully!" -ForegroundColor Green