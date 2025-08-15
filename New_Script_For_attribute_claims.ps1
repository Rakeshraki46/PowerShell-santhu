<#
 SAML Onboarding Automation Script
 =================================
 This script automates the onboarding of a SAML-based application into Microsoft Entra ID (Azure AD).
 It performs the following tasks:

 1. Connects to Microsoft Graph with the necessary permissions.
 2. Creates a new SAML-based application from the Microsoft-provided template.
 3. Configures SAML settings (ACS URLs, Entity ID, login URL).
 4. Updates SAML token claims to include cloud-only group display names.
 5. Generates and assigns a signing certificate for the application.
 6. Creates a security group if it doesn't already exist.
 7. Assigns the group to the SAML application.
 8. Outputs a summary with key details including the federation metadata URL.
#>

# === Step 1: Connect to Microsoft Graph ===
# Required scopes:
# - Application.ReadWrite.All: Create and configure applications.
# - Directory.ReadWrite.All: Create and manage directory objects like groups.
# - Policy.ReadWrite.ApplicationConfiguration: Configure application policies like claims.
# - Group.ReadWrite.All: Create and manage groups and their memberships.
Connect-MgGraph -Scopes "Application.ReadWrite.All","Directory.ReadWrite.All","Policy.ReadWrite.ApplicationConfiguration","Group.ReadWrite.All" -ErrorAction Stop

# === Step 2: Define application-specific parameters ===
$displayName = "addeed-helper function" # Name of the SAML application

# SAML URLs (multiple ACS endpoints; first is primary)
$acsUrls = @(
    "https://us.region-2c-tpdbos1.devgateway.verizon.com/secure_access/services/saml/login-consumer",  
    "https://KENUWADQ-VR-PNF.securegateway.verizon.com/secure-access/services/saml/login-consumer",
    "https://RVDLILBD-VR-PNF.securegateway.verizon.com/secure-access/services/saml/login-consumer"
)

# SAML Entity ID & Primary Sign-on URL
$entityId  = "https://us-region2-tc-tpdbos1.devgateway.verizon.com/metadata"
$signOnUrl = $acsUrls[0]

# Group details
$newGroupDisplayName = "addeed-helper"
$newGroupMailNickname = "addeed-helper"

# === Step 3: Create the SAML Application from Template ===
# Find the SAML application template in Microsoft Graph
$template = Get-MgApplicationTemplate -All | Where-Object { $_.DisplayName -like "*SAML*" } | Select-Object -First 1
if (-not $template) { throw "No SAML template found." }

# Instantiate the template with the display name
$body = @{ displayName = $displayName } | ConvertTo-Json
$result = Invoke-MgGraphRequest -Method POST -Uri "/beta/applicationTemplates/$($template.Id)/instantiate" -Body $body -ErrorAction Stop
$appId = $result.application.appId

# === Step 4: Helper Function to Wait for Graph Resource ===
# This waits until the given resource becomes available in Microsoft Graph, checking periodically.
# PURPOSE:
#   This helper function is designed to repeatedly check for the availability or creation of
#   a specific resource in Microsoft Graph (or any API/system) before proceeding with the script.
#   Some operations in Graph are asynchronous — for example:
#       - Creating an application
#       - Assigning a certificate
#       - Adding an owner
#   The changes may take a few seconds to be reflected when queried.
#
#   If you immediately try to use that resource without waiting, your request can fail
#   with "Resource Not Found" or similar errors. This function mitigates that risk by
#   performing a retry loop with a delay between attempts until the resource is confirmed.
#
# PARAMETERS:
#   - ScriptBlock (Mandatory)
#       A block of PowerShell code that performs the check (e.g., calling Get-MgUser, Get-MgGroup,
#       Get-MgApplication, etc.) and returns a truthy value when the resource exists or is ready.
#       Example usage: { Get-MgGroup -GroupId $groupId -ErrorAction SilentlyContinue }
#
#   - DelaySeconds (Optional, Default: 5)
#       The number of seconds to wait between retries. Increasing this can reduce the API call rate
#       but will slow down the overall waiting process.
#
#   - MaxRetries (Optional, Default: 20)
#       The maximum number of attempts before giving up. If this limit is reached, the function
#       will return $null, and the calling code should handle this scenario appropriately.
#
# RETURN VALUE:
#   - Returns the first non-null, non-empty result from the ScriptBlock when the resource is found.
#   - Returns $null if the resource could not be found after all retries.
#
# USAGE SCENARIO IN THIS SCRIPT:
#   - After creating the SAML application, we use Wait-ForResource to ensure the app is actually
#     registered in Microsoft Graph before we attempt to:
#         • Add a certificate
#         • Assign users or groups
#         • Configure SSO settings
#   - This avoids intermittent errors due to eventual consistency delays in Graph API.
#
# EXAMPLE:
#   $app = Wait-ForResource -ScriptBlock {
#       Get-MgApplication -ApplicationId $newAppId -ErrorAction SilentlyContinue
#   } -DelaySeconds 5 -MaxRetries 12
#
#   if (-not $app) {
#       Write-Error "Application not found after waiting. Aborting."
#       exit
#   }
# =================================================================================================
function Wait-ForResource {
    param (
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,  # The command to check (e.g., Get-MgApplication)
        [int]$DelaySeconds = 5,     # How long to wait between checks
        [int]$MaxRetries = 20       # Maximum number of retries before giving up
    )
    $count = 0
    while ($count -lt $MaxRetries) {
        $result = & $ScriptBlock
        if ($result) { return $result }
        Start-Sleep -Seconds $DelaySeconds
        $count++
    }
    return $null
}

# Wait until the new application is visible in Graph
$appObj = Wait-ForResource { Get-MgApplication -Filter "appId eq '$appId'" -ErrorAction SilentlyContinue }
if (-not $appObj) { throw "App registration not visible." }
$appObjectId = $appObj.Id

# === Step 5: Ensure Service Principal Exists ===
# A Service Principal represents the app instance in the tenant.
$spObj = Get-MgServicePrincipal -Filter "appId eq '$($appObj.AppId)'" -ErrorAction SilentlyContinue
if (-not $spObj) { $spObj = New-MgServicePrincipal -AppId $appObj.AppId -ErrorAction Stop }
$spObjectId = $spObj.Id

# === Step 6: Configure SAML Settings ===
# Set the preferred SSO mode to SAML
Update-MgServicePrincipal -ServicePrincipalId $spObjectId -BodyParameter @{ preferredSingleSignOnMode = "saml" } -ErrorAction Stop

# Update application SAML details: Entity ID, ACS URLs, Metadata URL
Update-MgApplication -ApplicationId $appObjectId -BodyParameter @{
    identifierUris = @($entityId)
    web = @{ redirectUris = $acsUrls }
    samlMetadataUrl = $entityId
} -ErrorAction Stop

# Set login URL for the Service Principal
Update-MgServicePrincipal -ServicePrincipalId $spObjectId -BodyParameter @{
    loginUrl = $signOnUrl
} -ErrorAction Stop

# === Step 7: Update Group Claims ===
# Adds a claim so that SAML tokens include group names from the cloud.
$groupClaimsBody = @{
    groupMembershipClaims = "ApplicationGroup"
    optionalClaims = @{
        saml2Token = @(
            @{
                name = "groups"
                additionalProperties = @("cloud_displayname")
            }
        )
    }
}
Update-MgApplication -ApplicationId $appObjectId -BodyParameter $groupClaimsBody

# === Step 8: Add a Signing Certificate for the App ===
# This is required for SAML token signing.
Invoke-MgGraphRequest -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spObjectId/addTokenSigningCertificate" `
    -Body (@{
        displayName = "CN=$displayName SAML Signing"
        endDateTime = (Get-Date).AddYears(2).ToString("o")
    } | ConvertTo-Json) -ErrorAction Stop

# === Step 9: Create the Security Group (if missing) ===
$groupObj = Get-MgGroup -Filter "displayName eq '$newGroupDisplayName'" -ErrorAction SilentlyContinue
if (-not $groupObj) {
    $groupObj = New-MgGroup -DisplayName $newGroupDisplayName -MailEnabled:$false -SecurityEnabled:$true `
        -MailNickname $newGroupMailNickname -ErrorAction Stop
    Write-Host "Created group: $($groupObj.DisplayName)"
} else {
    Write-Host "Group already exists: $($groupObj.DisplayName)"
}

# === Step 10: Assign the Group to the Application ===
$appObj = Wait-ForResource { Get-MgApplication -ApplicationId $appObjectId -ErrorAction SilentlyContinue }
$appRole = $appObj.AppRoles | Select-Object -First 1
if (-not $appRole) { throw "No app role found on application." }

$existingAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spObjectId -ErrorAction SilentlyContinue
$alreadyAssigned = $existingAssignments | Where-Object {
    $_.PrincipalId -eq $groupObj.Id -and $_.AppRoleId -eq $appRole.Id
}
if (-not $alreadyAssigned) {
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spObjectId `
        -PrincipalId $groupObj.Id `
        -ResourceId $spObjectId `
        -AppRoleId $appRole.Id -ErrorAction Stop
    Write-Host "Assigned group '$($groupObj.DisplayName)' to application '$displayName'"
} else {
    Write-Host "Group '$($groupObj.DisplayName)' is already assigned to application '$displayName'"
}

# === Step 11: Output Summary ===
$federationMetadataUrl = "https://login.microsoftonline.com/$($appObj.AppId)/federationmetadata/2007-06/federationmetadata.xml?appid=$($appObj.AppId)"
Write-Host "`n--- SUMMARY ---"
Write-Host "App: $displayName"
Write-Host "Group: $($groupObj.DisplayName)"
Write-Host "Federation Metadata URL: $federationMetadataUrl"
