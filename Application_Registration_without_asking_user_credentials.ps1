<#
 SAML Onboarding Automation Script (App-Only)
 -------------------------------------------
 - No interactive prompts; uses TenantId/ClientId/ClientSecret you pass in
 - Keeps your Entity ID and ACS URLs exactly as provided
 - Creates SAML app, sets SSO mode, configures ACS & Entity ID, adds cert, creates/assigns group
A) (Security) Rotate the client secret you pasted

Since a secret appeared in your transcript, revoke it now and create a new one in App registrations → your app → Certificates & secrets.

B) Ensure the app has these Application permissions (not Delegated)

For Microsoft Graph on your app registration, add and admin consent:

Application.ReadWrite.All

Directory.ReadWrite.All

Policy.ReadWrite.ApplicationConfiguration

Group.ReadWrite.All

Then press Grant admin consent. (Azure Portal: App registrations → Your app → API permissions → Add a permission → Microsoft Graph → Application permissions → [the four above] → Add → Grant admin consent.) The instantiate doc shows the needed rights for that cal
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)] [string]$TenantId,
  [Parameter(Mandatory=$true)] [string]$ClientId,
  [Parameter(Mandatory=$true)] [string]$ClientSecret,
  [Parameter(Mandatory=$true)] [string]$DisplayName
)

# === Step 2: Define application-specific parameters (URLs unchanged) ===
$displayName = $DisplayName

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

# === Helper: Wait for eventual consistency ===
function Wait-ForResource {
    param (
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [int]$DelaySeconds = 5,
        [int]$MaxRetries = 20
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

try {
    $ErrorActionPreference = 'Stop'

    # === Step 1: Connect to Microsoft Graph (APP-ONLY; no prompts) ===
    $secure = ConvertTo-SecureString -String $ClientSecret -AsPlainText -Force
    $clientSecretCred = New-Object System.Management.Automation.PSCredential ($ClientId, $secure)
    Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $clientSecretCred -NoWelcome

    $ctx = Get-MgContext
    if (-not $ctx) { throw "Get-MgContext returned null." }
    if ($ctx.AuthType -ne 'AppOnly') { throw "Not connected in AppOnly mode. (AuthType=$($ctx.AuthType))" }

    # === Step 3: Create the SAML Application from Template ===
    $template = Get-MgApplicationTemplate -All | Where-Object { $_.DisplayName -like "*SAML*" } | Select-Object -First 1
    if (-not $template) { throw "No SAML template found." }

    $body = @{ displayName = $displayName } | ConvertTo-Json
    # Use v1.0 instantiate endpoint
    $result = Invoke-MgGraphRequest -Method POST -Uri "/v1.0/applicationTemplates/$($template.Id)/instantiate" -Body $body -ErrorAction Stop
    $appId = $result.application.appId

    # Wait for app registration
    $appObj = Wait-ForResource { Get-MgApplication -Filter "appId eq '$appId'" -ErrorAction SilentlyContinue }
    if (-not $appObj) { throw "App registration not visible." }
    $appObjectId = $appObj.Id

    # === Step 5: Ensure Service Principal Exists ===
    $spObj = Get-MgServicePrincipal -Filter "appId eq '$($appObj.AppId)'" -ErrorAction SilentlyContinue
    if (-not $spObj) { $spObj = New-MgServicePrincipal -AppId $appObj.AppId -ErrorAction Stop }
    $spObjectId = $spObj.Id

    # === Step 6: Configure SAML Settings ===
    # SSO mode = SAML (Enterprise App)
    Update-MgServicePrincipal -ServicePrincipalId $spObjectId -BodyParameter @{ preferredSingleSignOnMode = "saml" } -ErrorAction Stop

    # App settings: Entity ID + ACS (Reply) URLs (URLs unchanged, as requested)
    Update-MgApplication -ApplicationId $appObjectId -BodyParameter @{
        identifierUris = @($entityId)
        web            = @{ redirectUris = $acsUrls }
        samlMetadataUrl = $entityId   # kept as in your original script
    } -ErrorAction Stop

    # Set login URL on Enterprise App
    Update-MgServicePrincipal -ServicePrincipalId $spObjectId -BodyParameter @{ loginUrl = $signOnUrl } -ErrorAction Stop

    # === Step 7: Update Group Claims ===
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
    $appObjFull = Wait-ForResource { Get-MgApplication -ApplicationId $appObjectId -ErrorAction SilentlyContinue }
    $appRole = $appObjFull.AppRoles | Select-Object -First 1
    if (-not $appRole) {
        # If no appRole exists, create a default one to allow assignment
        $newRole = @{
            allowedMemberTypes = @("User","Group")
            description        = "Default access"
            displayName        = "User"
            id                 = [Guid]::NewGuid()
            isEnabled          = $true
            value              = "user"
        }
        $appObjFull.AppRoles += (New-Object -TypeName PSObject -Property $newRole)
        Update-MgApplication -ApplicationId $appObjectId -BodyParameter @{ appRoles = $appObjFull.AppRoles }
        $appObjFull = Get-MgApplication -ApplicationId $appObjectId
        $appRole = $appObjFull.AppRoles | Select-Object -First 1
    }

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
    $federationMetadataUrl = "https://login.microsoftonline.com/$TenantId/federationmetadata/2007-06/federationmetadata.xml?appid=$($appObj.AppId)"
    Write-Host "`n--- SUMMARY ---"
    Write-Host "App: $displayName"
    Write-Host "Client (App) ID: $($appObj.AppId)"
    Write-Host "Object ID: $appObjectId"
    Write-Host "Service Principal: $spObjectId"
    Write-Host "Group: $($groupObj.DisplayName)"
    Write-Host "Entity ID: $entityId"
    Write-Host "ACS: $($acsUrls -join ', ')"
    Write-Host "Login URL: $signOnUrl"
    Write-Host "Federation Metadata URL: $federationMetadataUrl"
}
catch {
    Write-Error $_.Exception.Message
    if ($_.ErrorDetails.Message) { Write-Error $_.ErrorDetails.Message }
}
finally {
    try { Disconnect-MgGraph | Out-Null } catch {}
}
