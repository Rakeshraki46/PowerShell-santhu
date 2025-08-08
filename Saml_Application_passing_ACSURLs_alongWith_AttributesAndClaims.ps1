<#
.SYNOPSIS
 SAML onboarding script with:
 - User creation
 - Group creation
 - User -> Group membership
 - Group -> Application assignment
 - Group claims emitted in SAML assertion
#>

# === Parameters / Customize ===
$newUserPrincipalName = "santoshyamsani13@verizon038.onmicrosoft.com"
$newPassword = "P@ssword@1234"   # leave empty to be prompted securely
$newDisplayName = "santoshyamsani13"
$newMailNickname = "madriduser"

$newGroupDisplayName = "VerizonPOC_Group"
$newGroupMailNickname = "verizonpocgroup"

$displayName = "VerizonPOC" # SAML application name

# SAML URLs (multiple ACS endpoints, primary is first)
$acsUrls = @(
    "https://us.region-2c-tpdbos1.devgateway.verizon.com/secure_access/services/saml/login-consumer",  # Primary ACS URL
    "https://KENUWADQ-VR-PNF.securegateway.verizon.com/secure-access/services/saml/login-consumer",
    "https://RVDLILBD-VR-PNF.securegateway.verizon.com/secure-access/services/saml/login-consumer"
)

# SAML Entity ID (unchanged)
$entityId  = "https://us-region2-tc-tpdbos1.devgateway.verizon.com/metadata"
$signOnUrl = "https://us.region-2c-tpdbos1.devgateway.verizon.com/secure_access/services/saml/login-consumer"

# Connect to Graph
Connect-MgGraph -Scopes "Application.ReadWrite.All","Directory.ReadWrite.All","Policy.ReadWrite.ApplicationConfiguration","User.ReadWrite.All","Group.ReadWrite.All" -ErrorAction Stop

# Helper: wait for resource
function Wait-ForResource {
    param([ScriptBlock]$CheckScript,[int]$MaxAttempts=12,[int]$DelaySeconds=5)
    for ($i=0; $i -lt $MaxAttempts; $i++) {
        $result = & $CheckScript
        if ($result) { return $result }
        Start-Sleep -Seconds $DelaySeconds
    }
    return $null
}

try {
    # Prompt for password if not given
    if ([string]::IsNullOrWhiteSpace($newPassword)) {
        $securePwd = Read-Host -AsSecureString "Enter password for new user '$newUserPrincipalName'"
        $newPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePwd)
        )
    }

    # --- Create SAML App ---
    $template = Get-MgApplicationTemplate -All | Where-Object { $_.DisplayName -like "*SAML*" } | Select-Object -First 1
    if (-not $template) { throw "No SAML template found." }

    $body = @{ displayName = $displayName } | ConvertTo-Json
    $result = Invoke-MgGraphRequest -Method POST -Uri "/beta/applicationTemplates/$($template.Id)/instantiate" -Body $body -ErrorAction Stop
    $appId = $result.application.appId

    $appObj = Wait-ForResource { Get-MgApplication -Filter "appId eq '$appId'" -ErrorAction SilentlyContinue }
    if (-not $appObj) { throw "App registration not visible." }
    $appObjectId = $appObj.Id

    # Service Principal
    $spObj = Get-MgServicePrincipal -Filter "appId eq '$($appObj.AppId)'" -ErrorAction SilentlyContinue
    if (-not $spObj) { $spObj = New-MgServicePrincipal -AppId $appObj.AppId -ErrorAction Stop }
    $spObjectId = $spObj.Id

    # --- Configure SAML including multiple ACS URLs ---
    Update-MgServicePrincipal -ServicePrincipalId $spObjectId -BodyParameter @{ preferredSingleSignOnMode = "saml" } -ErrorAction Stop
    Update-MgApplication -ApplicationId $appObjectId -BodyParameter @{
        identifierUris = @($entityId)
        web = @{
            redirectUris = $acsUrls
        }
        samlMetadataUrl = $entityId
    } -ErrorAction Stop
    Update-MgServicePrincipal -ServicePrincipalId $spObjectId -BodyParameter @{
        loginUrl = $signOnUrl
        samlSingleSignOnSettings = @{ relayState = $acsUrls[0] }
    } -ErrorAction Stop

    # --- Add GROUP CLAIMS to manifest (Core Change) ---
    $groupClaimsBody = @{
        groupMembershipClaims = "ApplicationGroup"
        optionalClaims = @{
            saml2Token = @(
                @{
                    name = "groups"
                    additionalProperties = @("sam_account_name", "cloud_displayname")
                }
            )
        }
    }
    Update-MgApplication -ApplicationId $appObjectId -BodyParameter $groupClaimsBody

    # Signing certificate
    Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spObjectId/addTokenSigningCertificate" `
        -Body (@{
            displayName = "CN=$displayName SAML Signing"
            endDateTime = (Get-Date).AddYears(2).ToString("o")
        } | ConvertTo-Json) -ErrorAction Stop

    # --- Create User ---
    $newUser = Get-MgUser -Filter "userPrincipalName eq '$newUserPrincipalName'" -ErrorAction SilentlyContinue
    if (-not $newUser) {
        $passwordProfile = @{
            ForceChangePasswordNextSignIn = $true
            Password = $newPassword
        }
        $newUser = New-MgUser -DisplayName $newDisplayName -UserPrincipalName $newUserPrincipalName `
            -MailNickname $newMailNickname -PasswordProfile $passwordProfile -AccountEnabled:$true -ErrorAction Stop
        Write-Host "Created user: $($newUser.UserPrincipalName)"
    } else {
        Write-Host "User already exists: $($newUser.UserPrincipalName)"
    }

    # --- Create Group ---
    $groupObj = Get-MgGroup -Filter "displayName eq '$newGroupDisplayName'" -ErrorAction SilentlyContinue
    if (-not $groupObj) {
        $groupObj = New-MgGroup -DisplayName $newGroupDisplayName -MailEnabled:$false -SecurityEnabled:$true `
            -MailNickname $newGroupMailNickname -ErrorAction Stop
        Write-Host "Created group: $($groupObj.DisplayName)"
    } else {
        Write-Host "Group already exists: $($groupObj.DisplayName)"
    }

    # --- Add User to Group ---
    New-MgGroupMember -GroupId $groupObj.Id -DirectoryObjectId $newUser.Id -ErrorAction Stop
    Write-Host "Added user '$($newUser.UserPrincipalName)' to group '$($groupObj.DisplayName)'"

    # --- Assign Group to Application ---
    $appObj = Wait-ForResource { Get-MgApplication -ApplicationId $appObjectId -ErrorAction SilentlyContinue }
    $appRole = $appObj.AppRoles | Select-Object -First 1
    if (-not $appRole) { throw "No app role found on application." }

    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spObjectId `
        -PrincipalId $groupObj.Id `
        -ResourceId $spObjectId `
        -AppRoleId $appRole.Id -ErrorAction Stop

    Write-Host "Assigned group '$($groupObj.DisplayName)' to application '$displayName'"

    # Output
    $federationMetadataUrl = "https://login.microsoftonline.com/$($appObj.AppId)/federationmetadata/2007-06/federationmetadata.xml?appid=$($appObj.AppId)"
    Write-Host "`n--- SUMMARY ---"
    Write-Host "App: $displayName"
    Write-Host "User: $($newUser.UserPrincipalName)"
    Write-Host "Group: $($groupObj.DisplayName)"
    Write-Host "Federation Metadata URL: $federationMetadataUrl"

} catch {
    Write-Error "An error occurred: $_"
    throw
}
