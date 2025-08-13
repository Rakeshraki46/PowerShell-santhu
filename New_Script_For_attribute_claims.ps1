<#
 SAML onboarding script with:
 -Tenant is required to run this script
 - Group creation
 - Group -> Application assignment
 - Group claims emitted in SAML assertion (cloud-only group names)
#>
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.ReadWrite.All","Directory.ReadWrite.All","Policy.ReadWrite.ApplicationConfiguration","Group.ReadWrite.All" -ErrorAction Stop

# === Parameters / Customize ===
$displayName = "VerizonPOC999" # SAML application name

# SAML URLs (multiple ACS endpoints, primary is first)
$acsUrls = @(
    "https://us.region-2c-tpdbos1.devgateway.verizon.com/secure_access/services/saml/login-consumer",  # Primary ACS URL
    "https://KENUWADQ-VR-PNF.securegateway.verizon.com/secure-access/services/saml/login-consumer",
    "https://RVDLILBD-VR-PNF.securegateway.verizon.com/secure-access/services/saml/login-consumer"
)

# SAML Entity ID & Sign-on
$entityId  = "https://us-region2-tc-tpdbos1.devgateway.verizon.com/metadata"
$signOnUrl = $acsUrls[0]

# Group details
$newGroupDisplayName = "VerizonPOC_Group999"
$newGroupMailNickname = "verizonpocgroup999"

#try {
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

    # --- Configure SAML & ACS URLs ---
    Update-MgServicePrincipal -ServicePrincipalId $spObjectId -BodyParameter @{ preferredSingleSignOnMode = "saml" } -ErrorAction Stop
    Update-MgApplication -ApplicationId $appObjectId -BodyParameter @{
        identifierUris = @($entityId)
        web = @{ redirectUris = $acsUrls }
        samlMetadataUrl = $entityId
    } -ErrorAction Stop
    Update-MgServicePrincipal -ServicePrincipalId $spObjectId -BodyParameter @{
        loginUrl = $signOnUrl
        #samlSingleSignOnSettings = @{ relayState = $acsUrls[0] }
    } -ErrorAction Stop

    # --- Update GROUP CLAIMS (cloud_displayname only) ---
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

    # Add signing certificate
    Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spObjectId/addTokenSigningCertificate" `
        -Body (@{
            displayName = "CN=$displayName SAML Signing"
            endDateTime = (Get-Date).AddYears(2).ToString("o")
        } | ConvertTo-Json) -ErrorAction Stop

    # --- Create Group if missing ---
    $groupObj = Get-MgGroup -Filter "displayName eq '$newGroupDisplayName'" -ErrorAction SilentlyContinue
    if (-not $groupObj) {
        $groupObj = New-MgGroup -DisplayName $newGroupDisplayName -MailEnabled:$false -SecurityEnabled:$true `
            -MailNickname $newGroupMailNickname -ErrorAction Stop
        Write-Host "Created group: $($groupObj.DisplayName)"
    } else {
        Write-Host "Group already exists: $($groupObj.DisplayName)"
    }

    # --- Assign Group to Application ---
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

    # Output
    $federationMetadataUrl = "https://login.microsoftonline.com/$($appObj.AppId)/federationmetadata/2007-06/federationmetadata.xml?appid=$($appObj.AppId)"
    Write-Host "`n--- SUMMARY ---"
    Write-Host "App: $displayName"
    Write-Host "Group: $($groupObj.DisplayName)"
    Write-Host "Federation Metadata URL: $federationMetadataUrl"

#} catch {
    #Write-Error "An error occurred: $_"
   # throw
#}

