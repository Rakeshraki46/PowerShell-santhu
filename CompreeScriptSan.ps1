<#
 SAML onboarding script with:
 - User creation
 - Group creation
 - User -> Group membership
 - Group -> Application assignment
 - Group claims emitted in SAML assertion
#>

# === Parameters / Customize ===
$newUserPrincipalName = "santoshyamsani132@verizon038.onmicrosoft.com"
$newPassword = "P@ssword@1234"   # leave empty to be prompted securely
$newDisplayName = "santoshyamsani132"
$newMailNickname = "madriduser"

$newGroupDisplayName = "VerizonPOC_Group132"
$newGroupMailNickname = "verizonpocgroup"

$displayName = "VerizonPOC132" # SAML application name

# SAML URLs (multiple ACS endpoints, primary is first)
$acsUrls = @(
    "https://us.region-2c-tpdbos1.devgateway.verizon.com/secure_access/services/saml/login-consumer",  # Primary ACS URL
    "https://KENUWADQ-VR-PNF.securegateway.verizon.com/secure-access/services/saml/login-consumer",
    "https://RVDLILBD-VR-PNF.securegateway.verizon.com/secure-access/services/saml/login-consumer"
)

# SAML Entity ID (unchanged)
$entityId  = "https://us-region2-tc-tpdbos1.devgateway.verizon.com/metadata"
$signOnUrl = $acsUrls[0]

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.ReadWrite.All","Directory.ReadWrite.All","Policy.ReadWrite.ApplicationConfiguration","User.ReadWrite.All","Group.ReadWrite.All" -ErrorAction Stop

<#function Wait-ForResource {
    param([ScriptBlock]$CheckScript,[int]$MaxAttempts=12,[int]$DelaySeconds=5)
    for ($i=0; $i -lt $MaxAttempts; $i++) {
        $result = & $CheckScript
        if ($result) { return $result }
        Start-Sleep -Seconds $DelaySeconds
    }
    return $null
}#>

<#try {
    # Prompt for password if not provided
    if ([string]::IsNullOrWhiteSpace($newPassword)) {
        $securePwd = Read-Host -AsSecureString "Enter password for new user '$newUserPrincipalName'"
        $newPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePwd)
        )
    }#>

    # --- Create or get SAML App ---
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

    # Configure SAML including multiple ACS URLs and group claims in manifest
    Update-MgServicePrincipal -ServicePrincipalId $spObjectId -BodyParameter @{ preferredSingleSignOnMode = "saml" } -ErrorAction Stop
    Update-MgApplication -ApplicationId $appObjectId -BodyParameter @{
        identifierUris = @($entityId)
        web = @{ redirectUris = $acsUrls }
        samlMetadataUrl = $entityId
        groupMembershipClaims = "ApplicationGroup"
        optionalClaims = @{
            saml2Token = @(@{ name = "groups"; additionalProperties = @("sam_account_name", "cloud_displayname") })
        }
    } -ErrorAction Stop
    Update-MgServicePrincipal -ServicePrincipalId $spObjectId -BodyParameter @{
        loginUrl = $signOnUrl
        samlSingleSignOnSettings = @{ relayState = $signOnUrl }
    } -ErrorAction Stop

    # Add signing certificate
    Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spObjectId/addTokenSigningCertificate" `
        -Body (@{
            displayName = "CN=$displayName SAML Signing"
            endDateTime = (Get-Date).AddYears(2).ToString("o")
        } | ConvertTo-Json) -ErrorAction Stop

    # --- User and Group Handling as per requirements ---

    # Get or create group
    $groupObj = Get-MgGroup -Filter "displayName eq '$newGroupDisplayName'" -ErrorAction SilentlyContinue
    if (-not $groupObj) {
        $groupObj = New-MgGroup -DisplayName $newGroupDisplayName -MailEnabled:$false -SecurityEnabled:$true `
            -MailNickname $newGroupMailNickname -ErrorAction Stop
        Write-Host "Created group: $($groupObj.DisplayName)"
    } else {
        Write-Host "Group already exists: $($groupObj.DisplayName)"
    }

    # Check if group is assigned to application role
    $appRole = $appObj.AppRoles | Select-Object -First 1
    if (-not $appRole) { throw "No app role found on application." }
    $existingAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spObjectId -ErrorAction SilentlyContinue
    $groupAssignedToApp = $existingAssignments | Where-Object {
        $_.PrincipalId -eq $groupObj.Id -and $_.AppRoleId -eq $appRole.Id
    }

    # Get user if exists
    $userObj = Get-MgUser -Filter "userPrincipalName eq '$newUserPrincipalName'" -ErrorAction SilentlyContinue

    if ($groupAssignedToApp) {
        Write-Host "Group '$($groupObj.DisplayName)' is already assigned to application."

        if ($userObj) {
            # Add existing user to assigned group
            try {
                New-MgGroupMember -GroupId $groupObj.Id -DirectoryObjectId $userObj.Id -ErrorAction Stop
                Write-Host "Added existing user '$($userObj.UserPrincipalName)' to assigned group '$($groupObj.DisplayName)'."
            } catch {
                if ($_.Exception.Message -match 'already a member') {
                    Write-Host "User is already a member of the group."
                } else {
                    throw
                }
            }
        } else {
            # Create new user and add to assigned group
            $passwordProfile = @{
                ForceChangePasswordNextSignIn = $true
                Password = $newPassword
            }
            $userObj = New-MgUser -DisplayName $newDisplayName -UserPrincipalName $newUserPrincipalName `
                -MailNickname $newMailNickname -PasswordProfile $passwordProfile -AccountEnabled:$true -ErrorAction Stop
            Write-Host "Created new user: $($userObj.UserPrincipalName)."

            New-MgGroupMember -GroupId $groupObj.Id -DirectoryObjectId $userObj.Id -ErrorAction Stop
            Write-Host "Added new user '$($userObj.UserPrincipalName)' to assigned group '$($groupObj.DisplayName)'."
        }
    } else {
        # Group not assigned to app: assign now

        if (-not $userObj) {
            # Create user if missing
            $passwordProfile = @{
                ForceChangePasswordNextSignIn = $true
                Password = $newPassword
            }
            $userObj = New-MgUser -DisplayName $newDisplayName -UserPrincipalName $newUserPrincipalName `
                -MailNickname $newMailNickname -PasswordProfile $passwordProfile -AccountEnabled:$true -ErrorAction Stop
            Write-Host "Created new user: $($userObj.UserPrincipalName)."
        } else {
            Write-Host "User exists: $($userObj.UserPrincipalName)."
        }

        # Add user to group (idempotent)
        try {
            New-MgGroupMember -GroupId $groupObj.Id -DirectoryObjectId $userObj.Id -ErrorAction Stop
            Write-Host "Added user '$($userObj.UserPrincipalName)' to group '$($groupObj.DisplayName)'."
        } catch {
            if ($_.Exception.Message -match 'already a member') {
                Write-Host "User is already a member of the group."
            } else {
                throw
            }
        }

        # Assign group to app role
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spObjectId `
            -PrincipalId $groupObj.Id `
            -ResourceId $spObjectId `
            -AppRoleId $appRole.Id -ErrorAction Stop
        Write-Host "Assigned group '$($groupObj.DisplayName)' to application."
    }

    # --- Output summary ---
    $federationMetadataUrl = "https://login.microsoftonline.com/$($appObj.AppId)/federationmetadata/2007-06/federationmetadata.xml?appid=$($appObj.AppId)"
    Write-Host "`n--- SUMMARY ---"
    Write-Host "App: $displayName"
    Write-Host "User: $($userObj.UserPrincipalName)"
    Write-Host "Group: $($groupObj.DisplayName)"
    Write-Host "Federation Metadata URL: $federationMetadataUrl"

#}
 <#catch {
    Write-Error "An error occurred: $_"
    throw
}#>
