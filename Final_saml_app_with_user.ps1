#
# A complete script for SAML onboarding, including user and group provisioning.
# This script is an enhanced version of your original code.
#
# --- IMPORTANT ---
# Before running this script, please run the following command to ensure your PowerShell module is up to date:
# Update-Module Microsoft.Graph -Force
# -----------------

# --- Define New User and Group Parameters ---
# Use this section to provide details for the new user and groups to assign.
$newUserPrincipalName = "santoshyamsani@verizon038.onmicrosoft.com" # CHANGE THIS TO YOUR NEW USER'S UPN
$newPassword = "Password!123" # CHANGE THIS TO A STRONG, SECURE PASSWORD
$newDisplayName = "santoshyamsani"
$newMailNickname = "madriduser"
$groupsToAssign = @(
    #"group-object-id-1", # REPLACE WITH ACTUAL GROUP OBJECT IDs
   # "group-object-id-2"  # REPLACE WITH ACTUAL GROUP OBJECT IDs
)

# --- Start of Script Execution ---

# Add the 'User.ReadWrite.All' scope to the existing permissions.
Connect-MgGraph -Scopes "Application.ReadWrite.All","Directory.ReadWrite.All","Policy.ReadWrite.ApplicationConfiguration","User.ReadWrite.All"

#

try {
    # --- YOUR ORIGINAL SCRIPT STARTS HERE ---

    $displayName = "VerizonPOC"
    
    $template = Get-MgApplicationTemplate -All | Where-Object { $_.DisplayName -like "*SAML*" } | Select-Object -First 1
    if (-not $template) { throw "❌ No SAML template found." }

    $body = @{ displayName = $displayName } | ConvertTo-Json
    $result = Invoke-MgGraphRequest -Method POST -Uri "/beta/applicationTemplates/$($template.Id)/instantiate" -Body $body
    $appId = $result.application.appId

    for ($i = 0; $i -lt 12; $i++) {
        $appObj = Get-MgApplication -Filter "appId eq '$appId'" -ErrorAction SilentlyContinue
        if ($appObj) { break }
        Start-Sleep -Seconds 5
    }
    if (-not $appObj) { throw "App registration not visible yet." }

    $appObjectId = $appObj.Id

    # Create or get existing Service Principal
    $spObj = Get-MgServicePrincipal -Filter "appId eq '$($appObj.AppId)'" -ErrorAction SilentlyContinue
    if (-not $spObj) {
        Write-Host "Creating Service Principal..."
        $spObj = New-MgServicePrincipal -AppId $appObj.AppId
    }
    $spObjectId = $spObj.Id

    # CRITICAL STEP: Set SAML mode BEFORE setting custom URLs
    Update-MgServicePrincipal -ServicePrincipalId $spObjectId -BodyParameter @{
        preferredSingleSignOnMode = "saml"
    }
    Write-Host "✅ Set preferredSingleSignOnMode to SAML"

    # URLs (No Domain Verification required after above step)
    $entityId    = "https://us-region2-tc-tpdbos1.devgateway.verizon.com/metadata"
    $replyUrl    = "https://us.region-2c-tpdbos1.devgateway.verizon.com/secure_access/services/saml/login-consumer"
    $signOnUrl   = "https://us.region-2c-tpdbos1.devgateway.verizon.com/secure_access/services/saml/login-consumer"

    # Now safely set custom URLs
    Update-MgApplication -ApplicationId $appObjectId -BodyParameter @{
        identifierUris = @($entityId)
        web = @{ redirectUris = @($replyUrl) }
        samlMetadataUrl = $entityId
    }
    Write-Host "✅ Custom URLs configured without domain verification."

    # Configure SP for direct SAML SSO
    Update-MgServicePrincipal -ServicePrincipalId $spObjectId -BodyParameter @{
        loginUrl = $signOnUrl
        samlSingleSignOnSettings = @{ relayState = $replyUrl }
    }
    Write-Host "✅ Configured SP for SAML SSO"

    # Add Signing Certificate
    $certResp = Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spObjectId/addTokenSigningCertificate" `
        -Body (@{
            displayName = "CN=$displayName SAML Signing"
            endDateTime = (Get-Date).AddYears(2).ToString("o")
        } | ConvertTo-Json)

    Write-Host "✅ Certificate thumbprint: $($certResp.thumbprint)"

    # --- YOUR ORIGINAL SCRIPT ENDS HERE ---

    # --- NEW: User and Group Provisioning ---

    # 1. Create a new user
    Write-Host "`n👥 Creating new user account: '$newUserPrincipalName'..."
    $passwordProfile = @{
        ForceChangePasswordNextSignIn = $true
        Password = $newPassword
    }
    $newUser = New-MgUser -DisplayName $newDisplayName -UserPrincipalName $newUserPrincipalName -MailNickname $newMailNickname -PasswordProfile $passwordProfile -AccountEnabled:$true
    Write-Host "✅ New user '$($newUser.DisplayName)' created successfully."
    
    # 2. Get the AppRole from the Application object directly and wait for it
    Write-Host "➡️ Retrieving App Role from the Application object..."
    $appRoleFound = $false
    for ($i = 0; $i -lt 12; $i++) {
        $appObj = Get-MgApplication -ApplicationId $appObjectId
        if ($appObj.AppRoles) {
            $appRole = $appObj.AppRoles | Select-Object -First 1
            $appRoleFound = $true
            break
        }
        Start-Sleep -Seconds 5
    }

    if ($appRoleFound) {
        Write-Host "✅ App role found. Assigning user and groups..."
        
        # Assign the new user
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spObjectId `
            -PrincipalId $newUser.Id `
            -ResourceId $spObjectId `
            -AppRoleId $appRole.Id | Out-Null
        Write-Host "✅ Assigned new user '$($newUser.DisplayName)' to the application."
        
        # 3. Assign groups to the application
        if ($groupsToAssign) {
            Write-Host "`n➡️ Assigning specified groups to the application..."
            foreach ($groupId in $groupsToAssign) {
                $group = Get-MgGroup -GroupId $groupId -ErrorAction SilentlyContinue
                if ($group) {
                    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spObjectId `
                        -PrincipalId $group.Id `
                        -ResourceId $spObjectId `
                        -AppRoleId $appRole.Id | Out-Null
                    Write-Host "✅ Assigned group '$($group.DisplayName)' to the application."
                } else {
                    Write-Warning "⚠️ Could not find group with ID: $groupId. Skipping assignment."
                }
            }
        } else {
            Write-Host "`n📝 No groups were specified for assignment."
        }
    } else {
        Write-Warning "⚠️ Could not find any app roles on the Application object after several attempts. User was created but not assigned."
    }

    # Final Output with Federation Metadata URL
    $federationMetadataUrl = "https://login.microsoftonline.com/$($appObj.AppId)/federationmetadata/2007-06/federationmetadata.xml?appid=$($appObj.AppId)"
    Write-Host "`n✅ SAML App '$displayName' created and configured successfully!"
    Write-Host "Federation Metadata URL: $federationMetadataUrl"

} catch {
    Write-Host "`n❌ An error occurred during the execution. Details: $_"
}
