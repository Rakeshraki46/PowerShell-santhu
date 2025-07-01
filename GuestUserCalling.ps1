# --- 1. Connect to Microsoft Graph ---
Connect-MgGraph -Scopes "Application.ReadWrite.All", "Directory.ReadWrite.All", "User.Invite.All"

# --- 2. Configuration: Update these values as needed ---
$displayName   = "madrid-guest-demo-33333"
$identityUrl   = "https://us-region2-tc-tpdbos1.devgateway.verizon.com/metadata"   # EntityID
$replyUrl      = "https://us.region-2c-tpdbos1.devgateway.verizon.com/secure_access/services/saml/login-consumer"
$signOnUrl     = $replyUrl

$customerEmail = "rakesh.joruka9999@gmail.com"   # Guest email to invite
$redirectUrl   = $replyUrl                       # Where user lands after accepting invite

# --- 3. App Creation via SAML template ---
$appObj = Get-MgApplication -Filter "displayName eq '$displayName'" -ErrorAction SilentlyContinue
if (-not $appObj) {
    Write-Host "Creating SAML App '$displayName'..."
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
} else {
    $appId = $appObj.AppId
    Write-Host "Found existing App '$displayName' (AppId = $appId)"
}
$appObjectId = $appObj.Id

# --- 4. Set identifierUris using a verified domain (fallback to onmicrosoft.com) ---
$verifiedDomains = (Get-MgDomain | Where-Object { $_.IsVerified }).Id
$fallbackEntityId  = "https://verizon038.onmicrosoft.com/$displayName"
$entityIdToUse = if ($verifiedDomains -contains "us-region2-tc-tpdbos1.devgateway.verizon.com") {
                    $identityUrl
                } else {
                    Write-Warning "⚠ Domain not verified. Using fallback onmicrosoft domain."
                    $fallbackEntityId
                }
Update-MgApplication -ApplicationId $appObjectId -BodyParameter @{ identifierUris = @($entityIdToUse) }
Write-Host "✅ Set Entity ID to $entityIdToUse"
Update-MgApplication -ApplicationId $appObjectId -BodyParameter @{ samlMetadataUrl = $identityUrl }
Write-Host "✅ Set samlMetadataUrl"
Update-MgApplication -ApplicationId $appObjectId -BodyParameter @{ web = @{ redirectUris = @($replyUrl) } }
Write-Host "✅ Set Reply URL"

# --- 5. Wait for SP ---
$spObj = Get-MgServicePrincipal -Filter "appId eq '$appId'" -ErrorAction SilentlyContinue
if (-not $spObj) {
    for ($i = 0; $i -lt 12; $i++) {
        $spObj = Get-MgServicePrincipal -Filter "appId eq '$appId'" -ErrorAction SilentlyContinue
        if ($spObj) { break }
        Start-Sleep -Seconds 5
    }
    if (-not $spObj) { throw "ServicePrincipal not found." }
}
$spObjectId = $spObj.Id

# --- 6. Configure SP for SAML ---
Update-MgServicePrincipal -ServicePrincipalId $spObjectId -BodyParameter @{
    preferredSingleSignOnMode = "saml"
    loginUrl = $signOnUrl
    samlSingleSignOnSettings = @{ relayState = $replyUrl }
}
Write-Host "✅ Configured SP for direct SAML SSO"

# --- 7. Add signing cert (optional) ---
$certResp = Invoke-MgGraphRequest -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spObjectId/addTokenSigningCertificate" `
    -Body (@{
        displayName = "CN=$displayName SAML Signing"
        endDateTime = (Get-Date).AddYears(2).ToString("o")
    } | ConvertTo-Json)
Write-Host "✅ Certificate thumbprint: $($certResp.thumbprint)"

# --- 8. Output Federation Metadata URL ---
$federationMetadataUrl = "https://login.microsoftonline.com/$appId/federationmetadata/2007-06/federationmetadata.xml?appid=$appId"
Write-Host "`n✅ SAML app '$displayName' is ready!"
Write-Host "Federation Metadata URL: $federationMetadataUrl"

# --- 9. Onboard B2B guest user and assign to SAML app ---
try {
    $invitedUser = New-MgInvitation `
        -InvitedUserEmailAddress $customerEmail `
        -InviteRedirectUrl $redirectUrl `
        -SendInvitationMessage `
        -InvitedUserDisplayName "External Guest User"
    $guestUserId = $invitedUser.InvitedUser.Id
    Write-Host "✅ Invited guest user: $customerEmail"
} catch {
    Write-Warning "⚠ Error inviting user: $_"
    $guestUserId = $null
}

if ($guestUserId) {
    $appRoles = $spObj.AppRoles | Where-Object { $_.Value -eq "user" -or $_.Value -eq "default" }
    if (-not $appRoles) { $appRoles = $spObj.AppRoles | Select-Object -First 1 }
    $appRoleId = $appRoles.Id
    if ($appRoleId) {
        try {
            New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spObj.Id `
                -PrincipalId $guestUserId `
                -ResourceId $spObj.Id `
                -AppRoleId $appRoleId
            Write-Host "✅ Assigned guest user to SAML app"
        } catch {
            Write-Warning "⚠ Error assigning user to app: $_"
        }
    }
}

Write-Host "`n🎉 SAML app provisioned and external guest user onboarded! User will log in with their own Entra credentials and land at the Reply URL: $redirectUrl"
