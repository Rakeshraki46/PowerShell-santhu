############################################
# 1) Connect to Microsoft Graph
############################################
Connect-MgGraph -Scopes "Application.ReadWrite.All","Directory.ReadWrite.All","Policy.ReadWrite.ApplicationConfiguration"

$displayName = "madrid-100138"

############################################
# 2) Check if application already exists
############################################
$appObj = Get-MgApplication -Filter "displayName eq '$displayName'" -ErrorAction SilentlyContinue
if (-not $appObj) {
    Write-Host "Creating a new SAML application '$displayName'..."

    # Look for a SAML-based template by name (fallback method)
    $template = Get-MgApplicationTemplate -All |
        Where-Object { $_.DisplayName -like "*SAML*" -or $_.DisplayName -like "*Non-gallery*" } |
        Select-Object -First 1

    if (-not $template) { Throw "❌ No SAML template found. Please verify your Graph connectivity or permissions." }

    # Instantiate the template
    $body = @{ displayName = $displayName } | ConvertTo-Json -Depth 3
    $result = Invoke-MgGraphRequest -Method POST -Uri "/beta/applicationTemplates/$($template.Id)/instantiate" -Body $body

    $appId = $result.application.appId
    Write-Host "Created AppRegistration (AppId = $appId)"

    # Wait for app to appear
    for ($i = 0; $i -lt 12; $i++) {
        $appObj = Get-MgApplication -Filter "appId eq '$appId'" -ErrorAction SilentlyContinue
        if ($appObj) { break }
        Start-Sleep -Seconds 5
    }
    if (-not $appObj) { Throw "AppRegistration not visible yet." }
}
else {
    $appId = $appObj.AppId
    Write-Host "Found existing AppRegistration (AppId = $appId)"
}

$appObjectId = $appObj.Id

############################################
# 3) Get or wait for Service Principal
############################################
$spObj = Get-MgServicePrincipal -Filter "appId eq '$appId'" -ErrorAction SilentlyContinue
if (-not $spObj) {
    for ($i = 0; $i -lt 12; $i++) {
        $spObj = Get-MgServicePrincipal -Filter "appId eq '$appId'" -ErrorAction SilentlyContinue
        if ($spObj) { break }
        Start-Sleep -Seconds 5
    }
    if (-not $spObj) { Throw "ServicePrincipal not found." }
}
$spObjectId = $spObj.Id

############################################
# 4) Your URLs — change if needed
############################################
$entityId    = "https"  # ✅ verified domain
$identityUrl = "httpsm/metadata"
$replyUrl    = "httpsumer"
$signOnUrl   = "httpumer"

############################################
# 5) Set the Entity ID (identifierUris)
############################################
try {
    Update-MgApplication -ApplicationId $appObjectId -BodyParameter @{
        identifierUris = @($entityId)
    }
    Write-Host "✅ Set Entity ID (identifierUris)"
}
catch {
    Write-Warning "⚠ Failed to set Entity ID."
    Write-Warning $_
}

############################################
# 6) Set samlMetadataUrl
############################################
Update-MgApplication -ApplicationId $appObjectId -BodyParameter @{
    samlMetadataUrl = $identityUrl
}
Write-Host "✅ Set samlMetadataUrl"

############################################
# 7) Set Reply URL
############################################
Update-MgApplication -ApplicationId $appObjectId -BodyParameter @{
    web = @{
        redirectUris = @($replyUrl)
    }
}
Write-Host "✅ Set Reply URL"

############################################
# 8) Configure ServicePrincipal
############################################
Update-MgServicePrincipal -ServicePrincipalId $spObjectId -BodyParameter @{
    preferredSingleSignOnMode = "saml"
    loginUrl                  = $signOnUrl
    samlSingleSignOnSettings  = @{ relayState = $replyUrl }
}
Write-Host "✅ Configured SP for direct SAML SSO"

############################################
# 9) Issue a signing certificate
############################################
$certResp = Invoke-MgGraphRequest -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spObjectId/addTokenSigningCertificate" `
    -Body (@{
        displayName = "CN=$displayName SAML Signing"
        endDateTime = (Get-Date).AddYears(2).ToString("o")
    } | ConvertTo-Json)

Write-Host "✅ Certificate thumbprint: $($certResp.thumbprint)"

############################################
# 10) Output Metadata URL
############################################
$federationMetadataUrl = "https://login.microsoftonline.com/$appId/federationmetadata/2007-06/federationmetadata.xml?appid=$appId"
Write-Host "`n✅ SAML app '$displayName' is ready!"
Write-Host "Federation Metadata URL:"
Write-Host "  $federationMetadataUrl"
