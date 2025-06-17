Connect-MgGraph -Scopes "Application.ReadWrite.All","Directory.ReadWrite.All","Policy.ReadWrite.ApplicationConfiguration"

$displayName = "madrid-100139"
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
}
else {
    $appId = $appObj.AppId
    Write-Host "Found existing App '$displayName' (AppId = $appId)"
}

$appObjectId = $appObj.Id

# Wait for SP
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

# URLs
$identityUrl = "https:adata"
$replyUrl    = "https:consumer"
$signOnUrl   = "https:nsumer"

# Get Verified Domains
$verifiedDomains = (Get-MgDomain | Where-Object { $_.IsVerified }).Id

# Try preferred Entity ID
$preferredEntityId = "https://us-region2-tc-tpdbos1.devgateway.verizon.com/metadata"
$fallbackEntityId  = "https://verizon038.onmicrosoft.com/$displayName"

$entityIdToUse = if ($verifiedDomains -contains "devgateway.verizon.com" -or
                    $verifiedDomains -contains "us-region2-tc-tpdbos1.devgateway.verizon.com") {
                    $preferredEntityId
                }
                else {
                    Write-Warning "⚠ Domain not verified. Using fallback onmicrosoft domain."
                    $fallbackEntityId
                }

# Update identifierUris
try {
    Update-MgApplication -ApplicationId $appObjectId -BodyParameter @{
        identifierUris = @($entityIdToUse)
    }
    Write-Host "✅ Set Entity ID to $entityIdToUse"
}
catch {
    Write-Warning "⚠ Failed to set Entity ID. Using fallback."
    Write-Warning $_
}

# Set metadata
Update-MgApplication -ApplicationId $appObjectId -BodyParameter @{
    samlMetadataUrl = $identityUrl
}
Write-Host "✅ Set samlMetadataUrl"

# Set reply URL
Update-MgApplication -ApplicationId $appObjectId -BodyParameter @{
    web = @{ redirectUris = @($replyUrl) }
}
Write-Host "✅ Set Reply URL"

# SP config
Update-MgServicePrincipal -ServicePrincipalId $spObjectId -BodyParameter @{
    preferredSingleSignOnMode = "saml"
    loginUrl = $signOnUrl
    samlSingleSignOnSettings = @{ relayState = $replyUrl }
}
Write-Host "✅ Configured SP for direct SAML SSO"

# Add cert
$certResp = Invoke-MgGraphRequest -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spObjectId/addTokenSigningCertificate" `
    -Body (@{
        displayName = "CN=$displayName SAML Signing"
        endDateTime = (Get-Date).AddYears(2).ToString("o")
    } | ConvertTo-Json)

Write-Host "✅ Certificate thumbprint: $($certResp.thumbprint)"

# Metadata URL
$federationMetadataUrl = "https://login.microsoftonline.com/$appId/federationmetadata/2007-06/federationmetadata.xml?appid=$appId"
Write-Host "`n✅ SAML app '$displayName' is ready!"
Write-Host "Federation Metadata URL: $federationMetadataUrl"
