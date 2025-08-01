Connect-MgGraph -Scopes "Application.ReadWrite.All","Directory.ReadWrite.All","Policy.ReadWrite.ApplicationConfiguration"

$displayName = "madrid-1"

$template = Get-MgApplicationTemplate -All | Where-Object { $_.DisplayName -like "*SAML*" } | Select-Object -First 1
if (-not $template) { throw " No SAML template found." }

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
Write-Host " Set preferredSingleSignOnMode to SAML"

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
Write-Host " Custom URLs configured without domain verification."

# Configure SP for direct SAML SSO
Update-MgServicePrincipal -ServicePrincipalId $spObjectId -BodyParameter @{
    loginUrl = $signOnUrl
    samlSingleSignOnSettings = @{ relayState = $replyUrl }
}
Write-Host " Configured SP for SAML SSO"

# Add Signing Certificate
$certResp = Invoke-MgGraphRequest -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spObjectId/addTokenSigningCertificate" `
    -Body (@{
        displayName = "CN=$displayName SAML Signing"
        endDateTime = (Get-Date).AddYears(2).ToString("o")
    } | ConvertTo-Json)

Write-Host " Certificate thumbprint: $($certResp.thumbprint)"

# Output Federation Metadata URL
$federationMetadataUrl = "https://login.microsoftonline.com/$($appObj.AppId)/federationmetadata/2007-06/federationmetadata.xml?appid=$($appObj.AppId)"

Write-Host "`n SAML App '$displayName' created successfully!"
Write-Host "Federation Metadata URL: $federationMetadataUrl"
