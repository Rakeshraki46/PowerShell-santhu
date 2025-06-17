############################################
# 1) Connect to Microsoft Graph
############################################
Connect-MgGraph -Scopes "Application.ReadWrite.All","Directory.ReadWrite.All","Policy.ReadWrite.ApplicationConfiguration"

############################################
# 2) Find the existing madrid-10012 application
############################################
$displayName = "madrid-100139"
$appObj = Get-MgApplication -Filter "displayName eq '$displayName'" -ErrorAction Stop
if (-not $appObj) { Throw "Application '$displayName' not found in Graph." }
$appObjectId = $appObj.Id
$appId = $appObj.AppId

# Find the ServicePrincipal
$spObj = Get-MgServicePrincipal -Filter "appId eq '$appId'" -ErrorAction Stop
if (-not $spObj) { Throw "ServicePrincipal for appId '$appId' not found in Graph." }
$spObjectId = $spObj.Id

Write-Host "Found AppRegistration (AppId = $appId)"

############################################
# 3) YOUR SETTINGS — update these three
############################################
# URLs from the screenshot for madrid-10012
$entityId    = "https://metadata" # Entity ID (Identifier)
$identityUrl = "https://etadata"
$replyUrl    = "https://onsumer"
#$signOnUrl   = "https:/sumer"

############################################
# 4) Set the Entity ID (Identifier) on the AppRegistration
############################################
Update-MgApplication -ApplicationId $appObjectId -BodyParameter @{
    identifierUris = @($entityId)
}
Write-Host "Set Entity ID on AppRegistration."

############################################
# 5) Point the AppRegistration at your IdP metadata
############################################
Update-MgApplication -ApplicationId $appObjectId -BodyParameter @{
    samlMetadataUrl = $identityUrl
}
Write-Host "Set samlMetadataUrl on AppRegistration."

############################################
# 6) Explicitly set the Reply URL on the AppRegistration
############################################
Update-MgApplication -ApplicationId $appObjectId -BodyParameter @{
    web = @{
        redirectUris = @($replyUrl)
    }
}
Write-Host "Set Reply URL on AppRegistration."

############################################
# 7) Enable direct SAML SSO on the SP
############################################
Update-MgServicePrincipal -ServicePrincipalId $spObjectId -BodyParameter @{
    preferredSingleSignOnMode = "saml"
    loginUrl                  = $signOnUrl
    samlSingleSignOnSettings  = @{ relayState = $replyUrl }
}
Write-Host "Configured ServicePrincipal for direct SAML SSO."

############################################
# 8) (Optional) Let Azure AD issue your signing cert
############################################
$certResp = Invoke-MgGraphRequest -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spObjectId/addTokenSigningCertificate" `
    -Body (@{
        displayName = "CN=$displayName SAML Signing"
        endDateTime = (Get-Date).AddYears(2).ToString("o")
    } | ConvertTo-Json)

Write-Host "Certificate thumbprint: $($certResp.thumbprint)"

############################################
# 9) Done — output your metadata URL
############################################
$federationMetadataUrl = "https://login.microsoftonline.com/$appId/federationmetadata/2007-06/federationmetadata.xml?appid=$appId"
Write-Host "`n✅ SAML app '$displayName' is ready!"
Write-Host "Federation Metadata URL:"
Write-Host "  $federationMetadataUrl"
