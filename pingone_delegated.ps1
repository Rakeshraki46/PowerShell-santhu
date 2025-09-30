<# 
PingOne – Create/Update SAML App (handles name collision)
- Uses worker client_credentials (Basic auth) for Admin API
- Top-level SAML payload (protocol:"SAML", spEntityId, acsUrls, assertionDuration)
- If name exists:
   * if existing app is SAML -> update it
   * if existing app is OIDC  -> create a new app with "-saml-<timestamp>" suffix
#>

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

# ======= YOUR VALUES =======
$EnvId        = 'be5b8893-ab1b-446d-bff2-6f16a676cd76'
$RegionTld    = 'eu'

# Worker app (same env) with Admin API scopes
$ClientId     = '169b57b4-a834-42ce-88a8-1007e00590ca'
$ClientSecret = '0d-AzqCu4PbwuiGkAfTPB_0uWxxNggvz2rWsc4XQE32qilr41CxarsIcHDy4BhW8'
$Scopes       = 'p1:read:environments p1:read:applications p1:write:applications p1:read:groups p1:write:groups p1:read:roles p1:write:roles'

# Target app settings
$DisplayName  = 'api_worker12'
$SpEntityId   = 'https://us-region2-tc-tpdbos1.devgateway.verizon.com/metadata'
$AcsUrls      = @(
  'https://us.region-2c-tpdbos1.devgateway.verizon.com/secure_access/services/saml/login-consumer',
  'https://KENUWADQ-VR-PNF.securegateway.verizon.com/secure_access/services/saml/login-consumer',
  'https://RVDLILBD-VR-PNF.securegateway.verizon.com/secure_access/services/saml/login-consumer'
)
$SignOnUrl    = 'https://us.region-2c-tpdbos1.devgateway.verizon.com/secure_access/services/saml/login-consumer'
$NameIdFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
$AssertionDuration = 3600
$MapGroups   = $true

# ======= Endpoints =======
$AuthBase = "https://auth.pingone.$RegionTld/$EnvId"
$ApiBase  = "https://api.pingone.$RegionTld/v1/environments/$EnvId"

# ======= Helpers =======
function Write-Req($Method,$Url,$BodyObj) {
  Write-Host "`n--- $Method $Url ---"
  if ($null -ne $BodyObj) { $BodyObj | ConvertTo-Json -Depth 50 | Write-Host }
}

function Invoke-Json {
  param([ValidateSet('GET','POST','PUT')]$Method,[string]$Url,[hashtable]$Headers,$Body=$null)
  Write-Req $Method $Url $Body
  try {
    if ($Body -ne $null) {
      return Invoke-WebRequest -Method $Method -Uri $Url -Headers $Headers -ContentType 'application/json' -Body ($Body | ConvertTo-Json -Depth 50) -ErrorAction Stop
    } else {
      return Invoke-WebRequest -Method $Method -Uri $Url -Headers $Headers -ErrorAction Stop
    }
  } catch {
    if ($_.Exception.Response) {
      $resp = $_.Exception.Response
      $sr = New-Object IO.StreamReader($resp.GetResponseStream())
      $body = $sr.ReadToEnd()
      if ($body) { Write-Host "`n--- ERROR BODY ---" -ForegroundColor Yellow; Write-Host $body }
    }
    throw
  }
}

function Get-Json($resp) { if ($resp.Content) { return ($resp.Content | ConvertFrom-Json) } else { return $null } }

function GetProtocolType($app) {
  if ($null -eq $app) { return '' }
  $p = $app.protocol
  if ($p -is [string]) { return $p }            # "SAML" for top-level SAML apps
  if ($p -and $p.type) { return $p.type }       # e.g., "OPENID_CONNECT" for OIDC apps
  return ''
}

function BuildTopLevelSamlBody($name,$sp,$acs,$dur,$signOn,$nameId) {
  return @{
    name              = $name
    enabled           = $true
    type              = 'WEB_APP'
    protocol          = 'SAML'
    spEntityId        = $sp
    acsUrls           = $acs
    assertionDuration = [int]$dur
    signOnUrl         = $signOn
    nameIdFormat      = $nameId
  }
}

function SetAttr($ApiBase,$H,$AppId,$Name,$Value,$Multi) {
  try {
    $maps = Get-Json (Invoke-Json GET "$ApiBase/applications/$AppId/attributeMappings" $H)
    $hit = $maps._embedded.items | Where-Object { $_.name -eq $Name }
    $payload = @{ name=$Name; value=$Value; mappingType='CORE'; format='STRING'; multiValued=$Multi }
    if ($hit) {
      Invoke-Json PUT "$ApiBase/applications/$AppId/attributeMappings/$($hit.id)" $H ($payload + @{ id=$hit.id }) | Out-Null
    } else {
      Invoke-Json POST "$ApiBase/applications/$AppId/attributeMappings" $H $payload | Out-Null
    }
  } catch {
    # fallback legacy attributes endpoint
    $attrs = Get-Json (Invoke-Json GET "$ApiBase/applications/$AppId/attributes" $H)
    $hit2  = $attrs._embedded.items | Where-Object { $_.name -eq $Name }
    $payload2 = @{ name=$Name; value=$Value; mappingType='CORE'; format='STRING'; multiValued=$Multi }
    if ($hit2) {
      Invoke-Json PUT "$ApiBase/applications/$AppId/attributes/$($hit2.id)" $H ($payload2 + @{ id=$hit2.id }) | Out-Null
    } else {
      Invoke-Json POST "$ApiBase/applications/$AppId/attributes" $H $payload2 | Out-Null
    }
  }
}

# ======= 1) Token via Basic auth (works in your env) =======
$basic   = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$ClientId`:$ClientSecret"))
$tokHdrs = @{ Authorization = "Basic $basic"; 'Content-Type' = 'application/x-www-form-urlencoded' }
$scopes  = [Uri]::EscapeDataString($Scopes)
$tokResp = Invoke-RestMethod -Method POST -Uri "$AuthBase/as/token" -Headers $tokHdrs -Body "grant_type=client_credentials&scope=$scopes"
$H = @{ Authorization = "Bearer $($tokResp.access_token)"; Accept='application/json, application/hal+json' }
Write-Host "Token OK" -ForegroundColor Green

# ======= 2) Optional sanity GET =======
Get-Json (Invoke-Json GET $ApiBase $H) | Out-Null
Write-Host "Env GET OK" -ForegroundColor Green

# ======= 3) Try create; if name collision, handle it =======
$bodyCreate = BuildTopLevelSamlBody $DisplayName $SpEntityId $AcsUrls $AssertionDuration $SignOnUrl $NameIdFormat

try {
  $createResp = Invoke-Json POST "$ApiBase/applications" $H $bodyCreate
  $app = Get-Json $createResp
  $effectiveName = $DisplayName
  Write-Host ("Created SAML app id={0}" -f $app.id) -ForegroundColor Green
} catch {
  # Check if it’s a UNIQUENESS_VIOLATION on name
  $existingId = $null
  if ($_.Exception.Response) {
    try {
      $sr = New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())
      $errJson = $sr.ReadToEnd() | ConvertFrom-Json
      if ($errJson.code -eq 'INVALID_DATA' -and $errJson.details) {
        $nameErr = $errJson.details | Where-Object { $_.code -eq 'UNIQUENESS_VIOLATION' -and $_.target -eq 'name' }
        if ($nameErr -and $nameErr.innerError -and $nameErr.innerError.existingId) {
          $existingId = $nameErr.innerError.existingId
        }
      }
    } catch {}
  }

  if ($existingId) {
    # Fetch the existing app and decide
    $existResp = Invoke-Json GET "$ApiBase/applications/$existingId" $H
    $existing  = Get-Json $existResp
    $ptype = GetProtocolType $existing
    if ($ptype -eq 'SAML') {
      # Update that SAML app in-place
      $bodyUpdate = $bodyCreate + @{ id = $existingId }
      $updResp = Invoke-Json PUT "$ApiBase/applications/$existingId" $H $bodyUpdate
      $app = Get-Json $updResp
      $effectiveName = $app.name
      Write-Host ("Updated existing SAML app id={0}" -f $app.id) -ForegroundColor Yellow
    } else {
      # Existing is OIDC → create with a suffixed unique name
      $suffix = (Get-Date -Format 'yyyyMMddHHmmss')
      $newName = "$DisplayName-saml-$suffix"
      $bodyCreate2 = BuildTopLevelSamlBody $newName $SpEntityId $AcsUrls $AssertionDuration $SignOnUrl $NameIdFormat
      $createResp2 = Invoke-Json POST "$ApiBase/applications" $H $bodyCreate2
      $app = Get-Json $createResp2
      $effectiveName = $newName
      Write-Host ("Name in use by OIDC app. Created SAML app with new name '{0}' (id={1})" -f $newName, $app.id) -ForegroundColor Green
    }
  } else {
    throw  # rethrow unknown error
  }
}

$appId = $app.id

# ======= 4) Attribute mappings =======
SetAttr $ApiBase $H $appId 'saml_subject' '$${user.email}'        $false
SetAttr $ApiBase $H $appId 'email'        '$${user.email}'        $false
SetAttr $ApiBase $H $appId 'firstName'    '$${user.givenName}'    $false
SetAttr $ApiBase $H $appId 'lastName'     '$${user.familyName}'   $false
if ($MapGroups) { SetAttr $ApiBase $H $appId 'groups' '$${user.groups.names}' $true }

# ======= 5) Summary =======
$md = "https://auth.pingone.$RegionTld/$EnvId/saml20/idp/metadata"
Write-Host "`n--- ✅ COMPLETE ---" -ForegroundColor Green
Write-Host ("App Name      : {0}" -f $effectiveName)
Write-Host ("App ID        : {0}" -f $appId)
Write-Host ("SP Entity ID  : {0}" -f $SpEntityId)
Write-Host ("ACS URLs      : {0}" -f ($AcsUrls -join ', '))
Write-Host ("Assertion (s) : {0}" -f $AssertionDuration)
Write-Host ("IdP Metadata  : {0}" -f $md)
