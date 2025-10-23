# PingOne – Create/Update SAML App (PowerShell 5.1 compatible)
# Prompts for EnvId, ClientId and ClientSecret at runtime (ClientSecret is hidden)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

# ======= PROMPT FOR REQUIRED VALUES =======
function Read-NonEmpty([string]$prompt) {
  $val = Read-Host $prompt
  while ([string]::IsNullOrWhiteSpace($val)) {
    Write-Host "Value cannot be empty." -ForegroundColor Yellow
    $val = Read-Host $prompt
  }
  return $val
}

$EnvId = Read-NonEmpty "Enter Environment ID (EnvId)"
$RegionTld = Read-Host "Enter region TLD (default: ca)"
if ([string]::IsNullOrWhiteSpace($RegionTld)) { $RegionTld = 'ca' }

$ClientId = Read-NonEmpty "Enter Worker ClientId"

# read client secret as secure string and convert to plain for Basic auth
Write-Host "Enter Client Secret (input will be hidden) :" -NoNewline
$ClientSecretSecure = Read-Host -AsSecureString
# validate non-empty
while ($ClientSecretSecure.Length -eq 0) {
  Write-Host "`nClient Secret cannot be empty." -ForegroundColor Yellow
  Write-Host "Enter Client Secret (input will be hidden) :" -NoNewline
  $ClientSecretSecure = Read-Host -AsSecureString
}
$ClientSecret = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
  [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecretSecure)
)

# scopes (leave as-is or modify)
$Scopes = 'p1:read:environments p1:read:applications p1:write:applications p1:read:groups p1:write:groups p1:read:roles p1:write:roles'

# Target app settings (edit defaults if you want)
$DisplayName  = 'RakeshS'
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
      try {
        $sr = New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())
        $body = $sr.ReadToEnd()
        if ($body) { Write-Host "`n--- ERROR BODY ---" -ForegroundColor Yellow; Write-Host $body }
      } catch {}
    }
    throw
  }
}

function Get-Json($resp) {
  if ($null -ne $resp -and $resp.Content) { return ($resp.Content | ConvertFrom-Json) }
  return $null
}

function Get-EmbeddedItems($obj) {
  if ($null -eq $obj) { return @() }
  if ($obj.PSObject.Properties.Name -contains '_embedded' -and $null -ne $obj._embedded) {
    if ($obj._embedded.PSObject.Properties.Name -contains 'items' -and $null -ne $obj._embedded.items) {
      return $obj._embedded.items
    }
  }
  return @()
}

function GetProtocolType($app) {
  if ($null -eq $app) { return '' }
  $p = $app.protocol
  if ($p -is [string]) { return $p }
  if ($null -ne $p -and $p.PSObject.Properties.Name -contains 'type') { return $p.type }
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

function IsUniqNameError($errText) {
  if ([string]::IsNullOrEmpty($errText)) { return $false }
  return ($errText -match '"UNIQUENESS_VIOLATION"' -and $errText -match '"target"\s*:\s*"name"')
}

function UpsertAttr {
  param($ApiBase,$H,$AppId,[string]$Name,[string]$Value,[bool]$Multi)

  # Try modern attributeMappings
  $usedModern = $true
  try {
    $mapsResp = Invoke-Json GET "$ApiBase/applications/$AppId/attributeMappings" $H
    $maps     = Get-Json $mapsResp
    $items    = Get-EmbeddedItems $maps
    $hit      = $null
    if ($items.Count -gt 0) { $hit = $items | Where-Object { $_.name -eq $Name } | Select-Object -First 1 }

    $payload  = @{ name=$Name; value=$Value; mappingType='CORE'; format='STRING'; multiValued=$Multi }
    if ($null -ne $hit) {
      Invoke-Json PUT "$ApiBase/applications/$AppId/attributeMappings/$($hit.id)" $H ($payload + @{ id=$hit.id }) | Out-Null
      Write-Host "Attr '$Name' updated (attributeMappings)."
      return
    } else {
      try {
        Invoke-Json POST "$ApiBase/applications/$AppId/attributeMappings" $H $payload | Out-Null
        Write-Host "Attr '$Name' created (attributeMappings)."
        return
      } catch {
        $err = $null
        if ($_.Exception.Response) {
          $sr = New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())
          $err = $sr.ReadToEnd()
        }
        if (IsUniqNameError $err) {
          Write-Host "Attr '$Name' already exists (attributeMappings) → skipping."
          return
        }
        throw
      }
    }
  } catch {
    $usedModern = $false
  }

  # Fallback legacy /attributes
  try {
    $attrsResp = Invoke-Json GET "$ApiBase/applications/$AppId/attributes" $H
    $attrs     = Get-Json $attrsResp
    $items2    = Get-EmbeddedItems $attrs
    $hit2      = $null
    if ($items2.Count -gt 0) { $hit2 = $items2 | Where-Object { $_.name -eq $Name } | Select-Object -First 1 }

    $payload2  = @{ name=$Name; value=$Value; mappingType='CORE'; format='STRING'; multiValued=$Multi }
    if ($null -ne $hit2) {
      Invoke-Json PUT "$ApiBase/applications/$AppId/attributes/$($hit2.id)" $H ($payload2 + @{ id=$hit2.id }) | Out-Null
      Write-Host "Attr '$Name' updated (attributes)."
    } else {
      try {
        Invoke-Json POST "$ApiBase/applications/$AppId/attributes" $H $payload2 | Out-Null
        Write-Host "Attr '$Name' created (attributes)."
      } catch {
        $err2 = $null
        if ($_.Exception.Response) {
          $sr2 = New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())
          $err2 = $sr2.ReadToEnd()
        }
        if (IsUniqNameError $err2) {
          Write-Host "Attr '$Name' already exists (attributes) → skipping."
          return
        }
        throw
      }
    }
  } catch {
    if ($usedModern -eq $false) {
      Write-Host "Attr '$Name' could not be set; both endpoints failed." -ForegroundColor Yellow
    } else {
      throw
    }
  }
}

# ======= 1) Token via Basic auth =======
$basic   = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$ClientId`:$ClientSecret"))
$tokHdrs = @{ Authorization = "Basic $basic"; 'Content-Type' = 'application/x-www-form-urlencoded' }
$scopes  = [Uri]::EscapeDataString($Scopes)
$tokResp = Invoke-RestMethod -Method POST -Uri "$AuthBase/as/token" -Headers $tokHdrs -Body "grant_type=client_credentials&scope=$scopes"
$H = @{ Authorization = "Bearer $($tokResp.access_token)"; Accept='application/json, application/hal+json' }
Write-Host "Token OK" -ForegroundColor Green

# ======= 2) Optional sanity GET =======
Get-Json (Invoke-Json GET $ApiBase $H) | Out-Null
Write-Host "Env GET OK" -ForegroundColor Green

# ======= 3) Create or update app =======
$bodyCreate = BuildTopLevelSamlBody $DisplayName $SpEntityId $AcsUrls $AssertionDuration $SignOnUrl $NameIdFormat

$createResp = $null
try {
  $createResp = Invoke-Json POST "$ApiBase/applications" $H $bodyCreate
  $app = Get-Json $createResp
  Write-Host ("Created SAML app id={0}" -f $app.id) -ForegroundColor Green
} catch {
  # If name collision, update existing by name (or create suffixed)
  $appsResp = Invoke-Json GET "$ApiBase/applications?name=$([uri]::EscapeDataString($DisplayName))" $H
  $appsJson = Get-Json $appsResp
  $items    = Get-EmbeddedItems $appsJson
  $existing = $null
  if ($items.Count -gt 0) { $existing = $items | Where-Object { $_.name -eq $DisplayName } | Select-Object -First 1 }

  if ($null -ne $existing) {
    # fetch full app to check protocol type
    $aResp = Invoke-Json GET "$ApiBase/applications/$($existing.id)" $H
    $aJson = Get-Json $aResp
    $ptype = GetProtocolType $aJson

    if ($ptype -eq 'SAML') {
      $bodyUpdate = $bodyCreate + @{ id = $existing.id }
      $updResp = Invoke-Json PUT "$ApiBase/applications/$($existing.id)" $H $bodyUpdate
      $app = Get-Json $updResp
      Write-Host ("Updated SAML app id={0}" -f $app.id) -ForegroundColor Yellow
    } else {
      $suffix = (Get-Date -Format 'yyyyMMddHHmmss')
      $newName = "$DisplayName-saml-$suffix"
      $bodyCreate2 = BuildTopLevelSamlBody $newName $SpEntityId $AcsUrls $AssertionDuration $SignOnUrl $NameIdFormat
      $createResp2 = Invoke-Json POST "$ApiBase/applications" $H $bodyCreate2
      $app = Get-Json $createResp2
      Write-Host ("Existing name is OIDC. Created SAML app '{0}' (id={1})" -f $newName, $app.id) -ForegroundColor Green
    }
  } else {
    throw
  }
}

$appId = $app.id

# ======= 4) Attribute mappings (update-or-skip) =======
UpsertAttr $ApiBase $H $appId 'saml_subject' '$${user.email}'        $false
UpsertAttr $ApiBase $H $appId 'email'        '$${user.email}'        $false
UpsertAttr $ApiBase $H $appId 'firstName'    '$${user.givenName}'    $false
UpsertAttr $ApiBase $H $appId 'lastName'     '$${user.familyName}'   $false
if ($MapGroups) { UpsertAttr $ApiBase $H $appId 'groups' '$${user.groups.names}' $true }

# ======= 5) Summary =======
$md = "https://auth.pingone.$RegionTld/$EnvId/saml20/idp/metadata"
Write-Host "`n--- ✅ COMPLETE ---" -ForegroundColor Green
Write-Host ("App Name      : {0}" -f $app.name)
Write-Host ("App ID        : {0}" -f $appId)
Write-Host ("SP Entity ID  : {0}" -f $SpEntityId)
Write-Host ("ACS URLs      : {0}" -f ($AcsUrls -join ', '))
Write-Host ("Assertion (s) : {0}" -f $AssertionDuration)
Write-Host ("IdP Metadata  : {0}" -f $md)
