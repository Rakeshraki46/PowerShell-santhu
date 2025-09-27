<#
.SYNOPSIS
  Create & wire a PingOne SAML application (non-interactive).

.PARAMETER EnvId
  PingOne Environment ID (UUID).

.PARAMETER WorkerClientId / WorkerClientSecret
  Client credentials of a PingOne *Worker* or *Service* app with scopes to manage the environment.

.PARAMETER DisplayName
  Application name to create in PingOne.

.NOTES
  Requires outbound HTTPS to auth.pingone.com and api.pingone.com (or regional TLD).
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)] [string]$EnvId,
  [Parameter(Mandatory=$true)] [string]$WorkerClientId,
  [Parameter(Mandatory=$true)] [string]$WorkerClientSecret,
  [Parameter(Mandatory=$true)] [string]$DisplayName,

  # Optional: use "com", "eu", etc. Defaults to global (.com)
  [string]$RegionTld = "com"
)

# === Keep your original URLs exactly as-is ===
$AcsUrls = @(
  "https://us.region-2c-tpdbos1.devgateway.verizon.com/secure_access/services/saml/login-consumer",
  "https://KENUWADQ-VR-PNF.securegateway.verizon.com/secure-access/services/saml/login-consumer",
  "https://RVDLILBD-VR-PNF.securegateway.verizon.com/secure-access/services/saml/login-consumer"
)
$EntityId  = "https://us-region2-tc-tpdbos1.devgateway.verizon.com/metadata"
$SignOnUrl = $AcsUrls[0]

# Group details (created in PingOne Directory)
$NewGroupDisplayName  = "addeed-helper"
$NewGroupDescription  = "Automation-created group for $DisplayName access"

# ---------- Helpers ----------
$authBase = "https://auth.pingone.$RegionTld/$EnvId"
$apiBase  = "https://api.pingone.$RegionTld/v1/environments/$EnvId"

function Get-P1Token {
  param([string]$ClientId,[string]$ClientSecret)

  $body = @{
    grant_type    = "client_credentials"
    client_id     = $ClientId
    client_secret = $ClientSecret
  }
  $resp = Invoke-RestMethod -Method POST -Uri "$authBase/as/token" `
           -ContentType 'application/x-www-form-urlencoded' -Body $body -ErrorAction Stop
  return $resp.access_token
}

function Invoke-P1 {
  param(
    [Parameter(Mandatory)][string]$Method,
    [Parameter(Mandatory)][string]$Path,      # begins with "/..."
    [object]$Body = $null,
    [int]$Retry = 3
  )
  $headers = @{ Authorization = "Bearer $script:AccessToken" }
  $uri = "$apiBase$Path"

  for ($i=0; $i -lt $Retry; $i++) {
    try {
      if ($Body -ne $null) {
        return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers `
               -ContentType 'application/json' -Body ($Body | ConvertTo-Json -Depth 10)
      } else {
        return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers
      }
    } catch {
      if ($i -ge ($Retry-1)) { throw }
      Start-Sleep -Seconds 3
    }
  }
}

function Wait-P1 {
  param([scriptblock]$ScriptBlock, [int]$Max=20, [int]$Delay=4)
  for ($i=0; $i -lt $Max; $i++) {
    $r = & $ScriptBlock
    if ($r) { return $r }
    Start-Sleep -Seconds $Delay
  }
  return $null
}

try {
  $ErrorActionPreference = 'Stop'

  # 1) Token
  $script:AccessToken = Get-P1Token -ClientId $WorkerClientId -ClientSecret $WorkerClientSecret

  # 2) Create SAML Application (PingOne acts as IdP)
  #    Body matches PingOne "Create Application (SAML Protocol)" data model.
  $samlAppBody = @{
    name    = $DisplayName
    enabled = $true

    # Application "type" and SSO "protocol"
    type     = "WEB_APP"                 # Web application (browser-based)
    protocol = @{
      type = "SAML"
      saml = @{
        spEntityId = $EntityId
        # ACS endpoints (HTTP-POST)
        assertionConsumerService = @(
          foreach ($u in $AcsUrls) {
            @{ binding = "HTTP_POST"; url = $u; index = 0 }
          }
        )
        # IdP-initiated SSO allowed; NameID format like your AAD template
        nameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"

        # Managed signing key (PingOne generates/hosts cert)
        signing = @{
          type = "PINGONE_MANAGED"
        }

        # Optional: set RelayState / default sign-on URL for deep-linking
        defaultTargetUrl = $SignOnUrl
      }
    }
  }

  $app = Invoke-P1 -Method POST -Path "/applications" -Body $samlAppBody
  $appId = $app.id

  # 3) Ensure at least one App Role exists ("User")
  $roles = Invoke-P1 -Method GET -Path "/applications/$appId/roles"
  $userRole = $roles._embedded.items | Where-Object { $_.name -eq "User" }
  if (-not $userRole) {
    $userRole = Invoke-P1 -Method POST -Path "/applications/$appId/roles" -Body @{
      name        = "User"
      description = "Default access"
      enabled     = $true
    }
  }
  $roleId = $userRole.id

  # 4) Create/ensure group
  #    POST /groups creates a PingOne Directory group (environment-scoped).
  $existingGroups = Invoke-P1 -Method GET -Path "/groups?name=$([uri]::EscapeDataString($NewGroupDisplayName))"
  $group = $existingGroups._embedded.items | Where-Object { $_.name -eq $NewGroupDisplayName }
  if (-not $group) {
    $group = Invoke-P1 -Method POST -Path "/groups" -Body @{
      name        = $NewGroupDisplayName
      description = $NewGroupDescription
    }
  }
  $groupId = $group.id

  # 5) Assign the GROUP to the application's role (access control)
  #    POST /applications/{appId}/roleAssignments
  #    principalType can be GROUP or USER
  $assignments = Invoke-P1 -Method GET -Path "/applications/$appId/roleAssignments"
  $already = $assignments._embedded.items | Where-Object { $_.principal.id -eq $groupId -and $_.role.id -eq $roleId }
  if (-not $already) {
    [void](Invoke-P1 -Method POST -Path "/applications/$appId/roleAssignments" -Body @{
      principal = @{ id = $groupId; type = "GROUP" }
      role      = @{ id = $roleId }
    })
  }

  # 6) Add a simple SAML attribute mapping: Groups → Group Names (multivalue)
  #    POST /applications/{appId}/attributeMappings
  #    Many apps expect an attribute named "Groups"; this maps PingOne group names.
  $mappings = Invoke-P1 -Method GET -Path "/applications/$appId/attributeMappings"
  $hasGroups = $mappings._embedded.items | Where-Object { $_.name -eq "Groups" }
  if (-not $hasGroups) {
    [void](Invoke-P1 -Method POST -Path "/applications/$appId/attributeMappings" -Body @{
      name        = "Groups"
      mappingType = "CORE"         # or "CUSTOM" depending on your org’s policy
      # In PingOne UI this is “Group Names”; API value is a reference to the directory attribute.
      value       = "$${user.groups.names}"  # resolves to the user's group display names
      format      = "STRING"
      multiValued = $true
    })
  }

  # 7) Summary
  $spMetadataUrl = "https://auth.pingone.$RegionTld/$EnvId/saml20/idp/metadata"
  Write-Host "`n--- SUMMARY ---"
  Write-Host "PingOne Env:        $EnvId"
  Write-Host "App Name:           $DisplayName"
  Write-Host "App ID:             $appId"
  Write-Host "Entity ID:          $EntityId"
  Write-Host "ACS URLs:           $($AcsUrls -join ', ')"
  Write-Host "Default Sign-On:    $SignOnUrl"
  Write-Host "Group:              $($group.name)  (ID: $groupId)"
  Write-Host "Assigned Role:      $($userRole.name)  (ID: $roleId)"
  Write-Host "IdP Metadata URL:   $spMetadataUrl"
  Write-Host "`nNext: download the IdP metadata above and give it to your SP."

} catch {
  Write-Error $_.Exception.Message
  if ($_.ErrorDetails.Message) { Write-Error $_.ErrorDetails.Message }
}
