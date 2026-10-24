[CmdletBinding()]
param(
    [ValidateSet('<=255','256-511','512-1K','1K-4K','4K+')][string]$Band = '<=255',
    [ValidateSet('any','fresh','attempted')][string]$Prefer = 'any',
    [ValidateSet('','lean','resume')][string]$ContextMode=''
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
if (Test-Path -LiteralPath (Join-Path $root 'local/mcp/upgrade-pause-claims.json')) {
    throw 'New claims temporarily paused for coordinator upgrade; existing claims and checks remain available.'
}
$api = Join-Path $PSScriptRoot 'fnv.ps1'
$status = (& $api status) | ConvertFrom-Json
if ($status.open_claims.Count -ge $status.limits.claims) { throw 'Account active-claim limit reached.' }
if ($status.submissions_paused -or $status.awaiting_verification -ge $status.limits.pending -or $status.submissions_today -ge $status.limits.subsPerDay) {
    throw 'Account has no submission capacity; do not claim more work.'
}
$taskClaimBody=@{band=$Band;prefer=$Prefer}
if($ContextMode){$taskClaimBody.context_mode=$ContextMode}
$claim = (& $api claim -Json ($taskClaimBody | ConvertTo-Json -Compress)) | ConvertFrom-Json
if (!$claim.claim_id) { throw 'No claim id returned.' }
$directory = Join-Path $root ('work/' + $claim.claim_id)
New-Item -ItemType Directory -Path $directory -Force | Out-Null
$claim | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $directory 'claim-state.json')
$claim | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $root 'local/claim.json')
$taskPacketBody=@{claim_id=$claim.claim_id}
if($ContextMode){$taskPacketBody.context_mode=$ContextMode}
$packet = (& $api packet -Json ($taskPacketBody | ConvertTo-Json -Compress)) | ConvertFrom-Json
$packet | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $directory 'packet.json')
$packet | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $root 'local/packet.json')
$null = & (Join-Path $PSScriptRoot 'download-pack.ps1') -Pack $directory
@{claim_id=$claim.claim_id;symbol=$claim.symbol;address=$claim.address;size=$claim.size;expires=$claim.expires;pack=$directory} | ConvertTo-Json
