[CmdletBinding()]
param(
 [ValidateSet('<=255','256-511','512-1K','1K-4K','4K+')][string]$Band='<=255',
 [ValidateSet('any','fresh','attempted')][string]$Prefer='any',
 [string]$BeforeStatusFile,
 [ValidateSet('','lean','resume')][string]$ContextMode=''
)
# SINGLE COORDINATOR ONLY. Packet/context download is a separate read-only job.
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
if(Test-Path -LiteralPath (Join-Path $root 'local/mcp/upgrade-pause-claims.json')){throw 'Claims paused for upgrade'}
$api=Join-Path $PSScriptRoot 'fnv.ps1'
$status=(& $api status)|ConvertFrom-Json
if($BeforeStatusFile){
 $beforePath=[IO.Path]::GetFullPath($BeforeStatusFile)
 if(!$beforePath.StartsWith((Join-Path $root 'local/cpu-sweep/reservations/'),[StringComparison]::OrdinalIgnoreCase)){throw 'Invalid CPU preflight receipt path'}
 if(Test-Path -LiteralPath $beforePath){throw 'Existing preflight receipt; never replay reservation'}
 New-Item -ItemType Directory -Path (Split-Path $beforePath -Parent) -Force | Out-Null
 $snapshot=@{utc=[DateTimeOffset]::UtcNow.ToString('o');open_claims=@($status.open_claims|ForEach-Object {@{claim_id=$_.claim_id}})}
 $snapshot|ConvertTo-Json -Depth 6 -Compress|Set-Content -LiteralPath ($beforePath+'.tmp')
 Move-Item -LiteralPath ($beforePath+'.tmp') -Destination $beforePath
}

if($status.open_claims.Count -ge $status.limits.claims -or $status.submissions_paused -or $status.awaiting_verification -ge $status.limits.pending -or $status.submissions_today -ge $status.limits.subsPerDay){throw 'Account has no claim/submission capacity'}
try {
 $taskBody=@{band=$Band;prefer=$Prefer}
 if($ContextMode){$taskBody.context_mode=$ContextMode}
 $claim=(& $api claim -Json ($taskBody|ConvertTo-Json -Compress))|ConvertFrom-Json
 if(!$claim.claim_id -or !$claim.symbol -or !$claim.address -or !$claim.size -or !$claim.expires){throw 'Incomplete claim response; reconcile, never replay'}
 if($ContextMode){$claim|Add-Member -NotePropertyName context_mode -NotePropertyValue $ContextMode -Force}
} catch {
 # Exactly one service writer: recover a lost reply by identity, never retry claim.
 $recovered=$null
 try {
  $after=(& $api status)|ConvertFrom-Json
  $beforeIds=@($status.open_claims|ForEach-Object {$_.claim_id})
  $added=@($after.open_claims|Where-Object {$_.this_key -and $_.claim_id -notin $beforeIds})
  if($added.Count -eq 1){
   $owned=$added[0]
   $packet=(& $api packet -Json (@{claim_id=$owned.claim_id}|ConvertTo-Json -Compress))|ConvertFrom-Json
   if($packet.address -eq $owned.address -and $packet.symbol -and $packet.size){
    $recovered=@{claim_id=$owned.claim_id;symbol=$packet.symbol;address=$owned.address;size=$packet.size;expires=$owned.expires}
   }
  }
 } catch { }
 if(!$recovered){throw 'Claim response uncertain; read-only reconciliation failed; never replay'}
 $claim=$recovered
}
$directory=Join-Path $root ('work/'+$claim.claim_id)
New-Item -ItemType Directory -Path $directory -Force | Out-Null
$claim|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $directory 'claim-state.json')
@{claim_id=$claim.claim_id;symbol=$claim.symbol;address=$claim.address;size=$claim.size;expires=$claim.expires;pack=$directory}|ConvertTo-Json
