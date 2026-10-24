[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$RequestsFile)
# SINGLE COORDINATOR ONLY. No retries, downloads, releases or submissions.
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$file=[IO.Path]::GetFullPath($RequestsFile)
if(!$file.StartsWith((Join-Path $root 'local\mcp\batches\'),[StringComparison]::OrdinalIgnoreCase)){throw 'Batch outside private mailbox'}
$batch=Get-Content -LiteralPath $file -Raw|ConvertFrom-Json
if($batch.requests.Count -lt 1 -or $batch.requests.Count -gt 4){throw 'Batch must contain one to four reservations'}
if(Test-Path -LiteralPath (Join-Path $root 'local/mcp/upgrade-pause-claims.json')){throw 'Claims paused for upgrade'}
$api=Join-Path $PSScriptRoot 'fnv.ps1'
# Persist the phase before any network call; a failed status cannot have claimed.
$started=Join-Path (Split-Path $file -Parent) 'started.json'
if(Test-Path -LiteralPath $started){throw 'Batch already started; reconcile, never replay'}
@{phase='before_status';utc=[DateTimeOffset]::UtcNow.ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath $started
try { $status=(& $api status)|ConvertFrom-Json } catch {
 foreach($request in $batch.requests){
  @{request_id=$request.request_id;state='not_attempted';reason='status_preflight_failed'}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path (Split-Path $file -Parent) ($request.request_id+'.json'))
 }
 throw
}
@{phase='claiming';utc=[DateTimeOffset]::UtcNow.ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath $started
$results=@();$halt=$false
foreach($request in $batch.requests){
 $receipt=Join-Path (Split-Path $file -Parent) ($request.request_id+'.json')
 if($request.request_id -notmatch '^[0-9a-f]{32}$' -or $request.band -notin @('<=255','256-511','512-1K','1K-4K','4K+')){throw 'Invalid reservation request'}
 if(Test-Path -LiteralPath $receipt){throw 'Existing reservation receipt: reconcile; never replay a batch'}
 $value=@{request_id=$request.request_id;state='not_attempted'}
 if(!$halt -and $status.open_claims.Count -lt $status.limits.claims -and !$status.submissions_paused -and $status.awaiting_verification -lt $status.limits.pending -and $status.submissions_today -lt $status.limits.subsPerDay){
  try {
   $taskBody=@{band=$request.band;prefer='any'}
   $taskMode=[string]$request.context_mode
   if (!$taskMode -and $request.agent_id -match '^[a-z][a-z0-9_-]{0,63}$') {
    $taskPref=Join-Path $root ('local/mcp/context-preferences/'+$request.agent_id+'.json')
    if(Test-Path -LiteralPath $taskPref){try{$taskMode=[string](Get-Content -LiteralPath $taskPref -Raw|ConvertFrom-Json).context_mode}catch{$taskMode=''}}
   }
   if($taskMode -in @('lean','resume')){$taskBody.context_mode=$taskMode}
   $claim=(& $api claim -Json ($taskBody|ConvertTo-Json -Compress))|ConvertFrom-Json
   if(!$claim.claim_id -or !$claim.symbol -or !$claim.address -or !$claim.size -or !$claim.expires){throw 'Incomplete identity'}
   if($taskMode -in @('lean','resume')){$claim|Add-Member -NotePropertyName context_mode -NotePropertyValue $taskMode -Force}
   $pack=Join-Path $root ('work/'+$claim.claim_id)
   New-Item -ItemType Directory -Path $pack -Force|Out-Null
   $claim|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $pack 'claim-state.json')
   $value=@{request_id=$request.request_id;state='reserved';claim=@{claim_id=$claim.claim_id;symbol=$claim.symbol;address=$claim.address;size=$claim.size;expires=$claim.expires;pack=$pack}}
   $status.open_claims=@($status.open_claims)+@($claim)
  } catch {
   # Never replay claim. The single writer can recover a committed claim from
   # exactly one new owned identity, using read-only status and packet calls.
   $value=@{request_id=$request.request_id;state='uncertain'};$halt=$true
   try {
    $after=(& $api status)|ConvertFrom-Json
    $beforeIds=@($status.open_claims|ForEach-Object {$_.claim_id})
    $added=@($after.open_claims|Where-Object {$_.this_key -and $_.claim_id -notin $beforeIds})
    if($added.Count -eq 1){
     $owned=$added[0]
     $packet=(& $api packet -Json (@{claim_id=$owned.claim_id}|ConvertTo-Json -Compress))|ConvertFrom-Json
     if($packet.address -eq $owned.address -and $packet.symbol -and $packet.size){
      $pack=Join-Path $root ('work/'+$owned.claim_id)
      New-Item -ItemType Directory -Path $pack -Force|Out-Null
      $recovered=@{claim_id=$owned.claim_id;symbol=$packet.symbol;address=$owned.address;size=$packet.size;expires=$owned.expires;pack=$pack}
      $recovered|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $pack 'claim-state.json')
      $packet|ConvertTo-Json -Depth 30|Set-Content -LiteralPath (Join-Path $pack 'packet.json')
      $value=@{request_id=$request.request_id;state='reserved';claim=$recovered;reconciled_by='unique owned status delta and authenticated packet; no mutation replay'}
      $status=$after
     }
    }
   } catch { } # Failed reads preserve uncertainty and stop the batch.
  }
 }
 # Persist each identity before proceeding to another mutation.
 $temporary=$receipt+'.tmp'
 $value|ConvertTo-Json -Depth 16|Set-Content -LiteralPath $temporary
 Move-Item -LiteralPath $temporary -Destination $receipt
 $results+=@($value)
}
@{results=@($results)}|ConvertTo-Json -Depth 20 -Compress
