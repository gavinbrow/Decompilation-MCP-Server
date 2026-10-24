[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$RequestsFile)
# SINGLE COORDINATOR ONLY. No retries, downloads, releases or submissions.
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$file=[IO.Path]::GetFullPath($RequestsFile)
if(!$file.StartsWith((Join-Path $root 'local\cpu-sweep\claim-batches\'),[StringComparison]::OrdinalIgnoreCase)){throw 'Batch outside private mailbox'}
$batch=Get-Content -LiteralPath $file -Raw|ConvertFrom-Json
if($batch.requests.Count -lt 1 -or $batch.requests.Count -gt 16){throw 'Batch must contain one to sixteen CPU reservations'}
if(Test-Path -LiteralPath (Join-Path (Split-Path $file -Parent) 'started.json')){throw 'Batch already started: reconcile receipts; never replay'}
$api=Join-Path $PSScriptRoot 'fnv.ps1'
function Write-CpuBatchPhase([string]$phase){
 $marker=Join-Path (Split-Path $file -Parent) 'started.json'
 $temp=$marker+'.tmp'
 $body=[Text.Encoding]::UTF8.GetBytes((@{phase=$phase;utc=[DateTimeOffset]::UtcNow.ToString('o')}|ConvertTo-Json -Compress))
 $stream=[IO.FileStream]::new($temp,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try{$stream.Write($body,0,$body.Length);$stream.Flush($true)}finally{$stream.Dispose()}
 Move-Item -LiteralPath $temp -Destination $marker -Force
}
Write-CpuBatchPhase 'before_status'
if(Test-Path -LiteralPath (Join-Path $root 'local/mcp/upgrade-pause-claims.json')){throw 'Claims paused for upgrade'}
$status=(& $api status)|ConvertFrom-Json
Write-CpuBatchPhase 'claiming'
$results=@();$halt=$false
foreach($request in $batch.requests){
 $receipt=Join-Path (Split-Path $file -Parent) ($request.request_id+'.json')
 if($request.request_id -notmatch '^[0-9a-f]{32}$' -or $request.band -notin @('<=255','256-511','512-1K','1K-4K','4K+')){throw 'Invalid reservation request'}
 if(Test-Path -LiteralPath $receipt){throw 'Existing reservation receipt: reconcile; never replay a batch'}
 $value=@{request_id=$request.request_id;state='not_attempted'}
 if(!$halt -and $status.open_claims.Count -lt $status.limits.claims -and !$status.submissions_paused -and $status.awaiting_verification -lt $status.limits.pending -and $status.submissions_today -lt $status.limits.subsPerDay){
  try {
   $claim=(& $api claim -Json (@{band=$request.band;prefer='any'}|ConvertTo-Json -Compress))|ConvertFrom-Json
   if(!$claim.claim_id -or !$claim.symbol -or !$claim.address -or !$claim.size -or !$claim.expires){throw 'Incomplete identity'}
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
 $body=[Text.Encoding]::UTF8.GetBytes(($value|ConvertTo-Json -Depth 16 -Compress))
 $stream=[IO.FileStream]::new($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try{$stream.Write($body,0,$body.Length);$stream.Flush($true)}finally{$stream.Dispose()}
 Move-Item -LiteralPath $temporary -Destination $receipt
 $results+=@($value)
}
@{results=@($results)}|ConvertTo-Json -Depth 20 -Compress
