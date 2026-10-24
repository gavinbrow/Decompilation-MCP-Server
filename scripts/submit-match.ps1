[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Pack,
    [Parameter(Mandatory=$true)][string]$Candidate,
    [string]$Model
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$directory = (Resolve-Path -LiteralPath $Pack).Path
$claim = Get-Content -LiteralPath (Join-Path $directory 'claim-state.json') -Raw | ConvertFrom-Json
$packet = Get-Content -LiteralPath (Join-Path $directory 'pack.json') -Raw | ConvertFrom-Json
if ($claim.address -ne $packet.address -or $claim.symbol -ne $packet.symbol -or $claim.size -ne $packet.size) { throw 'Claim and context metadata differ.' }
if ($claim.symbol -notmatch '^FUN_[0-9a-fA-F]{8}$') { throw 'Unexpected contribution name.' }
$api = Join-Path $PSScriptRoot 'fnv.ps1'
$status = (& $api status) | ConvertFrom-Json
if ($status.submissions_paused -or $status.awaiting_verification -ge $status.limits.pending -or $status.submissions_today -ge $status.limits.subsPerDay) { throw 'Account submission limit reached.' }
if (!($status.open_claims | Where-Object { $_.claim_id -eq $claim.claim_id -or $_.id -eq $claim.claim_id })) { throw 'Claim is no longer active.' }
$sourcePath = Join-Path $root ('contributions/' + $claim.symbol + '.cpp')
$candidateResolved = (Resolve-Path -LiteralPath $Candidate).Path
$review = & (Join-Path $root '.venv/Scripts/python.exe') (Join-Path $PSScriptRoot 'source-address-review.py') $candidateResolved
if ($LASTEXITCODE -ne 0) {
    $review | Set-Content -LiteralPath (Join-Path $directory 'source-address-review.json')
    throw 'Potential hard-coded game address in source; review required before uploading.'
}
$sourceWorker = Split-Path (Split-Path $candidateResolved -Parent) -Leaf
$candidateParent = [System.IO.DirectoryInfo](Split-Path $candidateResolved -Parent)
while ($candidateParent -and $candidateParent.FullName -ne $directory) {
    if ($candidateParent.Name -match '^(sol_low|luna|qwen|cpu|gpu)_\d+$') {
        $sourceWorker = $candidateParent.Name
        break
    }
    $candidateParent = $candidateParent.Parent
}
if ($sourceWorker -like 'clm_*' -and (Split-Path $candidateResolved -Leaf) -match 'candidate_(.+)\.cpp$') { $sourceWorker = $Matches[1] }
Copy-Item -LiteralPath (Resolve-Path -LiteralPath $Candidate).Path -Destination $sourcePath -Force
$checkedHash = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash
$attributionArgs = @((Join-Path $PSScriptRoot 'submission-attribution.py'), '--candidate', $candidateResolved, '--worker', $sourceWorker)
if ($Model) { $attributionArgs += @('--model', $Model) }
$attribution = & (Join-Path $root '.venv/Scripts/python.exe') @attributionArgs
if ($LASTEXITCODE -ne 0) { throw 'Missing or invalid source attribution; set -Model or provide a hash-bound provenance sidecar.' }
$provenance = $attribution | ConvertFrom-Json
if ($provenance.source_sha256 -ne $checkedHash) { throw 'Candidate changed while staging source attribution.' }
$result = & (Join-Path $PSScriptRoot 'fnvcheck.ps1') -Pack $directory -Candidate $sourcePath -Worker coordinator -Json -Official
$exitCode = $LASTEXITCODE
$result | Set-Content -LiteralPath (Join-Path $directory 'coordinator-check.json')
$check = $result | ConvertFrom-Json
if ($exitCode -ne 0 -or $check.status -ne 'match') { throw 'Official checker did not report MATCH; nothing submitted.' }
if ((Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash -ne $checkedHash) { throw 'Source changed after checking.' }
$request = Join-Path $directory 'submit-request.json'
@{claim_id=$claim.claim_id;source=(Get-Content -LiteralPath $sourcePath -Raw);model=$provenance.model} | ConvertTo-Json | Set-Content -LiteralPath $request
$receipt = (& $api submit -InputFile $request) | ConvertFrom-Json
$receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $directory 'submit-receipt.json')
if (!$receipt.submission_id) { throw 'No submission id returned; inspect receipt before retrying.' }
$manifestPath = Join-Path $root 'local/submissions.json'
$manifest = @()
if (Test-Path -LiteralPath $manifestPath) { $manifest = @(Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json) }
$manifest += [pscustomobject]@{claim_id=$claim.claim_id;symbol=$claim.symbol;address=$claim.address;size=$claim.size;source=('contributions/'+$claim.symbol+'.cpp');source_worker=$sourceWorker;source_candidate=$candidateResolved;model=$provenance.model;attribution_basis=$provenance.basis;checker_result='MATCH';source_sha256=$checkedHash;submission_id=$receipt.submission_id;state=$receipt.state}
ConvertTo-Json -InputObject $manifest -Depth 8 | Set-Content -LiteralPath $manifestPath
$claim | Add-Member -NotePropertyName stage -NotePropertyValue 'submitted_awaiting_overnight_verification' -Force
$claim | Add-Member -NotePropertyName submission_id -NotePropertyValue $receipt.submission_id -Force
$claim | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $directory 'claim-state.json')
$receipt | ConvertTo-Json
