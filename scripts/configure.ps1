[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$GameExe,[string]$CheckerImage,[switch]$SetApiKey)
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
if (!(Test-Path -LiteralPath $GameExe -PathType Leaf)) { throw 'Supply your own installed game executable.' }
foreach($folder in @('local','local/auth','local/shared','local/mcp/live/requests','local/mcp/live/responses','local/mcp/live/targets','local/cpu-sweep','work','contributions','tools')) {
    New-Item -ItemType Directory -Path (Join-Path $root $folder) -Force | Out-Null
}
$settings=Join-Path $root 'local/settings.json'
if (Test-Path -LiteralPath $settings) { throw 'Existing settings retained; edit them explicitly rather than overwrite.' }
$image=if($CheckerImage){(Resolve-Path -LiteralPath $CheckerImage).Path}else{(Resolve-Path -LiteralPath $GameExe).Path}
@{game_exe=(Resolve-Path -LiteralPath $GameExe).Path;game_sha256=(Get-FileHash -LiteralPath $GameExe -Algorithm SHA256).Hash;checker_image=$image} | ConvertTo-Json | Set-Content -LiteralPath $settings
@{enabled=$false;cpu_concurrency=4;fast_screen=$true;return_all_failures=$true;batch_reservations=$true;batch_finalizations=$true;refill_per_turn=4} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'local/cpu-sweep/control.json')
'[]' | Set-Content -LiteralPath (Join-Path $root 'local/submissions.json')
@{flag_enabled=$false} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'local/contribution-policy.json')
if ($SetApiKey) {
    $key=Read-Host 'Your own FNV API key (hidden)' -AsSecureString
    $key|ConvertFrom-SecureString|Set-Content -LiteralPath (Join-Path $root 'local/api-key.dpapi') -NoNewline
    $key|ConvertFrom-SecureString|Set-Content -LiteralPath (Join-Path $root 'local/auth/api-key.dpapi') -NoNewline
}
Write-Output 'Private workspace initialized. CPU claiming is OFF until explicitly enabled. No service requests made.'
