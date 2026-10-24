[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$settingsPath = Join-Path $root 'local\settings.json'
$cl = Join-Path $root 'tools\vc2008\VC\bin\cl.exe'
$privateDir = Join-Path $env:LOCALAPPDATA 'FNVDecomp'
Write-Output "Workspace: $root"
if (Test-Path -LiteralPath $settingsPath) {
    $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    if (Test-Path -LiteralPath $settings.game_exe) {
        $hash = (Get-FileHash -LiteralPath $settings.game_exe -Algorithm SHA256).Hash
        Write-Output "Game present: $($settings.game_exe)"
        Write-Output "Game unchanged since setup: $($hash -eq $settings.game_sha256)"
    } else { Write-Output 'MISSING: game executable' }
    if ($settings.checker_image) {
        Write-Output "Private checker reference present: $(Test-Path -LiteralPath $settings.checker_image)"
    }
} else { Write-Output 'MISSING: local/settings.json' }
if (Test-Path -LiteralPath $cl) {
    $version = ((Get-Item -LiteralPath $cl).VersionInfo.FileVersion -split '\s+')[0]
    Write-Output "Compiler version: $version (required: 15.00.30729.01)"
} else { Write-Output 'MISSING: official VC2008 SP1 compiler' }
Write-Output "API credential stored: $(Test-Path -LiteralPath (Join-Path $privateDir 'api-key.dpapi'))"
Write-Output "Checker installed: $(Test-Path -LiteralPath (Join-Path $root 'tools\fnvcheck'))"
$limitPath = Join-Path $root 'local\service-limit.json'
if (Test-Path -LiteralPath $limitPath) {
    $limit = Get-Content -LiteralPath $limitPath -Raw | ConvertFrom-Json
    $retryAt = [DateTimeOffset]$limit.retry_at_utc
    Write-Output "Service retry time (UTC): $($retryAt.ToUniversalTime().ToString('o'))"
}
Write-Output 'Checker and pack availability must be confirmed before claiming a function.'
